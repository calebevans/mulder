"""Execution evidence and timeline composite MCP tools."""

from __future__ import annotations

import re
import time
from typing import Any

from mulder.models import WindowRow
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    hash_output,
    make_tool_call_id,
    slim_window,
)
from mulder.server.tools_composite_core import (
    _PROC_NAME_RE,
    _SRC_EZ_AMCACHE,
    _SRC_EZ_JUMPLISTS,
    _SRC_EZ_LNKFILES,
    _SRC_EZ_PREFETCH,
    _SRC_EZ_SHIMCACHE,
    _SRC_PSTREE,
    _check_missing_sources,
    _extract_exe_name,
    _query_source,
    _source_exists,
    _strip_source_windows,
)

__all__ = ["find_execution_evidence", "analyze_execution_timeline"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EXE_NAME_RE = re.compile(r"(\S+\.exe)", re.IGNORECASE)
_RUN_COUNT_RE = re.compile(r"run\s*count[:\s]+(\d+)", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b([a-fA-F0-9]{40})\b")

_UNUSUAL_EXE_PATHS: tuple[str, ...] = (
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\recycle",
    "\\programdata\\",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _accumulate_exe_evidence(
    exe_evidence: dict[str, dict[str, Any]],
    windows: list[WindowRow],
    label: str,
    include_times: bool = True,
) -> None:
    """Merge windows into the exe_evidence map keyed by executable name."""
    for w in windows:
        exe_name = _extract_exe_name(w.raw_text)
        if exe_name is None:
            continue
        if exe_name not in exe_evidence:
            exe_evidence[exe_name] = {
                "executable": exe_name,
                "sources": [],
                "source_windows": [],
                "event_times": [],
            }
        entry = exe_evidence[exe_name]
        if label not in entry["sources"]:
            entry["sources"].append(label)
        entry["source_windows"].append(slim_window(w))
        entry["_total_window_count"] = entry.get("_total_window_count", 0) + 1
        if include_times and w.event_time:
            entry["event_times"].append(w.event_time)


# ---------------------------------------------------------------------------
# MCP tool handlers
# ---------------------------------------------------------------------------


@mcp.tool()
def find_execution_evidence() -> dict[str, object]:
    """Build a unified execution evidence view from multiple artifact sources.

    Joins EZ Tools prefetch (run times), amcache (install/execution with
    hashes), shimcache (file existence evidence), jump lists (user file
    access), LNK files (shortcut execution), and the Volatility process
    tree (processes running at capture time).  Each entry lists which
    sources corroborate the execution.  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    exe_evidence: dict[str, dict[str, Any]] = {}

    source_configs = [
        (_SRC_EZ_PREFETCH, "prefetch"),
        (_SRC_EZ_AMCACHE, "amcache"),
        (_SRC_EZ_SHIMCACHE, "shimcache"),
        (_SRC_EZ_JUMPLISTS, "jumplists"),
        (_SRC_EZ_LNKFILES, "lnkfiles"),
    ]

    for src, label in source_configs:
        if not _source_exists(src):
            continue
        wins, tc_id = _query_source(src, "find_execution_evidence")
        sub_call_ids.append(tc_id)
        _accumulate_exe_evidence(exe_evidence, wins, label)

    if _source_exists(_SRC_PSTREE):
        pstree_wins, tc_pt = _query_source(_SRC_PSTREE, "find_execution_evidence")
        sub_call_ids.append(tc_pt)
        _accumulate_exe_evidence(exe_evidence, pstree_wins, "memory_pstree", include_times=False)

    _MAX_EXE_WINDOWS = 10
    for entry in exe_evidence.values():
        total = entry.pop("_total_window_count", len(entry["source_windows"]))
        entry["window_count"] = total
        if len(entry["source_windows"]) > _MAX_EXE_WINDOWS:
            entry["source_windows"] = entry["source_windows"][:_MAX_EXE_WINDOWS]
            entry["truncated"] = True

    results = sorted(
        exe_evidence.values(),
        key=lambda e: len(e["sources"]),
        reverse=True,
    )

    missing = _check_missing_sources(
        [
            ("ez.prefetch", "run_prefetch_parser('<image_path>')"),
            ("ez.amcache", "run_amcache_parser('<image_path>')"),
            ("ez.shimcache", "run_shimcache_parser('<image_path>')"),
            ("volatility.pstree", "run_volatility('pstree', '<memory_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_execution_evidence",
        params={},
        output_hash=hash_output(results),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _strip_source_windows(results)
    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": results,
        "source": None,
        "result_count": len(results),
    }
    if missing:
        result["missing_sources"] = missing
    return result


@mcp.tool()
def analyze_execution_timeline() -> dict[str, object]:
    """Build a unified execution timeline from prefetch, amcache, and shimcache.

    Merges per-executable evidence from EZ Tools to show first/last
    seen times, run counts, SHA1 hashes, and flags anomalies like
    single-execution tools, unusual paths, and executables with
    amcache entries but no prefetch (possible cleanup).  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    exe_data: dict[str, dict[str, Any]] = {}

    def _merge_exe(name: str, source: str, event_time: str | None, text: str) -> None:
        """Upsert an executable entry, updating first/last seen times."""
        key = name.lower()
        if key not in exe_data:
            exe_data[key] = {
                "executable": name,
                "sources": [],
                "first_seen": None,
                "last_seen": None,
                "run_count": None,
                "sha1": None,
                "anomaly_flags": [],
                "evidence_snippets": [],
            }
        entry = exe_data[key]
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if event_time:
            if entry["first_seen"] is None or event_time < entry["first_seen"]:
                entry["first_seen"] = event_time
            if entry["last_seen"] is None or event_time > entry["last_seen"]:
                entry["last_seen"] = event_time
        entry["evidence_snippets"].append(text[:150])

    if _source_exists(_SRC_EZ_PREFETCH):
        pf_wins, tc_pf = _query_source(_SRC_EZ_PREFETCH, "analyze_execution_timeline")
        sub_call_ids.append(tc_pf)
        for w in pf_wins:
            m = _EXE_NAME_RE.search(w.raw_text)
            if not m:
                continue
            exe_name = m.group(1)
            _merge_exe(exe_name, "prefetch", w.event_time, w.raw_text)
            rc = _RUN_COUNT_RE.search(w.raw_text)
            if rc:
                key = exe_name.lower()
                if key in exe_data:
                    exe_data[key]["run_count"] = int(rc.group(1))

    if _source_exists(_SRC_EZ_AMCACHE):
        am_wins, tc_am = _query_source(_SRC_EZ_AMCACHE, "analyze_execution_timeline")
        sub_call_ids.append(tc_am)
        for w in am_wins:
            m = _EXE_NAME_RE.search(w.raw_text)
            if not m:
                continue
            exe_name = m.group(1)
            _merge_exe(exe_name, "amcache", w.event_time, w.raw_text)
            sha = _SHA1_RE.search(w.raw_text)
            if sha:
                key = exe_name.lower()
                if key in exe_data:
                    exe_data[key]["sha1"] = sha.group(1)

    if _source_exists(_SRC_EZ_SHIMCACHE):
        sc_wins, tc_sc = _query_source(_SRC_EZ_SHIMCACHE, "analyze_execution_timeline")
        sub_call_ids.append(tc_sc)
        for w in sc_wins:
            m = _EXE_NAME_RE.search(w.raw_text)
            if not m:
                continue
            _merge_exe(m.group(1), "shimcache", w.event_time, w.raw_text)

    for key, entry in exe_data.items():
        if entry["run_count"] == 1:
            entry["anomaly_flags"].append("single_execution")
        if any(pat in key for pat in _UNUSUAL_EXE_PATHS):
            entry["anomaly_flags"].append("unusual_path")
        if "amcache" in entry["sources"] and "prefetch" not in entry["sources"]:
            entry["anomaly_flags"].append("amcache_only_no_prefetch")
        entry["evidence_snippets"] = entry["evidence_snippets"][:3]

    results = sorted(
        exe_data.values(),
        key=lambda e: (len(e["anomaly_flags"]), len(e["sources"])),
        reverse=True,
    )

    missing = _check_missing_sources(
        [
            ("ez.prefetch", "run_prefetch_parser('<image_path>')"),
            ("ez.amcache", "run_amcache_parser('<image_path>')"),
            ("ez.shimcache", "run_shimcache_parser('<image_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="analyze_execution_timeline",
        params={},
        output_hash=hash_output(results),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _strip_source_windows(results)
    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": results,
        "source": None,
        "result_count": len(results),
    }
    if missing:
        result["missing_sources"] = missing
    return result
