"""Execution evidence and timeline composite MCP tools."""

from __future__ import annotations

import re
import time
from typing import Any

from mulder.models import WindowRow
from mulder.patterns import SUSPICIOUS_PATHS
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    make_tool_call_id,
    slim_window,
)
from mulder.server.tools.composite.core import (
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
    finalize_composite_result,
)

__all__ = ["find_execution_evidence", "analyze_execution_timeline"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EXE_NAME_RE = re.compile(r"(\S+\.exe)", re.IGNORECASE)
_RUN_COUNT_RE = re.compile(r"run\s*count[:\s]+(\d+)", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b([a-fA-F0-9]{40})\b")

_UNUSUAL_EXE_PATHS = SUSPICIOUS_PATHS

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
# Timeline helpers
# ---------------------------------------------------------------------------


def _merge_exe(
    exe_data: dict[str, dict[str, Any]],
    name: str,
    source: str,
    event_time: str | None,
    text: str,
) -> None:
    """Upsert an executable entry, updating first/last seen times.

    Args:
        exe_data: Mutable map of lowercased exe name to timeline entry.
        name: Executable name (original case).
        source: Source label (e.g. "prefetch", "amcache").
        event_time: ISO-8601 timestamp from the source window, or None.
        text: Raw text snippet for evidence.
    """
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


def _ingest_source_entries(
    exe_data: dict[str, dict[str, Any]],
    source_name: str,
    windows: list[WindowRow],
    name_re: re.Pattern[str],
) -> list[tuple[str, WindowRow]]:
    """Ingest windows from a forensic source into the exe timeline map.

    Iterates *windows*, extracts executable names via *name_re*, and
    upserts each into *exe_data* via ``_merge_exe``.

    Args:
        exe_data: Mutable map of lowercased exe name to timeline entry.
        source_name: Label for this source (e.g. "prefetch").
        windows: Source windows to process.
        name_re: Compiled regex whose first group captures the exe name.

    Returns:
        List of (exe_name, window) pairs that matched, for source-specific
        post-processing (e.g. extracting run counts or hashes).
    """
    matched: list[tuple[str, WindowRow]] = []
    for w in windows:
        m = name_re.search(w.raw_text)
        if not m:
            continue
        exe_name = m.group(1)
        _merge_exe(exe_data, exe_name, source_name, w.event_time, w.raw_text)
        matched.append((exe_name, w))
    return matched


def _annotate_execution_anomalies(
    exe_data: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flag execution anomalies and trim evidence snippets.

    Anomalies detected:
      - ``single_execution``: run count of 1 (one-shot tools).
      - ``unusual_path``: executable in temp, downloads, or other suspect dirs.
      - ``amcache_only_no_prefetch``: amcache entry with no prefetch record,
        suggesting possible evidence cleanup.

    Args:
        exe_data: Map of lowercased exe name to timeline entry (mutated in place).

    Returns:
        Sorted list of timeline entries, highest anomaly count first.
    """
    for key, entry in exe_data.items():
        if entry["run_count"] == 1:
            entry["anomaly_flags"].append("single_execution")
        if any(pat in key for pat in _UNUSUAL_EXE_PATHS):
            entry["anomaly_flags"].append("unusual_path")
        if "amcache" in entry["sources"] and "prefetch" not in entry["sources"]:
            entry["anomaly_flags"].append("amcache_only_no_prefetch")
        entry["evidence_snippets"] = entry["evidence_snippets"][:3]

    return sorted(
        exe_data.values(),
        key=lambda e: (len(e["anomaly_flags"]), len(e["sources"])),
        reverse=True,
    )


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

    return finalize_composite_result(
        ctx=ctx,
        composite_id=composite_id,
        tool_name="find_execution_evidence",
        results=results,
        coverage_sources=[
            _SRC_EZ_PREFETCH,
            _SRC_EZ_AMCACHE,
            _SRC_EZ_SHIMCACHE,
            _SRC_EZ_JUMPLISTS,
            _SRC_EZ_LNKFILES,
            _SRC_PSTREE,
        ],
        missing=missing,
        sub_call_ids=sub_call_ids,
        t0=t0,
    )


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

    if _source_exists(_SRC_EZ_PREFETCH):
        pf_wins, tc_pf = _query_source(_SRC_EZ_PREFETCH, "analyze_execution_timeline")
        sub_call_ids.append(tc_pf)
        matched = _ingest_source_entries(exe_data, "prefetch", pf_wins, _EXE_NAME_RE)
        for exe_name, w in matched:
            rc = _RUN_COUNT_RE.search(w.raw_text)
            if rc:
                key = exe_name.lower()
                if key in exe_data:
                    exe_data[key]["run_count"] = int(rc.group(1))

    if _source_exists(_SRC_EZ_AMCACHE):
        am_wins, tc_am = _query_source(_SRC_EZ_AMCACHE, "analyze_execution_timeline")
        sub_call_ids.append(tc_am)
        matched = _ingest_source_entries(exe_data, "amcache", am_wins, _EXE_NAME_RE)
        for exe_name, w in matched:
            sha = _SHA1_RE.search(w.raw_text)
            if sha:
                key = exe_name.lower()
                if key in exe_data:
                    exe_data[key]["sha1"] = sha.group(1)

    if _source_exists(_SRC_EZ_SHIMCACHE):
        sc_wins, tc_sc = _query_source(_SRC_EZ_SHIMCACHE, "analyze_execution_timeline")
        sub_call_ids.append(tc_sc)
        _ingest_source_entries(exe_data, "shimcache", sc_wins, _EXE_NAME_RE)

    results = _annotate_execution_anomalies(exe_data)

    missing = _check_missing_sources(
        [
            ("ez.prefetch", "run_prefetch_parser('<image_path>')"),
            ("ez.amcache", "run_amcache_parser('<image_path>')"),
            ("ez.shimcache", "run_shimcache_parser('<image_path>')"),
        ]
    )

    return finalize_composite_result(
        ctx=ctx,
        composite_id=composite_id,
        tool_name="analyze_execution_timeline",
        results=results,
        coverage_sources=[
            _SRC_EZ_PREFETCH,
            _SRC_EZ_AMCACHE,
            _SRC_EZ_SHIMCACHE,
        ],
        missing=missing,
        sub_call_ids=sub_call_ids,
        t0=t0,
    )
