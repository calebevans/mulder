"""Shared helpers and constants for composite analysis tool submodules.

This module contains no MCP tool handlers. It provides the source-name
constants, regex patterns, caching infrastructure, and helper functions
that all composite submodules depend on.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any

from mulder.models import SourceRow, WindowRow
from mulder.patterns import SUSPICIOUS_PATHS
from mulder.server.app import get_ctx
from mulder.server.helpers import (
    extract_pid,
    hash_output,
    make_tool_call_id,
)

__all__: list[str] = []

# ---------------------------------------------------------------------------
# Source-name constants
# ---------------------------------------------------------------------------

_SRC_NETSCAN = "volatility.netscan"
_SRC_PSSCAN = "volatility.psscan"
_SRC_PSLIST = "volatility.pslist"
_SRC_ENVARS = "volatility.envars"
_SRC_PRIVS = "volatility.privs"
_SRC_CMDLINE = "volatility.cmdline"
_SRC_PSTREE = "volatility.pstree"
_SRC_DLLLIST = "volatility.dlllist"
_SRC_MODULES = "volatility.modules"
_SRC_MODSCAN = "volatility.modscan"
_SRC_PLASO = "plaso.timeline"
_SRC_EVTX_SECURITY = "evtx.security"
_SRC_EVTX_SYSTEM = "evtx.system"
_SRC_EZ_SHIMCACHE = "ez.shimcache"
_SRC_EZ_AMCACHE = "ez.amcache"
_SRC_EZ_PREFETCH = "ez.prefetch"
_SRC_EZ_EVTX_SECURITY = "ez.evtx.security"
_SRC_EZ_SRUM = "ez.srum"
_SRC_EZ_USNJRNL = "ez.usnjrnl"
_SRC_EZ_MFT = "ez.mft"
_SRC_EZ_JUMPLISTS = "ez.jumplists"
_SRC_EZ_LNKFILES = "ez.lnkfiles"
_SRC_TSK_FILELIST = "tsk.filelist"
_SRC_BULK_URL = "bulk.url"
_SRC_BULK_EMAIL = "bulk.email"
_SRC_BULK_DOMAIN = "bulk.domain"
_SRC_PCAP_CONVERSATIONS = "pcap.conversations"
_SRC_PCAP_DNS = "pcap.dns"
_SRC_PCAP_HTTP = "pcap.http"

# ---------------------------------------------------------------------------
# Shared executable name constants (used by process + persistence modules)
# ---------------------------------------------------------------------------

_EXE_POWERSHELL = "powershell.exe"
_EXE_CMD = "cmd.exe"

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_PORT_RE = re.compile(r":(\d{1,5})(?:\s|$)")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PROC_NAME_RE = re.compile(r"^([^\t]+\.exe)", re.MULTILINE | re.IGNORECASE)
_PPID_RE = re.compile(r"(?:^|\t)(\d{1,6})\t(\d{1,6})(?:\t|$)", re.MULTILINE)

# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

_sources_cache: list[SourceRow] | None = None
_sources_cache_case_id: str | None = None

# ---------------------------------------------------------------------------
# Constants used by multiple submodules
# ---------------------------------------------------------------------------

_LATERAL_PORTS: set[int] = {445, 3389, 5985, 5986, 135}

_UNUSUAL_DLL_PATHS = SUSPICIOUS_PATHS

_NETWORK_SOURCE_ALTERNATIVES = (
    "volatility.netscan",
    "volatility.connscan",
    "volatility.sockscan",
)

_SEVERITY_WEIGHTS = {
    "malfind_injection": 10,
    "suspicious_network": 8,
    "hidden_process": 9,
    "suspicious_cmdline": 7,
    "unusual_parent": 6,
    "suspicious_dll_path": 5,
    "suspicious_environment": 4,
}

# ---------------------------------------------------------------------------
# Shared helper functions
# ---------------------------------------------------------------------------


def _strip_source_windows(items: list[Any] | Any) -> None:
    """Remove ``source_windows`` / ``source_window`` from result dicts in-place.

    Handles nested lists (e.g., execution chains = list of list of dicts).
    The agent can retrieve evidence via ``search()`` when needed.
    """
    if not isinstance(items, list):
        return
    for item in items:
        if isinstance(item, dict):
            item.pop("source_windows", None)
            item.pop("source_window", None)
        elif isinstance(item, list):
            _strip_source_windows(item)


def _get_cached_sources() -> list[SourceRow]:
    """Return cached sources for the current case, refreshing if case changed."""
    global _sources_cache, _sources_cache_case_id
    ctx = get_ctx()
    if _sources_cache is None or _sources_cache_case_id != ctx.case_id:
        _sources_cache = ctx.db.get_sources()
        _sources_cache_case_id = ctx.case_id
    return _sources_cache


def _source_exists(source_prefix: str) -> bool:
    """Return True if any indexed source matches *source_prefix* exactly or as a prefix."""
    return any(
        s.source_name == source_prefix or s.source_name.startswith(source_prefix + ".")
        for s in _get_cached_sources()
    )


def _find_matching_sources(source_prefix: str) -> list[str]:
    """Return all source names that match *source_prefix* exactly or as a prefix."""
    return [
        s.source_name
        for s in _get_cached_sources()
        if s.source_name == source_prefix or s.source_name.startswith(source_prefix + ".")
    ]


def _check_missing_sources(
    required: list[tuple[str, str]],
) -> list[dict[str, str]]:
    """Return a list of missing sources with suggested extraction commands.

    *required* is a list of ``(source_name, suggested_command)`` pairs.
    Only returns entries for sources not yet indexed.  Uses prefix
    matching so ``volatility.netscan.host1`` satisfies ``volatility.netscan``.

    Network sources (netscan/connscan/sockscan) are treated as
    interchangeable; having any one satisfies the requirement.
    """
    missing = []
    for src, cmd in required:
        if src in _NETWORK_SOURCE_ALTERNATIVES:
            if not any(_source_exists(alt) for alt in _NETWORK_SOURCE_ALTERNATIVES):
                missing.append({"source": src, "suggestion": cmd})
        elif not _source_exists(src):
            missing.append({"source": src, "suggestion": cmd})
    return missing


def _score_and_sort_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Score composite results by severity signals and sort most anomalous first."""
    for item in results:
        reasons = item.get("reasons", [])
        score = sum(_SEVERITY_WEIGHTS.get(r, 3) for r in reasons)
        item["anomaly_score"] = score
    results.sort(key=lambda x: x.get("anomaly_score", 0), reverse=True)
    return results


def _query_source(
    source_name: str,
    tool_name: str,
) -> tuple[list[WindowRow], str]:
    """Fetch all windows for a source (prefix-matched), log as a sub-call.

    Uses prefix matching so ``volatility.malfind`` retrieves data from
    ``volatility.malfind``, ``volatility.malfind.host1``, etc.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    matched = _find_matching_sources(source_name)
    windows = ctx.db.get_windows_by_source_prefix(source_name)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=f"{tool_name}._query({source_name})",
        params={"source_name": source_name, "matched_sources": matched},
        output_hash=hash_output({"count": len(windows)}),
        duration_ms=elapsed,
    )
    return windows, tc_id


def _keyword_sub_query(
    query: str,
    tool_name: str,
    source_name: str | None = None,
    k: int = 20,
) -> tuple[list[WindowRow], str]:
    """Run a keyword search as a logged sub-call, return (windows, tool_call_id).

    Searches raw_text for *query* as a case-insensitive substring.
    Falls back to searching all sources when the requested source doesn't
    exist in the case database.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    effective_source = source_name if source_name and _source_exists(source_name) else None
    results = ctx.db.search_windows(query, source_name=effective_source, max_results=k)
    windows = [w for w, _sname in results]

    actual_label = effective_source or "all"
    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=f"{tool_name}._search({actual_label})",
        params={"query": query, "source": effective_source, "max_results": k},
        output_hash=hash_output({"count": len(windows)}),
        duration_ms=elapsed,
    )
    return windows, tc_id


def _extract_process_name(text: str) -> str:
    """Best-effort extraction of a process name from Volatility output."""
    m = _PROC_NAME_RE.search(text)
    return m.group(1).strip() if m else "unknown"


def _extract_exe_name(text: str) -> str | None:
    """Best-effort extraction of an executable name from artifact text."""
    m = _PROC_NAME_RE.search(text)
    return m.group(1).strip().lower() if m else None


def _extract_ports(text: str) -> list[int]:
    """Extract port numbers from netscan output text."""
    return [int(m.group(1)) for m in _PORT_RE.finditer(text)]


def _build_pid_metadata(
    pstree_wins: list[WindowRow],
    cmdline_wins: list[WindowRow],
) -> tuple[dict[int, int], dict[int, str]]:
    """Extract parent-PID mapping and PID-to-name mapping from Volatility output."""
    parent_map: dict[int, int] = {}
    pid_names: dict[int, str] = {}
    for w in pstree_wins:
        m = _PPID_RE.search(w.raw_text)
        if m:
            parent_map[int(m.group(1))] = int(m.group(2))
        pid = extract_pid(w.raw_text)
        if pid is not None:
            pid_names[pid] = _extract_process_name(w.raw_text)
    for w in cmdline_wins:
        pid = extract_pid(w.raw_text)
        if pid is not None and pid not in pid_names:
            pid_names[pid] = _extract_process_name(w.raw_text)
    return parent_map, pid_names


def _build_coverage_metadata(
    required_sources: list[str],
) -> dict[str, object]:
    """Build coverage metadata comparing queried sources against all indexed sources.

    Computes which of the *required_sources* are indexed (and therefore
    queryable) versus which are missing. Also reports total indexed
    source count so the caller knows the overall evidence landscape.

    Args:
        required_sources: Source name prefixes the composite tool
            intends to query (e.g. ``["volatility.netscan", "evtx.security"]``).

    Returns:
        Dict with ``sources_queried``, ``sources_available``,
        ``total_sources_available``, and optionally ``coverage_note``
        when some required sources are not yet indexed.
    """
    all_sources = _get_cached_sources()
    source_names: set[str] = {s.source_name for s in all_sources}
    all_names = sorted(source_names)
    queried: list[str] = []
    not_indexed: list[str] = []

    def _prefix_matches(prefix: str) -> list[str]:
        return [n for n in source_names if n == prefix or n.startswith(prefix + ".")]

    for src in required_sources:
        if src in _NETWORK_SOURCE_ALTERNATIVES:
            net_matched: list[str] = []
            for alt in _NETWORK_SOURCE_ALTERNATIVES:
                net_matched.extend(_prefix_matches(alt))
            if net_matched:
                queried.extend(net_matched)
            else:
                not_indexed.append(src)
        else:
            matched = _prefix_matches(src)
            if matched:
                queried.extend(matched)
            else:
                not_indexed.append(src)

    queried_unique = sorted(set(queried))
    meta: dict[str, object] = {
        "sources_queried": len(queried_unique),
        "sources_queried_names": queried_unique,
        "total_sources_available": len(all_names),
    }
    if not_indexed:
        meta["coverage_note"] = (
            f"Queried {len(queried_unique)}/{len(all_names)} sources. "
            f"Sources not yet indexed: {sorted(not_indexed)}"
        )
    return meta


def _parse_event_time(ts: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string, returning None on failure."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def finalize_composite_result(
    ctx: Any,
    composite_id: str,
    tool_name: str,
    results: list[Any] | dict[str, object],
    coverage_sources: list[str],
    missing: list[dict[str, str]],
    sub_call_ids: list[str],
    t0: float,
    *,
    audit_params: dict[str, object] | None = None,
) -> dict[str, object]:
    """Compute elapsed time, log audit, strip windows, and build the result dict.

    Centralizes the epilogue boilerplate shared by all composite tools.

    Args:
        ctx: The request context (must expose ``audit.log_tool_call``).
        composite_id: Tool call ID for this composite invocation.
        tool_name: Name of the composite tool for the audit log.
        results: The analysis results (list or single dict).
        coverage_sources: Source prefixes to report in coverage metadata.
        missing: Missing source descriptors from ``_check_missing_sources``.
        sub_call_ids: IDs of sub-queries executed during the analysis.
        t0: ``time.monotonic()`` value captured at tool entry.
        audit_params: Optional params dict for the audit log entry.

    Returns:
        Standardized result dict ready to be returned to the caller.
    """
    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name=tool_name,
        params=audit_params or {},
        output_hash=hash_output(results),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )

    if isinstance(results, list):
        _strip_source_windows(results)
    elif isinstance(results, dict):
        af = results.get("anti_forensics_detected")
        if isinstance(af, list):
            _strip_source_windows(af)

    coverage = _build_coverage_metadata(coverage_sources)

    result_count = len(results) if isinstance(results, list) else 1

    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": results,
        "source": None,
        "result_count": result_count,
        **coverage,
    }
    if missing:
        result["missing_sources"] = missing
    return result
