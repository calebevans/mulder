"""Shared helpers and constants for composite analysis tool submodules.

This module contains no MCP tool handlers. It provides the source-name
constants, regex patterns, caching infrastructure, and helper functions
that all composite submodules depend on.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import datetime
from typing import Any

from mulder.models import SourceRow, WindowRow
from mulder.server import source_names as _sn
from mulder.server.app import get_ctx
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    extract_pid,
    hash_output,
    make_tool_call_id,
)

logger = logging.getLogger(__name__)

__all__: list[str] = []

# ---------------------------------------------------------------------------
# Composite tool name -> indexed source name mapping
# ---------------------------------------------------------------------------

_TOOL_SOURCE_MAP: dict[str, str] = {
    "find_persistence_mechanisms": "composite.persistence",
    "find_lateral_movement_indicators": "composite.lateral_movement",
    "find_data_exfiltration_indicators": "composite.exfil",
    "find_defense_evasion": "composite.defense_evasion",
    "find_suspicious_processes": "composite.suspicious_processes",
    "find_execution_evidence": "composite.execution",
    "correlate_across_sources": "composite.correlation",
    "reconstruct_execution_chains": "composite.execution_chains",
    "analyze_execution_timeline": "composite.timeline",
    "assess_recovery": "composite.recovery",
    "correlate_pcap_with_host": "composite.pcap_correlation",
}

# ---------------------------------------------------------------------------
# Source-name constants (canonical definitions in mulder.server.source_names)
# ---------------------------------------------------------------------------

_SRC_NETSCAN = _sn.SRC_NETSCAN
_SRC_PSSCAN = _sn.SRC_PSSCAN
_SRC_PSLIST = _sn.SRC_PSLIST
_SRC_ENVARS = _sn.SRC_ENVARS
_SRC_PRIVS = _sn.SRC_PRIVS
_SRC_CMDLINE = _sn.SRC_CMDLINE
_SRC_PSTREE = _sn.SRC_PSTREE
_SRC_DLLLIST = _sn.SRC_DLLLIST
_SRC_MODULES = _sn.SRC_MODULES
_SRC_MODSCAN = _sn.SRC_MODSCAN
_SRC_PLASO = _sn.SRC_PLASO_TIMELINE
_SRC_EVTX_SECURITY = _sn.SRC_EVTX_SECURITY
_SRC_EVTX_SYSTEM = _sn.SRC_EVTX_SYSTEM
_SRC_EZ_SHIMCACHE = _sn.SRC_EZ_SHIMCACHE
_SRC_EZ_AMCACHE = _sn.SRC_EZ_AMCACHE
_SRC_EZ_PREFETCH = _sn.SRC_EZ_PREFETCH
_SRC_EZ_EVTX_SECURITY = _sn.SRC_EZ_EVTX_SECURITY
_SRC_EZ_SRUM = _sn.SRC_EZ_SRUM
_SRC_EZ_USNJRNL = _sn.SRC_EZ_USNJRNL
_SRC_EZ_MFT = _sn.SRC_EZ_MFT
_SRC_EZ_JUMPLISTS = _sn.SRC_EZ_JUMPLISTS
_SRC_EZ_LNKFILES = _sn.SRC_EZ_LNKFILES
_SRC_TSK_FILELIST = _sn.SRC_TSK_FILELIST
_SRC_BULK_URL = _sn.SRC_BULK_URL
_SRC_BULK_EMAIL = _sn.SRC_BULK_EMAIL
_SRC_BULK_DOMAIN = _sn.SRC_BULK_DOMAIN
_SRC_PCAP_CONVERSATIONS = _sn.SRC_PCAP_CONVERSATIONS
_SRC_PCAP_DNS = _sn.SRC_PCAP_DNS
_SRC_PCAP_HTTP = _sn.SRC_PCAP_HTTP

# ---------------------------------------------------------------------------
# Shared executable name constants (used by process + persistence modules)
# ---------------------------------------------------------------------------

_EXE_POWERSHELL = "powershell.exe"
_EXE_CMD = "cmd.exe"

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_PORT_RE = re.compile(r":(\d{1,5})(?:\s|$)")
_PROC_NAME_RE = re.compile(r"^([^\t]+\.exe)", re.MULTILINE | re.IGNORECASE)
_PPID_RE = re.compile(r"(?:^|\t)(\d{1,6})\t(\d{1,6})(?:\t|$)", re.MULTILINE)

# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

_sources_cache: list[SourceRow] | None = None
_sources_cache_case_id: str | None = None
_sources_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Constants used by multiple submodules
# ---------------------------------------------------------------------------

_LATERAL_PORTS: set[int] = {445, 3389, 5985, 5986, 135}

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
    with _sources_lock:
        if _sources_cache is not None and _sources_cache_case_id == ctx.case_id:
            return _sources_cache
    sources = ctx.db.get_sources()
    with _sources_lock:
        _sources_cache = sources
        _sources_cache_case_id = ctx.case_id
    return sources


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


def _invalidate_sources_cache() -> None:
    """Clear the cached sources list so newly indexed sources are visible."""
    global _sources_cache, _sources_cache_case_id
    with _sources_lock:
        _sources_cache = None
        _sources_cache_case_id = None


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
    """Compute elapsed time, log audit, strip windows, persist, and build result.

    Centralizes the epilogue boilerplate shared by all composite tools.
    After building the result, indexes it into the case database so that
    subsequent phases can query it via ``search(query, source="composite.*")``.

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

    # Persist composite results as a searchable source
    source_name = _TOOL_SOURCE_MAP.get(tool_name)
    if source_name and result_count > 0:
        try:
            raw_output = json.dumps(results, indent=2, default=str)
            extract_and_index(
                raw_output=raw_output,
                source_name=source_name,
                source_path="composite_analysis",
                extractor_name="composite",
            )
            _invalidate_sources_cache()
        except Exception:
            logger.warning("Failed to index composite results for %s", tool_name, exc_info=True)

    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": results,
        "source": source_name,
        "result_count": result_count,
        **coverage,
    }
    if missing:
        result["missing_sources"] = missing
    return result
