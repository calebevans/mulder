"""Core read-only MCP tool implementations for Mulder.

Every tool in this module is a pure query; no destructive operations exist
in the Mulder MCP surface.  Evidence integrity is enforced by the API design,
not by prompts.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from sqlalchemy import select as sa_select

from mulder.db import windows_t
from mulder.security.evidence_envelope import envelope_evidence
from mulder.server import source_names as _sn
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    _DEFAULT_SEARCH_LIMIT,
    _HINT_CHAR_LIMIT,
    _PREVIEW_CHAR_LIMIT,
    audited_tool,
    extract_module_names,
    extract_pid,
    extract_pids_from_windows,
    hash_output,
    make_tool_call_id,
    serialize_windows,
    truncate_raw_text,
    windowed_response,
)
from mulder.server.tool_access import PLANNERS, Role, tool_access

logger = logging.getLogger(__name__)

_SRC_PSLIST = _sn.SRC_PSLIST
_SRC_PSTREE = _sn.SRC_PSTREE
_SRC_PSSCAN = _sn.SRC_PSSCAN
_SRC_ENVARS = _sn.SRC_ENVARS
_SRC_PRIVS = _sn.SRC_PRIVS
_SRC_MODULES = _sn.SRC_MODULES
_SRC_MODSCAN = _sn.SRC_MODSCAN
_SRC_USERASSIST = _sn.SRC_USERASSIST
_SRC_FILESCAN = _sn.SRC_FILESCAN

_RAW_TEXT_SEARCH_CAP = 300
_RAW_TEXT_CORRELATE_CAP = 200
_CORRELATE_WINDOW_CAP = 20
_MODEL_EVIDENCE_CHAR_CAP = 100_000


def _truncated_window(w: Any, cap: int = _RAW_TEXT_SEARCH_CAP) -> dict[str, object]:
    """Serialize a window with raw_text truncated for compact output."""
    d: dict[str, Any] = w.model_dump() if hasattr(w, "model_dump") else dict(w)
    truncate_raw_text(d, cap)
    return d


@mcp.tool()
@tool_access(
    Role.CATALOG
    | PLANNERS
    | Role.EXTRACT_ANALYST
    | Role.CROSS_ANALYST
    | Role.NARRATIVE_EXECUTOR
    | Role.REPORT
)
@audited_tool("list_sources")
def list_sources() -> dict[str, object]:
    """List all evidence sources currently indexed in the active case.

    Call to understand what data is available before running queries or
    submitting findings. Initially empty; grows as extraction tools run.

    Returns source names, file paths, hash digests, extractor names,
    and line counts for each indexed source.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    results = [s.model_dump() for s in sources]

    response: dict[str, object] = {
        "status": "success",
        "results": results,
        "source": None,
        "result_count": len(results),
    }
    if not results:
        response["message"] = (
            "No sources indexed yet. Use scan_evidence() to see available evidence, "
            "then run extraction tools (run_volatility, run_fls, etc.) to populate sources."
        )
    return response


@mcp.tool()
@tool_access(
    Role.CATALOG
    | Role.EXTRACT_ANALYST
    | Role.CROSS_PLANNER
    | Role.CROSS_ANALYST
    | Role.NARRATIVE_EXECUTOR
    | Role.REPORT
)
@audited_tool("get_source_stats")
def get_source_stats() -> dict[str, object]:
    """Return per-source statistics including citation coverage.

    Call during analysis to identify which sources have data and which
    are not yet cited by any finding. Helps identify analysis gaps.

    Returns window counts, time ranges, and cited_by_finding flag for
    each source, plus summary counts of cited vs uncited sources.
    """
    ctx = get_ctx()

    source_rows = ctx.db.get_source_stats()
    findings = ctx.db.get_findings()

    cited: set[str] = set()
    for f in findings:
        cited.update(f.sources)

    stats: list[dict[str, object]] = []
    for row in source_rows:
        src_name = str(row["source_name"])
        earliest = row["earliest"]
        latest = row["latest"]
        stats.append(
            {
                "source_name": src_name,
                "extractor": row["extractor"],
                "window_count": row["window_count"],
                "has_timestamps": earliest is not None,
                "time_range": {"earliest": earliest, "latest": latest},
                "cited_by_finding": src_name in cited,
            }
        )

    cited_count = sum(1 for s in stats if s["cited_by_finding"])
    return {
        "status": "success",
        "total_sources": len(stats),
        "cited_sources": cited_count,
        "uncited_sources": len(stats) - cited_count,
        "sources": stats,
    }


def _search_regex(
    db: Any,
    terms: list[str],
    source: str | None,
    exclude_sources: list[str] | None,
    t_start: str | None,
    t_end: str | None,
    max_results: int,
) -> tuple[list[dict[str, object]], int] | dict[str, object]:
    """Regex search path across ingested evidence windows.

    Returns ``(results, total_matches)`` on success, or an error dict
    if the pattern is invalid.
    """
    combined_pattern = "|".join(terms)
    _MAX_REGEX_LEN = 500
    if len(combined_pattern) > _MAX_REGEX_LEN:
        return {
            "status": "error",
            "error_message": f"Regex pattern too long (max {_MAX_REGEX_LEN} chars)",
            "results": [],
            "result_count": 0,
        }
    try:
        pattern = re.compile(combined_pattern, re.IGNORECASE)
    except re.error as exc:
        return {
            "status": "error",
            "error_message": f"Invalid regex: {exc}",
            "results": [],
            "result_count": 0,
        }

    _CHUNK = 5000
    matches: list[dict[str, object]] = []
    total_regex_matches = 0
    cursor = 0
    src_prefix = source or ""
    source_map: dict[int, str] = {s.source_id: s.source_name for s in db.get_sources()}
    exclude_set = exclude_sources or []

    while True:
        chunk, _total = db.get_windows_page(src_prefix, after_id=cursor, limit=_CHUNK)
        if not chunk:
            break
        for w in chunk:
            src_name = source_map.get(w.source_id, source or "unknown")
            if exclude_set and any(
                src_name == ex or src_name.startswith(ex + ".") for ex in exclude_set
            ):
                continue
            if t_start and w.event_time and w.event_time < t_start:
                continue
            if t_end and w.event_time and w.event_time > t_end:
                continue
            if pattern.search(w.raw_text):
                total_regex_matches += 1
                if len(matches) < max_results:
                    matches.append(
                        {
                            "window": _truncated_window(w),
                            "source_name": src_name,
                        }
                    )
        cursor = chunk[-1].window_id or 0

    return matches, total_regex_matches


def _search_fts(
    db: Any,
    terms: list[str],
    source: str | None,
    exclude_sources: list[str] | None,
    t_start: str | None,
    t_end: str | None,
    max_results: int,
) -> tuple[list[dict[str, object]], int]:
    """Full-text search path using the database FTS index.

    Returns ``(results, total_matches)``.
    """
    combined_fts = " OR ".join(terms)
    total_matches = db.count_search_windows(
        combined_fts,
        source_name=source,
        time_start=t_start,
        time_end=t_end,
        exclude_source_names=exclude_sources,
    )
    raw_matches = db.search_windows(
        combined_fts,
        source_name=source,
        max_results=max_results,
        time_start=t_start,
        time_end=t_end,
        exclude_source_names=exclude_sources,
    )
    results = [{"window": _truncated_window(w), "source_name": sname} for w, sname in raw_matches]
    return results, total_matches


@mcp.tool()
@tool_access(
    Role.EXTRACT_ANALYST
    | Role.CROSS_EXECUTOR
    | Role.CROSS_ANALYST
    | Role.NARRATIVE_EXECUTOR
    | Role.NARRATIVE_ANALYST
    | Role.REPORT
)
def search(
    query: str = "",
    source: str | None = None,
    max_results: int = 50,
    regex: bool = False,
    t_start: str | None = None,
    t_end: str | None = None,
    queries: list[str] | None = None,
    exclude_sources: list[str] | None = None,
) -> dict[str, object]:
    """Search all ingested evidence for keywords or regex patterns.

    Call after extraction tools have indexed evidence. Use the source
    parameter to scope to a specific source (e.g.
    ``source='volatility.netscan'``). For large sources, prefer this
    over paginating get_raw_output.

    IMPORTANT: Before asserting any factual claim in a finding, search
    for the specific artifact you are citing. Zero results means the
    claim is unsupported by indexed evidence.

    Common forensic search patterns:
    - Network: search(query='192.168', source='volatility.netscan')
    - Registry: search(query='UserAuthentication', source='registry.system')
    - Process: search(query='svchost', source='volatility.pslist')
    - Lateral movement: search(queries=['psexec', 'wmic', 'winrm'])
    - Time-bounded: search(query='4625', t_start='...', t_end='...')

    Returns matching windows with source names, match counts, and
    truncated raw text. Use get_raw_output(source_name) for full content.

    Args:
        query: Search term (substring match) or regex pattern.
        source: Optional source name or prefix to scope the search.
        max_results: Maximum number of matching windows to return.
        regex: If True, treat *query* as a Python regex pattern.
        t_start: Optional ISO 8601 start time to filter results.
        t_end: Optional ISO 8601 end time to filter results.
        queries: Optional list of search terms. Matches windows containing
            ANY of the terms. Combines with query if both provided.
        exclude_sources: Optional list of source name prefixes to exclude
            from results (e.g. ["tsk.filelist"] to skip file listings).
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    all_terms: list[str] = list(queries) if queries else []
    if query:
        all_terms.append(query)
    if not all_terms:
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": "At least one of query or queries must be provided.",
            "results": [],
            "result_count": 0,
        }

    if regex:
        outcome = _search_regex(
            ctx.db, all_terms, source, exclude_sources, t_start, t_end, max_results
        )
        if isinstance(outcome, dict):
            outcome["tool_call_id"] = tc_id
            return outcome
        results, total_matches = outcome
    else:
        results, total_matches = _search_fts(
            ctx.db, all_terms, source, exclude_sources, t_start, t_end, max_results
        )

    sources_matched = sorted({str(r["source_name"]) for r in results})

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="search",
        params={
            "query": query,
            "source": source,
            "max_results": max_results,
            "regex": regex,
            "t_start": t_start,
            "t_end": t_end,
            "queries": queries,
            "exclude_sources": exclude_sources,
            "returned_window_ids": [
                window_id
                for result in results
                if type(window_id := result.get("window_id")) is int and window_id > 0
            ],
            "sources": sources_matched,
        },
        output_hash=hash_output(results),
        duration_ms=elapsed,
    )
    remaining = max(0, total_matches - len(results))
    response: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": source,
        "result_count": len(results),
        "total_matches": total_matches,
        "returned": len(results),
        "has_more": total_matches > len(results),
        "remaining": remaining,
        "sources_matched": sources_matched,
        "returned_window_ids": [
            window_id
            for result in results
            if type(window_id := result.get("window_id")) is int and window_id > 0
        ],
        "hint": "Use get_raw_output(source_name, offset, limit) to retrieve full evidence text.",
    }
    if remaining > 0:
        response["hint"] = (
            f"Showing {len(results)} of {total_matches} matches "
            f"({remaining} remaining). Increase max_results or narrow with "
            "source/time filters to see more. "
            "Use get_raw_output(source_name, offset, limit) to retrieve full evidence text."
        )
    return response


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR)
def correlate_across_sources(
    t_start: str,
    t_end: str,
    sources: list[str] | None = None,
) -> dict[str, object]:
    """Cross-reference all evidence sources within a time window.

    Call during cross-system analysis to answer: "what did each artifact
    type observe during this time period?" Requires multiple sources to
    have timestamped data indexed.

    Returns windows grouped by source, with counts of sources with and
    without data in the range. Use get_raw_output() for full text of
    interesting windows.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    correlation = ctx.correlator.correlate_across_sources(
        time_start=t_start,
        time_end=t_end,
        sources=sources,
    )

    sources_with_data = sorted(correlation.windows_by_source.keys())
    sources_without_data = sorted(set(correlation.sources_queried) - set(sources_with_data))
    all_source_names = [s.source_name for s in ctx.db.get_sources()]
    unindexed = sorted(set(all_source_names) - set(correlation.sources_queried))

    n_with = len(sources_with_data)
    n_queried = len(correlation.sources_queried)
    hint_parts = [f"{n_with} of {n_queried} indexed sources had data in this time window."]
    if sources_without_data:
        hint_parts.append(f"Sources without data in range: {sources_without_data[:10]}.")
    if unindexed:
        hint_parts.append(
            f"{len(unindexed)} other source(s) exist but were not queried. "
            "Consider running additional extractions to fill gaps."
        )
    hint = " ".join(hint_parts)

    slimmed_by_source: dict[str, Any] = {}
    for src, wins in correlation.windows_by_source.items():
        total_for_src = len(wins)
        capped = wins[:_CORRELATE_WINDOW_CAP]
        slimmed_by_source[src] = {
            "windows": [_truncated_window(w, cap=_RAW_TEXT_CORRELATE_CAP) for w in capped],
            "total_windows": total_for_src,
            "truncated": total_for_src > _CORRELATE_WINDOW_CAP,
        }

    results = {
        "time_start": correlation.time_start,
        "time_end": correlation.time_end,
        "sources_queried": correlation.sources_queried,
        "total_windows": correlation.total_windows,
        "windows_by_source": slimmed_by_source,
    }

    # Index results so later phases can search them
    from mulder.server.extract_helpers import extract_and_index

    source_name = "composite.correlation"
    try:
        extract_and_index(
            raw_output=json.dumps(results, default=str),
            source_name=source_name,
            source_path="correlate_across_sources",
            extractor_name="composite",
        )
    except Exception:
        logger.debug("Failed to index correlation results", exc_info=True)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="correlate_across_sources",
        params={"t_start": t_start, "t_end": t_end, "sources": sources},
        output_hash=hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": source_name,
        "result_count": correlation.total_windows,
        "sources_with_data": sources_with_data,
        "sources_without_data": sources_without_data,
        "hint": hint + " Use get_raw_output(source_name) for full evidence text.",
    }


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR)
def list_processes_from_memory() -> dict[str, object]:
    """List all processes captured in the memory dump (Volatility pslist).

    Returns every window from the ``volatility.pslist`` source.  This is
    typically small enough to return in full without reduction.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PSLIST)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(
        tc_id, windows, _SRC_PSLIST, "list_processes_from_memory", {}, elapsed
    )


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR)
def get_process_tree() -> dict[str, object]:
    """Return the process parent-child tree from memory (Volatility pstree).

    Shows process hierarchy as captured in the memory dump.  Useful for
    detecting suspicious parent-child relationships (e.g. cmd.exe spawned
    by svchost.exe).  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PSTREE)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_PSTREE, "get_process_tree", {}, elapsed)


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR)
def get_eventlog_anomalies(
    channel: str,
    t_start: str,
    t_end: str,
    top_percent: float = 0.1,
) -> dict[str, object]:
    """Find anomalous entries in a Windows Event Log channel.

    Scores every event in the specified *channel* (e.g. "security",
    "system") within [t_start, t_end] by k-NN density and returns
    the top outliers.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    source_name = f"evtx.{channel}"
    windows = ctx.db.get_windows_by_source(source_name, t_start, t_end)
    elapsed = (time.monotonic() - t0) * 1000
    params = {
        "channel": channel,
        "t_start": t_start,
        "t_end": t_end,
        "top_percent": top_percent,
    }
    return windowed_response(
        tc_id, windows, source_name, "get_eventlog_anomalies", params, elapsed
    )


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR | Role.CROSS_ANALYST)
def extract_mft_timeline(t_start: str, t_end: str) -> dict[str, object]:
    """Extract the Plaso super-timeline for a time range.

    Only the most relevant blocks are returned.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    source_name = "plaso.timeline"
    windows = ctx.db.get_windows_by_source(source_name, t_start, t_end)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(
        tc_id,
        windows,
        source_name,
        "extract_mft_timeline",
        {"t_start": t_start, "t_end": t_end},
        elapsed,
    )


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR | Role.CROSS_ANALYST)
def parse_prefetch() -> dict[str, object]:
    """Return all parsed Windows Prefetch data.

    Prefetch files are small, so the full output is returned without
    reduction.  Shows which executables were recently run and how
    many times.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source("prefetch.all")
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, "prefetch.all", "parse_prefetch", {}, elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR | Role.CROSS_ANALYST)
def get_amcache() -> dict[str, object]:
    """Return parsed AmCache / registry system hive data.

    Shows application execution history from the Windows registry.
    This is a small artifact returned in full.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source("registry.system")
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, "registry.system", "get_amcache", {}, elapsed)


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR)
def scan_hidden_processes() -> dict[str, object]:
    """Detect processes hidden from the linked list by comparing psscan against pslist.

    Call after run_volatility_batch has indexed both pslist and psscan
    plugins. PIDs present only in psscan may be unlinked by a rootkit.

    Returns the discrepancy set with supporting evidence windows from
    psscan. Empty results when psscan or pslist data is not yet indexed.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    psscan_wins = ctx.db.get_windows_by_source(_SRC_PSSCAN)
    pslist_wins = ctx.db.get_windows_by_source(_SRC_PSLIST)

    if not psscan_wins and not pslist_wins:
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="scan_hidden_processes",
            params={},
            output_hash=hash_output([]),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "success",
            "results": [],
            "source": _SRC_PSSCAN,
            "result_count": 0,
            "hint": (
                "No pslist or psscan data indexed yet. Run "
                "run_volatility_batch(['pslist', 'psscan'], memory_path) first."
            ),
        }

    psscan_pids = extract_pids_from_windows(psscan_wins)
    pslist_pids = extract_pids_from_windows(pslist_wins)

    hidden_pids = set(psscan_pids) - set(pslist_pids)
    results = [
        {
            "pid": pid,
            "source": _SRC_PSSCAN,
            "evidence_windows": serialize_windows(psscan_pids[pid], cap=10),
        }
        for pid in sorted(hidden_pids)
    ]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="scan_hidden_processes",
        params={},
        output_hash=hash_output(results),
        duration_ms=elapsed,
    )
    response: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_PSSCAN,
        "result_count": len(results),
    }
    if not psscan_wins:
        response["hint"] = (
            "psscan data not indexed. Run "
            "run_volatility('psscan', memory_path) to enable full comparison."
        )
    return response


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR | Role.CROSS_ANALYST)
def get_process_environment(pid: int) -> dict[str, object]:
    """Return environment variables for a specific process from memory.

    Filters Volatility envars output by *pid*.  Useful for detecting
    injected environment variables or suspicious PATH modifications.
    Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    pid_str = str(pid)
    search_results = ctx.db.search_windows(pid_str, source_name=_SRC_ENVARS)
    matching = [row[0] for row in search_results if extract_pid(row[0].raw_text) == pid]
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(
        tc_id, matching, _SRC_ENVARS, "get_process_environment", {"pid": pid}, elapsed
    )


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR | Role.CROSS_ANALYST)
def get_process_privileges(pid: int) -> dict[str, object]:
    """Return token privileges for a specific process from memory.

    Filters Volatility privs output by *pid*.  SeDebugPrivilege or
    SeTcbPrivilege on unexpected processes is a strong indicator of
    privilege escalation.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    pid_str = str(pid)
    search_results = ctx.db.search_windows(pid_str, source_name=_SRC_PRIVS)
    matching = [row[0] for row in search_results if extract_pid(row[0].raw_text) == pid]
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(
        tc_id, matching, _SRC_PRIVS, "get_process_privileges", {"pid": pid}, elapsed
    )


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR)
def scan_kernel_modules() -> dict[str, object]:
    """Detect hidden kernel modules by comparing modscan (pool-tag) against modules (linked list).

    Modules present in modscan but absent from the linked list may have
    been unlinked by a rootkit.  Returns the discrepancy set with
    supporting evidence windows.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    modules_wins = ctx.db.get_windows_by_source(_SRC_MODULES)
    modscan_wins = ctx.db.get_windows_by_source(_SRC_MODSCAN)

    if not modules_wins and not modscan_wins:
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="scan_kernel_modules",
            params={},
            output_hash=hash_output([]),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "success",
            "results": [],
            "source": _SRC_MODSCAN,
            "result_count": 0,
            "hint": (
                "No modules or modscan data indexed yet. Run "
                "run_volatility_batch(['modules', 'modscan'], memory_path) first."
            ),
        }

    linked_mods = extract_module_names(modules_wins)
    scanned_mods = extract_module_names(modscan_wins)

    hidden_names = set(scanned_mods) - set(linked_mods)
    results = [
        {
            "module_name": name,
            "source": _SRC_MODSCAN,
            "evidence_windows": serialize_windows(scanned_mods[name], cap=10),
        }
        for name in sorted(hidden_names)
    ]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="scan_kernel_modules",
        params={},
        output_hash=hash_output(results),
        duration_ms=elapsed,
    )
    response: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_MODSCAN,
        "result_count": len(results),
    }
    if not modscan_wins:
        response["hint"] = (
            "modscan data not indexed. Run "
            "run_volatility('modscan', memory_path) to enable full comparison."
        )
    return response


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR | Role.CROSS_ANALYST)
def get_userassist() -> dict[str, object]:
    """Return UserAssist registry entries extracted from memory.

    UserAssist tracks GUI program execution with run counts and
    timestamps.  Useful for building an execution timeline.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_USERASSIST)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_USERASSIST, "get_userassist", {}, elapsed)


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR | Role.CROSS_ANALYST)
def scan_files_in_memory() -> dict[str, object]:
    """Return a summary of file objects cached in the memory dump (Volatility filescan).

    Lists every file object found via pool-tag scanning.  Returns a
    count and sample of file paths rather than full window content.
    Use ``search(query, source='volatility.filescan')`` to find
    specific files or ``get_raw_output('volatility.filescan')`` to
    paginate through the full listing.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_FILESCAN)
    total_entries = sum(w.raw_text.count("\n") + 1 for w in windows)

    sample_paths: list[str] = []
    for w in windows[:10]:
        for line in w.raw_text.split("\n"):
            stripped = line.strip()
            if stripped and len(sample_paths) < 20:
                sample_paths.append(stripped[:200])

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="scan_files_in_memory",
        params={},
        output_hash=hash_output({"total": len(windows)}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "source": _SRC_FILESCAN,
        "total_windows": len(windows),
        "approx_file_count": total_entries,
        "sample_paths": sample_paths,
        "hint": (
            f"{total_entries} file objects found in memory. "
            f"Use search(query, source='volatility.filescan') to find specific files, "
            f"or get_raw_output('volatility.filescan') to paginate the full listing."
        ),
    }


@mcp.tool()
@tool_access(
    Role.EXTRACT_ANALYST
    | Role.CROSS_EXECUTOR
    | Role.CROSS_ANALYST
    | Role.NARRATIVE_EXECUTOR
    | Role.NARRATIVE_ANALYST
    | Role.REPORT
)
@audited_tool("get_raw_output")
def get_raw_output(
    source_name: str,
    after_id: int = 0,
    limit: int = _DEFAULT_SEARCH_LIMIT,
) -> dict[str, object]:
    """Retrieve full raw text from a specific evidence source with cursor pagination.

    Call when you need to read the complete output from an extraction
    tool (e.g. volatility.pslist, tsk.filelist). For finding specific
    content in large sources, prefer search(query, source=source_name).

    Returns raw_text with keyset pagination. Pass ``next_after_id`` from
    the response to get subsequent pages. Every page is equally fast
    regardless of position.

    Args:
        source_name: Exact source name or prefix (e.g. "volatility.pslist"
            matches "volatility.pslist" and "volatility.pslist.host1").
        after_id: Cursor for keyset pagination; return windows with ID > this value.
            Use 0 for the first page, then pass ``next_after_id`` from
            the response to get subsequent pages.
        limit: Maximum number of windows to return.
    """
    ctx = get_ctx()
    page, total = ctx.db.get_windows_page(source_name, after_id=after_id, limit=limit)
    raw_text = "\n".join(w.raw_text for w in page)

    next_after = page[-1].window_id if page else after_id
    window_ids = [w.window_id for w in page if w.window_id is not None]
    selector = json.dumps(
        {
            "after_window_id": after_id,
            "returned_window_ids": window_ids,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    envelope = envelope_evidence(
        raw_text,
        source_id=source_name,
        source_name=source_name,
        source_record_ids=[w.source_id for w in page],
        selector=selector,
        max_characters=_MODEL_EVIDENCE_CHAR_CAP,
    )
    model_representation = envelope.for_model()

    result: dict[str, object] = {
        "status": "success",
        "source_name": source_name,
        "total_windows": total,
        "returned_windows": len(page),
        "returned_window_ids": window_ids,
        "next_after_id": next_after,
        "has_more": len(page) == limit,
        # Backwards-compatible string field, now carrying a delimited JSON
        # packet rather than executable-looking evidence text.  The complete
        # raw value remains unchanged in the case DB and committed by digest.
        "raw_text": envelope.to_model_packet(),
        "evidence_envelope": model_representation.model_dump(
            mode="json", exclude={"content"}
        ),
    }
    if envelope.truncation.truncated:
        result["content_truncated"] = True
        result["hint"] = (
            "This evidence page exceeded the model presentation cap. "
            "Use search() to narrow the evidence or request fewer windows; "
            "the envelope digest still commits to the complete page."
        )
    if total > 5000:
        scale_hint = (
            f"This source has {total} windows. Use search(query, source='{source_name}') "
            "to find specific content efficiently instead of paginating."
        )
        result["hint"] = f"{result.get('hint', '')} {scale_hint}".strip()
    return result


_MAX_DECODE_INPUT = 100_000
_MAX_DECODE_OUTPUT = 50_000

_B64_EXTRACT_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR)
def decode_payload(
    data: str = "",
    encoding: str = "auto",
    source: str | None = None,
    pattern: str | None = None,
) -> dict[str, object]:
    """Safely decode an encoded payload found in evidence.

    Supports base64, hex, UTF-16LE (PowerShell -EncodedCommand), and
    Python pickle (inspection only, never executed).  Use this instead
    of shell commands to decode suspicious strings.  Read-only and safe:
    no code is ever executed.

    Can also extract encoded strings directly from indexed evidence when
    ``source`` is provided, removing the need for shell commands like
    grep or tail.

    Args:
        data: The encoded string to decode.  May be empty when ``source``
            is provided (the encoded string is extracted from the matching
            evidence window).
        encoding: One of ``"auto"``, ``"base64"``, ``"hex"``,
            ``"utf16le"`` (PowerShell encoded commands), or
            ``"pickle"``.  ``"auto"`` tries to detect the encoding.
        source: Optional indexed source name (e.g. ``"read_evidence"``).
            When provided with an empty ``data``, searches the source for
            ``pattern`` and extracts the longest base64-like substring
            from the first match.
        pattern: Search pattern within the source.  Required when
            ``source`` is provided and ``data`` is empty.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    extraction_meta: dict[str, object] = {}

    if source and not data:
        if not pattern:
            return {
                "tool_call_id": tc_id,
                "status": "error",
                "error_message": "pattern is required when source is provided and data is empty",
            }
        hits = ctx.db.search_windows(pattern, source_name=source, max_results=5)
        if not hits:
            return {
                "tool_call_id": tc_id,
                "status": "error",
                "error_message": f"No matches for pattern '{pattern}' in source '{source}'",
            }
        best_match = ""
        for window, src_name in hits:
            candidates = _B64_EXTRACT_RE.findall(window.raw_text)
            if candidates:
                longest = max(candidates, key=len)
                if len(longest) > len(best_match):
                    best_match = longest
                    extraction_meta = {
                        "extracted_from_source": src_name,
                        "extracted_length": len(longest),
                        "window_line_start": window.line_start,
                        "search_pattern": pattern,
                    }
        if not best_match:
            return {
                "tool_call_id": tc_id,
                "status": "error",
                "error_message": (
                    f"Found matches for '{pattern}' in '{source}'"
                    " but no base64-like substring detected"
                ),
            }
        data = best_match

    params = {"encoding": encoding, "data_length": len(data)}
    if extraction_meta:
        params["extraction"] = extraction_meta

    if len(data) > _MAX_DECODE_INPUT:
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"Input too large ({len(data)} chars, max {_MAX_DECODE_INPUT})",
        }

    data = data.strip()
    decoded: str | None = None
    detected_encoding: str = encoding
    layers: list[dict[str, str]] = []

    if encoding == "auto":
        detected_encoding = _detect_encoding(data)

    raw_bytes: bytes | None = None

    if detected_encoding == "hex":
        try:
            raw_bytes = binascii.unhexlify(data)
            decoded = _safe_decode_bytes(raw_bytes)
            layers.append({"encoding": "hex", "preview": decoded[:_HINT_CHAR_LIMIT]})
        except (binascii.Error, ValueError) as exc:
            decoded = f"[hex decode failed: {exc}]"

    elif detected_encoding == "utf16le":
        try:
            raw_bytes = base64.b64decode(data)
            decoded = raw_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
            layers.append(
                {
                    "encoding": "utf16le (PowerShell -EncodedCommand)",
                    "preview": decoded[:_PREVIEW_CHAR_LIMIT],
                }
            )
        except Exception as exc:
            decoded = f"[utf16le decode failed: {exc}]"

    elif detected_encoding == "pickle":
        decoded = _inspect_pickle(data)
        layers.append(
            {
                "encoding": "pickle (inspected, NOT executed)",
                "preview": decoded[:_PREVIEW_CHAR_LIMIT],
            }
        )

    elif detected_encoding == "base64":
        try:
            raw_bytes = base64.b64decode(data)
        except (binascii.Error, ValueError) as exc:
            decoded = f"[base64 decode failed: {exc}]"

        if raw_bytes is not None:
            if raw_bytes[:2] == b"\x80\x04" or raw_bytes[:2] == b"\x80\x05":
                layers.append({"encoding": "base64", "preview": "(binary -> pickle detected)"})
                decoded = _inspect_pickle_bytes(raw_bytes)
                layers.append(
                    {
                        "encoding": "pickle (inspected, NOT executed)",
                        "preview": decoded[:_PREVIEW_CHAR_LIMIT],
                    }
                )
            elif raw_bytes[:2] == b"\x1f\x8b":
                import gzip
                import io

                try:
                    decompressed = gzip.GzipFile(fileobj=io.BytesIO(raw_bytes)).read()
                    decoded = _safe_decode_bytes(decompressed)
                    layers.append({"encoding": "base64", "preview": "(binary -> gzip detected)"})
                    layers.append({"encoding": "gzip", "preview": decoded[:_PREVIEW_CHAR_LIMIT]})
                except Exception:
                    decoded = _safe_decode_bytes(raw_bytes)
                    layers.append({"encoding": "base64", "preview": decoded[:_HINT_CHAR_LIMIT]})
            else:
                decoded = _safe_decode_bytes(raw_bytes)
                layers.append({"encoding": "base64", "preview": decoded[:_HINT_CHAR_LIMIT]})
                inner = _detect_encoding(decoded)
                if inner != "base64" and inner != "unknown":
                    inner_result = decode_payload(decoded, encoding=inner)
                    inner_results = inner_result.get("results")
                    if isinstance(inner_results, dict):
                        inner_layers = inner_results.get("layers", [])
                        if inner_layers:
                            layers.extend(inner_layers)
                            decoded = inner_results.get("decoded", decoded)

    else:
        decoded = f"[unknown encoding: {detected_encoding}]"

    if decoded and len(decoded) > _MAX_DECODE_OUTPUT:
        decoded = decoded[:_MAX_DECODE_OUTPUT] + f"\n... [truncated at {_MAX_DECODE_OUTPUT} chars]"

    results: dict[str, object] = {
        "detected_encoding": detected_encoding,
        "layers": layers,
        "decoded": decoded,
        "decoded_length": len(decoded) if decoded else 0,
    }
    if extraction_meta:
        results["extraction"] = extraction_meta

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="decode_payload",
        params=params,
        output_hash=hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
    }


def _detect_encoding(data: str) -> str:
    """Best-effort encoding detection from the raw string."""
    stripped = data.strip()

    if stripped.startswith(("gASV", "gAST", "gANV")):
        return "pickle"

    if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) % 2 == 0 and len(stripped) >= 8:
        return "hex"

    try:
        raw = base64.b64decode(stripped, validate=True)
        if len(raw) >= 4:
            if raw[:2] in (b"\xff\xfe", b"\x00\x00") or b"\x00" in raw[:20]:
                return "utf16le"
            return "base64"
    except Exception:
        pass

    return "unknown"


def _safe_decode_bytes(raw: bytes) -> str:
    """Decode bytes to text, preferring UTF-8 with latin-1 fallback."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _inspect_pickle(b64_data: str) -> str:
    """Decode base64 pickle and disassemble it without executing."""
    try:
        raw = base64.b64decode(b64_data)
        return _inspect_pickle_bytes(raw)
    except Exception as exc:
        return f"[pickle inspection failed: {exc}]"


def _inspect_pickle_bytes(raw: bytes) -> str:
    """Disassemble pickle bytes without executing them."""
    import io
    import pickletools

    out = io.StringIO()
    try:
        pickletools.dis(io.BytesIO(raw), out, annotate=1)
        disasm = out.getvalue()
    except Exception as exc:
        text = _safe_decode_bytes(raw)
        return f"[pickle disassembly failed: {exc}]\nRaw text preview:\n{text[:2000]}"

    text_fragments: list[str] = []
    for line in disasm.splitlines():
        for match in re.finditer(r"'([^']{4,})'", line):
            text_fragments.append(match.group(1))

    result = ""
    if text_fragments:
        result = "Embedded strings:\n" + "\n".join(f"  {s}" for s in text_fragments[:50])
    result += "\n\nPickle disassembly:\n" + disasm
    return result


_TIMELINE_TEXT_CAP = 500


@mcp.tool()
@tool_access(
    Role.EXTRACT_ANALYST
    | Role.CROSS_PLANNER
    | Role.CROSS_EXECUTOR
    | Role.CROSS_ANALYST
    | Role.NARRATIVE_PLANNER
    | Role.NARRATIVE_EXECUTOR
    | Role.NARRATIVE_ANALYST
    | Role.REPORT
)
def get_timeline(
    t_start: str,
    t_end: str,
    limit: int = 50,
) -> dict[str, object]:
    """Merge events from all indexed sources into a single chronological view.

    Call during cross-system analysis when you need to understand what
    happened across ALL artifact types at a specific time. Requires at
    least some extraction tools to have indexed timestamped data.

    Returns time-sorted events with source_name and truncated raw_text.
    Narrow the time range or increase limit when results are truncated.

    Args:
        t_start: ISO 8601 start time.
        t_end: ISO 8601 end time.
        limit: Maximum events to return (default 50).
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    grouped = ctx.db.get_windows_by_time_range(t_start, t_end)

    flat: list[dict[str, object]] = []
    for source_name, windows in grouped.items():
        for w in windows:
            raw = w.raw_text
            if len(raw) > _TIMELINE_TEXT_CAP:
                raw = raw[:_TIMELINE_TEXT_CAP] + "..."
            flat.append(
                {
                    "event_time": w.event_time,
                    "source_name": source_name,
                    "raw_text": raw,
                    "window_id": w.window_id,
                }
            )

    flat.sort(key=lambda e: str(e.get("event_time") or ""))
    total_events = len(flat)
    capped = flat[:limit]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_timeline",
        params={"t_start": t_start, "t_end": t_end, "limit": limit},
        output_hash=hash_output(capped),
        duration_ms=elapsed,
    )

    response: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "results": capped,
        "result_count": len(capped),
        "total_events": total_events,
        "has_more": total_events > limit,
        "sources_represented": sorted({str(e["source_name"]) for e in capped}),
    }
    if total_events > limit:
        response["hint"] = (
            f"Showing {limit} of {total_events} events. "
            "Narrow the time range or increase limit to see more."
        )
    return response


@mcp.tool()
@tool_access(
    Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR | Role.CROSS_ANALYST | Role.NARRATIVE_ANALYST
)
@audited_tool("bookmark_window")
def bookmark_window(
    window_id: int,
    note: str,
    source_name: str = "",
) -> dict[str, object]:
    """Bookmark a specific window for later review.

    Use this to flag interesting evidence that doesn't yet warrant a
    full finding. Bookmarks persist in the database and survive context
    compaction. Review bookmarks later with get_bookmarks(). Read-only
    on evidence (writes only to case DB metadata).

    Args:
        window_id: The window_id to bookmark.
        note: Why this window is interesting.
        source_name: Source name for context (optional).
    """
    ctx = get_ctx()
    bookmark_id = ctx.db.add_bookmark(window_id, source_name, note)

    return {
        "status": "success",
        "bookmark_id": bookmark_id,
        "window_id": window_id,
        "note": note,
    }


@mcp.tool()
@tool_access(Role.CROSS_PLANNER | Role.CROSS_ANALYST | Role.REPORT)
def get_bookmarks() -> dict[str, object]:
    """Retrieve all bookmarked windows with their notes.

    Returns bookmarks created during this investigation, including the
    window content and the note explaining why it was flagged. Use this
    after context compaction to recover interesting leads. Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    bookmarks = ctx.db.get_bookmarks()

    enriched: list[dict[str, object]] = []
    window_ids = [int(str(bm["window_id"])) for bm in bookmarks]
    window_map: dict[int, Any] = {}
    if window_ids:
        with ctx.db._engine.connect() as conn:
            rows = conn.execute(
                sa_select(windows_t).where(windows_t.c.window_id.in_(window_ids))
            ).fetchall()
        window_map = {row.window_id: row for row in rows}

    for bm in bookmarks:
        entry: dict[str, object] = dict(bm)
        wid = int(str(bm["window_id"]))
        row = window_map.get(wid)
        if row:
            raw = row.raw_text
            if len(raw) > _TIMELINE_TEXT_CAP:
                raw = raw[:_TIMELINE_TEXT_CAP] + "..."
            entry["raw_text"] = raw
            entry["event_time"] = row.event_time
        enriched.append(entry)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_bookmarks",
        params={},
        output_hash=hash_output(enriched),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": enriched,
        "result_count": len(enriched),
    }


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_ANALYST | Role.NARRATIVE_ANALYST)
@audited_tool("remove_bookmark")
def remove_bookmark(bookmark_id: int) -> dict[str, object]:
    """Remove a bookmark by ID.

    Args:
        bookmark_id: The bookmark ID to remove.
    """
    ctx = get_ctx()
    removed = ctx.db.remove_bookmark(bookmark_id)

    return {
        "status": "success" if removed else "not_found",
        "bookmark_id": bookmark_id,
        "removed": removed,
    }


_TOOL_GUIDE_PATH = Path(__file__).resolve().parent.parent / "data" / "tool_guide.json"

_ToolGuide = dict[str, list[dict[str, str | list[str]]]]


def _load_tool_guide() -> _ToolGuide:
    """Load the tool reference guide from the JSON data file."""
    with open(_TOOL_GUIDE_PATH) as f:
        guide: _ToolGuide = json.load(f)
    return guide


_TOOL_GUIDE = _load_tool_guide()
_VALID_CATEGORIES = frozenset(_TOOL_GUIDE.keys())


@mcp.tool()
@tool_access(Role.CROSS_PLANNER)
def get_tool_guide(category: str = "all") -> dict[str, object]:
    """Return a reference guide of available forensic tools and their relationships.

    Call this when you need to decide which tools to run next for a
    given evidence type, or to understand dependencies between tools.

    Args:
        category: Filter by category. Options: "all", "case_management",
            "evidence_browsing", "memory", "disk", "windows", "network",
            "browser_forensics", "mobile", "macos", "malware_analysis",
            "encryption", "composite", "reporting", "post_extraction",
            "reference".
    """
    if category == "all":
        return {
            "status": "success",
            "categories": list(_TOOL_GUIDE.keys()),
            "guide": _TOOL_GUIDE,
        }

    if category not in _VALID_CATEGORIES:
        return {
            "status": "error",
            "error_message": (
                f"Unknown category: {category!r}. "
                f"Valid options: 'all', {sorted(_VALID_CATEGORIES)}"
            ),
        }

    return {
        "status": "success",
        "category": category,
        "tools": _TOOL_GUIDE[category],
    }
