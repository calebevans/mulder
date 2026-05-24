"""Core read-only MCP tool implementations for Mulder.

Every tool in this module is a pure query -- no destructive operations exist
in the Mulder MCP surface.  Evidence integrity is enforced by the API design,
not by prompts.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
from typing import Any

from sqlalchemy import select as sa_select

from mulder.db import windows_t
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    _DEFAULT_SEARCH_LIMIT,
    _HINT_CHAR_LIMIT,
    _PREVIEW_CHAR_LIMIT,
    extract_module_names,
    extract_pid,
    extract_pids_from_windows,
    hash_output,
    make_tool_call_id,
    serialize_windows,
    windowed_response,
)

_RAW_TEXT_SEARCH_CAP = 300
_RAW_TEXT_CORRELATE_CAP = 200
_CORRELATE_WINDOW_CAP = 20


def _truncated_window(w: Any, cap: int = _RAW_TEXT_SEARCH_CAP) -> dict[str, object]:
    """Serialize a window with raw_text truncated for compact output."""
    d = w.model_dump() if hasattr(w, "model_dump") else dict(w)
    full = d.get("raw_text", "")
    if len(full) > cap:
        d["raw_text"] = full[:cap] + "..."
        d["full_text_available"] = True
    return d


def _serialize_scored(scored: list[Any]) -> list[dict[str, object]]:
    """Convert ScoredWindow objects to serializable dicts."""
    return [
        {
            "window": s.window.model_dump(),
            "score": s.score,
            "source_name": s.source_name,
        }
        for s in scored
    ]


_SRC_PSLIST = "volatility.pslist"
_SRC_PSTREE = "volatility.pstree"
_SRC_PSSCAN = "volatility.psscan"
_SRC_ENVARS = "volatility.envars"
_SRC_PRIVS = "volatility.privs"
_SRC_MODULES = "volatility.modules"
_SRC_MODSCAN = "volatility.modscan"
_SRC_USERASSIST = "volatility.userassist"
_SRC_FILESCAN = "volatility.filescan"


@mcp.tool()
def list_sources() -> dict[str, object]:
    """List every evidence source indexed for the active case.

    Returns source names, file paths, hash digests, extractors used,
    and line counts.  Initially empty for a new case -- grows as the
    agent runs Tier 2 extraction tools.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    sources = ctx.db.get_sources()
    results = [s.model_dump() for s in sources]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="list_sources",
        params={},
        output_hash=hash_output(results),
        duration_ms=elapsed,
    )
    response: dict[str, object] = {
        "tool_call_id": tc_id,
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
def get_source_stats() -> dict[str, object]:
    """Return per-source statistics for the current case.

    Shows window counts, time ranges, and whether each source is cited
    by any finding. Useful for understanding what data is available and
    identifying analysis gaps. Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

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

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_source_stats",
        params={},
        output_hash=hash_output(stats),
        duration_ms=elapsed,
    )

    cited_count = sum(1 for s in stats if s["cited_by_finding"])
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "total_sources": len(stats),
        "cited_sources": cited_count,
        "uncited_sources": len(stats) - cited_count,
        "sources": stats,
    }


@mcp.tool()
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
    """Keyword or regex search across all ingested evidence.

    Searches the raw text of all stored windows for *query*.  Use
    *source* to scope to a specific source name or prefix (e.g.
    ``"volatility.netscan"``).  Use *regex=True* for regular
    expression matching.  Read-only.

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
    import re as _re

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
        combined_pattern = "|".join(all_terms)
        _MAX_REGEX_LEN = 500
        if len(combined_pattern) > _MAX_REGEX_LEN:
            return {
                "tool_call_id": tc_id,
                "status": "error",
                "error_message": f"Regex pattern too long (max {_MAX_REGEX_LEN} chars)",
                "results": [],
                "result_count": 0,
            }
        try:
            pattern = _re.compile(combined_pattern, _re.IGNORECASE)
        except _re.error as exc:
            return {
                "tool_call_id": tc_id,
                "status": "error",
                "error_message": f"Invalid regex: {exc}",
                "results": [],
                "result_count": 0,
            }
        _CHUNK = 5000
        matches: list[dict[str, object]] = []
        cursor = 0
        src_prefix = source or ""
        source_map: dict[int, str] = {s.source_id: s.source_name for s in ctx.db.get_sources()}
        exclude_set = exclude_sources or []
        while len(matches) < max_results:
            chunk, _total = ctx.db.get_windows_page(src_prefix, after_id=cursor, limit=_CHUNK)
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
                    matches.append(
                        {
                            "window": _truncated_window(w),
                            "source_name": src_name,
                        }
                    )
                    if len(matches) >= max_results:
                        break
            cursor = chunk[-1].window_id or 0
        results = matches
    else:
        combined_fts = " OR ".join(all_terms)
        raw_matches = ctx.db.search_windows(
            combined_fts,
            source_name=source,
            max_results=max_results,
            time_start=t_start,
            time_end=t_end,
            exclude_source_names=exclude_sources,
        )
        results = [
            {"window": _truncated_window(w), "source_name": sname} for w, sname in raw_matches
        ]

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
        },
        output_hash=hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": source,
        "result_count": len(results),
        "sources_matched": sources_matched,
        "has_more": len(results) == max_results,
        "hint": "Use get_raw_output(source_name, offset, limit) to retrieve full evidence text.",
    }


@mcp.tool()
def correlate_across_sources(
    t_start: str,
    t_end: str,
    sources: list[str] | None = None,
) -> dict[str, object]:
    """Cross-reference evidence from multiple sources in a time window.

    For every source (or the specified subset), retrieves all windows
    whose timestamps fall within [t_start, t_end] and groups them by
    source.  Use this to answer: "at this point in time, what did each
    artifact type see?"  Read-only.
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
        "source": None,
        "result_count": correlation.total_windows,
        "sources_with_data": sources_with_data,
        "sources_without_data": sources_without_data,
        "hint": hint + " Use get_raw_output(source_name) for full evidence text.",
    }


@mcp.tool()
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
def scan_hidden_processes() -> dict[str, object]:
    """Detect hidden processes by comparing psscan (pool-tag scan) against pslist (linked list).

    PIDs present in psscan but absent from pslist may be hidden or unlinked
    by a rootkit.  Returns the discrepancy set with supporting evidence
    windows from psscan.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    psscan_wins = ctx.db.get_windows_by_source(_SRC_PSSCAN)
    pslist_wins = ctx.db.get_windows_by_source(_SRC_PSLIST)

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
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_PSSCAN,
        "result_count": len(results),
    }


@mcp.tool()
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
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_MODSCAN,
        "result_count": len(results),
    }


@mcp.tool()
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
def scan_files_in_memory() -> dict[str, object]:
    """Return all file objects cached in the memory dump (Volatility filescan).

    Lists every file object found via pool-tag scanning.  Useful for
    identifying files that were open or recently accessed at the time
    of capture.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_FILESCAN)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_FILESCAN, "scan_files_in_memory", {}, elapsed)


@mcp.tool()
def get_raw_output(
    source_name: str,
    after_id: int = 0,
    limit: int = _DEFAULT_SEARCH_LIMIT,
) -> dict[str, object]:
    """Retrieve raw extraction output for a source, with cursor pagination.

    Returns windows for the given source ordered by ID.  Pass
    ``after_id`` from the previous response's ``next_after_id`` to
    get the next page.  Every page is equally fast regardless of
    position in the source.

    For finding specific content in large sources, prefer
    ``search(query, source=source_name)`` over paginating.

    Args:
        source_name: Exact source name or prefix (e.g. "volatility.pslist"
            matches "volatility.pslist" and "volatility.pslist.host1").
        after_id: Cursor -- return windows with ID > this value.
            Use 0 for the first page, then pass ``next_after_id`` from
            the response to get subsequent pages.
        limit: Maximum number of windows to return.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    page, total = ctx.db.get_windows_page(source_name, after_id=after_id, limit=limit)
    raw_text = "\n".join(w.raw_text for w in page)

    next_after = page[-1].window_id if page else after_id

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_raw_output",
        params={"source_name": source_name, "after_id": after_id, "limit": limit},
        output_hash=hash_output({"total": total, "returned": len(page)}),
        duration_ms=elapsed,
    )
    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "source_name": source_name,
        "total_windows": total,
        "returned_windows": len(page),
        "next_after_id": next_after,
        "has_more": len(page) == limit,
        "raw_text": raw_text,
    }
    if total > 5000:
        result["hint"] = (
            f"This source has {total} windows. Use search(query, source='{source_name}') "
            "to find specific content efficiently instead of paginating."
        )
    return result


_MAX_DECODE_INPUT = 100_000
_MAX_DECODE_OUTPUT = 50_000

_B64_EXTRACT_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")


@mcp.tool()
def decode_payload(
    data: str = "",
    encoding: str = "auto",
    source: str | None = None,
    pattern: str | None = None,
) -> dict[str, object]:
    """Safely decode an encoded payload found in evidence.

    Supports base64, hex, UTF-16LE (PowerShell -EncodedCommand), and
    Python pickle (inspection only -- never executed).  Use this instead
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
                    if isinstance(inner_result.get("results"), dict):
                        inner_layers = inner_result["results"].get("layers", [])
                        if inner_layers:
                            layers.extend(inner_layers)
                            decoded = inner_result["results"].get("decoded", decoded)

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
def get_timeline(
    t_start: str,
    t_end: str,
    limit: int = 50,
) -> dict[str, object]:
    """Return a unified chronological timeline across all sources.

    Merges events from all indexed sources (volatility, EVTX, filesystem,
    bulk_extractor, etc.) into a single time-sorted view. Use this to
    understand what happened across ALL systems at a specific time.
    Read-only.

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
        "elapsed_ms": round(elapsed, 1),
    }
    if total_events > limit:
        response["hint"] = (
            f"Showing {limit} of {total_events} events. "
            "Narrow the time range or increase limit to see more."
        )
    return response


@mcp.tool()
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
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    bookmark_id = ctx.db.add_bookmark(window_id, source_name, note)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="bookmark_window",
        params={"window_id": window_id, "note": note, "source_name": source_name},
        output_hash=hash_output({"bookmark_id": bookmark_id}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "bookmark_id": bookmark_id,
        "window_id": window_id,
        "note": note,
        "elapsed_ms": round(elapsed, 1),
    }


@mcp.tool()
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
    for bm in bookmarks:
        entry: dict[str, object] = dict(bm)
        wid = int(str(bm["window_id"]))
        with ctx.db._engine.connect() as conn:
            row = conn.execute(sa_select(windows_t).where(windows_t.c.window_id == wid)).fetchone()
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
        "elapsed_ms": round(elapsed, 1),
    }


@mcp.tool()
def remove_bookmark(bookmark_id: int) -> dict[str, object]:
    """Remove a bookmark by ID.

    Args:
        bookmark_id: The bookmark ID to remove.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    removed = ctx.db.remove_bookmark(bookmark_id)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="remove_bookmark",
        params={"bookmark_id": bookmark_id},
        output_hash=hash_output({"removed": removed}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success" if removed else "not_found",
        "bookmark_id": bookmark_id,
        "removed": removed,
        "elapsed_ms": round(elapsed, 1),
    }
