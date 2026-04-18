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

from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
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

_PID_RE = re.compile(r"(?:^|\t)(\d{1,6})(?:\t|$)", re.MULTILINE)

_MODULE_NAME_RE = re.compile(r"^([^\t]+\.sys)", re.MULTILINE | re.IGNORECASE)


def _extract_pid(text: str) -> int | None:
    """Parse the first PID value from a Volatility output line."""
    m = _PID_RE.search(text)
    if m:
        val = int(m.group(1))
        if val > 0:
            return val
    return None


def _extract_pids_from_windows(windows: list[Any]) -> dict[int, list[Any]]:
    """Group windows by the PID found in their text."""
    pid_map: dict[int, list[Any]] = {}
    for w in windows:
        pid = _extract_pid(w.raw_text)
        if pid is not None:
            pid_map.setdefault(pid, []).append(w)
    return pid_map


def _extract_module_names(windows: list[Any]) -> dict[str, list[Any]]:
    """Group windows by the kernel module name found in their text."""
    mod_map: dict[str, list[Any]] = {}
    for w in windows:
        m = _MODULE_NAME_RE.search(w.raw_text)
        if m:
            name = m.group(1).strip().lower()
            mod_map.setdefault(name, []).append(w)
    return mod_map


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
def search(
    query: str,
    source: str | None = None,
    max_results: int = 50,
    regex: bool = False,
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
    """
    import re as _re

    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if regex:
        try:
            pattern = _re.compile(query, _re.IGNORECASE)
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
        while len(matches) < max_results:
            chunk, _total = ctx.db.get_windows_page(src_prefix, after_id=cursor, limit=_CHUNK)
            if not chunk:
                break
            for w in chunk:
                if pattern.search(w.raw_text):
                    matches.append(
                        {
                            "window": _truncated_window(w),
                            "source_name": source or "unknown",
                        }
                    )
                    if len(matches) >= max_results:
                        break
            cursor = chunk[-1].window_id or 0
        results = matches
    else:
        raw_matches = ctx.db.search_windows(query, source_name=source, max_results=max_results)
        results = [
            {"window": _truncated_window(w), "source_name": sname} for w, sname in raw_matches
        ]

    sources_matched = sorted({str(r["source_name"]) for r in results})

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="search",
        params={"query": query, "source": source, "max_results": max_results, "regex": regex},
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

    psscan_pids = _extract_pids_from_windows(psscan_wins)
    pslist_pids = _extract_pids_from_windows(pslist_wins)

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

    all_wins = ctx.db.get_windows_by_source(_SRC_ENVARS)
    matching = [w for w in all_wins if _extract_pid(w.raw_text) == pid]
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

    all_wins = ctx.db.get_windows_by_source(_SRC_PRIVS)
    matching = [w for w in all_wins if _extract_pid(w.raw_text) == pid]
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

    linked_mods = _extract_module_names(modules_wins)
    scanned_mods = _extract_module_names(modscan_wins)

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
    limit: int = 500,
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
        limit: Maximum number of windows to return (default 500).
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


@mcp.tool()
def decode_payload(
    data: str,
    encoding: str = "auto",
) -> dict[str, object]:
    """Safely decode an encoded payload found in evidence.

    Supports base64, hex, UTF-16LE (PowerShell -EncodedCommand), and
    Python pickle (inspection only -- never executed).  Use this instead
    of shell commands to decode suspicious strings.  Read-only and safe:
    no code is ever executed.

    Args:
        data: The encoded string to decode.
        encoding: One of ``"auto"``, ``"base64"``, ``"hex"``,
            ``"utf16le"`` (PowerShell encoded commands), or
            ``"pickle"``.  ``"auto"`` tries to detect the encoding.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"encoding": encoding, "data_length": len(data)}

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
            layers.append({"encoding": "hex", "preview": decoded[:200]})
        except (binascii.Error, ValueError) as exc:
            decoded = f"[hex decode failed: {exc}]"

    elif detected_encoding == "utf16le":
        try:
            raw_bytes = base64.b64decode(data)
            decoded = raw_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
            layers.append(
                {"encoding": "utf16le (PowerShell -EncodedCommand)", "preview": decoded[:500]}
            )
        except Exception as exc:
            decoded = f"[utf16le decode failed: {exc}]"

    elif detected_encoding == "pickle":
        decoded = _inspect_pickle(data)
        layers.append({"encoding": "pickle (inspected, NOT executed)", "preview": decoded[:500]})

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
                    {"encoding": "pickle (inspected, NOT executed)", "preview": decoded[:500]}
                )
            elif raw_bytes[:2] == b"\x1f\x8b":
                import gzip
                import io

                try:
                    decompressed = gzip.GzipFile(fileobj=io.BytesIO(raw_bytes)).read()
                    decoded = _safe_decode_bytes(decompressed)
                    layers.append({"encoding": "base64", "preview": "(binary -> gzip detected)"})
                    layers.append({"encoding": "gzip", "preview": decoded[:500]})
                except Exception:
                    decoded = _safe_decode_bytes(raw_bytes)
                    layers.append({"encoding": "base64", "preview": decoded[:200]})
            else:
                decoded = _safe_decode_bytes(raw_bytes)
                layers.append({"encoding": "base64", "preview": decoded[:200]})
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
