"""Core read-only MCP tool implementations for Mulder.

Every tool in this module is a pure query -- no destructive operations exist
in the Mulder MCP surface.  Evidence integrity is enforced by the API design,
not by prompts.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from uuid import uuid4

from mulder.server.app import get_ctx, mcp


def _make_tool_call_id() -> str:
    return f"tc_{uuid4().hex[:8]}"


def _hash_output(output: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(output, sort_keys=True, default=str).encode()).hexdigest()
    )


def _serialize_windows(windows: list) -> list[dict]:
    return [w.model_dump() for w in windows]


def _serialize_scored(scored: list) -> list[dict]:
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


def _extract_pids_from_windows(windows: list) -> dict[int, list]:
    """Group windows by the PID found in their text."""
    pid_map: dict[int, list] = {}
    for w in windows:
        pid = _extract_pid(w.raw_text)
        if pid is not None:
            pid_map.setdefault(pid, []).append(w)
    return pid_map


def _extract_module_names(windows: list) -> dict[str, list]:
    """Group windows by the kernel module name found in their text."""
    mod_map: dict[str, list] = {}
    for w in windows:
        m = _MODULE_NAME_RE.search(w.raw_text)
        if m:
            name = m.group(1).strip().lower()
            mod_map.setdefault(name, []).append(w)
    return mod_map


# ------------------------------------------------------------------
# Tool: list_sources
# ------------------------------------------------------------------


@mcp.tool()
def list_sources(case_id: str) -> dict:
    """List every evidence source ingested for this case.

    Returns source names, file paths, hash digests, extractors used,
    and line counts.  Read-only: queries the case database.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    sources = ctx.db.get_sources()
    results = [s.model_dump() for s in sources]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="list_sources",
        params={"case_id": case_id},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": None,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: search
# ------------------------------------------------------------------


@mcp.tool()
def search(
    query: str,
    k: int = 20,
    source: str | None = None,
) -> dict:
    """Semantic search across all ingested evidence.

    Embeds the free-text *query* and returns the *k* closest windows
    from the per-case vector index.  Optionally filter by *source* name.
    Read-only: no evidence is modified.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    scored = ctx.query_engine.semantic_search(query, k=k, source_name=source)
    results = _serialize_scored(scored)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="search",
        params={"query": query, "k": k, "source": source},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": source,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_anomalies_in_range
# ------------------------------------------------------------------


@mcp.tool()
def get_anomalies_in_range(
    source: str,
    t_start: str,
    t_end: str,
    top_percent: float = 0.1,
) -> dict:
    """Return the most anomalous windows from a source within a time range.

    Uses k-NN density scoring: windows whose embeddings are furthest
    from their neighbours are ranked highest.  For verbose sources the
    output is automatically reduced via Cordon.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    scored = ctx.query_engine.get_anomalies(
        source_name=source,
        time_start=t_start,
        time_end=t_end,
        top_percent=top_percent,
    )
    results = _serialize_scored(scored)

    reduced = False
    reduction_ratio: float | None = None
    raw_text = "\n".join(s.window.raw_text for s in scored)
    if ctx.reducer.should_reduce(source, len(raw_text)):
        reduced_out = ctx.reducer.reduce(raw_text, target_percentile=top_percent)
        blocks = [b.model_dump() for b in reduced_out.blocks]
        results = [{"reduced_text": reduced_out.text, "blocks": blocks}]
        reduced = True
        reduction_ratio = reduced_out.reduction_ratio

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_anomalies_in_range",
        params={"source": source, "t_start": t_start, "t_end": t_end, "top_percent": top_percent},
        output_hash=_hash_output(results),
        cordon_ratio=reduction_ratio,
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": source,
        "result_count": len(results),
        "reduced": reduced,
        "reduction_ratio": reduction_ratio,
    }


# ------------------------------------------------------------------
# Tool: correlate_across_sources
# ------------------------------------------------------------------


@mcp.tool()
def correlate_across_sources(
    t_start: str,
    t_end: str,
    sources: list[str] | None = None,
) -> dict:
    """Cross-reference evidence from multiple sources in a time window.

    For every source (or the specified subset), retrieves all windows
    whose timestamps fall within [t_start, t_end] and groups them by
    source.  Use this to answer: "at this point in time, what did each
    artifact type see?"  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    correlation = ctx.correlator.correlate_across_sources(
        time_start=t_start,
        time_end=t_end,
        sources=sources,
    )
    results = {
        "time_start": correlation.time_start,
        "time_end": correlation.time_end,
        "sources_queried": correlation.sources_queried,
        "total_windows": correlation.total_windows,
        "windows_by_source": {
            src: _serialize_windows(wins) for src, wins in correlation.windows_by_source.items()
        },
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="correlate_across_sources",
        params={"t_start": t_start, "t_end": t_end, "sources": sources},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": None,
        "result_count": correlation.total_windows,
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: baseline_for
# ------------------------------------------------------------------


@mcp.tool()
def baseline_for(source: str) -> dict:
    """Return anomaly-score distribution statistics for a source.

    Shows min, mean, median, p90, and max anomaly scores so the
    investigator can understand what "normal" looks like for this
    artifact type before hunting for outliers.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    stats = ctx.query_engine.get_baseline_stats(source)
    results = stats.model_dump()

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="baseline_for",
        params={"source": source},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": source,
        "result_count": 1,
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: list_processes_from_memory
# ------------------------------------------------------------------


@mcp.tool()
def list_processes_from_memory() -> dict:
    """List all processes captured in the memory dump (Volatility pslist).

    Returns every window from the ``volatility.pslist`` source.  This is
    typically small enough to return in full without reduction.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PSLIST)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="list_processes_from_memory",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_PSLIST,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_process_tree
# ------------------------------------------------------------------


@mcp.tool()
def get_process_tree() -> dict:
    """Return the process parent-child tree from memory (Volatility pstree).

    Shows process hierarchy as captured in the memory dump.  Useful for
    detecting suspicious parent-child relationships (e.g. cmd.exe spawned
    by svchost.exe).  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PSTREE)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_process_tree",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_PSTREE,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_eventlog_anomalies
# ------------------------------------------------------------------


@mcp.tool()
def get_eventlog_anomalies(
    channel: str,
    t_start: str,
    t_end: str,
    top_percent: float = 0.1,
) -> dict:
    """Find anomalous entries in a Windows Event Log channel.

    Scores every event in the specified *channel* (e.g. "security",
    "system") within [t_start, t_end] by k-NN density and returns
    the top outliers.  Output is always Cordon-reduced because EVTX
    channels are typically very large.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    source_name = f"evtx.{channel}"
    scored = ctx.query_engine.get_anomalies(
        source_name=source_name,
        time_start=t_start,
        time_end=t_end,
        top_percent=top_percent,
    )

    reduced = False
    reduction_ratio: float | None = None
    raw_text = "\n".join(s.window.raw_text for s in scored)
    if raw_text:
        reduced_out = ctx.reducer.reduce(raw_text, target_percentile=top_percent)
        blocks = [b.model_dump() for b in reduced_out.blocks]
        results: list[dict] = [{"reduced_text": reduced_out.text, "blocks": blocks}]
        reduced = True
        reduction_ratio = reduced_out.reduction_ratio
    else:
        results = _serialize_scored(scored)

    elapsed = (time.monotonic() - t0) * 1000
    params = {
        "channel": channel,
        "t_start": t_start,
        "t_end": t_end,
        "top_percent": top_percent,
    }
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_eventlog_anomalies",
        params=params,
        output_hash=_hash_output(results),
        cordon_ratio=reduction_ratio,
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": source_name,
        "result_count": len(results),
        "reduced": reduced,
        "reduction_ratio": reduction_ratio,
    }


# ------------------------------------------------------------------
# Tool: extract_mft_timeline
# ------------------------------------------------------------------


@mcp.tool()
def extract_mft_timeline(t_start: str, t_end: str) -> dict:
    """Extract the Plaso super-timeline for a time range.

    Plaso timelines are extremely large, so the output is always
    reduced via Cordon anomaly detection.  Only the most anomalous
    blocks are returned.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    source_name = "plaso.timeline"
    windows = ctx.query_engine.get_windows_in_range(source_name, t_start, t_end)

    reduced = False
    reduction_ratio: float | None = None
    raw_text = "\n".join(w.raw_text for w in windows)
    if raw_text:
        reduced_out = ctx.reducer.reduce(raw_text)
        blocks = [b.model_dump() for b in reduced_out.blocks]
        results: list[dict] = [{"reduced_text": reduced_out.text, "blocks": blocks}]
        reduced = True
        reduction_ratio = reduced_out.reduction_ratio
    else:
        results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="extract_mft_timeline",
        params={"t_start": t_start, "t_end": t_end},
        output_hash=_hash_output(results),
        cordon_ratio=reduction_ratio,
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": source_name,
        "result_count": len(results),
        "reduced": reduced,
        "reduction_ratio": reduction_ratio,
    }


# ------------------------------------------------------------------
# Tool: parse_prefetch
# ------------------------------------------------------------------


@mcp.tool()
def parse_prefetch() -> dict:
    """Return all parsed Windows Prefetch data.

    Prefetch files are small, so the full output is returned without
    reduction.  Shows which executables were recently run and how
    many times.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source("prefetch.all")
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_prefetch",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": "prefetch.all",
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_amcache
# ------------------------------------------------------------------


@mcp.tool()
def get_amcache() -> dict:
    """Return parsed AmCache / registry system hive data.

    Shows application execution history from the Windows registry.
    This is a small artifact returned in full.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source("registry.system")
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_amcache",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": "registry.system",
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: scan_hidden_processes
# ------------------------------------------------------------------


@mcp.tool()
def scan_hidden_processes() -> dict:
    """Detect hidden processes by comparing psscan (pool-tag scan) against pslist (linked list).

    PIDs present in psscan but absent from pslist may be hidden or unlinked
    by a rootkit.  Returns the discrepancy set with supporting evidence
    windows from psscan.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
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
            "evidence_windows": _serialize_windows(psscan_pids[pid]),
        }
        for pid in sorted(hidden_pids)
    ]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="scan_hidden_processes",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_PSSCAN,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_process_environment
# ------------------------------------------------------------------


@mcp.tool()
def get_process_environment(pid: int) -> dict:
    """Return environment variables for a specific process from memory.

    Filters Volatility envars output by *pid*.  Useful for detecting
    injected environment variables or suspicious PATH modifications.
    Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    all_wins = ctx.db.get_windows_by_source(_SRC_ENVARS)
    matching = [w for w in all_wins if _extract_pid(w.raw_text) == pid]
    results = _serialize_windows(matching)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_process_environment",
        params={"pid": pid},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_ENVARS,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_process_privileges
# ------------------------------------------------------------------


@mcp.tool()
def get_process_privileges(pid: int) -> dict:
    """Return token privileges for a specific process from memory.

    Filters Volatility privs output by *pid*.  SeDebugPrivilege or
    SeTcbPrivilege on unexpected processes is a strong indicator of
    privilege escalation.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    all_wins = ctx.db.get_windows_by_source(_SRC_PRIVS)
    matching = [w for w in all_wins if _extract_pid(w.raw_text) == pid]
    results = _serialize_windows(matching)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_process_privileges",
        params={"pid": pid},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_PRIVS,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: scan_kernel_modules
# ------------------------------------------------------------------


@mcp.tool()
def scan_kernel_modules() -> dict:
    """Detect hidden kernel modules by comparing modscan (pool-tag) against modules (linked list).

    Modules present in modscan but absent from the linked list may have
    been unlinked by a rootkit.  Returns the discrepancy set with
    supporting evidence windows.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
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
            "evidence_windows": _serialize_windows(scanned_mods[name]),
        }
        for name in sorted(hidden_names)
    ]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="scan_kernel_modules",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_MODSCAN,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_userassist
# ------------------------------------------------------------------


@mcp.tool()
def get_userassist() -> dict:
    """Return UserAssist registry entries extracted from memory.

    UserAssist tracks GUI program execution with run counts and
    timestamps.  Useful for building an execution timeline.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_USERASSIST)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_userassist",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_USERASSIST,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: scan_files_in_memory
# ------------------------------------------------------------------


@mcp.tool()
def scan_files_in_memory() -> dict:
    """Return all file objects cached in the memory dump (Volatility filescan).

    Lists every file object found via pool-tag scanning.  Useful for
    identifying files that were open or recently accessed at the time
    of capture.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_FILESCAN)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="scan_files_in_memory",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_FILESCAN,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }
