"""Plaso MCP tools for timeline analysis.

Ingest-time tools query pre-extracted Plaso data from the case database.
Query-time tools shell out to ``psort.py`` for ad-hoc filtered queries
against the stored ``.plaso`` file.  All tools are read-only.
"""

from __future__ import annotations

import logging
import shutil
import time
from collections.abc import Mapping
from pathlib import Path

from mulder.execution import safe_subprocess as subprocess
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    _PREVIEW_CHAR_LIMIT,
    error_response,
    hash_output,
    make_tool_call_id,
    windowed_response,
)
from mulder.server.tool_access import Role, tool_access

logger = logging.getLogger(__name__)

_SRC_PLASO_STATS = "plaso.stats"
_SRC_PLASO_TIMELINE = "plaso.timeline"

_PSORT_BIN = "psort.py"
_PSORT_TIMEOUT = 300  # 5 minutes for filtered queries
_SLICE_SIZE_SECONDS = 300  # 5-minute window for timeline slices


def _find_plaso_file() -> str:
    """Locate the persistent ``.plaso`` file from source metadata.

    Checks the ``plaso.stats`` source first (whose ``source_path`` points
    directly at the ``.plaso`` file).  Falls back to the DB-path convention
    ``{db_dir}/{case_id}.plaso``.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    for s in sources:
        if s.source_name == _SRC_PLASO_STATS:
            path = Path(s.source_path)
            if path.exists():
                return str(path)

    fallback = ctx.db.db_path.with_suffix(".plaso")
    if fallback.exists():
        return str(fallback)

    raise RuntimeError("No .plaso storage file found. Was this case ingested with Plaso?")


def _plaso_error(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    error: str,
    t0: float,
    *,
    error_is_untrusted_evidence: bool = False,
) -> dict[str, object]:
    """Build an audited plaso error response with empty results metadata."""
    resp = error_response(
        tc_id,
        tool_name,
        params,
        error,
        (time.monotonic() - t0) * 1000,
        error_is_untrusted_evidence=error_is_untrusted_evidence,
    )
    resp.update({"results": [], "source": _SRC_PLASO_TIMELINE, "result_count": 0})
    return resp


def _run_psort(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Execute a psort command, raising on timeout."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_PSORT_TIMEOUT,
        check=False,
    )


def _reduce_or_return(output: str) -> list[dict[str, str | int]]:
    """Return timeline output as a single-item result list."""
    return [{"timeline_text": output, "line_count": output.count("\n") + 1}]


def _resolve_psort_prerequisites(
    tc_id: str, tool_name: str, params: Mapping[str, object], t0: float
) -> str | dict[str, object]:
    """Check psort availability and locate the .plaso file.

    Returns the plaso file path on success, or an error response dict.
    """
    if not shutil.which(_PSORT_BIN):
        return _plaso_error(tc_id, tool_name, params, "psort.py not found on PATH", t0)
    try:
        return _find_plaso_file()
    except RuntimeError as exc:
        return _plaso_error(tc_id, tool_name, params, str(exc), t0)


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def get_plaso_stats() -> dict[str, object]:
    """Return Plaso parser hit statistics collected during ingest.

    Shows which parsers fired and how many events each produced.
    Useful for understanding which artifact types are available in
    the case timeline.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PLASO_STATS)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_PLASO_STATS, "get_plaso_stats", {}, elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def filter_timeline(
    t_start: str,
    t_end: str,
    keyword: str | None = None,
    parser: str | None = None,
) -> dict[str, object]:
    """Query the Plaso timeline with time range and optional filters.

    Runs ``psort.py`` against the stored ``.plaso`` file with a date
    filter expression.  Optionally narrow results to a specific
    *parser* (e.g. ``"winevtx"``) or grep for *keyword* in the output.
    Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"t_start": t_start, "t_end": t_end, "keyword": keyword, "parser": parser}

    prereq = _resolve_psort_prerequisites(tc_id, "filter_timeline", params, t0)
    if isinstance(prereq, dict):
        return prereq
    plaso_path = prereq

    cmd = [_PSORT_BIN, "-o", "l2tcsv"]
    filter_expr = f"date > '{t_start}' AND date < '{t_end}'"
    if parser:
        filter_expr += f" AND parser is '{parser}'"
    cmd.extend([plaso_path, filter_expr])

    try:
        proc = _run_psort(cmd)
    except subprocess.TimeoutExpired:
        return _plaso_error(
            tc_id, "filter_timeline", params, f"psort timed out after {_PSORT_TIMEOUT}s", t0
        )

    output = proc.stdout.strip()
    if proc.returncode != 0:
        stderr_preview = (proc.stderr or "")[:_PREVIEW_CHAR_LIMIT]
        return _plaso_error(
            tc_id,
            "filter_timeline",
            params,
            f"psort exited {proc.returncode}: {stderr_preview}",
            t0,
            error_is_untrusted_evidence=True,
        )

    result_count = 0
    index_summary: dict[str, object] = {}
    if output:
        if keyword:
            output = _apply_keyword_filter(output, keyword)
        if output:
            result_count = len(output.splitlines()) - 1
            index_summary = extract_and_index(output, "plaso.filtered", str(plaso_path), "psort")

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="filter_timeline",
        params=params,
        output_hash=hash_output({"result_count": result_count}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "source": _SRC_PLASO_TIMELINE,
        "source_name": "plaso.filtered",
        "result_count": result_count,
        "windows_indexed": index_summary.get("windows_indexed", 0),
        "hint": (
            "Use search(query, source='plaso.filtered') or "
            "get_raw_output('plaso.filtered') to read timeline events."
        ),
    }


def _apply_keyword_filter(output: str, keyword: str) -> str:
    """Keep only L2T CSV lines containing *keyword* (case-insensitive)."""
    kw_lower = keyword.lower()
    lines = output.splitlines()
    header = lines[0] if lines else ""
    filtered = [ln for ln in lines[1:] if kw_lower in ln.lower()]
    return "\n".join([header, *filtered]) if filtered else ""


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def export_timeline_slice(timestamp: str) -> dict[str, object]:
    """Export a 5-minute timeline slice centred on a timestamp.

    Runs ``psort.py --slice`` to produce a narrow window of events around
    the given *timestamp* (ISO-8601 format, e.g. ``2024-01-15T14:30:00``).
    Useful for quickly pivoting around a known event of interest.
    Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"timestamp": timestamp}

    prereq = _resolve_psort_prerequisites(tc_id, "export_timeline_slice", params, t0)
    if isinstance(prereq, dict):
        return prereq
    plaso_path = prereq

    cmd = [
        _PSORT_BIN,
        "-o",
        "l2tcsv",
        "--slice",
        timestamp,
        "--slice_size",
        str(_SLICE_SIZE_SECONDS),
        plaso_path,
    ]

    try:
        proc = _run_psort(cmd)
    except subprocess.TimeoutExpired:
        return _plaso_error(
            tc_id, "export_timeline_slice", params, f"psort timed out after {_PSORT_TIMEOUT}s", t0
        )

    output = proc.stdout.strip()
    if proc.returncode != 0:
        stderr_preview = (proc.stderr or "")[:_PREVIEW_CHAR_LIMIT]
        return _plaso_error(
            tc_id,
            "export_timeline_slice",
            params,
            f"psort exited {proc.returncode}: {stderr_preview}",
            t0,
            error_is_untrusted_evidence=True,
        )

    result_count = 0
    index_summary: dict[str, object] = {}
    if output:
        result_count = len(output.splitlines()) - 1
        index_summary = extract_and_index(output, "plaso.slice", str(plaso_path), "psort")

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="export_timeline_slice",
        params=params,
        output_hash=hash_output({"result_count": result_count}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "source": _SRC_PLASO_TIMELINE,
        "source_name": "plaso.slice",
        "result_count": result_count,
        "windows_indexed": index_summary.get("windows_indexed", 0),
        "hint": (
            "Use search(query, source='plaso.slice') or "
            "get_raw_output('plaso.slice') to read the timeline slice."
        ),
    }
