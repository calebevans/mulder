"""Plaso MCP tools for timeline analysis.

Ingest-time tools query pre-extracted Plaso data from the case database.
Query-time tools shell out to ``psort.py`` for ad-hoc filtered queries
against the stored ``.plaso`` file.  All tools are read-only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from mulder.server.app import get_ctx, mcp

logger = logging.getLogger(__name__)

_SRC_PLASO_STATS = "plaso.stats"
_SRC_PLASO_TIMELINE = "plaso.timeline"

_PSORT_BIN = "psort.py"
_PSORT_TIMEOUT = 300  # 5 minutes for filtered queries
_SLICE_SIZE_SECONDS = 300  # 5-minute window for timeline slices


def _make_tool_call_id() -> str:
    return f"tc_{uuid4().hex[:8]}"


def _hash_output(output: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(output, sort_keys=True, default=str).encode()).hexdigest()
    )


def _serialize_windows(windows: list) -> list[dict]:
    return [w.model_dump() for w in windows]


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


def _error_response(
    tc_id: str,
    tool_name: str,
    params: dict,
    error: str,
    t0: float,
) -> dict:
    """Build an audited error response dict."""
    ctx = get_ctx()
    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=tool_name,
        params=params,
        output_hash=_hash_output({"error": error}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "error",
        "error_message": error,
        "results": [],
        "source": _SRC_PLASO_TIMELINE,
        "result_count": 0,
        "reduced": False,
        "reduction_ratio": None,
    }


def _run_psort(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Execute a psort command, raising on timeout."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_PSORT_TIMEOUT,
        check=False,
    )


def _reduce_or_return(output: str) -> tuple[list[dict], bool, float | None]:
    """Cordon-reduce *output* if warranted, returning ``(results, reduced, ratio)``."""
    ctx = get_ctx()
    if ctx.reducer.should_reduce(_SRC_PLASO_TIMELINE, len(output)):
        reduced_out = ctx.reducer.reduce(output)
        blocks = [b.model_dump() for b in reduced_out.blocks]
        return (
            [{"reduced_text": reduced_out.text, "blocks": blocks}],
            True,
            reduced_out.reduction_ratio,
        )
    return [{"timeline_text": output, "line_count": output.count("\n") + 1}], False, None


def _resolve_psort_prerequisites(
    tc_id: str, tool_name: str, params: dict, t0: float
) -> str | dict:
    """Check psort availability and locate the .plaso file.

    Returns the plaso file path on success, or an error response dict.
    """
    if not shutil.which(_PSORT_BIN):
        return _error_response(tc_id, tool_name, params, "psort.py not found on PATH", t0)
    try:
        return _find_plaso_file()
    except RuntimeError as exc:
        return _error_response(tc_id, tool_name, params, str(exc), t0)


# ------------------------------------------------------------------
# Tool: get_plaso_stats
# ------------------------------------------------------------------


@mcp.tool()
def get_plaso_stats() -> dict:
    """Return Plaso parser hit statistics collected during ingest.

    Shows which parsers fired and how many events each produced.
    Useful for understanding which artifact types are available in
    the case timeline.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PLASO_STATS)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_plaso_stats",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_PLASO_STATS,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: filter_timeline
# ------------------------------------------------------------------


@mcp.tool()
def filter_timeline(
    t_start: str,
    t_end: str,
    keyword: str | None = None,
    parser: str | None = None,
) -> dict:
    """Query the Plaso timeline with time range and optional filters.

    Runs ``psort.py`` against the stored ``.plaso`` file with a date
    filter expression.  Optionally narrow results to a specific
    *parser* (e.g. ``"winevtx"``) or grep for *keyword* in the output.
    Large results are Cordon-reduced.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
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
        return _error_response(
            tc_id, "filter_timeline", params, f"psort timed out after {_PSORT_TIMEOUT}s", t0
        )

    output = proc.stdout.strip()
    if proc.returncode != 0:
        stderr_preview = (proc.stderr or "")[:500]
        return _error_response(
            tc_id,
            "filter_timeline",
            params,
            f"psort exited {proc.returncode}: {stderr_preview}",
            t0,
        )

    if not output:
        results: list[dict] = []
        reduced = False
        reduction_ratio: float | None = None
    else:
        if keyword:
            output = _apply_keyword_filter(output, keyword)
        if not output:
            results = []
            reduced = False
            reduction_ratio = None
        else:
            results, reduced, reduction_ratio = _reduce_or_return(output)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="filter_timeline",
        params=params,
        output_hash=_hash_output(results),
        cordon_ratio=reduction_ratio,
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_PLASO_TIMELINE,
        "result_count": len(results),
        "reduced": reduced,
        "reduction_ratio": reduction_ratio,
    }


def _apply_keyword_filter(output: str, keyword: str) -> str:
    """Keep only L2T CSV lines containing *keyword* (case-insensitive)."""
    kw_lower = keyword.lower()
    lines = output.splitlines()
    header = lines[0] if lines else ""
    filtered = [ln for ln in lines[1:] if kw_lower in ln.lower()]
    return "\n".join([header, *filtered]) if filtered else ""


# ------------------------------------------------------------------
# Tool: export_timeline_slice
# ------------------------------------------------------------------


@mcp.tool()
def export_timeline_slice(timestamp: str) -> dict:
    """Export a 5-minute timeline slice centred on a timestamp.

    Runs ``psort.py --slice`` to produce a narrow window of events around
    the given *timestamp* (ISO-8601 format, e.g. ``2024-01-15T14:30:00``).
    Useful for quickly pivoting around a known event of interest.
    Large results are Cordon-reduced.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
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
        return _error_response(
            tc_id, "export_timeline_slice", params, f"psort timed out after {_PSORT_TIMEOUT}s", t0
        )

    output = proc.stdout.strip()
    if proc.returncode != 0:
        stderr_preview = (proc.stderr or "")[:500]
        return _error_response(
            tc_id,
            "export_timeline_slice",
            params,
            f"psort exited {proc.returncode}: {stderr_preview}",
            t0,
        )

    if not output:
        results: list[dict] = []
        reduced = False
        reduction_ratio: float | None = None
    else:
        results, reduced, reduction_ratio = _reduce_or_return(output)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="export_timeline_slice",
        params=params,
        output_hash=_hash_output(results),
        cordon_ratio=reduction_ratio,
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_PLASO_TIMELINE,
        "result_count": len(results),
        "reduced": reduced,
        "reduction_ratio": reduction_ratio,
    }
