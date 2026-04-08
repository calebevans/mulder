"""Eric Zimmerman Tools MCP tools for querying EZ-parsed Windows artifacts.

All tools are read-only and query pre-extracted EZ Tools data from the
case database.  Large time-range sources (MFT, UsnJrnl) are
Cordon-reduced to keep context-window usage manageable.
"""

from __future__ import annotations

import hashlib
import json
import time
from uuid import uuid4

from mulder.server.app import get_ctx, mcp

_SRC_PREFETCH = "ez.prefetch"
_SRC_AMCACHE = "ez.amcache"
_SRC_SHIMCACHE = "ez.shimcache"
_SRC_MFT = "ez.mft"
_SRC_USNJRNL = "ez.usnjrnl"
_SRC_JUMPLISTS = "ez.jumplists"
_SRC_LNKFILES = "ez.lnkfiles"
_SRC_SHELLBAGS = "ez.shellbags"
_SRC_SRUM = "ez.srum"


def _make_tool_call_id() -> str:
    return f"tc_{uuid4().hex[:8]}"


def _hash_output(output: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(output, sort_keys=True, default=str).encode()).hexdigest()
    )


def _serialize_windows(windows: list) -> list[dict]:
    return [w.model_dump() for w in windows]


# ------------------------------------------------------------------
# Simple source-query tools (no reduction)
# ------------------------------------------------------------------


@mcp.tool()
def parse_prefetch_detailed() -> dict:
    """Return detailed Prefetch data parsed by PECmd (EZ Tools).

    Shows last 8 run times, referenced DLLs, and execution metadata
    per executable.  Richer than the basic stat-based Prefetch data.
    Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PREFETCH)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_prefetch_detailed",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_PREFETCH,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


@mcp.tool()
def parse_amcache() -> dict:
    """Return Amcache data parsed by AmcacheParser (EZ Tools).

    Shows program execution history with SHA1 hashes, file paths,
    and timestamps.  Useful for identifying recently installed or
    executed programs.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_AMCACHE)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_amcache",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_AMCACHE,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


@mcp.tool()
def parse_shimcache() -> dict:
    """Return ShimCache (AppCompatCache) data parsed by AppCompatCacheParser (EZ Tools).

    Shows file existence evidence with timestamps.  On Windows 7 the
    entries are chronologically ordered, making this a useful execution
    timeline artifact.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_SHIMCACHE)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_shimcache",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_SHIMCACHE,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


@mcp.tool()
def parse_jump_lists() -> dict:
    """Return Jump List data parsed by JLECmd (EZ Tools).

    Shows user file access history from Windows AutomaticDestinations
    and CustomDestinations jump lists.  Useful for tracking which files
    a user recently opened.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_JUMPLISTS)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_jump_lists",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_JUMPLISTS,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


@mcp.tool()
def parse_lnk_files() -> dict:
    """Return LNK file data parsed by LECmd (EZ Tools).

    Shows shortcut targets, timestamps, and metadata.  LNK files
    provide execution evidence -- they are created when a file is
    opened from Explorer.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_LNKFILES)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_lnk_files",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_LNKFILES,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


@mcp.tool()
def parse_shellbags() -> dict:
    """Return Shellbags data parsed by SBECmd (EZ Tools).

    Shows folder access history from UsrClass.dat.  Shellbags persist
    even after folders are deleted, making them useful for proving a
    user navigated to a specific directory.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_SHELLBAGS)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_shellbags",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_SHELLBAGS,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


@mcp.tool()
def parse_srum() -> dict:
    """Return SRUM data parsed by SrumECmd (EZ Tools).

    Shows network usage, application resource usage, and energy usage
    over the past 30-60 days from the System Resource Usage Monitor
    database.  Useful for detecting anomalous network activity.
    Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_SRUM)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_srum",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_SRUM,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Time-range + Cordon-reduced tools
# ------------------------------------------------------------------


@mcp.tool()
def parse_mft(t_start: str, t_end: str) -> dict:
    """Return MFT entries within a time range, parsed by MFTECmd (EZ Tools).

    The Master File Table contains timestamps, sizes, and parent
    directories for every file on an NTFS volume.  Large results are
    Cordon-reduced to keep context-window usage manageable.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.query_engine.get_windows_in_range(_SRC_MFT, t_start, t_end)

    reduced = False
    reduction_ratio: float | None = None
    raw_text = "\n".join(w.raw_text for w in windows)
    if raw_text and ctx.reducer.should_reduce(_SRC_MFT, len(raw_text)):
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
        tool_name="parse_mft",
        params={"t_start": t_start, "t_end": t_end},
        output_hash=_hash_output(results),
        cordon_ratio=reduction_ratio,
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_MFT,
        "result_count": len(results),
        "reduced": reduced,
        "reduction_ratio": reduction_ratio,
    }


@mcp.tool()
def parse_usn_journal(t_start: str, t_end: str) -> dict:
    """Return USN Journal entries within a time range, parsed by MFTECmd (EZ Tools).

    The NTFS change journal records every file system modification
    (create, delete, rename, etc.).  Large results are Cordon-reduced
    to keep context-window usage manageable.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.query_engine.get_windows_in_range(_SRC_USNJRNL, t_start, t_end)

    reduced = False
    reduction_ratio: float | None = None
    raw_text = "\n".join(w.raw_text for w in windows)
    if raw_text and ctx.reducer.should_reduce(_SRC_USNJRNL, len(raw_text)):
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
        tool_name="parse_usn_journal",
        params={"t_start": t_start, "t_end": t_end},
        output_hash=_hash_output(results),
        cordon_ratio=reduction_ratio,
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_USNJRNL,
        "result_count": len(results),
        "reduced": reduced,
        "reduction_ratio": reduction_ratio,
    }
