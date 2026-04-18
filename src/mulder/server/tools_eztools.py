"""Eric Zimmerman Tools MCP tools for querying EZ-parsed Windows artifacts.

All tools are read-only and query pre-extracted EZ Tools data from the
case database.
"""

from __future__ import annotations

import time

from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import make_tool_call_id, windowed_response

_SRC_PREFETCH = "ez.prefetch"
_SRC_AMCACHE = "ez.amcache"
_SRC_SHIMCACHE = "ez.shimcache"
_SRC_MFT = "ez.mft"
_SRC_USNJRNL = "ez.usnjrnl"
_SRC_JUMPLISTS = "ez.jumplists"
_SRC_LNKFILES = "ez.lnkfiles"
_SRC_SHELLBAGS = "ez.shellbags"
_SRC_SRUM = "ez.srum"


@mcp.tool()
def parse_prefetch_detailed() -> dict[str, object]:
    """Return detailed Prefetch data parsed by PECmd (EZ Tools).

    Shows last 8 run times, referenced DLLs, and execution metadata
    per executable.  Richer than the basic stat-based Prefetch data.
    Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    windows = ctx.db.get_windows_by_source(_SRC_PREFETCH)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_PREFETCH, "parse_prefetch_detailed", {}, elapsed)


@mcp.tool()
def parse_amcache() -> dict[str, object]:
    """Return Amcache data parsed by AmcacheParser (EZ Tools).

    Shows program execution history with SHA1 hashes, file paths,
    and timestamps.  Useful for identifying recently installed or
    executed programs.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    windows = ctx.db.get_windows_by_source(_SRC_AMCACHE)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_AMCACHE, "parse_amcache", {}, elapsed)


@mcp.tool()
def parse_shimcache() -> dict[str, object]:
    """Return ShimCache (AppCompatCache) data parsed by AppCompatCacheParser (EZ Tools).

    Shows file existence evidence with timestamps.  On Windows 7 the
    entries are chronologically ordered, making this a useful execution
    timeline artifact.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    windows = ctx.db.get_windows_by_source(_SRC_SHIMCACHE)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_SHIMCACHE, "parse_shimcache", {}, elapsed)


@mcp.tool()
def parse_jump_lists() -> dict[str, object]:
    """Return Jump List data parsed by JLECmd (EZ Tools).

    Shows user file access history from Windows AutomaticDestinations
    and CustomDestinations jump lists.  Useful for tracking which files
    a user recently opened.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    windows = ctx.db.get_windows_by_source(_SRC_JUMPLISTS)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_JUMPLISTS, "parse_jump_lists", {}, elapsed)


@mcp.tool()
def parse_lnk_files() -> dict[str, object]:
    """Return LNK file data parsed by LECmd (EZ Tools).

    Shows shortcut targets, timestamps, and metadata.  LNK files
    provide execution evidence -- they are created when a file is
    opened from Explorer.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    windows = ctx.db.get_windows_by_source(_SRC_LNKFILES)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_LNKFILES, "parse_lnk_files", {}, elapsed)


@mcp.tool()
def parse_shellbags() -> dict[str, object]:
    """Return Shellbags data parsed by SBECmd (EZ Tools).

    Shows folder access history from UsrClass.dat.  Shellbags persist
    even after folders are deleted, making them useful for proving a
    user navigated to a specific directory.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    windows = ctx.db.get_windows_by_source(_SRC_SHELLBAGS)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_SHELLBAGS, "parse_shellbags", {}, elapsed)


@mcp.tool()
def parse_srum() -> dict[str, object]:
    """Return SRUM data parsed by SrumECmd (EZ Tools).

    Shows network usage, application resource usage, and energy usage
    over the past 30-60 days from the System Resource Usage Monitor
    database.  Useful for detecting anomalous network activity.
    Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    windows = ctx.db.get_windows_by_source(_SRC_SRUM)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_SRUM, "parse_srum", {}, elapsed)


@mcp.tool()
def parse_mft(t_start: str, t_end: str) -> dict[str, object]:
    """Return MFT entries within a time range, parsed by MFTECmd (EZ Tools).

    The Master File Table contains timestamps, sizes, and parent
    directories for every file on an NTFS volume.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    windows = ctx.db.get_windows_by_source(_SRC_MFT, t_start, t_end)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(
        tc_id, windows, _SRC_MFT, "parse_mft", {"t_start": t_start, "t_end": t_end}, elapsed
    )


@mcp.tool()
def parse_usn_journal(t_start: str, t_end: str) -> dict[str, object]:
    """Return USN Journal entries within a time range, parsed by MFTECmd (EZ Tools).

    The NTFS change journal records every file system modification
    (create, delete, rename, etc.).  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    windows = ctx.db.get_windows_by_source(_SRC_USNJRNL, t_start, t_end)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(
        tc_id,
        windows,
        _SRC_USNJRNL,
        "parse_usn_journal",
        {"t_start": t_start, "t_end": t_end},
        elapsed,
    )
