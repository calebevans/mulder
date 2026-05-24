"""MCP tools for EZ forensic parsers (Prefetch, Amcache, ShimCache, etc.).

All tools are read-only and query pre-extracted EZ Tools data from the
case database.
"""

from __future__ import annotations

import time
from typing import Any

from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import make_tool_call_id, windowed_response

# ---------------------------------------------------------------------------
# Config-driven simple tools (no parameters beyond ctx)
# Each tuple: (function_name, source_name, docstring)
# ---------------------------------------------------------------------------

_EZ_TOOLS: list[tuple[str, str, str]] = [
    (
        "parse_prefetch_detailed",
        "ez.prefetch",
        "Return detailed Prefetch data parsed by PECmd (EZ Tools).\n\n"
        "Shows last 8 run times, referenced DLLs, and execution metadata\n"
        "per executable.  Richer than the basic stat-based Prefetch data.\n"
        "Read-only.",
    ),
    (
        "parse_amcache",
        "ez.amcache",
        "Return Amcache data parsed by AmcacheParser (EZ Tools).\n\n"
        "Shows program execution history with SHA1 hashes, file paths,\n"
        "and timestamps.  Useful for identifying recently installed or\n"
        "executed programs.  Read-only.",
    ),
    (
        "parse_shimcache",
        "ez.shimcache",
        "Return ShimCache (AppCompatCache) data parsed by AppCompatCacheParser (EZ Tools).\n\n"
        "Shows file existence evidence with timestamps.  On Windows 7 the\n"
        "entries are chronologically ordered, making this a useful execution\n"
        "timeline artifact.  Read-only.",
    ),
    (
        "parse_jump_lists",
        "ez.jumplists",
        "Return Jump List data parsed by JLECmd (EZ Tools).\n\n"
        "Shows user file access history from Windows AutomaticDestinations\n"
        "and CustomDestinations jump lists.  Useful for tracking which files\n"
        "a user recently opened.  Read-only.",
    ),
    (
        "parse_lnk_files",
        "ez.lnkfiles",
        "Return LNK file data parsed by LECmd (EZ Tools).\n\n"
        "Shows shortcut targets, timestamps, and metadata.  LNK files\n"
        "provide execution evidence -- they are created when a file is\n"
        "opened from Explorer.  Read-only.",
    ),
    (
        "parse_shellbags",
        "ez.shellbags",
        "Return Shellbags data parsed by SBECmd (EZ Tools).\n\n"
        "Shows folder access history from UsrClass.dat.  Shellbags persist\n"
        "even after folders are deleted, making them useful for proving a\n"
        "user navigated to a specific directory.  Read-only.",
    ),
    (
        "parse_srum",
        "ez.srum",
        "Return SRUM data parsed by SrumECmd (EZ Tools).\n\n"
        "Shows network usage, application resource usage, and energy usage\n"
        "over the past 30-60 days from the System Resource Usage Monitor\n"
        "database.  Useful for detecting anomalous network activity.\n"
        "Read-only.",
    ),
]


def _make_ez_tool(source_name: str, tool_name: str) -> Any:
    """Create a no-arg tool function that fetches windows from *source_name*."""

    def tool_fn() -> dict[str, object]:
        ctx = get_ctx()
        tc_id = make_tool_call_id()
        t0 = time.monotonic()
        windows = ctx.db.get_windows_by_source(source_name)
        elapsed = (time.monotonic() - t0) * 1000
        return windowed_response(tc_id, windows, source_name, tool_name, {}, elapsed)

    return tool_fn


for _name, _source, _doc in _EZ_TOOLS:
    _fn = _make_ez_tool(_source, _name)
    _fn.__name__ = _name
    _fn.__qualname__ = _name
    _fn.__doc__ = _doc
    mcp.tool()(_fn)


# ---------------------------------------------------------------------------
# Tools with parameters (time-range filtering)
# ---------------------------------------------------------------------------

_SRC_MFT = "ez.mft"
_SRC_USNJRNL = "ez.usnjrnl"


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
