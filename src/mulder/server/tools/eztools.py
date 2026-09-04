"""MCP tools for EZ forensic parsers (Prefetch, Amcache, ShimCache, etc.).

All tools are read-only and query pre-extracted EZ Tools data from the
case database.  Tools return compact summaries with window counts and
sample entries; use ``search()`` or ``get_raw_output()`` for full data.
"""

from __future__ import annotations

import time
from typing import Any

from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    hash_output,
    make_tool_call_id,
    project_window_evidence,
    windowed_response,
)
from mulder.server.tool_access import Role, tool_access

_EZ_SUMMARY_SAMPLE_CAP = 10
_EZ_SUMMARY_TEXT_CAP = 200

_EZ_TOOLS: list[tuple[str, str, str]] = [
    (
        "parse_prefetch_detailed",
        "ez.prefetch",
        "Return detailed Prefetch data parsed by PECmd (EZ Tools).\n\n"
        "Shows last 8 run times, referenced DLLs, and execution metadata\n"
        "per executable.  Returns a summary with counts and sample entries;\n"
        "use ``search()`` or ``get_raw_output()`` for full data.  Read-only.",
    ),
    (
        "parse_amcache",
        "ez.amcache",
        "Return Amcache data parsed by AmcacheParser (EZ Tools).\n\n"
        "Shows program execution history with SHA1 hashes, file paths,\n"
        "and timestamps.  Returns a summary with counts and sample entries;\n"
        "use ``search()`` or ``get_raw_output()`` for full data.  Read-only.",
    ),
    (
        "parse_shimcache",
        "ez.shimcache",
        "Return ShimCache (AppCompatCache) data parsed by AppCompatCacheParser (EZ Tools).\n\n"
        "Shows file existence evidence with timestamps.  Returns a summary\n"
        "with counts and sample entries; use ``search()`` or\n"
        "``get_raw_output()`` for full data.  Read-only.",
    ),
    (
        "parse_jump_lists",
        "ez.jumplists",
        "Return Jump List data parsed by JLECmd (EZ Tools).\n\n"
        "Shows user file access history.  Returns a summary with counts and\n"
        "sample entries; use ``search()`` or ``get_raw_output()`` for full\n"
        "data.  Read-only.",
    ),
    (
        "parse_lnk_files",
        "ez.lnkfiles",
        "Return LNK file data parsed by LECmd (EZ Tools).\n\n"
        "Shows shortcut targets, timestamps, and metadata.  Returns a summary\n"
        "with counts and sample entries; use ``search()`` or\n"
        "``get_raw_output()`` for full data.  Read-only.",
    ),
    (
        "parse_shellbags",
        "ez.shellbags",
        "Return Shellbags data parsed by SBECmd (EZ Tools).\n\n"
        "Shows folder access history from UsrClass.dat.  Returns a summary\n"
        "with counts and sample entries; use ``search()`` or\n"
        "``get_raw_output()`` for full data.  Read-only.",
    ),
    (
        "parse_srum",
        "ez.srum",
        "Return SRUM data parsed by SrumECmd (EZ Tools).\n\n"
        "Shows network/app resource usage over 30-60 days.  Returns a summary\n"
        "with counts and sample entries; use ``search()`` or\n"
        "``get_raw_output()`` for full data.  Read-only.",
    ),
]


def _make_ez_tool(source_name: str, tool_name: str) -> Any:
    """Create a no-arg tool function that returns a compact summary."""

    def tool_fn() -> dict[str, object]:
        """Return a compact summary of EZ tool output."""
        ctx = get_ctx()
        tc_id = make_tool_call_id()
        t0 = time.monotonic()
        windows = ctx.db.get_windows_by_source(source_name)
        total = len(windows)

        samples: list[dict[str, object]] = []
        for w in windows[:_EZ_SUMMARY_SAMPLE_CAP]:
            samples.append(
                project_window_evidence(
                    w,
                    source_name,
                    max_characters=_EZ_SUMMARY_TEXT_CAP,
                    content_key="sample",
                )
            )

        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name=tool_name,
            params={},
            output_hash=hash_output({"total": total}),
            duration_ms=elapsed,
        )
        resp: dict[str, object] = {
            "tool_call_id": tc_id,
            "status": "success",
            "source": source_name,
            "total_windows": total,
            "sample_count": len(samples),
            "samples": samples,
        }
        if total == 0:
            resp["hint"] = (
                f"No data indexed for {source_name}. "
                f"Run the corresponding EZ Tools extractor first."
            )
        else:
            resp["hint"] = (
                f"Showing {len(samples)} of {total} entries. "
                f"Use search(query, source='{source_name}') to find specific entries, "
                f"or get_raw_output('{source_name}') to paginate the full data."
            )
        return resp

    return tool_fn


# EZ Tools are registered dynamically to avoid duplicating 7 identical
# no-arg tool functions. Each tool queries a different source name but
# shares the same implementation (_make_ez_tool). The trade-off is that
# these tools are invisible to @mcp.tool() grep searches and IDE
# go-to-definition. If you add a new EZ tool, append to _EZ_TOOLS above.
_EZ_TOOL_ROLES = Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR

for _name, _source, _doc in _EZ_TOOLS:
    _fn = _make_ez_tool(_source, _name)
    _fn.__name__ = _name
    _fn.__qualname__ = _name
    _fn.__doc__ = _doc
    _fn = tool_access(_EZ_TOOL_ROLES)(_fn)
    mcp.tool()(_fn)


# ---------------------------------------------------------------------------
# Tools with parameters (time-range filtering)
# ---------------------------------------------------------------------------

_SRC_MFT = "ez.mft"
_SRC_USNJRNL = "ez.usnjrnl"


_MFT_USN_CAP = 15


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
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
        tc_id,
        windows,
        _SRC_MFT,
        "parse_mft",
        {"t_start": t_start, "t_end": t_end},
        elapsed,
        cap=_MFT_USN_CAP,
    )


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
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
        cap=_MFT_USN_CAP,
    )
