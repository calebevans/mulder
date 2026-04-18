"""Bulk Extractor MCP tools for querying carved IOC data.

Queries pre-extracted bulk_extractor feature data from the case database.
Supports both summary mode (counts per feature type) and detail mode
(full windows for a specific feature).  All tools are read-only.
"""

from __future__ import annotations

import time

from mulder.server.app import ServerContext, get_ctx, mcp
from mulder.server.helpers import make_tool_call_id, windowed_response

_BULK_SOURCE_PREFIX = "bulk."


@mcp.tool()
def get_carved_iocs(feature: str | None = None) -> dict[str, object]:
    """Return IOC data carved by bulk_extractor during ingest.

    When *feature* is ``None``, returns a summary with the number of
    windows for each ``bulk.*`` source (email, url, domain, ip, etc.).

    When *feature* is specified (e.g. ``"email"``, ``"url"``), returns
    windows from the ``bulk.<feature>`` source (capped for efficiency).
    Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if feature is not None:
        source = f"{_BULK_SOURCE_PREFIX}{feature}"
        windows = ctx.db.get_windows_by_source(source)
        elapsed = (time.monotonic() - t0) * 1000
        return windowed_response(
            tc_id, windows, source, "get_carved_iocs", {"feature": feature}, elapsed
        )

    results = _summary_mode(ctx)
    elapsed = (time.monotonic() - t0) * 1000
    from mulder.server.helpers import current_batch_id, hash_output

    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_carved_iocs",
        params={"feature": feature},
        output_hash=hash_output({"count": len(results)}),
        duration_ms=elapsed,
        batch_id=current_batch_id.get(),
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": None,
        "result_count": len(results),
    }


def _summary_mode(ctx: ServerContext) -> list[dict[str, object]]:
    """Return per-feature window counts using sources.line_count."""
    sources = ctx.db.get_sources()
    return [
        {
            "source_name": s.source_name,
            "feature": s.source_name.removeprefix(_BULK_SOURCE_PREFIX),
            "window_count": s.line_count // 4 + 1,
        }
        for s in sources
        if s.source_name.startswith(_BULK_SOURCE_PREFIX)
    ]
