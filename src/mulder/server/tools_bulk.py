"""Bulk Extractor MCP tools for querying carved IOC data.

Queries pre-extracted bulk_extractor feature data from the case database.
Supports both summary mode (counts per feature type) and detail mode
(full windows for a specific feature).  All tools are read-only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from uuid import uuid4

from mulder.server.app import get_ctx, mcp

logger = logging.getLogger(__name__)

_BULK_SOURCE_PREFIX = "bulk."


def _make_tool_call_id() -> str:
    return f"tc_{uuid4().hex[:8]}"


def _hash_output(output: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(output, sort_keys=True, default=str).encode()).hexdigest()
    )


def _serialize_windows(windows: list) -> list[dict]:
    return [w.model_dump() for w in windows]


@mcp.tool()
def get_carved_iocs(feature: str | None = None) -> dict:
    """Return IOC data carved by bulk_extractor during ingest.

    When *feature* is ``None``, returns a summary with the number of
    windows for each ``bulk.*`` source (email, url, domain, ip, etc.).

    When *feature* is specified (e.g. ``"email"``, ``"url"``), returns
    all windows from the ``bulk.<feature>`` source.  Large results are
    Cordon-reduced.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()
    params = {"feature": feature}

    if feature is None:
        results = _summary_mode(ctx)
        source = None
        result_count = len(results)
        reduced = False
        reduction_ratio: float | None = None
    else:
        source = f"{_BULK_SOURCE_PREFIX}{feature}"
        results, reduced, reduction_ratio = _feature_mode(ctx, source)
        result_count = len(results)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_carved_iocs",
        params=params,
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": source,
        "result_count": result_count,
        "reduced": reduced,
        "reduction_ratio": reduction_ratio,
    }


def _summary_mode(ctx: object) -> list[dict]:
    """Return per-feature window counts for all bulk.* sources."""
    sources = ctx.db.get_sources()
    summary: list[dict] = []
    for s in sources:
        if s.source_name.startswith(_BULK_SOURCE_PREFIX):
            windows = ctx.db.get_windows_by_source(s.source_name)
            summary.append(
                {
                    "source_name": s.source_name,
                    "feature": s.source_name.removeprefix(_BULK_SOURCE_PREFIX),
                    "window_count": len(windows),
                }
            )
    return summary


def _feature_mode(ctx: object, source: str) -> tuple[list[dict], bool, float | None]:
    """Return windows for a specific bulk.* source, with optional Cordon reduction."""
    windows = ctx.db.get_windows_by_source(source)
    raw_text = "\n".join(w.raw_text for w in windows)

    if raw_text and ctx.reducer.should_reduce(source, len(raw_text)):
        reduced_out = ctx.reducer.reduce(raw_text)
        blocks = [b.model_dump() for b in reduced_out.blocks]
        return (
            [{"reduced_text": reduced_out.text, "blocks": blocks}],
            True,
            reduced_out.reduction_ratio,
        )

    return _serialize_windows(windows), False, None
