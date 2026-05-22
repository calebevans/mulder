"""Shared helper functions for MCP tool modules."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from typing import Any
from uuid import uuid4

from mulder.server.app import get_ctx

current_batch_id: ContextVar[str | None] = ContextVar("current_batch_id", default=None)


def make_tool_call_id() -> str:
    """Generate a short unique identifier for a tool invocation."""
    return f"tc_{uuid4().hex[:8]}"


_HASH_SIZE_THRESHOLD = 10000
_HASH_PREFIX = "blake2b:"
_HASH_DIGEST_SIZE = 32


def _blake2b_hex(data: bytes) -> str:
    return _HASH_PREFIX + hashlib.blake2b(data, digest_size=_HASH_DIGEST_SIZE).hexdigest()


def hash_output(output: object) -> str:
    """Return a BLAKE2b fingerprint of *output* for audit purposes.

    For small payloads, hashes the full JSON.  For large payloads
    (>10KB serialized), hashes a compact summary to avoid expensive
    serialization of data that's about to be serialized again for the
    MCP response.
    """
    if isinstance(output, list | dict):
        if isinstance(output, list) and len(output) > 200:
            return _blake2b_hex(f"list:len={len(output)}".encode())
        if isinstance(output, dict) and len(output) > 100:
            return _blake2b_hex(f"dict:keys={sorted(output.keys())}".encode())
        probe = json.dumps(output, sort_keys=True, default=str)
        return _blake2b_hex(probe.encode())
    raw = json.dumps(output, sort_keys=True, default=str)
    return _blake2b_hex(raw.encode())


_DEFAULT_WINDOW_CAP = 200


def serialize_windows(
    windows: Sequence[Any], cap: int = _DEFAULT_WINDOW_CAP
) -> list[dict[str, Any]]:
    """Convert Pydantic window models to dicts, capped for token efficiency.

    Returns at most *cap* windows.  Callers should check
    ``len(result) < len(windows)`` and include ``total_windows`` /
    ``truncated`` in the response so the agent knows to use
    ``search()`` or ``get_raw_output()`` for the full data.
    """
    capped = windows[:cap] if len(windows) > cap else windows
    return [w.model_dump() for w in capped]


def windowed_response(
    tc_id: str,
    windows: Sequence[Any],
    source: str,
    tool_name: str,
    params: Mapping[str, object],
    elapsed_ms: float,
    cap: int = _DEFAULT_WINDOW_CAP,
) -> dict[str, object]:
    """Build a standard response for tools that return serialized windows.

    Caps the result, includes truncation metadata, and logs the audit entry.
    """
    total = len(windows)
    results = serialize_windows(windows, cap=cap)

    ctx = get_ctx()
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=tool_name,
        params=params,
        output_hash=hash_output({"total": total, "returned": len(results)}),
        duration_ms=elapsed_ms,
        batch_id=current_batch_id.get(),
    )
    resp: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": source,
        "result_count": len(results),
        "total_windows": total,
    }
    if total > cap:
        resp["truncated"] = True
        resp["hint"] = (
            f"Showing {cap} of {total} windows. Use search(query, source='{source}') "
            f"or get_raw_output('{source}') for the full data."
        )
    return resp


def slim_window(w: Any) -> dict[str, Any]:
    """Return window metadata without raw_text for compact tool output.

    The agent can retrieve full text via ``get_raw_output`` or ``search``.
    """
    d: dict[str, Any] = w.model_dump() if hasattr(w, "model_dump") else dict(w)
    d.pop("raw_text", None)
    return d


def tool_response(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    results: dict[str, object] | list[object],
    source: str | None = None,
    elapsed_ms: float = 0,
) -> dict[str, object]:
    """Build an audited success response and log the tool call."""
    ctx = get_ctx()
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=tool_name,
        params=params,
        output_hash=hash_output(results),
        duration_ms=elapsed_ms,
        batch_id=current_batch_id.get(),
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": source,
    }


def error_response(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    error: str,
    elapsed_ms: float = 0,
    error_type: str = "unknown",
    suggestion: str | None = None,
) -> dict[str, object]:
    """Build an audited error response and log the tool call."""
    ctx = get_ctx()
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=tool_name,
        params=params,
        output_hash=hash_output({"error": error}),
        duration_ms=elapsed_ms,
        batch_id=current_batch_id.get(),
    )
    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "error",
        "error_type": error_type,
        "error_message": error,
    }
    if suggestion:
        result["suggestion"] = suggestion
    return result
