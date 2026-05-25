"""Shared helper functions for MCP tool modules."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from typing import Any
from uuid import uuid4

from mulder.server.app import get_ctx

current_batch_id: ContextVar[str | None] = ContextVar("current_batch_id", default=None)


def make_tool_call_id() -> str:
    """Generate a short unique identifier for a tool invocation."""
    return f"tc_{uuid4().hex[:8]}"


_PREVIEW_CHAR_LIMIT = 500
_HINT_CHAR_LIMIT = 200
_DEFAULT_SEARCH_LIMIT = 50
_FILE_LIST_CAP = 500

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


_DEFAULT_WINDOW_CAP = 20
_DEFAULT_TEXT_CAP = 300


def serialize_windows(
    windows: Sequence[Any],
    cap: int = _DEFAULT_WINDOW_CAP,
    text_cap: int = _DEFAULT_TEXT_CAP,
) -> list[dict[str, Any]]:
    """Convert Pydantic window models to dicts, capped for token efficiency.

    Returns at most *cap* windows with ``raw_text`` truncated to
    *text_cap* characters.  Callers should check
    ``len(result) < len(windows)`` and include ``total_windows`` /
    ``truncated`` in the response so the agent knows to use
    ``search()`` or ``get_raw_output()`` for the full data.
    """
    capped = windows[:cap] if len(windows) > cap else windows
    result: list[dict[str, Any]] = []
    for w in capped:
        d: dict[str, Any] = w.model_dump() if hasattr(w, "model_dump") else dict(w)
        raw = d.get("raw_text", "")
        if text_cap and len(raw) > text_cap:
            d["raw_text"] = raw[:text_cap] + "..."
            d["full_text_available"] = True
        result.append(d)
    return result


def windowed_response(
    tc_id: str,
    windows: Sequence[Any],
    source: str,
    tool_name: str,
    params: Mapping[str, object],
    elapsed_ms: float,
    cap: int = _DEFAULT_WINDOW_CAP,
    text_cap: int = _DEFAULT_TEXT_CAP,
) -> dict[str, object]:
    """Build a standard response for tools that return serialized windows.

    Caps the result, truncates ``raw_text``, includes truncation metadata,
    and logs the audit entry.
    """
    total = len(windows)
    results = serialize_windows(windows, cap=cap, text_cap=text_cap)

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


_PID_RE = re.compile(r"(?:^|\t)(\d{1,6})(?:\t|$)", re.MULTILINE)
_MODULE_NAME_RE = re.compile(r"^([^\t]+\.sys)", re.MULTILINE | re.IGNORECASE)


def extract_pid(text: str) -> int | None:
    """Parse the first PID value from a Volatility output line."""
    m = _PID_RE.search(text)
    if m:
        val = int(m.group(1))
        if val > 0:
            return val
    return None


def extract_pids_from_windows(windows: Sequence[Any]) -> dict[int, list[Any]]:
    """Group windows by the PID found in their text."""
    pid_map: dict[int, list[Any]] = defaultdict(list)
    for w in windows:
        pid = extract_pid(w.raw_text)
        if pid is not None:
            pid_map[pid].append(w)
    return dict(pid_map)


def extract_module_names(windows: Sequence[Any]) -> dict[str, list[Any]]:
    """Group windows by the kernel module name found in their text."""
    mod_map: dict[str, list[Any]] = defaultdict(list)
    for w in windows:
        m = _MODULE_NAME_RE.search(w.raw_text)
        if m:
            name = m.group(1).strip().lower()
            mod_map[name].append(w)
    return dict(mod_map)
