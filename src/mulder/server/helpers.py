"""Shared helper functions for MCP tool modules.

Convention: elapsed_ms is recorded in the audit log for every tool call.
It should NOT be included in the response dict unless wall-clock time
is meaningful to the consumer (e.g. verify_evidence_integrity).
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
from pathlib import Path
from typing import Any, ParamSpec
from uuid import uuid4

from mulder.server.app import get_ctx, has_ctx

current_batch_id: ContextVar[str | None] = ContextVar("current_batch_id", default=None)

TOOL_TIMEOUT: int = 600
"""Default subprocess timeout (seconds) shared across extraction tools."""

_GIB_THRESHOLD = 4
"""File size (GiB) below which no extra time is added."""


def adaptive_timeout(
    file_path: str | Path,
    base: int = 600,
    per_gib: int = 120,
    cap: int = 28800,
) -> int:
    """Compute a timeout that scales with file size.

    For files under 4 GiB, returns the base timeout. For larger files,
    adds *per_gib* seconds for each GiB above 4, capped at *cap* seconds.
    Returns the base timeout if the file doesn't exist or can't be stat'd.

    Args:
        file_path: Path to the evidence file being processed.
        base: Minimum timeout in seconds (default 600 = 10 min).
        per_gib: Additional seconds per GiB above 4 GiB (default 120 = 2 min/GiB).
        cap: Maximum timeout in seconds (default 28800 = 8 hours).

    Returns:
        Timeout in seconds, between *base* and *cap*.
    """
    try:
        size_bytes = Path(file_path).stat().st_size
    except OSError:
        return base
    gib = size_bytes / (1024**3)
    return min(base + int(max(0, gib - _GIB_THRESHOLD) * per_gib), cap)


def require_binary(name: str) -> str | None:
    """Return the absolute path to *name* if found on PATH, else None."""
    return shutil.which(name)


def interpreter_candidates() -> list[str]:
    """Python interpreters to probe, most-likely-correct first.

    ``sys.executable`` is mulder's own interpreter: under ``pipx install`` /
    ``uv tool install`` it is the only one that can see dependencies injected
    into mulder's venv.  The PATH interpreters follow because several helper
    tools (plaso, pyhindsight, ALEAPP, iLEAPP) are *not* mulder dependencies
    and on SIFT live in the system interpreter or a separate venv.  Order
    matters; duplicates are dropped so a probe never runs twice against the
    same binary.
    """
    seen: set[str] = set()
    out: list[str] = []
    for cand in (sys.executable, shutil.which("python3"), shutil.which("python")):
        if cand and cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def run_subprocess(
    cmd: list[str],
    *,
    timeout: int = TOOL_TIMEOUT,
    text: bool = True,
) -> subprocess.CompletedProcess[str] | str:
    """Run a subprocess with standardized timeout handling.

    Returns the CompletedProcess on success, or an error message string
    on timeout/OS failure. Callers check ``isinstance(result, str)`` to
    detect failures.
    """
    try:
        return subprocess.run(cmd, capture_output=True, text=text, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return f"{cmd[0]} timed out after {timeout}s"
    except OSError as exc:
        return f"Failed to run {cmd[0]}: {exc}"


def make_tool_call_id() -> str:
    """Generate a short unique identifier for a tool invocation."""
    return f"tc_{uuid4().hex[:8]}"


_P = ParamSpec("_P")


def audited_tool(
    tool_name: str,
) -> Callable[[Callable[_P, dict[str, object]]], Callable[_P, dict[str, object]]]:
    """Decorator that handles tool_call_id generation, timing, and audit logging.

    Wraps an MCP tool function to automatically:
      - Generate a unique ``tool_call_id``
      - Time the function execution
      - Log the call to the audit trail
      - Inject ``tool_call_id`` into the returned dict

    The wrapped function must return a ``dict[str, object]``.  The decorator
    adds ``"tool_call_id"`` to it before returning.  The original function
    signature is preserved so MCPServer introspection continues to work.

    Args:
        tool_name: The tool name recorded in the audit log.
    """

    def decorator(
        func: Callable[_P, dict[str, object]],
    ) -> Callable[_P, dict[str, object]]:
        @functools.wraps(func)
        def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> dict[str, object]:
            ctx = get_ctx()
            tc_id = make_tool_call_id()
            t0 = time.monotonic()
            try:
                result = func(*args, **kwargs)
                elapsed = (time.monotonic() - t0) * 1000
                ctx.audit.log_tool_call(
                    tool_call_id=tc_id,
                    tool_name=tool_name,
                    params=dict(kwargs),
                    output_hash=hash_output(result),
                    duration_ms=elapsed,
                )
                result["tool_call_id"] = tc_id
                return result
            except Exception:
                elapsed = (time.monotonic() - t0) * 1000
                ctx.audit.log_tool_call(
                    tool_call_id=tc_id,
                    tool_name=tool_name,
                    params=dict(kwargs),
                    output_hash="error",
                    duration_ms=elapsed,
                )
                raise

        return wrapper

    return decorator


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
        if len(probe) > _HASH_SIZE_THRESHOLD:
            return _blake2b_hex(f"large:{len(probe)}:{probe[:256]}".encode())
        return _blake2b_hex(probe.encode())
    raw = json.dumps(output, sort_keys=True, default=str)
    if len(raw) > _HASH_SIZE_THRESHOLD:
        return _blake2b_hex(f"large:{len(raw)}:{raw[:256]}".encode())
    return _blake2b_hex(raw.encode())


_DEFAULT_WINDOW_CAP = 20
_DEFAULT_TEXT_CAP = 300


def truncate_raw_text(d: dict[str, Any], cap: int = _DEFAULT_TEXT_CAP) -> None:
    """Truncate ``raw_text`` in a window dict in-place if it exceeds *cap*."""
    raw = d.get("raw_text", "")
    if cap and len(raw) > cap:
        d["raw_text"] = raw[:cap] + "..."
        d["full_text_available"] = True


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
        truncate_raw_text(d, text_cap)
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

    if has_ctx():
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
    """Build an audited success response and log the tool call.

    When *source* is provided (indicating data has been indexed into the
    case DB), returns a compact response with only a preview of the output.
    The agent should use ``search()`` or ``get_raw_output()`` to access
    the full data.

    When *source* is None, returns the full results (for read/reference
    tools whose output is not indexed elsewhere).
    """
    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name=tool_name,
            params=params,
            output_hash=hash_output(results),
            duration_ms=elapsed_ms,
            batch_id=current_batch_id.get(),
        )

    if source is None:
        return {
            "tool_call_id": tc_id,
            "status": "success",
            "results": results,
            "source": source,
        }

    line_count: int | None = None
    windows_indexed: int | None = None
    if isinstance(results, dict):
        lc = results.get("line_count")
        if isinstance(lc, int):
            line_count = lc
        wi = results.get("windows_indexed")
        if isinstance(wi, int):
            windows_indexed = wi

    preview = ""
    if isinstance(results, dict | list):
        preview = json.dumps(results, default=str)[:_PREVIEW_CHAR_LIMIT]
    elif isinstance(results, str):
        preview = results[:_PREVIEW_CHAR_LIMIT]

    resp: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "source": source,
        "preview": preview + ("..." if len(preview) >= _PREVIEW_CHAR_LIMIT else ""),
        "hint": (
            f"Full output indexed as '{source}'. "
            f"Use search(query, source='{source}') or "
            f"get_raw_output('{source}') to access."
        ),
    }
    if line_count is not None:
        resp["line_count"] = line_count
    if windows_indexed is not None:
        resp["windows_indexed"] = windows_indexed
    return resp


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
    if has_ctx():
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


_PID_RE = re.compile(r"(?:^|\t)(\d{1,6})(?:\t|$)")
_MODULE_NAME_RE = re.compile(r"^([^\t]+\.sys)", re.IGNORECASE)


def extract_pid(text: str) -> int | None:
    """The first PID value in *text*.

    Prefer :func:`extract_pids` when *text* is a whole window: a window holds
    many records, and "the first one" is rarely the question being asked.
    """
    for line in text.splitlines():
        m = _PID_RE.search(line)
        if m:
            val = int(m.group(1))
            if val > 0:
                return val
    return None


def extract_pids(text: str) -> list[int]:
    """Every PID in *text*, one per record, in order and without duplicates.

    One window holds many records. Reading only the first -- which is what
    ``re.search`` over the whole window did -- means a window of forty
    processes contributes exactly one of them and the other thirty-nine are
    invisible to every correlation built on top: process trees miss parents,
    "hidden process" diffs compare two differently-sampled sets and report
    processes that are in both, and per-PID lookups silently return nothing.

    Which column holds the PID still varies by Volatility plugin
    (``windows.pslist`` puts it first, ``windows.netscan`` eighth), so the
    per-line match is deliberately unchanged from what it always was. Only
    the number of lines examined changes: all of them, rather than one.
    """
    seen: dict[int, None] = {}
    for line in text.splitlines():
        m = _PID_RE.search(line)
        if m:
            val = int(m.group(1))
            if val > 0:
                seen.setdefault(val, None)
    return list(seen)


def window_has_pid(text: str, pid: int) -> bool:
    """Whether *text* contains a record for *pid*."""
    return pid in extract_pids(text)


def extract_pids_from_windows(windows: Sequence[Any]) -> dict[int, list[Any]]:
    """Map every PID in every window to the windows that mention it."""
    pid_map: dict[int, list[Any]] = defaultdict(list)
    for w in windows:
        for pid in extract_pids(w.raw_text):
            pid_map[pid].append(w)
    return dict(pid_map)


def extract_module_names(windows: Sequence[Any]) -> dict[str, list[Any]]:
    """Map every kernel module name in every window to the windows naming it."""
    mod_map: dict[str, list[Any]] = defaultdict(list)
    for w in windows:
        seen: set[str] = set()
        for line in w.raw_text.splitlines():
            m = _MODULE_NAME_RE.match(line)
            if not m:
                continue
            name = m.group(1).strip().lower()
            if name not in seen:
                seen.add(name)
                mod_map[name].append(w)
    return dict(mod_map)


def sources_already_indexed(
    source_prefixes: list[str],
    evidence_path: str | None = None,
) -> list[str]:
    """Return source names matching any prefix that already have indexed data.

    Used by extraction tools to skip re-running when data already exists
    in the case database.  Returns an empty list (proceed normally) when
    no case context is loaded, so callers never need to guard separately.

    When *evidence_path* is provided, only sources whose ``source_path``
    matches the given evidence file are considered. This ensures that
    adding new evidence (e.g. a second memory dump) is not blocked by
    sources produced from different evidence files.

    Args:
        source_prefixes: List of source name prefixes to check
            (e.g. ``["bulk."]``, ``["evtx."]``).
        evidence_path: If provided, only count sources originating from
            this specific evidence file path.

    Returns:
        List of existing source names that match any of the given prefixes.
        An empty list means no prior extraction data exists.
    """
    if not has_ctx():
        return []
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    existing: list[str] = []
    for src in sources:
        if evidence_path and src.source_path != evidence_path:
            continue
        for prefix in source_prefixes:
            if src.source_name.startswith(prefix):
                existing.append(src.source_name)
                break
    return existing


TOOL_SOURCE_PREFIXES: dict[str, list[str]] = {
    "run_volatility_batch": ["volatility."],
    "run_volatility": ["volatility."],
    "run_fls": ["tsk.filelist"],
    "run_bulk_extractor": ["bulk."],
    "run_evtx_parser": ["evtx.", "ez.evtx"],
    "run_hayabusa": ["hayabusa."],
    "run_chainsaw": ["chainsaw."],
    "run_registry_parser": ["registry."],
    "run_prefetch_parser": ["prefetch.", "ez.prefetch"],
    "run_amcache_parser": ["amcache.", "ez.amcache"],
    "run_shimcache_parser": ["shimcache.", "ez.shimcache"],
    "run_mft_parser": ["mft.", "ez.mft"],
    "run_zircolite": ["zircolite."],
    "parse_autoruns": ["autoruns."],
}
"""Maps extraction tool names to the source prefixes they produce.

Used by ``start_extraction_batch`` to skip submitting jobs for tools
whose output sources already exist in the case database. Tools not
listed here are always submitted (they either lack idempotency checks
or produce unique per-invocation sources).
"""


def tool_already_indexed(tool_name: str, evidence_path: str | None = None) -> list[str]:
    """Check whether a tool's output sources already exist in the case DB.

    Looks up the tool's known source prefixes in ``TOOL_SOURCE_PREFIXES``
    and delegates to ``sources_already_indexed``. Returns an empty list
    for tools without a known mapping or when no case context is loaded.

    When *evidence_path* is provided, only sources produced from that
    specific evidence file are considered. This allows the same tool to
    run on new evidence without being blocked by prior results from
    different evidence files.

    Args:
        tool_name: MCP tool function name (e.g. ``"run_fls"``).
        evidence_path: If provided, scope the check to sources from
            this evidence file only.

    Returns:
        List of existing source names, or empty if none found.
    """
    prefixes = TOOL_SOURCE_PREFIXES.get(tool_name)
    if not prefixes:
        return []
    return sources_already_indexed(prefixes, evidence_path=evidence_path)


def run_cli_tool(
    *,
    binary: str,
    cmd: list[str],
    tool_name: str,
    params: dict[str, object],
    source_name: str,
    source_path: str,
    extractor_label: str,
    timeout: int = TOOL_TIMEOUT,
    check_exists: str | None = None,
) -> dict[str, object]:
    """Run a CLI forensic tool and index its stdout output.

    Handles binary availability check, subprocess execution with timeout,
    error reporting, extract-and-index, and audit logging in a single call.

    Args:
        binary: Name of the required binary (checked via require_binary).
        cmd: Full command list to pass to subprocess.run.
        tool_name: MCP tool name for audit logging.
        params: Tool parameters dict for audit logging.
        source_name: Source label for indexing (e.g. "strings.output").
        source_path: Evidence file path for source registration.
        extractor_label: Short extractor name for the DB record.
        timeout: Subprocess timeout in seconds.
        check_exists: Optional file path to verify exists before running.

    Returns:
        Standardized tool response dict (success or error).
    """
    import time

    from mulder.server.extract_helpers import extract_and_index

    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if not require_binary(binary):
        return error_response(
            tc_id,
            tool_name,
            params,
            f"{binary} not found on PATH",
            error_type="binary_missing",
        )

    if check_exists and not Path(check_exists).exists():
        return error_response(
            tc_id,
            tool_name,
            params,
            f"File not found: {check_exists}",
            error_type="file_not_found",
        )

    result = run_subprocess(cmd, timeout=timeout)
    if isinstance(result, str):
        return error_response(tc_id, tool_name, params, result, error_type="timeout")
    proc = result

    summary = extract_and_index(proc.stdout.strip(), source_name, source_path, extractor_label)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, tool_name, params, summary, source_name, elapsed)
