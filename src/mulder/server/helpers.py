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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ParamSpec
from uuid import uuid4

from mulder.execution import (
    CommandPolicy,
    CommandRequest,
    CommandRunner,
    ExecutionAuditEvent,
    ExecutionStatus,
    NetworkClass,
    PathAccess,
    PathArgument,
)
from mulder.models import (
    CoverageMetadata,
    ToolExecutionMetadata,
    ToolOutcome,
    ToolOutcomeStatus,
)
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
    input_paths: tuple[Path, ...] = (),
    output_paths: tuple[Path, ...] = (),
    allowed_roots: tuple[Path, ...] = (),
    environment: dict[str, str] | None = None,
    network_class: NetworkClass = NetworkClass.NONE,
    max_output_bytes: int = 16 * 1024 * 1024,
) -> subprocess.CompletedProcess[Any] | str:
    """Run a command through the centralized, no-network policy seam.

    Returns the CompletedProcess on success, or an error message string
    on timeout/OS failure. Callers check ``isinstance(result, str)`` to
    detect failures.
    """
    if not cmd:
        return "Failed to run command: empty argv"
    resolved = require_binary(cmd[0])
    if resolved is None:
        return f"Failed to run {cmd[0]}: executable not found"

    def audit_sink(event: ExecutionAuditEvent) -> None:
        if has_ctx():
            get_ctx().audit.log_execution_decision(event.as_mapping())

    bound_inputs: set[Path] = set()
    bound_outputs: set[Path] = set()
    arguments: list[str | PathArgument] = []
    for argument in cmd[1:]:
        argument_path = Path(argument)
        matching_input = next((path for path in input_paths if path == argument_path), None)
        matching_output = next((path for path in output_paths if path == argument_path), None)
        if matching_input is not None and matching_output is not None:
            arguments.append(PathArgument(matching_input, PathAccess.READ_WRITE))
            bound_inputs.add(matching_input)
            bound_outputs.add(matching_output)
        elif matching_input is not None:
            arguments.append(PathArgument(matching_input, PathAccess.READ))
            bound_inputs.add(matching_input)
        elif matching_output is not None:
            arguments.append(PathArgument(matching_output, PathAccess.WRITE))
            bound_outputs.add(matching_output)
        else:
            arguments.append(argument)
    if bound_inputs != set(input_paths) or bound_outputs != set(output_paths):
        return "Failed to run command: a declared path is not bound to argv"
    request = CommandRequest(
        executable=resolved,
        arguments=tuple(arguments),
        timeout_seconds=timeout,
        environment=environment or {},
        network_class=network_class,
        max_output_bytes=max_output_bytes,
    )
    policy = CommandPolicy.for_executable(
        resolved,
        allowed_roots=allowed_roots,
        max_timeout_seconds=timeout,
        max_output_bytes=max_output_bytes,
    )
    result = CommandRunner(policy, audit_sink=audit_sink).run(request)
    if result.status is ExecutionStatus.TIMED_OUT:
        return f"{cmd[0]} timed out after {timeout}s"
    if result.status is ExecutionStatus.OUTPUT_LIMIT:
        return result.error or f"{cmd[0]} exceeded its output limit"
    if result.status in {ExecutionStatus.DENIED, ExecutionStatus.FAILED}:
        return result.error or f"Failed to run {cmd[0]}"

    stdout: str | bytes = result.stdout
    stderr: str | bytes = result.stderr
    if text:
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=result.returncode or 0,
        stdout=stdout,
        stderr=stderr,
    )


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
                audit_params = dict(kwargs)
                returned_window_ids = result.get("returned_window_ids")
                if isinstance(returned_window_ids, list):
                    audit_params["returned_window_ids"] = returned_window_ids
                for result_key, param_key in (
                    ("source", "source"),
                    ("source_name", "source"),
                    ("sources_matched", "sources"),
                ):
                    value = result.get(result_key)
                    if value is not None:
                        audit_params[param_key] = value
                ctx.audit.log_tool_call(
                    tool_call_id=tc_id,
                    tool_name=tool_name,
                    params=audit_params,
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

_HASH_PREFIX = "blake2b:"
_HASH_DIGEST_SIZE = 32


def _blake2b_hex(data: bytes) -> str:
    return _HASH_PREFIX + hashlib.blake2b(data, digest_size=_HASH_DIGEST_SIZE).hexdigest()


def hash_output(output: object) -> str:
    """Return a BLAKE2b commitment to the complete JSON form of *output*.

    The previous large-value heuristic committed only a length, key set, or
    short prefix.  That was useful as a cache fingerprint but unsuitable for
    an audit record: different tool outputs could have the same digest.  The
    existing algorithm and serialization remain stable for small values while
    all values now commit their complete serialized content.
    """
    raw = json.dumps(output, sort_keys=True, default=str)
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


def _infer_success_status(results: object, source: str | None) -> ToolOutcomeStatus:
    """Classify legacy success payloads without an optimistic default."""
    if isinstance(results, list | tuple | set | frozenset):
        return (
            ToolOutcomeStatus.SUCCESS_NONEMPTY if len(results) else ToolOutcomeStatus.SUCCESS_EMPTY
        )
    if isinstance(results, Mapping):
        for count_key in ("result_count", "count", "rows", "windows_indexed", "line_count"):
            count = results.get(count_key)
            if isinstance(count, int):
                return (
                    ToolOutcomeStatus.SUCCESS_NONEMPTY
                    if count > 0
                    else ToolOutcomeStatus.SUCCESS_EMPTY
                )
        for collection_key in ("results", "records", "items", "matches", "windows"):
            collection = results.get(collection_key)
            if isinstance(collection, list | tuple | set | frozenset | Mapping):
                return (
                    ToolOutcomeStatus.SUCCESS_NONEMPTY
                    if len(collection)
                    else ToolOutcomeStatus.SUCCESS_EMPTY
                )
        if not results:
            return ToolOutcomeStatus.SUCCESS_EMPTY
        if source is not None and has_ctx():
            windows = get_ctx().db.get_windows_by_source(source)
            return (
                ToolOutcomeStatus.SUCCESS_NONEMPTY
                if windows
                else ToolOutcomeStatus.SUCCESS_EMPTY
            )
        return ToolOutcomeStatus.PARTIAL
    if results in (None, "", b""):
        return ToolOutcomeStatus.SUCCESS_EMPTY
    return ToolOutcomeStatus.SUCCESS_NONEMPTY


def _source_ids_from_params(params: Mapping[str, object]) -> list[str]:
    """Derive source identifiers from the bounded public parameter contract."""
    source_ids: set[str] = set()
    for name in ("source", "source_name"):
        value = params.get(name)
        if isinstance(value, str) and value:
            source_ids.add(value)
    values = params.get("sources")
    if isinstance(values, list):
        source_ids.update(value for value in values if isinstance(value, str) and value)
    return sorted(source_ids)


def _attach_execution(
    outcome: ToolOutcome,
    *,
    output_digest: str,
    elapsed_ms: float,
    source_ids: list[str],
) -> ToolOutcome:
    """Replace a legacy marker with the exact execution commitment."""
    ended = datetime.now(timezone.utc)
    started = ended - timedelta(milliseconds=max(0.0, elapsed_ms))
    payload = outcome.model_dump(mode="json")
    payload["execution"] = ToolExecutionMetadata(
        source_ids=sorted(set(source_ids)),
        started_at=started,
        ended_at=ended,
        output_digest=output_digest,
    ).model_dump(mode="json")
    payload["legacy_mapping"] = None
    return ToolOutcome.model_validate(payload)


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

    committed_output = {
        "source": source,
        "results": results,
        "total_windows": total,
    }
    output_digest = hash_output(committed_output)
    if has_ctx():
        ctx = get_ctx()
        audit_params = dict(params)
        audit_params.setdefault("source", source)
        audit_params["returned_window_ids"] = [
            window_id
            for item in results
            if type(window_id := item.get("window_id")) is int and window_id > 0
        ]
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name=tool_name,
            params=audit_params,
            output_hash=output_digest,
            duration_ms=elapsed_ms,
            batch_id=current_batch_id.get(),
        )
    if total > cap:
        outcome_status = ToolOutcomeStatus.SAMPLED
    elif total == 0:
        outcome_status = ToolOutcomeStatus.SUCCESS_EMPTY
    else:
        outcome_status = ToolOutcomeStatus.SUCCESS_NONEMPTY
    outcome = _attach_execution(
        ToolOutcome(
            status=outcome_status,
            coverage=CoverageMetadata(
                rows_examined=len(results),
                rows_total=total,
                sample_reason=(f"response capped at {cap} windows" if total > cap else None),
            ),
        ),
        output_digest=output_digest,
        elapsed_ms=elapsed_ms,
        source_ids=[source],
    )
    resp: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "outcome": outcome.model_dump(mode="json"),
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
    outcome: ToolOutcome | None = None,
) -> dict[str, object]:
    """Build an audited success response and log the tool call.

    ``outcome`` is the precise, versioned execution contract. When omitted,
    empty/non-empty state is derived from the returned value instead of being
    optimistically classified as non-empty.
    The legacy top-level ``status`` is retained for existing clients.

    When *source* is provided (indicating data has been indexed into the
    case DB), returns a compact response with only a preview of the output.
    The agent should use ``search()`` or ``get_raw_output()`` to access
    the full data.

    When *source* is None, returns the full results (for read/reference
    tools whose output is not indexed elsewhere).
    """
    if outcome is None:
        inferred_status = _infer_success_status(results, source)
        outcome = ToolOutcome(
            status=inferred_status,
            reason=(
                "Result cardinality could not be inferred; caller must provide an explicit outcome"
                if inferred_status is ToolOutcomeStatus.PARTIAL
                else None
            ),
        )
    output_digest = hash_output(results)
    precise_outcome = _attach_execution(
        outcome,
        output_digest=output_digest,
        elapsed_ms=elapsed_ms,
        source_ids=[source] if source is not None else [],
    )

    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name=tool_name,
            params={**dict(params), **({"source": source} if source is not None else {})},
            output_hash=output_digest,
            duration_ms=elapsed_ms,
            batch_id=current_batch_id.get(),
        )

    if source is None:
        return {
            "tool_call_id": tc_id,
            "status": "success",
            "outcome": precise_outcome.model_dump(mode="json"),
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
        "outcome": precise_outcome.model_dump(mode="json"),
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
    outcome_status: ToolOutcomeStatus | None = None,
    coverage: CoverageMetadata | None = None,
) -> dict[str, object]:
    """Build an audited error response and log the tool call.

    Common legacy error types are mapped to precise outcome states.  A caller
    can supply ``outcome_status`` and ``coverage`` when it knows more.
    """
    if outcome_status is None:
        if error_type == "timeout":
            outcome_status = ToolOutcomeStatus.TIMED_OUT
        elif error_type in {
            "binary_missing",
            "file_not_found",
            "hive_not_found",
            "no_filelist",
        }:
            outcome_status = ToolOutcomeStatus.UNAVAILABLE
        else:
            outcome_status = ToolOutcomeStatus.FAILED
    error_payload = {"error": error, "error_type": error_type}
    outcome = _attach_execution(
        ToolOutcome(
            status=outcome_status,
            coverage=coverage or CoverageMetadata(),
            reason=error,
        ),
        output_digest=hash_output(error_payload),
        elapsed_ms=elapsed_ms,
        source_ids=_source_ids_from_params(params),
    )
    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name=tool_name,
            params=params,
            output_hash=hash_output(error_payload),
            duration_ms=elapsed_ms,
            batch_id=current_batch_id.get(),
        )
    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "error",
        "outcome": outcome.model_dump(mode="json"),
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

    resolved_binary = require_binary(binary)
    if resolved_binary is None:
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

    declared_input = Path(check_exists or source_path)
    pinned_cmd = [resolved_binary, *cmd[1:]]
    result = run_subprocess(
        pinned_cmd,
        timeout=timeout,
        input_paths=(declared_input,),
        allowed_roots=(declared_input,),
    )
    if isinstance(result, str):
        return error_response(tc_id, tool_name, params, result, error_type="timeout")
    proc = result

    summary = extract_and_index(proc.stdout.strip(), source_name, source_path, extractor_label)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, tool_name, params, summary, source_name, elapsed)
