"""FastMCP server definition and initialization for Mulder."""

from __future__ import annotations

import functools
import inspect
import logging
import os
import re
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

import anyio
from mcp.server.fastmcp import FastMCP

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.index.correlator import Correlator
from mulder.server.jobs import JobStore
from mulder.server.tool_access import EXECUTORS, tool_access

logger = logging.getLogger(__name__)

mcp = FastMCP("Mulder")

# ---------------------------------------------------------------------------
# Concurrent tool execution: wrap every sync @mcp.tool() to run in a thread
# pool so that the MCP SDK's task-group dispatch can execute them in parallel.
# ---------------------------------------------------------------------------

_P = ParamSpec("_P")
_R = TypeVar("_R")

_tool_limiter: anyio.CapacityLimiter | None = None


def _get_tool_limiter() -> anyio.CapacityLimiter:
    """Return the shared CapacityLimiter initialized by init_server."""
    assert _tool_limiter is not None, "init_server() must be called first"
    return _tool_limiter


def _wrap_sync_tool(fn: Callable[_P, _R]) -> Callable[_P, Awaitable[_R]]:
    """Return an async wrapper that runs *fn* in a worker thread.

    Resource throttling happens on the event loop via
    ``async_wait_for_resources`` (using ``anyio.sleep``) so the MCP
    transport stays responsive to heartbeats and new requests while
    the tool waits for CPU/memory pressure to subside.  The actual
    tool execution then runs in a worker thread.
    """
    tool_name = getattr(fn, "__name__", "unknown")

    @functools.wraps(fn)
    async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        """Async bridge that throttles then dispatches *fn* in a thread."""
        await async_wait_for_resources(tool_name)
        return await anyio.to_thread.run_sync(
            functools.partial(fn, *args, **kwargs),
            limiter=_get_tool_limiter(),
        )

    return wrapper


_original_mcp_tool = mcp.tool
_tool_dispatch: dict[str, Callable[..., Any]] = {}
_tool_dispatch_sync: dict[str, Callable[..., Any]] = {}


def _concurrent_tool(**kwargs: Any) -> Callable[..., Any]:
    """Drop-in replacement for ``mcp.tool()`` that auto-threads sync handlers."""
    original_decorator = _original_mcp_tool(**kwargs)

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        """Register *fn* with the MCP server, wrapping sync handlers for threading."""
        tool_name = kwargs.get("name") or fn.__name__
        _tool_dispatch_sync[tool_name] = fn
        if not inspect.iscoroutinefunction(fn):
            fn = _wrap_sync_tool(fn)
        _tool_dispatch[tool_name] = fn
        return original_decorator(fn)

    return decorator


mcp.tool = _concurrent_tool  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Resource-aware throttle: every tool call checks memory/CPU before running.
# ---------------------------------------------------------------------------

_RESOURCE_CHECK_INTERVAL = 5  # seconds between rechecks when throttled
_RESOURCE_MAX_WAIT = 300  # max total wait before proceeding anyway


_psutil_seeded = False


def _get_resource_usage() -> tuple[float, float]:
    """Return (memory_percent, cpu_percent) as system-wide 0-100 values.

    ``psutil.cpu_percent(interval=None)`` returns average CPU usage
    across **all** cores since the last call.  The first call after
    import always returns 0.0, so we seed it once at startup (see
    ``_seed_psutil``).  After that, each call reflects real usage.

    Returns ``(-1, -1)`` if neither psutil nor ``/proc`` is available.
    """
    global _psutil_seeded  # noqa: PLW0603
    try:
        import psutil

        if not _psutil_seeded:
            psutil.cpu_percent(interval=None)
            _psutil_seeded = True
        mem = psutil.virtual_memory().percent
        cpu = psutil.cpu_percent(interval=None)
        return mem, cpu
    except (ImportError, AttributeError):
        pass
    try:
        mem_pct = -1.0
        with open("/proc/meminfo") as f:
            total = avail = 0
            for line in f:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1])
            if total > 0:
                mem_pct = 100.0 * (1 - avail / total)
        cpu_pct = -1.0
        with open("/proc/loadavg") as f:
            import os

            load1 = float(f.read().split()[0])
            ncpu = os.cpu_count() or 1
            cpu_pct = min(100.0, 100.0 * load1 / ncpu)
        return mem_pct, cpu_pct
    except OSError:
        return -1.0, -1.0


def _check_resource_pressure() -> tuple[bool, str]:
    """Return ``(ok, reason_string)`` for current resource levels."""
    cfg = _cfg
    if cfg is None:
        return True, ""
    mem_limit = cfg.mem_percent_limit
    cpu_limit = cfg.cpu_percent_limit
    if mem_limit <= 0 and cpu_limit <= 0:
        return True, ""

    mem, cpu = _get_resource_usage()
    mem_ok = mem < 0 or mem_limit <= 0 or mem < mem_limit
    cpu_ok = cpu < 0 or cpu_limit <= 0 or cpu < cpu_limit
    if mem_ok and cpu_ok:
        return True, ""
    parts: list[str] = []
    if not mem_ok:
        parts.append(f"mem={mem:.0f}%>={mem_limit}%")
    if not cpu_ok:
        parts.append(f"cpu={cpu:.0f}%>={cpu_limit}%")
    return False, ", ".join(parts)


async def async_wait_for_resources(tool_name: str = "") -> None:
    """Async throttle for MCP tool calls; yields to the event loop while waiting.

    Uses ``anyio.sleep`` so the MCP event loop can still process
    heartbeats and new requests while this tool waits for resources
    to free up.  This prevents the MCP client from timing out.
    """
    waited = 0.0
    while waited < _RESOURCE_MAX_WAIT:
        ok, reason = _check_resource_pressure()
        if ok:
            return
        logger.info(
            "Resource throttle: %s waiting (%s, waited %.0fs)",
            tool_name or "tool",
            reason,
            waited,
        )
        await anyio.sleep(_RESOURCE_CHECK_INTERVAL)
        waited += _RESOURCE_CHECK_INTERVAL


def wait_for_resources(tool_name: str = "") -> None:
    """Blocking throttle for background job threads.

    Uses ``time.sleep``, only safe for threads that are NOT on the
    MCP event loop (i.e. background ``JobStore`` workers).  MCP tool
    calls use ``async_wait_for_resources`` instead so the event loop
    stays responsive.
    """
    waited = 0.0
    while waited < _RESOURCE_MAX_WAIT:
        ok, reason = _check_resource_pressure()
        if ok:
            return
        logger.info(
            "Resource throttle: %s waiting (%s, waited %.0fs)",
            tool_name or "tool",
            reason,
            waited,
        )
        time.sleep(_RESOURCE_CHECK_INTERVAL)
        waited += _RESOURCE_CHECK_INTERVAL


@dataclass
class ServerConfig:
    """Immutable server-level settings shared across case loads."""

    db_dir: Path
    max_workers: int = 8
    mem_percent_limit: float = 90.0
    cpu_percent_limit: float = 90.0


@dataclass
class ServerContext:
    """Shared state available to every MCP tool at runtime."""

    case_id: str
    db: CaseDB
    correlator: Correlator
    audit: AuditLog


_cfg: ServerConfig | None = None
_ctx: ServerContext | None = None
_ctx_lock = threading.Lock()
_job_store: JobStore | None = None


def get_cfg() -> ServerConfig:
    """Return the server config or raise if not initialised."""
    if _cfg is None:
        raise RuntimeError("Server not initialised. Call init_server() first.")
    return _cfg


def get_ctx() -> ServerContext:
    """Return the active case context or raise if no case is loaded."""
    if _ctx is None:
        raise RuntimeError("No case loaded. Call scan_evidence or open_case first.")
    return _ctx


def has_ctx() -> bool:
    """Return True if a case is currently loaded."""
    return _ctx is not None


def get_job_store() -> JobStore:
    """Return the background job store or raise if not initialised."""
    if _job_store is None:
        raise RuntimeError("Server not initialised. Call init_server() first.")
    return _job_store


def slugify(name: str) -> str:
    """Convert a directory name into a valid case ID."""
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-") or "case"


def init_server(
    db_dir: Path,
    case_id: str | None = None,
    max_workers: int = 8,
    mem_percent_limit: float = 90.0,
    cpu_percent_limit: float = 90.0,
    **_kwargs: object,
) -> None:
    """Initialise server-level config and optionally pre-load a case.

    Called by ``cli.py`` before ``mcp.run()``.
    """
    global _cfg, _job_store, _tool_limiter  # noqa: PLW0603

    _cfg = ServerConfig(
        db_dir=db_dir,
        max_workers=max_workers,
        mem_percent_limit=mem_percent_limit,
        cpu_percent_limit=cpu_percent_limit,
    )

    _tool_limiter = anyio.CapacityLimiter(max_workers)

    _job_store = JobStore(
        max_workers=max_workers,
        tool_dispatch=_tool_dispatch_sync,  # Shared mutable ref; late registrations visible
    )

    _seed_psutil()

    if case_id is not None:
        load_case(case_id)

    logger.info("Mulder MCP server ready (db_dir=%s)", db_dir)


def _seed_psutil() -> None:
    """Prime psutil's CPU counter so the first real check returns valid data."""
    global _psutil_seeded  # noqa: PLW0603
    try:
        import psutil

        psutil.cpu_percent(interval=None)
        _psutil_seeded = True
    except (ImportError, AttributeError):
        pass


def _close_current_ctx() -> None:
    """Close the current case context if one is active."""
    global _ctx  # noqa: PLW0603
    with _ctx_lock:
        if _ctx is None:
            return
        if _job_store is not None:
            for batch_id in _job_store.batch_ids():
                status = _job_store.get_batch_status(batch_id)
                if status and not status.get("all_done"):
                    raise RuntimeError(
                        f"Cannot switch cases: batch {batch_id} still has "
                        f"active jobs. Wait for completion or call wait(batch_id)."
                    )
        if _ctx.db is not None:
            try:
                _ctx.db.close()
            except Exception:
                logger.warning("Error closing case DB", exc_info=True)
        _ctx = None


def _build_context(case_id: str, db: CaseDB) -> ServerContext:
    """Build a ServerContext from a CaseDB."""
    global _ctx  # noqa: PLW0603

    cfg = get_cfg()
    correlator = Correlator(db=db)
    audit = AuditLog(cfg.db_dir / f"{case_id}.audit.jsonl")

    with _ctx_lock:
        _ctx = ServerContext(
            case_id=case_id,
            db=db,
            correlator=correlator,
            audit=audit,
        )
    logger.info("Server context ready for case '%s'", case_id)
    return _ctx


def load_case(case_id: str) -> ServerContext:
    """Open (or re-open) a case and set it as the active context.

    Swaps the context atomically so background threads never see
    ``_ctx = None``.  The old database is closed *after* the new
    context is installed.
    """
    global _ctx  # noqa: PLW0603

    cfg = get_cfg()
    logger.info("Opening case database for '%s' ...", case_id)

    with _ctx_lock:
        if _ctx is not None and _job_store is not None:
            for batch_id in _job_store.batch_ids():
                status = _job_store.get_batch_status(batch_id)
                if status and not status.get("all_done"):
                    raise RuntimeError(
                        f"Cannot switch cases: batch {batch_id} still has "
                        f"active jobs. Wait for completion or call wait(batch_id)."
                    )
        old_ctx = _ctx

    new_db = CaseDB.open(case_id, cfg.db_dir)
    correlator = Correlator(db=new_db)
    audit = AuditLog(cfg.db_dir / f"{case_id}.audit.jsonl")
    new_ctx = ServerContext(
        case_id=case_id,
        db=new_db,
        correlator=correlator,
        audit=audit,
    )

    with _ctx_lock:
        _ctx = new_ctx

    if old_ctx is not None and old_ctx.db is not None:
        try:
            old_ctx.db.close()
        except Exception:
            logger.warning("Error closing previous case DB", exc_info=True)

    logger.info("Server context ready for case '%s'", case_id)
    return new_ctx


def _try_open_existing(
    case_id: str,
    evidence_root: str,
    replace: bool,
    db_dir: Path,
) -> dict[str, object] | None:
    """Attempt to open an existing case DB, protecting populated databases.

    Returns a response dict if the existing DB was opened (or an error
    response for corrupt DBs when ``replace`` is False). Returns ``None``
    when the caller should proceed to create a fresh database (only
    possible for empty, corrupt DBs with ``replace=True``).
    """
    try:
        existing = CaseDB.open(case_id, db_dir)
        meta = existing.get_case_metadata()
        source_count = existing.get_source_count()
    except Exception as exc:
        if not replace:
            logger.exception("Failed to open existing case '%s'", case_id)
            from mulder.server.helpers import error_response, make_tool_call_id

            return error_response(
                make_tool_call_id(),
                "create_case",
                {"case_id": case_id, "evidence_root": evidence_root, "replace": replace},
                f"Failed to open existing case DB: {exc}",
                error_type="database_error",
                suggestion="Use replace=true to recreate the case.",
            )
        logger.warning(
            "Existing DB for '%s' is corrupt and replace=True; recreating.",
            case_id,
        )
        return None

    if source_count > 0:
        if replace:
            logger.warning(
                "Refusing to replace case '%s': database has %d indexed "
                "source(s). Opening existing database instead.",
                case_id,
                source_count,
            )
        _build_context(case_id, existing)
        return {
            "status": "case_exists",
            "case_id": case_id,
            "created_at": meta.ingested_at,
            "evidence_root": meta.evidence_root,
            "source_count": source_count,
            "message": (
                f"Case '{case_id}' loaded ({source_count} sources already indexed). "
                "Archives were extracted by the catalog phase. "
                "Proceed directly with analysis tools (run_volatility, run_fls, "
                "run_evtx_parser, etc.). Do NOT re-extract archives."
            ),
        }

    if not replace:
        _build_context(case_id, existing)
        return {
            "status": "case_exists",
            "case_id": case_id,
            "created_at": meta.ingested_at,
            "evidence_root": meta.evidence_root,
            "source_count": source_count,
            "message": (
                f"Case '{case_id}' loaded (0 sources indexed). Proceed with extraction tools."
            ),
        }

    existing.close()
    return None


def create_case(
    case_id: str, evidence_root: str, replace: bool = False
) -> ServerContext | dict[str, object]:
    """Create a new empty case and set it as the active context.

    No extractors are run; the agent populates the case incrementally
    by calling Tier 2 extraction tools.

    If a database for this case already exists and contains indexed
    sources, it is always opened rather than replaced. This prevents
    a second server instance (e.g. spawned between pipeline phases)
    from silently wiping extraction data. The ``replace`` flag only
    takes effect when the existing database is empty.

    When ``MULDER_CASE_ID`` is set in the environment, only that case
    ID is allowed. Attempts to create a different case are rejected
    and the enforced case is loaded instead.
    """
    enforced_id = os.environ.get("MULDER_CASE_ID", "")
    if enforced_id and case_id != enforced_id:
        logger.warning(
            "Refusing to create case '%s': MULDER_CASE_ID enforces '%s'. "
            "Loading the enforced case instead.",
            case_id,
            enforced_id,
        )
        ctx = load_case(enforced_id)
        return {
            "status": "case_exists",
            "case_id": enforced_id,
            "source_count": ctx.db.get_source_count(),
            "message": (
                f"MULDER_CASE_ID enforces case '{enforced_id}'. "
                f"Refused to create '{case_id}'. Using enforced case."
            ),
        }

    _close_current_ctx()

    cfg = get_cfg()

    db_file = cfg.db_dir / f"{case_id}.db"
    if db_file.exists():
        existing = _try_open_existing(case_id, evidence_root, replace, cfg.db_dir)
        if existing is not None:
            return existing

    if db_file.exists():
        db_file.unlink()
        for suffix in (".audit.jsonl", ".report.md", ".plaso"):
            sidecar = cfg.db_dir / f"{case_id}{suffix}"
            if sidecar.exists():
                sidecar.unlink()

    logger.info("Creating empty case database for '%s' ...", case_id)

    db = CaseDB.create(case_id, evidence_root, cfg.db_dir)
    return _build_context(case_id, db)


_PARALLEL_TEXT_CAP = 500
_PARALLEL_RESULTS_CAP = 5


def _slim_result(result: Any) -> Any:
    """Trim a sub-tool result for inclusion in a run_parallel response.

    Caps inline ``raw_text`` and large ``results`` arrays so the
    combined parallel response stays within a reasonable token budget.
    Full data remains in the case DB for retrieval via ``search()`` or
    ``get_raw_output()``.
    """
    if not isinstance(result, dict):
        return result
    slimmed = dict(result)

    if isinstance(slimmed.get("raw_text"), str):
        text = slimmed["raw_text"]
        if len(text) > _PARALLEL_TEXT_CAP:
            slimmed["raw_text"] = text[:_PARALLEL_TEXT_CAP]
            slimmed["raw_text_truncated"] = True

    if isinstance(slimmed.get("results"), list):
        full = slimmed["results"]
        if len(full) > _PARALLEL_RESULTS_CAP:
            slimmed["results"] = full[:_PARALLEL_RESULTS_CAP]
            slimmed["results_truncated"] = True
            slimmed["results_total"] = len(full)

    if isinstance(slimmed.get("results"), dict):
        inner = dict(slimmed["results"])
        slimmed["results"] = inner
        for k, v in inner.items():
            if isinstance(v, str) and len(v) > _PARALLEL_TEXT_CAP:
                inner[k] = v[:_PARALLEL_TEXT_CAP]
                slimmed.setdefault("truncated_fields", []).append(k)

    return slimmed


_SEQUENTIAL_ONLY: set[str] = {
    "run_bulk_extractor",
}


@mcp.tool()
@tool_access(EXECUTORS)
async def run_parallel(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    """Run multiple tool calls in parallel and return all results.

    Use this when you need to run the same tool on multiple evidence items
    (e.g., extracting 4 archives, running fls on 4 disk images) or any mix
    of independent tools that can safely execute concurrently.

    Each task specifies a tool name and its arguments.  All tasks execute
    in parallel worker threads bounded by ``max_workers``.  Tools that
    spawn heavy child processes (e.g. ``run_bulk_extractor``) are
    automatically run sequentially to avoid resource exhaustion.

    Args:
        tasks: List of objects, each with ``tool`` (tool name string) and
            ``args`` (dict of keyword arguments for that tool).
    """
    from uuid import uuid4

    from mulder.server.helpers import current_batch_id, hash_output

    batch_id = f"bp_{uuid4().hex[:8]}"
    results: list[Any] = [None] * len(tasks)

    async def _run_one(idx: int, tool_name: str, arguments: dict[str, Any]) -> None:
        """Execute a single task and store its result at *idx*."""
        token = current_batch_id.set(batch_id)
        try:
            fn = _tool_dispatch.get(tool_name)
            if fn is None:
                results[idx] = {"error": f"Unknown tool: {tool_name}"}
                return
            try:
                results[idx] = await fn(**arguments)
            except Exception as exc:
                logger.exception("run_parallel: %s failed", tool_name)
                results[idx] = {"error": f"{tool_name} failed: {exc}"}
        finally:
            current_batch_id.reset(token)

    for i, task in enumerate(tasks):
        if not isinstance(task, dict) or "tool" not in task:
            results[i] = {"error": f"Task {i} missing required 'tool' key"}

    valid_tasks = [
        (i, t)
        for i, t in enumerate(tasks)
        if results[i] is None and isinstance(t, dict) and "tool" in t
    ]
    parallel_tasks = [(i, t) for i, t in valid_tasks if t["tool"] not in _SEQUENTIAL_ONLY]
    sequential_tasks = [(i, t) for i, t in valid_tasks if t["tool"] in _SEQUENTIAL_ONLY]

    t0 = time.monotonic()

    async with anyio.create_task_group() as tg:
        for i, task in parallel_tasks:
            tg.start_soon(_run_one, i, task["tool"], task.get("args", {}))

    for i, task in sequential_tasks:
        await _run_one(i, task["tool"], task.get("args", {}))

    elapsed_ms = (time.monotonic() - t0) * 1000

    sub_call_ids = [
        r.get("tool_call_id", "") for r in results if isinstance(r, dict) and "tool_call_id" in r
    ]

    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=batch_id,
            tool_name="run_parallel",
            params={"tasks": [t["tool"] for t in tasks]},
            output_hash=hash_output(results),
            duration_ms=elapsed_ms,
            sub_calls=sub_call_ids,
            batch_id=None,
        )

    return {
        "batch_id": batch_id,
        "parallel_results": [
            {"tool": tasks[i]["tool"], "result": _slim_result(results[i])}
            for i in range(len(tasks))
        ],
        "total_tasks": len(tasks),
    }


import mulder.server.tools as _tools  # noqa: E402, F401
