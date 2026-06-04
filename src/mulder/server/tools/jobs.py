"""MCP tools for the async extraction job queue.

These tools replace ``run_parallel`` for slow Tier-2 extraction work.
The agent calls ``start_extraction_batch`` to launch background jobs,
then polls with ``check_extraction_status`` while doing fast analysis,
and retrieves results with ``get_completed_results``.

These tools guard audit logging with ``has_ctx()`` because job queue
operations can execute before or after a case context exists. The batch
submission and polling tools must remain functional even when no case
is active (e.g. during startup or after context teardown), so audit
calls are conditional rather than mandatory.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from mulder.server.app import get_ctx, mcp
from mulder.server.tool_access import Role, tool_access

if TYPE_CHECKING:
    from mulder.server.jobs import JobStore
from mulder.server.helpers import hash_output, make_tool_call_id, tool_already_indexed

logger = logging.getLogger(__name__)


def _get_job_store() -> JobStore:
    """Import lazily to avoid circular import at module level."""
    from mulder.server.app import get_job_store

    return get_job_store()


@mcp.tool()
@tool_access(Role.CATALOG | Role.EXTRACT_EXECUTOR)
def start_extraction_batch(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    """Submit long-running extraction tools for background execution and return immediately.

    Call after open_case when you have a plan with slow Tier-2 tools
    (Volatility, Plaso, bulk_extractor, fls, EVTX, registry). Tools
    already indexed are auto-skipped. Use run_parallel for fast tools
    (extract_archive, run_mmls, composite tools).

    Returns a batch_id for tracking. Poll with
    check_extraction_status(batch_id) and retrieve results with
    get_completed_results(batch_id).

    Args:
        tasks: List of objects, each with ``tool`` (tool name string) and
            ``args`` (dict of keyword arguments for that tool).  Example::

                [
                    {"tool": "run_volatility_batch",
                     "args": {"plugins": [...], "memory_path": "..."}},
                    {"tool": "run_fls",
                     "args": {"image_path": "..."}},
                    {"tool": "run_bulk_extractor",
                     "args": {"image_path": "...", "scanners": [...]}},
                ]
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    store = _get_job_store()

    from mulder.server.app import _tool_dispatch_sync

    invalid = [t["tool"] for t in tasks if t["tool"] not in _tool_dispatch_sync]
    if invalid:
        elapsed = (time.monotonic() - t0) * 1000
        try:
            ctx = get_ctx()
            ctx.audit.log_tool_call(
                tool_call_id=tc_id,
                tool_name="start_extraction_batch",
                params={"tasks": [t["tool"] for t in tasks]},
                output_hash=hash_output({"error": "unknown_tools", "tools": invalid}),
                duration_ms=elapsed,
            )
        except RuntimeError:
            logger.warning("Audit skipped: no active case context for start_extraction_batch")
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"Unknown tools: {invalid}",
        }

    tasks_to_submit: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for task in tasks:
        tool_name = task["tool"]
        args = task.get("args", {})
        force = args.get("force", False)
        if not force:
            evidence_path = (
                args.get("image_path")
                or args.get("memory_path")
                or args.get("evtx_path")
                or args.get("evidence_path")
                or args.get("events_path")
                or args.get("evtx_dir")
            )
            existing = tool_already_indexed(tool_name, evidence_path=evidence_path)
            if existing:
                logger.info(
                    "Skipping %s in batch: sources already indexed %s",
                    tool_name,
                    existing,
                )
                skipped.append(
                    {
                        "tool": tool_name,
                        "reason": "Sources already indexed from prior extraction",
                        "existing_sources": existing,
                    }
                )
                continue
        tasks_to_submit.append(task)

    if not tasks_to_submit:
        elapsed = (time.monotonic() - t0) * 1000
        try:
            ctx = get_ctx()
            ctx.audit.log_tool_call(
                tool_call_id=tc_id,
                tool_name="start_extraction_batch",
                params={"tasks": [t["tool"] for t in tasks]},
                output_hash=hash_output({"status": "all_skipped"}),
                duration_ms=elapsed,
            )
        except RuntimeError:
            logger.warning("Audit skipped: no active case context for start_extraction_batch")
        return {
            "tool_call_id": tc_id,
            "status": "all_skipped",
            "message": "All tools already have indexed sources; nothing to run.",
            "tasks_skipped": skipped,
        }

    batch = store.submit_batch(tasks_to_submit)

    elapsed = (time.monotonic() - t0) * 1000
    try:
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="start_extraction_batch",
            params={"tasks": [t["tool"] for t in tasks]},
            output_hash=hash_output({"batch_id": batch.batch_id}),
            duration_ms=elapsed,
        )
    except RuntimeError:
        logger.warning("Audit skipped: no active case context for start_extraction_batch")

    result: dict[str, Any] = {
        "tool_call_id": tc_id,
        "status": "submitted",
        "batch_id": batch.batch_id,
        "total_tasks": len(tasks),
        "tasks_submitted": [
            {"tool": t["tool"], "args_summary": list(t.get("args", {}).keys())}
            for t in tasks_to_submit
        ],
        "hint": (
            "Extractions are running in the background. "
            "Continue with fast analysis (search, correlate, submit_finding, "
            "composite tools) and poll with check_extraction_status(batch_id)."
        ),
    }
    if skipped:
        result["tasks_skipped"] = skipped
    return result


@mcp.tool()
@tool_access(Role.CATALOG | Role.EXTRACT_EXECUTOR)
def check_extraction_status(batch_id: str) -> dict[str, Any]:
    """Poll the progress of a background extraction batch.

    Call periodically after start_extraction_batch while continuing
    fast analysis work. Do NOT proceed to cross-system analysis until
    all batches report all_done.

    Returns counts of completed, running, pending, and failed tasks.
    Completed tasks include tool_call_ids usable as evidence_refs in
    submit_finding.

    Args:
        batch_id: The batch ID returned by ``start_extraction_batch``.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    store = _get_job_store()
    status = store.get_batch_status(batch_id)

    elapsed = (time.monotonic() - t0) * 1000
    try:
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="check_extraction_status",
            params={"batch_id": batch_id},
            output_hash=hash_output(status or {}),
            duration_ms=elapsed,
        )
    except RuntimeError:
        logger.warning("Audit skipped: no active case context for check_extraction_status")

    if status is None:
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"Unknown batch: {batch_id}",
        }

    hint_parts: list[str] = []
    if status["all_done"]:
        hint_parts.append(
            "All tasks finished. Call get_completed_results(batch_id) "
            "to retrieve the extraction summaries."
        )
    else:
        if status["completed"] > 0:
            hint_parts.append(
                f"{status['completed']} task(s) done -- call "
                "get_completed_results(batch_id) to get their results now."
            )
        if status["running"] > 0:
            running_tools = [j["tool"] for j in status.get("running_jobs", [])]
            hint_parts.append(
                f"Still running: {running_tools}. Continue other analysis and check again later."
            )

    status["tool_call_id"] = tc_id
    status["hint"] = " ".join(hint_parts)

    running_count = status.get("running", 0)
    if running_count > 0:
        status["warning"] = (
            f"{running_count} extraction jobs still running. "
            f"Do NOT proceed to cross-system composite analysis (Phase 3) "
            f"until all batches report all_done: true."
        )

    return status


@mcp.tool()
@tool_access(Role.CATALOG | Role.EXTRACT_EXECUTOR)
def get_completed_results(
    batch_id: str,
    tool_names: list[str] | None = None,
) -> dict[str, Any]:
    """Retrieve extraction summaries from completed background jobs.

    Call after check_extraction_status shows completed tasks. Only returns
    results not previously retrieved (safe to call repeatedly as more
    jobs finish).

    Returns per-tool metadata: source_name, windows_indexed, line_count,
    and tool_call_id for use as evidence_refs in submit_finding.

    Args:
        batch_id: The batch ID returned by ``start_extraction_batch``.
        tool_names: Optional filter -- only return results from these tools.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    store = _get_job_store()
    results = store.get_completed_results(batch_id, tool_names=tool_names, only_new=True)

    elapsed = (time.monotonic() - t0) * 1000

    if results is None:
        try:
            ctx = get_ctx()
            ctx.audit.log_tool_call(
                tool_call_id=tc_id,
                tool_name="get_completed_results",
                params={"batch_id": batch_id, "tool_names": tool_names},
                output_hash=hash_output({"error": "unknown_batch"}),
                duration_ms=elapsed,
            )
        except RuntimeError:
            logger.warning("Audit skipped: no active case context for get_completed_results")
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"Unknown batch: {batch_id}",
        }

    sub_call_ids = []
    summaries: list[dict[str, object]] = []
    for r in results:
        res = r.get("result")
        summary: dict[str, object] = {
            "tool": r.get("tool", "unknown"),
            "status": r.get("status", "unknown"),
        }
        if isinstance(res, dict):
            if "tool_call_id" in res:
                sub_call_ids.append(res["tool_call_id"])
                summary["tool_call_id"] = res["tool_call_id"]
            if "source_name" in res:
                summary["source_name"] = res["source_name"]
            if "windows_indexed" in res:
                summary["windows_indexed"] = res["windows_indexed"]
            if "line_count" in res:
                summary["line_count"] = res["line_count"]
            if "error_message" in res:
                summary["error_message"] = res["error_message"]
            if "status" in res:
                summary["result_status"] = res["status"]
        elif isinstance(res, str) and len(res) > 200:
            summary["result_preview"] = res[:200]
        else:
            summary["result"] = res
        summaries.append(summary)

    try:
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="get_completed_results",
            params={"batch_id": batch_id, "tool_names": tool_names},
            output_hash=hash_output({"count": len(results)}),
            duration_ms=elapsed,
            sub_calls=sub_call_ids if sub_call_ids else None,
        )
    except RuntimeError:
        logger.warning("Audit skipped: no active case context for get_completed_results")

    return {
        "tool_call_id": tc_id,
        "status": "success",
        "batch_id": batch_id,
        "results_returned": len(summaries),
        "results": summaries,
        "hint": (
            "Results show metadata only. Use search(query, source=source_name) "
            "or get_raw_output(source_name) to access the actual evidence data. "
            "Use tool_call_id values in submit_finding evidence_refs."
        ),
    }


@mcp.tool()
@tool_access(Role.CATALOG | Role.EXTRACT_EXECUTOR)
def wait_all(
    batch_ids: list[str],
    poll_interval: int = 5,
) -> dict[str, object]:
    """Wait for multiple extraction batches to complete simultaneously.

    Polls all batches and returns when every batch has finished. This
    enables parallel execution of independent tool groups (e.g., memory
    analysis, disk analysis, and carving can all run at the same time).

    Args:
        batch_ids: List of batch IDs returned by start_extraction_batch.
        poll_interval: Seconds between status checks (default 5).

    Returns:
        Combined status of all batches with per-batch results.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    store = _get_job_store()
    interval = max(poll_interval, 1)
    max_wait = 1800

    errors: dict[str, str] = {}
    valid_ids: list[str] = []
    for bid in batch_ids:
        status = store.get_batch_status(bid)
        if status is None:
            errors[bid] = f"Unknown batch: {bid}"
        else:
            valid_ids.append(bid)

    if errors and not valid_ids:
        elapsed = (time.monotonic() - t0) * 1000
        try:
            ctx = get_ctx()
            ctx.audit.log_tool_call(
                tool_call_id=tc_id,
                tool_name="wait_all",
                params={"batch_ids": batch_ids},
                output_hash=hash_output({"error": "all_invalid"}),
                duration_ms=elapsed,
            )
        except RuntimeError:
            logger.warning("Audit skipped: no active case context for wait_all")
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": "All batch IDs are invalid",
            "invalid_batches": errors,
        }

    deadline = t0 + max_wait
    completed_batches: dict[str, dict[str, object]] = {}
    remaining = set(valid_ids)

    while remaining and time.monotonic() < deadline:
        for bid in list(remaining):
            status = store.get_batch_status(bid)
            if status is not None and status.get("all_done", False):
                completed_batches[bid] = status
                remaining.discard(bid)
        if remaining:
            time.sleep(interval)

    for bid in remaining:
        status = store.get_batch_status(bid)
        if status is not None:
            completed_batches[bid] = status

    elapsed = (time.monotonic() - t0) * 1000
    all_done = len(remaining) == 0

    try:
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="wait_all",
            params={"batch_ids": batch_ids},
            output_hash=hash_output({"all_done": all_done, "count": len(batch_ids)}),
            duration_ms=elapsed,
        )
    except RuntimeError:
        logger.warning("Audit skipped: no active case context for wait_all")

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "done" if all_done else "timeout",
        "all_done": all_done,
        "waited_seconds": int(time.monotonic() - t0),
        "batch_results": completed_batches,
    }
    if errors:
        result["invalid_batches"] = errors
    if not all_done:
        still_running = list(remaining)
        result["still_running"] = still_running
        result["message"] = (
            f"{len(still_running)} batch(es) still running after timeout. "
            f"Call wait_all again with the remaining IDs."
        )
    else:
        result["message"] = (
            f"All {len(valid_ids)} batch(es) complete. "
            f"Call get_completed_results for each batch to retrieve results."
        )
    return result


@mcp.tool()
@tool_access(Role.CATALOG | Role.EXTRACT_EXECUTOR)
def wait(
    seconds: int = 300,
    batch_id: str | None = None,
    job_id: str | None = None,
) -> dict[str, object]:
    """Wait for extraction batches or individual jobs to complete.

    If *batch_id* is provided, polls until that batch reports all_done.
    If *job_id* is provided, polls until that specific job completes.
    If neither, sleeps for *seconds* and returns.

    Args:
        seconds: Max seconds to wait (default 300, max 1800 = 30 min).
            Used as timeout when waiting for batch_id or job_id.
        batch_id: Optional batch to wait for. Returns as soon as it
            completes instead of waiting the full duration.
        job_id: Optional individual job to wait for. Returns as soon
            as that job reaches a terminal state.
    """
    max_wait = min(max(seconds, 10), 1800)

    if job_id is not None:
        store = _get_job_store()
        t0 = time.monotonic()
        deadline = t0 + max_wait
        while time.monotonic() < deadline:
            with store._lock:
                job = store._jobs.get(job_id)
                if job is None:
                    return {
                        "status": "error",
                        "error_message": f"Unknown job: {job_id}",
                    }
                if job.status in ("completed", "failed", "deferred"):
                    elapsed = int(time.monotonic() - t0)
                    return {
                        "status": "done",
                        "job_id": job_id,
                        "job_status": job.status,
                        "waited_seconds": elapsed,
                        "result": job.result,
                    }
            time.sleep(5)
        elapsed = int(time.monotonic() - t0)
        return {
            "status": "timeout",
            "job_id": job_id,
            "waited_seconds": elapsed,
            "message": f"Job {job_id} still running after {elapsed}s",
        }

    if batch_id is not None:
        store = _get_job_store()
        status = store.get_batch_status(batch_id)
        if status is None:
            return {
                "status": "error",
                "error_message": f"Unknown batch: {batch_id}",
            }
        if status.get("all_done", False):
            return {
                "status": "done",
                "batch_id": batch_id,
                "waited_seconds": 0,
                "batch_status": status,
                "message": (
                    f"Batch {batch_id} already complete. "
                    f"Call get_completed_results('{batch_id}') to retrieve."
                ),
            }

        t0 = time.monotonic()
        finished = store.wait_for_batch(batch_id, timeout=float(max_wait))
        elapsed = int(time.monotonic() - t0)

        status = store.get_batch_status(batch_id)
        if finished:
            return {
                "status": "done",
                "batch_id": batch_id,
                "waited_seconds": elapsed,
                "batch_status": status,
                "message": (
                    f"Batch {batch_id} complete after {elapsed}s. "
                    f"Call get_completed_results('{batch_id}') to retrieve."
                ),
            }
        return {
            "status": "timeout",
            "batch_id": batch_id,
            "waited_seconds": elapsed,
            "batch_status": status,
            "message": (
                f"Batch {batch_id} still running after {elapsed}s. "
                f"Call wait(batch_id='{batch_id}') again to keep waiting."
            ),
        }

    time.sleep(max_wait)
    return {
        "status": "done",
        "waited_seconds": max_wait,
        "message": f"Waited {max_wait} seconds. Check extraction status now.",
    }
