"""MCP tools for the async extraction job queue.

These tools replace ``run_parallel`` for slow Tier-2 extraction work.
The agent calls ``start_extraction_batch`` to launch background jobs,
then polls with ``check_extraction_status`` while doing fast analysis,
and retrieves results with ``get_completed_results``.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from mulder.server.app import get_ctx, has_ctx, mcp

if TYPE_CHECKING:
    from mulder.server.jobs import JobStore
from mulder.server.helpers import hash_output, make_tool_call_id


def _get_job_store() -> JobStore:
    """Import lazily to avoid circular import at module level."""
    from mulder.server.app import get_job_store

    return get_job_store()


@mcp.tool()
def start_extraction_batch(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    """Launch slow extraction tools in the background and return immediately.

    Use this instead of ``run_parallel`` for long-running Tier-2 extraction
    tools (Volatility, Plaso, bulk_extractor, fls, EVTX, registry, EZ
    Tools, etc.).  The tools run concurrently in background threads while
    you continue with fast analysis (search, correlate, submit_finding,
    composite tools).

    Poll progress with ``check_extraction_status(batch_id)`` and retrieve
    results with ``get_completed_results(batch_id)``.

    Keep using ``run_parallel`` for fast operations like ``extract_archive``,
    ``run_mmls``, ``run_hayabusa``, composite tools, and searches.

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
        if has_ctx():
            ctx = get_ctx()
            ctx.audit.log_tool_call(
                tool_call_id=tc_id,
                tool_name="start_extraction_batch",
                params={"tasks": [t["tool"] for t in tasks]},
                output_hash=hash_output({"error": "unknown_tools", "tools": invalid}),
                duration_ms=elapsed,
            )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"Unknown tools: {invalid}",
        }

    batch = store.submit_batch(tasks)

    elapsed = (time.monotonic() - t0) * 1000
    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="start_extraction_batch",
            params={"tasks": [t["tool"] for t in tasks]},
            output_hash=hash_output({"batch_id": batch.batch_id}),
            duration_ms=elapsed,
        )

    return {
        "tool_call_id": tc_id,
        "status": "submitted",
        "batch_id": batch.batch_id,
        "total_tasks": len(tasks),
        "tasks_submitted": [
            {"tool": t["tool"], "args_summary": list(t.get("args", {}).keys())} for t in tasks
        ],
        "hint": (
            "Extractions are running in the background. "
            "Continue with fast analysis (search, correlate, submit_finding, "
            "composite tools) and poll with check_extraction_status(batch_id)."
        ),
    }


@mcp.tool()
def check_extraction_status(batch_id: str) -> dict[str, Any]:
    """Check progress of a background extraction batch.

    Returns how many tasks are completed, running, pending, and failed.
    For completed tasks, includes the ``tool_call_id`` so you can
    reference them in findings.  Call this periodically while doing
    other analysis work.

    Args:
        batch_id: The batch ID returned by ``start_extraction_batch``.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    store = _get_job_store()
    status = store.get_batch_status(batch_id)

    elapsed = (time.monotonic() - t0) * 1000
    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="check_extraction_status",
            params={"batch_id": batch_id},
            output_hash=hash_output(status or {}),
            duration_ms=elapsed,
        )

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
def get_completed_results(
    batch_id: str,
    tool_names: list[str] | None = None,
) -> dict[str, Any]:
    """Retrieve full results from completed background extraction jobs.

    Returns the extraction summaries (windows indexed, source names, etc.)
    for jobs that have finished.  By default only returns results you
    haven't retrieved before (so you can call this repeatedly as more
    jobs complete without seeing duplicates).

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
        if has_ctx():
            ctx = get_ctx()
            ctx.audit.log_tool_call(
                tool_call_id=tc_id,
                tool_name="get_completed_results",
                params={"batch_id": batch_id, "tool_names": tool_names},
                output_hash=hash_output({"error": "unknown_batch"}),
                duration_ms=elapsed,
            )
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

    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="get_completed_results",
            params={"batch_id": batch_id, "tool_names": tool_names},
            output_hash=hash_output({"count": len(results)}),
            duration_ms=elapsed,
            sub_calls=sub_call_ids if sub_call_ids else None,
        )

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
def wait(
    seconds: int = 300,
    batch_id: str | None = None,
) -> dict[str, object]:
    """Wait for extraction batches to complete without burning context.

    If *batch_id* is provided, polls every 30 seconds until that batch
    reports all_done, then returns the final status. Much better than
    calling check_extraction_status in a loop.

    If no batch_id, sleeps for *seconds* and returns.

    Args:
        seconds: Max seconds to wait (default 300, max 1800 = 30 min).
            Ignored when batch_id is provided and batch completes sooner.
        batch_id: Optional batch to wait for. Returns as soon as it
            completes instead of waiting the full duration.
    """
    max_wait = min(max(seconds, 10), 1800)

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
