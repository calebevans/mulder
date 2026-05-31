"""In-process background job store for long-running extraction tools.

Decouples *launching* slow forensic tools from *waiting* for their results.
The agent calls ``start_extraction_batch`` to submit work, then polls with
``check_extraction_status`` while continuing fast analysis.  Results are
written to the case DB by the background threads and retrieved via
``get_completed_results``.

Thread safety:
- ``_lock`` guards the ``_jobs`` and ``_batches`` dicts.
- Each background worker writes to the CaseDB captured at submission time
  (safe via the single-writer ``_WriteQueue`` in ``CaseDB``).
- ``AuditLog._append`` is already thread-safe.
"""

from __future__ import annotations

import contextvars
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import uuid4

from mulder.server.timeouts import should_defer

logger = logging.getLogger(__name__)


@dataclass
class Job:
    """Single background extraction task."""

    job_id: str
    batch_id: str
    tool_name: str
    args: dict[str, Any]
    status: Literal["pending", "running", "completed", "failed", "deferred"] = "pending"
    result: Any = None
    error: str | None = None
    submitted_at: float = field(default_factory=time.monotonic)
    started_at: float | None = None
    completed_at: float | None = None


@dataclass
class Batch:
    """Group of jobs submitted together."""

    batch_id: str
    job_ids: list[str]
    created_at: float = field(default_factory=time.monotonic)
    done_event: threading.Event = field(default_factory=threading.Event)
    retry_started: bool = False


def _extract_error_detail(result: object, fallback: str = "unknown error") -> str:
    """Extract a human-readable error message from a tool result dict.

    Checks ``error_message`` first (used by ``error_response``), then
    ``error`` (used by some tools directly).  Returns *fallback* if
    neither key is present or *result* is not a dict.
    """
    if isinstance(result, dict):
        for key in ("error_message", "error"):
            val = result.get(key)
            if isinstance(val, str):
                return val
    return fallback


class JobStore:
    """Manages background extraction jobs via a bounded thread pool.

    Parameters
    ----------
    max_workers:
        Upper bound on concurrent extraction threads.  Should match or be
        less than the server's ``max_workers`` setting.
    tool_dispatch:
        Map of tool name -> async callable (from ``app._tool_dispatch``).
    """

    def __init__(
        self,
        max_workers: int,
        tool_dispatch: dict[str, Callable[..., Any]],
    ) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="mulder-job"
        )
        self._tool_dispatch = tool_dispatch
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}
        self._batches: dict[str, Batch] = {}
        self._delivered: dict[str, set[str]] = {}

    def submit_batch(self, tasks: list[dict[str, Any]]) -> Batch:
        """Create jobs for *tasks* and submit them to the thread pool.

        Returns immediately with a ``Batch`` containing all job IDs.
        """
        batch_id = f"bg_{uuid4().hex[:8]}"
        job_ids: list[str] = []

        with self._lock:
            for task in tasks:
                job_id = f"job_{uuid4().hex[:8]}"
                job = Job(
                    job_id=job_id,
                    batch_id=batch_id,
                    tool_name=task["tool"],
                    args=task.get("args", {}),
                )
                self._jobs[job_id] = job
                job_ids.append(job_id)

            batch = Batch(batch_id=batch_id, job_ids=job_ids)
            self._batches[batch_id] = batch
            self._delivered[batch_id] = set()

        for job_id in job_ids:
            ctx = contextvars.copy_context()
            self._executor.submit(ctx.run, self._run_job, job_id)

        logger.info(
            "Submitted batch %s with %d jobs: %s",
            batch_id,
            len(tasks),
            [t["tool"] for t in tasks],
        )
        return batch

    def _run_job(self, job_id: str) -> None:
        """Execute a single job in a worker thread.

        Sets ``current_batch_id`` so that the tool's internal audit
        logging (via ``tool_response`` / ``error_response``) records
        the batch correlation automatically.
        """
        from mulder.server.helpers import current_batch_id

        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = "running"
            job.started_at = time.monotonic()

        tool_name = job.tool_name
        fn = self._tool_dispatch.get(tool_name)

        if fn is None:
            with self._lock:
                job.status = "failed"
                job.error = f"Unknown tool: {tool_name}"
                job.completed_at = time.monotonic()
            return

        from mulder.server.app import wait_for_resources

        current_batch_id.set(job.batch_id)
        try:
            wait_for_resources(tool_name)
            result = fn(**job.args)

            is_timeout = isinstance(result, dict) and result.get("error_type") == "timeout"
            is_error = isinstance(result, dict) and (
                result.get("status") == "error"
                or bool(result.get("error"))
                or bool(result.get("error_message"))
            )

            if is_timeout:
                error_detail = _extract_error_detail(result, "timeout")
                other_running = self._count_running_in_batch(job.batch_id, job_id)

                if should_defer(other_running):
                    with self._lock:
                        job.status = "deferred"
                        job.result = result
                        job.error = f"Deferred: {error_detail}"
                        job.completed_at = time.monotonic()
                    logger.warning("Job %s (%s) deferred for retry", job_id, tool_name)
                else:
                    with self._lock:
                        job.status = "failed"
                        job.result = result
                        job.error = error_detail
                        job.completed_at = time.monotonic()
                    logger.warning("Job %s (%s) timed out under low load", job_id, tool_name)
            elif is_error:
                with self._lock:
                    job.status = "failed"
                    job.result = result
                    job.error = _extract_error_detail(result, "unknown error")
                    job.completed_at = time.monotonic()
                logger.warning("Job %s (%s) returned error: %s", job_id, tool_name, job.error)
            else:
                with self._lock:
                    job.status = "completed"
                    job.result = result
                    job.completed_at = time.monotonic()
                logger.info("Job %s (%s) completed", job_id, tool_name)

        except Exception as exc:
            logger.exception("Job %s (%s) failed", job_id, tool_name)
            with self._lock:
                job.status = "failed"
                job.error = f"{tool_name} failed: {exc}"
                job.completed_at = time.monotonic()
        finally:
            current_batch_id.set(None)
            self._check_batch_done(job.batch_id)

    def _count_running_in_batch(self, batch_id: str, exclude_job_id: str) -> int:
        """Count jobs in *batch_id* that are running, excluding *exclude_job_id*."""
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return 0
            count = 0
            for jid in batch.job_ids:
                j = self._jobs.get(jid)
                if j is not None and j.status == "running" and j.job_id != exclude_job_id:
                    count += 1
            return count

    def _check_batch_done(self, batch_id: str) -> None:
        """Signal batch completion or spawn deferred retry if needed.

        When all active jobs finish but deferred jobs remain, spawns a
        daemon thread that retries them sequentially with full resources.
        The ``done_event`` is only set when no deferred jobs remain.
        """
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return
            jobs = [self._jobs[jid] for jid in batch.job_ids]

            active = [j for j in jobs if j.status in ("pending", "running")]
            deferred = [j for j in jobs if j.status == "deferred"]

            if active:
                return

            if deferred:
                if batch.retry_started:
                    return
                batch.retry_started = True
                threading.Thread(
                    target=self._retry_deferred,
                    args=(batch_id, [j.job_id for j in deferred]),
                    daemon=True,
                ).start()
                return

            batch.done_event.set()

    def _retry_deferred(self, batch_id: str, job_ids: list[str]) -> None:
        """Retry deferred jobs sequentially with full system resources.

        Runs each deferred job one at a time after all other batch jobs
        have completed.  On retry, any error (including another timeout)
        marks the job as permanently failed.
        """
        from mulder.server.app import wait_for_resources
        from mulder.server.helpers import current_batch_id

        for job_id in job_ids:
            with self._lock:
                job = self._jobs.get(job_id)
                if job is None:
                    continue
                job.status = "running"
                job.error = None
                job.started_at = time.monotonic()

            tool_name = job.tool_name
            fn = self._tool_dispatch.get(tool_name)
            if fn is None:
                with self._lock:
                    job.status = "failed"
                    job.error = "Unknown tool on retry"
                    job.completed_at = time.monotonic()
                continue

            current_batch_id.set(batch_id)
            try:
                wait_for_resources(tool_name)
                result = fn(**job.args)
                is_error = isinstance(result, dict) and (
                    bool(result.get("error"))
                    or result.get("status") == "error"
                    or bool(result.get("error_message"))
                )
                with self._lock:
                    job.status = "failed" if is_error else "completed"
                    job.result = result
                    job.error = _extract_error_detail(result) if is_error else None
                    job.completed_at = time.monotonic()

                if is_error:
                    logger.warning(
                        "Job %s (%s) failed on retry: %s",
                        job_id,
                        tool_name,
                        job.error,
                    )
                else:
                    logger.info("Job %s (%s) completed on retry", job_id, tool_name)
            except Exception as exc:
                logger.exception("Job %s (%s) failed on retry", job_id, tool_name)
                with self._lock:
                    job.status = "failed"
                    job.error = f"{tool_name} retry failed: {exc}"
                    job.completed_at = time.monotonic()
            finally:
                current_batch_id.set(None)

        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is not None:
                batch.done_event.set()

    def batch_ids(self) -> list[str]:
        """Return a snapshot of all known batch IDs."""
        with self._lock:
            return list(self._batches.keys())

    def wait_for_batch(self, batch_id: str, timeout: float | None = None) -> bool:
        """Block until all jobs in the batch finish. Returns True if done."""
        with self._lock:
            batch = self._batches.get(batch_id)
        if batch is None:
            return False
        return batch.done_event.wait(timeout=timeout)

    def get_batch_status(self, batch_id: str) -> dict[str, Any] | None:
        """Return a lean status summary for *batch_id*.

        Only includes details for running and failed jobs to minimize
        response size.  Completed and pending jobs are represented by
        counts only.
        """
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return None

            counts: dict[str, int] = {
                "completed": 0,
                "failed": 0,
                "running": 0,
                "pending": 0,
                "deferred": 0,
            }
            running_jobs: list[dict[str, Any]] = []
            failed_jobs: list[dict[str, Any]] = []
            deferred_jobs: list[dict[str, Any]] = []

            for jid in batch.job_ids:
                job = self._jobs[jid]
                counts[job.status] = counts.get(job.status, 0) + 1
                if job.status == "running":
                    elapsed = None
                    if job.started_at is not None:
                        elapsed = round((time.monotonic() - job.started_at) * 1000)
                    running_jobs.append({"tool": job.tool_name, "elapsed_ms": elapsed})
                elif job.status == "failed":
                    failed_jobs.append({"tool": job.tool_name, "error": job.error})
                elif job.status == "deferred":
                    deferred_jobs.append({"tool": job.tool_name, "error": job.error})

        still_active = counts["pending"] + counts["running"] + counts["deferred"]
        result: dict[str, Any] = {
            "batch_id": batch_id,
            "total": len(batch.job_ids),
            **counts,
            "all_done": still_active == 0,
        }
        if running_jobs:
            result["running_jobs"] = running_jobs
        if failed_jobs:
            result["failed_jobs"] = failed_jobs
        if deferred_jobs:
            result["deferred_jobs"] = deferred_jobs
        return result

    def get_completed_results(
        self,
        batch_id: str,
        tool_names: list[str] | None = None,
        only_new: bool = True,
    ) -> list[dict[str, Any]] | None:
        """Return full results for completed jobs in *batch_id*.

        Parameters
        ----------
        tool_names:
            If provided, only return results for these tool names.
        only_new:
            If True (default), skip results already returned by a prior call.
        """
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return None

            delivered = self._delivered.setdefault(batch_id, set())
            results: list[dict[str, Any]] = []

            for jid in batch.job_ids:
                job = self._jobs[jid]
                if job.status != "completed":
                    continue
                if only_new and jid in delivered:
                    continue
                if tool_names and job.tool_name not in tool_names:
                    continue

                elapsed = None
                if job.started_at and job.completed_at:
                    elapsed = round((job.completed_at - job.started_at) * 1000)

                results.append(
                    {
                        "job_id": jid,
                        "tool": job.tool_name,
                        "args": job.args,
                        "result": job.result,
                        "elapsed_ms": elapsed,
                    }
                )
                delivered.add(jid)

            return results

    def shutdown(self, wait: bool = False) -> None:
        """Shut down the thread pool."""
        self._executor.shutdown(wait=wait)
