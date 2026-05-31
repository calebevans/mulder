"""Tests for mulder.server.jobs -- JobStore batch lifecycle."""

from __future__ import annotations

import time
from unittest.mock import patch

from mulder.server.jobs import JobStore


def _noop_dispatch(**kwargs: object) -> dict[str, str]:
    return {"status": "ok"}


def _slow_dispatch(**kwargs: object) -> dict[str, str]:
    time.sleep(0.05)
    return {"status": "ok"}


def _timeout_tool(**kwargs: object) -> dict[str, str]:
    """Simulate a tool that returns a timeout error."""
    return {"status": "error", "error_type": "timeout", "error_message": "timed out"}


class _OnceTimeoutTool:
    """Returns timeout on first call, success on subsequent calls."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, **kwargs: object) -> dict[str, str]:
        self.calls += 1
        if self.calls == 1:
            return {
                "status": "error",
                "error_type": "timeout",
                "error_message": "timed out",
            }
        return {"status": "ok"}


class TestSubmitBatch:
    def test_returns_batch_with_jobs(self) -> None:
        store = JobStore(max_workers=2, tool_dispatch={"fast_tool": _noop_dispatch})
        batch = store.submit_batch([{"tool": "fast_tool", "args": {}}])
        assert len(batch.job_ids) == 1
        assert batch.batch_id.startswith("bg_")
        store.shutdown(wait=True)

    def test_multiple_jobs(self) -> None:
        store = JobStore(max_workers=2, tool_dispatch={"fast_tool": _noop_dispatch})
        batch = store.submit_batch(
            [
                {"tool": "fast_tool", "args": {}},
                {"tool": "fast_tool", "args": {}},
                {"tool": "fast_tool", "args": {}},
            ]
        )
        assert len(batch.job_ids) == 3
        store.shutdown(wait=True)


class TestBatchStatus:
    @patch("mulder.server.app.wait_for_resources", return_value=None)
    def test_completed_status(self, _mock_wait: object) -> None:
        store = JobStore(max_workers=2, tool_dispatch={"fast_tool": _noop_dispatch})
        batch = store.submit_batch([{"tool": "fast_tool", "args": {}}])
        time.sleep(0.2)
        status = store.get_batch_status(batch.batch_id)
        assert status is not None
        assert status["all_done"]
        assert status["completed"] == 1
        store.shutdown(wait=True)

    def test_nonexistent_batch_returns_none(self) -> None:
        store = JobStore(max_workers=1, tool_dispatch={})
        assert store.get_batch_status("bg_nonexistent") is None
        store.shutdown()


class TestUnknownTool:
    def test_unknown_tool_fails(self) -> None:
        store = JobStore(max_workers=1, tool_dispatch={})
        batch = store.submit_batch([{"tool": "no_such_tool", "args": {}}])
        time.sleep(0.2)
        status = store.get_batch_status(batch.batch_id)
        assert status is not None
        assert status["failed"] == 1
        store.shutdown(wait=True)


class TestCompletedResults:
    @patch("mulder.server.app.wait_for_resources", return_value=None)
    def test_only_new_skips_delivered(self, _mock_wait: object) -> None:
        store = JobStore(max_workers=2, tool_dispatch={"tool_a": _noop_dispatch})
        batch = store.submit_batch(
            [
                {"tool": "tool_a", "args": {}},
                {"tool": "tool_a", "args": {}},
            ]
        )
        time.sleep(0.3)

        first = store.get_completed_results(batch.batch_id, only_new=True)
        assert first is not None
        assert len(first) == 2

        second = store.get_completed_results(batch.batch_id, only_new=True)
        assert second is not None
        assert len(second) == 0
        store.shutdown(wait=True)

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    def test_tool_names_filter(self, _mock_wait: object) -> None:
        store = JobStore(
            max_workers=2,
            tool_dispatch={"tool_a": _noop_dispatch, "tool_b": _noop_dispatch},
        )
        batch = store.submit_batch(
            [
                {"tool": "tool_a", "args": {}},
                {"tool": "tool_b", "args": {}},
            ]
        )
        time.sleep(0.3)
        results = store.get_completed_results(batch.batch_id, tool_names=["tool_a"])
        assert results is not None
        assert all(r["tool"] == "tool_a" for r in results)
        store.shutdown(wait=True)

    def test_nonexistent_batch_returns_none(self) -> None:
        store = JobStore(max_workers=1, tool_dispatch={})
        assert store.get_completed_results("bg_none") is None
        store.shutdown()


class TestDeferredRetry:
    """Tests for the deferred retry system (SPEC-009b)."""

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    @patch("mulder.server.jobs.should_defer", return_value=True)
    @patch.object(JobStore, "_retry_deferred")
    def test_timeout_deferred_under_load(
        self,
        _mock_retry: object,
        _mock_defer: object,
        _mock_wait: object,
    ) -> None:
        """Timeout + high load marks job as deferred, not failed."""
        store = JobStore(max_workers=2, tool_dispatch={"slow_tool": _timeout_tool})
        batch = store.submit_batch([{"tool": "slow_tool", "args": {}}])
        time.sleep(0.3)

        with store._lock:
            job = store._jobs[batch.job_ids[0]]
            assert job.status == "deferred"
            assert job.error is not None
            assert "Deferred" in job.error
        store.shutdown(wait=True)

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    @patch("mulder.server.jobs.should_defer", return_value=False)
    def test_timeout_failed_low_load(
        self,
        _mock_defer: object,
        _mock_wait: object,
    ) -> None:
        """Timeout + low load (no other running jobs) marks job as failed."""
        store = JobStore(max_workers=2, tool_dispatch={"slow_tool": _timeout_tool})
        batch = store.submit_batch([{"tool": "slow_tool", "args": {}}])
        time.sleep(0.3)

        with store._lock:
            job = store._jobs[batch.job_ids[0]]
            assert job.status == "failed"
            assert job.error is not None
            assert "timed out" in job.error
        store.shutdown(wait=True)

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    @patch("mulder.server.jobs.should_defer", return_value=True)
    def test_deferred_retry_after_batch(
        self,
        _mock_defer: object,
        _mock_wait: object,
    ) -> None:
        """Deferred jobs are retried once all active batch jobs finish."""
        tracker = _OnceTimeoutTool()
        store = JobStore(
            max_workers=4,
            tool_dispatch={"retry_tool": tracker, "fast_tool": _noop_dispatch},
        )
        batch = store.submit_batch(
            [
                {"tool": "retry_tool", "args": {}},
                {"tool": "fast_tool", "args": {}},
                {"tool": "fast_tool", "args": {}},
            ]
        )
        done = batch.done_event.wait(timeout=5.0)
        assert done

        assert tracker.calls == 2

        status = store.get_batch_status(batch.batch_id)
        assert status is not None
        assert status["all_done"]
        store.shutdown(wait=True)

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    @patch("mulder.server.jobs.should_defer", return_value=True)
    def test_deferred_retry_succeeds(
        self,
        _mock_defer: object,
        _mock_wait: object,
    ) -> None:
        """A deferred job that succeeds on retry is marked completed."""
        tracker = _OnceTimeoutTool()
        store = JobStore(max_workers=4, tool_dispatch={"retry_tool": tracker})
        batch = store.submit_batch([{"tool": "retry_tool", "args": {}}])
        done = batch.done_event.wait(timeout=5.0)
        assert done

        with store._lock:
            job = store._jobs[batch.job_ids[0]]
            assert job.status == "completed"
        assert tracker.calls == 2
        store.shutdown(wait=True)

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    @patch("mulder.server.jobs.should_defer", return_value=True)
    def test_deferred_retry_still_fails(
        self,
        _mock_defer: object,
        _mock_wait: object,
    ) -> None:
        """A deferred job that still fails on retry is marked failed."""
        store = JobStore(
            max_workers=4,
            tool_dispatch={"always_timeout": _timeout_tool, "fast": _noop_dispatch},
        )
        batch = store.submit_batch(
            [
                {"tool": "always_timeout", "args": {}},
                {"tool": "fast", "args": {}},
            ]
        )
        done = batch.done_event.wait(timeout=5.0)
        assert done

        with store._lock:
            job = store._jobs[batch.job_ids[0]]
            assert job.status == "failed"
        store.shutdown(wait=True)

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    @patch("mulder.server.jobs.should_defer", return_value=True)
    @patch.object(JobStore, "_retry_deferred")
    def test_batch_done_waits_for_deferred(
        self,
        _mock_retry: object,
        _mock_defer: object,
        _mock_wait: object,
    ) -> None:
        """done_event is NOT set while deferred jobs are pending retry."""
        store = JobStore(max_workers=2, tool_dispatch={"timeout_tool": _timeout_tool})
        batch = store.submit_batch([{"tool": "timeout_tool", "args": {}}])
        time.sleep(0.3)

        assert not batch.done_event.is_set()
        store.shutdown(wait=True)
