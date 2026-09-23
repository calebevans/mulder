"""Tests for mulder.server.jobs -- JobStore batch lifecycle."""

from __future__ import annotations

import time
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from mulder.server.jobs import (
    JobStore,
    _extract_error_detail,
    fill_case_id,
    validate_tool_args,
)
from mulder.server.tool_access import EXECUTORS


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
        assert batch.done_event.wait(timeout=5.0)
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
        # Unknown tool path does not set done_event; poll status instead
        deadline = time.monotonic() + 5.0
        status = None
        while time.monotonic() < deadline:
            status = store.get_batch_status(batch.batch_id)
            if status and status["all_done"]:
                break
            time.sleep(0.01)
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
        assert batch.done_event.wait(timeout=5.0)

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
        assert batch.done_event.wait(timeout=5.0)
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
        # Deferred jobs do not set done_event; poll job status instead
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with store._lock:
                job = store._jobs.get(batch.job_ids[0])
                if job and job.status == "deferred":
                    break
            time.sleep(0.01)

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
        assert batch.done_event.wait(timeout=5.0)

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
        fired = batch.done_event.wait(timeout=0.5)

        assert not fired
        store.shutdown(wait=True)


class TestExtractErrorDetail:
    """Tests for _extract_error_detail helper."""

    def test_extracts_error_message_key(self) -> None:
        """Prefers 'error_message' key from dict."""
        result = _extract_error_detail({"error_message": "timed out", "error": "generic"})
        assert result == "timed out"

    def test_extracts_error_key(self) -> None:
        """Falls back to 'error' when 'error_message' absent."""
        result = _extract_error_detail({"error": "connection refused"})
        assert result == "connection refused"

    def test_non_dict_returns_fallback(self) -> None:
        """Non-dict input returns the fallback string."""
        result = _extract_error_detail("not a dict", fallback="oops")
        assert result == "oops"

    def test_none_values_return_fallback(self) -> None:
        """Dict with None error values returns fallback."""
        result = _extract_error_detail({"error_message": None, "error": None}, fallback="default")
        assert result == "default"


def _raising_dispatch(**kwargs: object) -> dict[str, str]:
    """Tool that always raises an exception."""
    raise RuntimeError("simulated tool explosion")


class TestRunJobException:
    """Tests for JobStore._run_job exception handling."""

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    def test_exception_marks_job_failed(self, _mock_wait: object) -> None:
        """Unhandled exception in tool sets status='failed' with message."""
        store = JobStore(max_workers=1, tool_dispatch={"boom": _raising_dispatch})
        batch = store.submit_batch([{"tool": "boom", "args": {}}])
        assert batch.done_event.wait(timeout=5.0)

        status = store.get_batch_status(batch.batch_id)
        assert status is not None
        assert status["failed"] == 1
        store.shutdown(wait=True)


def _typed_tool(
    target_path: str, rules: str | None = None, *, ruleset: str = "builtin"
) -> dict[str, str]:
    return {"status": "ok", "target_path": target_path}


class TestValidateToolArgs:
    def test_valid_args_pass(self) -> None:
        assert validate_tool_args(_typed_tool, {"target_path": "/x"}) is None
        assert validate_tool_args(_typed_tool, {"target_path": "/x", "ruleset": "custom"}) is None

    def test_unknown_param_names_accepted(self) -> None:
        msg = validate_tool_args(_typed_tool, {"image_path": "/x", "target_path": "/x"})
        assert msg == "unexpected parameter(s) 'image_path'; accepted: target_path, rules, ruleset"

    def test_missing_required_reported(self) -> None:
        msg = validate_tool_args(_typed_tool, {"rules": "r"})
        assert (
            msg
            == "missing required parameter(s) 'target_path'; accepted: target_path, rules, ruleset"
        )

    def test_var_keyword_accepts_anything(self) -> None:
        assert validate_tool_args(_noop_dispatch, {"anything": 1}) is None


class TestBatchRejectsBadArgs:
    """start_extraction_batch drops tasks with bad args and still runs the rest."""

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    def test_rest_of_batch_still_runs(self, _mock_wait: object) -> None:
        from mulder.server import app
        from mulder.server.tools import jobs as job_tools

        start_extraction_batch = app._tool_dispatch_sync[job_tools.start_extraction_batch.__name__]

        dispatch = {"typed_tool": _typed_tool}
        store = JobStore(max_workers=2, tool_dispatch=dispatch)
        with (
            patch("mulder.server.app._tool_dispatch_sync", dispatch),
            patch.dict("mulder.server.tool_access._registry", dict.fromkeys(dispatch, EXECUTORS)),
            patch("mulder.server.app.get_job_store", return_value=store),
            patch("mulder.server.tools.jobs.tool_already_indexed", return_value=None),
        ):
            result = start_extraction_batch(
                [
                    {"tool": "typed_tool", "args": {"image_path": "/bad"}},
                    {"tool": "typed_tool", "args": {"target_path": "/good"}},
                ]
            )
        assert result["status"] == "submitted"
        assert [t["tool"] for t in result["tasks_submitted"]] == ["typed_tool"]
        assert result["tasks_rejected"][0]["args"] == {"image_path": "/bad"}
        assert "accepted: target_path" in result["tasks_rejected"][0]["error"]
        assert "tasks_rejected" in result["hint"]
        assert store.wait_for_batch(result["batch_id"], timeout=5.0)
        status = store.get_batch_status(result["batch_id"])
        assert status is not None and status["completed"] == 1 and status["failed"] == 0
        store.shutdown(wait=True)

    def test_all_rejected_is_error(self) -> None:
        from mulder.server import app
        from mulder.server.tools import jobs as job_tools

        start_extraction_batch = app._tool_dispatch_sync[job_tools.start_extraction_batch.__name__]

        dispatch = {"typed_tool": _typed_tool}
        store = JobStore(max_workers=1, tool_dispatch=dispatch)
        with (
            patch("mulder.server.app._tool_dispatch_sync", dispatch),
            patch.dict("mulder.server.tool_access._registry", dict.fromkeys(dispatch, EXECUTORS)),
            patch("mulder.server.app.get_job_store", return_value=store),
        ):
            result = start_extraction_batch([{"tool": "typed_tool", "args": {}}])
        assert result["status"] == "error"
        assert (
            "missing required parameter(s) 'target_path'" in result["tasks_rejected"][0]["error"]
        )
        assert store.batch_ids() == []
        store.shutdown()


class TestRunParallelRejectsBadArgs:
    def test_bad_task_errors_without_calling_tool(self) -> None:
        import anyio

        from mulder.server import app

        calls: list[dict[str, object]] = []

        async def typed_tool(target_path: str) -> dict[str, str]:
            calls.append({"target_path": target_path})
            return {"status": "ok"}

        with (
            patch.dict(app._tool_dispatch, {"typed_tool": typed_tool}),
            patch("mulder.server.app.has_ctx", return_value=False),
        ):
            result = anyio.run(
                app.run_parallel,
                [
                    {"tool": "typed_tool", "args": {"image_path": "/bad"}},
                    {"tool": "typed_tool", "args": {"target_path": "/good"}},
                ],
            )
        results = [r["result"] for r in result["parallel_results"]]
        assert "unexpected parameter(s) 'image_path'" in results[0]["error"]
        assert results[1]["status"] == "ok"
        assert calls == [{"target_path": "/good"}]


_case_calls: list[dict[str, str]] = []


def _case_tool(case_id: str, image_path: str) -> dict[str, str]:
    _case_calls.append({"case_id": case_id, "image_path": image_path})
    return {"status": "ok"}


def _open_case(case_id: str) -> SimpleNamespace:
    return SimpleNamespace(case_id=case_id, audit=MagicMock())


class TestFillCaseId:
    def test_fills_when_tool_wants_it_and_task_omits_it(self) -> None:
        assert fill_case_id(_case_tool, {"image_path": "/x"}, "c1") == {
            "image_path": "/x",
            "case_id": "c1",
        }

    def test_explicit_case_id_untouched(self) -> None:
        args = {"image_path": "/x", "case_id": "explicit"}
        assert fill_case_id(_case_tool, args, "c1") is args

    def test_tool_without_case_id_param_unaffected(self) -> None:
        args = {"target_path": "/x"}
        assert fill_case_id(_typed_tool, args, "c1") is args

    def test_no_open_case_leaves_args_alone(self) -> None:
        args = {"image_path": "/x"}
        assert fill_case_id(_case_tool, args, None) is args


class TestBatchFillsCaseId:
    """start_extraction_batch fills case_id from the open case instead of rejecting."""

    @patch("mulder.server.app.wait_for_resources", return_value=None)
    def test_omitted_case_id_filled_and_task_runs(self, _mock_wait: object) -> None:
        from mulder.server import app
        from mulder.server.tools import jobs as job_tools

        start_extraction_batch = app._tool_dispatch_sync[job_tools.start_extraction_batch.__name__]
        dispatch: dict[str, Callable[..., Any]] = {
            "case_tool": _case_tool,
            "typed_tool": _typed_tool,
        }
        store = JobStore(max_workers=2, tool_dispatch=dispatch)
        _case_calls.clear()
        with (
            patch("mulder.server.app._tool_dispatch_sync", dispatch),
            patch.dict("mulder.server.tool_access._registry", dict.fromkeys(dispatch, EXECUTORS)),
            patch("mulder.server.app.get_job_store", return_value=store),
            patch("mulder.server.app._ctx", _open_case("case-1")),
            patch("mulder.server.tools.jobs.tool_already_indexed", return_value=None),
        ):
            result = start_extraction_batch(
                [
                    {"tool": "case_tool", "args": {"image_path": "/a"}},
                    {"tool": "case_tool", "args": {"image_path": "/b", "case_id": "explicit"}},
                    {"tool": "typed_tool", "args": {"target_path": "/c"}},
                ]
            )
            assert store.wait_for_batch(result["batch_id"], timeout=5.0)
        assert result["status"] == "submitted"
        assert "tasks_rejected" not in result
        assert [t["args_summary"] for t in result["tasks_submitted"]] == [
            ["image_path", "case_id"],
            ["image_path", "case_id"],
            ["target_path"],
        ]
        status = store.get_batch_status(result["batch_id"])
        assert status is not None and status["completed"] == 3 and status["failed"] == 0
        assert sorted(_case_calls, key=str) == [
            {"case_id": "case-1", "image_path": "/a"},
            {"case_id": "explicit", "image_path": "/b"},
        ]
        store.shutdown(wait=True)

    def test_no_open_case_still_rejected(self) -> None:
        from mulder.server import app
        from mulder.server.tools import jobs as job_tools

        start_extraction_batch = app._tool_dispatch_sync[job_tools.start_extraction_batch.__name__]
        dispatch = {"case_tool": _case_tool}
        store = JobStore(max_workers=1, tool_dispatch=dispatch)
        with (
            patch("mulder.server.app._tool_dispatch_sync", dispatch),
            patch.dict("mulder.server.tool_access._registry", dict.fromkeys(dispatch, EXECUTORS)),
            patch("mulder.server.app.get_job_store", return_value=store),
            patch("mulder.server.app._ctx", None),
        ):
            result = start_extraction_batch([{"tool": "case_tool", "args": {"image_path": "/a"}}])
        assert result["status"] == "error"
        assert "missing required parameter(s) 'case_id'" in result["tasks_rejected"][0]["error"]
        assert store.batch_ids() == []
        store.shutdown()


class TestRunParallelFillsCaseId:
    @staticmethod
    def _run(
        tasks: list[dict[str, Any]], ctx: object
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        import anyio

        from mulder.server import app

        calls: list[dict[str, str]] = []

        async def case_tool(case_id: str, image_path: str) -> dict[str, str]:
            calls.append({"case_id": case_id, "image_path": image_path})
            return {"status": "ok"}

        async def typed_tool(target_path: str) -> dict[str, str]:
            calls.append({"target_path": target_path})
            return {"status": "ok"}

        with (
            patch.dict(app._tool_dispatch, {"case_tool": case_tool, "typed_tool": typed_tool}),
            patch("mulder.server.app._ctx", ctx),
        ):
            result = anyio.run(app.run_parallel, tasks)
        return [r["result"] for r in result["parallel_results"]], calls

    def test_omitted_case_id_filled_from_open_case(self) -> None:
        results, calls = self._run(
            [
                {"tool": "case_tool", "args": {"image_path": "/a"}},
                {"tool": "case_tool", "args": {"image_path": "/b", "case_id": "explicit"}},
                {"tool": "typed_tool", "args": {"target_path": "/c"}},
            ],
            _open_case("case-1"),
        )
        assert [r["status"] for r in results] == ["ok", "ok", "ok"]
        assert sorted(calls, key=str) == [
            {"case_id": "case-1", "image_path": "/a"},
            {"case_id": "explicit", "image_path": "/b"},
            {"target_path": "/c"},
        ]

    def test_no_open_case_still_rejected(self) -> None:
        results, calls = self._run([{"tool": "case_tool", "args": {"image_path": "/a"}}], None)
        assert "missing required parameter(s) 'case_id'" in results[0]["error"]
        assert calls == []
