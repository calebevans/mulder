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
