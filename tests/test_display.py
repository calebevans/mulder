"""Tests for mulder.orchestrator.display -- dashboard task list UI."""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from mulder.orchestrator.display import InvestigationDashboard


def _make_dashboard() -> InvestigationDashboard:
    """Create a dashboard with psutil seeding suppressed."""
    with patch("mulder.orchestrator.display.psutil"):
        return InvestigationDashboard()


class TestSetTasksAndRender:
    """Setting tasks produces correct panel output."""

    def test_set_tasks_produces_panel(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive", "run_volatility_batch"])
        panel = dash._build_task_panel()
        assert panel is not None
        rendered = (
            panel.renderable.plain if hasattr(panel.renderable, "plain") else str(panel.renderable)
        )
        assert "extract_archive" in rendered
        assert "run_volatility_batch" in rendered

    def test_no_tasks_returns_none(self) -> None:
        dash = _make_dashboard()
        assert dash._build_task_panel() is None


class TestTaskUpdateStatus:
    """Updating a task changes its icon and style in the rendered panel."""

    def test_done_task_not_overwritten(self) -> None:
        """Once a task is done, subsequent updates should not change it."""
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive"])
        dash.update_task("base-dc", "extract_archive", "done", elapsed=2.0)
        dash.update_task("base-dc", "extract_archive", "running")

        assert dash._tasks[0].status == "done"

    def test_update_wrong_system_is_noop(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive"])
        dash.update_task("base-admin", "extract_archive", "running")

        assert dash._tasks[0].status == "pending"


class TestTaskClear:
    """Clearing removes the panel entirely."""

    def test_clear_removes_tasks(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive", "run_fls"])
        assert dash._tasks_active is True

        dash.clear_tasks()
        assert dash._tasks == []
        assert dash._tasks_active is False
        assert dash._build_task_panel() is None


class TestMultipleSystems:
    """Systems are grouped correctly in the panel output."""

    def test_multiple_systems_grouped(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive", "run_volatility_batch"])
        dash.set_tasks("base-admin", ["extract_archive"])

        assert len(dash._tasks) == 3
        assert dash._tasks[0].system == "base-dc"
        assert dash._tasks[1].system == "base-dc"
        assert dash._tasks[2].system == "base-admin"

        panel = dash._build_task_panel()
        assert panel is not None

    def test_update_correct_system_in_multi(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive"])
        dash.set_tasks("base-admin", ["extract_archive"])

        dash.update_task("base-admin", "extract_archive", "done", elapsed=1.0)

        assert dash._tasks[0].status == "pending"
        assert dash._tasks[1].status == "done"
        assert dash._tasks[1].elapsed_seconds == 1.0


class TestLogPersistence:
    """Log methods emit to the Python logger for file persistence."""

    @pytest.mark.parametrize(
        ("method", "arg", "expected"),
        [
            ("log", "[base-dc] found artifact", "found artifact"),
            ("log_tool", "extract_archive", "extract_archive"),
            ("log_info", "retrying phase", "retrying phase"),
        ],
    )
    def test_log_methods_write_to_logger(self, method: str, arg: str, expected: str) -> None:
        dash = _make_dashboard()
        with patch.object(logging.getLogger("mulder.orchestrator.display"), "info") as mock_info:
            getattr(dash, method)(arg)
            mock_info.assert_called()
            args = mock_info.call_args[0]
            assert expected in args[1]
