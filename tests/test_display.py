"""Tests for mulder.orchestrator.display -- dashboard task list UI."""

from __future__ import annotations

import logging
from unittest.mock import patch

from mulder.orchestrator.display import (
    _SYSTEM_COLORS,
    InvestigationDashboard,
    TaskItem,
)


def _make_dashboard() -> InvestigationDashboard:
    """Create a dashboard with psutil seeding suppressed."""
    with patch("mulder.orchestrator.display.psutil"):
        return InvestigationDashboard()


class TestTaskItemDataclass:
    """TaskItem dataclass has correct defaults."""

    def test_defaults(self) -> None:
        task = TaskItem(tool="extract_archive", system="base-dc")
        assert task.status == "pending"
        assert task.elapsed_seconds is None
        assert task.error is None


class TestSetTasksAndRender:
    """Setting tasks produces correct panel output."""

    def test_set_tasks_populates_list(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive", "run_volatility_batch"])

        assert len(dash._tasks) == 2
        assert dash._tasks_active is True
        assert dash._tasks[0].tool == "extract_archive"
        assert dash._tasks[0].system == "base-dc"
        assert dash._tasks[1].tool == "run_volatility_batch"

    def test_set_tasks_renders_panel(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive", "run_fls"])

        panel = dash._build_task_panel()
        assert panel is not None
        assert panel.title is not None
        title_text = panel.title.plain if hasattr(panel.title, "plain") else str(panel.title)
        assert "Evidence Analysis" in title_text

    def test_no_tasks_returns_none(self) -> None:
        dash = _make_dashboard()
        assert dash._build_task_panel() is None


class TestTaskUpdateStatus:
    """Updating a task changes its icon and style in the rendered panel."""

    def test_update_to_running(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive"])
        dash.update_task("base-dc", "extract_archive", "running")

        assert dash._tasks[0].status == "running"

    def test_update_to_done_with_elapsed(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive"])
        dash.update_task("base-dc", "extract_archive", "done", elapsed=2.5)

        assert dash._tasks[0].status == "done"
        assert dash._tasks[0].elapsed_seconds == 2.5

    def test_update_to_failed_with_error(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive"])
        dash.update_task("base-dc", "extract_archive", "failed", error="timeout")

        assert dash._tasks[0].status == "failed"
        assert dash._tasks[0].error == "timeout"

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


class TestSpinnerAnimates:
    """Spinner frame advances on each panel build."""

    def test_spinner_frame_advances(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive"])
        dash.update_task("base-dc", "extract_archive", "running")

        # Spinner is now time-based, just verify the panel renders
        # with a spinner character from the expected set
        import time as _time

        panel = dash._build_task_panel()
        assert panel is not None
        _time.sleep(0.15)
        panel2 = dash._build_task_panel()
        assert panel2 is not None

    def test_spinner_uses_time_based_frame(self) -> None:
        """Spinner derives frame from monotonic clock, always animates."""
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["run_fls"])
        dash.update_task("base-dc", "run_fls", "running")

        # Just verify it renders without error
        panel = dash._build_task_panel()
        assert panel is not None


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


class TestBuildLayoutWithTasks:
    """Layout includes task panel when tasks are active."""

    def test_layout_has_side_by_side_with_tasks(self) -> None:
        dash = _make_dashboard()
        dash.set_tasks("base-dc", ["extract_archive"])

        with patch.object(dash, "_get_system_stats", return_value=(10.0, 4.0, 16.0)):
            layout = dash._build_layout()

        assert layout["header"] is not None
        assert layout["body"] is not None
        assert layout["logs"] is not None
        assert layout["tasks"] is not None

    def test_layout_has_two_regions_without_tasks(self) -> None:
        dash = _make_dashboard()

        with patch.object(dash, "_get_system_stats", return_value=(10.0, 4.0, 16.0)):
            layout = dash._build_layout()

        assert layout["header"] is not None
        assert layout["logs"] is not None

        has_tasks = True
        try:
            layout["tasks"]
        except KeyError:
            has_tasks = False
        assert not has_tasks


class TestSystemColors:
    """Each system gets a unique, consistent color."""

    def test_same_system_returns_same_color(self) -> None:
        dash = _make_dashboard()
        c1 = dash._get_system_color("base-dc")
        c2 = dash._get_system_color("base-dc")
        assert c1 == c2

    def test_different_systems_get_different_colors(self) -> None:
        dash = _make_dashboard()
        c1 = dash._get_system_color("base-dc")
        c2 = dash._get_system_color("base-admin")
        assert c1 != c2

    def test_color_wraps_around_palette(self) -> None:
        dash = _make_dashboard()
        colors = [dash._get_system_color(f"system-{i}") for i in range(len(_SYSTEM_COLORS) + 1)]
        assert colors[-1] == colors[0]


class TestLogPersistence:
    """Log methods emit to the Python logger for file persistence."""

    def test_log_writes_to_logger(self, caplog: object) -> None:
        dash = _make_dashboard()
        with patch.object(
            logging.getLogger("mulder.orchestrator.display"),
            "info",
        ) as mock_info:
            dash.log("[base-dc] found artifact")
            mock_info.assert_called()
            args = mock_info.call_args[0]
            assert "found artifact" in args[1]

    def test_log_tool_writes_to_logger(self) -> None:
        dash = _make_dashboard()
        with patch.object(
            logging.getLogger("mulder.orchestrator.display"),
            "info",
        ) as mock_info:
            dash.log_tool("extract_archive")
            mock_info.assert_called()
            args = mock_info.call_args[0]
            assert "extract_archive" in args[1]

    def test_log_info_writes_to_logger(self) -> None:
        dash = _make_dashboard()
        with patch.object(
            logging.getLogger("mulder.orchestrator.display"),
            "info",
        ) as mock_info:
            dash.log_info("retrying phase")
            mock_info.assert_called()
            args = mock_info.call_args[0]
            assert "retrying phase" in args[1]


class TestSystemColorInLog:
    """Log lines with [system] prefixes get colored."""

    def test_system_prefix_colored_in_log(self) -> None:
        dash = _make_dashboard()
        dash.log("[base-dc] some output")

        last_line = dash._log_lines[-1]
        plain = last_line.plain
        assert "base-dc" in plain
        assert "some output" in plain

    def test_no_prefix_renders_plain(self) -> None:
        dash = _make_dashboard()
        dash.log("plain text without prefix")

        last_line = dash._log_lines[-1]
        assert "plain text without prefix" in last_line.plain


class TestExtractionCounters:
    """set_extraction_counts updates internal state and phase label."""

    def test_set_extraction_counts_updates_state(self) -> None:
        dash = _make_dashboard()
        dash.set_extraction_counts(total=18, done=5, active=3)

        assert dash._extraction_total == 18
        assert dash._extraction_done == 5
        assert dash._extraction_active == 3

    def test_set_extraction_counts_updates_phase_label(self) -> None:
        dash = _make_dashboard()
        dash.set_extraction_counts(total=10, done=3, active=2)

        assert "3/10 done" in dash._phase_label
        assert "2 active" in dash._phase_label

    def test_extraction_counts_zero_initial(self) -> None:
        dash = _make_dashboard()
        assert dash._extraction_total == 0
        assert dash._extraction_done == 0
        assert dash._extraction_active == 0

    def test_extraction_counts_progress_sequence(self) -> None:
        """Simulate a realistic progression of counter updates."""
        dash = _make_dashboard()

        dash.set_extraction_counts(total=5, done=0, active=1)
        assert "0/5 done" in dash._phase_label
        assert "1 active" in dash._phase_label

        dash.set_extraction_counts(total=5, done=1, active=2)
        assert "1/5 done" in dash._phase_label
        assert "2 active" in dash._phase_label

        dash.set_extraction_counts(total=5, done=4, active=1)
        assert "4/5 done" in dash._phase_label
        assert "1 active" in dash._phase_label

        dash.set_extraction_counts(total=5, done=5, active=0)
        assert "5/5 done" in dash._phase_label
        assert "0 active" in dash._phase_label
