"""Tests for mulder.orchestrator.display -- control characters in untrusted text."""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest
from rich.console import Console

from mulder.orchestrator.display import InvestigationDashboard, _neutralize_controls

_OSC52 = "\x1b]52;c;SGVsbG8=\x07"
_CLEAR = "\x1b[2J"
_CSI_C1 = "\x9b2J"
_MARKUP = "[link=https://evil.example]click[/link]"


def _make_dashboard() -> InvestigationDashboard:
    """Create a dashboard with psutil seeding suppressed."""
    with patch("mulder.orchestrator.display.psutil"):
        return InvestigationDashboard()


def _render(renderable: object) -> str:
    """Render to a forced terminal and return the raw bytes written."""
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, color_system="truecolor", width=200)
    console.print(renderable)
    return buf.getvalue()


def _assert_neutralized(output: str) -> None:
    assert "\x1b]" not in output
    assert "\x1b[2J" not in output
    assert "\x9b" not in output
    assert "\x07" not in output
    assert "\\x1b]52;c;SGVsbG8=\\x07" in output
    assert "\\x1b[2J" in output
    assert "\\x9b2J" in output
    assert _MARKUP in output


class TestNeutralizeControls:
    """The helper escapes C0/C1 controls but keeps newline and tab."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (_OSC52, "\\x1b]52;c;SGVsbG8=\\x07"),
            (_CLEAR, "\\x1b[2J"),
            (_CSI_C1, "\\x9b2J"),
            ("a\x7fb", "a\\x7fb"),
            ("a\x00b\rc", "a\\x00b\\x0dc"),
            ("line1\nline2\tx", "line1\nline2\tx"),
            ("plain [bold]text[/bold] é 🔴", "plain [bold]text[/bold] é 🔴"),
        ],
    )
    def test_escapes(self, raw: str, expected: str) -> None:
        assert _neutralize_controls(raw) == expected


class TestDashboardNeutralizesUntrustedText:
    """Model output and tool errors render without raw control sequences."""

    def test_log_line(self) -> None:
        dash = _make_dashboard()
        dash.log(f"[base-dc] saw {_OSC52} {_CLEAR} {_CSI_C1} {_MARKUP}")
        output = _render(dash._build_log_panel(body_height=10))
        _assert_neutralized(output)
        assert "[base-dc]" in output

    def test_finding_title(self) -> None:
        dash = _make_dashboard()
        dash.log_finding("high", f"{_OSC52} {_CLEAR} {_CSI_C1} {_MARKUP}")
        _assert_neutralized(_render(dash._build_log_panel(body_height=10)))

    def test_log_info_and_gate_fail(self) -> None:
        dash = _make_dashboard()
        dash.log_info(f"{_OSC52} {_CLEAR} {_CSI_C1} {_MARKUP}")
        dash.log_gate_fail(f"Query error: {_OSC52} {_CLEAR} {_CSI_C1} {_MARKUP}")
        _assert_neutralized(_render(dash._build_log_panel(body_height=10)))

    def test_task_error_from_log_tailer(self) -> None:
        dash = _make_dashboard()
        dash.update_task("base-dc", "run_fls", "running")
        dash.complete_one_running_task(
            "run_fls", "failed", error=f"{_OSC52} {_CLEAR} {_CSI_C1} {_MARKUP}"
        )
        _assert_neutralized(_render(dash._build_task_panel(body_height=40)))

    def test_task_tool_and_system_names(self) -> None:
        dash = _make_dashboard()
        dash.update_task(f"sys{_CLEAR}", f"tool{_CSI_C1}", "failed", error=f"{_OSC52} {_MARKUP}")
        output = _render(dash._build_task_panel(body_height=40))
        assert "\x1b[2J" not in output
        assert "\x9b" not in output
        assert "\x1b]" not in output
        assert "sys\\x1b[2J" in output
        assert "tool\\x9b2J" in output
