"""Tests for mulder.server.timeouts -- deferral decision logic."""

from __future__ import annotations

from unittest.mock import patch

from mulder.server.timeouts import is_system_under_load, should_defer


class TestIsSystemUnderLoad:
    @patch("mulder.server.timeouts._get_cpu_percent", return_value=85.0)
    def test_high_cpu_returns_true(self, _mock_cpu: object) -> None:
        assert is_system_under_load() is True

    @patch("mulder.server.timeouts._get_cpu_percent", return_value=30.0)
    def test_low_cpu_returns_false(self, _mock_cpu: object) -> None:
        assert is_system_under_load() is False

    @patch("mulder.server.timeouts._get_cpu_percent", return_value=-1.0)
    def test_unavailable_cpu_returns_false(self, _mock_cpu: object) -> None:
        assert is_system_under_load() is False

    @patch("mulder.server.timeouts._get_cpu_percent", return_value=75.0)
    def test_custom_threshold(self, _mock_cpu: object) -> None:
        assert is_system_under_load(cpu_threshold=80.0) is False
        assert is_system_under_load(cpu_threshold=70.0) is True


class TestShouldDefer:
    @patch("mulder.server.timeouts.is_system_under_load", return_value=False)
    def test_other_running_jobs_defers(self, _mock_load: object) -> None:
        assert should_defer(other_running_in_batch=2) is True

    @patch("mulder.server.timeouts.is_system_under_load", return_value=True)
    def test_high_load_no_running_defers(self, _mock_load: object) -> None:
        assert should_defer(other_running_in_batch=0) is True

    @patch("mulder.server.timeouts.is_system_under_load", return_value=False)
    def test_low_load_no_running_does_not_defer(self, _mock_load: object) -> None:
        assert should_defer(other_running_in_batch=0) is False
