"""Tests for the resource gate exemption in ``app._wrap_sync_tool``."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import anyio
import pytest

from mulder.server import app
from mulder.server.tool_access import UNTHROTTLED, Role, tool_access


@pytest.fixture
def pressured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Configure a server whose gate always reports CPU pressure."""
    monkeypatch.setattr(app, "_cfg", app.ServerConfig(db_dir=tmp_path, max_workers=1))
    monkeypatch.setattr(app, "_tool_limiter", anyio.CapacityLimiter(1))
    monkeypatch.setattr(app, "_get_resource_usage", lambda: (10.0, 100.0))
    monkeypatch.setattr(app, "_RESOURCE_CHECK_INTERVAL", 0.01)
    monkeypatch.setattr(app, "_RESOURCE_MAX_WAIT", 0.03)
    yield
    UNTHROTTLED.discard("unthrottled_probe")


def _throttle_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if "Resource throttle" in r.getMessage()]


async def test_gated_tool_waits_under_pressure(
    pressured: None, caplog: pytest.LogCaptureFixture
) -> None:
    def gated_probe() -> str:
        return "ran"

    wrapped = app._wrap_sync_tool(gated_probe)
    with caplog.at_level(logging.INFO, logger="mulder.server.app"):
        assert await wrapped() == "ran"
    assert any("gated_probe waiting" in line for line in _throttle_lines(caplog))


async def test_unthrottled_tool_skips_gate_and_limiter(
    pressured: None, caplog: pytest.LogCaptureFixture
) -> None:
    @tool_access(Role.CATALOG, unthrottled=True)
    def unthrottled_probe() -> str:
        return "ran"

    wrapped = app._wrap_sync_tool(unthrottled_probe)
    # Hold the only tool-limiter slot from this task: acquiring it again here
    # would raise, and the gate would log a throttle line, so a clean "ran"
    # proves the tool used neither.
    with caplog.at_level(logging.INFO, logger="mulder.server.app"), anyio.fail_after(1):
        async with app._get_tool_limiter():
            assert await wrapped() == "ran"
    assert _throttle_lines(caplog) == []


def test_control_tools_are_registered_unthrottled() -> None:
    import mulder.server.tools.case  # noqa: F401
    import mulder.server.tools.jobs  # noqa: F401

    assert {
        "start_extraction_batch",
        "check_extraction_status",
        "get_completed_results",
        "wait",
        "wait_all",
        "open_case",
        "list_cases",
    } <= UNTHROTTLED
    assert "search" not in UNTHROTTLED
    assert "run_plaso" not in UNTHROTTLED
