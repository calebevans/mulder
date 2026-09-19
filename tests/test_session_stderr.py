"""Opt-in agent CLI diagnostics across both SDK query paths."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from unittest.mock import patch

import pytest
from claude_agent_sdk import ClaudeAgentOptions

from mulder.orchestrator.runner import Orchestrator


@pytest.mark.parametrize("show_stderr", [False, True])
@pytest.mark.parametrize("utility", [False, True])
@pytest.mark.asyncio()
async def test_cli_stderr_on_failure(
    show_stderr: bool, utility: bool, caplog: pytest.LogCaptureFixture
) -> None:
    """Diagnostics survive a failing query only when explicitly requested."""
    orchestrator = Orchestrator("/evidence", show_cli_stderr=show_stderr)

    async def failing_query(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[object]:
        assert options.stderr is not None
        options.stderr("\x1b[2J\x1b[31m[red]CLI diagnostic[/red]\x1b[0m")
        options.stderr("\n")
        raise RuntimeError("Check stderr output for details")
        yield  # pragma: no cover

    with patch("mulder.orchestrator.session.query", failing_query), caplog.at_level(logging.INFO):
        if utility:
            result = await orchestrator._session.execute_utility("wait", [], "wait_all")
            assert result is None
        else:
            phase = await orchestrator._session.execute("test", "test", "test-model", [], [], 1)
            assert not phase.success

    label = "utility: wait_all" if utility else "test-model"
    expected = f"[{label}] CLI stderr: [red]CLI diagnostic[/red]"
    lines = [line.plain.strip() for line in orchestrator.dashboard._log_lines]
    if show_stderr:
        assert expected in lines
        assert expected in caplog.text
    else:
        assert not any("CLI diagnostic" in line for line in lines)
        assert "CLI diagnostic" not in caplog.text
    assert "\x1b" not in "".join(lines)
    assert sum("CLI stderr:" in line for line in lines) == int(show_stderr)


@pytest.mark.asyncio()
async def test_concurrent_stderr_keeps_worker_labels() -> None:
    """Interleaved callbacks retain each query's worker label."""
    orchestrator = Orchestrator("/evidence", show_cli_stderr=True)

    async def interleaved_query(
        *, prompt: str, options: ClaudeAgentOptions
    ) -> AsyncIterator[object]:
        assert options.stderr is not None
        options.stderr(f"{prompt} first")
        await asyncio.sleep(0)
        options.stderr(f"{prompt} second")
        return
        yield  # pragma: no cover

    with patch("mulder.orchestrator.session.query", interleaved_query):
        await asyncio.gather(
            *(
                orchestrator._session.execute("test", host, "test-model", [], [], 1, host)
                for host in ("host-a", "host-b")
            )
        )

    lines = [line.plain.strip() for line in orchestrator.dashboard._log_lines]
    diagnostics = [line for line in lines if "CLI stderr:" in line]
    assert diagnostics == [
        "[host-a] CLI stderr: host-a first",
        "[host-b] CLI stderr: host-b first",
        "[host-a] CLI stderr: host-a second",
        "[host-b] CLI stderr: host-b second",
    ]
