"""Both SDK query paths opt out of Claude Code's per-session auto-title request."""

from __future__ import annotations

from collections.abc import AsyncIterator
from unittest.mock import patch

import pytest
from claude_agent_sdk import ClaudeAgentOptions

from mulder.orchestrator.runner import Orchestrator

_VAR = "CLAUDE_CODE_DISABLE_TERMINAL_TITLE"


@pytest.mark.parametrize("utility", [False, True])
@pytest.mark.parametrize("caller_value", [None, "0"])
@pytest.mark.asyncio()
async def test_session_title_disabled_unless_caller_overrides(
    utility: bool, caller_value: str | None
) -> None:
    env = {"MULDER_TEST_MARKER": "x"}
    if caller_value is not None:
        env[_VAR] = caller_value
    orchestrator = Orchestrator("/evidence", env=env)
    seen: list[dict[str, str]] = []

    async def capture_query(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[object]:
        seen.append(dict(options.env))
        return
        yield  # pragma: no cover

    with patch("mulder.orchestrator.session.query", capture_query):
        if utility:
            await orchestrator._session.execute_utility("wait", [], "wait_all")
        else:
            await orchestrator._session.execute("s", "p", "test-model", [], [], 1)

    assert len(seen) == 1
    assert seen[0][_VAR] == (caller_value or "1")
    assert seen[0]["MULDER_TEST_MARKER"] == "x"
