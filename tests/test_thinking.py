"""Thinking opt-out reaches phase and utility SDK queries without changing defaults."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from claude_agent_sdk import ClaudeAgentOptions
from claude_agent_sdk.types import AssistantMessage, TextBlock
from click.testing import CliRunner

from mulder.cli import cli
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import EffortLevel


@pytest.mark.parametrize("no_thinking", [False, True])
@pytest.mark.parametrize("effort", ["max", "xhigh", "high"])
@pytest.mark.asyncio
async def test_thinking_options_reach_both_queries(
    tmp_path: Path, no_thinking: bool, effort: EffortLevel
) -> None:
    options_seen: list[ClaudeAgentOptions] = []

    async def capture_query(
        *, prompt: str, options: ClaudeAgentOptions
    ) -> AsyncIterator[AssistantMessage]:
        options_seen.append(options)
        yield AssistantMessage(content=[TextBlock(text='{"ok": true}')], model="test")

    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orchestrator = Orchestrator(
            evidence_path="/evidence",
            cwd=tmp_path,
            db_dir=tmp_path,
            effort=effort,
            no_thinking=no_thinking,
        )
    with patch("mulder.orchestrator.session.query", capture_query):
        await orchestrator._session.execute(
            system_prompt="test",
            prompt="test",
            model="test",
            allowed_tools=[],
            disallowed_tools=[],
            max_turns=1,
        )
        result = await orchestrator._session.execute_utility(
            prompt="test", allowed_tools=[], label="test"
        )

    assert result == {"ok": True}
    assert len(options_seen) == 2
    assert [option.thinking for option in options_seen] == (
        [{"type": "disabled"}] * 2 if no_thinking else [None, None]
    )
    assert [option.effort for option in options_seen] == (
        [None, None] if no_thinking else [effort, "low"]
    )


@pytest.mark.parametrize("no_thinking", [False, True])
def test_cli_thinking_option(tmp_path: Path, no_thinking: bool) -> None:
    with (
        patch("mulder.orchestrator.runner.Orchestrator") as orchestrator,
        patch("asyncio.run", return_value=MagicMock(success=True)),
    ):
        result = CliRunner().invoke(
            cli,
            [
                "investigate",
                "/evidence",
                "case-1",
                "--db-dir",
                str(tmp_path / "db"),
                "--cwd",
                str(tmp_path / "workspace"),
                *(["--no-thinking"] if no_thinking else []),
            ],
        )
    assert result.exit_code == 0, result.output
    assert orchestrator.call_args.kwargs["no_thinking"] is no_thinking
