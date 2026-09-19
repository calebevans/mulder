"""A session that stops at ``max_turns`` has produced no final answer, so it
gets the same bounded continuation as a context overflow, classified by the
SDK's structured ``error_max_turns`` subtype rather than by string matching
(issue #195, restoring what #192 dropped)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from claude_agent_sdk import ClaudeAgentOptions as Options
from claude_agent_sdk import ResultError
from claude_agent_sdk.types import ResultMessage

from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.roles import RoleRunner
from mulder.orchestrator.session import SessionExecutor
from mulder.orchestrator.types import PhaseResult

MAX_TURNS_TEXT = "Claude Code returned an error result: Reached maximum number of turns (35)"
OVERFLOW_TEXT = "API Error: 400 This model's maximum context length is 163840 tokens"


def _max_turns_result() -> ResultMessage:
    return ResultMessage(
        subtype="error_max_turns",
        duration_ms=1,
        duration_api_ms=1,
        is_error=True,
        num_turns=35,
        session_id="s1",
        errors=["Reached maximum number of turns (35)"],
        terminal_reason="max_turns",
    )


async def _run(yield_result: bool, error: Exception | None) -> tuple[PhaseResult, MagicMock]:
    async def fake_query(*, prompt: str, options: Options) -> AsyncIterator[object]:
        if yield_result:
            yield _max_turns_result()
        if error is not None:
            raise error

    dashboard = MagicMock()
    session = SessionExecutor(
        dashboard=dashboard, model_config=ModelConfig(), cwd="/tmp", env={}, effort="max"
    )
    with patch("mulder.orchestrator.session.query", fake_query):
        result = await session.execute("s", "p", "m", [], [], 35)
    return result, dashboard


@pytest.mark.asyncio()
async def test_max_turns_result_then_result_error_is_turn_exhaustion() -> None:
    err = ResultError(MAX_TURNS_TEXT, data={"subtype": "error_max_turns"}, exit_code=1)
    result, dashboard = await _run(yield_result=True, error=err)
    assert result.turns_exhausted
    assert result.context_exhausted
    assert result.turns_used == 35
    dashboard.log_gate_fail.assert_not_called()


@pytest.mark.asyncio()
async def test_result_error_subtype_alone_is_enough() -> None:
    err = ResultError(MAX_TURNS_TEXT, data={"subtype": "error_max_turns"}, exit_code=1)
    result, _ = await _run(yield_result=False, error=err)
    assert result.turns_exhausted and result.context_exhausted


@pytest.mark.asyncio()
async def test_context_overflow_is_still_exhaustion_but_not_turns() -> None:
    result, _ = await _run(yield_result=False, error=RuntimeError(OVERFLOW_TEXT))
    assert result.context_exhausted
    assert not result.turns_exhausted


@pytest.mark.asyncio()
async def test_other_errors_do_not_continue() -> None:
    result, dashboard = await _run(yield_result=False, error=RuntimeError("API Error: 500"))
    assert not result.context_exhausted
    assert not result.turns_exhausted
    dashboard.log_gate_fail.assert_called_once()


@pytest.mark.asyncio()
async def test_role_continuation_after_turn_limit_is_bounded() -> None:
    session = MagicMock()
    calls: list[str] = []

    async def execute(**kwargs: Any) -> PhaseResult:
        calls.append(kwargs["prompt"])
        return PhaseResult(
            phase_name="query", turns_used=35, context_exhausted=True, turns_exhausted=True
        )

    session.execute = execute
    dashboard = MagicMock()
    roles = RoleRunner(session, dashboard, ModelConfig(), "c", {}, "/tmp", max_compactions=2)
    first = await execute(prompt="initial")
    extra = await roles.compaction_loop(first, "sys", "m", [], [], 35, "CONTINUE", "Analyst")

    assert extra == 70
    assert calls == ["initial", "CONTINUE", "CONTINUE"]
    assert first.turns_exhausted  # still exhausted after the cap; caller decides
    assert "ran out of turns" in dashboard.log_info.call_args_list[0].args[0]
