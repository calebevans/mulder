"""Thinking blocks and silent assistant turns are visible in orchestrator.log (#199)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import patch

import pytest
from claude_agent_sdk import ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    ContentBlock,
    ResultMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
)

from mulder.orchestrator.runner import Orchestrator

REASONING = "SECRET-REASONING " * 100
SILENT_WARNING = "assistant turn had no text and no tool use (thinking-only or empty)"


def _assistant(*blocks: ContentBlock, msg_id: str = "msg_1") -> AssistantMessage:
    return AssistantMessage(content=list(blocks), model="test-model", message_id=msg_id)


def _result(stop_reason: str | None = "end_turn") -> ResultMessage:
    return ResultMessage(
        subtype="success",
        duration_ms=1,
        duration_api_ms=1,
        is_error=False,
        num_turns=1,
        session_id="sess",
        stop_reason=stop_reason,
    )


async def _run(tmp_path: Path, stream: list[object], caplog: pytest.LogCaptureFixture) -> None:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator(evidence_path="/evidence", case_id="case", db_dir=str(tmp_path))

    async def fake_query(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[object]:
        for message in stream:
            yield message

    with patch("mulder.orchestrator.session.query", fake_query), caplog.at_level(logging.INFO):
        await orch._session.execute("sys", "go", "test-model", [], [], 3, log_prefix="host-a")


@pytest.mark.asyncio()
async def test_thinking_logged_as_counts_without_content(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    stream = [
        _assistant(
            ThinkingBlock(thinking=REASONING, signature="sig"),
            ThinkingBlock(thinking="short", signature="sig"),
            ToolUseBlock(id="t1", name="mcp__mulder__search", input={}),
        ),
        _result(),
    ]
    await _run(tmp_path, stream, caplog)

    assert f"[host-a] thinking: 2 blocks, {len(REASONING) + 5} chars" in caplog.text
    assert "SECRET-REASONING" not in caplog.text
    assert SILENT_WARNING not in caplog.text
    assert f"thinking=2 blocks/{len(REASONING) + 5} chars" in caplog.text
    assert "silent turn" not in caplog.text


@pytest.mark.asyncio()
async def test_final_silent_turn_warns_and_marks_completion(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The #197 shape: answer in the thinking block, empty text, no tool use."""
    stream = [
        _assistant(ThinkingBlock(thinking=REASONING, signature="sig"), TextBlock(text="  \n")),
        _result("end_turn"),
    ]
    await _run(tmp_path, stream, caplog)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert [r.getMessage() for r in warnings] == [
        f"[host-a] {SILENT_WARNING}; session may end here"
    ]
    assert "Query complete (model=test-model)" in caplog.text
    assert "ended on a silent turn (stop_reason=end_turn)" in caplog.text


@pytest.mark.asyncio()
async def test_plain_text_turn_logs_nothing_extra(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    stream = [_assistant(TextBlock(text="Investigation complete.")), _result()]
    await _run(tmp_path, stream, caplog)

    assert "thinking:" not in caplog.text
    assert SILENT_WARNING not in caplog.text
    assert "silent turn" not in caplog.text
    assert "thinking=0 blocks/0 chars" in caplog.text


@pytest.mark.asyncio()
async def test_per_block_messages_of_one_turn_are_not_silent(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The CLI may split one API turn into one AssistantMessage per block."""
    stream = [
        _assistant(ThinkingBlock(thinking=REASONING, signature="sig"), msg_id="msg_1"),
        _assistant(ToolUseBlock(id="t1", name="mcp__mulder__search", input={}), msg_id="msg_1"),
        _result("tool_use"),
    ]
    await _run(tmp_path, stream, caplog)

    assert SILENT_WARNING not in caplog.text
    assert "silent turn" not in caplog.text


@pytest.mark.asyncio()
async def test_mid_session_silent_turn_warns_once_but_completion_is_clean(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    stream = [
        _assistant(ThinkingBlock(thinking="hmm", signature="sig"), msg_id="msg_1"),
        _assistant(TextBlock(text="Done."), msg_id="msg_2"),
        _result(),
    ]
    await _run(tmp_path, stream, caplog)

    assert caplog.text.count(SILENT_WARNING) == 1
    assert "silent turn" not in caplog.text
