"""Executor sessions, their continuations and plan JSON repair run at
``--executor-effort``; every other role session keeps following ``--effort``.

The fake below stands in for the SDK's ``query``, so each assertion is on the
``ClaudeAgentOptions`` a session would hand the CLI, with the real
orchestrator, role runner and session executor in between.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, get_args
from unittest.mock import MagicMock, patch

import pytest
from claude_agent_sdk import ClaudeAgentOptions
from claude_agent_sdk.types import AssistantMessage, ResultMessage, TextBlock, ToolUseBlock
from click.testing import CliRunner

from mulder.cli import cli
from mulder.orchestrator.phases import (
    ALTERNATIVE_NARRATIVE,
    CATALOG,
    CROSS_SYSTEM,
    EXTRACTION,
    REPORT,
    PhaseConfig,
)
from mulder.orchestrator.roles import _EXECUTOR_PASSIVE_TOOLS
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import EffortLevel

SPLIT_PHASES = [EXTRACTION, CROSS_SYSTEM, ALTERNATIVE_NARRATIVE]
LEVELS: tuple[EffortLevel, ...] = get_args(EffortLevel)
VARS = {"case_id": "case", "case_briefing": "", "system_name": "host1"}
REPAIR_SYSTEM_PROMPT = "You fix malformed JSON. Return only valid JSON, nothing else."


def _text(text: str) -> AssistantMessage:
    return AssistantMessage(content=[TextBlock(text=text)], model="test")


class _FakeSdk:
    """Answer each role session by its system prompt and record its options.

    The planner returns string tasks, which fail validation and send the plan
    to JSON repair. The first executor, analyst and single-mode session each
    stop at their turn limit, so each gets one continuation; with
    *planner_out_of_turns* so does the planner, which sends it to the
    plan-from-notes follow-up.
    """

    def __init__(self, phase: PhaseConfig, planner_out_of_turns: bool = False) -> None:
        self.phase = phase
        self.out_of_turns = {"executor", "analyst", "single"}
        if planner_out_of_turns:
            self.out_of_turns.add("planner")
        self.seen: list[tuple[str, ClaudeAgentOptions]] = []
        # A tool the executor role may run that counts as extraction work.
        self.tool = next(
            (
                name
                for t in phase.executor_allowed_tools
                if (name := t.removeprefix("mcp__mulder__")) not in _EXECUTOR_PASSIVE_TOOLS
            ),
            "",
        )

    def _role(self, system_prompt: object) -> str:
        return {
            self.phase.planner_system_prompt: "planner",
            self.phase.executor_system_prompt: "executor",
            self.phase.analyst_system_prompt: "analyst",
            self.phase.single_system_prompt: "single",
            REPAIR_SYSTEM_PROMPT: "repair",
        }[str(system_prompt)]

    async def query(self, *, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[object]:
        role = self._role(options.system_prompt)
        first = not any(r == role for r, _ in self.seen)
        self.seen.append((role, options))
        if first and role in self.out_of_turns:
            yield ResultMessage(
                subtype="error_max_turns",
                duration_ms=1,
                duration_api_ms=1,
                is_error=True,
                num_turns=options.max_turns or 0,
                session_id="s1",
                terminal_reason="max_turns",
            )
        elif role == "planner":
            yield _text(json.dumps({"tasks": [f"run {self.tool}"]}))
        elif role == "repair":
            yield _text(json.dumps({"tasks": [{"tool": self.tool, "args": {}, "purpose": "p"}]}))
        elif role == "executor":
            yield AssistantMessage(
                content=[ToolUseBlock(id="t1", name=f"mcp__mulder__{self.tool}", input={})],
                model="test",
            )
            yield _text(json.dumps({"results": [{"tool": self.tool, "status": "ok"}]}))
        else:
            yield _text("done")

    def efforts(self) -> list[tuple[str, str | None]]:
        return [(role, options.effort) for role, options in self.seen]


async def _run_phase(
    phase: PhaseConfig,
    tmp_path: Path,
    planner_out_of_turns: bool = False,
    **orchestrator_args: Any,
) -> _FakeSdk:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator(
            evidence_path="/evidence", case_id="case", db_dir=tmp_path, **orchestrator_args
        )
    sdk = _FakeSdk(phase, planner_out_of_turns)
    run = orch._run_split_phase if phase.mode == "split" else orch._run_single_phase
    with (
        patch("mulder.orchestrator.session.query", sdk.query),
        patch.object(orch, "_validate_phase", return_value=None),
    ):
        result = await run(phase, VARS)
    assert result.success
    return sdk


@pytest.mark.parametrize("phase", SPLIT_PHASES, ids=lambda p: p.name)
@pytest.mark.asyncio
async def test_only_executor_sessions_and_repair_use_executor_effort(
    phase: PhaseConfig, tmp_path: Path
) -> None:
    sdk = await _run_phase(phase, tmp_path, effort="max", executor_effort="low")

    assert sdk.efforts() == [
        ("planner", "max"),
        ("repair", "low"),
        ("executor", "low"),
        ("executor", "low"),  # continuation after the turn limit
        ("analyst", "max"),
        ("analyst", "max"),  # continuation: same loop as the executor's, other level
    ]


@pytest.mark.asyncio
async def test_plan_from_notes_follow_up_uses_effort(tmp_path: Path) -> None:
    sdk = await _run_phase(
        EXTRACTION, tmp_path, planner_out_of_turns=True, effort="max", executor_effort="low"
    )

    assert sdk.efforts()[:3] == [
        ("planner", "max"),
        ("planner", "max"),  # plan-from-notes follow-up after the turn limit
        ("repair", "low"),
    ]


@pytest.mark.parametrize("phase", SPLIT_PHASES, ids=lambda p: p.name)
@pytest.mark.asyncio
async def test_executor_effort_defaults_to_low(phase: PhaseConfig, tmp_path: Path) -> None:
    sdk = await _run_phase(phase, tmp_path)

    assert {effort for role, effort in sdk.efforts() if role in ("executor", "repair")} == {"low"}
    assert {effort for role, effort in sdk.efforts() if role in ("planner", "analyst")} == {"max"}


@pytest.mark.parametrize("phase", [CATALOG, REPORT], ids=lambda p: p.name)
@pytest.mark.asyncio
async def test_single_phases_follow_effort(phase: PhaseConfig, tmp_path: Path) -> None:
    sdk = await _run_phase(phase, tmp_path, effort="xhigh", executor_effort="low")

    # The second session is the continuation after the turn limit.
    assert sdk.efforts() == [("single", "xhigh"), ("single", "xhigh")]


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.asyncio
async def test_equal_levels_give_every_session_one_effort(
    level: EffortLevel, tmp_path: Path
) -> None:
    """What every session received before the executor had its own level."""
    sdk = await _run_phase(EXTRACTION, tmp_path, effort=level, executor_effort=level)

    assert [role for role, _ in sdk.efforts()] == [
        "planner",
        "repair",
        "executor",
        "executor",
        "analyst",
        "analyst",
    ]
    assert {effort for _, effort in sdk.efforts()} == {level}


@pytest.mark.asyncio
async def test_no_thinking_overrides_both_levels(tmp_path: Path) -> None:
    sdk = await _run_phase(
        EXTRACTION, tmp_path, effort="max", executor_effort="low", no_thinking=True
    )

    assert len(sdk.seen) == 6
    assert {options.effort for _, options in sdk.seen} == {None}
    assert all(options.thinking == {"type": "disabled"} for _, options in sdk.seen)


@pytest.mark.parametrize(("no_thinking", "shown"), [(False, "low"), (True, "unset")])
@pytest.mark.asyncio
async def test_starting_query_log_line_names_the_effort(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, no_thinking: bool, shown: str
) -> None:
    with caplog.at_level(logging.INFO, logger="mulder.orchestrator.session"):
        await _run_phase(
            EXTRACTION, tmp_path, effort="max", executor_effort="low", no_thinking=no_thinking
        )

    limit = EXTRACTION.executor_max_turns
    assert f"max_turns={limit}, effort={shown})" in caplog.text


class TestCli:
    """``--executor-effort`` and ``MULDER_EXECUTOR_EFFORT`` reach the orchestrator."""

    @staticmethod
    def _invoke(args: list[str], env: dict[str, str] | None = None) -> tuple[Any, MagicMock]:
        with (
            patch("mulder.orchestrator.runner.Orchestrator") as orchestrator_cls,
            patch("asyncio.run", return_value=MagicMock(success=True)),
        ):
            result = CliRunner().invoke(
                cli, ["investigate", "/evidence", "case-1", *args], env=env
            )
        return result, orchestrator_cls

    def _levels(self, args: list[str], env: dict[str, str] | None = None) -> tuple[str, str]:
        result, cls = self._invoke(args, env)
        assert result.exit_code == 0, result.output
        kwargs = cls.call_args.kwargs
        return kwargs["effort"], kwargs["executor_effort"]

    def test_defaults(self) -> None:
        assert self._levels([]) == ("max", "low")

    def test_flag(self) -> None:
        assert self._levels(["--executor-effort", "max"]) == ("max", "max")

    def test_env_var(self) -> None:
        assert self._levels([], env={"MULDER_EXECUTOR_EFFORT": "medium"}) == ("max", "medium")

    def test_flag_beats_env_var(self) -> None:
        args = ["--executor-effort", "high"]
        assert self._levels(args, env={"MULDER_EXECUTOR_EFFORT": "medium"}) == ("max", "high")

    @pytest.mark.parametrize("level", LEVELS)
    def test_effort_accepts_every_level(self, level: str) -> None:
        assert self._levels(["--effort", level]) == (level, "low")

    @pytest.mark.parametrize("option", ["--effort", "--executor-effort"])
    def test_unknown_level_is_rejected(self, option: str) -> None:
        result, _ = self._invoke([option, "minimal"])
        assert result.exit_code != 0

    def test_bad_env_value_is_rejected(self) -> None:
        result, _ = self._invoke([], env={"MULDER_EXECUTOR_EFFORT": "minimal"})
        assert result.exit_code != 0

    def test_banner_shows_both_levels(self) -> None:
        result, _ = self._invoke(["--effort", "high"])
        assert "Effort: high (executor: low)" in result.output

    def test_banner_under_no_thinking(self) -> None:
        result, _ = self._invoke(["--no-thinking"])
        assert "Thinking: disabled (effort ignored)" in result.output
        assert "executor:" not in result.output
