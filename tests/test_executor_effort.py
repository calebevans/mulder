"""Executor sessions, their continuations and plan JSON repair run at
``--executor-effort``; every other role session keeps following ``--effort``.

The fake below stands in for the SDK's ``query``, so each assertion is on the
``ClaudeAgentOptions`` a session would hand the CLI, with the real
orchestrator, role runner and session executor in between.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any, get_args
from unittest.mock import MagicMock, patch

import pytest
from claude_agent_sdk import ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
)
from click.testing import CliRunner

import mulder.server.app as server_app
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.orchestrator.phases import (
    ALTERNATIVE_NARRATIVE,
    CATALOG,
    CROSS_SYSTEM,
    EXTRACTION,
    REPORT,
    PhaseConfig,
)
from mulder.orchestrator.roles import (
    _EXECUTOR_PASSIVE_TOOLS,
    _PLANNER_NO_QUESTIONS,
    _WRAPUP_MAX_TURNS,
)
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.session import _NUDGE_PROMPT
from mulder.orchestrator.types import EffortLevel

SPLIT_PHASES = [EXTRACTION, CROSS_SYSTEM, ALTERNATIVE_NARRATIVE]
LEVELS: tuple[EffortLevel, ...] = get_args(EffortLevel)
CASE = "case"
VARS = {"case_id": CASE, "case_briefing": "", "system_name": "host1"}
QUESTIONS = ["Were credentials dumped?", "Was data staged?"]
REPAIR_SYSTEM_PROMPT = "You fix malformed JSON. Return only valid JSON, nothing else."
OVERFLOW = "Prompt is too long"

#: (role, how the session was started, effort) for one session.
Session = tuple[str, str, str | None]


@pytest.fixture(autouse=True)
def _case_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The case database the role runner reads notes and findings from."""
    CaseDB.create(case_id=CASE, evidence_root="/evidence", db_dir=tmp_path).close()
    # The bridge only sets the directory when no server config exists yet.
    monkeypatch.setattr(server_app, "_cfg", None)
    yield
    server_app._close_current_ctx()


def _text(text: str) -> AssistantMessage:
    return AssistantMessage(content=[TextBlock(text=text)], model="test")


def _result(session_id: str, turn_limit: int = 0) -> ResultMessage:
    """The end of a session; with *turn_limit*, at that limit."""
    return ResultMessage(
        subtype="error_max_turns" if turn_limit else "success",
        duration_ms=1,
        duration_api_ms=1,
        is_error=bool(turn_limit),
        num_turns=turn_limit or 1,
        session_id=session_id,
    )


def _start(prompt: str, options: ClaudeAgentOptions) -> str:
    """How a session was started, read off what the CLI would be handed."""
    if prompt == _NUDGE_PROMPT:
        return "nudge"
    if options.resume:
        return "wrap-up" if options.max_turns == _WRAPUP_MAX_TURNS else "resume"
    return "new"


class _FakeSdk:
    """Answer each role session by its system prompt and record its options.

    The planner returns string tasks, which fail validation and send the plan
    to JSON repair; the repaired plan has two questions, so the extraction
    analyst runs two question sessions and a consolidation. Without
    *questions* it has none, and the planner gives them when it is asked.

    *endings* scripts how the sessions of a role end, in the order they
    start: at the turn limit ("limit"), on a context overflow ("overflow"),
    on a turn with no text and no tool call ("silent"), or with the role's
    answer, which is also what follows the script. Unless scripted, the
    first executor, analyst and single-mode session each stop at their turn
    limit, so each is resumed once.
    """

    def __init__(self, phase: PhaseConfig, questions: bool = True, **endings: list[str]) -> None:
        self.phase = phase
        self.questions = QUESTIONS if questions else []
        self.endings = {role: ["limit"] for role in ("executor", "analyst", "single")} | endings
        self.seen: list[tuple[str, str, ClaudeAgentOptions]] = []
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
        script = self.endings.get(role, [])
        number = sum(r == role for r, _, _ in self.seen)
        ending = script[number] if number < len(script) else "done"
        self.seen.append((role, _start(prompt, options), options))
        session_id = options.resume or f"s{len(self.seen)}"
        if ending == "limit":
            yield _result(session_id, turn_limit=options.max_turns or 1)
            return
        if ending == "overflow":
            yield _text(OVERFLOW)
        elif ending == "silent":
            yield AssistantMessage(
                content=[ThinkingBlock(thinking="the answer", signature="s")],
                model="test",
                message_id=f"silent-{len(self.seen)}",
            )
        elif role == "planner" and _PLANNER_NO_QUESTIONS in prompt:
            yield _text(json.dumps({"investigation_questions": QUESTIONS}))
        elif role == "planner":
            yield _text(json.dumps({"tasks": [f"run {self.tool}"]}))
        elif role == "repair":
            task = {"tool": self.tool, "args": {}, "purpose": "p"}
            yield _text(json.dumps({"tasks": [task], "investigation_questions": self.questions}))
        elif role == "executor":
            yield AssistantMessage(
                content=[ToolUseBlock(id="t1", name=f"mcp__mulder__{self.tool}", input={})],
                model="test",
            )
            yield _text(json.dumps({"results": [{"tool": self.tool, "status": "ok"}]}))
        else:
            yield _text("done")
        yield _result(session_id)

    def sessions(self, role: str = "") -> list[Session]:
        """Every session in the order it started, or those of one *role*."""
        return [(r, start, o.effort) for r, start, o in self.seen if role in ("", r)]


async def _run_phase(
    phase: PhaseConfig,
    tmp_path: Path,
    questions: bool = True,
    endings: dict[str, list[str]] | None = None,
    **orchestrator_args: Any,
) -> _FakeSdk:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator(
            evidence_path="/evidence", case_id=CASE, db_dir=tmp_path, **orchestrator_args
        )
    sdk = _FakeSdk(phase, questions, **(endings or {}))
    run = orch._run_split_phase if phase.mode == "split" else orch._run_single_phase
    with (
        patch("mulder.orchestrator.session.query", sdk.query),
        patch.object(orch, "_validate_phase", return_value=None),
    ):
        result = await run(phase, VARS)
    assert result.success
    return sdk


def _split_sessions(phase: PhaseConfig, effort: str, executor_effort: str) -> list[Session]:
    """The sessions of one split phase under the fake's default script."""
    sessions: list[Session] = [
        ("planner", "new", effort),
        ("repair", "new", executor_effort),
        ("executor", "new", executor_effort),
        ("executor", "resume", executor_effort),  # resumed at its turn limit
        ("analyst", "new", effort),
        ("analyst", "resume", effort),  # the same loop as the executor's, other level
    ]
    if phase is EXTRACTION:
        # The first two were question 1; then question 2 and the consolidation.
        sessions += [("analyst", "new", effort)] * 2
    return sessions


@pytest.mark.parametrize("phase", SPLIT_PHASES, ids=lambda p: p.name)
@pytest.mark.asyncio
async def test_only_executor_sessions_and_repair_use_executor_effort(
    phase: PhaseConfig, tmp_path: Path
) -> None:
    sdk = await _run_phase(phase, tmp_path, effort="max", executor_effort="low")

    assert sdk.sessions() == _split_sessions(phase, "max", "low")


@pytest.mark.parametrize(
    ("phase", "role", "level"),
    [
        (EXTRACTION, "executor", "low"),
        (EXTRACTION, "analyst", "max"),
        (CATALOG, "single", "max"),
        (REPORT, "single", "max"),
    ],
    ids=lambda v: getattr(v, "name", v),
)
@pytest.mark.asyncio
async def test_every_continuation_keeps_the_level_of_its_role_session(
    phase: PhaseConfig, role: str, level: str, tmp_path: Path
) -> None:
    """A handoff to a new session, a resume at the turn limit, and the wrap-up."""
    sdk = await _run_phase(
        phase,
        tmp_path,
        endings={role: ["overflow", "limit", "limit"]},
        effort="max",
        executor_effort="low",
        max_compactions=2,
    )

    assert sdk.sessions(role)[:4] == [
        (role, "new", level),
        (role, "new", level),  # the handoff session after the context overflow
        (role, "resume", level),
        (role, "wrap-up", level),
    ]
    # An extraction analyst goes on to question 2 and the consolidation.
    rest = 2 if role == "analyst" else 0
    assert sdk.sessions(role)[4:] == [(role, "new", level)] * rest


@pytest.mark.parametrize(
    ("role", "level"),
    [("planner", "max"), ("repair", "low"), ("executor", "low"), ("analyst", "max")],
)
@pytest.mark.asyncio
async def test_a_nudge_runs_at_the_level_of_the_session_it_nudges(
    role: str, level: str, tmp_path: Path
) -> None:
    sdk = await _run_phase(
        EXTRACTION, tmp_path, endings={role: ["silent"]}, effort="max", executor_effort="low"
    )

    assert sdk.sessions(role)[:2] == [(role, "new", level), (role, "nudge", level)]


@pytest.mark.asyncio
async def test_plan_from_notes_follow_up_uses_effort(tmp_path: Path) -> None:
    sdk = await _run_phase(
        EXTRACTION, tmp_path, endings={"planner": ["limit"]}, effort="max", executor_effort="low"
    )

    assert sdk.sessions()[:4] == [
        ("planner", "new", "max"),
        ("planner", "resume", "max"),  # resumed with its tools off to write the plan
        ("planner", "new", "max"),  # plan-from-notes follow-up: the resume gave no plan
        ("repair", "new", "low"),
    ]


@pytest.mark.parametrize(("wrapup", "start"), [(True, "resume"), (False, "new")])
@pytest.mark.asyncio
async def test_questions_request_uses_effort(tmp_path: Path, wrapup: bool, start: str) -> None:
    """A plan with no questions goes back to the planner, resumed or anew."""
    sdk = await _run_phase(
        EXTRACTION, tmp_path, questions=False, effort="max", executor_effort="low", wrapup=wrapup
    )

    assert sdk.sessions()[:3] == [
        ("planner", "new", "max"),
        ("repair", "new", "low"),
        ("planner", start, "max"),
    ]


@pytest.mark.parametrize("phase", SPLIT_PHASES, ids=lambda p: p.name)
@pytest.mark.asyncio
async def test_executor_effort_defaults_to_low(phase: PhaseConfig, tmp_path: Path) -> None:
    sdk = await _run_phase(phase, tmp_path)

    assert sdk.sessions() == _split_sessions(phase, "max", "low")


@pytest.mark.parametrize("phase", [CATALOG, REPORT], ids=lambda p: p.name)
@pytest.mark.asyncio
async def test_single_phases_follow_effort(phase: PhaseConfig, tmp_path: Path) -> None:
    sdk = await _run_phase(phase, tmp_path, effort="xhigh", executor_effort="low")

    # The second is the same session, resumed at its turn limit.
    assert sdk.sessions() == [("single", "new", "xhigh"), ("single", "resume", "xhigh")]


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.asyncio
async def test_equal_levels_give_every_session_one_effort(
    level: EffortLevel, tmp_path: Path
) -> None:
    """What every session received before the executor had its own level."""
    sdk = await _run_phase(EXTRACTION, tmp_path, effort=level, executor_effort=level)

    assert sdk.sessions() == _split_sessions(EXTRACTION, level, level)


@pytest.mark.asyncio
async def test_no_thinking_overrides_both_levels(tmp_path: Path) -> None:
    # A handoff, a nudge, a resume and a wrap-up among them.
    endings = {"executor": ["overflow", "silent", "limit", "limit"]}
    sdk = await _run_phase(
        EXTRACTION,
        tmp_path,
        endings=endings,
        effort="max",
        executor_effort="low",
        no_thinking=True,
        max_compactions=2,
    )

    assert [start for _, start, _ in sdk.sessions("executor")] == [
        "new",
        "new",
        "nudge",
        "resume",
        "wrap-up",
    ]
    assert {effort for _, _, effort in sdk.sessions()} == {None}
    assert all(options.thinking == {"type": "disabled"} for _, _, options in sdk.seen)


@pytest.mark.parametrize(("no_thinking", "shown"), [(False, "low"), (True, "unset")])
@pytest.mark.asyncio
async def test_starting_query_log_line_names_the_effort(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, no_thinking: bool, shown: str
) -> None:
    with caplog.at_level(logging.INFO, logger="mulder.orchestrator.session"):
        sdk = await _run_phase(
            EXTRACTION, tmp_path, effort="max", executor_effort="low", no_thinking=no_thinking
        )

    limit = EXTRACTION.executor_max_turns
    assert f"max_turns={limit}, effort={shown})" in caplog.text
    # A resumed session names the session it resumes after its level.
    resumed = next(
        o.resume for role, start, o in sdk.seen if (role, start) == ("executor", "resume")
    )
    assert f"max_turns={limit}, effort={shown}, resume={resumed})" in caplog.text


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
