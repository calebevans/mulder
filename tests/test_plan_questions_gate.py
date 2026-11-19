"""An extraction plan always has investigation questions, and that is gated.

Every extraction analyst session answers one of the plan's questions, so a
plan with tasks and no usable question is not accepted. The planner is told
why and asked for the questions alone (its session resumed with tools off,
then one tool-less new session). If it still has none the plan is rejected:
the first cycle re-plans and then fails the system, a follow-up round ends,
and no analyst session runs on that plan. The questions are the planner's,
written from everything it has, the investigator's ``MULDER.md`` included.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

import mulder.server.app as server_app
from mulder.db import CaseDB
from mulder.orchestrator import evidence
from mulder.orchestrator.budget import TokenBudgetReached
from mulder.orchestrator.fallback import incomplete_notice
from mulder.orchestrator.gates import GateResult
from mulder.orchestrator.phases import ALTERNATIVE_NARRATIVE, CROSS_SYSTEM, EXTRACTION
from mulder.orchestrator.roles import (
    _MAX_QUESTION_CHARS,
    _MAX_QUESTION_SESSIONS,
    _PLANNER_NO_QUESTIONS,
    _PLANNER_NO_QUESTIONS_NOTES,
    _QUESTION_MAX_TURNS,
    _QUESTION_PLACEHOLDER,
    RoleRunner,
)
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import ExecutionResults, InvestigationResult, PhaseResult, Plan
from mulder.questions import ID_LABELS, MAX_QUESTIONS_PER_PLAN

CASE = "case-1"
SYSTEM = "host-a"
PLANNER_SESSION = "planner-1"
TASKS = [{"tool": "run_mmls", "args": {"image_path": "/evidence/host-a.E01"}, "purpose": "x"}]
QUESTIONS = ["Were credentials dumped?", "Was data staged?"]
FOLLOW_UP = {"request": "additional_plan", "reason": "need evtx", "suggested_tools": ["x"]}
BRIEFING = "## Investigation Questions\n1. Did jdoe copy the payroll export to a USB drive?"


def _plan(questions: Any = None, tasks: Any = TASKS) -> str:
    """A planner's final message; *questions* None leaves the key out."""
    plan: dict[str, Any] = {"tasks": tasks, "expected_sources": []}
    if questions is not None:
        plan["investigation_questions"] = questions
    return json.dumps(plan)


def _answer(questions: Any) -> str:
    return json.dumps({"investigation_questions": questions})


NO_QUESTIONS = _plan()
NONE = "I cannot think of any."


@pytest.fixture()
def db_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    CaseDB.create(case_id=CASE, evidence_root="/evidence", db_dir=tmp_path).close()
    monkeypatch.setattr(server_app, "_cfg", None)
    yield tmp_path
    server_app._close_current_ctx()


def _orchestrator(db_dir: Path, evidence: str = "/evidence", **kwargs: Any) -> Orchestrator:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        return Orchestrator(evidence, case_id=CASE, db_dir=db_dir, **kwargs)


class _Script:
    """Fake ``SessionExecutor.execute`` that answers by the kind of session.

    ``planner`` sessions take the next of *plans* (the last repeats), the
    tool-less requests for the questions (``resume`` of the planner session,
    then ``ask``, a new one) the next of *answers* (then ``NONE``), and
    ``analyst`` sessions the next of *analysts* (then "done"). *resume*
    answers the resume instead, to make it fail. *planner_ended* is how the
    planner session ended early: at its "turn limit", or a "context overflow".
    """

    def __init__(
        self,
        plans: list[str],
        answers: list[str] | None = None,
        analysts: list[str] | None = None,
        session_id: str = PLANNER_SESSION,
        phase: Any = EXTRACTION,
        resume: PhaseResult | Exception | None = None,
        planner_ended: str = "",
    ) -> None:
        self.plans = plans
        self.planner_ended = planner_ended
        self.answers = iter(answers or [])
        self.analysts = iter(analysts or [])
        self.session_id = session_id
        self.phase = phase
        self.resume = resume
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _kind(self, kwargs: dict[str, Any]) -> str:
        if kwargs["system_prompt"] == self.phase.analyst_system_prompt:
            return "analyst"
        if kwargs["allowed_tools"]:
            return "planner"
        return "resume" if kwargs.get("resume") else "ask"

    async def execute(self, **kwargs: Any) -> PhaseResult:
        kind = self._kind(kwargs)
        self.calls.append((kind, kwargs))
        if kind == "analyst":
            return PhaseResult("query", messages=[next(self.analysts, "done")], turns_used=5)
        if kind == "planner":
            planned = self.kinds.count("planner")
            message = self.plans[min(planned, len(self.plans)) - 1]
            return PhaseResult(
                "query",
                messages=[message],
                turns_used=3,
                session_id=self.session_id,
                context_exhausted=bool(self.planner_ended),
                turns_exhausted=self.planner_ended == "turn limit",
            )
        if kind == "resume" and self.resume is not None:
            if isinstance(self.resume, Exception):
                raise self.resume
            return self.resume
        # A resume that took reports the session it resumed.
        return PhaseResult(
            "query",
            messages=[next(self.answers, NONE)],
            turns_used=1,
            session_id=kwargs.get("resume", ""),
        )

    @property
    def kinds(self) -> list[str]:
        return [kind for kind, _ in self.calls]

    def prompts(self, kind: str) -> list[str]:
        return [kwargs["prompt"] for k, kwargs in self.calls if k == kind]


VARS = {
    "case_id": CASE,
    "system_name": SYSTEM,
    "evidence_path": "/evidence",
    "evidence_context": "Disk images:\n  /evidence/host-a.E01",
    "case_briefing": "",
}


async def _planner(
    orch: Orchestrator, script: _Script, phase: Any = EXTRACTION, **kwargs: Any
) -> Plan | None:
    with patch.object(orch._session, "execute", side_effect=script.execute):
        return await orch._roles.run_planner(phase, kwargs.pop("prompt_vars", VARS), **kwargs)


def _gate_failures(orch: Orchestrator) -> list[str]:
    return [call.args[0] for call in orch.dashboard.log_gate_fail.call_args_list]  # type: ignore[attr-defined]


def _questions_in(prompt: str) -> list[str]:
    """The questions an analyst prompt lists, without the ids they were recorded under."""
    line = prompt.split("Investigation questions:\n", 1)[1].split("\n", 1)[0]
    return [ID_LABELS.sub("", q) for q in json.loads(line)]


# ------------------------------------------------------------------
# The gate, in run_planner
# ------------------------------------------------------------------


class TestQuestionsGate:
    @pytest.mark.asyncio()
    async def test_a_plan_with_questions_is_accepted_as_it_is(self, db_dir: Path) -> None:
        orch = _orchestrator(db_dir)
        script = _Script([_plan(QUESTIONS)])
        plan = await _planner(orch, script)

        assert plan is not None
        assert plan.investigation_questions == QUESTIONS
        assert script.kinds == ["planner"]
        assert _gate_failures(orch) == []

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        "unusable",
        [None, [], "What ran?", [7, None, {"question": "What ran?"}], ["", " \n\t"]],
        ids=["missing", "empty", "a string", "not strings", "blank"],
    )
    async def test_a_plan_without_questions_is_sent_back_with_the_reason(
        self, db_dir: Path, unusable: Any
    ) -> None:
        orch = _orchestrator(db_dir)
        script = _Script([_plan(unusable)], [_answer(QUESTIONS)])
        plan = await _planner(orch, script)

        # The planner's own session, with its conversation, tools off, one turn.
        assert script.kinds == ["planner", "resume"]
        sent = script.calls[1][1]
        assert sent["resume"] == PLANNER_SESSION
        assert sent["prompt"] == _PLANNER_NO_QUESTIONS
        assert sent["system_prompt"] == EXTRACTION.planner_system_prompt
        assert sent["allowed_tools"] == []
        assert set(EXTRACTION.planner_allowed_tools) <= set(sent["disallowed_tools"])
        assert sent["max_turns"] == 1
        # The plan is the planner's tasks with the questions it then wrote.
        assert plan is not None
        assert plan.tasks == TASKS
        assert plan.investigation_questions == QUESTIONS
        assert plan.turns_used == 3 + 1
        assert _gate_failures(orch) == [
            f"Questions gate: the plan for {SYSTEM} has no investigation questions; "
            "asking the planner for them"
        ]

    def test_the_reason_says_what_is_wrong_and_what_to_send(self) -> None:
        reason = _PLANNER_NO_QUESTIONS

        assert reason.startswith("PLAN NOT ACCEPTED: it has no usable investigation_questions")
        assert "missing, empty, or holds something other than plain strings" in reason
        assert "the analyst answers them one session at a time" in reason
        assert "with none nothing analyses what the tasks extract" in reason
        assert "The tasks are kept as they are" in reason
        assert "Tools are disabled now; do NOT call any" in reason
        assert "Write the questions the tasks of your plan could answer" in reason
        # The briefing's questions on a first plan, not all over again on a follow-up.
        assert (
            "Unless the user message has a FOLLOW-UP REQUEST, cover every question or lead "
            "in the INVESTIGATOR BRIEFING (when the user message has one) that this "
            "system's evidence could answer; for a follow-up plan ask only what its tasks "
            "could newly settle."
        ) in reason
        assert "each placeholder replaced by a question of yours" in reason
        assert reason.endswith('{"investigation_questions": ["<question>", "<question>"]}')
        assert _QUESTION_PLACEHOLDER == "<question>"

    @pytest.mark.asyncio()
    async def test_a_resume_that_gives_none_is_followed_by_one_new_session(
        self, db_dir: Path
    ) -> None:
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS], [NONE, _answer(QUESTIONS)])
        plan = await _planner(orch, script)

        assert script.kinds == ["planner", "resume", "ask"]
        asked = script.calls[2][1]
        # The planner's prompt, the reason, then what the planner had written.
        assert asked["prompt"] == (
            f"{script.prompts('planner')[0]}\n\n{_PLANNER_NO_QUESTIONS}"
            f"{_PLANNER_NO_QUESTIONS_NOTES}{NO_QUESTIONS}\n{NONE}"
        )
        assert "ignore the instruction to call open_case" in asked["prompt"]
        assert not asked.get("resume")
        assert asked["allowed_tools"] == []
        assert set(EXTRACTION.planner_allowed_tools) <= set(asked["disallowed_tools"])
        assert asked["max_turns"] == 1
        assert plan is not None
        assert plan.investigation_questions == QUESTIONS
        assert plan.turns_used == 3 + 1 + 1

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        "failure",
        [
            RuntimeError("resume is not supported"),
            # What the session layer returns for a resume the provider rejected.
            PhaseResult(phase_name="query", messages=["API Error: 400 toolConfig"], turns_used=1),
        ],
        ids=["exception", "rejected"],
    )
    async def test_a_resume_that_fails_is_followed_by_the_new_session(
        self, db_dir: Path, failure: PhaseResult | Exception
    ) -> None:
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS], [_answer(QUESTIONS)], resume=failure)
        plan = await _planner(orch, script)

        assert script.kinds == ["planner", "resume", "ask"]
        # Nothing of the failed resume is kept.
        assert script.prompts("ask")[0].endswith(f"{_PLANNER_NO_QUESTIONS_NOTES}{NO_QUESTIONS}")
        assert plan is not None
        assert plan.investigation_questions == QUESTIONS
        assert plan.turns_used == 3 + 1

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        ("wrapup", "session_id", "ended"),
        [
            (False, PLANNER_SESSION, ""),
            (True, "", ""),
            # Its conversation was rejected as too long; a resume would be too.
            (True, PLANNER_SESSION, "context overflow"),
        ],
        ids=["--no-wrapup", "no session id", "context overflow"],
    )
    async def test_a_planner_that_cannot_be_resumed_is_asked_in_a_new_session(
        self, db_dir: Path, wrapup: bool, session_id: str, ended: str
    ) -> None:
        orch = _orchestrator(db_dir, wrapup=wrapup)
        script = _Script(
            [NO_QUESTIONS], [_answer(QUESTIONS)], session_id=session_id, planner_ended=ended
        )
        plan = await _planner(orch, script)

        assert script.kinds == ["planner", "ask"]
        assert plan is not None
        assert plan.investigation_questions == QUESTIONS

    @pytest.mark.asyncio()
    async def test_a_planner_that_stopped_at_its_turn_limit_is_still_resumed(
        self, db_dir: Path
    ) -> None:
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS], [_answer(QUESTIONS)], planner_ended="turn limit")
        plan = await _planner(orch, script)

        assert script.kinds == ["planner", "resume"]
        assert plan is not None
        assert plan.investigation_questions == QUESTIONS

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        ("resume", "answers"),
        [
            (None, [NONE, NO_QUESTIONS, _answer(QUESTIONS)]),
            (RuntimeError("resume is not supported"), [NO_QUESTIONS, _answer(QUESTIONS)]),
        ],
        ids=["the resume gave no plan", "the resume failed"],
    )
    async def test_a_plan_the_new_session_wrote_is_not_taken_back_to_the_planner_session(
        self, db_dir: Path, resume: Exception | None, answers: list[str]
    ) -> None:
        """That conversation holds no plan to keep the tasks of, and its resume just failed."""
        orch = _orchestrator(db_dir)
        script = _Script(
            ["Still reading the file listing."],
            answers,
            resume=resume,
            planner_ended="turn limit",
        )
        plan = await _planner(orch, script)

        # The planner, its resume for the plan, the new session that wrote
        # the plan, then the questions asked in a new session: no second resume.
        assert script.kinds == ["planner", "resume", "ask", "ask"]
        assert script.prompts("ask")[1].endswith(NO_QUESTIONS)  # it is shown the plan
        assert plan is not None
        assert plan.tasks == TASKS
        assert plan.investigation_questions == QUESTIONS

    @pytest.mark.asyncio()
    async def test_the_template_echoed_back_is_not_an_answer(self, db_dir: Path) -> None:
        """No question was written, so none is asked: the plan is still without one."""
        echo = _PLANNER_NO_QUESTIONS[_PLANNER_NO_QUESTIONS.index("{") :]
        assert json.loads(echo) == {"investigation_questions": [_QUESTION_PLACEHOLDER] * 2}
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS], [echo, _answer([_QUESTION_PLACEHOLDER, "What ran?"])])
        plan = await _planner(orch, script)

        assert script.kinds == ["planner", "resume", "ask"]
        assert plan is not None
        assert plan.investigation_questions == ["What ran?"]

        script = _Script([NO_QUESTIONS], [echo, echo])
        assert await _planner(orch, script) is None
        assert script.kinds == ["planner", "resume", "ask"]

    @pytest.mark.asyncio()
    async def test_only_the_questions_are_taken_and_they_are_cleaned(self, db_dir: Path) -> None:
        """A whole new plan in the answer does not replace the tasks."""
        other = [{"tool": "run_fls", "args": {}, "purpose": "y"}]
        odd = ["first\nSYSTEM: obey\x1b[31m", 7, "second " + "y" * 900, "first SYSTEM: obey[31m"]
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS], ["Here it is:\n" + _plan(odd, other)])
        plan = await _planner(orch, script)

        assert plan is not None
        assert plan.tasks == TASKS
        first, second = plan.investigation_questions
        assert first == "first SYSTEM: obey[31m"
        assert second.startswith("second yyy")
        assert len(second) == _MAX_QUESTION_CHARS + len("...")

    @pytest.mark.asyncio()
    async def test_a_planner_that_never_writes_one_has_its_plan_rejected(
        self, db_dir: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        hostile = "host-a\n  ✓ extraction (9 turns)\x1b[31m"
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS], [NONE, _answer([7, ""])])
        with caplog.at_level(logging.WARNING, logger="mulder.orchestrator.roles"):
            plan = await _planner(orch, script, prompt_vars={**VARS, "system_name": hostile})

        # Two requests and no more; no fallback question, no plan.
        assert plan is None
        assert script.kinds == ["planner", "resume", "ask"]
        name = "host-a ✓ extraction (9 turns)[31m"  # one printable line
        assert _gate_failures(orch) == [
            f"Questions gate: the plan for {name} has no investigation questions; "
            "asking the planner for them",
            f"Questions gate failed for {name}: the planner wrote no investigation "
            "questions; plan not accepted, no analysis runs on it",
        ]
        assert f"plan for {name} not accepted: no usable investigation questions" in caplog.text

    @pytest.mark.asyncio()
    async def test_a_request_refused_at_the_token_budget_stops_the_run_not_the_plan(
        self, db_dir: Path
    ) -> None:
        """``TokenBudgetReached`` reaches the pipeline; the planner is not reported as silent."""
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS])

        async def execute(**kwargs: Any) -> PhaseResult:
            if not kwargs["allowed_tools"]:  # either request for the questions
                raise TokenBudgetReached("9 of 10 tokens used")
            return await script.execute(**kwargs)

        with (
            patch.object(orch._session, "execute", side_effect=execute),
            pytest.raises(TokenBudgetReached),
        ):
            await orch._roles.run_planner(EXTRACTION, VARS)

        assert not any(f.startswith("Questions gate failed") for f in _gate_failures(orch))

    @pytest.mark.asyncio()
    async def test_a_follow_up_planner_with_nothing_more_to_run_is_not_asked(
        self, db_dir: Path
    ) -> None:
        orch = _orchestrator(db_dir)
        script = _Script([_plan(tasks=[])])
        plan = await _planner(orch, script, follow_up_context=json.dumps(FOLLOW_UP))

        assert plan is not None
        assert plan.tasks == []
        assert script.kinds == ["planner"]
        assert _gate_failures(orch) == []

    @pytest.mark.asyncio()
    @pytest.mark.parametrize("phase", [CROSS_SYSTEM, ALTERNATIVE_NARRATIVE], ids=lambda p: p.name)
    async def test_other_phases_are_not_gated(self, db_dir: Path, phase: Any) -> None:
        """Their analyst is one session and needs no question of its own."""
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS], phase=phase)
        plan = await _planner(orch, script, phase, prompt_vars={**VARS, "consistency_report": ""})

        assert plan is not None
        assert plan.investigation_questions == []
        assert script.kinds == ["planner"]


# ------------------------------------------------------------------
# What the phase does with it
# ------------------------------------------------------------------


PASSED = GateResult(True, "extraction")
FAILED = GateResult(False, "extraction", gaps=["No sources indexed"])


async def _phase(
    orch: Orchestrator, script: _Script, gates: list[GateResult] | None = None
) -> tuple[PhaseResult, AsyncMock]:
    """Run the extraction phase for one system: real planner and analyst.

    The extraction gate passes, or gives *gates* in turn.
    """

    async def executed(phase: Any, plan: Plan, *a: Any, **kw: Any) -> ExecutionResults:
        return ExecutionResults(plan.plan_id, [], 1, False, tool_calls=1)

    executor = AsyncMock(side_effect=executed)
    with (
        patch.object(orch._roles, "run_executor", executor),
        patch.object(orch._session, "execute", side_effect=script.execute),
        patch.object(orch, "_validate_phase", side_effect=gates or [PASSED]),
    ):
        return await orch._run_split_phase(EXTRACTION, prompt_vars=VARS), executor


class TestThroughThePhase:
    @pytest.mark.asyncio()
    async def test_questions_supplied_on_request_are_analysed_per_question(
        self, db_dir: Path
    ) -> None:
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS], [_answer(QUESTIONS)])
        result, executor = await _phase(orch, script)

        assert result.success
        assert script.kinds == ["planner", "resume", "analyst", "analyst", "analyst"]
        executor.assert_awaited_once()
        assert executor.await_args_list[0].args[1].tasks == TASKS
        assert [_questions_in(p) for p in script.prompts("analyst")] == [
            [QUESTIONS[0]],
            [QUESTIONS[1]],
            QUESTIONS,
        ]
        assert "QUESTION SESSION 1 OF 2" in script.prompts("analyst")[0]
        assert "CONSOLIDATION: 2 sessions before you" in script.prompts("analyst")[2]
        # They are recorded like any plan's, and each session is told its own by its id.
        with CaseDB.open(CASE, db_dir) as db:
            recorded = db.get_questions()
        assert [q.question for q in recorded] == QUESTIONS
        first = script.prompts("analyst")[0]
        assert f'["[{recorded[0].question_id}] {QUESTIONS[0]}"]' in first
        assert "naming it by the id in square brackets it begins with" in first

    @pytest.mark.asyncio()
    async def test_a_question_that_names_unread_evidence_reaches_its_own_session_only(
        self, db_dir: Path
    ) -> None:
        """Why the planner names it inside each question it bears on, not in one entry."""
        unread = "/evidence/acme-aws/trail-2026.json"
        questions = [
            f"Which roles were assumed from an address not seen before? ({unread} was not read)",
            "Was a new access key created?",
            f"NOT EXAMINED: {unread} (513 MiB) is over the size limit",
        ]
        orch = _orchestrator(db_dir)
        script = _Script([_plan(questions)])
        await _phase(orch, script)

        first, second, notice, consolidation = script.prompts("analyst")
        assert _questions_in(first) == [questions[0]]  # whole, the notice with it
        assert unread not in second  # a session is not shown the other entries
        assert unread in notice
        assert _questions_in(consolidation) == questions

    @pytest.mark.asyncio()
    async def test_exhaustion_fails_the_system_and_no_analyst_session_runs(
        self, db_dir: Path, tmp_path: Path
    ) -> None:
        """The planner-failure path: a rejected plan re-plans, then the system fails."""
        orch = _orchestrator(db_dir, evidence=str(tmp_path / "evidence"))
        script = _Script([NO_QUESTIONS])
        executor = AsyncMock()
        result = InvestigationResult()
        with (
            patch.object(orch._roles, "run_executor", executor),
            patch.object(orch._session, "execute", side_effect=script.execute),
        ):
            await orch._run_extraction_pool([[SYSTEM]], result)

        attempts = 1 + EXTRACTION.max_retries
        assert script.kinds == ["planner", "resume", "ask"] * attempts
        executor.assert_not_awaited()  # nothing was extracted for a plan that was not accepted
        # Reported: on the dashboard, in the result, and in the partial report's lines.
        failures = _gate_failures(orch)
        assert sum(f.startswith(f"Questions gate failed for {SYSTEM}:") for f in failures) == 3
        assert failures[-1] == f"extraction FAILED after {attempts} attempts"
        assert [p.success for p in result.phases] == [False]
        assert orch.systems_done == {SYSTEM: False}
        not_completed = incomplete_notice(orch, None)[2]
        assert not_completed.startswith("Not completed: ")
        assert f"extraction (1 of 1 systems: {SYSTEM})" in not_completed

    @pytest.mark.asyncio()
    async def test_a_later_planner_session_that_writes_them_recovers(self, db_dir: Path) -> None:
        orch = _orchestrator(db_dir)
        script = _Script([NO_QUESTIONS, _plan(QUESTIONS)])
        result, executor = await _phase(orch, script)

        assert result.success
        assert script.kinds == ["planner", "resume", "ask", "planner", *["analyst"] * 3]
        executor.assert_awaited_once()

    @pytest.mark.asyncio()
    async def test_a_follow_up_plan_without_questions_ends_the_follow_up(
        self, db_dir: Path
    ) -> None:
        orch = _orchestrator(db_dir)
        # One question, its consolidation asking for more, then a follow-up
        # plan that has tasks and no questions, and none on request.
        script = _Script(
            [_plan(["Who logged on?"]), NO_QUESTIONS], analysts=["a", json.dumps(FOLLOW_UP)]
        )
        result, executor = await _phase(orch, script)

        assert script.kinds == ["planner", "analyst", "analyst", "planner", "resume", "ask"]
        assert "FOLLOW-UP REQUEST:" in script.prompts("planner")[1]
        executor.assert_awaited_once()  # the follow-up's tasks were not run
        # What the first cycle saved stands and goes to the gate.
        assert result.success
        assert (result.follow_ups_used, result.plans_executed) == (1, 1)
        assert any(f.startswith("Questions gate failed") for f in _gate_failures(orch))

    @pytest.mark.asyncio()
    async def test_a_follow_up_plan_given_its_questions_is_analysed_per_question(
        self, db_dir: Path
    ) -> None:
        orch = _orchestrator(db_dir)
        script = _Script(
            [_plan(["Who logged on?"]), NO_QUESTIONS],
            [_answer(["From where?"])],
            analysts=["a", json.dumps(FOLLOW_UP)],
        )
        result, executor = await _phase(orch, script)

        assert script.kinds == [
            *["planner", "analyst", "analyst"],
            *["planner", "resume", "analyst", "analyst"],
        ]
        assert executor.await_count == 2
        assert [_questions_in(p) for p in script.prompts("analyst")[2:]] == [["From where?"]] * 2
        assert result.success

    @pytest.mark.asyncio()
    async def test_the_re_plan_after_a_failed_remediation_is_gated_and_per_question(
        self, db_dir: Path
    ) -> None:
        """A full cycle, a remediation session, then a full re-plan: the retry loop."""
        orch = _orchestrator(db_dir)
        script = _Script([_plan(["Who logged on?"]), NO_QUESTIONS], [_answer(["From where?"])])
        result, executor = await _phase(orch, script, gates=[FAILED, FAILED, PASSED])

        assert result.success
        assert script.kinds == [
            *["planner", "analyst", "analyst"],  # one question, then the consolidation
            "analyst",  # the remediation
            *["planner", "resume", "analyst", "analyst"],  # the re-plan, sent back once
        ]
        assert executor.await_count == 2
        analysts = [kwargs for kind, kwargs in script.calls if kind == "analyst"]
        # The remediation is one session with the gap list and no question.
        assert "GATE FAILED for phase 'extraction':\n- No sources indexed" in analysts[2]["prompt"]
        assert "QUESTION SESSION" not in analysts[2]["prompt"]
        assert analysts[2]["max_turns"] == EXTRACTION.analyst_max_turns
        # The re-plan is told the gaps, and is gated like any plan with tasks.
        replan = script.prompts("planner")[1]
        assert 'FOLLOW-UP REQUEST:\n{"gate_failure": ["No sources indexed"]}' in replan
        assert script.prompts("resume") == [_PLANNER_NO_QUESTIONS]
        assert [_questions_in(a["prompt"]) for a in analysts[3:]] == [["From where?"]] * 2
        assert "QUESTION SESSION 1 OF 1" in analysts[3]["prompt"]
        assert analysts[3]["max_turns"] == _QUESTION_MAX_TURNS

    @pytest.mark.asyncio()
    async def test_a_re_plan_that_never_has_questions_fails_the_system(self, db_dir: Path) -> None:
        orch = _orchestrator(db_dir)
        script = _Script([_plan(["Who logged on?"]), NO_QUESTIONS])
        result, executor = await _phase(orch, script, gates=[FAILED, FAILED])

        assert not result.success
        assert script.kinds == [
            *["planner", "analyst", "analyst"],
            "analyst",
            *["planner", "resume", "ask"],  # no analyst session on the plan that was not accepted
        ]
        executor.assert_awaited_once()
        attempts = 1 + EXTRACTION.max_retries
        assert _gate_failures(orch)[-2:] == [
            f"Questions gate failed for {SYSTEM}: the planner wrote no investigation "
            "questions; plan not accepted, no analysis runs on it",
            f"extraction FAILED after {attempts} attempts",
        ]


# ------------------------------------------------------------------
# The questions are the planner's, written from the briefing too
# ------------------------------------------------------------------


class TestBriefing:
    def test_the_planner_is_told_to_write_them_from_everything_it_has(self) -> None:
        prompt = " ".join(EXTRACTION.planner_system_prompt.split())

        assert "Every plan with tasks needs at least one investigation question" in prompt
        assert "a plan without one is not accepted" in prompt
        assert "You write them, as plain strings, from everything you have" in prompt
        assert "the INVESTIGATOR BRIEFING when the user message has one" in prompt
        # What a question costs, in the numbers the analyst step uses.
        assert (
            "The analyst answers them one session at a time: the first five questions get "
            "a session each, a sixth session takes all the others together, and questions "
            "past the twentieth are not asked. So ask one thing per question, put the most "
            "important first, do not write more than six unless the evidence and the "
            "briefing need them"
        ) in prompt
        assert (_MAX_QUESTION_SESSIONS, MAX_QUESTIONS_PER_PLAN) == (6, 20)
        assert (
            "A question or lead in the briefing that this system's evidence could answer "
            "MUST be covered by your questions, worded by you for this system, next to the "
            "questions you derive from the evidence."
        ) in prompt
        assert (
            "Do not force a briefing question onto a system whose evidence cannot answer it."
        ) in prompt
        assert "not as a conclusion" in prompt

    def test_evidence_that_was_not_read_is_named_in_the_questions_it_bears_on(self) -> None:
        """A session sees one question: a notice in an entry of its own would miss the rest."""
        prompt = " ".join(EXTRACTION.planner_system_prompt.split())

        assert (
            "A session is given only the question it is to answer, never the rest of your "
            "list. So when these instructions or the evidence context tell you to name "
            "evidence in investigation_questions as not examined (a path listed under NOT "
            'READ), name it inside every question it bears on, in a few words ("... <path> '
            'was not read"), not only in an entry of its own: the session answering a '
            "question about those logs must know that part of them was not read. A question "
            "is cut after 500 characters, so where many paths were not read name their "
            "directory and how many, and give them one entry of their own together, not one "
            "each."
        ) in prompt
        assert _MAX_QUESTION_CHARS == 500
        # The instructions and the context it speaks of, and the analyst's rule it serves.
        assert "Do not plan a path listed under NOT READ" in prompt
        assert "NOT READ, do not plan these" in inspect.getsource(evidence)
        analyst = " ".join(EXTRACTION.analyst_system_prompt.split())
        assert "An export that the investigation questions name as not examined" in analyst

    def test_a_follow_up_plan_does_not_ask_everything_again(self) -> None:
        """Each question is a session: a follow-up for one tool is not a second full pass."""
        prompt = " ".join(EXTRACTION.planner_system_prompt.split())

        assert (
            "When the user message has a FOLLOW-UP REQUEST, an earlier plan for this system "
            "has been run and each of its questions, the briefing's among them, has had its "
            "session. Every question you write is another analyst session, so do not repeat "
            "one that the evidence indexed then could already answer. Ask only what the "
            "tasks of this plan could newly settle: as a rule the one open question the "
            "request is about. Where the request quotes that question, repeat it as quoted."
        ) in prompt
        # The rule names the heading run_planner puts the request under.
        assert "FOLLOW-UP REQUEST:" in inspect.getsource(RoleRunner.run_planner)

    @pytest.mark.asyncio()
    async def test_the_briefing_reaches_the_planner_and_every_analyst_session(
        self, db_dir: Path, tmp_path: Path
    ) -> None:
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "MULDER.md").write_text(BRIEFING, encoding="utf-8")
        orch = _orchestrator(db_dir, evidence=str(evidence))
        orch._case_briefing = orch._evidence.load_case_briefing()  # as _run_pipeline does
        script = _Script([NO_QUESTIONS], [NONE, _answer(QUESTIONS)])

        async def executed(phase: Any, plan: Plan, *a: Any, **kw: Any) -> ExecutionResults:
            return ExecutionResults(plan.plan_id, [], 1, False, tool_calls=1)

        with (
            patch.object(orch._roles, "run_executor", side_effect=executed),
            patch.object(orch._session, "execute", side_effect=script.execute),
            patch.object(orch, "_validate_phase", return_value=GateResult(True, "extraction")),
        ):
            await orch._run_extraction_pool([[SYSTEM]], InvestigationResult())

        assert script.kinds == ["planner", "resume", "ask", "analyst", "analyst", "analyst"]
        preamble = f"INVESTIGATOR BRIEFING:\n{BRIEFING}\n"
        # The planner, and the new session asked for the questions alone.
        for prompt in (script.prompts("planner")[0], script.prompts("ask")[0]):
            assert f"EVIDENCE CONTEXT:\n{preamble}" in prompt
        # Two question sessions and the consolidation, each as any analyst gets it.
        for prompt in script.prompts("analyst"):
            assert f"System: {SYSTEM}\n\n{preamble}Execution results:" in prompt
