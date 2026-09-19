"""An analyst that says it is done does not start a follow-up cycle, and a
follow-up planner with nothing more to run ends the cycle as success rather
than failing the phase (issue #214)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mulder.orchestrator.gates import GateResult
from mulder.orchestrator.phases import CROSS_SYSTEM
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import (
    ExecutionResults,
    PhaseResult,
    Plan,
    extract_follow_up_request,
    extract_json_plan,
)

PLAN = json.dumps(
    {"tasks": [{"tool": "correlate_across_sources", "args": {}, "purpose": "find shared IOCs"}]}
)
EMPTY_PLAN = json.dumps(
    {
        "tasks": [],
        "investigation_questions": ["What additional narrative or audit documentation is needed?"],
        "expected_sources": [],
    }
)
DONE = json.dumps(
    {
        "request": "additional_plan",
        "reason": "The investigation is complete with 2 findings submitted and timestamps added.",
        "suggested_tools": [],
    }
)
MORE = json.dumps(
    {
        "request": "additional_plan",
        "reason": "Q4 needs snapshot.db extracted from inode 75039.",
        "suggested_tools": ["extract_file_by_inode"],
    }
)
VARS = {"case_id": "case", "case_briefing": ""}


def _make_orchestrator(tmp_path: Path) -> Orchestrator:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        return Orchestrator(evidence_path="/evidence", case_id="case", db_dir=str(tmp_path))


async def _executor(phase: Any, plan: Plan, *a: Any, **kw: Any) -> ExecutionResults:
    return ExecutionResults(plan.plan_id, [], 1, False, tool_calls=1)


async def _gate_passes(phase: Any, result: PhaseResult) -> GateResult:
    return GateResult(True, phase.name)


async def _run_split(orch: Orchestrator, messages: list[str]) -> tuple[PhaseResult, AsyncMock]:
    """Run the split phase with the real planner and analyst over scripted messages."""
    responses = [PhaseResult(phase_name="query", messages=[m], turns_used=1) for m in messages]
    execute = AsyncMock(side_effect=responses)
    with (
        patch.object(orch._roles, "run_executor", side_effect=_executor),
        patch.object(orch._session, "execute", new=execute),
        patch.object(orch, "_validate_phase", side_effect=_gate_passes),
    ):
        result = await orch._run_split_phase(CROSS_SYSTEM, VARS)
    return result, execute


@pytest.mark.parametrize(
    "message",
    [
        DONE,
        json.dumps({"request": "additional_plan", "reason": "Analysis is complete."}),
        json.dumps({"request": "additional_plan", "reason": "done", "suggested_tools": "none"}),
    ],
)
def test_completion_message_is_not_a_follow_up(message: str) -> None:
    assert extract_follow_up_request(["Findings submitted.", message]) is None


def test_request_naming_tools_is_a_follow_up() -> None:
    result = extract_follow_up_request(["Findings submitted.", MORE])
    assert result is not None
    assert result["suggested_tools"] == ["extract_file_by_inode"]


def test_empty_plan_accepted_only_when_allowed() -> None:
    assert extract_json_plan([EMPTY_PLAN]) is None
    accepted = extract_json_plan([EMPTY_PLAN], allow_empty=True)
    assert accepted is not None
    assert accepted["tasks"] == []


@pytest.mark.asyncio
async def test_analyst_completion_does_not_start_follow_up(tmp_path: Path) -> None:
    result, execute = await _run_split(_make_orchestrator(tmp_path), [PLAN, DONE])
    assert result.success
    assert result.follow_ups_used == 0
    assert execute.await_count == 2  # planner, analyst; no second planner


@pytest.mark.asyncio
async def test_follow_up_empty_plan_ends_cycle_with_success(tmp_path: Path) -> None:
    result, execute = await _run_split(_make_orchestrator(tmp_path), [PLAN, MORE, EMPTY_PLAN])
    assert result.success
    assert result.follow_ups_used == 1
    assert result.plans_executed == 1
    assert execute.await_count == 3  # planner, analyst, follow-up planner; no JSON repair
    assert "FOLLOW-UP REQUEST" in execute.call_args.kwargs["prompt"]


@pytest.mark.asyncio
async def test_follow_up_planner_with_no_plan_keeps_completed_work(tmp_path: Path) -> None:
    garbage = "I could not decide what to run next."
    result, execute = await _run_split(_make_orchestrator(tmp_path), [PLAN, MORE, garbage])
    assert result.success
    assert result.follow_ups_used == 1
    assert execute.await_count == 3


@pytest.mark.asyncio
async def test_empty_first_plan_still_fails(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    execute = AsyncMock(return_value=PhaseResult(phase_name="query", messages=[EMPTY_PLAN]))
    with patch.object(orch._session, "execute", new=execute):
        plan = await orch._roles.run_planner(CROSS_SYSTEM, VARS)
    assert plan is None
    assert execute.await_count == 2  # planner, then the repair attempt, as before
