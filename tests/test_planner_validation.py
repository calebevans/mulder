"""Malformed planner tasks are repaired or rejected before execution."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from claude_agent_sdk.types import AssistantMessage, TextBlock

from mulder.orchestrator.phases import CROSS_SYSTEM
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import PhaseResult, extract_json_plan

BAD = json.dumps(
    {
        "tasks": [
            "Open the case using open_case(case_id='case')",
            "Review findings and sources",
            "Plan cross-system correlation",
        ]
    }
)
GOOD = json.dumps(
    {"tasks": [{"tool": "correlate_across_sources", "args": {}, "purpose": "find shared IOCs"}]}
)
VARS = {"case_id": "case", "case_briefing": ""}


def _make_orchestrator(tmp_path: Path) -> Orchestrator:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        return Orchestrator(evidence_path="/evidence", case_id="case", db_dir=str(tmp_path))


@pytest.mark.parametrize("tasks", [["text"], [{"tool": "search"}, "text"], [None], [1], []])
def test_rejects_invalid_tasks(tasks: list[object]) -> None:
    assert extract_json_plan([json.dumps({"tasks": tasks})]) is None


@pytest.mark.asyncio
async def test_invalid_plan_runs_utility_repair_and_accepts_corrected_plan(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    responses = [
        PhaseResult(phase_name="query", messages=[BAD]),
        PhaseResult(phase_name="query", messages=[GOOD]),
    ]
    with patch.object(orch._session, "execute", new=AsyncMock(side_effect=responses)) as execute:
        plan = await orch._roles.run_planner(CROSS_SYSTEM, VARS)
    assert execute.await_count == 2
    assert plan is not None
    assert plan.tasks[0]["tool"] == "correlate_across_sources"
    assert execute.call_args.kwargs["allowed_tools"] == []


@pytest.mark.asyncio
async def test_invalid_repair_skips_executor_and_runs_analyst(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    with patch.object(
        orch._session,
        "execute",
        new=AsyncMock(return_value=PhaseResult(phase_name="query", messages=[BAD])),
    ) as execute:
        result = await orch._run_split_phase(CROSS_SYSTEM, VARS)
    # planner, repair, then the analyst on existing results (#217); no executor
    assert execute.await_count == 3
    assert execute.call_args.kwargs["allowed_tools"] == CROSS_SYSTEM.analyst_allowed_tools
    assert result.plans_executed == 0


def test_display_retains_malformed_message_without_raising(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    messages: list[str] = []
    message = AssistantMessage(content=[TextBlock(text=BAD)], model="test-model")
    orch._session._process_assistant_message(message, "", set(), messages)
    assert messages == [BAD]


NOTES = "Now let me search for specific evidence to identify potential counter-evidence."


@pytest.mark.asyncio
async def test_planner_prompt_states_tool_call_budget(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    with patch.object(
        orch._session,
        "execute",
        new=AsyncMock(return_value=PhaseResult(phase_name="query", messages=[GOOD])),
    ) as execute:
        await orch._roles.run_planner(CROSS_SYSTEM, VARS)
    prompt = execute.call_args.kwargs["prompt"]
    assert f"at most {CROSS_SYSTEM.planner_max_turns - 1} tool calls" in prompt
    assert execute.call_args.kwargs["max_turns"] == CROSS_SYSTEM.planner_max_turns


@pytest.mark.asyncio
async def test_turn_limit_without_plan_requests_plan_from_notes(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    responses = [
        PhaseResult(phase_name="query", messages=[NOTES], turns_used=11, context_exhausted=True),
        PhaseResult(phase_name="query", messages=[GOOD], turns_used=1),
    ]
    with patch.object(orch._session, "execute", new=AsyncMock(side_effect=responses)) as execute:
        plan = await orch._roles.run_planner(CROSS_SYSTEM, VARS)
    assert execute.await_count == 2
    assert plan is not None
    assert plan.tasks[0]["tool"] == "correlate_across_sources"
    assert plan.turns_used == 12
    follow_up = execute.call_args.kwargs
    assert follow_up["max_turns"] == 1
    assert follow_up["allowed_tools"] == []
    assert set(CROSS_SYSTEM.planner_allowed_tools) <= set(follow_up["disallowed_tools"])
    assert "OUT OF TURNS" in follow_up["prompt"]
    assert NOTES in follow_up["prompt"]
    assert "Case ID: case" in follow_up["prompt"]


@pytest.mark.asyncio
async def test_turn_limit_recovery_falls_back_to_repair(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    responses = [
        PhaseResult(phase_name="query", messages=[NOTES], context_exhausted=True),
        PhaseResult(phase_name="query", messages=[BAD]),
        PhaseResult(phase_name="query", messages=[GOOD]),
    ]
    with patch.object(orch._session, "execute", new=AsyncMock(side_effect=responses)) as execute:
        plan = await orch._roles.run_planner(CROSS_SYSTEM, VARS)
    assert execute.await_count == 3
    assert plan is not None
    assert plan.tasks[0]["tool"] == "correlate_across_sources"
