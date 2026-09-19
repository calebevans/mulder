"""Planner prompts list exactly the tools the phase's executor may run (rendered
from the allowlist), hand-written prose never names an off-role tool, and a
plan that names one anyway is trimmed and logged (issue #175)."""

from __future__ import annotations

import logging
import re
from unittest.mock import AsyncMock, patch

import pytest

from mulder.orchestrator.phases import ALTERNATIVE_NARRATIVE, CROSS_SYSTEM, EXTRACTION, PhaseConfig
from mulder.orchestrator.roles import _EXECUTOR_CONTROL_TOOLS, executor_tools_section
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import PhaseResult, Plan
from mulder.server.tool_access import ALL_ROLES, get_tools_for_role

SPLIT_PHASES = [EXTRACTION, CROSS_SYSTEM, ALTERNATIVE_NARRATIVE]

REGISTERED = frozenset(t.removeprefix("mcp__mulder__") for t in get_tools_for_role(ALL_ROLES))

#: Tools the planner prompts tell the planner to call (or not call) itself
#: while reading the case, as opposed to tools it puts in the plan.
PLANNER_OWN_TOOLS = frozenset(
    {
        "open_case",
        "list_directory",
        "get_tool_guide",
        "get_findings",
        "get_investigation_summary",
        "list_sources",
        "get_source_stats",
        "get_timeline",
        "get_bookmarks",
    }
)


PLANNER_VARS = {
    "case_id": "case",
    "system_name": "host",
    "evidence_path": "/evidence",
    "evidence_context": "",
    "case_briefing": "",
    "consistency_report": "",
}

PLAN = '{"tasks": [{"tool": "search", "args": {"query": "x"}, "purpose": "p"}]}'


def _advertised(phase: PhaseConfig) -> set[str]:
    mentioned = set(re.findall(r"\b[a-z][a-z0-9_]*\b", phase.planner_system_prompt)) & REGISTERED
    return mentioned - PLANNER_OWN_TOOLS


@pytest.mark.parametrize("phase", SPLIT_PHASES, ids=lambda p: p.name)
def test_planner_prompt_only_advertises_executor_tools(phase: PhaseConfig) -> None:
    executor = {t.removeprefix("mcp__mulder__") for t in phase.executor_allowed_tools}
    advertised = _advertised(phase)
    assert advertised, f"{phase.name}: prompt names no plannable tools; extractor broke?"
    assert advertised <= executor, (
        f"{phase.name} planner prompt advertises tools its executor cannot run: "
        f"{sorted(advertised - executor)}"
    )


@pytest.mark.parametrize("phase", SPLIT_PHASES, ids=lambda p: p.name)
def test_rendered_section_is_executor_allowlist_minus_control_tools(phase: PhaseConfig) -> None:
    section = executor_tools_section(phase)
    header, _, listing = section.partition(":\n")
    assert header.endswith("dropped from the plan") and phase.name in header
    rendered = listing.split(", ")
    expected = sorted(
        t.removeprefix("mcp__mulder__")
        for t in phase.executor_allowed_tools
        if t not in _EXECUTOR_CONTROL_TOOLS
    )
    assert rendered == expected
    assert "mcp__mulder__" not in listing
    assert not {"open_case", "start_extraction_batch", "wait_all"} & set(rendered)


@pytest.mark.asyncio()
@pytest.mark.parametrize("phase", SPLIT_PHASES, ids=lambda p: p.name)
async def test_planner_prompt_renders_allowlist_without_prompt_edit(
    phase: PhaseConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        phase,
        "executor_allowed_tools",
        [*phase.executor_allowed_tools, "mcp__mulder__brand_new_tool"],
    )
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence")
    execute = AsyncMock(return_value=PhaseResult(phase_name="x", messages=[PLAN]))
    with patch.object(orch._session, "execute", new=execute):
        assert await orch._roles.run_planner(phase, PLANNER_VARS) is not None
    prompt = execute.call_args.kwargs["prompt"]
    assert executor_tools_section(phase) in prompt
    assert "brand_new_tool" in prompt
    assert "brand_new_tool" not in phase.planner_system_prompt
    assert prompt.index("EXECUTOR TOOLS:") < prompt.index("TURN BUDGET:")


@pytest.mark.asyncio()
async def test_run_executor_drops_off_role_tasks_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence")
    orch._case_id = "case"
    plan = Plan(
        plan_id="p",
        tasks=[
            {"tool": "search", "args": {"query": "x"}, "purpose": "ok"},
            {"tool": "check_finalize_readiness", "args": {}, "purpose": "analyst-only"},
            {"tool": "run_mmls", "args": {}, "purpose": "extraction-only"},
        ],
        investigation_questions=[],
        expected_sources=[],
        raw_text="plan",
        turns_used=1,
    )
    seen: dict[str, object] = {}

    async def mock_execute(**kwargs: object) -> PhaseResult:
        seen.update(kwargs)
        return PhaseResult(phase_name="x", success=True, messages=[], turns_used=1)

    with (
        patch.object(orch._session, "execute", side_effect=mock_execute),
        caplog.at_level(logging.WARNING, logger="mulder.orchestrator.roles"),
    ):
        await orch._roles.run_executor(ALTERNATIVE_NARRATIVE, plan)

    prompt = str(seen["prompt"])
    assert '"search"' in prompt
    assert "check_finalize_readiness" not in prompt
    assert "run_mmls" not in prompt
    allowed = seen["allowed_tools"]
    assert isinstance(allowed, list)
    assert "mcp__mulder__search" in allowed
    assert "mcp__mulder__check_finalize_readiness" not in allowed
    assert any(
        "check_finalize_readiness, run_mmls" in r.getMessage()
        and "alternative_narrative" in r.getMessage()
        for r in caplog.records
    ), caplog.text
