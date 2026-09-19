"""A split phase whose planner produces no plan still runs the analyst on the
existing results and goes to the gate, and the report role can satisfy the
``audit_tools_called`` gate on its own (issue #217)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mulder.orchestrator.gates import GateResult
from mulder.orchestrator.phases import ALTERNATIVE_NARRATIVE, CROSS_SYSTEM, EXTRACTION
from mulder.orchestrator.prompts import REPORT_PROMPT
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import PhaseResult
from mulder.server.tool_access import Role, get_tools_for_role

AUDIT_TOOLS = {"mcp__mulder__audit_evidence_coverage", "mcp__mulder__audit_tool_coverage"}


class _Harness:
    """Planner always fails; analyst reaches the (mocked) session."""

    def __init__(self, gate_outcomes: list[bool]) -> None:
        with patch("mulder.orchestrator.runner.InvestigationDashboard"):
            self.orch = Orchestrator("/evidence", case_id="test-case")
        self.gate_outcomes = iter(gate_outcomes)
        self.executor = AsyncMock()
        self.session_prompts: list[str] = []

    async def session_execute(self, **kwargs: Any) -> PhaseResult:
        self.session_prompts.append(kwargs["prompt"])
        return PhaseResult(phase_name="query", messages=["done"], turns_used=1)

    async def validate(self, phase: Any, result: PhaseResult) -> GateResult:
        passed = next(self.gate_outcomes)
        return GateResult(passed, phase.name, gaps=[] if passed else ["gap"])

    async def run(self, phase: Any) -> PhaseResult:
        with (
            patch.object(self.orch._roles, "run_planner", AsyncMock(return_value=None)),
            patch.object(self.orch._roles, "run_executor", self.executor),
            patch.object(self.orch._session, "execute", side_effect=self.session_execute),
            patch.object(self.orch, "_validate_phase", side_effect=self.validate),
        ):
            return await self.orch._run_split_phase(phase, prompt_vars={"case_id": "test-case"})


@pytest.mark.asyncio()
@pytest.mark.parametrize("phase", [ALTERNATIVE_NARRATIVE, CROSS_SYSTEM], ids=lambda p: p.name)
async def test_planner_failure_runs_analyst_then_gate(phase: Any) -> None:
    h = _Harness(gate_outcomes=[True])
    result = await h.run(phase)

    assert result.success
    assert result.plans_executed == 0
    h.executor.assert_not_awaited()
    assert len(h.session_prompts) == 1  # the analyst, on empty execution results
    assert "open_case(case_id='test-case')" in h.session_prompts[0]
    assert "Execution results:\n[]" in h.session_prompts[0]


@pytest.mark.asyncio()
async def test_planner_failure_then_gate_failure_still_remediates() -> None:
    h = _Harness(gate_outcomes=[False, True])
    result = await h.run(ALTERNATIVE_NARRATIVE)

    assert result.success
    assert len(h.session_prompts) == 2  # analyst, then analyst-only remediation
    assert "GATE FAILED" in h.session_prompts[1]


@pytest.mark.asyncio()
async def test_planner_failure_fails_phase_only_after_all_attempts() -> None:
    h = _Harness(gate_outcomes=[False] * (1 + ALTERNATIVE_NARRATIVE.max_retries))
    result = await h.run(ALTERNATIVE_NARRATIVE)

    assert not result.success
    assert len(h.session_prompts) == 1 + ALTERNATIVE_NARRATIVE.max_retries


@pytest.mark.asyncio()
async def test_extraction_planner_failure_replans_instead_of_analysing() -> None:
    h = _Harness(gate_outcomes=[])
    result = await h.run(EXTRACTION)

    assert not result.success
    assert h.session_prompts == []  # no analyst on an empty system
    h.executor.assert_not_awaited()


def test_report_role_can_satisfy_audit_gate_itself() -> None:
    report_tools = set(get_tools_for_role(Role.REPORT))
    assert report_tools >= AUDIT_TOOLS
    assert {
        "mcp__mulder__check_finalize_readiness",
        "mcp__mulder__deduplicate_findings",
        "mcp__mulder__update_finding",
        "mcp__mulder__submit_narrative",
        "mcp__mulder__finalize_report",
    } <= report_tools
    assert "mcp__mulder__submit_finding" not in report_tools
    assert "audit_evidence_coverage" in REPORT_PROMPT and "audit_tool_coverage" in REPORT_PROMPT
