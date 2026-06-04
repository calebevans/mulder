"""Tests for mulder.orchestrator.runner -- orchestrator core logic."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.orchestrator.gates import (
    GateResult,
    validate_cross_system,
    validate_extraction,
    validate_narrative,
)
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import PhaseResult


def _make_orchestrator(**kwargs: object) -> Orchestrator:
    """Create an Orchestrator with a mocked dashboard."""
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        if "evidence_path" not in kwargs:
            kwargs["evidence_path"] = "/evidence"
        return Orchestrator(**kwargs)  # type: ignore[arg-type]


class TestOrchestratorInit:
    """Verify the new Orchestrator constructor API."""

    def test_default_model_config(self) -> None:
        orch = _make_orchestrator()
        assert isinstance(orch.model_config, ModelConfig)
        assert orch.model_config.planner == "claude-sonnet-4-6"

    def test_custom_model_config(self) -> None:
        mc = ModelConfig(
            planner="custom-planner", executor="custom-exec", analyst="custom-analyst"
        )
        orch = _make_orchestrator(model_config=mc)
        assert orch.model_config.planner == "custom-planner"
        assert orch.model_config.executor == "custom-exec"
        assert orch.model_config.analyst == "custom-analyst"


class TestSplitPhaseHappyPath:
    """Split-mode phase planner -> executor -> analyst pipeline."""

    @pytest.mark.asyncio()
    async def test_planner_produces_plan(self) -> None:
        orch = _make_orchestrator()
        orch._case_id = "test-case"

        plan_json = json.dumps(
            {
                "tasks": [{"tool": "search", "args": {"q": "ssh"}, "purpose": "find ssh logs"}],
                "investigation_questions": ["Were there SSH connections?"],
                "expected_sources": ["auth.log"],
            }
        )

        async def mock_execute_query(**kwargs: object) -> PhaseResult:
            return PhaseResult(
                phase_name="query",
                success=False,
                messages=[f"Here is the plan:\n{plan_json}"],
                turns_used=3,
            )

        from mulder.orchestrator.phases import EXTRACTION

        with patch.object(orch, "_execute_query", side_effect=mock_execute_query):
            plan = await orch._run_planner(
                EXTRACTION,
                prompt_vars={
                    "system_name": "host-a",
                    "evidence_path": "/evidence",
                    "evidence_context": "System: host-a\n(No pre-populated paths available.)",
                },
            )

        assert plan is not None
        assert len(plan.tasks) == 1
        assert plan.tasks[0]["tool"] == "search"
        assert plan.turns_used == 3

    @pytest.mark.asyncio()
    async def test_planner_invalid_json_returns_none(self) -> None:
        orch = _make_orchestrator()
        orch._case_id = "test-case"

        async def mock_execute_query(**kwargs: object) -> PhaseResult:
            return PhaseResult(
                phase_name="query",
                success=False,
                messages=["I'm not sure what to do here."],
                turns_used=2,
            )

        from mulder.orchestrator.phases import EXTRACTION

        with patch.object(orch, "_execute_query", side_effect=mock_execute_query):
            plan = await orch._run_planner(
                EXTRACTION,
                prompt_vars={
                    "system_name": "host-a",
                    "evidence_path": "/evidence",
                    "evidence_context": "System: host-a\n(No pre-populated paths available.)",
                },
            )

        assert plan is None


class TestFollowUpCapping:
    """Analyst follow-up requests are capped at max_follow_ups."""

    @pytest.mark.asyncio()
    async def test_max_follow_ups_cap(self) -> None:
        orch = _make_orchestrator()
        orch._case_id = "test-case"

        from mulder.orchestrator.phases import CROSS_SYSTEM
        from mulder.orchestrator.types import AnalystResult, ExecutionResults, Plan

        planner_call_count = 0

        async def mock_planner(
            phase: object,
            prompt_vars: object = None,
            follow_up_context: str = "",
            log_prefix: str = "",
        ) -> Plan:
            nonlocal planner_call_count
            planner_call_count += 1
            return Plan(
                plan_id=f"plan-{planner_call_count}",
                tasks=[{"tool": "search", "args": {}, "purpose": "test"}],
                investigation_questions=[],
                expected_sources=[],
                raw_text="plan",
                turns_used=1,
            )

        async def mock_executor(
            phase: object, plan: Plan, log_prefix: str = "", task_system: str = ""
        ) -> ExecutionResults:
            return ExecutionResults(
                plan_id=plan.plan_id,
                results=[],
                turns_used=1,
                has_failures=False,
            )

        call_count = 0

        async def mock_analyst(
            phase: object,
            plan: Plan,
            exec_results: ExecutionResults,
            prompt_vars: object = None,
            log_prefix: str = "",
            task_system: str = "",
        ) -> AnalystResult:
            nonlocal call_count
            call_count += 1
            # Always request follow-up
            return AnalystResult(
                findings_submitted=0,
                follow_up_request={
                    "request": "additional_plan",
                    "reason": f"Need more data (round {call_count})",
                },
                messages=["analysis"],
                turns_used=1,
            )

        with (
            patch.object(orch, "_run_planner", side_effect=mock_planner),
            patch.object(orch, "_run_executor", side_effect=mock_executor),
            patch.object(orch, "_run_analyst", side_effect=mock_analyst),
            patch.object(orch, "_validate_phase", return_value=None),
        ):
            result = await orch._run_split_phase(CROSS_SYSTEM)

        # 1 initial + max_follow_ups (2) = 3 iterations
        assert planner_call_count == 1 + CROSS_SYSTEM.max_follow_ups
        assert result.success


class TestGatherErrorHandling:
    """asyncio.gather with return_exceptions=True handles sibling failures."""

    @pytest.mark.asyncio()
    async def test_gather_handles_sibling_exception(self) -> None:
        async def mock_run_split_phase(
            phase: object,
            prompt_vars: dict[str, str] | None = None,
            skip_phase_header: bool = False,
        ) -> PhaseResult:
            system = (prompt_vars or {}).get("system_name", "")
            if "fail-system" in system:
                raise RuntimeError("Simulated extraction failure")
            return PhaseResult(
                phase_name="extraction",
                success=True,
                messages=["ok"],
                turns_used=5,
            )

        groups = [["host-a"], ["fail-system"], ["host-b"]]

        tasks = [
            mock_run_split_phase(
                None,
                prompt_vars={
                    "system_name": ", ".join(g),
                    "evidence_path": "/evidence",
                },
                skip_phase_header=True,
            )
            for g in groups
        ]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        successes = sum(1 for r in batch_results if not isinstance(r, BaseException))
        failures = sum(1 for r in batch_results if isinstance(r, BaseException))

        assert successes == 2
        assert failures == 1


class TestSinglePhaseGate:
    """Single-mode phases run gate validation after execution."""

    @pytest.mark.asyncio()
    async def test_single_phase_passes_on_gate_pass(self) -> None:
        orch = _make_orchestrator()
        orch._case_id = "test-case"

        async def mock_execute_query(**kwargs: object) -> PhaseResult:
            return PhaseResult(
                phase_name="query",
                success=False,
                messages=["evidence scanned"],
                turns_used=5,
            )

        gate = GateResult(passed=True, phase_name="catalog")

        from mulder.orchestrator.phases import CATALOG

        with (
            patch.object(orch, "_execute_query", side_effect=mock_execute_query),
            patch.object(orch, "_validate_phase", return_value=gate),
        ):
            result = await orch._run_single_phase(
                CATALOG,
                prompt_vars={"evidence_path": "/evidence"},
            )

        assert result.success

    @pytest.mark.asyncio()
    async def test_single_phase_retries_on_gate_fail(self) -> None:
        orch = _make_orchestrator()
        orch._case_id = "test-case"

        call_count = 0

        async def mock_execute_query(**kwargs: object) -> PhaseResult:
            nonlocal call_count
            call_count += 1
            return PhaseResult(
                phase_name="query",
                success=False,
                messages=["attempt"],
                turns_used=2,
            )

        fail_gate = GateResult(passed=False, phase_name="catalog", gaps=["No case created"])

        from mulder.orchestrator.phases import CATALOG

        with (
            patch.object(orch, "_execute_query", side_effect=mock_execute_query),
            patch.object(orch, "_validate_phase", return_value=fail_gate),
        ):
            result = await orch._run_single_phase(
                CATALOG,
                prompt_vars={"evidence_path": "/evidence"},
            )

        assert not result.success
        # 1 initial + max_retries (2) = 3 attempts
        assert call_count == 1 + CATALOG.max_retries


class TestNarrativeGateNonVacuous:
    """Narrative gate should fail when no checks are evaluated."""

    def test_empty_gates_fails(self) -> None:
        result = validate_narrative(
            summary={"remaining_work": []},
            readiness={"gates": []},
        )
        assert not result.passed
        check_names = [c.name for c in result.checks]
        assert "checks_performed" in check_names

    def test_none_readiness_fails(self) -> None:
        result = validate_narrative(
            summary={"remaining_work": []},
            readiness=None,
        )
        assert not result.passed

    def test_passing_gates_succeed(self) -> None:
        result = validate_narrative(
            summary={"remaining_work": []},
            readiness={
                "gates": [
                    {"name": "minimum_findings", "passed": True, "detail": "3 findings"},
                    {"name": "narrative_submitted", "passed": True, "detail": "ok"},
                ]
            },
        )
        assert result.passed


class TestUtilityQueryNoneReturn:
    """Utility queries should return None on failure."""

    @pytest.mark.asyncio()
    async def test_run_utility_query_returns_none_on_exception(self) -> None:
        orch = _make_orchestrator()

        async def failing_query(prompt: str, options: object) -> object:
            raise RuntimeError("Connection refused")
            yield  # make it an async generator  # noqa: RUF027

        with patch("mulder.orchestrator.runner.query", failing_query):
            result = await orch._run_utility_query(
                prompt="test",
                allowed_tools=["mcp__mulder__test"],
                label="test_query",
            )

        assert result is None

    @pytest.mark.asyncio()
    async def test_run_utility_query_returns_none_on_unparseable(self) -> None:
        orch = _make_orchestrator()

        mock_assistant = MagicMock()
        mock_text_block = MagicMock()
        mock_text_block.text = "I couldn't find any data."
        mock_assistant.content = [mock_text_block]
        mock_assistant.message_id = "m1"
        mock_assistant.usage = {}

        mock_result = MagicMock()
        mock_result.usage = {"input_tokens": 5, "output_tokens": 3}
        mock_result.model_usage = None

        async def mock_query(prompt: str, options: object) -> object:
            yield mock_assistant
            yield mock_result

        with (
            patch("mulder.orchestrator.runner.query", mock_query),
            patch(
                "mulder.orchestrator.runner.AssistantMessage",
                type(mock_assistant),
            ),
            patch("mulder.orchestrator.runner.ResultMessage", type(mock_result)),
            patch("mulder.orchestrator.runner.TextBlock", type(mock_text_block)),
        ):
            result = await orch._run_utility_query(
                prompt="test",
                allowed_tools=["mcp__mulder__test"],
                label="test_query",
            )

        assert result is None

    @pytest.mark.asyncio()
    async def test_run_utility_query_returns_dict_on_success(self) -> None:
        orch = _make_orchestrator()

        mock_assistant = MagicMock()
        mock_text_block = MagicMock()
        mock_text_block.text = '{"case_id": "test-123", "sources_indexed": 5}'
        mock_assistant.content = [mock_text_block]
        mock_assistant.message_id = "m1"
        mock_assistant.usage = {}

        mock_result = MagicMock()
        mock_result.usage = {"input_tokens": 5, "output_tokens": 3}
        mock_result.model_usage = None

        async def mock_query(prompt: str, options: object) -> object:
            yield mock_assistant
            yield mock_result

        with (
            patch("mulder.orchestrator.runner.query", mock_query),
            patch(
                "mulder.orchestrator.runner.AssistantMessage",
                type(mock_assistant),
            ),
            patch("mulder.orchestrator.runner.ResultMessage", type(mock_result)),
            patch("mulder.orchestrator.runner.TextBlock", type(mock_text_block)),
        ):
            result = await orch._run_utility_query(
                prompt="test",
                allowed_tools=["mcp__mulder__test"],
                label="test_query",
            )

        assert result is not None
        assert result["case_id"] == "test-123"
        assert result["sources_indexed"] == 5

    def test_extraction_gate_handles_none_summary(self) -> None:
        result = validate_extraction(None)
        assert result.passed
        assert any(c.name == "summary_unavailable" for c in result.checks)

    def test_cross_system_gate_handles_none_summary(self) -> None:
        result = validate_cross_system(None)
        assert result.passed
        assert any(c.name == "summary_unavailable" for c in result.checks)


class TestGateAfterAnalyst:
    """Gate validation runs after analyst, not after executor."""

    @pytest.mark.asyncio()
    async def test_gate_runs_after_analyst_completes(self) -> None:
        orch = _make_orchestrator()
        orch._case_id = "test-case"

        from mulder.orchestrator.phases import EXTRACTION
        from mulder.orchestrator.types import AnalystResult, ExecutionResults, Plan

        gate_calls: list[str] = []

        async def mock_planner(
            phase: object,
            prompt_vars: object = None,
            follow_up_context: str = "",
            log_prefix: str = "",
        ) -> Plan:
            return Plan(
                plan_id="plan-1",
                tasks=[{"tool": "t", "args": {}, "purpose": "p"}],
                investigation_questions=[],
                expected_sources=[],
                raw_text="plan",
                turns_used=1,
            )

        async def mock_executor(
            phase: object, plan: Plan, log_prefix: str = "", task_system: str = ""
        ) -> ExecutionResults:
            return ExecutionResults(
                plan_id=plan.plan_id, results=[], turns_used=1, has_failures=False
            )

        async def mock_analyst(
            phase: object,
            plan: Plan,
            exec_results: ExecutionResults,
            prompt_vars: object = None,
            log_prefix: str = "",
            task_system: str = "",
        ) -> AnalystResult:
            return AnalystResult(
                findings_submitted=1,
                follow_up_request=None,
                messages=["done"],
                turns_used=1,
            )

        async def mock_validate(phase: object, result: PhaseResult) -> GateResult | None:
            gate_calls.append("validated")
            return GateResult(passed=True, phase_name="extraction")

        with (
            patch.object(orch, "_run_planner", side_effect=mock_planner),
            patch.object(orch, "_run_executor", side_effect=mock_executor),
            patch.object(orch, "_run_analyst", side_effect=mock_analyst),
            patch.object(orch, "_validate_phase", side_effect=mock_validate),
        ):
            result = await orch._run_split_phase(
                EXTRACTION,
                prompt_vars={
                    "system_name": "host-a",
                    "evidence_path": "/evidence",
                    "evidence_context": "System: host-a\nDisk images:\n  /evidence/host-a.E01",
                },
            )

        assert result.success
        assert len(gate_calls) == 1


class TestRollingExtractionPool:
    """Tests for the _run_extraction_pool semaphore-based worker pool."""

    @pytest.mark.asyncio()
    async def test_semaphore_limits_concurrency(self) -> None:
        """Verify that max concurrent extractions never exceeds --workers."""
        orch = _make_orchestrator(parallel_extractions=2)
        orch._case_id = "test-case"

        from mulder.orchestrator.types import InvestigationResult

        max_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        async def mock_split_phase(
            phase: object,
            prompt_vars: dict[str, str] | None = None,
            skip_phase_header: bool = False,
        ) -> PhaseResult:
            nonlocal max_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                max_concurrent = max(max_concurrent, current_concurrent)
            await asyncio.sleep(0.01)
            async with lock:
                current_concurrent -= 1
            return PhaseResult(phase_name="extraction", success=True, turns_used=1)

        groups = [["host-a"], ["host-b"], ["host-c"], ["host-d"]]
        result = InvestigationResult()

        with patch.object(orch, "_run_split_phase", side_effect=mock_split_phase):
            await orch._run_extraction_pool(groups, result)

        assert max_concurrent <= 2
        assert len(result.phases) == 4
        assert all(p.success for p in result.phases)

    @pytest.mark.asyncio()
    async def test_pool_continues_on_failure(self) -> None:
        """One system failing does not block other systems from completing."""
        orch = _make_orchestrator(parallel_extractions=3)
        orch._case_id = "test-case"

        from mulder.orchestrator.types import InvestigationResult

        async def mock_split_phase(
            phase: object,
            prompt_vars: dict[str, str] | None = None,
            skip_phase_header: bool = False,
        ) -> PhaseResult:
            system = (prompt_vars or {}).get("system_name", "")
            if "fail-system" in system:
                raise RuntimeError("Simulated extraction failure")
            return PhaseResult(phase_name="extraction", success=True, turns_used=1)

        groups = [["host-a"], ["fail-system"], ["host-b"]]
        result = InvestigationResult()

        with patch.object(orch, "_run_split_phase", side_effect=mock_split_phase):
            await orch._run_extraction_pool(groups, result)

        successes = sum(1 for p in result.phases if p.success)
        failures = sum(1 for p in result.phases if not p.success)
        assert successes == 2
        assert failures == 1

    @pytest.mark.asyncio()
    async def test_all_systems_processed(self) -> None:
        """Every group gets processed regardless of submission order."""
        orch = _make_orchestrator(parallel_extractions=2)
        orch._case_id = "test-case"

        from mulder.orchestrator.types import InvestigationResult

        processed: list[str] = []

        async def mock_split_phase(
            phase: object,
            prompt_vars: dict[str, str] | None = None,
            skip_phase_header: bool = False,
        ) -> PhaseResult:
            system = (prompt_vars or {}).get("system_name", "unknown")
            processed.append(system)
            await asyncio.sleep(0.01)
            return PhaseResult(phase_name="extraction", success=True, turns_used=1)

        groups = [["a"], ["b"], ["c"], ["d"], ["e"]]
        result = InvestigationResult()

        with patch.object(orch, "_run_split_phase", side_effect=mock_split_phase):
            await orch._run_extraction_pool(groups, result)

        assert sorted(processed) == ["a", "b", "c", "d", "e"]
        assert len(result.phases) == 5

    @pytest.mark.asyncio()
    async def test_dashboard_counters_update(self) -> None:
        """Dashboard extraction counters reflect real progress."""
        orch = _make_orchestrator(parallel_extractions=2)
        orch._case_id = "test-case"

        from mulder.orchestrator.types import InvestigationResult

        counter_snapshots: list[tuple[int, int, int]] = []

        def capture_counts(total: int, done: int, active: int) -> None:
            counter_snapshots.append((total, done, active))

        orch.dashboard.set_extraction_counts = capture_counts  # type: ignore[method-assign]

        async def mock_split_phase(
            phase: object,
            prompt_vars: dict[str, str] | None = None,
            skip_phase_header: bool = False,
        ) -> PhaseResult:
            await asyncio.sleep(0.01)
            return PhaseResult(phase_name="extraction", success=True, turns_used=1)

        groups = [["host-a"], ["host-b"], ["host-c"]]
        result = InvestigationResult()

        with patch.object(orch, "_run_split_phase", side_effect=mock_split_phase):
            await orch._run_extraction_pool(groups, result)

        assert len(counter_snapshots) > 0
        # All calls use total=3
        assert all(t == 3 for t, _, _ in counter_snapshots)
        # Final snapshot should have done=3, active=0
        last_total, last_done, last_active = counter_snapshots[-1]
        assert last_done == 3
        assert last_active == 0


class TestBuildEvidenceContext:
    """Tests for _build_evidence_context evidence path scanner."""

    def test_finds_disk_images(self, tmp_path: Path) -> None:
        """Disk images matching the system name are listed."""
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "host-a-cdrive.E01").write_text("disk")
        (evidence / "host-a-cdrive.E02").write_text("segment")
        (evidence / "unrelated.txt").write_text("other")

        orch = _make_orchestrator(evidence_path=str(evidence))
        ctx = orch._build_evidence_context("host-a")

        assert "host-a-cdrive.E01" in ctx
        assert "Disk images:" in ctx
        assert "unrelated.txt" not in ctx

    def test_finds_extracted_memory(self, tmp_path: Path) -> None:
        """Extracted memory dumps in ~/.mulder/cases/extracted/ are listed."""
        evidence = tmp_path / "evidence"
        evidence.mkdir()

        extracted = tmp_path / "extracted" / "host-a-memory"
        extracted.mkdir(parents=True)
        (extracted / "host-a-memory.img").write_text("memory")

        orch = _make_orchestrator(evidence_path=str(evidence))
        with patch("pathlib.Path.home", return_value=tmp_path / "fakehome"):
            # Set up the expected path structure
            mulder_extracted = tmp_path / "fakehome" / ".mulder" / "cases" / "extracted"
            mulder_extracted.mkdir(parents=True)
            mem_dir = mulder_extracted / "host-a-memory"
            mem_dir.mkdir()
            (mem_dir / "host-a-memory.img").write_text("memory")

            ctx = orch._build_evidence_context("host-a")

        assert "Extracted memory dumps (ready for Volatility):" in ctx
        assert "host-a-memory.img" in ctx

    def test_fallback_when_no_files(self, tmp_path: Path) -> None:
        """Returns fallback instruction when no matching files exist."""
        evidence = tmp_path / "evidence"
        evidence.mkdir()

        orch = _make_orchestrator(evidence_path=str(evidence))
        with patch("pathlib.Path.home", return_value=tmp_path / "fakehome"):
            ctx = orch._build_evidence_context("nonexistent-host")

        assert "No pre-populated paths available" in ctx
        assert "list_directory" in ctx

    def test_system_name_case_insensitive(self, tmp_path: Path) -> None:
        """System name matching is case-insensitive."""
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "HostA-disk.vmdk").write_text("disk")

        orch = _make_orchestrator(evidence_path=str(evidence))
        ctx = orch._build_evidence_context("hosta")

        assert "HostA-disk.vmdk" in ctx


class TestExtractionPoolPassesEvidenceContext:
    """Extraction pool injects evidence_context into prompt_vars."""

    @pytest.mark.asyncio()
    async def test_evidence_context_in_prompt_vars(self) -> None:
        """_run_extraction_pool passes evidence_context to split phase."""
        orch = _make_orchestrator(parallel_extractions=1)
        orch._case_id = "test-case"

        from mulder.orchestrator.types import InvestigationResult

        captured_vars: list[dict[str, str]] = []

        async def mock_split_phase(
            phase: object,
            prompt_vars: dict[str, str] | None = None,
            skip_phase_header: bool = False,
        ) -> PhaseResult:
            if prompt_vars:
                captured_vars.append(dict(prompt_vars))
            return PhaseResult(phase_name="extraction", success=True, turns_used=1)

        groups = [["host-a"]]
        result = InvestigationResult()

        with patch.object(orch, "_run_split_phase", side_effect=mock_split_phase):
            await orch._run_extraction_pool(groups, result)

        assert len(captured_vars) == 1
        assert "evidence_context" in captured_vars[0]
        assert "host-a" in captured_vars[0]["evidence_context"]
