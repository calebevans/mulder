"""Tests for fatal error propagation in mulder.orchestrator.runner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.orchestrator.errors import AuthenticationError, ModelNotAvailableError
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import PhaseResult


def _make_orchestrator(**kwargs: object) -> Orchestrator:
    """Create an Orchestrator with a mocked dashboard."""
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        if "evidence_path" not in kwargs:
            kwargs["evidence_path"] = "/evidence"
        return Orchestrator(**kwargs)  # type: ignore[arg-type]


class TestSinglePhaseAbort:
    """Fatal errors in single-mode phases abort without retrying."""

    @pytest.mark.asyncio()
    async def test_auth_error_aborts_single_phase(self) -> None:
        """AuthenticationError from execute() propagates through _run_single_phase."""
        orch = _make_orchestrator()
        orch._case_id = "test-case"

        call_count = 0

        async def mock_execute(**kwargs: object) -> PhaseResult:
            nonlocal call_count
            call_count += 1
            raise AuthenticationError(
                message="Not logged in",
                suggestion="Set ANTHROPIC_API_KEY",
            )

        from mulder.orchestrator.phases import CATALOG

        with (
            patch.object(orch._session, "execute", side_effect=mock_execute),
            pytest.raises(AuthenticationError),
        ):
            await orch._run_single_phase(
                CATALOG,
                prompt_vars={
                    "evidence_path": "/evidence",
                    "case_id_instruction": "",
                },
            )

        assert call_count == 1  # no retries

    @pytest.mark.asyncio()
    async def test_model_error_aborts_single_phase(self) -> None:
        """ModelNotAvailableError from execute() propagates without retrying."""
        orch = _make_orchestrator()
        orch._case_id = "test-case"

        call_count = 0

        async def mock_execute(**kwargs: object) -> PhaseResult:
            nonlocal call_count
            call_count += 1
            raise ModelNotAvailableError(
                message="model is not available",
                model="claude-test",
                alternative="claude-haiku-4-5",
            )

        from mulder.orchestrator.phases import CATALOG

        with (
            patch.object(orch._session, "execute", side_effect=mock_execute),
            pytest.raises(ModelNotAvailableError),
        ):
            await orch._run_single_phase(
                CATALOG,
                prompt_vars={
                    "evidence_path": "/evidence",
                    "case_id_instruction": "",
                },
            )

        assert call_count == 1


class TestSplitPhaseAbort:
    """Fatal errors during split-mode (planner/executor/analyst) abort immediately."""

    @pytest.mark.asyncio()
    async def test_auth_error_in_planner_aborts(self) -> None:
        """AuthenticationError from planner propagates through _run_split_phase."""
        orch = _make_orchestrator()
        orch._case_id = "test-case"

        async def mock_planner(
            phase: object,
            prompt_vars: object = None,
            follow_up_context: str = "",
            log_prefix: str = "",
        ) -> None:
            raise AuthenticationError(
                message="Not logged in",
                suggestion="Fix your auth",
            )

        from mulder.orchestrator.phases import CROSS_SYSTEM

        with (
            patch.object(orch._roles, "run_planner", side_effect=mock_planner),
            pytest.raises(AuthenticationError),
        ):
            await orch._run_split_phase(CROSS_SYSTEM)


class TestExtractionPoolAbort:
    """Fatal errors in extraction pool workers propagate to the caller."""

    @pytest.mark.asyncio()
    async def test_model_error_in_extraction_propagates(self) -> None:
        """ModelNotAvailableError from a worker propagates out of _run_extraction_pool."""
        orch = _make_orchestrator()
        orch._case_id = "test-case"
        orch._parallel_extractions = 2

        async def mock_split_phase(
            phase: object,
            prompt_vars: object = None,
            skip_phase_header: bool = False,
        ) -> PhaseResult:
            raise ModelNotAvailableError(
                message="model not found",
                model="claude-test",
            )

        from mulder.orchestrator.types import InvestigationResult

        result = InvestigationResult()
        groups = [["host-a"], ["host-b"]]

        with (
            patch.object(orch, "_run_split_phase", side_effect=mock_split_phase),
            pytest.raises(ModelNotAvailableError),
        ):
            await orch._run_extraction_pool(groups, result)


class TestRunPipelineAbort:
    """Fatal errors propagate through the full run() pipeline."""

    @pytest.mark.asyncio()
    async def test_auth_error_propagates_through_run(self, tmp_path: Path) -> None:
        """AuthenticationError in the catalog phase propagates through run()."""
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "sample.log").write_text("event", encoding="utf-8")
        orch = _make_orchestrator(
            evidence_path=str(evidence),
            case_id="test-case",
            db_dir=tmp_path / "cases",
        )

        async def mock_execute(**kwargs: object) -> PhaseResult:
            raise AuthenticationError(
                message="Not logged in",
                suggestion="Set ANTHROPIC_API_KEY",
            )

        with (
            patch.object(orch._session, "execute", side_effect=mock_execute),
            patch.object(orch, "_start_proxy_if_needed"),
            patch.object(orch._log_tailer, "start"),
            pytest.raises(AuthenticationError),
        ):
            await orch.run()
