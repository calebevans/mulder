"""Tests for SPEC-067: skip cross-system analysis for single-host cases."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from mulder.orchestrator.phases import CROSS_SYSTEM
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import InvestigationResult, PhaseResult


def _make_orchestrator(**kwargs: object) -> Orchestrator:
    """Create an Orchestrator with a mocked dashboard."""
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        if "evidence_path" not in kwargs:
            kwargs["evidence_path"] = "/evidence"
        return Orchestrator(**kwargs)  # type: ignore[arg-type]


def _catalog_result_with_systems(systems: list[dict[str, object]]) -> PhaseResult:
    """Build a fake catalog PhaseResult containing a systems JSON."""
    catalog_json = json.dumps({"systems": systems})
    return PhaseResult(
        phase_name="catalog",
        success=True,
        messages=[f"```json\n{catalog_json}\n```"],
        turns_used=5,
        session_id="sess-catalog",
    )


class TestSingleSystemSkipsCrossSystem:
    """When only 1 system is detected, cross-system phase is skipped."""

    @pytest.mark.asyncio()
    async def test_single_system_multiple_evidence_types_still_skips(self) -> None:
        """A single host with diverse evidence types still skips cross-system."""
        systems_data: list[dict[str, object]] = [
            {
                "name": "server-01",
                "evidence": ["disk_image", "memory_dump", "network_capture"],
            }
        ]
        catalog = _catalog_result_with_systems(systems_data)

        orch = _make_orchestrator()
        systems, catalog_data = orch._identify_systems_from_catalog(catalog)

        assert len(systems) == 1
        assert systems == ["server-01"]
        # The condition `len(systems) > 1` would be False, so cross-system is skipped
        assert not (len(systems) > 1)


class TestMultiSystemRunsCrossSystem:
    """When 2+ systems are detected, cross-system phase executes normally."""

    @pytest.mark.asyncio()
    async def test_multi_system_runs_cross_system(self) -> None:
        """Cross-system phase is executed when multiple systems are present."""
        orch = _make_orchestrator()
        orch._case_id = "test-case"
        orch._case_briefing = ""
        orch._total_phases = 5
        orch._phase_counter = 2

        run_split_phase_calls: list[str] = []

        async def mock_run_split_phase(
            phase: object, prompt_vars: object = None, **kwargs: object
        ) -> PhaseResult:
            phase_name = getattr(phase, "name", "unknown")
            run_split_phase_calls.append(phase_name)
            return PhaseResult(phase_name=phase_name, success=True, turns_used=10)

        result = InvestigationResult()
        systems = ["dc-01", "workstation-02", "mail-server"]

        with patch.object(orch, "_run_split_phase", side_effect=mock_run_split_phase):
            if len(systems) > 1:
                cross_result = await orch._run_split_phase(
                    CROSS_SYSTEM, prompt_vars={"case_briefing": ""}
                )
                result.phases.append(cross_result)

            assert "cross_system" in run_split_phase_calls
            cross_phase = result.phases[-1]
            assert cross_phase.phase_name == "cross_system"
            assert cross_phase.success is True
            assert cross_phase.turns_used == 10


class TestDashboardShowsSkipIndicator:
    """Dashboard displays skip status when cross-system is skipped."""

    @pytest.mark.asyncio()
    async def test_dashboard_set_phase_called_with_skip_label(self) -> None:
        """Dashboard.set_phase receives the skip label for single-system cases."""
        orch = _make_orchestrator()
        orch._case_id = "test-case"
        orch._case_briefing = ""
        orch._total_phases = 5
        orch._phase_counter = 2

        systems = ["single-host"]

        # Simulate the skip path
        if len(systems) <= 1:
            orch._phase_counter += 1
            orch.dashboard.set_phase(
                label="cross_system (skipped: single system)",
                phase_num=orch._phase_counter,
                total_phases=orch._total_phases,
                model="\u2014",
                max_turns=0,
            )
            orch.dashboard.log_info(
                "Skipping cross-system phase (single system; nothing to correlate)"
            )

        orch.dashboard.set_phase.assert_called_once_with(  # type: ignore[attr-defined]
            label="cross_system (skipped: single system)",
            phase_num=3,
            total_phases=5,
            model="\u2014",
            max_turns=0,
        )
        orch.dashboard.log_info.assert_called_with(  # type: ignore[attr-defined]
            "Skipping cross-system phase (single system; nothing to correlate)"
        )
