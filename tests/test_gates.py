"""Tests for mulder.orchestrator.gates -- quality gate validation functions."""

from __future__ import annotations

from mulder.orchestrator.gates import (
    validate_catalog,
    validate_cross_system,
    validate_extraction,
    validate_narrative,
    validate_report,
)


class TestValidateReport:
    """Tests for validate_report gate function."""

    def test_passes_when_finalize_report_called(self) -> None:
        """Tool list containing 'finalize_report' passes gate."""
        result = validate_report(["open_case", "finalize_report"])
        assert result.passed

    def test_fails_on_empty_tool_list(self) -> None:
        """Empty tool list fails gate."""
        result = validate_report([])
        assert not result.passed

    def test_fails_when_finalize_report_absent(self) -> None:
        """Tool list without finalize_report fails gate."""
        result = validate_report(["open_case", "get_investigation_summary"])
        assert not result.passed

    def test_passes_with_many_tools(self) -> None:
        """finalize_report among many tools still passes."""
        tools = ["open_case", "submit_finding", "finalize_report", "search"]
        result = validate_report(tools)
        assert result.passed


class TestValidateCatalog:
    """Tests for validate_catalog gate function."""

    def test_passes_with_complete_json(self) -> None:
        """Catalog JSON with case_id, evidence_root, and systems passes."""
        catalog_json = {
            "case_id": "incident-42",
            "evidence_root": "/evidence",
            "systems": [{"name": "host-a", "type": "Linux", "evidence": ["disk_image"]}],
        }
        result = validate_catalog(catalog_json)
        assert result.passed

    def test_fails_when_case_id_none(self) -> None:
        """JSON with case_id=None fails the case_created check."""
        catalog_json = {
            "case_id": None,
            "evidence_root": "/evidence",
            "systems": [{"name": "host-a"}],
        }
        result = validate_catalog(catalog_json)
        assert not result.passed

    def test_fails_on_empty_dict(self) -> None:
        """Empty dict fails all checks."""
        result = validate_catalog({})
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "case_created" in check_names
        assert "systems_identified" in check_names

    def test_fails_on_empty_systems(self) -> None:
        """Empty systems array fails the systems_identified check."""
        catalog_json = {
            "case_id": "test",
            "evidence_root": "/evidence",
            "systems": [],
        }
        result = validate_catalog(catalog_json)
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "systems_identified" in check_names

    def test_fails_on_missing_evidence_root(self) -> None:
        """Missing evidence_root fails that specific check."""
        catalog_json = {
            "case_id": "test",
            "systems": [{"name": "host-a"}],
        }
        result = validate_catalog(catalog_json)
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "evidence_discovered" in check_names


class TestValidateCrossSystemWithData:
    """Tests for validate_cross_system with realistic data."""

    def test_passes_with_findings_and_mitre(self) -> None:
        """Summary with findings and mitre mappings passes both checks."""
        summary = {"findings_submitted": 5, "findings_with_mitre_ids": 3}
        result = validate_cross_system(summary)
        assert result.passed

    def test_fails_zero_findings(self) -> None:
        """Zero findings_submitted fails cross_system_findings check."""
        summary = {"findings_submitted": 0, "findings_with_mitre_ids": 0}
        result = validate_cross_system(summary)
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "cross_system_findings" in check_names

    def test_fails_zero_mitre(self) -> None:
        """Zero findings_with_mitre_ids fails mitre_mapping check."""
        summary = {"findings_submitted": 3, "findings_with_mitre_ids": 0}
        result = validate_cross_system(summary)
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "mitre_mapping" in check_names


class TestValidateNarrativeDeferral:
    """Tests for validate_narrative narrative_submitted deferral logic."""

    def test_narrative_submitted_false_still_passes(self) -> None:
        """narrative_submitted gate failing is deferred to report phase."""
        readiness = {
            "gates": [
                {"name": "minimum_findings", "passed": True, "detail": "3 findings"},
                {"name": "narrative_submitted", "passed": False, "detail": "not yet"},
            ]
        }
        result = validate_narrative(summary={"remaining_work": []}, readiness=readiness)
        assert result.passed

    def test_other_gate_failing_blocks(self) -> None:
        """A non-narrative failing gate causes overall failure."""
        readiness = {
            "gates": [
                {"name": "minimum_findings", "passed": False, "detail": "0 findings"},
                {"name": "narrative_submitted", "passed": False, "detail": "not yet"},
            ]
        }
        result = validate_narrative(summary={"remaining_work": []}, readiness=readiness)
        assert not result.passed


class TestExtractionRetryFailure:
    """Tests for validate_extraction retry-aware failure tracking."""

    def test_first_none_passes_with_advisory(self) -> None:
        """First None summary passes with an advisory gap."""
        result = validate_extraction(None)
        assert result.passed
        assert any("ADVISORY" in g for g in result.gaps)

    def test_second_none_fails(self) -> None:
        """Consecutive None summaries fail the gate."""
        validate_extraction(None)
        result = validate_extraction(None)
        assert not result.passed
        assert any("retry" in g for g in result.gaps)

    def test_success_resets_counter(self) -> None:
        """A successful summary resets the failure counter."""
        validate_extraction(None)
        validate_extraction({"sources_indexed": 3})
        result = validate_extraction(None)
        assert result.passed

    def test_passes_with_sources(self) -> None:
        """Non-None summary with sources passes normally."""
        result = validate_extraction({"sources_indexed": 5})
        assert result.passed


class TestCrossSystemRetryFailure:
    """Tests for validate_cross_system retry-aware failure tracking."""

    def test_first_none_passes_with_advisory(self) -> None:
        """First None summary passes with an advisory gap."""
        result = validate_cross_system(None)
        assert result.passed
        assert any("ADVISORY" in g for g in result.gaps)

    def test_second_none_fails(self) -> None:
        """Consecutive None summaries fail the gate."""
        validate_cross_system(None)
        result = validate_cross_system(None)
        assert not result.passed
        assert any("retry" in g for g in result.gaps)

    def test_success_resets_counter(self) -> None:
        """A successful summary resets the failure counter."""
        validate_cross_system(None)
        validate_cross_system({"findings_submitted": 2, "findings_with_mitre_ids": 1})
        result = validate_cross_system(None)
        assert result.passed
