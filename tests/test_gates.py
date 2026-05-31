"""Tests for mulder.orchestrator.gates -- quality gate validation functions."""

from __future__ import annotations

from mulder.orchestrator.gates import (
    validate_audit,
    validate_catalog,
    validate_cross_system,
    validate_report,
)


class TestValidateReport:
    """Tests for validate_report gate function."""

    def test_passes_on_report_path_indicator(self) -> None:
        """Message containing 'report_path' passes gate."""
        messages = [{"text": "Generated report_path: /cases/out.report.md"}]
        result = validate_report(messages)
        assert result.passed

    def test_passes_on_finalized_indicator(self) -> None:
        """Message containing 'finalized' passes gate."""
        messages = [{"text": "The report has been finalized successfully."}]
        result = validate_report(messages)
        assert result.passed

    def test_fails_on_empty_messages(self) -> None:
        """Empty message list fails gate."""
        result = validate_report([])
        assert not result.passed

    def test_fails_on_irrelevant_text(self) -> None:
        """Messages without success indicators fail gate."""
        messages = [{"text": "I attempted to analyze the evidence but encountered errors."}]
        result = validate_report(messages)
        assert not result.passed


class TestValidateCatalog:
    """Tests for validate_catalog gate function."""

    def test_passes_when_case_id_present(self) -> None:
        """Summary with non-null case_id and evidence_root passes."""
        summary = {"case_id": "incident-42", "evidence_root": "/evidence", "sources_indexed": 3}
        result = validate_catalog(summary)
        assert result.passed

    def test_fails_when_case_id_none(self) -> None:
        """Summary with case_id=None fails."""
        summary = {"case_id": None, "sources_indexed": 0}
        result = validate_catalog(summary)
        assert not result.passed

    def test_fails_on_empty_summary(self) -> None:
        """Empty dict fails with 'No case found' detail."""
        result = validate_catalog({})
        assert not result.passed
        assert any("No case found" in c.detail for c in result.checks)


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


class TestValidateAuditNarrativeDeferral:
    """Tests for validate_audit narrative deferral logic."""

    def test_narrative_submitted_false_still_passes(self) -> None:
        """narrative_submitted gate failing is deferred to report phase."""
        readiness = {
            "gates": [
                {"name": "minimum_findings", "passed": True, "detail": "3 findings"},
                {"name": "narrative_submitted", "passed": False, "detail": "not yet"},
            ]
        }
        result = validate_audit(summary={"remaining_work": []}, readiness=readiness)
        assert result.passed

    def test_other_gate_failing_blocks(self) -> None:
        """A non-narrative failing gate causes overall failure."""
        readiness = {
            "gates": [
                {"name": "minimum_findings", "passed": False, "detail": "0 findings"},
                {"name": "narrative_submitted", "passed": False, "detail": "not yet"},
            ]
        }
        result = validate_audit(summary={"remaining_work": []}, readiness=readiness)
        assert not result.passed
