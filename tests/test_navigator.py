"""Tests for ATT&CK Navigator layer generation."""

from __future__ import annotations

from typing import Literal

from mulder.models import Finding
from mulder.report.navigator import (
    _SEVERITY_COLOR,
    _SEVERITY_SCORE,
    build_navigator_layer,
)

_DEFAULT_MITRE_IDS = ["T1059.001"]

_Severity = Literal["critical", "high", "medium", "low", "info"]


def _make_finding(
    title: str = "Test Finding",
    severity: _Severity = "high",
    mitre_ids: list[str] | None = None,
) -> Finding:
    """Create a minimal Finding for Navigator layer tests."""
    return Finding(
        finding_id="f-nav-001",
        case_id="nav-case",
        title=title,
        description="Test description",
        severity=severity,
        confidence="confirmed",
        evidence_refs=["tc_aabbccdd"],
        sources=["volatility.pslist"],
        mitre_attack_ids=_DEFAULT_MITRE_IDS if mitre_ids is None else mitre_ids,
        event_time_start="2025-01-15T08:00:00Z",
        submitted_at="2025-01-15T12:00:00Z",
    )


class TestLayerStructure:
    """Tests for Navigator layer required structure."""

    def test_layer_structure(self) -> None:
        """Navigator layer has required ATT&CK structure."""
        findings = [_make_finding(mitre_ids=["T1059.001"])]
        layer = build_navigator_layer("test-case", findings)

        assert layer["name"] == "Mulder Investigation: test-case"
        assert "versions" in layer
        assert layer["versions"]["attack"] == "16"
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert "gradient" in layer
        assert "layout" in layer

    def test_layer_custom_domain(self) -> None:
        """Custom domain parameter is reflected in layer output."""
        findings = [_make_finding(mitre_ids=["T1059"])]
        layer = build_navigator_layer("test-case", findings, domain="ics-attack")
        assert layer["domain"] == "ics-attack"

    def test_empty_findings_produces_empty_techniques(self) -> None:
        """Findings with no MITRE IDs produce an empty techniques list."""
        findings = [_make_finding(mitre_ids=[])]
        layer = build_navigator_layer("test-case", findings)
        assert layer["techniques"] == []


class TestSeverityColorMapping:
    """Tests for severity-to-color code mapping."""

    def test_severity_color_mapping(self) -> None:
        """Severity maps to correct color codes."""
        findings = [_make_finding(severity="critical", mitre_ids=["T1059.001"])]
        layer = build_navigator_layer("test-case", findings)

        technique = layer["techniques"][0]
        assert technique["color"] == _SEVERITY_COLOR["critical"]
        assert technique["score"] == _SEVERITY_SCORE["critical"]

    def test_severity_low_color(self) -> None:
        """Low severity findings produce the expected color."""
        findings = [_make_finding(severity="low", mitre_ids=["T1070"])]
        layer = build_navigator_layer("test-case", findings)

        technique = layer["techniques"][0]
        assert technique["color"] == "#66ccff"
        assert technique["score"] == 25


class TestTechniqueDeduplication:
    """Tests for duplicate technique ID merging."""

    def test_technique_deduplication(self) -> None:
        """Duplicate technique IDs are merged."""
        findings = [
            Finding(
                finding_id="f-1",
                case_id="test-case",
                title="Finding A",
                description="First finding",
                severity="medium",
                confidence="confirmed",
                evidence_refs=["tc_aabbccdd"],
                sources=["volatility.pslist"],
                mitre_attack_ids=["T1059.001"],
                event_time_start="2025-01-15T08:00:00Z",
                submitted_at="2025-01-15T12:00:00Z",
            ),
            Finding(
                finding_id="f-2",
                case_id="test-case",
                title="Finding B",
                description="Second finding",
                severity="critical",
                confidence="confirmed",
                evidence_refs=["tc_aabbccdd"],
                sources=["volatility.netscan"],
                mitre_attack_ids=["T1059.001"],
                event_time_start="2025-01-15T09:00:00Z",
                submitted_at="2025-01-15T12:00:00Z",
            ),
        ]
        layer = build_navigator_layer("test-case", findings)

        technique_ids = [t["techniqueID"] for t in layer["techniques"]]
        assert technique_ids.count("T1059.001") == 1

        technique = layer["techniques"][0]
        assert technique["color"] == _SEVERITY_COLOR["critical"]
        assert "Finding A" in technique["comment"]
        assert "Finding B" in technique["comment"]

    def test_subtechnique_shows_subtechniques(self) -> None:
        """Sub-technique IDs (containing '.') set showSubtechniques to True."""
        findings = [_make_finding(mitre_ids=["T1059.001"])]
        layer = build_navigator_layer("test-case", findings)

        technique = layer["techniques"][0]
        assert technique.get("showSubtechniques") is True
