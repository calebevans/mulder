"""Tests for mulder.models -- Pydantic model validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mulder.models import AtomicClaimInput, EvidenceAnchorInput, Finding


class TestFinding:
    def test_rejects_empty_evidence_refs(self) -> None:
        with pytest.raises(ValidationError, match="evidence_refs"):
            Finding(
                finding_id="f-001",
                case_id="c-001",
                title="Bad",
                description="desc",
                severity="high",
                confidence="confirmed",
                evidence_refs=[],
                sources=["src"],
                submitted_at="2025-01-01T00:00:00Z",
            )

    def test_roundtrip_via_model_dump(self, sample_finding: Finding) -> None:
        data = sample_finding.model_dump()
        restored = Finding.model_validate(data)
        assert restored == sample_finding

    def test_accepts_all_severity_levels(self) -> None:
        for sev in ("critical", "high", "medium", "low", "info"):
            Finding(
                finding_id="f-1",
                case_id="c-1",
                title="t",
                description="d",
                confidence="confirmed",
                evidence_refs=["tc_1"],
                sources=["s"],
                submitted_at="2025-01-01T00:00:00Z",
                severity=sev,
            )

    def test_rejects_invalid_severity(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                finding_id="f-1",
                case_id="c-1",
                title="t",
                description="d",
                severity="banana",  # type: ignore[arg-type]
                confidence="confirmed",
                evidence_refs=["tc_1"],
                sources=["s"],
                submitted_at="2025-01-01T00:00:00Z",
            )

    def test_rejects_invalid_confidence(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                finding_id="f-1",
                case_id="c-1",
                title="t",
                description="d",
                severity="high",
                confidence="maybe",  # type: ignore[arg-type]
                evidence_refs=["tc_1"],
                sources=["s"],
                submitted_at="2025-01-01T00:00:00Z",
            )

    def test_optional_fields_default_correctly(self) -> None:
        f = Finding(
            finding_id="f-1",
            case_id="c-1",
            title="t",
            description="d",
            severity="low",
            confidence="inference",
            evidence_refs=["tc_1"],
            sources=["s"],
            submitted_at="2025-01-01T00:00:00Z",
        )
        assert f.mitre_attack_ids == []
        assert f.event_time_start is None
        assert f.event_time_end is None


class TestAtomicClaimInput:
    def test_rejects_empty_anchor_list(self) -> None:
        with pytest.raises(ValidationError, match="anchors"):
            AtomicClaimInput(
                statement="cmd.exe executed",
                subject="cmd.exe",
                predicate="executed",
                object_value=True,
                anchors=[],
            )

    def test_rejects_reversed_character_range(self) -> None:
        with pytest.raises(ValidationError, match="char_end"):
            EvidenceAnchorInput(
                tool_call_id="tc_1",
                window_id=1,
                char_start=8,
                char_end=4,
                expected_text="cmd",
            )
