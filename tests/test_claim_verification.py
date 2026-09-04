"""Tests for deterministic atomic-claim verification."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import text

from mulder.db import CaseDB
from mulder.models import (
    AtomicClaim,
    AtomicClaimInput,
    EvidenceAnchor,
    EvidenceAnchorInput,
    Finding,
    WindowRow,
)
from mulder.verification.claims import verify_claim
from mulder.verification.policy import assess_confirmation


def _claim(
    *,
    predicate: str = "equals",
    expected: str = "cmd.exe",
    observed: str = "cmd.exe",
    value_type: str = "text",
    role: str = "supports",
) -> AtomicClaim:
    anchor = EvidenceAnchor(
        anchor_id="a_1",
        claim_id="c_1",
        tool_call_id="tc_1",
        source_id=1,
        source_name="volatility.pslist",
        source_hash="hash",
        window_id=1,
        line_start=1,
        line_end=1,
        char_start=0,
        char_end=len(observed),
        exact_text=observed,
        artifact_family="memory",
        extractor_family="volatility",
        independence_key="source:hash",
        value_type=value_type,
        role=role,  # type: ignore[arg-type]
    )
    return AtomicClaim(
        claim_id="c_1",
        finding_id="f_1",
        ordinal=0,
        statement="structured statement",
        subject="process:1",
        predicate=predicate,
        object_value=expected,
        anchors=[anchor],
    )


class TestPureClaimVerifier:
    def test_exact_equality_verifies(self) -> None:
        result = verify_claim(_claim())
        assert result.result == "verified"
        assert result.reason_code == "all_supporting_anchors_matched"

    def test_wrong_value_is_contradicted(self) -> None:
        result = verify_claim(_claim(observed="powershell.exe"))
        assert result.result == "contradicted"
        assert result.reason_code == "supporting_anchor_mismatch"

    def test_unsupported_predicate_is_inconclusive(self) -> None:
        result = verify_claim(_claim(predicate="caused_exfiltration"))
        assert result.result == "inconclusive"
        assert result.reason_code == "unsupported_predicate"

    def test_path_normalization_is_deterministic(self) -> None:
        result = verify_claim(
            _claim(
                predicate="path_equals",
                expected="c:/windows/system32/cmd.exe",
                observed=r"C:\Windows\System32\cmd.exe",
                value_type="path",
            )
        )
        assert result.result == "verified"

    def test_invalid_ip_is_inconclusive(self) -> None:
        result = verify_claim(
            _claim(
                predicate="ip_equals",
                expected="999.2.3.4",
                observed="10.0.0.1",
                value_type="ip",
            )
        )
        assert result.result == "inconclusive"
        assert result.reason_code == "normalization_failed"

    def test_matching_contradicting_anchor_refutes(self) -> None:
        result = verify_claim(_claim(role="contradicts"))
        assert result.result == "contradicted"
        assert result.reason_code == "contradicting_anchor_matched"


class TestConfirmationPolicy:
    def test_two_distinct_root_sources_are_required(self) -> None:
        claim = _claim().model_copy(update={"epistemic_state": "verified"})
        first = claim.anchors[0]
        second = first.model_copy(
            update={
                "anchor_id": "a_2",
                "source_id": 2,
                "source_hash": "hash-2",
                "independence_key": "source:hash-2",
            }
        )
        assessment = assess_confirmation(
            [claim.model_copy(update={"anchors": [first, second]})]
        )
        assert assessment.accepted is True
        assert assessment.claims[0].independent_sources == 2

    def test_repeated_anchor_from_same_root_counts_once(self) -> None:
        claim = _claim().model_copy(update={"epistemic_state": "verified"})
        duplicate = claim.anchors[0].model_copy(update={"anchor_id": "a_2"})
        assessment = assess_confirmation(
            [claim.model_copy(update={"anchors": [claim.anchors[0], duplicate]})]
        )
        assert assessment.accepted is False
        assert assessment.claims[0].reason_code == "insufficient_independent_sources"

    def test_non_verified_claim_cannot_be_confirmed(self) -> None:
        assessment = assess_confirmation([_claim()])
        assert assessment.accepted is False
        assert assessment.claims[0].reason_code == "claim_unverified"


class TestPersistedVerification:
    def test_reopens_anchor_and_appends_history(self, tmp_path: Path) -> None:
        db = CaseDB.create("case", "/evidence", tmp_path)
        try:
            sid = db.register_source("src", "/evidence/a", "hash", "text", 1)
            db.insert_windows(
                sid,
                [
                    WindowRow(
                        source_id=sid,
                        line_start=1,
                        line_end=1,
                        event_time=None,
                        raw_text="cmd.exe",
                    )
                ],
            )
            window = db.get_windows_by_source("src")[0]
            assert window.window_id is not None
            finding = Finding(
                finding_id="f_1",
                case_id="case",
                title="Process",
                description="cmd.exe",
                severity="medium",
                confidence="inference",
                evidence_refs=["tc_1"],
                sources=["src"],
                submitted_at="2026-01-01T01:00:00Z",
            )
            db.insert_finding(
                finding,
                [
                    AtomicClaimInput(
                        statement="Image is cmd.exe",
                        subject="process:1",
                        predicate="image_name",
                        object_value="cmd.exe",
                        anchors=[
                            EvidenceAnchorInput(
                                tool_call_id="tc_1",
                                window_id=window.window_id,
                                char_start=0,
                                char_end=7,
                                expected_text="cmd.exe",
                            )
                        ],
                    )
                ],
            )

            first = db.verify_finding_claims("f_1")
            assert first[0].result == "verified"
            assert db.get_claims("f_1")[0].epistemic_state == "verified"

            with db._engine.begin() as conn:
                conn.execute(
                    text("UPDATE windows SET raw_text = 'pwsh.exe' WHERE window_id = :wid"),
                    {"wid": window.window_id},
                )
            second = db.verify_finding_claims("f_1")
            assert second[0].result == "inconclusive"
            assert second[0].reason_code == "anchor_text_changed"
            assert len(db.get_claim_verifications("f_1")) == 2
            assert db.get_claims("f_1")[0].epistemic_state == "inconclusive"
        finally:
            db.close()
