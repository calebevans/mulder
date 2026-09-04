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

    def test_set_membership_and_bounded_range_are_supported(self) -> None:
        member = verify_claim(
            _claim(predicate="set_contains", expected="cmd.exe", observed="pwsh.exe, cmd.exe")
        )
        ranged = verify_claim(
            _claim(predicate="within_range", expected="42", observed="42").model_copy(
                update={"qualifiers": {"minimum": 40, "maximum": 50}}
            )
        )

        assert member.result == "verified"
        assert ranged.result == "verified"

    def test_cross_source_identity_requires_distinct_artifacts(self) -> None:
        claim = _claim(predicate="cross_source_identity")
        first = claim.anchors[0].model_copy(update={"artifact_independence_key": "artifact:a"})
        second = first.model_copy(
            update={
                "anchor_id": "a_2",
                "source_id": 2,
                "source_hash": "hash-2",
                "artifact_independence_key": "artifact:b",
            }
        )

        assert verify_claim(claim.model_copy(update={"anchors": [first, second]})).result == (
            "verified"
        )

    def test_process_ancestry_and_bounded_cooccurrence_are_explicit(self) -> None:
        claim = _claim(predicate="process_ancestry", expected="child.exe")
        parent = claim.anchors[0].model_copy(
            update={"exact_text": "parent.exe", "char_start": 0, "char_end": 10}
        )
        child = parent.model_copy(
            update={
                "anchor_id": "a_2",
                "exact_text": "child.exe",
                "char_start": 12,
                "char_end": 21,
            }
        )
        ancestry = claim.model_copy(
            update={
                "anchors": [parent, child],
                "qualifiers": {"ancestor": "parent.exe", "descendant": "child.exe"},
            }
        )
        nearby = claim.model_copy(
            update={
                "predicate": "bounded_cooccurrence",
                "object_value": "parent.exe",
                "anchors": [parent, child],
                "qualifiers": {"with": "child.exe", "max_line_distance": 0},
            }
        )

        assert verify_claim(ancestry).result == "verified"
        assert verify_claim(nearby).result == "verified"

        unrelated_record = child.model_copy(update={"window_id": 2})
        assert (
            verify_claim(
                ancestry.model_copy(update={"anchors": [parent, unrelated_record]})
            ).result
            == "contradicted"
        )


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
        assessment = assess_confirmation([claim.model_copy(update={"anchors": [first, second]})])
        assert assessment.accepted is True
        assert assessment.claims[0].independent_sources == 2

    def test_repeated_anchor_from_same_root_counts_once(self) -> None:
        claim = _claim().model_copy(update={"epistemic_state": "verified"})
        duplicate = claim.anchors[0].model_copy(update={"anchor_id": "a_2"})
        assessment = assess_confirmation(
            [claim.model_copy(update={"anchors": [claim.anchors[0], duplicate]})]
        )
        assert assessment.accepted is False
        assert assessment.claims[0].reason_code == (
            "insufficient_independence:artifact,observation"
        )

    def test_material_policy_exposes_and_enforces_each_independence_dimension(self) -> None:
        claim = _claim().model_copy(update={"epistemic_state": "verified"})
        first = claim.anchors[0].model_copy(
            update={
                "artifact_independence_key": "artifact:a",
                "acquisition_independence_key": "acquisition:shared",
                "extractor_independence_key": "extractor:one",
                "observation_independence_key": "observation:a",
            }
        )
        second = first.model_copy(
            update={
                "anchor_id": "a_2",
                "source_id": 2,
                "artifact_independence_key": "artifact:b",
                "observation_independence_key": "observation:b",
            }
        )

        assessment = assess_confirmation([claim.model_copy(update={"anchors": [first, second]})])

        assert assessment.accepted is True
        assert assessment.claims[0].independence_dimensions == {
            "artifact": 2,
            "acquisition": 1,
            "extractor": 1,
            "observation": 2,
        }
        assert assessment.claims[0].required_independence_dimensions == {
            "artifact": 2,
            "acquisition": 1,
            "extractor": 1,
            "observation": 2,
        }

        strict = assess_confirmation(
            [claim.model_copy(update={"anchors": [first, second]})],
            min_independent_acquisitions=2,
            min_independent_extractors=2,
        )
        assert strict.accepted is False
        assert strict.claims[0].reason_code == ("insufficient_independence:acquisition,extractor")

    def test_non_verified_claim_cannot_be_confirmed(self) -> None:
        assessment = assess_confirmation([_claim()])
        assert assessment.accepted is False
        assert assessment.claims[0].reason_code == "claim_unverified"

    def test_nonmaterial_and_cryptographic_predicates_use_documented_policy(self) -> None:
        verified = _claim().model_copy(update={"epistemic_state": "verified"})
        nonmaterial = assess_confirmation([verified.model_copy(update={"material": False})])
        hash_claim = assess_confirmation(
            [verified.model_copy(update={"predicate": "hash_equals"})]
        )

        assert nonmaterial.accepted is True
        assert nonmaterial.claims[0].policy_id == "nonmaterial-single-observation-v2"
        assert hash_claim.accepted is True
        assert hash_claim.claims[0].policy_id == "cryptographic-single-artifact-v2"


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
