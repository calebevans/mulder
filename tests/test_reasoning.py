"""Tests for the typed competing-hypothesis and specialist-review seam."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from mulder.db import CaseDB
from mulder.models import AtomicClaimInput, AuditSummary, EvidenceAnchorInput, Finding, WindowRow
from mulder.reasoning import (
    REVIEWER_SEATS,
    Contradiction,
    ContradictionResolution,
    CreateHypothesis,
    EstimatedCost,
    Hypothesis,
    HypothesisDiscriminatorInput,
    HypothesisTestResult,
    ReasoningError,
    RecordContradiction,
    RecordHypothesisTest,
    RecordReviewVerdict,
    ResolveContradiction,
)
from mulder.report.renderer import ReportRenderer
from mulder.server.tool_access import Role, get_tools_for_role


def _create_hypothesis(db: CaseDB, *, title: str = "Operator intrusion") -> Hypothesis:
    result = db.record_reasoning(
        CreateHypothesis(
            competing_group="remote-access-explanation",
            title=title,
            statement="The remote session was controlled by an intruder.",
            discriminators=(
                HypothesisDiscriminatorInput(
                    expected_observation=(
                        "An unapproved source address appears in authentication logs."
                    ),
                    falsifier=(
                        "The address belongs to an approved jump host during a change window."
                    ),
                    estimated_cost=EstimatedCost(
                        amount=12,
                        unit="minutes",
                        basis="Authentication-log pivot",
                    ),
                ),
            ),
            author_id="counter-analyst",
        )
    )
    assert isinstance(result, Hypothesis)
    return result


def _insert_unverified_claim(db: CaseDB, case_id: str) -> str:
    source_id = db.register_source("auth.log", "/evidence/auth.log", "sha256:auth", "text", 1)
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=1,
                line_end=1,
                event_time="2026-01-01T00:00:00Z",
                raw_text="login source=203.0.113.9 account=admin",
            )
        ],
    )
    window = db.get_windows_by_source("auth.log")[0]
    assert window.window_id is not None
    finding = Finding(
        finding_id=f"finding-{case_id}",
        case_id=case_id,
        title="Remote login",
        description="An external login was observed.",
        severity="high",
        confidence="inference",
        evidence_refs=["tc-auth"],
        sources=["auth.log"],
        submitted_at="2026-01-01T01:00:00Z",
    )
    claims = db.insert_finding(
        finding,
        [
            AtomicClaimInput(
                statement="203.0.113.9 authenticated as admin",
                subject="ip:203.0.113.9",
                predicate="authenticated_as",
                object_value="account:admin",
                anchors=[
                    EvidenceAnchorInput(
                        tool_call_id="tc-auth",
                        window_id=window.window_id,
                        char_start=13,
                        char_end=24,
                        expected_text="203.0.113.9",
                    )
                ],
            )
        ],
    )
    return claims[0].claim_id


def test_reasoning_records_persist_with_cost_tests_and_resolution(tmp_path: Path) -> None:
    db = CaseDB.create("reasoning-persist", "/evidence", tmp_path)
    hypothesis = _create_hypothesis(db)
    discriminator_id = hypothesis.discriminators[0].discriminator_id

    test_result = db.record_reasoning(
        RecordHypothesisTest(
            discriminator_id=discriminator_id,
            outcome="inconclusive",
            summary="Authentication logs were truncated before the relevant hour.",
            tool_call_ids=("tc-search-auth",),
            actor_id="counter-analyst",
        )
    )
    contradiction = db.record_reasoning(
        RecordContradiction(
            hypothesis_id=hypothesis.hypothesis_id,
            description="The source address has both approved and unapproved classifications.",
            material=True,
            author_id="contradiction-reviewer",
        )
    )
    assert isinstance(test_result, HypothesisTestResult)
    assert isinstance(contradiction, Contradiction)
    assert test_result.discriminator_id == discriminator_id
    assert contradiction.material is True
    db.close()

    reopened = CaseDB.open("reasoning-persist", tmp_path)
    projection = reopened.get_reasoning_review()
    assert projection.hypotheses[0].discriminators[0].estimated_cost.amount == 12
    assert projection.hypotheses[0].discriminators[0].test_results[0].outcome == "inconclusive"
    assert projection.unresolved_material_contradiction_ids == (contradiction.contradiction_id,)
    resolution = reopened.record_reasoning(
        ResolveContradiction(
            contradiction_id=contradiction.contradiction_id,
            disposition="accepted_risk",
            rationale="The source classification cannot be recovered; report the limitation.",
            actor_id="lead-reviewer",
        )
    )
    assert isinstance(resolution, ContradictionResolution)
    with pytest.raises(ReasoningError, match="resolution is immutable"):
        reopened.record_reasoning(
            ResolveContradiction(
                contradiction_id=contradiction.contradiction_id,
                disposition="resolved",
                rationale="Attempted replacement.",
                actor_id="another-reviewer",
            )
        )
    final = reopened.get_reasoning_review()
    assert final.contradictions[0].resolution == resolution
    assert final.unresolved_material_contradiction_ids == ()
    reopened.close()


def test_open_migrates_legacy_database_without_reasoning_tables(tmp_path: Path) -> None:
    db = CaseDB.create("reasoning-legacy", "/evidence", tmp_path)
    with db.engine.begin() as conn:
        for table in (
            "review_verdicts",
            "contradiction_resolutions",
            "hypothesis_contradictions",
            "hypothesis_test_results",
            "hypothesis_discriminators",
            "hypotheses",
        ):
            conn.execute(text(f"DROP TABLE {table}"))
    db.close()

    migrated = CaseDB.open("reasoning-legacy", tmp_path)
    projection = migrated.get_reasoning_review()
    assert projection.hypotheses == ()
    assert tuple(seat.seat for seat in projection.review_seats) == REVIEWER_SEATS
    assert isinstance(_create_hypothesis(migrated), Hypothesis)
    migrated.close()


def test_reasoning_references_are_case_local(tmp_path: Path) -> None:
    db_a = CaseDB.create("case-a", "/evidence-a", tmp_path)
    db_b = CaseDB.create("case-b", "/evidence-b", tmp_path)
    hypothesis = _create_hypothesis(db_a)

    with pytest.raises(ReasoningError, match="discriminator is not in case case-b"):
        db_b.record_reasoning(
            RecordHypothesisTest(
                discriminator_id=hypothesis.discriminators[0].discriminator_id,
                outcome="supports",
                summary="Foreign result.",
                actor_id="reviewer",
            )
        )
    with pytest.raises(ReasoningError, match="hypothesis is not in case case-b"):
        db_b.record_reasoning(
            RecordContradiction(
                hypothesis_id=hypothesis.hypothesis_id,
                description="Foreign contradiction.",
                material=True,
                author_id="reviewer",
            )
        )
    with pytest.raises(ReasoningError, match="review target is not in case case-b"):
        db_b.record_reasoning(
            RecordReviewVerdict(
                seat="scope",
                target_kind="hypothesis",
                target_id=hypothesis.hypothesis_id,
                verdict="fail",
                rationale="Foreign target.",
                reviewer_id="scope-reviewer",
            )
        )
    assert db_b.get_reasoning_review().hypotheses == ()
    db_a.close()
    db_b.close()


def test_reviewer_seats_stay_separate_immutable_and_do_not_verify_claim(tmp_path: Path) -> None:
    db = CaseDB.create("review-seats", "/evidence", tmp_path)
    claim_id = _insert_unverified_claim(db, "review-seats")
    before = db.get_claims("finding-review-seats")[0]
    assert before.epistemic_state == "unverified"

    for seat in REVIEWER_SEATS:
        db.record_reasoning(
            RecordReviewVerdict(
                seat=seat,
                target_kind="claim",
                target_id=claim_id,
                verdict="pass",
                rationale=f"Independent {seat} review completed.",
                reviewer_id=f"{seat}-reviewer",
                claim_ids=(claim_id,),
            )
        )

    projection = db.get_reasoning_review()
    assert tuple(seat.seat for seat in projection.review_seats) == REVIEWER_SEATS
    assert [len(seat.verdicts) for seat in projection.review_seats] == [1, 1, 1, 1, 1]
    assert len({seat.verdicts[0].verdict_id for seat in projection.review_seats}) == 5
    with pytest.raises(ValidationError, match="frozen"):
        setattr(projection.review_seats[0].verdicts[0], "verdict", "fail")  # noqa: B010

    after = db.get_claims("finding-review-seats")[0]
    assert after.epistemic_state == "unverified"
    assert db.get_claim_verifications("finding-review-seats") == []
    db.close()


def test_report_renders_reasoning_projection_and_escapes_content(tmp_path: Path) -> None:
    db = CaseDB.create("reasoning-report", "/evidence", tmp_path)
    hypothesis = _create_hypothesis(db, title="Operator <script>alert(1)</script>")
    contradiction = db.record_reasoning(
        RecordContradiction(
            hypothesis_id=hypothesis.hypothesis_id,
            description="Material conflict | forged row",
            material=True,
            author_id="reviewer",
        )
    )
    assert isinstance(contradiction, Contradiction)
    db.record_reasoning(
        RecordReviewVerdict(
            seat="inference",
            target_kind="contradiction",
            target_id=contradiction.contradiction_id,
            verdict="concern",
            rationale="Inference exceeds the recovered evidence.",
            reviewer_id="inference-reviewer",
            material=True,
        )
    )
    meta = db.get_case_metadata()
    projection = db.get_reasoning_review()
    summary = AuditSummary(
        total_tool_calls=0,
        total_findings=0,
        tool_call_counts={},
        total_duration_ms=0,
        first_timestamp="",
        last_timestamp="",
    )
    renderer = ReportRenderer()
    markdown = renderer.render(
        meta,
        [],
        summary,
        tmp_path / "missing.audit.jsonl",
        reasoning_review=projection,
    )
    html = renderer.render_html(
        meta,
        [],
        summary,
        tmp_path / "missing.audit.jsonl",
        reasoning_review=projection,
    )
    assert "Competing Hypotheses and Specialist Review" in markdown
    assert "UNRESOLVED MATERIAL" in markdown
    assert "Material conflict | forged row" in markdown
    assert "no majority-vote truth" in html
    assert "Operator &lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Operator <script>" not in html
    db.close()


def test_reasoning_tools_use_least_privilege_role_registration() -> None:
    import mulder.server.tools.reasoning  # noqa: F401

    read_tool = "mcp__mulder__get_reasoning_review"
    write_tools = {
        "mcp__mulder__create_hypothesis",
        "mcp__mulder__record_hypothesis_test",
        "mcp__mulder__record_contradiction",
        "mcp__mulder__resolve_contradiction",
        "mcp__mulder__record_review_verdict",
    }

    for role in (Role.NARRATIVE_PLANNER, Role.NARRATIVE_ANALYST, Role.REPORT):
        assert read_tool in get_tools_for_role(role)
    assert write_tools <= set(get_tools_for_role(Role.NARRATIVE_ANALYST))
    for role in (Role.CATALOG, Role.EXTRACT_ANALYST, Role.CROSS_ANALYST, Role.REPORT):
        assert write_tools.isdisjoint(get_tools_for_role(role))
