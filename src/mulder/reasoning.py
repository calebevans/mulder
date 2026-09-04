"""Durable competing-hypothesis and independent-review records.

The public interface is the typed seam on :class:`mulder.db.CaseDB`.  This
module owns the reasoning vocabulary and append-only persistence mechanics;
callers cannot provide SQL or convert reviewer opinion into claim truth.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypeAlias
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Column, Connection, ForeignKey, Integer, MetaData, Table, Text, select

REASONING_SCHEMA_VERSION: Literal["1"] = "1"

ReviewerSeat = Literal["citation", "tool_semantics", "contradiction", "inference", "scope"]
ReviewTargetKind = Literal["case", "finding", "claim", "hypothesis", "contradiction"]
ReviewVerdictValue = Literal["pass", "concern", "fail", "abstain"]
TestOutcome = Literal["supports", "falsifies", "inconclusive", "failed", "unavailable"]
ResolutionDisposition = Literal["resolved", "accepted_risk", "not_material"]
CostUnit = Literal["minutes", "tokens", "usd", "analyst_hours", "tool_calls"]

REVIEWER_SEATS: tuple[ReviewerSeat, ...] = (
    "citation",
    "tool_semantics",
    "contradiction",
    "inference",
    "scope",
)


class ReasoningError(ValueError):
    """Raised when a typed reasoning command violates case-local invariants."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EstimatedCost(_FrozenModel):
    """Estimated effort for checking one discriminating observation."""

    amount: float = Field(ge=0)
    unit: CostUnit
    basis: str | None = None


class HypothesisDiscriminatorInput(_FrozenModel):
    """Expected observation, explicit falsifier, and estimated checking cost."""

    expected_observation: str = Field(min_length=1)
    falsifier: str = Field(min_length=1)
    estimated_cost: EstimatedCost


class CreateHypothesis(_FrozenModel):
    """Create a durable hypothesis and its initial discriminators."""

    competing_group: str = Field(min_length=1)
    title: str = Field(min_length=1)
    statement: str = Field(min_length=1)
    discriminators: tuple[HypothesisDiscriminatorInput, ...] = Field(min_length=1)
    author_id: str = Field(min_length=1)


class RecordHypothesisTest(_FrozenModel):
    """Append one observed result to a hypothesis discriminator."""

    discriminator_id: str = Field(min_length=1)
    outcome: TestOutcome
    summary: str = Field(min_length=1)
    claim_ids: tuple[str, ...] = ()
    tool_call_ids: tuple[str, ...] = ()
    actor_id: str = Field(min_length=1)


class RecordContradiction(_FrozenModel):
    """Record an unresolved contradiction against one or two hypotheses."""

    hypothesis_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    material: bool
    competing_hypothesis_id: str | None = None
    claim_ids: tuple[str, ...] = ()
    author_id: str = Field(min_length=1)


class ResolveContradiction(_FrozenModel):
    """Append the single resolution record for a contradiction."""

    contradiction_id: str = Field(min_length=1)
    disposition: ResolutionDisposition
    rationale: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)


class RecordReviewVerdict(_FrozenModel):
    """Append one immutable verdict in one specialist reviewer seat."""

    seat: ReviewerSeat
    target_kind: ReviewTargetKind
    target_id: str = Field(min_length=1)
    verdict: ReviewVerdictValue
    rationale: str = Field(min_length=1)
    reviewer_id: str = Field(min_length=1)
    material: bool = False
    claim_ids: tuple[str, ...] = ()
    tool_call_ids: tuple[str, ...] = ()


ReasoningCommand: TypeAlias = (
    CreateHypothesis
    | RecordHypothesisTest
    | RecordContradiction
    | ResolveContradiction
    | RecordReviewVerdict
)


class HypothesisTestResult(_FrozenModel):
    result_id: str
    discriminator_id: str
    outcome: TestOutcome
    summary: str
    claim_ids: tuple[str, ...]
    tool_call_ids: tuple[str, ...]
    actor_id: str
    created_at: str


class HypothesisDiscriminator(_FrozenModel):
    discriminator_id: str
    ordinal: int
    expected_observation: str
    falsifier: str
    estimated_cost: EstimatedCost
    test_results: tuple[HypothesisTestResult, ...] = ()


class Hypothesis(_FrozenModel):
    hypothesis_id: str
    case_id: str
    competing_group: str
    title: str
    statement: str
    discriminators: tuple[HypothesisDiscriminator, ...]
    author_id: str
    created_at: str


class ContradictionResolution(_FrozenModel):
    resolution_id: str
    contradiction_id: str
    disposition: ResolutionDisposition
    rationale: str
    actor_id: str
    created_at: str


class Contradiction(_FrozenModel):
    contradiction_id: str
    case_id: str
    hypothesis_id: str
    competing_hypothesis_id: str | None
    description: str
    material: bool
    claim_ids: tuple[str, ...]
    author_id: str
    created_at: str
    resolution: ContradictionResolution | None = None


class ReviewVerdict(_FrozenModel):
    verdict_id: str
    case_id: str
    seat: ReviewerSeat
    target_kind: ReviewTargetKind
    target_id: str
    verdict: ReviewVerdictValue
    rationale: str
    reviewer_id: str
    material: bool
    claim_ids: tuple[str, ...]
    tool_call_ids: tuple[str, ...]
    created_at: str


class ReviewSeatProjection(_FrozenModel):
    """One specialist seat; deliberately has no aggregate or winning vote."""

    seat: ReviewerSeat
    verdicts: tuple[ReviewVerdict, ...]


class ReasoningReviewProjection(_FrozenModel):
    """Case-local read model shared by MCP review and reports."""

    schema_version: Literal["1"] = REASONING_SCHEMA_VERSION
    case_id: str
    hypotheses: tuple[Hypothesis, ...]
    contradictions: tuple[Contradiction, ...]
    unresolved_material_contradiction_ids: tuple[str, ...]
    review_seats: tuple[ReviewSeatProjection, ...]


class ReasoningSealAssessment(_FrozenModel):
    """Result of the optional material-contradiction sealing policy."""

    enforced: bool
    allowed: bool
    unresolved_material_contradiction_ids: tuple[str, ...]


ReasoningWriteResult: TypeAlias = (
    Hypothesis | HypothesisTestResult | Contradiction | ContradictionResolution | ReviewVerdict
)


@dataclass(frozen=True)
class _ReasoningTables:
    hypotheses: Table
    discriminators: Table
    test_results: Table
    contradictions: Table
    contradiction_resolutions: Table
    review_verdicts: Table


def _define_reasoning_tables(metadata: MetaData) -> _ReasoningTables:
    """Attach the private append-only reasoning schema to case metadata."""
    hypotheses = Table(
        "hypotheses",
        metadata,
        Column("hypothesis_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column("competing_group", Text, nullable=False, index=True),
        Column("title", Text, nullable=False),
        Column("statement", Text, nullable=False),
        Column("author_id", Text, nullable=False),
        Column("created_at", Text, nullable=False),
    )
    discriminators = Table(
        "hypothesis_discriminators",
        metadata,
        Column("discriminator_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column(
            "hypothesis_id",
            Text,
            ForeignKey("hypotheses.hypothesis_id"),
            nullable=False,
            index=True,
        ),
        Column("ordinal", Integer, nullable=False),
        Column("expected_observation", Text, nullable=False),
        Column("falsifier", Text, nullable=False),
        Column("estimated_cost", Text, nullable=False),
    )
    test_results = Table(
        "hypothesis_test_results",
        metadata,
        Column("result_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column(
            "discriminator_id",
            Text,
            ForeignKey("hypothesis_discriminators.discriminator_id"),
            nullable=False,
            index=True,
        ),
        Column("outcome", Text, nullable=False),
        Column("summary", Text, nullable=False),
        Column("claim_ids", Text, nullable=False),
        Column("tool_call_ids", Text, nullable=False),
        Column("actor_id", Text, nullable=False),
        Column("created_at", Text, nullable=False),
    )
    contradictions = Table(
        "hypothesis_contradictions",
        metadata,
        Column("contradiction_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column(
            "hypothesis_id",
            Text,
            ForeignKey("hypotheses.hypothesis_id"),
            nullable=False,
            index=True,
        ),
        Column(
            "competing_hypothesis_id",
            Text,
            ForeignKey("hypotheses.hypothesis_id"),
        ),
        Column("description", Text, nullable=False),
        Column("material", Integer, nullable=False),
        Column("claim_ids", Text, nullable=False),
        Column("author_id", Text, nullable=False),
        Column("created_at", Text, nullable=False),
    )
    contradiction_resolutions = Table(
        "contradiction_resolutions",
        metadata,
        Column("resolution_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column(
            "contradiction_id",
            Text,
            ForeignKey("hypothesis_contradictions.contradiction_id"),
            nullable=False,
            unique=True,
            index=True,
        ),
        Column("disposition", Text, nullable=False),
        Column("rationale", Text, nullable=False),
        Column("actor_id", Text, nullable=False),
        Column("created_at", Text, nullable=False),
    )
    review_verdicts = Table(
        "review_verdicts",
        metadata,
        Column("verdict_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column("seat", Text, nullable=False, index=True),
        Column("target_kind", Text, nullable=False),
        Column("target_id", Text, nullable=False, index=True),
        Column("verdict", Text, nullable=False),
        Column("rationale", Text, nullable=False),
        Column("reviewer_id", Text, nullable=False),
        Column("material", Integer, nullable=False),
        Column("claim_ids", Text, nullable=False),
        Column("tool_call_ids", Text, nullable=False),
        Column("created_at", Text, nullable=False),
    )
    return _ReasoningTables(
        hypotheses=hypotheses,
        discriminators=discriminators,
        test_results=test_results,
        contradictions=contradictions,
        contradiction_resolutions=contradiction_resolutions,
        review_verdicts=review_verdicts,
    )


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_tuple(raw: str) -> tuple[str, ...]:
    return tuple(str(item) for item in json.loads(raw))


def _case_hypothesis(conn: Connection, case_id: str, hypothesis_id: str) -> None:
    from mulder.db import hypotheses_t

    exists = conn.execute(
        select(hypotheses_t.c.hypothesis_id).where(
            (hypotheses_t.c.case_id == case_id) & (hypotheses_t.c.hypothesis_id == hypothesis_id)
        )
    ).fetchone()
    if exists is None:
        raise ReasoningError(f"hypothesis is not in case {case_id}: {hypothesis_id}")


def _case_claims(conn: Connection, case_id: str, claim_ids: tuple[str, ...]) -> None:
    if not claim_ids:
        return
    from mulder.db import claims_t, findings_t

    rows = conn.execute(
        select(claims_t.c.claim_id)
        .select_from(claims_t.join(findings_t, claims_t.c.finding_id == findings_t.c.finding_id))
        .where((findings_t.c.case_id == case_id) & claims_t.c.claim_id.in_(claim_ids))
    ).fetchall()
    found = {str(row.claim_id) for row in rows}
    missing = sorted(set(claim_ids) - found)
    if missing:
        raise ReasoningError(f"claims are not in case {case_id}: {', '.join(missing)}")


def _case_discriminator(conn: Connection, case_id: str, discriminator_id: str) -> None:
    from mulder.db import hypothesis_discriminators_t

    exists = conn.execute(
        select(hypothesis_discriminators_t.c.discriminator_id).where(
            (hypothesis_discriminators_t.c.case_id == case_id)
            & (hypothesis_discriminators_t.c.discriminator_id == discriminator_id)
        )
    ).fetchone()
    if exists is None:
        raise ReasoningError(f"discriminator is not in case {case_id}: {discriminator_id}")


def _case_contradiction(conn: Connection, case_id: str, contradiction_id: str) -> None:
    from mulder.db import hypothesis_contradictions_t

    exists = conn.execute(
        select(hypothesis_contradictions_t.c.contradiction_id).where(
            (hypothesis_contradictions_t.c.case_id == case_id)
            & (hypothesis_contradictions_t.c.contradiction_id == contradiction_id)
        )
    ).fetchone()
    if exists is None:
        raise ReasoningError(f"contradiction is not in case {case_id}: {contradiction_id}")


def _case_review_target(
    conn: Connection, case_id: str, target_kind: ReviewTargetKind, target_id: str
) -> None:
    from mulder.db import claims_t, findings_t, hypotheses_t, hypothesis_contradictions_t

    if target_kind == "case":
        if target_id != case_id:
            raise ReasoningError(f"case review target must be {case_id}")
        return
    if target_kind == "finding":
        stmt = select(findings_t.c.finding_id).where(
            (findings_t.c.case_id == case_id) & (findings_t.c.finding_id == target_id)
        )
    elif target_kind == "claim":
        stmt = (
            select(claims_t.c.claim_id)
            .select_from(
                claims_t.join(findings_t, claims_t.c.finding_id == findings_t.c.finding_id)
            )
            .where((findings_t.c.case_id == case_id) & (claims_t.c.claim_id == target_id))
        )
    elif target_kind == "hypothesis":
        stmt = select(hypotheses_t.c.hypothesis_id).where(
            (hypotheses_t.c.case_id == case_id) & (hypotheses_t.c.hypothesis_id == target_id)
        )
    else:
        stmt = select(hypothesis_contradictions_t.c.contradiction_id).where(
            (hypothesis_contradictions_t.c.case_id == case_id)
            & (hypothesis_contradictions_t.c.contradiction_id == target_id)
        )
    if conn.execute(stmt).fetchone() is None:
        raise ReasoningError(f"{target_kind} review target is not in case {case_id}: {target_id}")


def _record_hypothesis(conn: Connection, case_id: str, command: CreateHypothesis) -> Hypothesis:
    from mulder.db import hypotheses_t, hypothesis_discriminators_t

    hypothesis_id = _new_id("hyp")
    created_at = _now()
    conn.execute(
        hypotheses_t.insert().values(
            hypothesis_id=hypothesis_id,
            case_id=case_id,
            competing_group=command.competing_group,
            title=command.title,
            statement=command.statement,
            author_id=command.author_id,
            created_at=created_at,
        )
    )
    discriminators: list[HypothesisDiscriminator] = []
    for ordinal, item in enumerate(command.discriminators, start=1):
        discriminator_id = _new_id("hd")
        conn.execute(
            hypothesis_discriminators_t.insert().values(
                discriminator_id=discriminator_id,
                case_id=case_id,
                hypothesis_id=hypothesis_id,
                ordinal=ordinal,
                expected_observation=item.expected_observation,
                falsifier=item.falsifier,
                estimated_cost=item.estimated_cost.model_dump_json(),
            )
        )
        discriminators.append(
            HypothesisDiscriminator(
                discriminator_id=discriminator_id,
                ordinal=ordinal,
                expected_observation=item.expected_observation,
                falsifier=item.falsifier,
                estimated_cost=item.estimated_cost,
            )
        )
    return Hypothesis(
        hypothesis_id=hypothesis_id,
        case_id=case_id,
        competing_group=command.competing_group,
        title=command.title,
        statement=command.statement,
        discriminators=tuple(discriminators),
        author_id=command.author_id,
        created_at=created_at,
    )


def _record_test(
    conn: Connection, case_id: str, command: RecordHypothesisTest
) -> HypothesisTestResult:
    from mulder.db import hypothesis_test_results_t

    _case_discriminator(conn, case_id, command.discriminator_id)
    _case_claims(conn, case_id, command.claim_ids)
    result = HypothesisTestResult(
        result_id=_new_id("htr"),
        discriminator_id=command.discriminator_id,
        outcome=command.outcome,
        summary=command.summary,
        claim_ids=command.claim_ids,
        tool_call_ids=command.tool_call_ids,
        actor_id=command.actor_id,
        created_at=_now(),
    )
    conn.execute(
        hypothesis_test_results_t.insert().values(
            result_id=result.result_id,
            case_id=case_id,
            discriminator_id=result.discriminator_id,
            outcome=result.outcome,
            summary=result.summary,
            claim_ids=json.dumps(result.claim_ids),
            tool_call_ids=json.dumps(result.tool_call_ids),
            actor_id=result.actor_id,
            created_at=result.created_at,
        )
    )
    return result


def _record_contradiction(
    conn: Connection, case_id: str, command: RecordContradiction
) -> Contradiction:
    from mulder.db import hypothesis_contradictions_t

    _case_hypothesis(conn, case_id, command.hypothesis_id)
    if command.competing_hypothesis_id is not None:
        if command.competing_hypothesis_id == command.hypothesis_id:
            raise ReasoningError("a hypothesis cannot compete with itself")
        _case_hypothesis(conn, case_id, command.competing_hypothesis_id)
    _case_claims(conn, case_id, command.claim_ids)
    contradiction = Contradiction(
        contradiction_id=_new_id("hc"),
        case_id=case_id,
        hypothesis_id=command.hypothesis_id,
        competing_hypothesis_id=command.competing_hypothesis_id,
        description=command.description,
        material=command.material,
        claim_ids=command.claim_ids,
        author_id=command.author_id,
        created_at=_now(),
    )
    conn.execute(
        hypothesis_contradictions_t.insert().values(
            contradiction_id=contradiction.contradiction_id,
            case_id=case_id,
            hypothesis_id=contradiction.hypothesis_id,
            competing_hypothesis_id=contradiction.competing_hypothesis_id,
            description=contradiction.description,
            material=int(contradiction.material),
            claim_ids=json.dumps(contradiction.claim_ids),
            author_id=contradiction.author_id,
            created_at=contradiction.created_at,
        )
    )
    return contradiction


def _resolve_contradiction(
    conn: Connection, case_id: str, command: ResolveContradiction
) -> ContradictionResolution:
    from mulder.db import contradiction_resolutions_t

    _case_contradiction(conn, case_id, command.contradiction_id)
    prior = conn.execute(
        select(contradiction_resolutions_t.c.resolution_id).where(
            contradiction_resolutions_t.c.contradiction_id == command.contradiction_id
        )
    ).fetchone()
    if prior is not None:
        raise ReasoningError(f"contradiction resolution is immutable: {command.contradiction_id}")
    resolution = ContradictionResolution(
        resolution_id=_new_id("hcr"),
        contradiction_id=command.contradiction_id,
        disposition=command.disposition,
        rationale=command.rationale,
        actor_id=command.actor_id,
        created_at=_now(),
    )
    conn.execute(
        contradiction_resolutions_t.insert().values(
            resolution_id=resolution.resolution_id,
            case_id=case_id,
            contradiction_id=resolution.contradiction_id,
            disposition=resolution.disposition,
            rationale=resolution.rationale,
            actor_id=resolution.actor_id,
            created_at=resolution.created_at,
        )
    )
    return resolution


def _record_review(conn: Connection, case_id: str, command: RecordReviewVerdict) -> ReviewVerdict:
    from mulder.db import review_verdicts_t

    _case_review_target(conn, case_id, command.target_kind, command.target_id)
    _case_claims(conn, case_id, command.claim_ids)
    verdict = ReviewVerdict(
        verdict_id=_new_id("rv"),
        case_id=case_id,
        seat=command.seat,
        target_kind=command.target_kind,
        target_id=command.target_id,
        verdict=command.verdict,
        rationale=command.rationale,
        reviewer_id=command.reviewer_id,
        material=command.material,
        claim_ids=command.claim_ids,
        tool_call_ids=command.tool_call_ids,
        created_at=_now(),
    )
    conn.execute(
        review_verdicts_t.insert().values(
            verdict_id=verdict.verdict_id,
            case_id=case_id,
            seat=verdict.seat,
            target_kind=verdict.target_kind,
            target_id=verdict.target_id,
            verdict=verdict.verdict,
            rationale=verdict.rationale,
            reviewer_id=verdict.reviewer_id,
            material=int(verdict.material),
            claim_ids=json.dumps(verdict.claim_ids),
            tool_call_ids=json.dumps(verdict.tool_call_ids),
            created_at=verdict.created_at,
        )
    )
    return verdict


def _record_command(
    conn: Connection, case_id: str, command: ReasoningCommand
) -> ReasoningWriteResult:
    """Execute one bounded append-only command within the caller's transaction."""
    if isinstance(command, CreateHypothesis):
        return _record_hypothesis(conn, case_id, command)
    if isinstance(command, RecordHypothesisTest):
        return _record_test(conn, case_id, command)
    if isinstance(command, RecordContradiction):
        return _record_contradiction(conn, case_id, command)
    if isinstance(command, ResolveContradiction):
        return _resolve_contradiction(conn, case_id, command)
    return _record_review(conn, case_id, command)


def _empty_projection(case_id: str) -> ReasoningReviewProjection:
    return ReasoningReviewProjection(
        case_id=case_id,
        hypotheses=(),
        contradictions=(),
        unresolved_material_contradiction_ids=(),
        review_seats=tuple(
            ReviewSeatProjection(seat=seat, verdicts=()) for seat in REVIEWER_SEATS
        ),
    )


def _read_review_projection(conn: Connection, case_id: str) -> ReasoningReviewProjection:
    """Build the shared deterministic review/report projection for one case."""
    from mulder.db import (
        contradiction_resolutions_t,
        hypotheses_t,
        hypothesis_contradictions_t,
        hypothesis_discriminators_t,
        hypothesis_test_results_t,
        review_verdicts_t,
    )

    # Some read-only report paths open pre-migration databases directly.
    if not conn.dialect.has_table(conn, "hypotheses"):
        return _empty_projection(case_id)

    result_rows = conn.execute(
        select(hypothesis_test_results_t)
        .where(hypothesis_test_results_t.c.case_id == case_id)
        .order_by(hypothesis_test_results_t.c.created_at, hypothesis_test_results_t.c.result_id)
    ).fetchall()
    results: dict[str, list[HypothesisTestResult]] = {}
    for row in result_rows:
        item = HypothesisTestResult(
            result_id=row.result_id,
            discriminator_id=row.discriminator_id,
            outcome=row.outcome,
            summary=row.summary,
            claim_ids=_json_tuple(row.claim_ids),
            tool_call_ids=_json_tuple(row.tool_call_ids),
            actor_id=row.actor_id,
            created_at=row.created_at,
        )
        results.setdefault(item.discriminator_id, []).append(item)

    discriminator_rows = conn.execute(
        select(hypothesis_discriminators_t)
        .where(hypothesis_discriminators_t.c.case_id == case_id)
        .order_by(
            hypothesis_discriminators_t.c.hypothesis_id,
            hypothesis_discriminators_t.c.ordinal,
            hypothesis_discriminators_t.c.discriminator_id,
        )
    ).fetchall()
    discriminators: dict[str, list[HypothesisDiscriminator]] = {}
    for row in discriminator_rows:
        discriminator = HypothesisDiscriminator(
            discriminator_id=row.discriminator_id,
            ordinal=row.ordinal,
            expected_observation=row.expected_observation,
            falsifier=row.falsifier,
            estimated_cost=EstimatedCost.model_validate_json(row.estimated_cost),
            test_results=tuple(results.get(str(row.discriminator_id), ())),
        )
        discriminators.setdefault(str(row.hypothesis_id), []).append(discriminator)

    hypotheses = tuple(
        Hypothesis(
            hypothesis_id=row.hypothesis_id,
            case_id=row.case_id,
            competing_group=row.competing_group,
            title=row.title,
            statement=row.statement,
            discriminators=tuple(discriminators.get(str(row.hypothesis_id), ())),
            author_id=row.author_id,
            created_at=row.created_at,
        )
        for row in conn.execute(
            select(hypotheses_t)
            .where(hypotheses_t.c.case_id == case_id)
            .order_by(
                hypotheses_t.c.competing_group,
                hypotheses_t.c.created_at,
                hypotheses_t.c.hypothesis_id,
            )
        ).fetchall()
    )

    resolution_rows = conn.execute(
        select(contradiction_resolutions_t).where(contradiction_resolutions_t.c.case_id == case_id)
    ).fetchall()
    resolutions = {
        str(row.contradiction_id): ContradictionResolution(
            resolution_id=row.resolution_id,
            contradiction_id=row.contradiction_id,
            disposition=row.disposition,
            rationale=row.rationale,
            actor_id=row.actor_id,
            created_at=row.created_at,
        )
        for row in resolution_rows
    }
    contradictions = tuple(
        Contradiction(
            contradiction_id=row.contradiction_id,
            case_id=row.case_id,
            hypothesis_id=row.hypothesis_id,
            competing_hypothesis_id=row.competing_hypothesis_id,
            description=row.description,
            material=bool(row.material),
            claim_ids=_json_tuple(row.claim_ids),
            author_id=row.author_id,
            created_at=row.created_at,
            resolution=resolutions.get(str(row.contradiction_id)),
        )
        for row in conn.execute(
            select(hypothesis_contradictions_t)
            .where(hypothesis_contradictions_t.c.case_id == case_id)
            .order_by(
                hypothesis_contradictions_t.c.created_at,
                hypothesis_contradictions_t.c.contradiction_id,
            )
        ).fetchall()
    )

    seat_verdicts: dict[ReviewerSeat, list[ReviewVerdict]] = {seat: [] for seat in REVIEWER_SEATS}
    for row in conn.execute(
        select(review_verdicts_t)
        .where(review_verdicts_t.c.case_id == case_id)
        .order_by(review_verdicts_t.c.created_at, review_verdicts_t.c.verdict_id)
    ).fetchall():
        verdict = ReviewVerdict(
            verdict_id=row.verdict_id,
            case_id=row.case_id,
            seat=row.seat,
            target_kind=row.target_kind,
            target_id=row.target_id,
            verdict=row.verdict,
            rationale=row.rationale,
            reviewer_id=row.reviewer_id,
            material=bool(row.material),
            claim_ids=_json_tuple(row.claim_ids),
            tool_call_ids=_json_tuple(row.tool_call_ids),
            created_at=row.created_at,
        )
        seat_verdicts[verdict.seat].append(verdict)

    unresolved = tuple(
        item.contradiction_id
        for item in contradictions
        if item.material and item.resolution is None
    )
    return ReasoningReviewProjection(
        case_id=case_id,
        hypotheses=hypotheses,
        contradictions=contradictions,
        unresolved_material_contradiction_ids=unresolved,
        review_seats=tuple(
            ReviewSeatProjection(seat=seat, verdicts=tuple(seat_verdicts[seat]))
            for seat in REVIEWER_SEATS
        ),
    )


def assess_reasoning_seal(
    db_path: Path, *, require_resolved_contradictions: bool
) -> ReasoningSealAssessment:
    """Assess the optional seal gate through a fixed read-only SQLite query."""
    if not require_resolved_contradictions:
        return ReasoningSealAssessment(
            enforced=False,
            allowed=True,
            unresolved_material_contradiction_ids=(),
        )
    uri = f"file:{db_path.resolve()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN "
                "('hypothesis_contradictions', 'contradiction_resolutions')"
            )
        }
        if tables != {"hypothesis_contradictions", "contradiction_resolutions"}:
            unresolved: tuple[str, ...] = ()
        else:
            unresolved = tuple(
                str(row[0])
                for row in conn.execute(
                    "SELECT c.contradiction_id FROM hypothesis_contradictions AS c "
                    "LEFT JOIN contradiction_resolutions AS r "
                    "ON r.contradiction_id = c.contradiction_id "
                    "WHERE c.material = 1 AND r.resolution_id IS NULL "
                    "ORDER BY c.created_at, c.contradiction_id"
                )
            )
    return ReasoningSealAssessment(
        enforced=True,
        allowed=not unresolved,
        unresolved_material_contradiction_ids=unresolved,
    )


__all__ = [
    "REASONING_SCHEMA_VERSION",
    "REVIEWER_SEATS",
    "Contradiction",
    "ContradictionResolution",
    "CreateHypothesis",
    "EstimatedCost",
    "Hypothesis",
    "HypothesisDiscriminator",
    "HypothesisDiscriminatorInput",
    "HypothesisTestResult",
    "ReasoningCommand",
    "ReasoningError",
    "ReasoningReviewProjection",
    "ReasoningSealAssessment",
    "ReasoningWriteResult",
    "RecordContradiction",
    "RecordHypothesisTest",
    "RecordReviewVerdict",
    "ResolveContradiction",
    "ReviewSeatProjection",
    "ReviewVerdict",
    "ReviewerSeat",
    "assess_reasoning_seal",
]
