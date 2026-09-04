"""Typed MCP seam for competing hypotheses and specialist review seats."""

from __future__ import annotations

from typing import Literal

from mulder.reasoning import (
    CreateHypothesis,
    EstimatedCost,
    HypothesisDiscriminatorInput,
    RecordContradiction,
    RecordHypothesisTest,
    RecordReviewVerdict,
    ResolveContradiction,
)
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import audited_tool
from mulder.server.tool_access import Role, tool_access

_REASONING_READ_ROLES = Role.NARRATIVE_PLANNER | Role.NARRATIVE_ANALYST | Role.REPORT
_REASONING_WRITE_ROLES = Role.NARRATIVE_ANALYST


@mcp.tool()
@tool_access(_REASONING_WRITE_ROLES)
@audited_tool("create_hypothesis")
def create_hypothesis(
    competing_group: str,
    title: str,
    statement: str,
    discriminators: list[dict[str, object]],
    author_id: str,
) -> dict[str, object]:
    """Persist a hypothesis with expected observations, falsifiers, and costs.

    Each discriminator object must contain ``expected_observation``,
    ``falsifier``, and ``estimated_cost``. Estimated cost contains a
    non-negative ``amount``, a unit (minutes, tokens, usd, analyst_hours, or
    tool_calls), and an optional basis.
    """
    parsed: list[HypothesisDiscriminatorInput] = []
    for item in discriminators:
        cost = item.get("estimated_cost")
        if not isinstance(cost, dict):
            raise ValueError("each discriminator requires an estimated_cost object")
        parsed.append(
            HypothesisDiscriminatorInput(
                expected_observation=str(item.get("expected_observation", "")),
                falsifier=str(item.get("falsifier", "")),
                estimated_cost=EstimatedCost.model_validate(cost),
            )
        )
    result = get_ctx().db.record_reasoning(
        CreateHypothesis(
            competing_group=competing_group,
            title=title,
            statement=statement,
            discriminators=tuple(parsed),
            author_id=author_id,
        )
    )
    return {"status": "success", "hypothesis": result.model_dump(mode="json")}


@mcp.tool()
@tool_access(_REASONING_WRITE_ROLES)
@audited_tool("record_hypothesis_test")
def record_hypothesis_test(
    discriminator_id: str,
    outcome: Literal["supports", "falsifies", "inconclusive", "failed", "unavailable"],
    summary: str,
    actor_id: str,
    claim_ids: list[str] | None = None,
    tool_call_ids: list[str] | None = None,
) -> dict[str, object]:
    """Append an observed test result without deciding hypothesis truth."""
    result = get_ctx().db.record_reasoning(
        RecordHypothesisTest(
            discriminator_id=discriminator_id,
            outcome=outcome,
            summary=summary,
            claim_ids=tuple(claim_ids or ()),
            tool_call_ids=tuple(tool_call_ids or ()),
            actor_id=actor_id,
        )
    )
    return {"status": "success", "test_result": result.model_dump(mode="json")}


@mcp.tool()
@tool_access(_REASONING_WRITE_ROLES)
@audited_tool("record_contradiction")
def record_contradiction(
    hypothesis_id: str,
    description: str,
    material: bool,
    author_id: str,
    competing_hypothesis_id: str | None = None,
    claim_ids: list[str] | None = None,
) -> dict[str, object]:
    """Persist an unresolved contradiction, optionally between two hypotheses."""
    result = get_ctx().db.record_reasoning(
        RecordContradiction(
            hypothesis_id=hypothesis_id,
            competing_hypothesis_id=competing_hypothesis_id,
            description=description,
            material=material,
            claim_ids=tuple(claim_ids or ()),
            author_id=author_id,
        )
    )
    return {"status": "success", "contradiction": result.model_dump(mode="json")}


@mcp.tool()
@tool_access(_REASONING_WRITE_ROLES)
@audited_tool("resolve_contradiction")
def resolve_contradiction(
    contradiction_id: str,
    disposition: Literal["resolved", "accepted_risk", "not_material"],
    rationale: str,
    actor_id: str,
) -> dict[str, object]:
    """Append the immutable resolution for a recorded contradiction."""
    result = get_ctx().db.record_reasoning(
        ResolveContradiction(
            contradiction_id=contradiction_id,
            disposition=disposition,
            rationale=rationale,
            actor_id=actor_id,
        )
    )
    return {"status": "success", "resolution": result.model_dump(mode="json")}


@mcp.tool()
@tool_access(_REASONING_WRITE_ROLES)
@audited_tool("record_review_verdict")
def record_review_verdict(
    seat: Literal["citation", "tool_semantics", "contradiction", "inference", "scope"],
    target_kind: Literal["case", "finding", "claim", "hypothesis", "contradiction"],
    target_id: str,
    verdict: Literal["pass", "concern", "fail", "abstain"],
    rationale: str,
    reviewer_id: str,
    material: bool = False,
    claim_ids: list[str] | None = None,
    tool_call_ids: list[str] | None = None,
) -> dict[str, object]:
    """Append one specialist verdict; seats never vote claim state into truth."""
    result = get_ctx().db.record_reasoning(
        RecordReviewVerdict(
            seat=seat,
            target_kind=target_kind,
            target_id=target_id,
            verdict=verdict,
            rationale=rationale,
            reviewer_id=reviewer_id,
            material=material,
            claim_ids=tuple(claim_ids or ()),
            tool_call_ids=tuple(tool_call_ids or ()),
        )
    )
    return {"status": "success", "review_verdict": result.model_dump(mode="json")}


@mcp.tool()
@tool_access(_REASONING_READ_ROLES)
@audited_tool("get_reasoning_review")
def get_reasoning_review() -> dict[str, object]:
    """Return hypotheses, contradictions, and all five separate reviewer seats."""
    projection = get_ctx().db.get_reasoning_review()
    return {"status": "success", "review": projection.model_dump(mode="json")}
