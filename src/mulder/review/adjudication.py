"""Explicit, auditable finding-withdrawal policies used by review workflows."""

from __future__ import annotations

from typing import Literal

from mulder.models import Finding, FindingRevision

ReviewStage = Literal["candidate_filters", "alternative_narrative", "blind_reviewer"]

_REASON_STAGES: dict[str, ReviewStage] = {
    "candidate_filter_rejected": "candidate_filters",
    "alternative_narrative_refuted": "alternative_narrative",
    "blind_review_rejected": "blind_reviewer",
}


def withdrawal_stage(revision: FindingRevision | None) -> ReviewStage | None:
    """Return the production stage explicitly encoded by a withdrawal reason."""
    if revision is None or not revision.tombstone:
        return None
    return _REASON_STAGES.get(revision.reason_code)


def apply_alternative_narrative_review(
    finding: Finding, revision: FindingRevision | None
) -> bool:
    """Apply a persisted counter-analysis refutation to its exact finding."""
    return _applies(finding, revision, "alternative_narrative")


def apply_blind_review(finding: Finding, revision: FindingRevision | None) -> bool:
    """Apply a persisted independent blind-review rejection to its exact finding."""
    return _applies(finding, revision, "blind_reviewer")


def _applies(
    finding: Finding,
    revision: FindingRevision | None,
    expected_stage: ReviewStage,
) -> bool:
    if revision is None:
        return False
    if revision.finding_id != finding.finding_id:
        raise ValueError("review withdrawal belongs to a different finding")
    if withdrawal_stage(revision) != expected_stage:
        return False
    expected_actor = {
        "alternative_narrative": "investigator",
        "blind_reviewer": "blind_reviewer",
    }.get(expected_stage)
    return expected_actor is None or revision.actor_kind == expected_actor
