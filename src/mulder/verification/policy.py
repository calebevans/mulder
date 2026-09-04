"""Server-owned policy for promoting atomic claims to confirmed findings."""

from __future__ import annotations

from collections.abc import Sequence

from mulder.models import (
    AtomicClaim,
    ClaimConfirmation,
    ConfirmationAssessment,
)

DEFAULT_MIN_INDEPENDENT_SOURCES = 2


def assess_confirmation(
    claims: Sequence[AtomicClaim],
    *,
    min_independent_sources: int = DEFAULT_MIN_INDEPENDENT_SOURCES,
) -> ConfirmationAssessment:
    """Decide whether every claim is verified and independently corroborated.

    Independence keys are resolved from root source hashes by the case store,
    never accepted from the model-facing submission. Contradicting anchors do
    not count toward corroboration.
    """
    if min_independent_sources < 1:
        raise ValueError("min_independent_sources must be at least one")
    decisions: list[ClaimConfirmation] = []
    for claim in claims:
        independent = {
            anchor.independence_key
            for anchor in claim.anchors
            if anchor.role == "supports"
        }
        if claim.epistemic_state != "verified":
            accepted = False
            reason = f"claim_{claim.epistemic_state}"
        elif len(independent) < min_independent_sources:
            accepted = False
            reason = "insufficient_independent_sources"
        else:
            accepted = True
            reason = "verified_and_independently_corroborated"
        decisions.append(
            ClaimConfirmation(
                claim_id=claim.claim_id,
                accepted=accepted,
                reason_code=reason,
                independent_sources=len(independent),
                required_sources=min_independent_sources,
            )
        )
    return ConfirmationAssessment(
        accepted=bool(decisions) and all(item.accepted for item in decisions),
        claims=decisions,
    )
