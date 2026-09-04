"""Server-owned policy for promoting atomic claims to confirmed findings."""

from __future__ import annotations

from collections.abc import Sequence

from mulder.models import (
    AtomicClaim,
    ClaimConfirmation,
    ConfirmationAssessment,
)

DEFAULT_MIN_INDEPENDENT_SOURCES = 2
_SINGLE_WITNESS_PREDICATES = frozenset({"hash_equals"})


def assess_confirmation(
    claims: Sequence[AtomicClaim],
    *,
    min_independent_sources: int = DEFAULT_MIN_INDEPENDENT_SOURCES,
    min_independent_acquisitions: int = 1,
    min_independent_extractors: int = 1,
) -> ConfirmationAssessment:
    """Decide whether every claim is verified and independently corroborated.

    Independence keys are resolved from root source hashes by the case store,
    never accepted from the model-facing submission. Contradicting anchors do
    not count toward corroboration.
    """
    if min_independent_sources < 1:
        raise ValueError("min_independent_sources must be at least one")
    if min_independent_acquisitions < 1:
        raise ValueError("min_independent_acquisitions must be at least one")
    if min_independent_extractors < 1:
        raise ValueError("min_independent_extractors must be at least one")
    decisions: list[ClaimConfirmation] = []
    for claim in claims:
        artifacts = {
            anchor.artifact_independence_key or anchor.independence_key
            for anchor in claim.anchors
            if anchor.role == "supports"
        }
        acquisitions = {
            anchor.acquisition_independence_key or f"legacy-acquisition:{anchor.source_id}"
            for anchor in claim.anchors
            if anchor.role == "supports"
        }
        extractors = {
            anchor.extractor_independence_key or f"extractor:{anchor.extractor_family}"
            for anchor in claim.anchors
            if anchor.role == "supports"
        }
        observations = {
            anchor.observation_independence_key
            or (
                f"legacy-observation:{anchor.source_id}:{anchor.window_id}:"
                f"{anchor.char_start}-{anchor.char_end}"
            )
            for anchor in claim.anchors
            if anchor.role == "supports"
        }
        predicate = claim.predicate.strip().lower()
        required = (
            1
            if not claim.material or predicate in _SINGLE_WITNESS_PREDICATES
            else min_independent_sources
        )
        policy_id = (
            "nonmaterial-single-observation-v2"
            if not claim.material
            else "cryptographic-single-artifact-v2"
            if predicate in _SINGLE_WITNESS_PREDICATES
            else "material-two-artifact-v2"
        )
        requirements = {
            "artifact": required,
            "acquisition": 1 if required == 1 else min_independent_acquisitions,
            "extractor": 1 if required == 1 else min_independent_extractors,
            "observation": required,
        }
        dimensions = {
            "artifact": len(artifacts),
            "acquisition": len(acquisitions),
            "extractor": len(extractors),
            "observation": len(observations),
        }
        deficient = sorted(
            name for name, threshold in requirements.items() if dimensions[name] < threshold
        )
        if claim.epistemic_state != "verified":
            accepted = False
            reason = f"claim_{claim.epistemic_state}"
        elif deficient:
            accepted = False
            reason = "insufficient_independence:" + ",".join(deficient)
        else:
            accepted = True
            reason = "verified_and_independently_corroborated"
        decisions.append(
            ClaimConfirmation(
                claim_id=claim.claim_id,
                accepted=accepted,
                reason_code=reason,
                independent_sources=len(artifacts),
                required_sources=required,
                policy_id=policy_id,
                independence_dimensions=dimensions,
                required_independence_dimensions=requirements,
            )
        )
    return ConfirmationAssessment(
        accepted=bool(decisions) and all(item.accepted for item in decisions),
        claims=decisions,
    )
