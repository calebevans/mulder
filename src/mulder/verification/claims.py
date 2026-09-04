"""Deterministic semantic verification for atomic forensic claims.

The public interface is intentionally one function.  It accepts a claim whose
anchors have already been reopened and integrity-checked by the case store, and
returns a three-valued decision.  Predicate dispatch, normalization, conflict
handling, and reason codes remain local to this module.
"""

from __future__ import annotations

import ipaddress
import json
import math
from datetime import datetime

from mulder.models import AtomicClaim, EvidenceAnchor, JsonScalar, VerificationDecision

VERIFIER_NAME = "mulder.atomic"
VERIFIER_VERSION = "2"

_EQUALITY_PREDICATES = frozenset(
    {
        "equals",
        "eq",
        "image_name",
        "field_equals",
        "hash_equals",
        "ip_equals",
        "domain_equals",
        "path_equals",
        "timestamp_equals",
    }
)
_CONTAINS_PREDICATES = frozenset({"contains", "text_contains"})
_NUMERIC_PREDICATES = frozenset(
    {"greater_than", "greater_or_equal", "less_than", "less_or_equal"}
)
_TEMPORAL_PREDICATES = frozenset({"before", "after", "at_or_before", "at_or_after"})


def _normalize(value: JsonScalar, value_type: str) -> JsonScalar:
    """Normalize a scalar according to the server-owned anchor value type."""
    if value is None or isinstance(value, bool):
        return value
    kind = value_type.strip().lower()
    text = str(value).strip()
    if kind in {"integer", "int"}:
        return int(text, 0)
    if kind in {"number", "float"}:
        number = float(text)
        if not math.isfinite(number):
            raise ValueError("non-finite number")
        return number
    if kind in {"hash", "sha256", "md5", "sha1"}:
        return text.lower()
    if kind == "domain":
        return text.lower().rstrip(".")
    if kind == "ip":
        return str(ipaddress.ip_address(text))
    if kind in {"path", "windows_path"}:
        return text.replace("\\", "/").rstrip("/").casefold()
    if kind in {"timestamp", "datetime"}:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    return text


def _compare(predicate: str, observed: JsonScalar, expected: JsonScalar, value_type: str) -> bool:
    """Execute one supported predicate or raise ``KeyError`` if unsupported."""
    canonical = predicate.strip().lower()
    observed_n = _normalize(observed, value_type)
    expected_n = _normalize(expected, value_type)
    if canonical in _EQUALITY_PREDICATES:
        return observed_n == expected_n
    if canonical in _CONTAINS_PREDICATES:
        return str(expected_n) in str(observed_n)
    if canonical in _NUMERIC_PREDICATES:
        observed_f = float(str(observed_n))
        expected_f = float(str(expected_n))
        if canonical == "greater_than":
            return observed_f > expected_f
        if canonical == "greater_or_equal":
            return observed_f >= expected_f
        if canonical == "less_than":
            return observed_f < expected_f
        return observed_f <= expected_f
    if canonical in _TEMPORAL_PREDICATES:
        observed_dt = datetime.fromisoformat(str(observed_n))
        expected_dt = datetime.fromisoformat(str(expected_n))
        if canonical == "before":
            return observed_dt < expected_dt
        if canonical == "after":
            return observed_dt > expected_dt
        if canonical == "at_or_before":
            return observed_dt <= expected_dt
        return observed_dt >= expected_dt
    raise KeyError(canonical)


def _observed_value(anchor: EvidenceAnchor) -> JsonScalar:
    """Use deterministic normalization hints only when they match raw text."""
    # ``normalized_value`` is retained for display and later parser adapters,
    # but it is caller-supplied in the first schema version.  Verification is
    # deliberately based on exact source text until an adapter can attest the
    # normalized field.
    return anchor.exact_text


def _verify_structured_predicate(claim: AtomicClaim) -> VerificationDecision | None:
    """Verify predicates whose semantics span values or multiple anchors."""
    predicate = claim.predicate.strip().lower()
    supporting = [anchor for anchor in claim.anchors if anchor.role == "supports"]
    if predicate in {"set_contains", "member_of"}:
        membership_matches: list[bool] = []
        for anchor in supporting:
            text = anchor.exact_text.strip()
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = [part.strip() for part in text.split(",")]
            values = parsed if isinstance(parsed, list | tuple | set) else [parsed]
            expected = _normalize(claim.object_value, anchor.value_type)
            membership_matches.append(
                any(_normalize(value, anchor.value_type) == expected for value in values)
            )
        return VerificationDecision(
            result=(
                "verified" if membership_matches and all(membership_matches) else "contradicted"
            ),
            reason_code="set_membership_matched"
            if membership_matches and all(membership_matches)
            else "set_membership_failed",
            details={"support_count": len(membership_matches)},
        )
    if predicate in {"within_range", "in_range"}:
        lower = claim.qualifiers.get("minimum")
        upper = claim.qualifiers.get("maximum")
        if lower is None or upper is None:
            return VerificationDecision(
                result="inconclusive",
                reason_code="range_bounds_missing",
            )
        try:
            expected = float(str(claim.object_value))
            values = [float(anchor.exact_text.strip()) for anchor in supporting]
            within = float(str(lower)) <= expected <= float(str(upper))
        except (TypeError, ValueError, OverflowError):
            return VerificationDecision(result="inconclusive", reason_code="normalization_failed")
        predicate_matched = bool(values) and all(value == expected for value in values) and within
        return VerificationDecision(
            result="verified" if predicate_matched else "contradicted",
            reason_code="range_matched" if predicate_matched else "range_mismatch",
        )
    if predicate == "bounded_cooccurrence":
        companion = claim.qualifiers.get("with")
        distance = claim.qualifiers.get("max_line_distance")
        if not isinstance(companion, str) or not isinstance(distance, int) or distance < 0:
            return VerificationDecision(
                result="inconclusive", reason_code="cooccurrence_bounds_missing"
            )
        subject = str(claim.object_value)
        same_source = len({anchor.source_id for anchor in supporting}) == 1
        lines = [anchor.line_start for anchor in supporting]
        combined = "\n".join(anchor.exact_text for anchor in supporting)
        predicate_matched = (
            bool(lines)
            and same_source
            and max(lines) - min(lines) <= distance
            and subject in combined
            and companion in combined
        )
        return VerificationDecision(
            result="verified" if predicate_matched else "contradicted",
            reason_code="bounded_cooccurrence_matched"
            if predicate_matched
            else "bounded_cooccurrence_failed",
        )
    if predicate == "process_ancestry":
        ancestor = claim.qualifiers.get("ancestor")
        descendant = claim.qualifiers.get("descendant", claim.object_value)
        if not isinstance(ancestor, str) or not isinstance(descendant, str):
            return VerificationDecision(
                result="inconclusive", reason_code="ancestry_nodes_missing"
            )
        records: dict[tuple[int, int], set[str]] = {}
        for anchor in supporting:
            records.setdefault((anchor.source_id, anchor.window_id), set()).add(
                anchor.exact_text.strip()
            )
        predicate_matched = any(
            ancestor in observations and descendant in observations
            for observations in records.values()
        )
        return VerificationDecision(
            result="verified" if predicate_matched else "contradicted",
            reason_code=(
                "process_ancestry_matched" if predicate_matched else "process_ancestry_failed"
            ),
            details={"co_record_count": len(records)},
        )
    if predicate == "cross_source_identity":
        try:
            normalized = {
                _normalize(anchor.exact_text, anchor.value_type) for anchor in supporting
            }
            expected = _normalize(claim.object_value, supporting[0].value_type)
        except (IndexError, TypeError, ValueError, OverflowError):
            return VerificationDecision(result="inconclusive", reason_code="normalization_failed")
        independent = {
            anchor.artifact_independence_key or anchor.independence_key for anchor in supporting
        }
        predicate_matched = len(independent) >= 2 and normalized == {expected}
        return VerificationDecision(
            result="verified" if predicate_matched else "contradicted",
            reason_code="cross_source_identity_matched"
            if predicate_matched
            else "cross_source_identity_failed",
            details={"independent_artifacts": len(independent)},
        )
    return None


def verify_claim(claim: AtomicClaim) -> VerificationDecision:
    """Verify one atomic claim against its integrity-checked exact anchors.

    All selected supporting observations must satisfy the predicate. A selected
    contradictory observation satisfying it refutes the claim. Unsupported or
    unparseable semantics produce ``inconclusive`` rather than an optimistic
    false/true coercion.
    """
    structured = _verify_structured_predicate(claim)
    if structured is not None:
        return structured
    supports: list[bool] = []
    contradictions: list[bool] = []
    try:
        for anchor in claim.anchors:
            matched = _compare(
                claim.predicate,
                _observed_value(anchor),
                claim.object_value,
                anchor.value_type,
            )
            if anchor.role == "contradicts":
                contradictions.append(matched)
            else:
                supports.append(matched)
    except KeyError:
        return VerificationDecision(
            result="inconclusive",
            reason_code="unsupported_predicate",
            details={"predicate": claim.predicate},
        )
    except (TypeError, ValueError, OverflowError) as exc:
        return VerificationDecision(
            result="inconclusive",
            reason_code="normalization_failed",
            details={"error": str(exc)},
        )

    if any(contradictions):
        return VerificationDecision(
            result="contradicted",
            reason_code="contradicting_anchor_matched",
            details={"support_count": len(supports), "contradiction_count": len(contradictions)},
        )
    if not supports:
        return VerificationDecision(
            result="inconclusive",
            reason_code="no_supporting_anchor",
            details={"contradiction_count": len(contradictions)},
        )
    if all(supports):
        return VerificationDecision(
            result="verified",
            reason_code="all_supporting_anchors_matched",
            details={"support_count": len(supports)},
        )
    return VerificationDecision(
        result="contradicted",
        reason_code="supporting_anchor_mismatch",
        details={"support_count": len(supports), "mismatch_count": supports.count(False)},
    )
