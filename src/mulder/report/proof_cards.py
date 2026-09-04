"""Per-finding proof cards assembled from durable case records."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass

from mulder.models import (
    AtomicClaim,
    ClaimVerification,
    CoverageRecord,
    Finding,
    FindingRevision,
)


@dataclass(frozen=True)
class ReceiptState:
    """Receipt facts known when a report is rendered.

    Reports normally precede sealing, so ``pending_seal`` is honest and avoids
    a circular report -> manifest -> report commitment.  A separately rendered
    proof card may instead carry the result of a completed verification.
    """

    status: str = "pending_seal"
    signature_status: str = "not_sealed"
    manifest_hash: str | None = None
    audit_head: str | None = None
    public_key_fingerprint: str | None = None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def build_proof_cards(
    findings: Sequence[Finding],
    *,
    claims: Mapping[str, Sequence[AtomicClaim]],
    verifications: Mapping[str, Sequence[ClaimVerification]],
    revisions: Mapping[str, Sequence[FindingRevision]],
    coverage_records: Sequence[CoverageRecord],
    receipt_state: ReceiptState | None = None,
) -> list[dict[str, object]]:
    """Build stable, JSON-safe proof-card data for each visible finding."""
    receipt = (receipt_state or ReceiptState()).as_dict()
    cards: list[dict[str, object]] = []
    for finding in findings:
        finding_claims = claims.get(finding.finding_id, ())
        verification_by_claim: dict[str, list[dict[str, object]]] = {}
        for verification in verifications.get(finding.finding_id, ()):
            verification_by_claim.setdefault(verification.claim_id, []).append(
                verification.model_dump(mode="json")
            )
        claim_data: list[dict[str, object]] = []
        for claim in finding_claims:
            data = claim.model_dump(mode="json")
            data["verifications"] = verification_by_claim.get(claim.claim_id, [])
            claim_data.append(data)

        relevant_coverage = [
            record.model_dump(mode="json")
            for record in coverage_records
            if record.source_name in finding.sources
            or record.tool_call_id in finding.evidence_refs
            or (
                finding.negative_verdict is not None
                and record.key in finding.negative_verdict.scope
            )
        ]
        cards.append(
            {
                "schema": "mulder.finding-proof-card",
                "version": 1,
                "finding": {
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "evidence_refs": list(finding.evidence_refs),
                    "sources": list(finding.sources),
                },
                "claims": claim_data,
                "revisions": [
                    revision.model_dump(mode="json")
                    for revision in revisions.get(finding.finding_id, ())
                ],
                "coverage": relevant_coverage,
                "receipt": dict(receipt),
            }
        )
    return cards
