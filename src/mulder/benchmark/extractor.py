"""Read-only normalization of Mulder case databases into benchmark results."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from mulder.benchmark.models import (
    BenchmarkManifest,
    BenchmarkRunResult,
    CaseRunResult,
    ObservedClaim,
    ObservedCoverage,
    ResourceUsage,
    RunIdentity,
    Verdict,
    VerificationState,
)
from mulder.db import CaseDB
from mulder.models import AtomicClaim, EvidenceAnchor


def canonical_anchor_id(anchor: EvidenceAnchor) -> str:
    """Build a stable citation ID from immutable source coordinates and content."""
    identity = {
        "source_name": anchor.source_name,
        "source_hash": anchor.source_hash,
        "line_start": anchor.line_start,
        "line_end": anchor.line_end,
        "char_start": anchor.char_start,
        "char_end": anchor.char_end,
        "exact_text_sha256": hashlib.sha256(anchor.exact_text.encode("utf-8")).hexdigest(),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "anchor:" + hashlib.sha256(encoded).hexdigest()


def canonical_coverage_domain(system: str, domain: str, check: str) -> str:
    """Encode a coverage-register key into an unambiguous manifest domain."""
    return "/".join(quote(part, safe="") for part in (system, domain, check))


def _verification_states(db: CaseDB, finding_id: str) -> dict[str, VerificationState]:
    latest = {item.claim_id: item for item in db.get_claim_verifications(finding_id)}
    states: dict[str, VerificationState] = {}
    for claim_id, decision in latest.items():
        if decision.reason_code == "unsupported_predicate":
            states[claim_id] = "unsupported"
        else:
            states[claim_id] = decision.result
    return states


def _observed_claim(claim: AtomicClaim, state: VerificationState) -> ObservedClaim:
    return ObservedClaim(
        claim_id=claim.claim_id,
        subject=claim.subject,
        predicate=claim.predicate,
        object_value=claim.object_value,
        qualifiers=claim.qualifiers,
        verification_state=state,
        citations=sorted(
            canonical_anchor_id(anchor) for anchor in claim.anchors if anchor.role == "supports"
        ),
    )


def extract_case_result(case_id: str, db_path: Path) -> CaseRunResult:
    """Extract one normalized result cell without migrating or writing the DB."""
    if not db_path.is_file():
        raise ValueError(f"case database does not exist: {db_path}")
    with CaseDB(db_path) as db:
        metadata = db.get_case_metadata()
        if metadata.case_id != case_id:
            raise ValueError(
                f"database case_id {metadata.case_id!r} does not match manifest case {case_id!r}"
            )
        findings = db.get_findings()
        observed_claims: list[ObservedClaim] = []
        for finding in findings:
            latest_states = _verification_states(db, finding.finding_id)
            for claim in db.get_claims(finding.finding_id):
                raw_state = latest_states.get(claim.claim_id, claim.epistemic_state)
                state: VerificationState = (
                    raw_state
                    if raw_state
                    in {
                        "verified",
                        "contradicted",
                        "inconclusive",
                        "unsupported",
                        "unverified",
                    }
                    else "unverified"
                )
                observed_claims.append(_observed_claim(claim, state))

        coverage = [
            ObservedCoverage(
                domain=canonical_coverage_domain(
                    record.key.system_name,
                    record.key.evidence_domain,
                    record.key.check_name,
                ),
                status=record.outcome.status,
            )
            for record in db.get_coverage()
        ]

    positive = any(
        not finding.title.startswith("[NEGATIVE]") and finding.negative_verdict is None
        for finding in findings
    )
    scoped_negative = any(finding.negative_verdict is not None for finding in findings)
    if positive:
        verdict: Verdict = "positive"
        cell_status: Literal["completed", "failed", "no_verdict"] = "completed"
    elif scoped_negative:
        verdict = "no_evil_within_coverage"
        cell_status = "completed"
    else:
        verdict = "no_verdict"
        cell_status = "no_verdict"
    return CaseRunResult(
        case_id=case_id,
        verdict=verdict,
        cell_status=cell_status,
        claims=sorted(observed_claims, key=lambda claim: claim.claim_id),
        coverage=sorted(coverage, key=lambda item: item.domain),
    )


def extract_run_result(
    manifest: BenchmarkManifest,
    *,
    case_databases: Mapping[str, Path],
    failed_cases: Mapping[str, str],
    run_id: str,
    system_name: str,
    system_version: str,
    identity: RunIdentity,
    resources: ResourceUsage,
) -> BenchmarkRunResult:
    """Normalize a complete benchmark run from DB cells and explicit failures."""
    overlap = set(case_databases) & set(failed_cases)
    if overlap:
        raise ValueError(f"cases cannot be both databases and failures: {sorted(overlap)!r}")
    expected = {case.case_id for case in manifest.cases}
    supplied = set(case_databases) | set(failed_cases)
    if supplied != expected:
        raise ValueError(
            "case inputs must exactly match the manifest; "
            f"missing={sorted(expected - supplied)!r}, unexpected={sorted(supplied - expected)!r}"
        )
    cases: list[CaseRunResult] = []
    for case_id in sorted(expected):
        if case_id in failed_cases:
            cases.append(
                CaseRunResult(
                    case_id=case_id,
                    verdict="no_verdict",
                    cell_status="failed",
                    failure_reason=failed_cases[case_id],
                )
            )
        else:
            cases.append(extract_case_result(case_id, case_databases[case_id]))
    return BenchmarkRunResult(
        benchmark_id=manifest.benchmark_id,
        run_id=run_id,
        system_name=system_name,
        system_version=system_version,
        identity=identity,
        cases=cases,
        resources=resources,
    )
