"""Read-only normalization of Mulder case databases into benchmark results."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from urllib.parse import quote

from mulder.benchmark.ablations import execute_workflow_base
from mulder.benchmark.anchors import canonical_anchor_id as canonical_anchor_id
from mulder.benchmark.models import (
    AlternativeNarrativeWorkflowInput,
    BenchmarkManifest,
    BenchmarkRunResult,
    CaseRunResult,
    CaseWorkflowTrace,
    ObservedCoverage,
    ResourceUsage,
    RunIdentity,
    WorkflowCandidate,
    WorkflowGateCheck,
)
from mulder.db import CaseDB
from mulder.models import ClaimVerification, FindingRevision


def canonical_coverage_domain(system: str, domain: str, check: str) -> str:
    """Encode a coverage-register key into an unambiguous manifest domain."""
    return "/".join(quote(part, safe="") for part in (system, domain, check))


def _extract_case_workflow(case_id: str, db_path: Path) -> tuple[CaseRunResult, CaseWorkflowTrace]:
    if not db_path.is_file():
        raise ValueError(f"case database does not exist: {db_path}")
    with CaseDB(db_path) as db:
        metadata = db.get_case_metadata()
        if metadata.case_id != case_id:
            raise ValueError(
                f"database case_id {metadata.case_id!r} does not match manifest case {case_id!r}"
            )
        active = {finding.finding_id: finding for finding in db.get_findings()}
        histories: dict[str, list[FindingRevision]] = {}
        for revision in db.get_all_finding_revisions():
            histories.setdefault(revision.finding_id, []).append(revision)
        candidates: list[WorkflowCandidate] = []
        for finding_id in sorted(set(active) | set(histories)):
            revisions = histories.get(finding_id, [])
            finding = revisions[0].snapshot if revisions else active[finding_id]
            current = active.get(finding_id) or next(
                revision.snapshot for revision in reversed(revisions) if not revision.tombstone
            )
            withdrawal = next(
                (revision for revision in reversed(revisions) if revision.tombstone),
                None,
            )
            verifications = db.get_claim_verifications(finding_id)
            by_claim: dict[str, list[ClaimVerification]] = {}
            for verification in verifications:
                by_claim.setdefault(verification.claim_id, []).append(verification)
            for claim in db.get_claims(finding_id):
                candidates.append(
                    WorkflowCandidate(
                        finding=finding,
                        claim=claim.model_copy(update={"epistemic_state": "unverified"}),
                        confidence_probability=(
                            0.95 if current.confidence == "confirmed" else 0.5
                        ),
                        source_verifications=by_claim.get(claim.claim_id, []),
                        finding_revisions=revisions,
                        withdrawal_revision=withdrawal,
                    )
                )

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

    trace = CaseWorkflowTrace(
        case_id=case_id,
        trace_version=2,
        candidates=candidates,
        coverage=sorted(coverage, key=lambda item: item.domain),
        alternative_narrative=AlternativeNarrativeWorkflowInput(
            checks=[
                WorkflowGateCheck(
                    name="case_database_projection",
                    passed=True,
                    detail="Real CaseDB state was projected into the bounded workflow.",
                )
            ]
        ),
    )
    return execute_workflow_base(trace), trace


def extract_case_result(case_id: str, db_path: Path) -> CaseRunResult:
    """Execute the real bounded benchmark workflow over one read-only case DB."""
    result, _ = _extract_case_workflow(case_id, db_path)
    return result


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
    workflow_traces: list[CaseWorkflowTrace] = []
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
            workflow_traces.append(
                CaseWorkflowTrace(
                    case_id=case_id,
                    trace_version=2,
                    failure_reason=failed_cases[case_id],
                )
            )
        else:
            case, trace = _extract_case_workflow(case_id, case_databases[case_id])
            cases.append(case)
            workflow_traces.append(trace)
    return BenchmarkRunResult(
        benchmark_id=manifest.benchmark_id,
        run_id=run_id,
        system_name=system_name,
        system_version=system_version,
        identity=identity,
        cases=cases,
        resources=resources,
        workflow_traces=workflow_traces,
    )
