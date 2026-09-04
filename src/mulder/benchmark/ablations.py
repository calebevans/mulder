"""Executable, offline ablations over auditable benchmark workflow traces.

This module deliberately operates only on normalized benchmark objects.  It is
not imported by the production investigation runner and cannot change Mulder's
production safety defaults.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Literal

from mulder.benchmark.anchors import canonical_anchor_id
from mulder.benchmark.models import (
    AblationExecutionReceipt,
    AblationTarget,
    BenchmarkRunResult,
    BenchmarkStage,
    CaseRunResult,
    CaseWorkflowTrace,
    ClaimRevision,
    ObservedClaim,
    ResourceUsage,
    RunIdentity,
    Verdict,
    VerificationState,
    WorkflowCandidate,
)
from mulder.models import AtomicClaim, Finding, ToolOutcomeStatus
from mulder.review.adjudication import (
    apply_alternative_narrative_review,
    apply_blind_review,
    withdrawal_stage,
)
from mulder.review.candidates import group_duplicate_findings, representative_finding
from mulder.verification.claims import verify_claim
from mulder.verification.policy import assess_confirmation

STAGE_ORDER: tuple[BenchmarkStage, ...] = (
    "candidate_filters",
    "verifier",
    "independence_gate",
    "blind_reviewer",
)
TARGET_TO_STAGE: dict[AblationTarget, BenchmarkStage] = {
    "without-candidate-filters": "candidate_filters",
    "without-verifier": "verifier",
    "without-independence-gate": "independence_gate",
    "without-blind-reviewer": "blind_reviewer",
}
ABLATION_CHOICES = tuple(TARGET_TO_STAGE)


def _canonical_hash(value: object) -> str:
    payload = json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _result_hash(result: BenchmarkRunResult) -> str:
    return _canonical_hash(result.model_dump(mode="json"))


def _workflow_hash(traces: list[CaseWorkflowTrace]) -> str:
    return _canonical_hash([trace.model_dump(mode="json") for trace in traces])


def _replay(
    trace: CaseWorkflowTrace, disabled: frozenset[BenchmarkStage]
) -> tuple[list[ObservedClaim], list[ClaimRevision]]:
    # The concrete claim type remains encoded by the Pydantic objects. Keeping
    # the list stable preserves deterministic result ordering.
    claims: list[ObservedClaim] = list(trace.input_claims)
    revisions: list[ClaimRevision] = []
    for stage in trace.stages:
        if stage.stage in disabled:
            continue
        for operation in stage.operations:
            matching = [
                index for index, claim in enumerate(claims) if claim.claim_id == operation.claim_id
            ]
            if len(matching) != 1:
                raise ValueError(
                    f"workflow {trace.case_id!r} stage {stage.stage!r} references absent "
                    f"claim {operation.claim_id!r}"
                )
            index = matching[0]
            before = claims[index]
            if operation.action == "remove_claim":
                del claims[index]
            elif operation.action == "set_verification_state":
                assert operation.verification_state is not None
                claims[index] = before.model_copy(
                    update={"verification_state": operation.verification_state}
                )
            else:
                assert operation.replacement is not None
                assert operation.revision_id is not None
                assert operation.iteration is not None
                assert operation.reason is not None
                after = operation.replacement.model_copy(
                    update={"verification_state": before.verification_state}
                )
                claims[index] = after
                revisions.append(
                    ClaimRevision(
                        revision_id=operation.revision_id,
                        claim_id=operation.claim_id,
                        iteration=operation.iteration,
                        stage=stage.stage,
                        before=before,
                        after=after,
                        reason=operation.reason,
                    )
                )
    return claims, revisions


def _effective_finding(candidate: WorkflowCandidate) -> Finding:
    current = candidate.finding
    for revision in candidate.finding_revisions:
        if not revision.tombstone:
            current = revision.snapshot
    return current


def _observed(
    candidate: WorkflowCandidate,
    state: VerificationState,
    *,
    finding: Finding | None = None,
) -> ObservedClaim:
    finding = finding or _effective_finding(candidate)
    severity = "informational" if finding.severity == "info" else finding.severity
    return ObservedClaim(
        claim_id=candidate.claim.claim_id,
        subject=candidate.claim.subject,
        predicate=candidate.claim.predicate,
        object_value=candidate.claim.object_value,
        qualifiers=candidate.claim.qualifiers,
        verification_state=state,
        citations=sorted(
            canonical_anchor_id(anchor)
            for anchor in candidate.claim.anchors
            if anchor.role == "supports"
        ),
        confidence=candidate.confidence_probability,
        severity=severity,
    )


def _real_case_execution(
    trace: CaseWorkflowTrace,
    disabled: frozenset[BenchmarkStage],
) -> tuple[CaseRunResult, dict[BenchmarkStage, int]]:
    """Execute actual deterministic Mulder policies over bounded domain inputs."""
    if trace.trace_version != 2:
        raise ValueError("new executable ablations require v2 real-component traces")
    if trace.failure_reason is not None:
        return (
            CaseRunResult(
                case_id=trace.case_id,
                verdict="no_verdict",
                cell_status="failed",
                failure_reason=trace.failure_reason,
            ),
            {stage: 0 for stage in STAGE_ORDER},
        )
    candidates = {item.claim.claim_id: item for item in trace.candidates}
    effective_findings = {
        claim_id: _effective_finding(candidate) for claim_id, candidate in candidates.items()
    }
    claims = {
        claim_id: _observed(candidate, "unverified", finding=candidate.finding)
        for claim_id, candidate in candidates.items()
    }
    revisions: list[ClaimRevision] = []
    iterations: dict[str, int] = {}
    counts: dict[BenchmarkStage, int] = {stage: 0 for stage in STAGE_ORDER}

    def transition(
        claim_id: str,
        *,
        stage: str,
        after: ObservedClaim | None,
        reason: str,
        source_revision_id: str | None = None,
        revision_id: str | None = None,
    ) -> None:
        before = claims.get(claim_id)
        if before is None:
            raise ValueError(f"stage {stage!r} references absent claim {claim_id!r}")
        iteration = iterations.get(claim_id, 0) + 1
        iterations[claim_id] = iteration
        emitted_revision_id = (
            revision_id or source_revision_id or f"benchmark:{stage}:{claim_id}:{iteration}"
        )
        revisions.append(
            ClaimRevision(
                revision_id=emitted_revision_id,
                claim_id=claim_id,
                iteration=iteration,
                stage=stage,
                source_revision_id=source_revision_id,
                before=before,
                after=after,
                tombstone=after is None,
                reason=reason,
            )
        )
        if stage in counts:
            counts[stage] += 1
        if after is None:
            del claims[claim_id]
        else:
            claims[claim_id] = after

    for claim_id in sorted(claims):
        candidate = candidates[claim_id]
        for revision in candidate.finding_revisions:
            if revision.tombstone:
                continue
            updated = claims[claim_id].model_copy(
                update={
                    "severity": (
                        "informational"
                        if revision.snapshot.severity == "info"
                        else revision.snapshot.severity
                    )
                }
            )
            transition(
                claim_id,
                stage="source_finding_revision",
                after=updated,
                reason=revision.reason_code,
                source_revision_id=revision.revision_id,
                revision_id=f"{revision.revision_id}:{claim_id}",
            )

    if "candidate_filters" not in disabled:
        findings_by_id = {finding.finding_id: finding for finding in effective_findings.values()}
        duplicate_groups = group_duplicate_findings(
            list(findings_by_id.values()), trace.candidate_similarity_threshold
        )
        retained_finding_ids = {
            representative_finding(group).finding_id for group in duplicate_groups
        }
        for claim_id, candidate in candidates.items():
            source_withdrawal = candidate.withdrawal_revision
            filtered_by_source = withdrawal_stage(source_withdrawal) == "candidate_filters"
            if candidate.finding.finding_id not in retained_finding_ids or filtered_by_source:
                transition(
                    claim_id,
                    stage="candidate_filters",
                    after=None,
                    reason=(
                        source_withdrawal.reason_code
                        if filtered_by_source and source_withdrawal is not None
                        else "production_duplicate_candidate_policy"
                    ),
                    source_revision_id=(
                        source_withdrawal.revision_id
                        if filtered_by_source and source_withdrawal is not None
                        else None
                    ),
                    revision_id=(
                        f"{source_withdrawal.revision_id}:{claim_id}"
                        if filtered_by_source and source_withdrawal is not None
                        else None
                    ),
                )

    if "verifier" not in disabled:
        for claim_id in sorted(claims):
            candidate = candidates[claim_id]
            semantic_decision = verify_claim(candidate.claim)
            decision = candidate.current_verification or semantic_decision
            if (
                candidate.current_verification is not None
                and not candidate.current_verification.reason_code.startswith("anchor_")
                and candidate.current_verification != semantic_decision
            ):
                raise ValueError(
                    f"current verification for {claim_id!r} disagrees with real verifier"
                )
            history = candidate.source_verifications
            if history:
                for source in history:
                    transition(
                        claim_id,
                        stage="verifier",
                        after=claims[claim_id].model_copy(
                            update={"verification_state": source.result}
                        ),
                        reason=source.reason_code,
                        source_revision_id=source.verification_id,
                    )
            if not history or (
                history[-1].result != decision.result
                or history[-1].reason_code != decision.reason_code
            ):
                transition(
                    claim_id,
                    stage="verifier",
                    after=claims[claim_id].model_copy(
                        update={"verification_state": decision.result}
                    ),
                    reason=decision.reason_code,
                )

    if "independence_gate" not in disabled:
        active_by_finding: dict[str, list[str]] = {}
        for claim_id in claims:
            finding_id = candidates[claim_id].finding.finding_id
            active_by_finding.setdefault(finding_id, []).append(claim_id)
        for claim_ids in active_by_finding.values():
            finding = effective_findings[claim_ids[0]]
            atomic = [
                AtomicClaim.model_validate(
                    {
                        **candidates[claim_id].claim.model_dump(mode="json"),
                        "epistemic_state": claims[claim_id].verification_state,
                    }
                )
                for claim_id in claim_ids
            ]
            assessment = assess_confirmation(atomic)
            if finding.confidence == "confirmed" and not assessment.accepted:
                reasons = {item.claim_id: item.reason_code for item in assessment.claims}
                for claim_id in claim_ids:
                    transition(
                        claim_id,
                        stage="independence_gate",
                        after=None,
                        reason=reasons[claim_id],
                    )

    if "alternative_narrative" not in disabled:
        for claim_id in sorted(tuple(claims)):
            withdrawal = candidates[claim_id].withdrawal_revision
            if apply_alternative_narrative_review(
                effective_findings[claim_id], withdrawal
            ):
                assert withdrawal is not None
                transition(
                    claim_id,
                    stage="alternative_narrative",
                    after=None,
                    reason=withdrawal.reason_code,
                    source_revision_id=withdrawal.revision_id,
                    revision_id=f"{withdrawal.revision_id}:{claim_id}",
                )

    if "blind_reviewer" not in disabled:
        for claim_id in sorted(tuple(claims)):
            withdrawal = candidates[claim_id].withdrawal_revision
            if apply_blind_review(effective_findings[claim_id], withdrawal):
                assert withdrawal is not None
                transition(
                    claim_id,
                    stage="blind_reviewer",
                    after=None,
                    reason=withdrawal.reason_code,
                    source_revision_id=withdrawal.revision_id,
                    revision_id=f"{withdrawal.revision_id}:{claim_id}",
                )

    ordered_claims = [claims[claim_id] for claim_id in sorted(claims)]
    has_verified = any(claim.verification_state == "verified" for claim in ordered_claims)
    completed_coverage = bool(trace.coverage) and all(
        item.status in {ToolOutcomeStatus.SUCCESS_EMPTY, ToolOutcomeStatus.SUCCESS_NONEMPTY}
        for item in trace.coverage
    )
    verdict: Verdict
    cell_status: Literal["completed", "no_verdict"]
    if has_verified:
        verdict = "positive"
        cell_status = "completed"
    elif ordered_claims or not completed_coverage:
        verdict = "no_verdict"
        cell_status = "no_verdict"
    else:
        verdict = "no_evil_within_coverage"
        cell_status = "completed"
    return (
        CaseRunResult(
            case_id=trace.case_id,
            verdict=verdict,
            cell_status=cell_status,
            claims=ordered_claims,
            coverage=[item.model_copy(deep=True) for item in trace.coverage],
            revisions=revisions,
        ),
        counts,
    )


def execute_workflow_base(trace: CaseWorkflowTrace) -> CaseRunResult:
    """Replay production components and persisted adjudications for a v2 case."""
    result, _ = _real_case_execution(trace, frozenset())
    return result


def _validated_base(result: BenchmarkRunResult) -> dict[str, CaseWorkflowTrace]:
    identity = result.identity
    if identity is None:
        raise ValueError("executable ablations require a stamped run identity")
    if identity.ablations or result.ablation_receipt is not None:
        raise ValueError("ablation input must be an unablated base result")
    if (
        not identity.models
        or identity.prompt_set_sha256 is None
        or identity.toolset_sha256 is None
    ):
        raise ValueError("executable ablations require model, prompt-set, and toolset stamps")
    traces = {trace.case_id: trace for trace in result.workflow_traces}
    if set(traces) != {case.case_id for case in result.cases}:
        raise ValueError("executable ablations require one complete trace per result case")
    if any(trace.trace_version != 2 for trace in traces.values()):
        raise ValueError("new executable ablations require v2 real-component traces")
    for case in result.cases:
        executed, _ = _real_case_execution(traces[case.case_id], frozenset())
        if executed != case:
            raise ValueError(
                f"real workflow for {case.case_id!r} does not reproduce the base result"
            )
    return traces


def _canonical_targets(targets: Iterable[str]) -> list[AblationTarget]:
    values = list(targets)
    if not values:
        raise ValueError("at least one executable ablation is required")
    if len(set(values)) != len(values):
        raise ValueError("executable ablations must be unique")
    unknown = sorted(set(values) - set(TARGET_TO_STAGE))
    if unknown:
        raise ValueError(f"unknown executable ablations: {unknown!r}")
    requested = set(values)
    return [target for target in TARGET_TO_STAGE if target in requested]


def execute_ablations(
    result: BenchmarkRunResult,
    targets: Iterable[str],
    *,
    run_id: str,
    matrix_cell: str,
) -> BenchmarkRunResult:
    """Execute real workflow components while skipping the requested stages."""
    traces = _validated_base(result)
    disabled_targets = _canonical_targets(targets)
    if run_id == result.run_id:
        raise ValueError("an ablation run_id must differ from its base result")
    assert result.identity is not None
    if matrix_cell == result.identity.matrix_cell:
        raise ValueError("an ablation matrix cell must differ from its base result")
    disabled_stages = frozenset(TARGET_TO_STAGE[target] for target in disabled_targets)
    new_cases: list[CaseRunResult] = []
    operation_counts: dict[str, dict[BenchmarkStage, int]] = {}
    for case in result.cases:
        trace = traces[case.case_id]
        executed, counts = _real_case_execution(trace, disabled_stages)
        new_cases.append(executed)
        operation_counts[case.case_id] = counts

    identity = result.identity
    new_identity = RunIdentity.model_validate(
        {
            **identity.model_dump(mode="json"),
            "matrix_cell": matrix_cell,
            "ablations": disabled_targets,
        }
    )
    receipt = AblationExecutionReceipt(
        base_run_id=result.run_id,
        base_matrix_cell=identity.matrix_cell,
        base_result_sha256=_result_hash(result),
        base_runtime_ms=result.resources.runtime_ms,
        base_input_tokens=result.resources.input_tokens,
        base_output_tokens=result.resources.output_tokens,
        base_unattributed_tokens=result.resources.unattributed_tokens,
        base_cost_usd=result.resources.cost_usd,
        workflow_sha256=_workflow_hash(result.workflow_traces),
        disabled=disabled_targets,
        executed_stages=[stage for stage in STAGE_ORDER if stage not in disabled_stages],
        skipped_stages=[stage for stage in STAGE_ORDER if stage in disabled_stages],
        case_operation_counts=operation_counts,
    )
    payload = result.model_dump(mode="json")
    payload.update(
        {
            "run_id": run_id,
            "identity": new_identity.model_dump(mode="json"),
            "cases": [case.model_dump(mode="json") for case in new_cases],
            "resources": ResourceUsage().model_dump(mode="json"),
            "ablation_receipt": receipt.model_dump(mode="json"),
        }
    )
    ablated = BenchmarkRunResult.model_validate(payload)
    validate_ablation_result(ablated)
    return ablated


def validate_ablation_result(result: BenchmarkRunResult) -> None:
    """Verify receipt bindings and the observable output of an ablated result."""
    receipt = result.ablation_receipt
    if receipt is None:
        return
    unsupported = sorted(set(receipt.disabled) - set(TARGET_TO_STAGE))
    if unsupported:
        raise ValueError(
            "ablation receipt references unsupported executable ablations: "
            f"{unsupported!r}"
        )
    disabled_stages = frozenset(TARGET_TO_STAGE[target] for target in receipt.disabled)
    expected_executed = [stage for stage in STAGE_ORDER if stage not in disabled_stages]
    expected_skipped = [stage for stage in STAGE_ORDER if stage in disabled_stages]
    if receipt.executed_stages != expected_executed or receipt.skipped_stages != expected_skipped:
        raise ValueError("ablation receipt has inconsistent executed/skipped stages")
    if receipt.workflow_sha256 != _workflow_hash(result.workflow_traces):
        raise ValueError("ablation receipt workflow hash does not match its traces")
    traces = {trace.case_id: trace for trace in result.workflow_traces}
    base_cases: list[CaseRunResult] = []
    for case in result.cases:
        trace = traces[case.case_id]
        if trace.trace_version == 2:
            executed, expected_counts = _real_case_execution(trace, disabled_stages)
            base_case, _ = _real_case_execution(trace, frozenset())
        else:
            claims, revisions = _replay(trace, disabled_stages)
            executed = case.model_copy(update={"claims": claims, "revisions": revisions})
            expected_counts = {stage.stage: len(stage.operations) for stage in trace.stages}
            base_claims, base_revisions = _replay(trace, frozenset())
            base_case = case.model_copy(
                update={"claims": base_claims, "revisions": base_revisions}
            )
        if receipt.case_operation_counts.get(case.case_id) != expected_counts:
            raise ValueError(f"ablation receipt operation counts disagree for {case.case_id!r}")
        if executed != case:
            raise ValueError(
                f"ablated workflow trace for {case.case_id!r} does not reproduce the result"
            )
        base_cases.append(base_case)
    if set(receipt.case_operation_counts) != set(traces):
        raise ValueError("ablation receipt case set does not match its traces")
    identity = result.identity
    assert identity is not None
    base_payload = result.model_dump(mode="json")
    base_payload.update(
        {
            "run_id": receipt.base_run_id,
            "identity": {
                **identity.model_dump(mode="json"),
                "matrix_cell": receipt.base_matrix_cell,
                "ablations": [],
            },
            "cases": [case.model_dump(mode="json") for case in base_cases],
            "resources": ResourceUsage(
                runtime_ms=receipt.base_runtime_ms,
                input_tokens=receipt.base_input_tokens,
                output_tokens=receipt.base_output_tokens,
                unattributed_tokens=receipt.base_unattributed_tokens,
                cost_usd=receipt.base_cost_usd,
            ).model_dump(mode="json"),
            "ablation_receipt": None,
        }
    )
    reconstructed_base = BenchmarkRunResult.model_validate(base_payload)
    if receipt.base_result_sha256 != _result_hash(reconstructed_base):
        raise ValueError("ablation receipt base result hash does not match reconstructed base")
