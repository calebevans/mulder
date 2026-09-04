"""Executable, offline ablations over auditable benchmark workflow traces.

This module deliberately operates only on normalized benchmark objects.  It is
not imported by the production investigation runner and cannot change Mulder's
production safety defaults.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from mulder.benchmark.models import (
    AblationExecutionReceipt,
    AblationTarget,
    BenchmarkRunResult,
    BenchmarkStage,
    CaseRunResult,
    CaseWorkflowTrace,
    ClaimRevision,
    ObservedClaim,
    RunIdentity,
)

STAGE_ORDER: tuple[BenchmarkStage, ...] = (
    "candidate_filters",
    "verifier",
    "independence_gate",
    "alternative_narrative",
    "blind_reviewer",
)
TARGET_TO_STAGE: dict[AblationTarget, BenchmarkStage] = {
    "without-candidate-filters": "candidate_filters",
    "without-verifier": "verifier",
    "without-independence-gate": "independence_gate",
    "without-alternative-narrative": "alternative_narrative",
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
                index
                for index, claim in enumerate(claims)
                if claim.claim_id == operation.claim_id
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
    for case in result.cases:
        claims, revisions = _replay(traces[case.case_id], frozenset())
        if claims != case.claims or revisions != case.revisions:
            raise ValueError(
                f"workflow trace for {case.case_id!r} does not reproduce the base result"
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
    """Replay a complete trace while actually skipping the requested stages."""
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
        claims, revisions = _replay(trace, disabled_stages)
        new_cases.append(
            case.model_copy(update={"claims": claims, "revisions": revisions})
        )
        operation_counts[case.case_id] = {
            stage.stage: len(stage.operations) for stage in trace.stages
        }

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
        expected_counts = {stage.stage: len(stage.operations) for stage in trace.stages}
        if receipt.case_operation_counts.get(case.case_id) != expected_counts:
            raise ValueError(f"ablation receipt operation counts disagree for {case.case_id!r}")
        claims, revisions = _replay(trace, disabled_stages)
        if claims != case.claims or revisions != case.revisions:
            raise ValueError(
                f"ablated workflow trace for {case.case_id!r} does not reproduce the result"
            )
        base_claims, base_revisions = _replay(trace, frozenset())
        base_cases.append(
            case.model_copy(update={"claims": base_claims, "revisions": base_revisions})
        )
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
            "ablation_receipt": None,
        }
    )
    reconstructed_base = BenchmarkRunResult.model_validate(base_payload)
    if receipt.base_result_sha256 != _result_hash(reconstructed_base):
        raise ValueError("ablation receipt base result hash does not match reconstructed base")
