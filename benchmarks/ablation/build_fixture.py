#!/usr/bin/env python3
"""Build the deterministic real-component benchmark fixture."""

from __future__ import annotations

from pathlib import Path

from mulder.benchmark.ablations import execute_workflow_base
from mulder.benchmark.io import write_result
from mulder.benchmark.models import (
    AlternativeNarrativeWorkflowInput,
    BenchmarkRunResult,
    CaseWorkflowTrace,
    ObservedCoverage,
    ResourceUsage,
    RunIdentity,
    WorkflowCandidate,
    WorkflowGateCheck,
)
from mulder.models import (
    AtomicClaim,
    EvidenceAnchor,
    Finding,
    FindingRevision,
    ToolOutcomeStatus,
)


def _finding(
    finding_id: str,
    title: str,
    description: str,
    *,
    confidence: str,
    evidence_ref: str,
    source: str,
) -> Finding:
    return Finding.model_validate(
        {
            "finding_id": finding_id,
            "case_id": "staged-incident",
            "title": title,
            "description": description,
            "severity": "high",
            "confidence": confidence,
            "evidence_refs": [evidence_ref],
            "sources": [source],
            "submitted_at": "2026-01-01T00:00:00Z",
        }
    )


def _claim(
    finding: Finding,
    claim_id: str,
    subject: str,
    predicate: str,
    value: str,
    *,
    source_prefix: str,
    anchors: int,
) -> AtomicClaim:
    evidence = [
        EvidenceAnchor(
            anchor_id=f"anchor-{source_prefix}-{index}",
            claim_id=claim_id,
            tool_call_id=f"tc-{source_prefix}-{index}",
            source_id=index,
            source_name=f"{source_prefix}-{index}",
            source_hash=f"sha256:{source_prefix}-{index}",
            window_id=index,
            line_start=1,
            line_end=1,
            char_start=0,
            char_end=len(value),
            exact_text=value,
            artifact_family="fixture",
            extractor_family="fixture",
            independence_key=f"source:{source_prefix}-{index}",
            value_type="text",
        )
        for index in range(1, anchors + 1)
    ]
    return AtomicClaim(
        claim_id=claim_id,
        finding_id=finding.finding_id,
        ordinal=0,
        statement=f"{subject} {predicate} {value}",
        subject=subject,
        predicate=predicate,
        object_value=value,
        anchors=evidence,
    )


def _withdrawal(finding: Finding, actor: str, reason: str) -> FindingRevision:
    return FindingRevision.model_validate(
        {
            "revision_id": f"withdraw-{finding.finding_id}",
            "finding_id": finding.finding_id,
            "revision_number": 2,
            "parent_revision_id": f"initial-{finding.finding_id}",
            "state": "withdrawn",
            "snapshot": finding.model_dump(mode="json"),
            "actor_kind": actor,
            "reason_code": reason,
            "changed_fields": ["is_deleted"],
            "tombstone": True,
            "created_at": "2026-01-01T00:05:00Z",
        }
    )


def _initial_revision(finding: Finding) -> FindingRevision:
    return FindingRevision.model_validate(
        {
            "revision_id": f"initial-{finding.finding_id}",
            "finding_id": finding.finding_id,
            "revision_number": 1,
            "state": "confirmed" if finding.confidence == "confirmed" else "indicated",
            "snapshot": finding.model_dump(mode="json"),
            "actor_kind": "investigator",
            "reason_code": "finding_submitted",
            "changed_fields": list(type(finding).model_fields),
            "created_at": finding.submitted_at,
        }
    )


def build_result() -> BenchmarkRunResult:
    good = _finding(
        "finding-good",
        "Command process observed",
        "Detailed command process observation retained as representative.",
        confidence="confirmed",
        evidence_ref="tc-shared",
        source="shared-source",
    )
    duplicate = _finding(
        "finding-duplicate",
        "Duplicate process candidate",
        "Duplicate.",
        confidence="confirmed",
        evidence_ref="tc-shared",
        source="shared-source",
    )
    weak = _finding(
        "finding-weak",
        "Weak one-source assertion",
        "One source only.",
        confidence="confirmed",
        evidence_ref="tc-weak",
        source="weak-source",
    )
    alternative = _finding(
        "finding-alternative",
        "Competing destination narrative",
        "Counter-analysis refutes this destination.",
        confidence="inference",
        evidence_ref="tc-alternative",
        source="alternative-source",
    )
    blind = _finding(
        "finding-blind",
        "Blind-review false positive",
        "Independent review rejects this process.",
        confidence="inference",
        evidence_ref="tc-blind",
        source="blind-source",
    )
    initial = {
        finding.finding_id: _initial_revision(finding)
        for finding in (good, duplicate, weak, alternative, blind)
    }
    alternative_withdrawal = _withdrawal(
        alternative, "investigator", "alternative_narrative_refuted"
    )
    blind_withdrawal = _withdrawal(blind, "blind_reviewer", "blind_review_rejected")
    candidates = [
        WorkflowCandidate(
            finding=good,
            claim=_claim(
                good,
                "claim-good",
                "process:412",
                "image_name",
                "cmd.exe",
                source_prefix="good",
                anchors=2,
            ),
            confidence_probability=0.95,
            finding_revisions=[initial[good.finding_id]],
        ),
        WorkflowCandidate(
            finding=duplicate,
            claim=_claim(
                duplicate,
                "claim-duplicate",
                "process:412",
                "image_name",
                "cmd.exe",
                source_prefix="duplicate",
                anchors=2,
            ),
            confidence_probability=0.95,
            finding_revisions=[initial[duplicate.finding_id]],
        ),
        WorkflowCandidate(
            finding=weak,
            claim=_claim(
                weak,
                "claim-weak",
                "process:999",
                "image_name",
                "powershell.exe",
                source_prefix="weak",
                anchors=1,
            ),
            confidence_probability=0.8,
            finding_revisions=[initial[weak.finding_id]],
        ),
        WorkflowCandidate(
            finding=alternative,
            claim=_claim(
                alternative,
                "claim-alternative",
                "connection:412:443",
                "ip_equals",
                "198.51.100.10",
                source_prefix="alternative",
                anchors=1,
            ),
            confidence_probability=0.7,
            finding_revisions=[initial[alternative.finding_id], alternative_withdrawal],
            withdrawal_revision=alternative_withdrawal,
        ),
        WorkflowCandidate(
            finding=blind,
            claim=_claim(
                blind,
                "claim-blind",
                "process:777",
                "image_name",
                "evil.exe",
                source_prefix="blind",
                anchors=1,
            ),
            confidence_probability=0.75,
            finding_revisions=[initial[blind.finding_id], blind_withdrawal],
            withdrawal_revision=blind_withdrawal,
        ),
    ]
    trace = CaseWorkflowTrace(
        case_id="staged-incident",
        trace_version=2,
        candidates=candidates,
        coverage=[
            ObservedCoverage(domain="process_memory", status=ToolOutcomeStatus.SUCCESS_NONEMPTY)
        ],
        alternative_narrative=AlternativeNarrativeWorkflowInput(
            checks=[
                WorkflowGateCheck(
                    name="counter_analysis_complete",
                    passed=True,
                    detail="Bounded counter-analysis completed.",
                )
            ]
        ),
    )
    return BenchmarkRunResult(
        benchmark_id="mulder-executable-ablation-v1",
        run_id="real-component-base",
        system_name="mulder-real-component-fixture",
        system_version="1.1",
        identity=RunIdentity(
            matrix_cell="fixture/default",
            models={"analyst": "bounded-offline-adapter"},
            prompt_set_sha256="a" * 64,
            toolset_sha256="b" * 64,
            orchestrator_version="fixture-2",
            methodology_version="1.1",
            seed=7,
        ),
        cases=[execute_workflow_base(trace)],
        resources=ResourceUsage(runtime_ms=10, cost_usd=0.0),
        workflow_traces=[trace],
    )


def main() -> None:
    destination = Path(__file__).with_name("result-real-base-v2.json")
    write_result(destination, build_result())


if __name__ == "__main__":
    main()
