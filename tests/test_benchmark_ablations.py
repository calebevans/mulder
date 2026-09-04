"""Calibration, correction, and real-component benchmark ablation tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import mulder.benchmark.ablations as ablation_engine
from mulder.benchmark.ablations import execute_ablations, execute_workflow_base
from mulder.benchmark.io import load_manifest, load_result
from mulder.benchmark.models import BenchmarkRunResult, ClaimRevision
from mulder.benchmark.scorer import score_benchmark
from mulder.cli import cli

FIXTURES = Path(__file__).parents[1] / "benchmarks" / "ablation"
BASE_RESULT = FIXTURES / "result-real-base-v2.json"
TARGETS = (
    "without-candidate-filters",
    "without-verifier",
    "without-independence-gate",
    "without-alternative-narrative",
    "without-blind-reviewer",
)


def _single_revision_result(*, before: Any, after: Any | None, run_id: str) -> BenchmarkRunResult:
    base = load_result(BASE_RESULT)
    revision = ClaimRevision(
        revision_id=f"{run_id}-r1",
        claim_id=before.claim_id,
        iteration=1,
        stage="fixture_reviewer",
        before=before,
        after=after,
        tombstone=after is None,
        reason="Adversarial scoring regression.",
    )
    case = base.cases[0].model_copy(
        update={"claims": [] if after is None else [after], "revisions": [revision]}
    )
    return BenchmarkRunResult.model_validate(
        {
            **base.model_dump(mode="json"),
            "run_id": run_id,
            "cases": [case.model_dump(mode="json")],
            "workflow_traces": [],
        }
    )


def test_calibration_and_revision_metrics_are_deterministic() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    result = load_result(BASE_RESULT)

    first = score_benchmark(manifest, [result])
    second = score_benchmark(manifest, [result])
    assert first == second
    overall = first.runs[0].overall
    assert overall.confidence_calibration.model_dump() == {
        "count": 1,
        "mean_confidence": 0.95,
        "empirical_accuracy": 1.0,
        "brier_score": 0.0025,
        "expected_calibration_error": 0.05,
    }
    assert overall.severity_calibration.model_dump() == {
        "count": 1,
        "exact_matches": 1,
        "unmatched_predictions": 0,
        "exact_rate": 1.0,
        "mean_absolute_error": 0.0,
    }
    assert overall.revisions.model_dump() == {
        "revision_events": 13,
        "assertion_revisions": 8,
        "iterations_observed": 3,
        "errors_fixed": 4,
        "errors_introduced": 3,
        "correct_preserved": 0,
        "errors_persisted": 1,
        "net_errors_fixed": 1,
    }


@pytest.mark.parametrize(
    (
        "is_expected",
        "before_state",
        "after_state",
        "expected_fixed",
        "expected_introduced",
    ),
    [
        (True, "verified", "contradicted", 0, 1),
        (False, "verified", "contradicted", 1, 0),
        (True, "contradicted", "verified", 1, 0),
    ],
)
def test_same_proposition_state_changes_are_scored(
    is_expected: bool,
    before_state: str,
    after_state: str,
    expected_fixed: int,
    expected_introduced: int,
) -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    correct = load_result(BASE_RESULT).cases[0].claims[0]
    proposition = (
        correct
        if is_expected
        else correct.model_copy(update={"object_value": "false-positive.exe"})
    )
    before = proposition.model_copy(update={"verification_state": before_state})
    after = proposition.model_copy(update={"verification_state": after_state})
    changed = _single_revision_result(before=before, after=after, run_id="state-change")

    revisions = score_benchmark(manifest, [changed]).runs[0].overall.revisions
    assert revisions.errors_fixed == expected_fixed
    assert revisions.errors_introduced == expected_introduced


@pytest.mark.parametrize(
    ("is_expected", "expected_fixed", "expected_introduced"),
    [(False, 1, 0), (True, 0, 1)],
)
def test_removal_tombstones_score_fixed_and_introduced_errors(
    is_expected: bool,
    expected_fixed: int,
    expected_introduced: int,
) -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    correct = load_result(BASE_RESULT).cases[0].claims[0]
    before = (
        correct
        if is_expected
        else correct.model_copy(update={"object_value": "false-positive.exe"})
    )
    removed = _single_revision_result(before=before, after=None, run_id="removal")

    revisions = score_benchmark(manifest, [removed]).runs[0].overall.revisions
    assert revisions.errors_fixed == expected_fixed
    assert revisions.errors_introduced == expected_introduced
    assert removed.cases[0].revisions[0].tombstone is True


def test_duplicate_propositions_do_not_reweight_calibration() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    base = load_result(BASE_RESULT)
    claim = base.cases[0].claims[0]
    duplicate = claim.model_copy(update={"claim_id": "duplicate-id"})
    duplicated_case = base.cases[0].model_copy(
        update={"claims": [claim, duplicate], "revisions": []}
    )
    duplicated = base.model_copy(
        update={"run_id": "duplicate", "cases": [duplicated_case], "workflow_traces": []}
    )

    score = score_benchmark(manifest, [duplicated]).runs[0].overall
    assert score.atomic_claims.true_positive == 1
    assert score.duplicate_claims == 1
    assert score.confidence_calibration.count == 1
    assert score.severity_calibration.count == 1

    for conflicting in (
        duplicate.model_copy(update={"confidence": 0.1}),
        duplicate.model_copy(update={"confidence": None}),
        duplicate.model_copy(update={"severity": "low"}),
        duplicate.model_copy(update={"severity": None}),
    ):
        case = duplicated_case.model_copy(update={"claims": [claim, conflicting]})
        result = duplicated.model_copy(update={"cases": [case]})
        with pytest.raises(ValueError, match="duplicate propositions have conflicting"):
            score_benchmark(manifest, [result])


def test_unattached_revision_history_is_rejected() -> None:
    result = load_result(BASE_RESULT)
    payload = result.cases[0].model_dump(mode="json")
    revision = next(item for item in payload["revisions"] if item["claim_id"] == "claim-good")
    revision["after"]["object_value"] = "unpublished.exe"
    with pytest.raises(ValueError, match="revision before/after|last claim revision"):
        type(result.cases[0]).model_validate(payload)


def test_bounded_workflow_calls_real_mulder_components(monkeypatch: pytest.MonkeyPatch) -> None:
    trace = load_result(BASE_RESULT).workflow_traces[0]
    calls = {"candidate": 0, "verifier": 0, "independence": 0, "narrative": 0}

    def spy(name: str, target: Any) -> Any:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            calls[name] += 1
            return target(*args, **kwargs)

        return wrapped

    monkeypatch.setattr(
        ablation_engine,
        "group_duplicate_findings",
        spy("candidate", ablation_engine.group_duplicate_findings),
    )
    monkeypatch.setattr(
        ablation_engine,
        "verify_claim",
        spy("verifier", ablation_engine.verify_claim),
    )
    monkeypatch.setattr(
        ablation_engine,
        "assess_confirmation",
        spy("independence", ablation_engine.assess_confirmation),
    )
    monkeypatch.setattr(
        ablation_engine,
        "validate_narrative",
        spy("narrative", ablation_engine.validate_narrative),
    )

    result = execute_workflow_base(trace)

    assert all(count > 0 for count in calls.values())
    assert [claim.claim_id for claim in result.claims] == ["claim-good"]
    assert {revision.stage for revision in result.revisions} == {
        "source_finding_revision",
        "candidate_filters",
        "verifier",
        "independence_gate",
        "alternative_narrative",
        "blind_reviewer",
    }
    assert any(
        revision.stage == "blind_reviewer"
        and revision.source_revision_id == "withdraw-finding-blind"
        and revision.tombstone
        for revision in result.revisions
    )


@pytest.mark.parametrize("target", TARGETS)
def test_each_ablation_actually_skips_its_stage_and_emits_a_receipt(target: str) -> None:
    base = load_result(BASE_RESULT)
    result = execute_ablations(
        base,
        [target],
        run_id=f"fixture-{target}",
        matrix_cell=f"fixture/{target}",
    )

    receipt = result.ablation_receipt
    assert receipt is not None
    assert receipt.disabled == [target]
    assert len(receipt.skipped_stages) == 1
    skipped = receipt.skipped_stages[0]
    assert skipped not in receipt.executed_stages
    assert receipt.case_operation_counts["staged-incident"][skipped] == 0
    assert len(receipt.base_result_sha256) == 64
    assert len(receipt.workflow_sha256) == 64
    assert result.identity is not None
    assert result.identity.ablations == [target]
    assert result.resources.runtime_ms is None
    assert result.resources.total_tokens == 0
    assert result.resources.cost_usd is None


def test_ablation_matrix_has_real_stage_specific_effects() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    base = load_result(BASE_RESULT)
    results = {
        target: execute_ablations(
            base,
            [target],
            run_id=f"fixture-{target}",
            matrix_cell=f"fixture/{target}",
        )
        for target in TARGETS
    }

    def claim_ids(target: str) -> set[str]:
        return {claim.claim_id for claim in results[target].cases[0].claims}

    assert claim_ids("without-candidate-filters") == {"claim-good", "claim-duplicate"}
    assert results["without-verifier"].cases[0].verdict == "no_evil_within_coverage"
    assert claim_ids("without-verifier") == set()
    assert claim_ids("without-independence-gate") == {"claim-good", "claim-weak"}
    assert claim_ids("without-alternative-narrative") == {
        "claim-good",
        "claim-alternative",
    }
    assert claim_ids("without-blind-reviewer") == {"claim-good", "claim-blind"}

    scores = {run.run_id: run.overall for run in score_benchmark(manifest, results.values()).runs}
    assert scores["fixture-without-verifier"].atomic_claims.recall == 0.0
    assert scores["fixture-without-independence-gate"].atomic_claims.false_positive == 1
    assert scores["fixture-without-alternative-narrative"].atomic_claims.false_positive == 1
    assert scores["fixture-without-blind-reviewer"].atomic_claims.false_positive == 1


def test_ablation_engine_rejects_invalid_or_legacy_inputs() -> None:
    base = load_result(BASE_RESULT)
    with pytest.raises(ValueError, match="unique"):
        execute_ablations(base, [TARGETS[0], TARGETS[0]], run_id="x", matrix_cell="x")
    with pytest.raises(ValueError, match="unknown"):
        execute_ablations(base, ["label-only"], run_id="x", matrix_cell="x")

    missing_trace = base.model_copy(update={"workflow_traces": []})
    with pytest.raises(ValueError, match="one complete trace"):
        execute_ablations(missing_trace, [TARGETS[0]], run_id="x", matrix_cell="x")

    legacy = load_result(FIXTURES / "result-base.json")
    with pytest.raises(ValueError, match="v2 real-component"):
        execute_ablations(legacy, [TARGETS[0]], run_id="x", matrix_cell="x")

    result = execute_ablations(base, [TARGETS[0]], run_id="once", matrix_cell="once")
    with pytest.raises(ValueError, match="unablated base"):
        execute_ablations(result, [TARGETS[1]], run_id="twice", matrix_cell="twice")


def test_scorer_rejects_a_tampered_ablated_result() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    base = load_result(BASE_RESULT)
    result = execute_ablations(
        base,
        ["without-independence-gate"],
        run_id="without-independence-gate",
        matrix_cell="fixture/without-independence-gate",
    )
    payload = result.model_dump(mode="json")
    claim = next(
        item for item in payload["cases"][0]["claims"] if item["claim_id"] == "claim-weak"
    )
    claim["verification_state"] = "contradicted"
    revision = next(
        item
        for item in reversed(payload["cases"][0]["revisions"])
        if item["claim_id"] == "claim-weak"
    )
    revision["after"]["verification_state"] = "contradicted"
    tampered = BenchmarkRunResult.model_validate(payload)
    with pytest.raises(ValueError, match="does not reproduce"):
        score_benchmark(manifest, [tampered])


def test_benchmark_ablate_cli_writes_same_versioned_result_schema(tmp_path: Path) -> None:
    output = tmp_path / "ablated.json"
    invocation = CliRunner().invoke(
        cli,
        [
            "benchmark-ablate",
            str(BASE_RESULT),
            "--ablation",
            "without-alternative-narrative",
            "--run-id",
            "cli-ablation",
            "--matrix-cell",
            "fixture/cli-ablation",
            "--output",
            str(output),
        ],
    )
    assert invocation.exit_code == 0, invocation.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["identity"]["ablations"] == ["without-alternative-narrative"]
    assert payload["ablation_receipt"]["skipped_stages"] == ["alternative_narrative"]


def test_export_refuses_to_stamp_an_executable_ablation_without_execution() -> None:
    invocation = CliRunner().invoke(
        cli,
        [
            "benchmark-export",
            str(FIXTURES / "manifest-v1.yaml"),
            "--ablation",
            "without-verifier",
            "--run-id",
            "invalid",
            "--system-version",
            "test",
            "--matrix-cell",
            "invalid",
            "--model",
            "analyst=fixture",
            "--prompt-set-sha256",
            "a" * 64,
            "--toolset-sha256",
            "b" * 64,
            "--orchestrator-version",
            "test",
            "--output",
            "unused.json",
        ],
    )
    assert invocation.exit_code != 0
    assert "cannot be stamped" in invocation.output
