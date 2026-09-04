"""Calibration, correction, and executable benchmark ablation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mulder.benchmark.ablations import execute_ablations
from mulder.benchmark.io import load_manifest, load_result
from mulder.benchmark.models import BenchmarkRunResult, ClaimRevision
from mulder.benchmark.scorer import score_benchmark
from mulder.cli import cli

FIXTURES = Path(__file__).parents[1] / "benchmarks" / "ablation"
TARGETS = (
    "without-candidate-filters",
    "without-verifier",
    "without-independence-gate",
    "without-alternative-narrative",
    "without-blind-reviewer",
)


def test_calibration_and_revision_metrics_are_deterministic() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    result = load_result(FIXTURES / "result-base.json")

    first = score_benchmark(manifest, [result])
    second = score_benchmark(manifest, [result])
    assert first == second
    overall = first.runs[0].overall
    assert overall.confidence_calibration.model_dump() == {
        "count": 3,
        "mean_confidence": 0.8,
        "empirical_accuracy": 0.666667,
        "brier_score": 0.246667,
        "expected_calibration_error": 0.4,
    }
    assert overall.severity_calibration.model_dump() == {
        "count": 2,
        "exact_matches": 1,
        "unmatched_predictions": 1,
        "exact_rate": 0.5,
        "mean_absolute_error": 0.5,
    }
    assert overall.revisions.model_dump() == {
        "revision_events": 1,
        "assertion_revisions": 1,
        "iterations_observed": 1,
        "errors_fixed": 1,
        "errors_introduced": 0,
        "correct_preserved": 0,
        "errors_persisted": 0,
        "net_errors_fixed": 1,
    }


def test_error_introduced_is_adjudicated_from_before_and_after_claims() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    result = load_result(FIXTURES / "result-base.json")
    case = result.cases[0]
    correct = case.claims[0]
    incorrect = correct.model_copy(update={"object_value": "calc.exe"})
    introduced = ClaimRevision(
        revision_id="introduced-r1",
        claim_id=correct.claim_id,
        iteration=1,
        stage="fixture_reviewer",
        before=correct,
        after=incorrect,
        reason="Synthetic regression for an introduced error.",
    )
    changed_case = case.model_copy(
        update={"claims": [incorrect, *case.claims[1:]], "revisions": [introduced]}
    )
    changed = BenchmarkRunResult.model_validate(
        {
            **result.model_dump(mode="json"),
            "run_id": "introduced-error",
            "cases": [changed_case.model_dump(mode="json")],
            "workflow_traces": [],
        }
    )

    revisions = score_benchmark(manifest, [changed]).runs[0].overall.revisions
    assert revisions.errors_fixed == 0
    assert revisions.errors_introduced == 1
    assert revisions.net_errors_fixed == -1


def test_unattached_revision_history_is_rejected() -> None:
    result = load_result(FIXTURES / "result-base.json")
    payload = result.cases[0].model_dump(mode="json")
    payload["revisions"][0]["after"]["object_value"] = "unpublished.exe"
    with pytest.raises(ValueError, match="last claim revision"):
        type(result.cases[0]).model_validate(payload)


@pytest.mark.parametrize("target", TARGETS)
def test_each_ablation_actually_skips_its_stage_and_emits_a_receipt(target: str) -> None:
    base = load_result(FIXTURES / "result-base.json")
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
    assert receipt.skipped_stages[0] not in receipt.executed_stages
    assert len(receipt.base_result_sha256) == 64
    assert len(receipt.workflow_sha256) == 64
    assert result.identity is not None
    assert result.identity.ablations == [target]


def test_ablation_matrix_has_the_expected_observable_effects() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    base = load_result(FIXTURES / "result-base.json")
    results = {
        target: execute_ablations(
            base,
            [target],
            run_id=f"fixture-{target}",
            matrix_cell=f"fixture/{target}",
        )
        for target in TARGETS
    }

    assert {claim.claim_id for claim in results["without-candidate-filters"].cases[0].claims} == {
        "good",
        "weak",
        "alternative",
        "filtered-candidate",
    }
    assert all(
        claim.verification_state != "verified"
        for claim in results["without-verifier"].cases[0].claims
    )
    weak = next(
        claim
        for claim in results["without-independence-gate"].cases[0].claims
        if claim.claim_id == "weak"
    )
    assert weak.verification_state == "verified"
    alternative = next(
        claim
        for claim in results["without-alternative-narrative"].cases[0].claims
        if claim.claim_id == "alternative"
    )
    assert alternative.object_value == "198.51.100.10"
    assert results["without-alternative-narrative"].cases[0].revisions == []
    assert "blind-false-positive" in {
        claim.claim_id for claim in results["without-blind-reviewer"].cases[0].claims
    }

    scores = {
        run.run_id: run.overall
        for run in score_benchmark(manifest, results.values()).runs
    }
    assert scores["fixture-without-verifier"].atomic_claims.recall == 0.0
    assert scores["fixture-without-independence-gate"].atomic_claims.false_positive == 1
    assert scores["fixture-without-alternative-narrative"].revisions.errors_fixed == 0


def test_ablation_engine_rejects_invalid_or_unreproducible_inputs() -> None:
    base = load_result(FIXTURES / "result-base.json")
    with pytest.raises(ValueError, match="unique"):
        execute_ablations(base, [TARGETS[0], TARGETS[0]], run_id="x", matrix_cell="x")
    with pytest.raises(ValueError, match="unknown"):
        execute_ablations(base, ["label-only"], run_id="x", matrix_cell="x")

    missing_trace = base.model_copy(update={"workflow_traces": []})
    with pytest.raises(ValueError, match="one complete trace"):
        execute_ablations(missing_trace, [TARGETS[0]], run_id="x", matrix_cell="x")

    result = execute_ablations(base, [TARGETS[0]], run_id="once", matrix_cell="once")
    with pytest.raises(ValueError, match="unablated base"):
        execute_ablations(result, [TARGETS[1]], run_id="twice", matrix_cell="twice")


def test_scorer_rejects_a_tampered_ablated_result() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    base = load_result(FIXTURES / "result-base.json")
    result = execute_ablations(
        base,
        ["without-verifier"],
        run_id="without-verifier",
        matrix_cell="fixture/without-verifier",
    )
    payload = result.model_dump(mode="json")
    payload["cases"][0]["claims"][0]["verification_state"] = "verified"
    tampered = BenchmarkRunResult.model_validate(payload)
    with pytest.raises(ValueError, match="does not reproduce"):
        score_benchmark(manifest, [tampered])


def test_benchmark_ablate_cli_writes_same_versioned_result_schema(tmp_path: Path) -> None:
    output = tmp_path / "ablated.json"
    invocation = CliRunner().invoke(
        cli,
        [
            "benchmark-ablate",
            str(FIXTURES / "result-base.json"),
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


def test_export_refuses_to_stamp_an_executable_ablation_without_replay() -> None:
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
