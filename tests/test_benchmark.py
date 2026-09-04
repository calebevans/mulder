"""Schema and deterministic scoring tests for the offline benchmark module."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from mulder.benchmark.io import BenchmarkInputError, load_manifest, load_result
from mulder.benchmark.models import (
    BenchmarkManifest,
    BenchmarkRunResult,
    BenchmarkScoreDocument,
    RunIdentity,
)
from mulder.benchmark.scorer import score_benchmark

FIXTURES = Path(__file__).parents[1] / "benchmarks" / "fixtures"


def test_fixture_evidence_hashes_match_manifest() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    artifacts = {artifact.path: artifact for case in manifest.cases for artifact in case.evidence}
    for relative_path, artifact in artifacts.items():
        evidence_path = FIXTURES / relative_path
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == artifact.sha256
        assert evidence_path.stat().st_size == artifact.size_bytes
        assert artifact.origin == "synthetic"
        assert artifact.license.spdx_id == "CC0-1.0"


def test_models_expose_versioned_json_schemas() -> None:
    manifest_schema = BenchmarkManifest.model_json_schema()
    result_schema = BenchmarkRunResult.model_json_schema()
    assert manifest_schema["properties"]["schema_version"]["const"] == 1
    assert result_schema["properties"]["schema_version"]["const"] == 1
    assert "EvidenceLicense" in manifest_schema["$defs"]
    assert manifest_schema["additionalProperties"] is False
    assert result_schema["additionalProperties"] is False


def test_committed_json_schemas_match_authoritative_models() -> None:
    models: dict[str, type[BaseModel]] = {
        "manifest-v1.schema.json": BenchmarkManifest,
        "result-v1.schema.json": BenchmarkRunResult,
        "score-v1.schema.json": BenchmarkScoreDocument,
    }
    schema_dir = FIXTURES.parent / "schemas"
    for filename, model in models.items():
        committed = json.loads((schema_dir / filename).read_text(encoding="utf-8"))
        assert committed == model.model_json_schema()


def test_reference_result_scores_exact_claims_citations_and_verdicts() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    result = load_result(FIXTURES / "result-reference.json")
    score = score_benchmark(manifest, [result]).runs[0]

    assert score.overall.atomic_claims.f1 == 1.0
    assert score.overall.entities.f1 == 1.0
    assert score.overall.predicates.f1 == 1.0
    assert score.overall.citations.validity_rate == 1.0
    assert score.overall.citations.claim_citation_rate == 1.0
    assert score.overall.coverage.expectation_accuracy == 1.0
    # The expected unsupported outcome is accurate, but not completed coverage.
    assert score.overall.coverage.required_completeness == pytest.approx(2 / 3, abs=1e-6)
    assert score.overall.verdicts.accuracy == 1.0
    assert score.overall.verdicts.no_verdict_rate == pytest.approx(1 / 3, abs=1e-6)
    assert score.clean.atomic_claims.f1 == 1.0
    assert score.nonempty.atomic_claims.f1 == 1.0
    assert score.resources.total_tokens == 150
    assert len(score.result_sha256) == 64


def test_duplicate_and_partial_claims_have_stable_separate_counts() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    result = load_result(FIXTURES / "result-duplicate-partial.yaml")
    score = score_benchmark(manifest, [result]).runs[0].overall

    assert score.atomic_claims.model_dump() == {
        "true_positive": 1,
        "false_positive": 2,
        "false_negative": 1,
        "precision": 0.333333,
        "recall": 0.5,
        "f1": 0.4,
    }
    assert score.entities.true_positive == 2
    assert score.entities.false_positive == 1
    assert score.predicates.true_positive == 2
    assert score.predicates.false_positive == 1
    assert score.duplicate_claims == 1
    assert score.duplicate_citations == 1
    assert score.citations.total == 3
    assert score.citations.resolved == 3
    assert score.citations.valid == 2
    assert score.citations.verified_claims == 4
    assert score.citations.claims_with_valid_citation == 2
    assert score.citations.claim_citation_rate == 0.5
    assert score.citations.uncited_verified_claims == 1
    assert score.epistemic.total_claims == 7
    assert score.epistemic.unsupported_rate == 0.142857
    assert score.epistemic.contradicted_rate == 0.142857
    assert score.epistemic.inconclusive_rate == 0.142857
    assert score.coverage.expectation_accuracy == pytest.approx(1 / 3, abs=1e-6)
    assert score.coverage.required_completeness == 0.0
    assert score.coverage.unexpected_domains == 1
    assert score.verdicts.accuracy == pytest.approx(1 / 3, abs=1e-6)
    assert score.verdicts.unsafe_clean_verdicts == 1


def test_no_verdict_result_is_visible_and_does_not_inflate_recall() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    result = load_result(FIXTURES / "result-no-verdict.json")
    score = score_benchmark(manifest, [result]).runs[0].overall

    assert score.atomic_claims.precision == 0.0
    assert score.atomic_claims.recall == 0.0
    assert score.atomic_claims.false_negative == 2
    assert score.verdicts.no_verdict_rate == 1.0
    assert score.verdicts.no_verdict_recall == 1.0
    assert score.verdicts.accuracy == pytest.approx(1 / 3, abs=1e-6)


def test_scoring_is_independent_of_result_file_order() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    reference = load_result(FIXTURES / "result-reference.json")
    partial = load_result(FIXTURES / "result-duplicate-partial.yaml")
    forward = score_benchmark(manifest, [reference, partial])
    reverse = score_benchmark(manifest, [partial, reference])
    assert forward == reverse
    assert [run.run_id for run in forward.runs] == ["duplicate-partial", "reference"]


def test_comparable_repeats_publish_population_variance() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    reference = load_result(FIXTURES / "result-reference.json").model_copy(
        update={
            "run_id": "repeat-0",
            "identity": RunIdentity(
                matrix_cell="mulder/default",
                models={"analyst": "fixture-model"},
                orchestrator_version="fixture",
                methodology_version="1.0",
                repeat_index=0,
                seed=10,
            ),
        }
    )
    abstaining = load_result(FIXTURES / "result-no-verdict.json").model_copy(
        update={
            "run_id": "repeat-1",
            "system_name": reference.system_name,
            "system_version": reference.system_version,
            "identity": RunIdentity.model_validate(reference.identity).model_copy(
                update={"repeat_index": 1, "seed": 11}
            ),
        }
    )

    score = score_benchmark(manifest, [reference, abstaining])
    aggregate = score.aggregates[0]
    claim_f1 = aggregate.metrics["atomic_claims.f1"]
    assert aggregate.matrix_cell == "mulder/default"
    assert aggregate.repeat_count == 2
    assert aggregate.run_ids == ["repeat-0", "repeat-1"]
    assert claim_f1.mean == 0.5
    assert claim_f1.population_variance == 0.25
    assert claim_f1.population_stddev == 0.5
    assert aggregate.metrics["verdicts.failed_rate"].mean == 0.0


def test_duplicate_repeat_index_is_rejected() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    base = load_result(FIXTURES / "result-reference.json")
    identity = RunIdentity(
        matrix_cell="same-cell",
        models={"analyst": "fixture-model"},
        orchestrator_version="fixture",
        methodology_version="1.0",
    )
    first = base.model_copy(update={"run_id": "one", "identity": identity})
    second = base.model_copy(update={"run_id": "two", "identity": identity})
    with pytest.raises(ValueError, match="duplicate repeat_index"):
        score_benchmark(manifest, [first, second])


def test_matrix_cell_rejects_inconsistent_identity_stamps() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    base = load_result(FIXTURES / "result-reference.json")
    first_identity = RunIdentity(
        matrix_cell="same-cell",
        models={"analyst": "model-a"},
        orchestrator_version="fixture",
        methodology_version="1.0",
    )
    second_identity = first_identity.model_copy(
        update={"models": {"analyst": "model-b"}, "repeat_index": 1}
    )
    first = base.model_copy(update={"run_id": "one", "identity": first_identity})
    second = base.model_copy(update={"run_id": "two", "identity": second_identity})
    with pytest.raises(ValueError, match="inconsistent .* identity"):
        score_benchmark(manifest, [first, second])


def test_failed_cell_does_not_receive_expected_abstention_credit() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    result = load_result(FIXTURES / "result-reference.json")
    failed_cases = [
        case.model_copy(
            update={
                "cell_status": "failed",
                "failure_reason": "fixture failure",
                "verdict": "no_verdict",
                "claims": [],
                "coverage": [],
            }
        )
        if case.case_id == "unsupported-no-verdict"
        else case
        for case in result.cases
    ]
    failed = result.model_copy(update={"cases": failed_cases})
    score = score_benchmark(manifest, [failed]).runs[0].overall
    assert score.verdicts.failed_cases == 1
    assert score.verdicts.correct == 2
    assert score.verdicts.correct_no_verdict == 0


def test_incomparable_case_sets_are_rejected() -> None:
    manifest = load_manifest(FIXTURES / "manifest-v1.yaml")
    result = load_result(FIXTURES / "result-reference.json")
    incomplete = result.model_copy(update={"cases": result.cases[:-1], "run_id": "incomplete"})
    with pytest.raises(ValueError, match="incomparable case set"):
        score_benchmark(manifest, [incomplete])


def test_invalid_schema_version_and_resource_values_are_rejected() -> None:
    with pytest.raises(BenchmarkInputError, match="invalid"):
        load_result(FIXTURES / "invalid-result.json")


def test_unknown_fields_are_rejected() -> None:
    valid = load_result(FIXTURES / "result-reference.json")
    payload = valid.model_dump(mode="json")
    payload["surprise"] = True
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        BenchmarkRunResult.model_validate(payload)
