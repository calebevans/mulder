"""Committed deterministic and historical benchmark case tests."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

import yaml

from mulder.benchmark.io import load_manifest, load_result
from mulder.benchmark.scorer import score_benchmark

ROOT = Path(__file__).resolve().parents[1]


def test_ci_subset_is_content_addressed_synthetic_and_scores_offline() -> None:
    directory = ROOT / "benchmarks" / "ci"
    manifest = load_manifest(directory / "manifest-v1.yaml")
    result = load_result(directory / "result-reference.json")

    assert len(manifest.cases) == 5
    for case in manifest.cases:
        for artifact in case.evidence:
            assert artifact.origin == "synthetic"
            assert artifact.redistribution == "redistributable"
            evidence_path = directory / artifact.path
            payload = evidence_path.read_bytes()
            assert artifact.size_bytes == len(payload)
            assert artifact.sha256 == hashlib.sha256(payload).hexdigest()

    score = score_benchmark(manifest, [result]).runs[0].overall
    assert score.atomic_claims.true_positive == 2
    assert score.atomic_claims.false_negative == 2
    assert score.atomic_claims.recall == 0.5
    assert score.citations.validity_rate == 1.0
    assert score.coverage.expectation_accuracy == 1.0
    assert score.coverage.completed_required_domains == 3
    assert score.verdicts.accuracy == 1.0
    assert score.verdicts.completed_cases == 3
    assert score.verdicts.no_verdict_rate == 0.4
    assert score.verdicts.unsafe_clean_verdicts == 0


def test_ndlc_conversion_retains_source_labels_and_real_evidence_hashes() -> None:
    directory = ROOT / "benchmarks" / "ndlc"
    source = ROOT / "examples" / "ndlc" / "ACCURACY-REPORT.md"
    manifest = load_manifest(directory / "manifest-v1.json")
    result = load_result(directory / "result-historical.json")

    case = manifest.cases[0]
    assert case.ground_truth_label == "nonempty"
    assert len(case.expected_claims) == 20
    assert len(case.evidence) == 8
    assert all(artifact.origin == "real" for artifact in case.evidence)
    assert all(artifact.redistribution == "manifest_only" for artifact in case.evidence)
    download_manifest = yaml.safe_load(
        (directory / "download-manifest-v1.yaml").read_text(encoding="utf-8")
    )
    assert download_manifest["schema"] == "mulder.benchmark.downloads/v1"
    assert {(item["path"], item["sha256"]) for item in download_manifest["artifacts"]} == {
        (artifact.path, artifact.sha256) for artifact in case.evidence
    }

    adjudication = result.source_adjudication
    assert adjudication is not None
    assert adjudication.source_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert adjudication.reported_counts == {
        "FOUND": 12,
        "PARTIAL": 6,
        "MISSED": 1,
        "FALSE POSITIVE": 1,
    }
    assert Counter(item.status for item in adjudication.items) == {
        "FOUND": 11,
        "PARTIAL": 7,
        "MISSED": 1,
        "FALSE POSITIVE": 1,
    }
    assert adjudication.count_mismatch_note is not None

    score = score_benchmark(manifest, [result]).runs[0].overall
    assert score.atomic_claims.true_positive == 11
    assert score.atomic_claims.recall == 0.55
    assert score.epistemic.inconclusive == 7
    assert score.epistemic.contradicted == 1
    assert score.citations.total == 0
