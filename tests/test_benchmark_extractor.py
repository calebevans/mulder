"""Read-only case-database benchmark normalization tests."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

import mulder.benchmark.extractor as benchmark_extractor
from mulder.benchmark.ablations import execute_ablations
from mulder.benchmark.extractor import (
    canonical_anchor_id,
    canonical_coverage_domain,
    extract_case_result,
    extract_run_result,
)
from mulder.benchmark.models import (
    BenchmarkManifest,
    BenchmarkRunResult,
    CaseWorkflowTrace,
    ResourceUsage,
    RunIdentity,
)
from mulder.benchmark.scorer import score_benchmark
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.models import (
    AtomicClaimInput,
    CoverageKey,
    CoverageMetadata,
    EvidenceAnchorInput,
    Finding,
    ToolOutcome,
    ToolOutcomeStatus,
    WindowRow,
)


def _case_database(tmp_path: Path, case_id: str = "db-case") -> Path:
    evidence_path = tmp_path / "processes.txt"
    evidence_path.write_text("image=cmd.exe\n", encoding="utf-8")
    source_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    db = CaseDB.create(case_id, str(tmp_path), tmp_path)
    source_id = db.register_source(
        "processes", str(evidence_path), source_hash, "text", 1
    )
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=1,
                line_end=1,
                event_time=None,
                raw_text="image=cmd.exe",
            )
        ],
    )
    window = db.get_windows_by_source("processes")[0]
    assert window.window_id is not None
    finding = Finding(
        finding_id="finding-1",
        case_id=case_id,
        title="Command interpreter",
        description="cmd.exe was observed",
        severity="medium",
        confidence="inference",
        evidence_refs=["tc-1"],
        sources=["processes"],
        submitted_at="2026-01-01T00:00:00Z",
    )
    db.insert_finding(
        finding,
        [
            AtomicClaimInput(
                statement="Process image is cmd.exe",
                subject="process:412",
                predicate="image_name",
                object_value="cmd.exe",
                anchors=[
                    EvidenceAnchorInput(
                        tool_call_id="tc-1",
                        window_id=window.window_id,
                        char_start=6,
                        char_end=13,
                        expected_text="cmd.exe",
                    )
                ],
            )
        ],
    )
    db.verify_finding_claims("finding-1")
    assert db.update_finding(
        "finding-1",
        actor_kind="investigator",
        reason_code="severity_raised",
        severity="high",
    )
    db.record_coverage(
        CoverageKey(system_name="host/a", evidence_domain="process list", check_name="pslist"),
        ToolOutcome(
            status=ToolOutcomeStatus.SUCCESS_NONEMPTY,
            coverage=CoverageMetadata(rows_examined=1, rows_total=1),
        ),
    )
    db.close()
    return tmp_path / f"{case_id}.db"


def _manifest(result_anchor: str, artifact_path: Path) -> BenchmarkManifest:
    return BenchmarkManifest.model_validate(
        {
            "benchmark_id": "db-extraction",
            "title": "DB extraction fixture",
            "description": "Tests normalization from the integrated claim store.",
            "cases": [
                {
                    "case_id": "db-case",
                    "title": "Database case",
                    "ground_truth_label": "nonempty",
                    "applicability": ["artifact:case-db"],
                    "expected_verdict": "positive",
                    "evidence": [
                        {
                            "artifact_id": "source",
                            "path": artifact_path.name,
                            "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
                            "origin": "synthetic",
                            "redistribution": "redistributable",
                            "license": {"name": "CC0-1.0", "spdx_id": "CC0-1.0"},
                            "size_bytes": artifact_path.stat().st_size,
                            "root_acquisition_id": "acquisition-db",
                        }
                    ],
                    "coverage": [
                        {
                            "domain": canonical_coverage_domain(
                                "host/a", "process list", "pslist"
                            ),
                            "applicability": "applicable",
                            "expected_content": "nonempty",
                            "acceptable_statuses": ["SUCCESS_NONEMPTY"],
                        }
                    ],
                    "expected_claims": [
                        {
                            "claim_id": "expected",
                            "subject": "process:412",
                            "predicate": "image_name",
                            "object_value": "cmd.exe",
                            "severity": "high",
                        }
                    ],
                    "anchors": [
                        {
                            "anchor_id": result_anchor,
                            "artifact_id": "source",
                            "selector": "line=1;field=image",
                            "exact_text_sha256": hashlib.sha256(
                                b"cmd.exe"
                            ).hexdigest(),
                            "supports_claim_ids": ["expected"],
                        }
                    ],
                }
            ],
        }
    )


def test_case_database_extraction_uses_stable_citations_and_coverage(tmp_path: Path) -> None:
    db_path = _case_database(tmp_path)
    digest_before = hashlib.sha256(db_path.read_bytes()).hexdigest()
    result = extract_case_result("db-case", db_path)
    assert result.verdict == "positive"
    assert result.cell_status == "completed"
    assert result.claims[0].verification_state == "verified"
    assert result.claims[0].confidence == 0.5
    assert result.claims[0].severity == "high"
    assert result.claims[0].citations[0].startswith("anchor:")
    assert result.coverage[0].domain == "host%2Fa/process%20list/pslist"

    # Stored UUIDs are deliberately absent from the citation identity.
    with CaseDB(db_path) as db:
        anchor = db.get_claims("finding-1")[0].anchors[0]
    assert result.claims[0].citations == [canonical_anchor_id(anchor)]
    assert [revision.stage for revision in result.revisions] == [
        "source_finding_revision",
        "source_finding_revision",
        "verifier",
    ]
    assert result.revisions[1].source_revision_id is not None
    assert result.revisions[1].before.severity == "medium"
    assert result.revisions[1].after is not None
    assert result.revisions[1].after.severity == "high"
    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == digest_before


def test_case_database_extraction_rechecks_current_anchor_bytes(tmp_path: Path) -> None:
    db_path = _case_database(tmp_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE windows SET raw_text = 'image=evil.ex'")

    result = extract_case_result("db-case", db_path)
    assert result.claims[0].verification_state == "inconclusive"
    assert result.verdict == "no_verdict"


def test_benchmark_export_cli_writes_stamped_normalized_result(tmp_path: Path) -> None:
    db_path = _case_database(tmp_path)
    extracted = extract_case_result("db-case", db_path)
    manifest = _manifest(extracted.claims[0].citations[0], tmp_path / "processes.txt")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    output = tmp_path / "result.json"

    result = CliRunner().invoke(
        cli,
        [
            "benchmark-export",
            str(manifest_path),
            "--case-db",
            f"db-case={db_path}",
            "--run-id",
            "run-0",
            "--system-version",
            "test",
            "--matrix-cell",
            "test/default",
            "--model",
            "analyst=fixture-model",
            "--orchestrator-version",
            "test",
            "--prompt-set-sha256",
            "a" * 64,
            "--toolset-sha256",
            "b" * 64,
            "--repeat-index",
            "0",
            "--seed",
            "42",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["cases"][0]["claims"][0]["verification_state"] == "verified"
    assert payload["cases"][0]["claims"][0]["confidence"] == 0.5
    assert payload["cases"][0]["claims"][0]["severity"] == "high"
    assert payload["cases"][0]["revisions"]
    trace = payload["workflow_traces"][0]
    assert trace["trace_version"] == 2
    assert trace["candidates"][0]["source_verifications"]
    assert len(trace["candidates"][0]["finding_revisions"]) == 2
    assert payload["identity"]["models"] == {"analyst": "fixture-model"}
    assert payload["identity"]["seed"] == 42

    normalized = BenchmarkRunResult.model_validate(payload)
    score = score_benchmark(manifest, [normalized]).runs[0].overall
    assert score.confidence_calibration.count == 1
    assert score.confidence_calibration.brier_score == 0.25
    assert score.severity_calibration.exact_rate == 1.0
    assert score.revisions.errors_fixed == 1

    ablated = execute_ablations(
        normalized,
        ["without-verifier"],
        run_id="run-without-verifier",
        matrix_cell="test/without-verifier",
    )
    assert ablated.cases[0].verdict == "no_verdict"
    assert ablated.cases[0].claims[0].verification_state == "unverified"


def test_export_rejects_explicit_methodology_mismatch(tmp_path: Path) -> None:
    evidence_path = tmp_path / "processes.txt"
    evidence_path.write_text("image=cmd.exe\n", encoding="utf-8")
    manifest = _manifest("unused-anchor", evidence_path).model_copy(
        update={"methodology_version": "1.1"}
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    derived_output = tmp_path / "derived.json"
    derived = CliRunner().invoke(
        cli,
        [
            "benchmark-export",
            str(manifest_path),
            "--failed-case",
            "db-case=fixture failure",
            "--run-id",
            "derived",
            "--system-version",
            "test",
            "--matrix-cell",
            "test/default",
            "--model",
            "analyst=fixture",
            "--orchestrator-version",
            "test",
            "--prompt-set-sha256",
            "a" * 64,
            "--toolset-sha256",
            "b" * 64,
            "--output",
            str(derived_output),
        ],
    )
    assert derived.exit_code == 0, derived.output
    assert json.loads(derived_output.read_text(encoding="utf-8"))["identity"][
        "methodology_version"
    ] == "1.1"
    invocation = CliRunner().invoke(
        cli,
        [
            "benchmark-export",
            str(manifest_path),
            "--failed-case",
            "db-case=fixture failure",
            "--run-id",
            "mismatch",
            "--system-version",
            "test",
            "--matrix-cell",
            "test/default",
            "--model",
            "analyst=fixture",
            "--orchestrator-version",
            "test",
            "--prompt-set-sha256",
            "a" * 64,
            "--toolset-sha256",
            "b" * 64,
            "--methodology-version",
            "1.0",
            "--output",
            str(tmp_path / "result.json"),
        ],
    )
    assert invocation.exit_code != 0
    assert "methodology" in invocation.output


def test_run_export_rejects_case_source_path_that_is_not_the_bound_artifact(
    tmp_path: Path,
) -> None:
    db_path = _case_database(tmp_path)
    extracted = extract_case_result("db-case", db_path)
    manifest = _manifest(extracted.claims[0].citations[0], tmp_path / "processes.txt")
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE sources SET source_path = '/different/acquisition/processes.txt'")

    with pytest.raises(ValueError, match="source path does not match manifest artifact"):
        extract_run_result(
            manifest,
            case_databases={"db-case": db_path},
            failed_cases={},
            run_id="misbound",
            system_name="mulder",
            system_version="test",
            identity=RunIdentity(
                matrix_cell="test/default",
                models={"analyst": "fixture"},
                prompt_set_sha256="a" * 64,
                toolset_sha256="b" * 64,
                orchestrator_version="test",
                methodology_version=manifest.methodology_version,
            ),
            resources=ResourceUsage(),
            evidence_root=tmp_path,
        )


def test_run_export_rejects_anchor_without_answer_key_selector(tmp_path: Path) -> None:
    db_path = _case_database(tmp_path)
    extracted = extract_case_result("db-case", db_path)
    manifest = _manifest(extracted.claims[0].citations[0], tmp_path / "processes.txt")
    case = manifest.cases[0].model_copy(update={"anchors": []})
    manifest = manifest.model_copy(update={"cases": [case]})

    with pytest.raises(ValueError, match="answer-key selector"):
        extract_run_result(
            manifest,
            case_databases={"db-case": db_path},
            failed_cases={},
            run_id="missing-selector",
            system_name="mulder",
            system_version="test",
            identity=RunIdentity(
                matrix_cell="test/default",
                models={"analyst": "fixture"},
                prompt_set_sha256="a" * 64,
                toolset_sha256="b" * 64,
                orchestrator_version="test",
                methodology_version=manifest.methodology_version,
            ),
            resources=ResourceUsage(),
            evidence_root=tmp_path,
        )


def test_run_export_rejects_unresolved_answer_key_selector(tmp_path: Path) -> None:
    db_path = _case_database(tmp_path)
    extracted = extract_case_result("db-case", db_path)
    manifest = _manifest(extracted.claims[0].citations[0], tmp_path / "processes.txt")
    anchor = manifest.cases[0].anchors[0].model_copy(update={"selector": "line=99;field=image"})
    case = manifest.cases[0].model_copy(update={"anchors": [anchor]})
    manifest = manifest.model_copy(update={"cases": [case]})

    with pytest.raises(ValueError, match="does not resolve|outside"):
        extract_run_result(
            manifest,
            case_databases={"db-case": db_path},
            failed_cases={},
            run_id="unresolved-selector",
            system_name="mulder",
            system_version="test",
            identity=RunIdentity(
                matrix_cell="test/default",
                models={"analyst": "fixture"},
                prompt_set_sha256="a" * 64,
                toolset_sha256="b" * 64,
                orchestrator_version="test",
                methodology_version=manifest.methodology_version,
            ),
            resources=ResourceUsage(),
            evidence_root=tmp_path,
        )


def test_run_export_rejects_database_mutation_during_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _case_database(tmp_path)
    extracted = extract_case_result("db-case", db_path)
    manifest = _manifest(extracted.claims[0].citations[0], tmp_path / "processes.txt")
    execute = benchmark_extractor.execute_workflow_base

    def mutate_after_evaluation(trace: CaseWorkflowTrace) -> object:
        result = execute(trace)
        with sqlite3.connect(db_path) as connection:
            connection.execute("UPDATE windows SET raw_text = 'image=mutated.exe'")
        return result

    monkeypatch.setattr(benchmark_extractor, "execute_workflow_base", mutate_after_evaluation)
    with pytest.raises(ValueError, match="changed during benchmark export"):
        extract_run_result(
            manifest,
            case_databases={"db-case": db_path},
            failed_cases={},
            run_id="mutated-during-export",
            system_name="mulder",
            system_version="test",
            identity=RunIdentity(
                matrix_cell="test/default",
                models={"analyst": "fixture"},
                prompt_set_sha256="a" * 64,
                toolset_sha256="b" * 64,
                orchestrator_version="test",
                methodology_version=manifest.methodology_version,
            ),
            resources=ResourceUsage(),
            evidence_root=tmp_path,
        )


def test_run_export_rejects_artifact_mutation_during_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _case_database(tmp_path)
    extracted = extract_case_result("db-case", db_path)
    evidence_path = tmp_path / "processes.txt"
    manifest = _manifest(extracted.claims[0].citations[0], evidence_path)
    execute = benchmark_extractor.execute_workflow_base

    def mutate_after_evaluation(trace: CaseWorkflowTrace) -> object:
        result = execute(trace)
        evidence_path.write_text("image=mutated.exe\n", encoding="utf-8")
        return result

    monkeypatch.setattr(
        benchmark_extractor, "execute_workflow_base", mutate_after_evaluation
    )
    with pytest.raises(ValueError, match="artifact bytes no longer match manifest"):
        extract_run_result(
            manifest,
            case_databases={"db-case": db_path},
            failed_cases={},
            run_id="artifact-mutated-during-export",
            system_name="mulder",
            system_version="test",
            identity=RunIdentity(
                matrix_cell="test/default",
                models={"analyst": "fixture"},
                prompt_set_sha256="a" * 64,
                toolset_sha256="b" * 64,
                orchestrator_version="test",
                methodology_version=manifest.methodology_version,
            ),
            resources=ResourceUsage(),
            evidence_root=tmp_path,
        )


def test_scorer_rechecks_selector_against_current_artifact_bytes(tmp_path: Path) -> None:
    db_path = _case_database(tmp_path)
    extracted = extract_case_result("db-case", db_path)
    evidence_path = tmp_path / "processes.txt"
    manifest = _manifest(extracted.claims[0].citations[0], evidence_path).model_copy(
        update={"methodology_version": "1.1"}
    )
    result = extract_run_result(
        manifest,
        case_databases={"db-case": db_path},
        failed_cases={},
        run_id="artifact-mutated-after-export",
        system_name="mulder",
        system_version="test",
        identity=RunIdentity(
            matrix_cell="test/default",
            models={"analyst": "fixture"},
            prompt_set_sha256="a" * 64,
            toolset_sha256="b" * 64,
            orchestrator_version="test",
            methodology_version=manifest.methodology_version,
        ),
        resources=ResourceUsage(),
        evidence_root=tmp_path,
    )
    evidence_path.write_text("image=mutated.exe\n", encoding="utf-8")

    with pytest.raises(ValueError, match="artifact bytes no longer match manifest"):
        score_benchmark(manifest, [result], evidence_root=tmp_path)


def test_withdrawn_case_db_reviewer_decision_feeds_real_ablation(tmp_path: Path) -> None:
    db_path = _case_database(tmp_path)
    with CaseDB(db_path) as db:
        anchor_id = canonical_anchor_id(db.get_claims("finding-1")[0].anchors[0])
        assert db.delete_finding(
            "finding-1",
            actor_kind="blind_reviewer",
            reason_code="blind_review_rejected",
        )
    extracted = extract_case_result("db-case", db_path)
    assert extracted.verdict == "no_evil_within_coverage"
    assert extracted.claims == []
    assert extracted.revisions[-1].stage == "blind_reviewer"
    assert extracted.revisions[-1].tombstone is True

    run = extract_run_result(
        _manifest(anchor_id, tmp_path / "processes.txt"),
        case_databases={"db-case": db_path},
        failed_cases={},
        run_id="withdrawn-base",
        system_name="mulder",
        system_version="test",
        identity=RunIdentity(
            matrix_cell="test/default",
            models={"analyst": "fixture"},
            prompt_set_sha256="a" * 64,
            toolset_sha256="b" * 64,
            orchestrator_version="test",
            methodology_version="1.1",
        ),
        resources=ResourceUsage(),
        evidence_root=tmp_path,
    )
    restored = execute_ablations(
        run,
        ["without-blind-reviewer"],
        run_id="without-blind",
        matrix_cell="test/without-blind",
    )
    assert restored.cases[0].verdict == "positive"
    assert restored.cases[0].claims[0].verification_state == "verified"


def test_export_accepts_explicit_failed_cells_without_a_database(tmp_path: Path) -> None:
    evidence_path = tmp_path / "processes.txt"
    evidence_path.write_text("image=cmd.exe\n", encoding="utf-8")
    manifest = _manifest("unused-anchor", evidence_path)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    output = tmp_path / "failed.json"
    invocation = CliRunner().invoke(
        cli,
        [
            "benchmark-export",
            str(manifest_path),
            "--failed-case",
            "db-case=worker exceeded resource budget",
            "--run-id",
            "failed-0",
            "--system-version",
            "test",
            "--matrix-cell",
            "test/default",
            "--model",
            "analyst=fixture-model",
            "--orchestrator-version",
            "test",
            "--prompt-set-sha256",
            "a" * 64,
            "--toolset-sha256",
            "b" * 64,
            "--output",
            str(output),
        ],
    )
    assert invocation.exit_code == 0, invocation.output
    normalized = json.loads(output.read_text(encoding="utf-8"))
    assert normalized["cases"][0]["cell_status"] == "failed"
    assert normalized["cases"][0]["failure_reason"] == "worker exceeded resource budget"
