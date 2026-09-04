"""Read-only case-database benchmark normalization tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from click.testing import CliRunner

from mulder.benchmark.extractor import (
    canonical_anchor_id,
    canonical_coverage_domain,
    extract_case_result,
)
from mulder.benchmark.models import BenchmarkManifest
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
    db = CaseDB.create(case_id, "/evidence", tmp_path)
    source_id = db.register_source("processes", "/evidence/processes", "source-hash", "text", 1)
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=1,
                line_end=1,
                event_time=None,
                raw_text="cmd.exe",
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
                        char_start=0,
                        char_end=7,
                        expected_text="cmd.exe",
                    )
                ],
            )
        ],
    )
    db.verify_finding_claims("finding-1")
    db.record_coverage(
        CoverageKey(system_name="host/a", evidence_domain="process list", check_name="pslist"),
        ToolOutcome(
            status=ToolOutcomeStatus.SUCCESS_NONEMPTY,
            coverage=CoverageMetadata(rows_examined=1, rows_total=1),
        ),
    )
    db.close()
    return tmp_path / f"{case_id}.db"


def _manifest(result_anchor: str) -> BenchmarkManifest:
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
                            "path": "generated-in-test",
                            "sha256": "1" * 64,
                            "origin": "synthetic",
                            "redistribution": "redistributable",
                            "license": {"name": "CC0-1.0", "spdx_id": "CC0-1.0"},
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
                        }
                    ],
                    "anchors": [
                        {
                            "anchor_id": result_anchor,
                            "artifact_id": "source",
                            "selector": "case-db canonical anchor",
                            "exact_text_sha256": "2" * 64,
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
    assert result.claims[0].citations[0].startswith("anchor:")
    assert result.coverage[0].domain == "host%2Fa/process%20list/pslist"

    # Stored UUIDs are deliberately absent from the citation identity.
    with CaseDB(db_path) as db:
        anchor = db.get_claims("finding-1")[0].anchors[0]
    assert result.claims[0].citations == [canonical_anchor_id(anchor)]
    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == digest_before


def test_benchmark_export_cli_writes_stamped_normalized_result(tmp_path: Path) -> None:
    db_path = _case_database(tmp_path)
    extracted = extract_case_result("db-case", db_path)
    manifest = _manifest(extracted.claims[0].citations[0])
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
    assert payload["identity"]["models"] == {"analyst": "fixture-model"}
    assert payload["identity"]["seed"] == 42


def test_export_accepts_explicit_failed_cells_without_a_database(tmp_path: Path) -> None:
    manifest = _manifest("unused-anchor")
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
