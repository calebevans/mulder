"""CLI tests for local benchmark comparison and score emission."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from mulder.cli import cli

FIXTURES = Path(__file__).parents[1] / "benchmarks" / "fixtures"


def test_benchmark_cli_emits_json_and_comparison_table(tmp_path: Path) -> None:
    output = tmp_path / "scores.json"
    result = CliRunner().invoke(
        cli,
        [
            "benchmark",
            str(FIXTURES / "manifest-v1.yaml"),
            str(FIXTURES / "result-reference.json"),
            str(FIXTURES / "result-duplicate-partial.yaml"),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Claims P/R/F1" in result.output
    assert "Anchor/claim cite" in result.output
    assert "duplicate-partial" in result.output
    assert "reference" in result.output
    assert f"JSON score: {output}" in result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["score_schema"] == "mulder.benchmark.score/v1"
    assert len(payload["manifest_sha256"]) == 64
    assert [run["run_id"] for run in payload["runs"]] == [
        "duplicate-partial",
        "reference",
    ]


def test_benchmark_cli_reports_invalid_input_without_traceback(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "benchmark",
            str(FIXTURES / "manifest-v1.yaml"),
            str(FIXTURES / "invalid-result.json"),
            "--output",
            str(tmp_path / "scores.json"),
        ],
    )
    assert result.exit_code != 0
    assert "Error: invalid" in result.output
    assert "Traceback" not in result.output
