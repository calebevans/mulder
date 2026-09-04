#!/usr/bin/env python3
"""Regenerate committed Mulder contract schemas from authoritative models."""

from __future__ import annotations

import json
from pathlib import Path

from mulder.benchmark.models import (
    BenchmarkManifest,
    BenchmarkRunResult,
    BenchmarkScoreDocument,
)
from mulder.contracts import core_contract_schema


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    destination = repo_root / "schemas" / "core-contract-v1.schema.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(core_contract_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    benchmark_schemas = {
        "manifest-v1.schema.json": BenchmarkManifest,
        "result-v1.schema.json": BenchmarkRunResult,
        "score-v1.schema.json": BenchmarkScoreDocument,
    }
    benchmark_dir = repo_root / "benchmarks" / "schemas"
    benchmark_dir.mkdir(parents=True, exist_ok=True)
    for filename, model in benchmark_schemas.items():
        (benchmark_dir / filename).write_text(
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
