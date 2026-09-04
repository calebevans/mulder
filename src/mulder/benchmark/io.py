"""Local-only benchmark document loading, serialization, and table rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from mulder.benchmark.models import (
    BenchmarkManifest,
    BenchmarkRunResult,
    BenchmarkScoreDocument,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


class BenchmarkInputError(ValueError):
    """A local benchmark document could not be parsed or validated."""


def _read_mapping(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BenchmarkInputError(f"cannot read {path}: {exc}") from exc
    try:
        if path.suffix.casefold() == ".json":
            return json.loads(text)
        if path.suffix.casefold() in {".yaml", ".yml"}:
            return yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise BenchmarkInputError(f"cannot parse {path}: {exc}") from exc
    extension = path.suffix or "<none>"
    raise BenchmarkInputError(f"unsupported benchmark document extension: {extension}")


def _load(path: Path, model: type[ModelT]) -> ModelT:
    try:
        return model.model_validate(_read_mapping(path))
    except ValidationError as exc:
        raise BenchmarkInputError(f"invalid {path}: {exc}") from exc


def load_manifest(path: Path) -> BenchmarkManifest:
    """Load a versioned JSON/YAML benchmark manifest without external I/O."""
    return _load(path, BenchmarkManifest)


def load_result(path: Path) -> BenchmarkRunResult:
    """Load a versioned JSON/YAML benchmark result without external I/O."""
    return _load(path, BenchmarkRunResult)


def write_score(path: Path, score: BenchmarkScoreDocument) -> None:
    """Write stable, versioned score JSON."""
    payload = score.model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_comparison_table(score: BenchmarkScoreDocument) -> str:
    """Render a compact human comparison table from the same score document."""
    headers = (
        "Run",
        "Claims P/R/F1",
        "Entity F1",
        "Predicate F1",
        "Anchor/claim cite",
        "Coverage",
        "Verdict",
        "U/C/I",
        "No verdict",
        "Runtime",
        "Tokens",
        "Cost USD",
    )
    rows: list[tuple[str, ...]] = []
    for run in score.runs:
        overall = run.overall
        resources = run.resources
        rows.append(
            (
                run.run_id,
                f"{overall.atomic_claims.precision:.3f}/{overall.atomic_claims.recall:.3f}/"
                f"{overall.atomic_claims.f1:.3f}",
                f"{overall.entities.f1:.3f}",
                f"{overall.predicates.f1:.3f}",
                f"{overall.citations.validity_rate:.3f}/"
                f"{overall.citations.claim_citation_rate:.3f}",
                f"{overall.coverage.required_completeness:.3f}",
                f"{overall.verdicts.accuracy:.3f}",
                f"{overall.epistemic.unsupported_rate:.3f}/"
                f"{overall.epistemic.contradicted_rate:.3f}/"
                f"{overall.epistemic.inconclusive_rate:.3f}",
                f"{overall.verdicts.no_verdict_rate:.3f}",
                str(resources.runtime_ms),
                str(resources.total_tokens),
                f"{resources.cost_usd:.6f}",
            )
        )
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]

    def format_row(row: tuple[str, ...]) -> str:
        return " | ".join(value.ljust(widths[index]) for index, value in enumerate(row))

    separator = "-+-".join("-" * width for width in widths)
    return "\n".join((format_row(headers), separator, *(format_row(row) for row in rows)))
