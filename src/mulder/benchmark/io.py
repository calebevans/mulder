"""Local-only benchmark document loading, serialization, and table rendering."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
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
    """Load and content-verify a local versioned benchmark manifest."""
    manifest = _load(path, BenchmarkManifest)
    _verify_manifest_evidence(path.parent, manifest)
    manifest._evidence_root = path.parent.resolve()
    return manifest


_TEXT_SELECTOR = re.compile(r"line=(?P<line>[1-9][0-9]*)[; ]+field=(?P<field>[A-Za-z0-9_.-]+)")


@dataclass(frozen=True)
class TextSelectorSnapshot:
    """Digest and selected text derived from one immutable in-memory read."""

    artifact_sha256: str
    size_bytes: int
    exact_text: str


def _read_evidence_bytes(path: Path) -> bytes:
    try:
        with path.open("rb") as evidence_file:
            return evidence_file.read()
    except OSError as exc:
        raise BenchmarkInputError(f"cannot verify evidence artifact {path}: {exc}") from exc


def resolve_text_selector_bytes(content: bytes, selector: str, *, source: Path) -> str:
    """Resolve a bounded key-value selector from already captured artifact bytes."""
    match = _TEXT_SELECTOR.fullmatch(selector)
    if match is None:
        raise BenchmarkInputError(f"unsupported evidence selector {selector!r}")
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise BenchmarkInputError(f"evidence artifact is not UTF-8 text: {source}") from exc
    line_number = int(match.group("line"))
    if line_number > len(lines):
        raise BenchmarkInputError(f"selector {selector!r} is outside {source}")
    field = re.escape(match.group("field"))
    value = re.search(rf"(?:^|\s){field}=([^\s]+)", lines[line_number - 1])
    if value is None and match.group("field") == "format":
        return lines[line_number - 1].split(maxsplit=1)[0]
    if value is None:
        raise BenchmarkInputError(f"selector {selector!r} does not resolve in {source}")
    return value.group(1)


def read_text_selector_snapshot(path: Path, selector: str) -> TextSelectorSnapshot:
    """Hash and resolve a selector from one file descriptor and byte buffer."""
    content = _read_evidence_bytes(path)
    return TextSelectorSnapshot(
        artifact_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        exact_text=resolve_text_selector_bytes(content, selector, source=path),
    )


def resolve_text_selector(path: Path, selector: str) -> str:
    """Resolve the bounded key-value text selector used by local fixtures."""
    return read_text_selector_snapshot(path, selector).exact_text


def _verify_manifest_evidence(root: Path, manifest: BenchmarkManifest) -> None:
    for case in manifest.cases:
        artifacts = {artifact.artifact_id: artifact for artifact in case.evidence}
        contents: dict[str, bytes] = {}
        paths: dict[str, Path] = {}
        for artifact in case.evidence:
            if artifact.redistribution != "redistributable":
                continue
            evidence_path = (root / artifact.path).resolve()
            content = _read_evidence_bytes(evidence_path)
            if hashlib.sha256(content).hexdigest() != artifact.sha256:
                raise BenchmarkInputError(
                    f"evidence artifact {artifact.artifact_id!r} sha256 does not match"
                )
            if artifact.size_bytes is not None and len(content) != artifact.size_bytes:
                raise BenchmarkInputError(
                    f"evidence artifact {artifact.artifact_id!r} size does not match"
                )
            paths[artifact.artifact_id] = evidence_path
            contents[artifact.artifact_id] = content
        for anchor in case.anchors:
            artifact = artifacts[anchor.artifact_id]
            if artifact.redistribution != "redistributable":
                continue
            artifact_path = paths[artifact.artifact_id]
            exact_text = resolve_text_selector_bytes(
                contents[artifact.artifact_id], anchor.selector, source=artifact_path
            )
            if hashlib.sha256(exact_text.encode("utf-8")).hexdigest() != anchor.exact_text_sha256:
                raise BenchmarkInputError(
                    f"evidence anchor {anchor.anchor_id!r} exact text hash does not match"
                )


def load_result(path: Path) -> BenchmarkRunResult:
    """Load a versioned JSON/YAML benchmark result without external I/O."""
    return _load(path, BenchmarkRunResult)


def write_score(path: Path, score: BenchmarkScoreDocument) -> None:
    """Write stable, versioned score JSON."""
    payload = score.model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_result(path: Path, result: BenchmarkRunResult) -> None:
    """Write a stable normalized benchmark result document."""
    payload = result.model_dump(mode="json")
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
        "Confidence Brier/ECE",
        "Severity exact/MAE",
        "Fixed/introduced",
        "No verdict",
        "Failed",
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
                (
                    f"{overall.confidence_calibration.brier_score:.3f}/"
                    f"{overall.confidence_calibration.expected_calibration_error:.3f}"
                    if overall.confidence_calibration.brier_score is not None
                    and overall.confidence_calibration.expected_calibration_error is not None
                    else "n/a"
                ),
                (
                    f"{overall.severity_calibration.exact_rate:.3f}/"
                    f"{overall.severity_calibration.mean_absolute_error:.3f}"
                    if overall.severity_calibration.exact_rate is not None
                    and overall.severity_calibration.mean_absolute_error is not None
                    else "n/a"
                ),
                f"{overall.revisions.errors_fixed}/{overall.revisions.errors_introduced}",
                f"{overall.verdicts.no_verdict_rate:.3f}",
                f"{overall.verdicts.failed_cases}/{overall.verdicts.total_cases}",
                str(resources.runtime_ms) if resources.runtime_ms is not None else "unknown",
                str(resources.total_tokens),
                f"{resources.cost_usd:.6f}" if resources.cost_usd is not None else "unknown",
            )
        )
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]

    def format_row(row: tuple[str, ...]) -> str:
        return " | ".join(value.ljust(widths[index]) for index, value in enumerate(row))

    separator = "-+-".join("-" * width for width in widths)
    sections = [format_row(headers), separator, *(format_row(row) for row in rows)]
    if len(score.runs) > 1:
        aggregate_headers = ("Matrix cell", "Runs", "Claim F1 mean +/- sd", "Verdict mean +/- sd")
        aggregate_rows: list[tuple[str, ...]] = []
        for aggregate in score.aggregates:
            claim = aggregate.metrics["atomic_claims.f1"]
            verdict = aggregate.metrics["verdicts.accuracy"]
            aggregate_rows.append(
                (
                    aggregate.matrix_cell,
                    str(aggregate.repeat_count),
                    f"{claim.mean:.3f} +/- {claim.population_stddev:.3f}",
                    f"{verdict.mean:.3f} +/- {verdict.population_stddev:.3f}",
                )
            )
        aggregate_widths = [
            max(len(header), *(len(row[index]) for row in aggregate_rows))
            for index, header in enumerate(aggregate_headers)
        ]

        def format_aggregate(row: tuple[str, ...]) -> str:
            return " | ".join(
                value.ljust(aggregate_widths[index]) for index, value in enumerate(row)
            )

        sections.extend(
            (
                "",
                "Repeat aggregates",
                format_aggregate(aggregate_headers),
                "-+-".join("-" * width for width in aggregate_widths),
                *(format_aggregate(row) for row in aggregate_rows),
            )
        )
    return "\n".join(sections)
