#!/usr/bin/env python3
"""Build the reproducible executable-ablation fixture through a real CaseDB."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import UUID

from mulder.benchmark.extractor import extract_run_result
from mulder.benchmark.io import load_manifest, write_result
from mulder.benchmark.models import ResourceUsage, RunIdentity
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

ROOT = Path(__file__).resolve().parent
CASE_ID = "staged-incident"
FIXED_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _FixedDateTime(datetime):
    @classmethod
    def now(cls, tz: tzinfo | None = None) -> _FixedDateTime:
        value = FIXED_TIME if tz is not None else FIXED_TIME.replace(tzinfo=None)
        return cls(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            tzinfo=value.tzinfo,
        )


def _finding(
    finding_id: str,
    title: str,
    description: str,
    *,
    confidence: str,
    source_names: list[str],
    tool_ids: list[str],
) -> Finding:
    return Finding.model_validate(
        {
            "finding_id": finding_id,
            "case_id": CASE_ID,
            "title": title,
            "description": description,
            "severity": "high",
            "confidence": confidence,
            "evidence_refs": tool_ids,
            "sources": source_names,
            "submitted_at": FIXED_TIME.isoformat(),
        }
    )


def _anchor(tool_id: str, window_id: int, start: int, end: int, text: str) -> EvidenceAnchorInput:
    return EvidenceAnchorInput(
        tool_call_id=tool_id,
        window_id=window_id,
        char_start=start,
        char_end=end,
        expected_text=text,
        artifact_family="fixture-text",
    )


def _build_case_database(directory: Path) -> Path:
    db = CaseDB.create(CASE_ID, str(ROOT / "evidence"), directory)
    windows: dict[str, int] = {}
    for relative in (
        "acquisition-a/processes.txt",
        "acquisition-b/processes.txt",
        "acquisition-c/processes.txt",
        "acquisition-d/network.txt",
        "acquisition-e/processes.txt",
    ):
        path = (ROOT / "evidence" / relative).resolve()
        raw_text = path.read_text(encoding="utf-8").rstrip("\n")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        source_id = db.register_source(relative.removesuffix(".txt"), str(path), digest, "text", 1)
        db.insert_windows(
            source_id,
            [
                WindowRow(
                    source_id=source_id,
                    line_start=1,
                    line_end=1,
                    event_time=None,
                    raw_text=raw_text,
                )
            ],
        )
        window = db.get_windows_by_source(relative.removesuffix(".txt"))[0]
        assert window.window_id is not None
        windows[relative] = window.window_id

    common_anchors = [
        _anchor("tc-acquisition-a", windows["acquisition-a/processes.txt"], 26, 33, "cmd.exe"),
        _anchor("tc-acquisition-b", windows["acquisition-b/processes.txt"], 40, 47, "cmd.exe"),
    ]
    definitions = [
        (
            _finding(
                "finding-good",
                "Command process observed",
                "Two root acquisitions independently record the same process image.",
                confidence="confirmed",
                source_names=["acquisition-a/processes", "acquisition-b/processes"],
                tool_ids=["tc-acquisition-a", "tc-acquisition-b"],
            ),
            "process:412",
            "image_name",
            "cmd.exe",
            common_anchors,
        ),
        (
            _finding(
                "finding-duplicate",
                "Command process observed",
                "Two root acquisitions independently record the same process image.",
                confidence="confirmed",
                source_names=["acquisition-a/processes", "acquisition-b/processes"],
                tool_ids=["tc-acquisition-a", "tc-acquisition-b"],
            ),
            "process:412",
            "image_name",
            "cmd.exe",
            common_anchors,
        ),
        (
            _finding(
                "finding-weak",
                "Weak one-source assertion",
                "Only one root acquisition records this assertion.",
                confidence="confirmed",
                source_names=["acquisition-c/processes"],
                tool_ids=["tc-acquisition-c"],
            ),
            "process:999",
            "image_name",
            "powershell.exe",
            [
                _anchor(
                    "tc-acquisition-c",
                    windows["acquisition-c/processes.txt"],
                    26,
                    40,
                    "powershell.exe",
                )
            ],
        ),
        (
            _finding(
                "finding-alternative",
                "Competing destination narrative",
                "Counter-analysis establishes the destination was blocked.",
                confidence="inference",
                source_names=["acquisition-d/network"],
                tool_ids=["tc-acquisition-d"],
            ),
            "connection:412:443",
            "ip_equals",
            "198.51.100.10",
            [
                _anchor(
                    "tc-acquisition-d",
                    windows["acquisition-d/network.txt"],
                    12,
                    25,
                    "198.51.100.10",
                )
            ],
        ),
        (
            _finding(
                "finding-blind",
                "Blind-review false positive",
                "Independent review establishes the signed process is benign.",
                confidence="inference",
                source_names=["acquisition-e/processes"],
                tool_ids=["tc-acquisition-e"],
            ),
            "process:777",
            "image_name",
            "evil.exe",
            [
                _anchor(
                    "tc-acquisition-e",
                    windows["acquisition-e/processes.txt"],
                    6,
                    14,
                    "evil.exe",
                )
            ],
        ),
    ]
    for finding, subject, predicate, value, anchors in definitions:
        db.insert_finding(
            finding,
            [
                AtomicClaimInput(
                    statement=f"{subject} {predicate} {value}",
                    subject=subject,
                    predicate=predicate,
                    object_value=value,
                    anchors=anchors,
                )
            ],
        )
        db.verify_finding_claims(finding.finding_id)

    db.delete_finding(
        "finding-alternative",
        actor_kind="investigator",
        reason_code="alternative_narrative_refuted",
    )
    db.delete_finding(
        "finding-blind",
        actor_kind="blind_reviewer",
        reason_code="blind_review_rejected",
    )
    db.record_coverage(
        CoverageKey(
            system_name="fixture",
            evidence_domain="process_memory",
            check_name="complete",
        ),
        ToolOutcome(
            status=ToolOutcomeStatus.SUCCESS_NONEMPTY,
            coverage=CoverageMetadata(rows_examined=5, rows_total=5),
        ),
    )
    db.close()
    return directory / f"{CASE_ID}.db"


def build_result_path(destination: Path) -> None:
    manifest_path = ROOT / "manifest-v1.yaml"
    manifest = load_manifest(manifest_path)
    sequence = iter(UUID(hex=f"{index:012x}" + "0" * 20) for index in range(1, 100))
    with TemporaryDirectory(prefix="mulder-benchmark-") as temporary:
        with patch("mulder.db.uuid4", side_effect=lambda: next(sequence)), patch(
            "mulder.db.datetime", _FixedDateTime
        ):
            db_path = _build_case_database(Path(temporary))
        result = extract_run_result(
            manifest,
            case_databases={CASE_ID: db_path},
            failed_cases={},
            run_id="real-component-base",
            system_name="mulder-real-component-fixture",
            system_version="1.1",
            identity=RunIdentity(
                matrix_cell="fixture/default",
                models={"analyst": "bounded-offline-adapter"},
                prompt_set_sha256="a" * 64,
                toolset_sha256="b" * 64,
                orchestrator_version="fixture-3",
                methodology_version=manifest.methodology_version,
                seed=7,
            ),
            resources=ResourceUsage(runtime_ms=10, cost_usd=0.0),
            evidence_root=manifest_path.parent,
        )
    write_result(destination, result)


def main() -> None:
    build_result_path(ROOT / "result-real-base-v2.json")


if __name__ == "__main__":
    main()
