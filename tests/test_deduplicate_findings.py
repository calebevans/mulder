"""Tests for deduplicate_findings: lossless merges and the over-merge guards."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.models import Finding
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools.findings import _consolidate_group


def _finding(fid: str, **overrides: Any) -> Finding:
    base: dict[str, Any] = {
        "finding_id": fid,
        "case_id": "test-case",
        "title": "USB device RM1 connected",
        "description": f"Description of {fid}",
        "severity": "medium",
        "confidence": "inference",
        "evidence_refs": ["tc_aabbccdd"],
        "sources": ["registry.usbstor"],
        "mitre_attack_ids": ["T1052.001"],
        "event_time_start": "2015-03-24T10:00:00Z",
        "event_time_end": "2015-03-24T11:00:00Z",
        "submitted_at": "2025-01-15T12:00:00Z",
    }
    base.update(overrides)
    return Finding(**base)


# Two true duplicates: same evidence, source, MITRE id and time window.
DUP_A = _finding(
    "f-a",
    description="Short.",
    severity="high",
    event_time_start="2015-03-24T10:30:00Z",
    event_time_end="2015-03-24T11:00:00Z",
)
DUP_B = _finding(
    "f-b",
    title="Authorized USB RM1 serial 4C530012450531101593",
    description="RM1 serial 4C530012450531101593 exFAT volume label 'Authorized USB'.",
    confidence="confirmed",
    evidence_refs=["tc_aabbccdd", "tc_11223344"],
    sources=["registry.usbstor", "setupapi.log"],
    mitre_attack_ids=["T1052.001", "T1091"],
    event_time_start="2015-03-24T09:00:00Z",
    event_time_end="2015-03-24T10:45:00Z",
)
# Two unrelated findings: no shared evidence, source, technique or time.
OTHER_1 = _finding(
    "f-c",
    title="IAMAN CD burned",
    evidence_refs=["tc_cd000001"],
    sources=["cdburn.log"],
    mitre_attack_ids=["T1052"],
    event_time_start="2015-03-25T14:00:00Z",
    event_time_end=None,
)
OTHER_2 = _finding(
    "f-d",
    title="7z archive created on desktop",
    evidence_refs=["tc_7z000001"],
    sources=["mft.csv"],
    mitre_attack_ids=["T1560.001"],
    event_time_start="2015-03-26T14:00:00Z",
    event_time_end=None,
)


@pytest.fixture()
def case_db(tmp_path: Path) -> CaseDB:
    return CaseDB.create(case_id="test-case", evidence_root="/evidence", db_dir=tmp_path)


@pytest.fixture()
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "test.audit.jsonl"


def _dedup(case_db: CaseDB, audit_path: Path, **kwargs: object) -> dict[str, Any]:
    ctx = MagicMock()
    ctx.db = case_db
    ctx.audit = AuditLog(audit_path)
    fn = _tool_dispatch_sync["deduplicate_findings"]
    with (
        patch("mulder.server.tools.findings.get_ctx", return_value=ctx),
        patch("mulder.server.helpers.has_ctx", return_value=False),
    ):
        return fn(case_id="test-case", **kwargs)  # type: ignore[no-any-return]


def _seed(case_db: CaseDB, *findings: Finding) -> None:
    for f in findings:
        case_db.insert_finding(f.model_copy(deep=True))


class TestConsolidateGroup:
    def test_merge_is_lossless(self) -> None:
        best, deleted = _consolidate_group([DUP_A.model_copy(), DUP_B.model_copy()])

        assert best.finding_id == "f-b"  # longest description survives
        assert deleted == ["f-a"]
        assert best.evidence_refs == ["tc_11223344", "tc_aabbccdd"]
        assert best.sources == ["registry.usbstor", "setupapi.log"]
        assert best.mitre_attack_ids == ["T1052.001", "T1091"]
        assert best.severity == "high"
        assert best.confidence == "confirmed"
        assert best.event_time_start == "2015-03-24T09:00:00Z"
        assert best.event_time_end == "2015-03-24T11:00:00Z"
        # The absorbed finding's title, id and text are appended, not dropped.
        assert "**Merged findings:**" in best.description
        assert "**USB device RM1 connected** (f-a, high, inference): Short." in best.description
        assert best.description.startswith("RM1 serial 4C530012450531101593")

    def test_time_range_widened_from_end_less_finding(self) -> None:
        late = OTHER_1.model_copy(update={"evidence_refs": DUP_A.evidence_refs})
        best, _ = _consolidate_group([DUP_A.model_copy(), late])
        assert best.event_time_start == "2015-03-24T10:30:00Z"
        assert best.event_time_end == "2015-03-25T14:00:00Z"


class TestDeduplicateFindingsTool:
    def test_merge_persists_and_audits(self, case_db: CaseDB, audit_path: Path) -> None:
        _seed(case_db, DUP_A, DUP_B, OTHER_1, OTHER_2)

        result = _dedup(case_db, audit_path, dry_run=False)

        assert result["status"] == "success"
        assert result["merged_count"] == 1
        assert result["kept_count"] == 3
        assert result["absorbed"] == {"f-b": ["f-a"]}
        assert result["groups"][0]["merged_titles"] == ["USB device RM1 connected"]
        assert "1 of 4 findings absorbed into 1 survivor(s)" in str(result["summary"])

        assert case_db.get_finding("f-a") is None
        survivor = case_db.get_finding("f-b")
        assert survivor is not None
        assert "(f-a, high, inference): Short." in survivor.description
        assert "**Affected Systems:** registry.usbstor, setupapi.log" in survivor.description
        assert survivor.severity == "high"
        assert survivor.confidence == "confirmed"
        assert survivor.event_time_start == "2015-03-24T09:00:00Z"
        assert survivor.event_time_end == "2015-03-24T11:00:00Z"
        assert survivor.evidence_refs == ["tc_11223344", "tc_aabbccdd"]

        entries = [json.loads(line) for line in audit_path.read_text().splitlines()]
        dedup_entries = [e for e in entries if e["tool_name"] == "deduplicate_findings"]
        assert dedup_entries[-1]["params"]["absorbed"] == {"f-b": ["f-a"]}

    def test_dry_run_changes_nothing(self, case_db: CaseDB, audit_path: Path) -> None:
        _seed(case_db, DUP_A, DUP_B, OTHER_1, OTHER_2)

        result = _dedup(case_db, audit_path, dry_run=True)

        assert result["status"] == "success"
        assert result["would_merge_count"] == 1
        assert result["merged_count"] == 0
        assert result["absorbed"] == {"f-b": ["f-a"]}
        assert len(case_db.get_findings()) == 4
        assert "Merged findings" not in str(case_db.get_findings()[1].description)

    def test_threshold_floor_enforced_for_live_merge(
        self, case_db: CaseDB, audit_path: Path
    ) -> None:
        _seed(case_db, DUP_A, DUP_B, OTHER_1, OTHER_2)

        result = _dedup(case_db, audit_path, similarity_threshold=0.2, dry_run=False)

        assert result["status"] == "error"
        assert result["error_type"] == "invalid_params"
        assert "below the minimum 0.4" in str(result["error_message"])
        assert len(case_db.get_findings()) == 4

    def test_low_threshold_allowed_for_dry_run(self, case_db: CaseDB, audit_path: Path) -> None:
        _seed(case_db, DUP_A, DUP_B, OTHER_1, OTHER_2)

        result = _dedup(case_db, audit_path, similarity_threshold=0.2, dry_run=True)

        assert result["status"] == "success"
        assert len(case_db.get_findings()) == 4

    def test_over_aggressive_merge_refused(self, case_db: CaseDB, audit_path: Path) -> None:
        # Four near-identical findings: a live pass would absorb 3 of 4.
        _seed(
            case_db,
            DUP_A,
            DUP_B,
            DUP_A.model_copy(update={"finding_id": "f-e"}),
            DUP_B.model_copy(update={"finding_id": "f-f"}),
        )

        refused = _dedup(case_db, audit_path, dry_run=False)
        assert refused["status"] == "error"
        assert "would absorb 3 of 4 findings" in str(refused["error_message"])
        assert len(case_db.get_findings()) == 4

        preview = _dedup(case_db, audit_path, dry_run=True)
        assert preview["status"] == "success"
        assert preview["would_merge_count"] == 3
        assert len(case_db.get_findings()) == 4
