"""Regression tests for issue #239: a finding row with empty evidence_refs.

Every write path must leave a row the ``Finding`` model can load, and the
readers must skip (and report) a row that does not, instead of raising.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import insert

import mulder.server.tools.core  # noqa: F401 ensure tools are registered
import mulder.server.tools.review  # noqa: F401
from mulder.audit import AuditLog
from mulder.db import CaseDB, findings_t
from mulder.models import Finding
from mulder.server.app import _tool_dispatch_sync

REFS = ["tc_aabbccdd", "tc_11223344"]


def _finding(fid: str, **overrides: Any) -> Finding:
    base: dict[str, Any] = {
        "finding_id": fid,
        "case_id": "test-case",
        "title": "USB device RM1 connected",
        "description": f"Description of {fid}",
        "severity": "medium",
        "confidence": "inference",
        "evidence_refs": list(REFS),
        "sources": ["registry.usbstor"],
        "mitre_attack_ids": ["T1052.001"],
        "event_time_start": "2015-03-24T10:00:00Z",
        "event_time_end": "2015-03-24T11:00:00Z",
        "submitted_at": "2025-01-15T12:00:00Z",
    }
    base.update(overrides)
    return Finding(**base)


@pytest.fixture()
def ctx(tmp_path: Path) -> Iterator[Any]:
    db = CaseDB.create(case_id="test-case", evidence_root="/evidence", db_dir=tmp_path)
    audit = AuditLog(tmp_path / "test.audit.jsonl")
    for ref in REFS:
        audit.log_tool_call(ref, "search", {}, "sha256:x", duration_ms=1)
    mock = MagicMock()
    mock.db = db
    mock.audit = audit
    yield mock
    db.close()


def _call(ctx: Any, tool: str, **kwargs: Any) -> dict[str, Any]:
    with (
        patch("mulder.server.tools.findings.get_ctx", return_value=ctx),
        patch("mulder.server.tools.review.get_ctx", return_value=ctx),
        patch("mulder.server.tools.core.get_ctx", return_value=ctx),
        patch("mulder.server.helpers.has_ctx", return_value=False),
    ):
        return _tool_dispatch_sync[tool](**kwargs)  # type: ignore[no-any-return]


def _insert_raw_empty_refs(db: CaseDB, fid: str) -> None:
    """Insert a row the way the bug left it: evidence_refs='[]'."""
    with db._engine.begin() as conn:
        conn.execute(
            insert(findings_t).values(
                finding_id=fid,
                case_id="test-case",
                title="Analysis of files on optical media",
                description="d",
                severity="medium",
                confidence="inference",
                evidence_refs="[]",
                sources='["tsk.filelist"]',
                mitre_attack_ids="[]",
                submitted_at="2025-01-15T12:00:00Z",
            )
        )


class TestWritePaths:
    def test_update_with_empty_refs_keeps_stored_refs(self, ctx: Any) -> None:
        ctx.db.insert_finding(_finding("f_1"))

        result = _call(ctx, "update_finding", finding_id="f_1", evidence_refs=[], severity="high")

        assert result["status"] == "updated"
        assert result["updated_fields"] == ["severity"]
        stored = ctx.db.get_finding("f_1")
        assert stored is not None
        assert stored.evidence_refs == REFS
        assert stored.severity == "high"

    def test_update_that_would_invalidate_row_is_rejected(self, ctx: Any) -> None:
        ctx.db.insert_finding(_finding("f_1"))

        result = _call(ctx, "update_finding", finding_id="f_1", severity="catastrophic")

        assert result["status"] == "error"
        assert "invalid finding" in str(result["error_message"])
        stored = ctx.db.get_finding("f_1")
        assert stored is not None
        assert stored.severity == "medium"

    def test_dedup_leaves_survivors_with_refs(self, ctx: Any) -> None:
        ctx.db.insert_finding(_finding("f_a", description="Short."))
        ctx.db.insert_finding(_finding("f_b", evidence_refs=[REFS[0]]))
        ctx.db.insert_finding(
            _finding(
                "f_c",
                title="7z archive created on desktop",
                evidence_refs=["tc_7z000001"],
                sources=["mft.csv"],
                mitre_attack_ids=["T1560.001"],
                event_time_start="2015-03-26T14:00:00Z",
                event_time_end=None,
            )
        )
        ctx.db.insert_finding(
            _finding(
                "f_d",
                title="IAMAN CD burned",
                evidence_refs=["tc_cd000001"],
                sources=["cdburn.log"],
                mitre_attack_ids=["T1052"],
                event_time_start="2015-03-25T14:00:00Z",
                event_time_end=None,
            )
        )

        result = _call(ctx, "deduplicate_findings", case_id="test-case", dry_run=False)

        assert result["status"] == "success"
        assert result["merged_count"] == 1
        remaining = ctx.db.get_findings()
        assert len(remaining) == 3
        assert all(f.evidence_refs for f in remaining)
        assert ctx.db.get_invalid_findings() == []
        survivor = next(f for f in remaining if f.finding_id in {"f_a", "f_b"})
        assert survivor.evidence_refs == sorted(REFS)


class TestReadersSkipInvalidRows:
    def test_db_accessors_skip_and_report(self, ctx: Any) -> None:
        ctx.db.insert_finding(_finding("f_ok"))
        _insert_raw_empty_refs(ctx.db, "f_bad")

        assert [f.finding_id for f in ctx.db.get_findings()] == ["f_ok"]
        assert ctx.db.get_finding("f_bad") is None
        invalid = ctx.db.get_invalid_findings()
        assert [i["finding_id"] for i in invalid] == ["f_bad"]
        assert "evidence_refs" in invalid[0]["error"]

    @pytest.mark.parametrize(
        "tool", ["get_findings", "get_investigation_summary", "check_finalize_readiness"]
    )
    def test_tools_do_not_raise_and_report_invalid(self, ctx: Any, tool: str) -> None:
        ctx.db.insert_finding(_finding("f_ok"))
        _insert_raw_empty_refs(ctx.db, "f_bad")

        result = _call(ctx, tool)

        assert result["status"] == "success"
        assert [i["finding_id"] for i in result["invalid_findings"]] == ["f_bad"]

    def test_readiness_lists_invalid_row_as_work(self, ctx: Any) -> None:
        _insert_raw_empty_refs(ctx.db, "f_bad")

        readiness = _call(ctx, "check_finalize_readiness")
        summary = _call(ctx, "get_investigation_summary")

        assert "f_bad" in str(readiness["action"])
        assert any("f_bad" in item for item in summary["remaining_work"])
        assert summary["findings_submitted"] == 0
