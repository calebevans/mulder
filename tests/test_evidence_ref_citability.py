"""An evidence_ref must be a successful call to an evidence tool, not any logged id."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server.app import _tool_dispatch_sync
from mulder.server.helpers import error_response


@pytest.fixture()
def case_db(tmp_path: Path) -> CaseDB:
    return CaseDB.create(case_id="test-case", evidence_root="/evidence", db_dir=tmp_path)


@pytest.fixture()
def audit_log(tmp_path: Path) -> AuditLog:
    log_path = tmp_path / "test.audit.jsonl"
    # Written before this change: no "status" key. It must still count as a success.
    old_entry = {
        "type": "tool_call",
        "tool_call_id": "tc_0ld0ld00",
        "tool_name": "search_windows",
        "params": {"query": "cmd.exe"},
        "output_hash": "hash0",
        "duration_ms": 1.0,
        "timestamp": "2025-01-01T00:00:00+00:00",
    }
    log_path.write_text(json.dumps(old_entry) + "\n")
    log = AuditLog(log_path)
    log.log_tool_call("tc_aabbccdd", "run_volatility", {"plugin": "pslist"}, "hash1")
    return log


@pytest.fixture()
def ctx(case_db: CaseDB, audit_log: AuditLog) -> Iterator[MagicMock]:
    ctx = MagicMock()
    ctx.db = case_db
    ctx.audit = audit_log
    with (
        patch("mulder.server.tools.findings.get_ctx", return_value=ctx),
        patch("mulder.server.helpers.get_ctx", return_value=ctx),
        patch("mulder.server.helpers.has_ctx", return_value=True),
    ):
        yield ctx


def _submit(evidence_refs: list[str]) -> dict[str, object]:
    return _tool_dispatch_sync["submit_finding"](  # type: ignore[no-any-return]
        title="Suspicious process",
        description="cmd.exe spawned with network connection",
        severity="high",
        confidence="inference",
        evidence_refs=evidence_refs,
        sources=["volatility.pslist"],
        event_time_start="2025-01-15T08:30:00Z",
    )


def test_successful_evidence_calls_are_citable(ctx: MagicMock) -> None:
    assert _submit(["tc_aabbccdd", "tc_0ld0ld00"])["status"] == "accepted"


def test_a_rejected_submission_cannot_be_cited(ctx: MagicMock) -> None:
    rejected = _submit(["tc_deadbeef"])
    assert rejected["status"] == "error"

    result = _submit([str(rejected["tool_call_id"])])

    assert result["status"] == "error"
    assert ctx.db.get_findings() == []


def test_a_failed_call_cannot_be_cited(ctx: MagicMock) -> None:
    failed = error_response("tc_f41l3d00", "search_windows", {"query": "x"}, "boom")
    assert ctx.audit.get_tool_call(failed["tool_call_id"])["status"] == "error"

    result = _submit(["tc_f41l3d00"])

    assert result["status"] == "error"
    assert "tc_f41l3d00" in str(result["error_message"])
    assert "tc_f41l3d00" not in result["valid_refs"]  # type: ignore[operator]


def test_a_findings_tool_cannot_be_cited(ctx: MagicMock) -> None:
    listing = _tool_dispatch_sync["get_findings"]()
    assert listing["status"] == "success"

    assert _submit([str(listing["tool_call_id"])])["status"] == "error"


def test_update_applies_the_same_rule(ctx: MagicMock) -> None:
    finding_id = _submit(["tc_aabbccdd"])["finding_id"]
    rejected = _submit(["tc_deadbeef"])

    result = _tool_dispatch_sync["update_finding"](
        finding_id=finding_id, evidence_refs=[rejected["tool_call_id"]]
    )

    assert result["status"] == "error"
    [stored] = ctx.db.get_findings()
    assert stored.evidence_refs == ["tc_aabbccdd"]
