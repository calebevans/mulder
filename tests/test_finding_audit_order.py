"""Every finding in the database must have a provenance chain in the audit log."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server.app import _tool_dispatch_sync


@pytest.fixture()
def ctx(tmp_path: Path) -> Iterator[MagicMock]:
    ctx = MagicMock()
    ctx.db = CaseDB.create(case_id="test-case", evidence_root="/evidence", db_dir=tmp_path)
    ctx.audit = AuditLog(tmp_path / "test.audit.jsonl")
    ctx.audit.log_tool_call("tc_aabbccdd", "run_volatility", {"plugin": "pslist"}, "hash1")
    with patch("mulder.server.tools.findings.get_ctx", return_value=ctx):
        yield ctx


def _submit() -> dict[str, object]:
    return _tool_dispatch_sync["submit_finding"](  # type: ignore[no-any-return]
        title="Suspicious process",
        description="cmd.exe spawned with network connection",
        severity="high",
        confidence="inference",
        evidence_refs=["tc_aabbccdd"],
        sources=["volatility.pslist"],
        event_time_start="2025-01-15T08:30:00Z",
    )


def test_submitted_finding_has_a_provenance_chain(ctx: MagicMock) -> None:
    finding_id = str(_submit()["finding_id"])

    chain = ctx.audit.get_provenance_chain(finding_id, ctx.db)
    assert [tc.tool_call_id for tc in chain.tool_calls] == ["tc_aabbccdd"]


def test_interrupted_submission_leaves_no_finding_without_provenance(ctx: MagicMock) -> None:
    # The process dies between the two writes of a submission.
    with (
        patch.object(ctx.audit, "log_finding_submission", side_effect=RuntimeError("killed")),
        pytest.raises(RuntimeError),
    ):
        _submit()

    for finding in ctx.db.get_findings():
        ctx.audit.get_provenance_chain(finding.finding_id, ctx.db)
    assert ctx.db.get_findings() == []
