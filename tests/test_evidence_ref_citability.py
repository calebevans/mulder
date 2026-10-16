"""An evidence_ref must be a successful call to an evidence tool, not any logged id."""

from __future__ import annotations

import ast
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import anyio
import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server import app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.helpers import audited_tool, error_response
from mulder.server.tool_access import ALLOWED_TOOLS_ENV


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


# --- the status flag reaches the audit log from every error path ---------------------


def _entry_by_id(ctx: MagicMock, tool_call_id: str) -> dict[str, object]:
    entry = ctx.audit.get_tool_call(tool_call_id)
    assert entry is not None
    return cast("dict[str, object]", entry)


def _entry(ctx: MagicMock, result: dict[str, object]) -> dict[str, object]:
    entry = ctx.audit.get_tool_call(str(result["tool_call_id"]))
    assert entry is not None
    return cast("dict[str, object]", entry)


class TestAuditedToolStatus:
    """``audited_tool`` marks a returned error and a raised exception as uncitable."""

    def test_a_returned_error_is_marked(self, ctx: MagicMock) -> None:
        @audited_tool("probe_tool")
        def probe() -> dict[str, object]:
            return {"status": "error", "error_message": "boom"}

        result = probe()

        assert _entry(ctx, result)["status"] == "error"
        assert _submit([str(result["tool_call_id"])])["status"] == "error"

    def test_a_raised_exception_is_marked(self, ctx: MagicMock) -> None:
        @audited_tool("probe_tool")
        def probe() -> dict[str, object]:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            probe()

        [failed_id] = [i for i in ctx.audit.tool_call_ids if i not in _KNOWN_IDS]
        assert _entry_by_id(ctx, failed_id)["status"] == "error"
        assert _submit([failed_id])["status"] == "error"

    def test_a_success_stays_citable(self, ctx: MagicMock) -> None:
        @audited_tool("probe_tool")
        def probe() -> dict[str, object]:
            return {"status": "success"}

        result = probe()

        assert "status" not in _entry(ctx, result)
        assert _submit([str(result["tool_call_id"])])["status"] == "accepted"


_KNOWN_IDS = {"tc_0ld0ld00", "tc_aabbccdd"}


def test_a_bare_error_return_in_a_tool_is_not_citable(ctx: MagicMock) -> None:
    """``extract_file_by_inode`` without icat returns an error through a bare log call."""
    with (
        patch("mulder.server.tools.tsk.get_ctx", return_value=ctx),
        patch("mulder.server.tools.tsk.shutil.which", return_value=None),
    ):
        result = _tool_dispatch_sync["extract_file_by_inode"](inode=5)

    assert result["status"] == "error"
    assert _entry(ctx, result)["status"] == "error"
    assert _submit([str(result["tool_call_id"])])["status"] == "error"


def test_a_dispatcher_with_nothing_to_run_is_not_citable(ctx: MagicMock) -> None:
    """Both dispatchers' audit entries are marked when every task is refused."""
    with (
        patch.dict(os.environ, {ALLOWED_TOOLS_ENV: "mcp__mulder__wait"}),
        patch("mulder.server.tools.jobs.get_ctx", return_value=ctx),
        patch("mulder.server.tools.jobs.has_ctx", return_value=True),
        patch("mulder.server.tools.jobs._get_job_store", return_value=MagicMock()),
        patch("mulder.server.app.get_ctx", return_value=ctx),
        patch("mulder.server.app.has_ctx", return_value=True),
    ):
        batch = _tool_dispatch_sync["start_extraction_batch"]([{"tool": "update_finding"}])
        parallel = anyio.run(app.run_parallel, [{"tool": "update_finding", "args": {}}])

    assert batch["status"] == "error"
    assert _entry(ctx, batch)["status"] == "error"
    assert _submit([str(batch["tool_call_id"])])["status"] == "error"
    batch_id = str(parallel["batch_id"])
    assert _entry_by_id(ctx, batch_id)["status"] == "error"
    assert _submit([batch_id])["status"] == "error"


def _unmarked_error_returns() -> list[str]:
    """``log_tool_call`` calls without ``status`` that are followed by an error return."""
    root = Path(__file__).parent.parent / "src" / "mulder" / "server"
    found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        source = path.read_text()
        for node in ast.walk(ast.parse(source)):
            for block in (getattr(node, "body", None), getattr(node, "orelse", None)):
                if not isinstance(block, list):
                    continue
                for i, stmt in enumerate(block):
                    if not isinstance(stmt, ast.Expr | ast.Try):
                        continue
                    for call in ast.walk(stmt):
                        if not (
                            isinstance(call, ast.Call)
                            and isinstance(call.func, ast.Attribute)
                            and call.func.attr == "log_tool_call"
                            and not any(k.arg == "status" for k in call.keywords)
                        ):
                            continue
                        following = "".join(
                            ast.get_source_segment(source, s) or "" for s in block[i + 1 : i + 3]
                        )
                        before_return = following.split("return", 2)[:2]
                        if '"status": "error"' in "return".join(before_return):
                            found.append(f"{path.name}:{call.lineno}")
    return found


def test_no_error_return_is_logged_as_a_success() -> None:
    """Every tool that logs a call and then returns ``status: error`` marks the entry."""
    assert _unmarked_error_returns() == []
