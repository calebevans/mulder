"""Tests for append-only review events and exact-state approval gates."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from asyncio import run
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from mulder.audit import AuditLog
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.models import AtomicClaimInput, EvidenceAnchorInput, Finding, WindowRow
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import InvestigationResult, PhaseResult
from mulder.receipt import SealError, seal_case
from mulder.review.decisions import ReviewWorkflow, ReviewWorkflowError


def _case(tmp_path: Path, case_id: str = "reviewed") -> tuple[Path, Path]:
    evidence = tmp_path / "evidence.log"
    content = b"host-a executed evil.exe\n"
    evidence.write_bytes(content)
    db = CaseDB.create(case_id, str(tmp_path), tmp_path)
    db.register_evidence_file(
        str(evidence), "sha256:" + hashlib.sha256(content).hexdigest(), len(content)
    )
    source_id = db.register_source(
        "host.processes",
        str(evidence),
        "sha256:" + hashlib.sha256(content).hexdigest(),
        "fixture",
        1,
    )
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=1,
                line_end=1,
                event_time="2026-01-01T00:00:00Z",
                raw_text=content.decode().strip(),
            )
        ],
    )
    window = db.get_windows_by_source("host.processes")[0]
    assert window.window_id is not None
    db.insert_finding(
        Finding(
            finding_id="finding-1",
            case_id=case_id,
            title="Execution",
            description="evil.exe executed",
            severity="high",
            confidence="inference",
            evidence_refs=["tc-1"],
            sources=["host.processes"],
            submitted_at="2026-01-01T00:00:01Z",
        ),
        [
            AtomicClaimInput(
                statement="host-a executed evil.exe",
                subject="host-a",
                predicate="executed",
                object_value="evil.exe",
                anchors=[
                    EvidenceAnchorInput(
                        tool_call_id="tc-1",
                        window_id=window.window_id,
                        char_start=16,
                        char_end=24,
                        expected_text="evil.exe",
                    )
                ],
            )
        ],
    )
    db.close()
    audit_path = tmp_path / f"{case_id}.audit.jsonl"
    audit = AuditLog(audit_path)
    audit.log_tool_call("tc-1", "search", {"query": "evil.exe"}, "sha256:one")
    audit.log_finding_submission("finding-1", ["tc-1"])
    return tmp_path / f"{case_id}.db", audit_path


def test_review_events_are_append_only_resumable_and_bounded(tmp_path: Path) -> None:
    db_path, _audit = _case(tmp_path)
    workflow = ReviewWorkflow("reviewed", tmp_path)
    first = workflow.append_event(
        "comment",
        subject_type="claim",
        subject_id="claim-1",
        reviewer="examiner-a",
        comment="check parent process",
    )
    second = workflow.append_event(
        "follow_up",
        subject_type="finding",
        subject_id="finding-1",
        reviewer="examiner-a",
        comment="collect Prefetch",
    )

    resumed = ReviewWorkflow("reviewed", tmp_path).events(after_sequence=first.sequence)
    assert resumed == (second,)
    with sqlite3.connect(db_path) as connection, pytest.raises(
        sqlite3.IntegrityError, match="append-only"
    ):
        connection.execute("UPDATE review_events SET comment='changed'")


def test_approval_survives_restart_and_allows_audit_descendants(tmp_path: Path) -> None:
    _db_path, audit_path = _case(tmp_path)
    workflow = ReviewWorkflow("reviewed", tmp_path)
    request = workflow.request_approval(requested_by="pipeline")
    workflow.decide(request.request_id, "approve", reviewer="examiner-a")

    restarted = ReviewWorkflow("reviewed", tmp_path)
    assert restarted.require_approved_state().state == "approved"
    AuditLog(audit_path).log_tool_call("tc-report", "finalize_report", {}, "sha256:report")
    descendant = ReviewWorkflow("reviewed", tmp_path).require_approved_state()
    assert descendant.state == "approved"
    assert descendant.audit_head_digest != request.audit_head_digest


def test_changed_claim_set_makes_pending_and_completed_approval_stale(tmp_path: Path) -> None:
    db_path, _audit_path = _case(tmp_path)
    workflow = ReviewWorkflow("reviewed", tmp_path)
    request = workflow.request_approval(requested_by="pipeline")
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE claims SET statement='materially changed claim'")

    with pytest.raises(ReviewWorkflowError, match="stale"):
        workflow.decide(request.request_id, "approve", reviewer="examiner-a")
    assert workflow.status().state == "stale"


def test_rejected_snapshot_requires_rework_before_new_request(tmp_path: Path) -> None:
    db_path, _audit_path = _case(tmp_path)
    workflow = ReviewWorkflow("reviewed", tmp_path)
    request = workflow.request_approval(requested_by="pipeline")
    workflow.decide(request.request_id, "reject", reviewer="examiner-a", comment="insufficient")

    with pytest.raises(ReviewWorkflowError, match="must change"):
        workflow.request_approval(requested_by="pipeline")
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE claims SET statement='reworked claim'")
    replacement = workflow.request_approval(requested_by="pipeline")
    assert replacement.request_id != request.request_id


def test_seal_approval_gate_binds_decision_and_default_remains_autonomous(
    tmp_path: Path,
) -> None:
    _case(tmp_path)
    default_manifest = seal_case("reviewed", tmp_path)
    assert default_manifest.is_file()
    default_manifest.unlink()

    with pytest.raises(SealError, match="Approval gate failed"):
        seal_case("reviewed", tmp_path, require_approval=True)

    workflow = ReviewWorkflow("reviewed", tmp_path)
    request = workflow.request_approval(requested_by="pipeline")
    workflow.decide(request.request_id, "approve", reviewer="examiner-a")
    manifest_path = seal_case("reviewed", tmp_path, require_approval=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["review_approval"]["state"] == "approved"
    assert manifest["review_approval"]["request"]["request_id"] == request.request_id


def test_cli_request_approve_status_and_stale_failure(tmp_path: Path) -> None:
    db_path, _audit_path = _case(tmp_path)
    runner = CliRunner()
    requested = runner.invoke(
        cli,
        ["request-approval", "reviewed", "--requested-by", "pipeline", "--db-dir", str(tmp_path)],
    )
    assert requested.exit_code == 0, requested.output
    request_id = json.loads(requested.output)["request_id"]
    approved = runner.invoke(
        cli,
        [
            "approve",
            "reviewed",
            "--request-id",
            request_id,
            "--decision",
            "approve",
            "--reviewer",
            "examiner-a",
            "--db-dir",
            str(tmp_path),
        ],
    )
    assert approved.exit_code == 0, approved.output
    status = runner.invoke(cli, ["approval-status", "reviewed", "--db-dir", str(tmp_path)])
    assert json.loads(status.output)["state"] == "approved"

    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE claims SET object_value='other.exe'")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    stale = runner.invoke(
        cli,
        ["seal-case", "reviewed", "--db-dir", str(tmp_path), "--require-approval", "--force"],
    )
    assert stale.exit_code != 0
    assert "Approval gate failed" in stale.output


def test_report_only_resume_validates_persisted_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _case(tmp_path)
    workflow = ReviewWorkflow("reviewed", tmp_path)
    request = workflow.request_approval(requested_by="pipeline")
    workflow.decide(request.request_id, "approve", reviewer="examiner-a")
    orchestrator = Orchestrator(
        evidence_path=str(tmp_path),
        case_id="reviewed",
        db_dir=tmp_path,
        resume_after_approval=True,
    )
    phase = PhaseResult(phase_name="report", success=True, turns_used=2)
    execute_report = AsyncMock(return_value=phase)
    monkeypatch.setattr(orchestrator, "_run_single_phase", execute_report)
    monkeypatch.setattr(orchestrator, "_write_model_usage", lambda: None)
    monkeypatch.setattr(orchestrator._evidence, "load_case_briefing", lambda: "brief")

    result = run(orchestrator._run_approved_report(InvestigationResult()))

    assert result.success
    assert result.review_state == "approved"
    assert result.approval_request_id == request.request_id
    execute_report.assert_awaited_once()


def test_report_only_resume_refuses_changed_claims(tmp_path: Path) -> None:
    db_path, _audit_path = _case(tmp_path)
    workflow = ReviewWorkflow("reviewed", tmp_path)
    request = workflow.request_approval(requested_by="pipeline")
    workflow.decide(request.request_id, "approve", reviewer="examiner-a")
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE claims SET object_value='changed.exe'")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    orchestrator = Orchestrator(
        evidence_path=str(tmp_path),
        case_id="reviewed",
        db_dir=tmp_path,
        resume_after_approval=True,
    )

    with pytest.raises(ReviewWorkflowError, match="stale"):
        run(orchestrator._run_approved_report(InvestigationResult()))
