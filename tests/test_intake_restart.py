"""Immutable collection intake and restart-safe orchestration tests."""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
import sqlite3
import stat
import struct
import threading
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

import mulder.audit as audit_module
import mulder.receipt as receipt_module
from mulder.adapters import (
    IntakeError,
    IntakeLimits,
    ingest_collection,
    load_intake_manifest,
    materialize_intake,
    read_intake_member,
    scan_collection,
    verify_intake_source,
)
from mulder.audit import AuditLog
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.models import AuditSummary, CaseMetadataRow
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.roles import RoleRunner
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import ExecutionResults, PhaseResult
from mulder.receipt import SealError, seal_case, verify_case
from mulder.report.renderer import ReportRenderer
from mulder.review.events import RunEventDraft, RunEventJournal
from mulder.run_state import (
    RunCancelled,
    RunLedger,
    RunStateError,
    digest_value,
    forecast_health,
    hold_active_run_lease,
)
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools import case as case_tools


def _kape_collection(root: Path) -> Path:
    root.mkdir()
    (root / "_kape.log").write_text(
        "KAPE Version: 1.3.0\nCollection ID: flow-7\nHost Name: ws-01\n",
        encoding="utf-8",
    )
    registry = root / "C" / "Windows" / "System32" / "config"
    registry.mkdir(parents=True)
    (registry / "SYSTEM").write_bytes(b"registry fixture")
    return root


def _audit_event(path: Path, case_id: str, message: str) -> None:
    RunEventJournal(path, case_id).append(RunEventDraft(kind="info", message=message))


def _completed_run_case(tmp_path: Path) -> tuple[Path, RunLedger, str, str]:
    """Build one intake-backed case with a real audit-bound checkpoint."""
    source = _kape_collection(tmp_path / "collection")
    db_dir = tmp_path / "cases"
    intake = ingest_collection(source, "case", db_dir)
    audit_path = db_dir / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger = RunLedger("case", db_dir / "case.runs.db", audit_path)
    run = ledger.open_run(profile="full", input_digest=intake.collection_digest)
    phase_input = digest_value("phase", {"receipt": True})
    attempt = ledger.begin_phase(
        run.run_id,
        generation=run.generation,
        step_key="catalog:receipt",
        phase_name="catalog",
        input_digest=phase_input,
    )
    ledger.complete_phase(
        attempt,
        PhaseResult(phase_name="catalog", success=True, messages=["sealed"]),
        generation=run.generation,
    )
    ledger.write_summary(run.run_id, db_dir / "case.run.json")
    return db_dir, ledger, run.run_id, attempt


def _crash_during_checkpoint(
    ledger_path: str,
    audit_path: str,
    attempt_id: str,
    generation: int,
    stage: str,
) -> None:
    """Child-process crash injector for actual SQLite recovery coverage."""
    ledger = RunLedger("case", Path(ledger_path), Path(audit_path))
    result = PhaseResult(phase_name="catalog", success=True, messages=["durable"])
    if stage == "after_proposal":
        original_connect = RunLedger._connect
        calls = 0

        def crash_before_commit(
            selected: RunLedger,
            *,
            configure_journal: bool = False,
        ) -> sqlite3.Connection:
            nonlocal calls
            calls += 1
            if calls == 2:
                os._exit(71)
            return original_connect(selected, configure_journal=configure_journal)

        with patch.object(RunLedger, "_connect", new=crash_before_commit):
            ledger.complete_phase(attempt_id, result, generation=generation)
        return

    if stage == "mid_transaction":
        original_event = RunLedger._event

        def crash_before_transaction_commit(
            connection: sqlite3.Connection,
            run_id: str,
            kind: str,
            actor: str,
            detail: object,
        ) -> None:
            if kind == "phase_completed":
                os._exit(73)
            original_event(connection, run_id, kind, actor, detail)

        with patch.object(
            RunLedger,
            "_event",
            new=staticmethod(crash_before_transaction_commit),
        ):
            ledger.complete_phase(attempt_id, result, generation=generation)
        return

    def crash_after_commit(**_fields: object) -> None:
        os._exit(72)

    with patch("mulder.run_state.PhaseCheckpoint", side_effect=crash_after_commit):
        ledger.complete_phase(attempt_id, result, generation=generation)


def test_kape_intake_is_content_bound_and_duplicate_import_is_idempotent(
    tmp_path: Path,
) -> None:
    source = _kape_collection(tmp_path / "collection")
    db_dir = tmp_path / "cases"

    first = ingest_collection(source, "case-1", db_dir, host="examiner-host")
    second = ingest_collection(source, "case-1", db_dir, host="examiner-host")

    assert first.created is True
    assert first.database_created is True
    assert first.registered_files == 2
    assert second.created is False
    assert second.database_created is False
    assert second.registered_files == 0
    manifest = load_intake_manifest(Path(first.manifest_path))
    assert manifest.collection_format == "kape"
    assert manifest.provenance.collector_version == "1.3.0"
    assert manifest.provenance.collection_id == "flow-7"
    assert manifest.provenance.host == "ws-01"
    assert [item.model_dump() for item in manifest.provenance.examiner_assertions] == [
        {"field": "host", "value": "examiner-host"}
    ]
    with CaseDB.open("case-1", db_dir) as database:
        registry = database.get_evidence_registry()
        assert len(registry) == 2
        assert {item["acquisition"]["acquisition_id"] for item in registry} == {
            manifest.collection_digest
        }
        assert {item["acquisition"]["host_id"] for item in registry} == {"ws-01"}

    (source / "C" / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(
        b"changed registry fixture"
    )
    with pytest.raises(IntakeError, match="changed"):
        ingest_collection(source, "case-1", db_dir, host="examiner-host")


def test_content_identity_excludes_examiner_assertions(tmp_path: Path) -> None:
    source = _kape_collection(tmp_path / "collection")

    first = scan_collection(source, "case-1", host="first-assertion")
    second = scan_collection(source, "case-1", host="corrected-assertion")

    assert first.collection_digest == second.collection_digest
    assert first.integrity["manifest_hash"] != second.integrity["manifest_hash"]
    assert first.provenance.examiner_assertions != second.provenance.examiner_assertions


def test_stored_directory_manifest_rejects_mutation_and_new_members(tmp_path: Path) -> None:
    source = _kape_collection(tmp_path / "collection")
    result = ingest_collection(source, "case-1", tmp_path / "cases")
    manifest_path = Path(result.manifest_path)

    added = source / "unexpected.log"
    added.write_text("not committed", encoding="utf-8")
    with pytest.raises(IntakeError, match="inventory changed"):
        load_intake_manifest(manifest_path)
    added.unlink()

    member = source / "C" / "Windows" / "System32" / "config" / "SYSTEM"
    member.write_bytes(b"changed registry fixture")
    with pytest.raises(IntakeError, match="member (?:size )?changed"):
        load_intake_manifest(manifest_path)


def test_stored_directory_manifest_rejects_symlink_replacement(tmp_path: Path) -> None:
    source = _kape_collection(tmp_path / "collection")
    result = ingest_collection(source, "case-1", tmp_path / "cases")
    manifest_path = Path(result.manifest_path)
    member = source / "C" / "Windows" / "System32" / "config" / "SYSTEM"
    external = tmp_path / "external"
    external.write_bytes(member.read_bytes())
    member.unlink()
    member.symlink_to(external)

    with pytest.raises(IntakeError, match="symbolic links"):
        load_intake_manifest(manifest_path)


def test_velociraptor_zip_retains_collector_provenance_without_extracting(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "collection.zip"
    context = {
        "Version": "0.73.2",
        "Request": {"FlowId": "F.CAFE", "ClientId": "C.1234"},
    }
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("collection_context.json", json.dumps(context))
        handle.writestr("uploads/ntfs/$MFT", b"mft")

    manifest = scan_collection(archive, "case-v")

    assert manifest.collection_format == "velociraptor"
    assert manifest.source_kind == "zip"
    assert manifest.source_sha256 is not None
    assert manifest.provenance.collection_id == "F.CAFE"
    assert manifest.provenance.host == "C.1234"
    assert [entry.storage for entry in manifest.entries] == ["zip_member", "zip_member"]
    assert not (tmp_path / "uploads").exists()


def test_verified_zip_member_read_is_bounded_and_detects_container_mutation(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "collection.zip"
    context = json.dumps({"Version": "0.73.2", "FlowId": "F.CAFE"}).encode()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("collection_context.json", context)
        handle.writestr("uploads/ntfs/$MFT", b"mft")
    result = ingest_collection(archive, "case-v", tmp_path / "cases")
    manifest = load_intake_manifest(Path(result.manifest_path))

    assert read_intake_member(
        manifest,
        "collection_context.json",
        max_bytes=len(context),
    ) == context
    materialized = tmp_path / "materialized"
    assert materialize_intake(
        manifest,
        materialized,
        max_file_bytes=1 << 20,
        max_total_bytes=2 << 20,
    ) == ("collection_context.json", "uploads/ntfs/$MFT")
    assert (materialized / "uploads" / "ntfs" / "$MFT").read_bytes() == b"mft"
    assert (materialized / "uploads" / "ntfs" / "$MFT").stat().st_mode & 0o222 == 0
    with pytest.raises(IntakeError, match="byte limit"):
        read_intake_member(manifest, "collection_context.json", max_bytes=1)

    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("collection_context.json", context)
        handle.writestr("uploads/ntfs/$MFT", b"changed")
    with pytest.raises(IntakeError, match="ZIP intake source changed"):
        verify_intake_source(manifest)


def test_archive_symlink_duplicate_and_compression_bomb_are_rejected(tmp_path: Path) -> None:
    symlink_archive = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("uploads/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(symlink_archive, "w") as handle:
        handle.writestr("collection_context.json", "{}")
        handle.writestr(link, "../../outside")
    with pytest.raises(IntakeError, match="symbolic link"):
        scan_collection(symlink_archive, "case-link")

    duplicate_archive = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(duplicate_archive, "w") as handle:
        handle.writestr("collection_context.json", "{}")
        handle.writestr("uploads/FILE", "one")
        handle.writestr("uploads/file", "two")
    with pytest.raises(IntakeError, match="duplicate or case-folding"):
        scan_collection(duplicate_archive, "case-duplicate")

    bomb_archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb_archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("collection_context.json", "{}")
        handle.writestr("uploads/repeated.bin", b"x" * (1 << 20))
    with pytest.raises(IntakeError, match="max_archive_ratio"):
        scan_collection(bomb_archive, "case-bomb")


def test_archive_container_and_central_directory_are_bounded_before_expansion(
    tmp_path: Path,
) -> None:
    container = tmp_path / "container.zip"
    with zipfile.ZipFile(container, "w") as handle:
        handle.writestr("collection_context.json", "{}")
        handle.writestr("large.bin", b"x" * 4096)
    with pytest.raises(IntakeError, match="max_container_bytes"):
        scan_collection(
            container,
            "case-container",
            limits=IntakeLimits(max_container_bytes=1024),
        )

    directory_bomb = tmp_path / "directory-bomb.zip"
    with zipfile.ZipFile(directory_bomb, "w") as handle:
        handle.writestr("collection_context.json", "{}")
        handle.writestr("one", "1")
        handle.writestr("two", "2")
    with pytest.raises(IntakeError, match="max_archive_entries"):
        scan_collection(
            directory_bomb,
            "case-directory",
            limits=IntakeLimits(max_archive_entries=2),
        )
    with pytest.raises(IntakeError, match="max_central_directory_bytes"):
        scan_collection(
            directory_bomb,
            "case-central-directory",
            limits=IntakeLimits(max_central_directory_bytes=64),
        )

    forged = bytearray(directory_bomb.read_bytes())
    eocd = forged.rfind(b"PK\x05\x06")
    assert eocd >= 0
    struct.pack_into("<HH", forged, eocd + 8, 1, 1)
    forged_archive = tmp_path / "forged-count.zip"
    forged_archive.write_bytes(forged)
    with pytest.raises(IntakeError, match="entry count is inconsistent"):
        scan_collection(forged_archive, "case-forged-directory")


def test_zip64_central_directory_obeys_preflight_bounds(tmp_path: Path) -> None:
    archive = tmp_path / "zip64.zip"
    with (
        patch.object(zipfile, "ZIP_FILECOUNT_LIMIT", 1),
        zipfile.ZipFile(archive, "w") as handle,
    ):
        handle.writestr("collection_context.json", "{}")
        handle.writestr("payload", "x")
    raw = archive.read_bytes()
    assert b"PK\x06\x06" in raw
    assert b"PK\x06\x07" in raw
    assert scan_collection(archive, "case-zip64-valid").file_count == 2

    with pytest.raises(IntakeError, match="max_archive_entries"):
        scan_collection(
            archive,
            "case-zip64-entries",
            limits=IntakeLimits(max_archive_entries=1),
        )
    with pytest.raises(IntakeError, match="max_central_directory_bytes"):
        scan_collection(
            archive,
            "case-zip64-directory",
            limits=IntakeLimits(max_central_directory_bytes=64),
        )


def test_downstream_nested_zip_inherits_intake_expansion_bounds(tmp_path: Path) -> None:
    archive = tmp_path / "nested.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("payload.bin", b"x" * (2 << 20))
    assert archive.stat().st_size < 3 << 10

    destination = tmp_path / "nested-output"
    result = _tool_dispatch_sync[case_tools.extract_archive.__name__](
        str(archive), str(destination)
    )

    assert result["status"] == "error"
    assert "max_archive_ratio" in str(result["error_message"])
    assert not (destination / "payload.bin").exists()


@pytest.mark.parametrize("member", ["../escape", "/absolute", "dir\\file"])
def test_archive_escape_paths_are_rejected(tmp_path: Path, member: str) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("collection_context.json", "{}")
        handle.writestr(member, "payload")
    with pytest.raises(IntakeError, match="path"):
        scan_collection(archive, "case-unsafe")


def test_checkpoint_resume_requires_exact_input_and_existing_audit_position(
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    handle = ledger.open_run(profile="full", input_digest="sha256:" + "a" * 64)
    _audit_event(audit_path, "case", "before")
    phase_input = digest_value("test", {"input": 1})
    attempt = ledger.begin_phase(
        handle.run_id,
        generation=handle.generation,
        step_key="catalog:one",
        phase_name="catalog",
        input_digest=phase_input,
    )
    _audit_event(audit_path, "case", "phase output committed")
    expected = PhaseResult(
        phase_name="catalog",
        success=True,
        messages=['{"systems":[{"name":"host"}]}'],
        tool_names=["scan_evidence"],
        turns_used=3,
    )
    checkpoint = ledger.complete_phase(attempt, expected, generation=handle.generation)
    _integrity, audit_entries = AuditLog(audit_path).read_verified_snapshot()
    checkpoint_event = next(
        entry for entry in audit_entries if entry.get("entry_hash") == checkpoint.audit_head_after
    )
    assert checkpoint_event["checkpoint_state"] == "proposed"
    assert checkpoint_event["attempt_number"] == 1
    _audit_event(audit_path, "case", "after")

    resumed = ledger.resume_phase(
        handle.run_id,
        generation=handle.generation,
        step_key="catalog:one",
        input_digest=phase_input,
    )
    assert resumed is not None
    assert resumed.messages == expected.messages
    assert resumed.turns_used == 3
    assert (
        ledger.resume_phase(
            handle.run_id,
            generation=handle.generation,
            step_key="catalog:one",
            input_digest=digest_value("test", {"input": 2}),
        )
        is None
    )

    with sqlite3.connect(ledger_path) as connection:
        original_result = connection.execute(
            "SELECT result_json FROM phase_attempts WHERE attempt_id=?", (attempt,)
        ).fetchone()[0]
        connection.execute(
            "UPDATE phase_attempts SET result_json=? WHERE attempt_id=?",
            (json.dumps({"phase_name": "catalog", "success": True}), attempt),
        )
    with pytest.raises(RunStateError, match="audit envelope"):
        ledger.resume_phase(
            handle.run_id,
            generation=handle.generation,
            step_key="catalog:one",
            input_digest=phase_input,
        )
    with sqlite3.connect(ledger_path) as connection:
        connection.execute(
            "UPDATE phase_attempts SET result_json=? WHERE attempt_id=?",
            (original_result, attempt),
        )

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if checkpoint.audit_head_after not in line]
    audit_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    with pytest.raises(RunStateError, match="audit envelope"):
        ledger.resume_phase(
            handle.run_id,
            generation=handle.generation,
            step_key="catalog:one",
            input_digest=phase_input,
        )


def test_run_contract_and_review_state_are_enforced_on_resume(tmp_path: Path) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger = RunLedger("case", tmp_path / "case.runs.db", audit_path)
    contract = digest_value("contract", {"approval": True})
    handle = ledger.open_run(
        profile="quick",
        input_digest="sha256:" + "b" * 64,
        contract_digest=contract,
        approval_required=True,
    )
    ledger.finish(handle.run_id, "awaiting_review", generation=handle.generation)

    with pytest.raises(RunStateError, match="approved-report resume"):
        ledger.open_run(
            profile="quick",
            input_digest=handle.input_digest,
            contract_digest=contract,
            approval_required=True,
            run_id=handle.run_id,
            resume=True,
        )
    with pytest.raises(RunStateError, match="run contract"):
        ledger.open_run(
            profile="quick",
            input_digest=handle.input_digest,
            contract_digest=digest_value("contract", {"approval": False}),
            approval_required=True,
            allow_awaiting_review_resume=True,
            run_id=handle.run_id,
            resume=True,
        )
    resumed = ledger.open_run(
        profile="quick",
        input_digest=handle.input_digest,
        contract_digest=contract,
        approval_required=True,
        allow_awaiting_review_resume=True,
        run_id=handle.run_id,
        resume=True,
    )
    assert resumed.status == "running"
    ledger.finish(handle.run_id, "completed", generation=resumed.generation)
    with pytest.raises(RunStateError, match="cannot be cancelled"):
        ledger.request_cancel(handle.run_id, requested_by="examiner")


def test_resuming_a_running_handle_supersedes_the_prior_process_lease(tmp_path: Path) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger = RunLedger("case", tmp_path / "case.runs.db", audit_path)
    first = ledger.open_run(profile="full", input_digest="sha256:" + "e" * 64)
    resumed = ledger.open_run(
        profile=first.profile,
        input_digest=first.input_digest,
        contract_digest=first.contract_digest,
        run_id=first.run_id,
        resume=True,
    )
    assert resumed.generation == first.generation + 1
    with pytest.raises(RunStateError, match="lease was superseded"):
        ledger.begin_phase(
            first.run_id,
            generation=first.generation,
            step_key="catalog:stale",
            phase_name="catalog",
            input_digest=digest_value("phase", {"stale": True}),
        )


def test_resume_cannot_overtake_an_inflight_tool_lease(tmp_path: Path) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    first = ledger.open_run(profile="full", input_digest="sha256:" + "f" * 64)

    with (
        hold_active_run_lease("case", ledger_path, first.run_id, first.generation),
        pytest.raises(RunStateError, match="active tool invocations"),
    ):
        ledger.open_run(
            profile=first.profile,
            input_digest=first.input_digest,
            contract_digest=first.contract_digest,
            run_id=first.run_id,
            resume=True,
        )

    resumed = ledger.open_run(
        profile=first.profile,
        input_digest=first.input_digest,
        contract_digest=first.contract_digest,
        run_id=first.run_id,
        resume=True,
    )
    with (
        pytest.raises(RunStateError, match="lease was superseded"),
        hold_active_run_lease("case", ledger_path, first.run_id, first.generation),
    ):
        pass
    with hold_active_run_lease("case", ledger_path, resumed.run_id, resumed.generation):
        pass


def test_terminal_transition_cannot_overtake_an_inflight_tool_lease(
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    run = ledger.open_run(profile="full", input_digest="sha256:" + "0" * 64)
    with (
        hold_active_run_lease("case", ledger_path, run.run_id, run.generation),
        pytest.raises(RunStateError, match="active tool invocations"),
    ):
        ledger.finish(run.run_id, "failed", generation=run.generation)
    assert ledger.status(run.run_id).status == "running"
    assert ledger.finish(run.run_id, "failed", generation=run.generation).status == "failed"


def test_orphan_checkpoint_proposal_is_not_completion(tmp_path: Path) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    run = ledger.open_run(profile="full", input_digest="sha256:" + "1" * 64)
    phase_input = digest_value("phase", {"orphan": True})
    attempt = ledger.begin_phase(
        run.run_id,
        generation=run.generation,
        step_key="catalog:orphan",
        phase_name="catalog",
        input_digest=phase_input,
    )
    result = PhaseResult(phase_name="catalog", success=True, messages=["done"])

    with (
        patch.object(RunLedger, "_event", side_effect=RuntimeError("simulated crash")),
        pytest.raises(RuntimeError, match="simulated crash"),
    ):
        ledger.complete_phase(attempt, result, generation=run.generation)

    with sqlite3.connect(ledger_path) as connection:
        assert connection.execute(
            "SELECT status FROM phase_attempts WHERE attempt_id=?", (attempt,)
        ).fetchone() == ("running",)
    assert ledger.status(run.run_id).completed_steps == ()
    assert (
        ledger.resume_phase(
            run.run_id,
            generation=run.generation,
            step_key="catalog:orphan",
            input_digest=phase_input,
        )
        is None
    )
    _integrity, entries = AuditLog(audit_path).read_verified_snapshot()
    proposals = [
        entry
        for entry in entries
        if entry.get("attempt_id") == attempt and entry.get("type") == "run_checkpoint"
    ]
    assert len(proposals) == 1
    assert proposals[0]["checkpoint_state"] == "proposed"

    replacement = ledger.begin_phase(
        run.run_id,
        generation=run.generation,
        step_key="catalog:orphan",
        phase_name="catalog",
        input_digest=phase_input,
    )
    assert replacement != attempt
    with sqlite3.connect(ledger_path) as connection:
        assert connection.execute(
            "SELECT status FROM phase_attempts ORDER BY attempt_number"
        ).fetchall() == [("interrupted",), ("running",)]


def test_committed_checkpoint_survives_failure_after_sqlite_commit(tmp_path: Path) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    run = ledger.open_run(profile="full", input_digest="sha256:" + "2" * 64)
    phase_input = digest_value("phase", {"committed": True})
    attempt = ledger.begin_phase(
        run.run_id,
        generation=run.generation,
        step_key="catalog:committed",
        phase_name="catalog",
        input_digest=phase_input,
    )
    result = PhaseResult(phase_name="catalog", success=True, messages=["durable"])

    with (
        patch("mulder.run_state.PhaseCheckpoint", side_effect=RuntimeError("return crash")),
        pytest.raises(RuntimeError, match="return crash"),
    ):
        ledger.complete_phase(attempt, result, generation=run.generation)

    restored = RunLedger("case", ledger_path, audit_path).resume_phase(
        run.run_id,
        generation=run.generation,
        step_key="catalog:committed",
        input_digest=phase_input,
    )
    assert restored is not None
    assert restored.messages == ["durable"]


@pytest.mark.parametrize(
    ("stage", "exit_code", "committed"),
    [
        ("after_proposal", 71, False),
        ("mid_transaction", 73, False),
        ("after_commit", 72, True),
    ],
)
def test_checkpoint_recovers_from_actual_process_termination(
    tmp_path: Path,
    stage: str,
    exit_code: int,
    committed: bool,
) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    run = ledger.open_run(profile="full", input_digest="sha256:" + "3" * 64)
    phase_input = digest_value("phase", {"process-crash": stage})
    attempt = ledger.begin_phase(
        run.run_id,
        generation=run.generation,
        step_key=f"catalog:{stage}",
        phase_name="catalog",
        input_digest=phase_input,
    )

    process = mp.get_context("fork").Process(
        target=_crash_during_checkpoint,
        args=(
            str(ledger_path),
            str(audit_path),
            attempt,
            run.generation,
            stage,
        ),
    )
    process.start()
    process.join(timeout=10)
    assert not process.is_alive()
    assert process.exitcode == exit_code

    recovered = RunLedger("case", ledger_path, audit_path)
    restored = recovered.resume_phase(
        run.run_id,
        generation=run.generation,
        step_key=f"catalog:{stage}",
        input_digest=phase_input,
    )
    if committed:
        assert restored is not None
        assert restored.messages == ["durable"]
    else:
        assert restored is None
        assert recovered.status(run.run_id).completed_steps == ()
        _integrity, entries = AuditLog(audit_path).read_verified_snapshot()
        assert any(
            entry.get("type") == "run_checkpoint"
            and entry.get("attempt_id") == attempt
            and entry.get("checkpoint_state") == "proposed"
            for entry in entries
        )


def test_status_rejects_completed_row_bound_to_noncheckpoint_event(tmp_path: Path) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    run = ledger.open_run(profile="full", input_digest="sha256:" + "4" * 64)
    phase_input = digest_value("phase", {"wrong-state": True})
    attempt = ledger.begin_phase(
        run.run_id,
        generation=run.generation,
        step_key="catalog:wrong-state",
        phase_name="catalog",
        input_digest=phase_input,
    )
    ledger.complete_phase(
        attempt,
        PhaseResult(phase_name="catalog", success=True, messages=["done"]),
        generation=run.generation,
    )
    _audit_event(audit_path, "case", "not a checkpoint proposal")
    wrong_hash = AuditLog(audit_path).verify_integrity().head_hash
    assert isinstance(wrong_hash, str)
    with sqlite3.connect(ledger_path) as connection:
        connection.execute(
            "UPDATE phase_attempts SET audit_head_after=?,checkpoint_event_hash=? "
            "WHERE attempt_id=?",
            (wrong_hash, wrong_hash, attempt),
        )
    with pytest.raises(RunStateError, match="audit envelope"):
        ledger.status(run.run_id)


def test_abandoned_attempt_is_marked_interrupted_and_cancellation_persists(
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    handle = ledger.open_run(profile="quick", input_digest="sha256:" + "b" * 64)
    phase_input = digest_value("test", {"step": 1})
    first = ledger.begin_phase(
        handle.run_id,
        generation=handle.generation,
        step_key="extraction:host",
        phase_name="extraction",
        input_digest=phase_input,
    )
    second = ledger.begin_phase(
        handle.run_id,
        generation=handle.generation,
        step_key="extraction:host",
        phase_name="extraction",
        input_digest=phase_input,
    )
    assert first != second
    with sqlite3.connect(ledger_path) as connection:
        statuses = connection.execute(
            "SELECT status FROM phase_attempts ORDER BY attempt_number"
        ).fetchall()
    assert statuses == [("interrupted",), ("running",)]

    cancelled = ledger.request_cancel(handle.run_id, requested_by="examiner")
    assert cancelled.status == "cancel_requested"
    with pytest.raises(RunCancelled):
        RunLedger("case", ledger_path, audit_path).assert_active(
            handle.run_id,
            generation=handle.generation,
        )


@pytest.mark.asyncio()
async def test_orchestrator_restores_report_checkpoint_and_quick_budget(
    tmp_path: Path,
) -> None:
    from mulder.orchestrator.phases import REPORT

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "sample.log").write_text("event", encoding="utf-8")
    db_dir = tmp_path / "cases"
    audit_path = db_dir / "case.audit.jsonl"
    state_path = db_dir / "case.runs.db"
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        first = Orchestrator(
            str(evidence),
            case_id="case",
            db_dir=db_dir,
            run_event_path=audit_path,
            run_state_path=state_path,
            run_profile="quick",
        )
    assert first.run_handle is not None
    assert first.env["MULDER_RUN_ID"] == first.run_handle.run_id
    assert first.env["MULDER_RUN_GENERATION"] == "1"
    assert first.env["MULDER_DB_DIR"] == str(db_dir.resolve())
    _audit_event(audit_path, "case", "run started")
    execute = AsyncMock(
        return_value=PhaseResult(
            phase_name="report",
            tool_names=["finalize_report"],
            turns_used=2,
        )
    )
    with patch.object(first._session, "execute", execute):
        completed = await first._run_single_phase(REPORT, {"case_briefing": "brief"})
    assert completed.success is True
    awaited = execute.await_args
    assert awaited is not None
    assert awaited.kwargs["max_budget"] == pytest.approx(
        REPORT.single_max_budget_usd * 0.35
    )

    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        resumed = Orchestrator(
            str(evidence),
            case_id="case",
            db_dir=db_dir,
            run_event_path=audit_path,
            run_state_path=state_path,
            run_profile="quick",
            run_id=first.run_handle.run_id,
            resume_run=True,
        )
    assert resumed.run_handle is not None
    assert resumed.env["MULDER_RUN_ID"] == first.run_handle.run_id
    assert resumed.env["MULDER_RUN_GENERATION"] == "2"
    resumed_execute = AsyncMock(side_effect=AssertionError("checkpoint should be reused"))
    with patch.object(resumed._session, "execute", resumed_execute):
        restored = await resumed._run_single_phase(REPORT, {"case_briefing": "brief"})
    assert restored.success is True
    resumed_execute.assert_not_awaited()


def test_unapproved_report_resume_does_not_mutate_awaiting_run(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    db_dir = tmp_path / "cases"
    audit_path = db_dir / "case.audit.jsonl"
    state_path = db_dir / "case.runs.db"
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        first = Orchestrator(
            str(evidence),
            case_id="case",
            db_dir=db_dir,
            approval_before_report=True,
            run_event_path=audit_path,
            run_state_path=state_path,
        )
    assert first.run_handle is not None
    assert first._run_ledger is not None
    awaiting = first._run_ledger.finish(
        first.run_handle.run_id,
        "awaiting_review",
        generation=first.run_handle.generation,
    )

    with (
        patch("mulder.orchestrator.runner.InvestigationDashboard"),
        pytest.raises(RunStateError, match="resume is not authorized"),
    ):
        Orchestrator(
            str(evidence),
            case_id="case",
            db_dir=db_dir,
            resume_after_approval=True,
            run_event_path=audit_path,
            run_state_path=state_path,
            run_id=awaiting.run_id,
            resume_run=True,
        )
    unchanged = first._run_ledger.status(awaiting.run_id)
    assert unchanged.status == "awaiting_review"
    assert unchanged.generation == awaiting.generation


def test_cli_requires_run_handle_for_approved_report_resume(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    result = CliRunner().invoke(
        cli,
        ["investigate", str(evidence), "case", "--resume-after-approval"],
    )
    assert result.exit_code == 2
    assert "requires --resume-run RUN_ID" in result.output


def test_quick_profile_report_cannot_present_full_coverage(tmp_path: Path) -> None:
    audit_path = tmp_path / "quick.audit.jsonl"
    audit_path.write_text("", encoding="utf-8")
    ledger = RunLedger("quick", tmp_path / "quick.runs.db", audit_path)
    run = ledger.open_run(
        profile="quick",
        input_digest="sha256:" + "c" * 64,
        run_id="run-quick",
    )
    ledger.write_summary(run.run_id, tmp_path / f"quick.{run.run_id}.run.json")
    metadata = CaseMetadataRow(
        case_id="quick",
        ingested_at="2026-01-01T00:00:00Z",
        evidence_root="/evidence",
        extractor_versions={},
    )
    summary = AuditSummary(
        total_tool_calls=0,
        total_findings=0,
        tool_call_counts={},
        total_duration_ms=0,
        first_timestamp="",
        last_timestamp="",
    )

    markdown = ReportRenderer(run_id=run.run_id).render(metadata, [], summary, audit_path)
    html = ReportRenderer(run_id=run.run_id).render_html(metadata, [], summary, audit_path)

    assert "SAMPLED TRIAGE — NOT FULL COVERAGE" in markdown
    assert "must not be interpreted as complete" in markdown
    assert "SAMPLED TRIAGE &mdash; NOT FULL COVERAGE" in html

    (tmp_path / "quick.report.md").write_text(markdown, encoding="utf-8")
    (tmp_path / "quick.report.html").write_text(html, encoding="utf-8")
    binding = {
        "schema": "mulder.report-run-binding",
        "version": 1,
        "case_id": "quick",
        "run_id": run.run_id,
        "reports": {
            "quick.report.md": "sha256:"
            + hashlib.sha256(markdown.encode()).hexdigest(),
            "quick.report.html": "sha256:"
            + hashlib.sha256(html.encode()).hexdigest(),
        },
    }
    (tmp_path / "quick.report-run.json").write_text(
        json.dumps(binding),
        encoding="utf-8",
    )
    newer = ledger.open_run(
        profile="full",
        input_digest="sha256:" + "f" * 64,
        run_id="run-newer",
    )
    ledger.write_summary(newer.run_id, tmp_path / "quick.run.json")
    still_bound = ReportRenderer().render(metadata, [], summary, audit_path)
    assert "SAMPLED TRIAGE — NOT FULL COVERAGE" in still_bound

    with sqlite3.connect(tmp_path / "quick.runs.db") as connection:
        connection.execute(
            "UPDATE runs SET coverage_ceiling='evidence_bounded' WHERE run_id=?",
            (run.run_id,),
        )
    invalid = ReportRenderer(run_id=run.run_id).render(metadata, [], summary, audit_path)
    assert "COVERAGE UNKNOWN — DO NOT CLAIM FULL COVERAGE" in invalid


def test_standalone_report_cannot_invalidate_durable_run_binding(tmp_path: Path) -> None:
    db_dir, _ledger, run_id, _attempt = _completed_run_case(tmp_path)
    markdown_path = db_dir / "case.report.md"
    html_path = db_dir / "case.report.html"
    markdown_path.write_bytes(b"bound markdown\n")
    html_path.write_bytes(b"bound html\n")
    binding_path = db_dir / "case.report-run.json"
    binding = {
        "schema": "mulder.report-run-binding",
        "version": 1,
        "case_id": "case",
        "run_id": run_id,
        "reports": {
            markdown_path.name: "sha256:"
            + hashlib.sha256(markdown_path.read_bytes()).hexdigest(),
            html_path.name: "sha256:" + hashlib.sha256(html_path.read_bytes()).hexdigest(),
        },
    }
    binding_path.write_text(json.dumps(binding), encoding="utf-8")
    original = {
        markdown_path: markdown_path.read_bytes(),
        html_path: html_path.read_bytes(),
        binding_path: binding_path.read_bytes(),
    }

    result = CliRunner().invoke(
        cli,
        ["report", "case", "--db-dir", str(db_dir)],
    )

    assert result.exit_code == 1
    assert "Durable run state exists" in result.output
    assert {path: path.read_bytes() for path in original} == original


def test_receipt_binds_exact_run_checkpoint_and_audit_snapshot(tmp_path: Path) -> None:
    db_dir, _ledger, run_id, _attempt = _completed_run_case(tmp_path)

    manifest_path = seal_case("case", db_dir)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    run_state = manifest["operational_state"]["run"]
    audit_snapshot = AuditLog(db_dir / "case.audit.jsonl").read_verified_file_snapshot()

    assert verify_case(manifest_path).ok
    assert run_state["run_id"] == run_id
    assert run_state["completed_steps"] == ["catalog:receipt"]
    assert len(run_state["checkpoint_event_hashes"]) == 1
    assert manifest["audit"]["sha256"] == audit_snapshot.sha256
    assert manifest["audit"]["size_bytes"] == audit_snapshot.size_bytes
    assert manifest["audit"]["head_hash"] == audit_snapshot.integrity.head_hash


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("completed_steps", "completed steps"),
        ("non_object_result", "JSON object"),
        ("orphan_ancestry", "not audit-bound"),
    ],
)
def test_receipt_rejects_forged_run_checkpoint_state(
    tmp_path: Path,
    tamper: str,
    message: str,
) -> None:
    db_dir, _ledger, _run_id, attempt = _completed_run_case(tmp_path)
    ledger_path = db_dir / "case.runs.db"
    if tamper == "completed_steps":
        summary_path = db_dir / "case.run.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["completed_steps"] = ["catalog:forged"]
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
    elif tamper == "non_object_result":
        with sqlite3.connect(ledger_path) as connection:
            connection.execute(
                "UPDATE phase_attempts SET result_json='[]' WHERE attempt_id=?",
                (attempt,),
            )
    else:
        invalid_parent = "sha256:" + "0" * 64
        with sqlite3.connect(ledger_path) as connection:
            row = connection.execute(
                "SELECT attempt_number,run_id,step_key,phase_name,input_digest,"
                "result_digest,run_generation FROM phase_attempts WHERE attempt_id=?",
                (attempt,),
            ).fetchone()
        assert row is not None
        forged = AuditLog(db_dir / "case.audit.jsonl").log_checkpoint_event(
            "case",
            {
                "checkpoint_schema": "mulder.run-checkpoint",
                "checkpoint_version": 2,
                "attempt_id": attempt,
                "attempt_number": row[0],
                "run_id": row[1],
                "step_key": row[2],
                "phase_name": row[3],
                "input_digest": row[4],
                "result_digest": row[5],
                "phase_start_audit_head": invalid_parent,
                "run_generation": row[6],
            },
        )
        forged_hash = forged["entry_hash"]
        with sqlite3.connect(ledger_path) as connection:
            connection.execute(
                "UPDATE phase_attempts SET audit_head_before=?,audit_head_after=?,"
                "checkpoint_event_hash=? WHERE attempt_id=?",
                (invalid_parent, forged_hash, forged_hash, attempt),
            )

    with pytest.raises(SealError, match=message):
        seal_case("case", db_dir)


def test_receipt_rejects_summary_mutation_during_coordinated_snapshot(
    tmp_path: Path,
) -> None:
    db_dir, _ledger, _run_id, _attempt = _completed_run_case(tmp_path)
    summary_path = db_dir / "case.run.json"
    original_commitment = receipt_module._stable_file_commitment
    summary_reads = 0

    def mutate_on_snapshot_recheck(path: Path) -> tuple[str, int]:
        nonlocal summary_reads
        if Path(path) == summary_path:
            summary_reads += 1
            if summary_reads == 2:
                summary_path.write_bytes(summary_path.read_bytes() + b" ")
        return original_commitment(path)

    with (
        patch.object(
            receipt_module,
            "_stable_file_commitment",
            side_effect=mutate_on_snapshot_recheck,
        ),
        pytest.raises(SealError, match="summary changed"),
    ):
        seal_case("case", db_dir)


def test_receipt_does_not_publish_a_cross_snapshot_candidate(tmp_path: Path) -> None:
    db_dir, _ledger, _run_id, _attempt = _completed_run_case(tmp_path)
    manifest_path = seal_case("case", db_dir)
    original_manifest = manifest_path.read_bytes()
    original_commitment = receipt_module._audit_commitment

    def append_after_snapshot(path: Path) -> object:
        snapshot = original_commitment(path)
        _audit_event(path, "case", "concurrent audit append")
        return snapshot

    with (
        patch.object(
            receipt_module,
            "_audit_commitment",
            side_effect=append_after_snapshot,
        ),
        pytest.raises(SealError, match="changed while the receipt was being sealed"),
    ):
        seal_case("case", db_dir, overwrite=True)

    assert manifest_path.read_bytes() == original_manifest
    assert not list(db_dir.glob(".case.manifest.json.candidate.*"))


def test_receipt_publication_holds_audit_and_run_mutation_guards(
    tmp_path: Path,
) -> None:
    db_dir, ledger, run_id, _attempt = _completed_run_case(tmp_path)
    manifest_path = db_dir / "case.manifest.json"
    audit_started = threading.Event()
    audit_finished = threading.Event()
    cancel_started = threading.Event()
    cancel_finished = threading.Event()
    original_verify = receipt_module.verify_case
    original_replace = receipt_module.os.replace
    workers: list[threading.Thread] = []
    publication_observed = False

    def append_audit() -> None:
        audit_started.set()
        _audit_event(db_dir / "case.audit.jsonl", "case", "after publication")
        audit_finished.set()

    def cancel_run() -> None:
        cancel_started.set()
        ledger.request_cancel(run_id, requested_by="concurrent examiner")
        cancel_finished.set()

    def verify_then_start_mutators(path: Path) -> object:
        result = original_verify(path)
        workers.extend(
            [threading.Thread(target=append_audit), threading.Thread(target=cancel_run)]
        )
        for worker in workers:
            worker.start()
        assert audit_started.wait(timeout=1)
        assert cancel_started.wait(timeout=1)
        return result

    def observe_publication(source: Path, destination: Path) -> None:
        nonlocal publication_observed
        if Path(destination) == manifest_path:
            publication_observed = True
            assert not audit_finished.is_set()
            assert not cancel_finished.is_set()
            assert original_verify(Path(source)).ok
        original_replace(source, destination)

    with (
        patch.object(receipt_module, "verify_case", side_effect=verify_then_start_mutators),
        patch.object(receipt_module.os, "replace", side_effect=observe_publication),
    ):
        seal_case("case", db_dir, overwrite=True)

    for worker in workers:
        worker.join(timeout=2)
        assert not worker.is_alive()
    assert publication_observed
    assert audit_finished.is_set()
    assert cancel_finished.is_set()


def test_receipt_rolls_back_publication_when_audit_inode_is_replaced(
    tmp_path: Path,
) -> None:
    db_dir, _ledger, _run_id, _attempt = _completed_run_case(tmp_path)
    manifest_path = seal_case("case", db_dir)
    previous_manifest = manifest_path.read_bytes()
    audit_path = db_dir / "case.audit.jsonl"
    replacement = db_dir / "replacement.audit.jsonl"
    replacement.write_bytes(audit_path.read_bytes())
    _audit_event(replacement, "case", "valid replacement suffix")
    original_verify = receipt_module.verify_case
    replaced = False

    def verify_then_replace_inode(path: Path) -> object:
        nonlocal replaced
        result = original_verify(path)
        if not replaced:
            replaced = True
            worker = threading.Thread(
                target=os.replace,
                args=(replacement, audit_path),
            )
            worker.start()
            worker.join(timeout=2)
            assert not worker.is_alive()
        return result

    with (
        patch.object(
            receipt_module,
            "verify_case",
            side_effect=verify_then_replace_inode,
        ),
        pytest.raises(RuntimeError, match="replaced while being verified"),
    ):
        seal_case("case", db_dir, overwrite=True)

    assert manifest_path.read_bytes() == previous_manifest
    assert not list(db_dir.glob(".case.manifest.json.candidate.*"))
    assert not list(db_dir.glob(".case.manifest.json.previous.*"))


def test_receipt_non_overwrite_publication_is_atomic(tmp_path: Path) -> None:
    db_dir, _ledger, _run_id, _attempt = _completed_run_case(tmp_path)
    manifest_path = db_dir / "case.manifest.json"
    competing_content = b"concurrent manifest creator\n"
    original_verify = receipt_module.verify_case
    created = False

    def verify_then_create_destination(path: Path) -> object:
        nonlocal created
        result = original_verify(path)
        if not created:
            created = True
            worker = threading.Thread(
                target=manifest_path.write_bytes,
                args=(competing_content,),
            )
            worker.start()
            worker.join(timeout=2)
            assert not worker.is_alive()
        return result

    with (
        patch.object(
            receipt_module,
            "verify_case",
            side_effect=verify_then_create_destination,
        ),
        pytest.raises(SealError, match="already exists"),
    ):
        seal_case("case", db_dir)

    assert manifest_path.read_bytes() == competing_content
    assert not list(db_dir.glob(".case.manifest.json.candidate.*"))


def test_locked_audit_snapshot_rejects_inode_replacement(tmp_path: Path) -> None:
    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    audit = AuditLog(audit_path)
    original_scan = audit_module._scan_audit_file
    injected = False

    def replace_after_scan(
        path: Path,
        *,
        locked_handle: object = None,
    ) -> object:
        nonlocal injected
        scan = original_scan(path, locked_handle=locked_handle)
        if not injected:
            injected = True
            replacement = tmp_path / "replacement.audit.jsonl"
            replacement.write_bytes(audit_path.read_bytes())
            os.replace(replacement, audit_path)
        return scan

    with (
        patch.object(audit_module, "_scan_audit_file", side_effect=replace_after_scan),
        pytest.raises(RuntimeError, match="replaced while being verified"),
    ):
        audit.read_verified_file_snapshot()


def test_health_forecast_distinguishes_quick_and_full_working_sets(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.bin"
    with evidence.open("wb") as handle:
        handle.seek(1 << 30)
        handle.write(b"x")
    quick = forecast_health(
        evidence,
        "quick",
        free_disk_bytes=4 << 30,
        available_memory_bytes=1 << 30,
    )
    full = forecast_health(
        evidence,
        "full",
        free_disk_bytes=4 << 30,
        available_memory_bytes=1 << 30,
    )
    assert quick.profile == "quick"
    assert quick.required_working_bytes < full.required_working_bytes
    assert quick.basis == "size_heuristic_v1"
    unknown_memory = forecast_health(
        evidence,
        "quick",
        free_disk_bytes=4 << 30,
        available_memory_bytes=0,
    )
    assert unknown_memory.ready is False
    assert "available memory could not be determined" in unknown_memory.warnings

    archive = tmp_path / "compressed.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("large.log", b"x" * (2 << 20))
    archive_health = forecast_health(
        archive,
        "full",
        free_disk_bytes=4 << 30,
        available_memory_bytes=1 << 30,
    )
    assert archive_health.evidence_bytes == 2 << 20


def test_health_forecast_uses_the_lowest_output_volume(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"evidence")
    db_dir = tmp_path / "case-output"
    workspace = tmp_path / "workspace-output"
    db_dir.mkdir()
    workspace.mkdir()
    observed: list[Path] = []

    def disk_usage(path: Path) -> SimpleNamespace:
        selected = Path(path)
        observed.append(selected)
        free = 128 << 20 if selected == db_dir else 4 << 30
        return SimpleNamespace(total=8 << 30, used=(8 << 30) - free, free=free)

    with patch("mulder.run_state.shutil.disk_usage", side_effect=disk_usage):
        forecast = forecast_health(
            evidence,
            "full",
            working_paths=(db_dir, workspace),
            available_memory_bytes=1 << 30,
        )
    assert forecast.free_disk_bytes == 128 << 20
    assert forecast.ready is False
    assert observed == [db_dir, workspace]
    assert evidence not in observed


def test_health_forecast_probes_missing_output_ancestor_without_creating(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"evidence")
    planned = tmp_path / "missing" / "cases"
    observed: list[Path] = []

    def disk_usage(path: Path) -> SimpleNamespace:
        observed.append(Path(path))
        return SimpleNamespace(total=8 << 30, used=0, free=8 << 30)

    with patch("mulder.run_state.shutil.disk_usage", side_effect=disk_usage):
        forecast = forecast_health(
            evidence,
            "full",
            working_paths=(planned,),
            available_memory_bytes=1 << 30,
        )
    assert observed == [tmp_path]
    assert not planned.exists()
    assert any(
        str(planned) in warning and str(tmp_path) in warning
        for warning in forecast.warnings
    )

    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    with pytest.raises(RunStateError, match="non-directory ancestor"):
        forecast_health(
            evidence,
            "full",
            working_paths=(blocker / "cases",),
            available_memory_bytes=1 << 30,
        )


def test_forecast_cli_forwards_planned_output_locations(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"evidence")
    db_dir = tmp_path / "cases"
    workspace = tmp_path / "workspace"
    forecast = MagicMock()
    forecast.model_dump_json.return_value = "{}"
    with patch("mulder.run_state.forecast_health", return_value=forecast) as call:
        result = CliRunner().invoke(
            cli,
            [
                "forecast-run",
                str(evidence),
                "--db-dir",
                str(db_dir),
                "--cwd",
                str(workspace),
            ],
        )
    assert result.exit_code == 0, result.output
    assert call.call_args.kwargs["working_paths"] == (db_dir, workspace)


@pytest.mark.asyncio()
async def test_server_tool_guards_enforce_immutable_run_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mulder.server import app

    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    first = ledger.open_run(profile="full", input_digest="sha256:" + "3" * 64)
    monkeypatch.setenv("MULDER_CASE_ID", "case")
    monkeypatch.setenv("MULDER_RUN_ID", first.run_id)
    monkeypatch.setenv("MULDER_RUN_GENERATION", str(first.generation))
    app.init_server(tmp_path, mem_percent_limit=0, cpu_percent_limit=0)
    calls: list[str] = []

    def sync_body() -> str:
        calls.append("sync")
        return "ok"

    async def async_body() -> str:
        calls.append("async")
        return "ok"

    guarded_sync = app._guard_sync_tool(sync_body)
    guarded_async = app._guard_async_tool(async_body)
    assert guarded_sync() == "ok"
    assert await guarded_async() == "ok"
    assert app._tool_dispatch_sync["list_cases"]()["status"] == "success"
    assert (await app._tool_dispatch["run_parallel"](tasks=[]))["total_tasks"] == 0
    assert "enrich_iocs" not in app._tool_dispatch_sync

    resumed = ledger.open_run(
        profile=first.profile,
        input_digest=first.input_digest,
        contract_digest=first.contract_digest,
        run_id=first.run_id,
        resume=True,
    )
    with pytest.raises(RunStateError, match="lease was superseded"):
        guarded_sync()
    with pytest.raises(RunStateError, match="lease was superseded"):
        app._tool_dispatch_sync["list_cases"]()
    with pytest.raises(RunStateError, match="lease was superseded"):
        await app._tool_dispatch["run_parallel"](tasks=[])
    assert calls == ["sync", "async"]

    monkeypatch.setenv("MULDER_RUN_GENERATION", str(resumed.generation))
    app.init_server(tmp_path, mem_percent_limit=0, cpu_percent_limit=0)
    assert guarded_sync() == "ok"
    ledger.request_cancel(resumed.run_id, requested_by="examiner")
    with pytest.raises(RunCancelled):
        await guarded_async()

    monkeypatch.delenv("MULDER_CASE_ID")
    monkeypatch.delenv("MULDER_RUN_ID")
    monkeypatch.delenv("MULDER_RUN_GENERATION")
    app.init_server(tmp_path, mem_percent_limit=0, cpu_percent_limit=0)


def test_server_rejects_partial_run_lease_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mulder.server import app

    monkeypatch.setenv("MULDER_RUN_ID", "run-partial")
    monkeypatch.delenv("MULDER_RUN_GENERATION", raising=False)
    with pytest.raises(RuntimeError, match="configured together"):
        app.init_server(tmp_path, mem_percent_limit=0, cpu_percent_limit=0)
    monkeypatch.delenv("MULDER_RUN_ID")
    app.init_server(tmp_path, mem_percent_limit=0, cpu_percent_limit=0)


def test_timed_out_private_worker_retains_the_run_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mulder.server import app
    from mulder.server.tools.extract import volatility

    audit_path = tmp_path / "case.audit.jsonl"
    _audit_event(audit_path, "case", "start")
    ledger_path = tmp_path / "case.runs.db"
    ledger = RunLedger("case", ledger_path, audit_path)
    run = ledger.open_run(profile="full", input_digest="sha256:" + "5" * 64)
    phase_input = digest_value("phase", {"private-worker": True})
    attempt = ledger.begin_phase(
        run.run_id,
        generation=run.generation,
        step_key="extraction:memory",
        phase_name="extraction",
        input_digest=phase_input,
    )
    monkeypatch.setenv("MULDER_CASE_ID", "case")
    monkeypatch.setenv("MULDER_RUN_ID", run.run_id)
    monkeypatch.setenv("MULDER_RUN_GENERATION", str(run.generation))
    app.init_server(tmp_path, mem_percent_limit=0, cpu_percent_limit=0)
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def slow_plugin(*_args: object) -> dict[str, object]:
        started.set()
        release.wait(timeout=5)
        finished.set()
        return {
            "status": "ready_to_index",
            "_raw_output": "PID\tName\n4\tSystem",
        }

    with (
        patch.object(volatility, "_run_batch_plugin", side_effect=slow_plugin),
        patch.object(volatility, "extract_and_index") as late_index,
    ):
        outcome = volatility._run_batch_plugin_timed(
            object(), object(), object(), "windows.pslist.PsList", "memory.raw", 1
        )
    assert outcome["error_type"] == "timeout"
    assert started.wait(timeout=1)
    with pytest.raises(RunStateError, match="active tool invocations"):
        ledger.complete_phase(
            attempt,
            PhaseResult(phase_name="extraction", success=True),
            generation=run.generation,
        )
    with pytest.raises(RunStateError, match="active tool invocations"):
        ledger.open_run(
            profile=run.profile,
            input_digest=run.input_digest,
            contract_digest=run.contract_digest,
            run_id=run.run_id,
            resume=True,
        )
    release.set()
    assert finished.wait(timeout=1)
    late_index.assert_not_called()
    for _attempt in range(100):
        try:
            resumed = ledger.open_run(
                profile=run.profile,
                input_digest=run.input_digest,
                contract_digest=run.contract_digest,
                run_id=run.run_id,
                resume=True,
            )
        except RunStateError as exc:
            if "active tool invocations" not in str(exc):
                raise
            threading.Event().wait(timeout=0.01)
        else:
            break
    else:
        pytest.fail("private worker did not release its run lease")
    assert resumed.generation == 2

    monkeypatch.delenv("MULDER_CASE_ID")
    monkeypatch.delenv("MULDER_RUN_ID")
    monkeypatch.delenv("MULDER_RUN_GENERATION")
    app.init_server(tmp_path, mem_percent_limit=0, cpu_percent_limit=0)


@pytest.mark.asyncio()
async def test_background_batch_timeout_cannot_be_checkpointed() -> None:
    session = MagicMock()
    session.execute_utility = AsyncMock(
        return_value={"status": "timeout", "still_running": ["bg_deadbeef"]}
    )
    runner = RoleRunner(
        session=session,
        dashboard=MagicMock(),
        model_config=ModelConfig(),
        case_id="case",
        env={},
        cwd=".",
    )
    results = ExecutionResults(
        plan_id="plan",
        results=[],
        turns_used=1,
        has_failures=False,
        batch_ids={"bg_deadbeef"},
    )
    with pytest.raises(RuntimeError, match="durable terminal state"):
        await runner.ensure_batches_complete(results)

    session.execute_utility = AsyncMock(
        return_value={
            "status": "done",
            "all_done": True,
            "invalid_batches": {"bg_deadbeef": "unknown"},
            "batch_results": {},
        }
    )
    with pytest.raises(RuntimeError, match="could not be verified"):
        await runner.ensure_batches_complete(results)

    session.execute_utility = AsyncMock(
        return_value={
            "status": "done",
            "all_done": True,
            "batch_results": {"bg_deadbeef": {"all_done": True}},
        }
    )
    await runner.ensure_batches_complete(results)


def test_intake_and_run_control_cli(tmp_path: Path) -> None:
    source = _kape_collection(tmp_path / "collection")
    db_dir = tmp_path / "cases"
    runner = CliRunner()
    intake = runner.invoke(
        cli,
        ["intake-collection", str(source), "cli-case", "--db-dir", str(db_dir)],
    )
    assert intake.exit_code == 0, intake.output
    assert '"created": true' in intake.output

    audit_path = db_dir / "cli-case.audit.jsonl"
    _audit_event(audit_path, "cli-case", "created")
    ledger = RunLedger(
        "cli-case",
        db_dir / "cli-case.runs.db",
        audit_path,
    )
    handle = ledger.open_run(profile="full", input_digest="sha256:" + "d" * 64)
    status = runner.invoke(
        cli,
        ["run-status", "cli-case", handle.run_id, "--db-dir", str(db_dir)],
    )
    assert status.exit_code == 0, status.output
    assert handle.run_id in status.output
    cancel = runner.invoke(
        cli,
        [
            "cancel-run",
            "cli-case",
            handle.run_id,
            "--requested-by",
            "examiner",
            "--db-dir",
            str(db_dir),
        ],
    )
    assert cancel.exit_code == 0, cancel.output
    assert '"status": "cancel_requested"' in cancel.output
