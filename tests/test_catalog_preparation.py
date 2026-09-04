"""CLI-owned, content-bound evidence preparation tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.adapters import IntakeError, IntakeManifest, prepare_evidence_case
from mulder.db import CaseDB
from mulder.orchestrator.runner import Orchestrator
from mulder.run_state import RunStateError


def test_generic_directory_preparation_is_byte_idempotent(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "host-a.evtx").write_bytes(b"event-log")
    (evidence / "autoruns.csv").write_text("Entry,Image Path\nRun,evil.exe\n")
    db_dir = tmp_path / "cases"

    first = prepare_evidence_case(evidence, "case-a", db_dir)
    manifest_path = db_dir / "case-a.intake.json"
    first_bytes = manifest_path.read_bytes()
    second = prepare_evidence_case(evidence, "case-a", db_dir)

    assert first.collection_format == "generic"
    assert second.collection_digest == first.collection_digest
    assert manifest_path.read_bytes() == first_bytes
    with CaseDB.open("case-a", db_dir) as db:
        registry = db.get_evidence_registry()
    assert len(registry) == 2
    assert {Path(str(row["file_path"])).name for row in registry} == {
        "autoruns.csv",
        "host-a.evtx",
    }


def test_preparation_rejects_changed_or_retargeted_input_without_replacing_case(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    artifact = evidence / "capture.pcap"
    artifact.write_bytes(b"original")
    db_dir = tmp_path / "cases"
    prepare_evidence_case(evidence, "case-a", db_dir)
    database = db_dir / "case-a.db"
    original_inode = database.stat().st_ino
    original_manifest = (db_dir / "case-a.intake.json").read_bytes()

    artifact.write_bytes(b"changed")
    with pytest.raises(IntakeError, match="changed|different immutable intake"):
        prepare_evidence_case(evidence, "case-a", db_dir)

    artifact.write_bytes(b"original")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "capture.pcap").write_bytes(b"original")
    with pytest.raises(IntakeError, match="different immutable intake"):
        prepare_evidence_case(replacement, "case-a", db_dir)

    assert database.stat().st_ino == original_inode
    assert (db_dir / "case-a.intake.json").read_bytes() == original_manifest


def test_generic_single_file_is_content_bound_and_registered(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"memory-image")
    db_dir = tmp_path / "cases"

    manifest = prepare_evidence_case(evidence, "memory-case", db_dir)

    assert manifest.source_kind == "file"
    assert manifest.collection_format == "generic"
    assert len(manifest.entries) == 1
    assert manifest.source_sha256 == manifest.entries[0].sha256
    with CaseDB.open("memory-case", db_dir) as db:
        assert db.get_case_metadata().evidence_root == str(evidence.resolve())
        assert len(db.get_evidence_registry()) == 1


def test_legacy_case_with_different_root_is_not_adopted_or_replaced(tmp_path: Path) -> None:
    evidence = tmp_path / "selected-evidence"
    evidence.mkdir()
    (evidence / "sample.log").write_text("event", encoding="utf-8")
    other_root = tmp_path / "other-evidence"
    other_root.mkdir()
    db_dir = tmp_path / "cases"
    with CaseDB.create("case-a", str(other_root.resolve()), db_dir):
        pass
    database = db_dir / "case-a.db"
    original_inode = database.stat().st_ino

    with pytest.raises(IntakeError, match="different evidence source"):
        prepare_evidence_case(evidence, "case-a", db_dir)

    assert database.stat().st_ino == original_inode
    assert not (db_dir / "case-a.intake.json").exists()


@pytest.mark.asyncio()
async def test_runtime_prepares_before_provider_or_proxy_start(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "sample.log").write_text("event", encoding="utf-8")
    manifest = prepare_evidence_case(evidence, "case-a", tmp_path / "prepared")
    order: list[str] = []

    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orchestrator = Orchestrator(
            str(evidence),
            case_id="case-a",
            db_dir=tmp_path / "runtime",
        )

    def prepare() -> IntakeManifest:
        order.append("prepare")
        return manifest

    def preflight() -> None:
        order.append("provider-preflight")
        raise RuntimeError("stop before provider startup")

    with (
        patch.object(orchestrator, "_prepare_input", side_effect=prepare),
        patch.object(orchestrator, "_preflight_provider_routes", side_effect=preflight),
        pytest.raises(RuntimeError, match="stop before provider startup"),
    ):
        await orchestrator.run()

    assert order == ["prepare", "provider-preflight"]
    assert orchestrator._prepared_intake is manifest


@pytest.mark.asyncio()
async def test_mutation_after_preparation_fails_before_provider_preflight(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    artifact = evidence / "sample.log"
    artifact.write_text("original", encoding="utf-8")
    db_dir = tmp_path / "cases"
    manifest = prepare_evidence_case(evidence, "case-a", db_dir)
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orchestrator = Orchestrator(
            str(evidence),
            case_id="case-a",
            db_dir=db_dir,
            prepared_intake=manifest,
        )
    artifact.write_text("mutated", encoding="utf-8")

    with (
        patch.object(orchestrator, "_preflight_provider_routes") as provider_preflight,
        pytest.raises(RunStateError, match="changed before provider startup"),
    ):
        await orchestrator.run()

    provider_preflight.assert_not_called()
