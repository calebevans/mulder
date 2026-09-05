"""Adversarial coverage for manifest-backed catalog and extraction discovery."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.adapters import (
    IntakeError,
    IntakeManifest,
    prepare_evidence_case,
    scan_collection,
)
from mulder.adapters.catalog import CATALOG_PAGE_MAX_BYTES, evidence_types, manifest_catalog_page
from mulder.adapters.intake import CollectorProvenance, IntakeEntry
from mulder.extractors.classifier import ClassifiedEvidence, EvidenceClassifier
from mulder.orchestrator.capabilities import (
    DELEGATION_GRANT_ENV,
    DELEGATION_SECRET_ENV,
    create_delegation_grant,
    identity_for_phase,
)
from mulder.orchestrator.evidence import EvidenceContext
from mulder.orchestrator.types import PhaseResult
from mulder.server import app
from mulder.server.tools import case as case_tools


def _context(source: Path, case_id: str, db_dir: Path) -> tuple[IntakeManifest, EvidenceContext]:
    manifest = prepare_evidence_case(source, case_id, db_dir)
    return manifest, EvidenceContext(str(source), manifest=manifest)


def test_prepared_context_never_rescans_changed_or_added_live_members(
    tmp_path: Path,
) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    artifact = source / "capture.pcapng"
    artifact.write_bytes(b"original")
    _manifest, context = _context(source, "case-a", tmp_path / "cases")
    expected = context.build_evidence_context("host-that-is-not-in-the-path")

    artifact.write_bytes(b"changed")
    (source / "added.raw").write_bytes(b"late")
    with patch.object(Path, "rglob", side_effect=AssertionError("live rescan")):
        actual = context.build_evidence_context("host-that-is-not-in-the-path")

    assert actual == expected
    assert "added.raw" not in actual
    assert "capture.pcapng" in actual


def test_committed_briefing_rejects_post_preparation_change(tmp_path: Path) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    briefing = source / "MULDER.md"
    briefing.write_text("trusted question")
    _manifest, context = _context(source, "case-a", tmp_path / "cases")

    assert "trusted question" in context.load_case_briefing()
    briefing.write_text("changed question")

    with pytest.raises(IntakeError, match="changed"):
        context.load_case_briefing()


@pytest.mark.parametrize(
    ("filename", "expected_type"),
    [
        ("disk.E01", "disk_image"),
        ("memory.raw", "memory_dump"),
        ("traffic.pcapng", "network_capture"),
    ],
)
def test_single_file_intakes_are_directly_usable(
    tmp_path: Path,
    filename: str,
    expected_type: str,
) -> None:
    source = tmp_path / filename
    source.write_bytes(b"evidence")
    _manifest, context = _context(source, "single", tmp_path / "cases")

    decoded = json.loads(context.build_evidence_context("system"))

    assert decoded["assigned_artifact_count"] == 1
    assert decoded["entries"][0]["path"] == str(source.resolve())
    assert expected_type in decoded["entries"][0]["evidence_types"]


def test_single_zip_intake_is_exposed_as_its_committed_container(tmp_path: Path) -> None:
    source = tmp_path / "collection.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("nested/host.raw", b"memory")
    manifest, context = _context(source, "zip-case", tmp_path / "cases")

    decoded = json.loads(context.build_evidence_context("system"))

    assert decoded["entries"] == [
        {
            "artifact_id": f"{manifest.collection_digest}:container",
            "committed_members": 1,
            "evidence_types": ["archive"],
            "path": str(source.resolve()),
            "relative_path": source.name,
            "sha256": manifest.source_sha256,
            "size_bytes": None,
            "storage": "zip",
        }
    ]


def test_mixed_directory_assigns_every_committed_evidence_kind_without_name_filter(
    tmp_path: Path,
) -> None:
    source = tmp_path / "mixed"
    source.mkdir()
    (source / "alpha.E01").write_bytes(b"disk")
    (source / "beta.vmem").write_bytes(b"memory")
    (source / "gamma.pcapng").write_bytes(b"network")
    (source / "Autoruns.csv").write_text("Entry,Image Path\nRun,evil.exe\n")
    with zipfile.ZipFile(source / "nested.zip", "w") as archive:
        archive.writestr("payload.txt", "payload")
    _manifest, context = _context(source, "mixed", tmp_path / "cases")

    decoded = json.loads(context.build_evidence_context("unrelated-model-name"))
    types = {kind for entry in decoded["entries"] for kind in entry["evidence_types"]}

    assert {"disk_image", "memory_dump", "network_capture", "autoruns", "archive"} <= types
    assert decoded["assigned_artifact_count"] == 5


def test_trusted_collector_host_controls_assignment_and_assertions_stay_excluded(
    tmp_path: Path,
) -> None:
    source = tmp_path / "kape"
    source.mkdir()
    (source / "_kape.log").write_text(
        "KAPE Version: 1.3.0\nCollection ID: flow-7\nHost Name: ws-01\n"
    )
    (source / "Autoruns.csv").write_text("Entry,Image Path\nRun,evil.exe\n")
    manifest = scan_collection(source, "kape-case", host="examiner-assertion")
    context = EvidenceContext(str(source), manifest=manifest)
    catalog = {
        "case_id": "kape-case",
        "evidence_root": str(source),
        "systems": [{"name": "model-invented-host", "evidence": []}],
    }

    systems, normalized = context.identify_systems(
        PhaseResult(phase_name="catalog", success=True),
        catalog,
    )
    snapshot = context.catalog_snapshot_json()

    assert systems == ["ws-01"]
    assert manifest.provenance.examiner_assertions
    assert normalized["systems"][0]["name"] == "ws-01"
    assert '"host":"ws-01"' in snapshot
    assert "examiner_assertions" not in snapshot


def test_catalog_page_is_bounded_and_cursor_addressable(tmp_path: Path) -> None:
    source = tmp_path / "large"
    source.mkdir()
    for index in range(400):
        (source / f"host-{index:04d}-{'x' * 40}.log").write_text("event")
    manifest = prepare_evidence_case(source, "large-case", tmp_path / "cases")

    first = manifest_catalog_page(manifest)
    first_bytes = json.dumps(first, sort_keys=True, separators=(",", ":")).encode()
    second = manifest_catalog_page(manifest, cursor=int(first["next_cursor"]))

    assert len(first_bytes) <= CATALOG_PAGE_MAX_BYTES
    assert first["next_cursor"] is not None
    assert second["cursor"] == first["next_cursor"]
    assert second["entries"][0]["artifact_id"] != first["entries"][0]["artifact_id"]


def test_catalog_page_advances_for_a_valid_oversized_manifest_row(tmp_path: Path) -> None:
    relative_path = "payload-" + ("x" * 50_000) + ".log"
    digest = "sha256:" + ("a" * 64)
    manifest = IntakeManifest(
        case_id="oversized",
        source_kind="directory",
        source_path=str(tmp_path / "evidence"),
        source_sha256=None,
        collection_format="generic",
        provenance=CollectorProvenance(collector="generic", assertion_source="format_only"),
        entries=(
            IntakeEntry(
                relative_path=relative_path,
                size_bytes=1,
                sha256=digest,
                artifact_type="log",
                storage="file",
            ),
        ),
        file_count=1,
        total_bytes=1,
        collection_digest=digest,
        created_at="2026-01-01T00:00:00+00:00",
        integrity={"algorithm": "sha256", "manifest_hash": digest},
    )

    page = manifest_catalog_page(manifest, max_items=1, max_bytes=2048)
    encoded = json.dumps(page, sort_keys=True, separators=(",", ":")).encode()

    assert len(encoded) <= 2048
    assert page["page_bytes"] == len(encoded)
    assert page["next_cursor"] is None
    assert len(page["entries"]) == 1
    row = page["entries"][0]
    assert row["artifact_id"] == f"{digest}:0"
    assert row["sha256"] == digest
    assert row["entry_truncated"] is True
    assert row["relative_path_sha256"] == (
        "sha256:" + hashlib.sha256(relative_path.encode()).hexdigest()
    )


def test_catalog_page_compacts_oversized_prepared_collector_metadata(
    tmp_path: Path,
) -> None:
    host = "host-" + ("x" * 50_000)
    source = tmp_path / "collection.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("collection_context.json", json.dumps({"Hostname": host}))
        archive.writestr("uploads/events.json", "{}")
    manifest = prepare_evidence_case(source, "case-a", tmp_path / "cases")

    page = manifest_catalog_page(manifest)
    encoded = json.dumps(page, sort_keys=True, separators=(",", ":")).encode()

    assert len(encoded) <= CATALOG_PAGE_MAX_BYTES
    assert page["page_bytes"] == len(encoded)
    assert len(page["entries"]) == manifest.file_count
    provenance = page["provenance"]
    assert isinstance(provenance, dict)
    projected_host = provenance["host"]
    assert isinstance(projected_host, str)
    assert "…[truncated;sha256:" in projected_host
    assert projected_host.endswith(hashlib.sha256(host.encode()).hexdigest() + "]")


def test_catalog_page_tool_reads_only_authenticated_manifest_after_live_mutation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "original.log").write_text("original")
    prepare_evidence_case(source, "case-a", tmp_path / "cases")
    app.init_server(tmp_path / "cases", mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")
    (source / "added.log").write_text("late")

    result = app._tool_dispatch_sync["get_intake_catalog_page"]()

    assert result["status"] == "success"
    entries = result["catalog"]["entries"]
    assert [entry["relative_path"] for entry in entries] == ["original.log"]


def test_nested_archive_must_be_committed_and_unchanged(tmp_path: Path) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    nested = source / "nested.zip"
    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr("payload.txt", "original")
    prepare_evidence_case(source, "case-a", tmp_path / "cases")
    app.init_server(tmp_path / "cases", mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")

    success = app._tool_dispatch_sync["extract_archive"](
        str(nested), str(tmp_path / "first-extraction")
    )
    assert success["status"] == "success"
    assert (tmp_path / "first-extraction" / "payload.txt").read_text() == "original"

    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr("payload.txt", "changed")
    changed = app._tool_dispatch_sync["extract_archive"](
        str(nested), str(tmp_path / "changed-extraction")
    )
    assert changed["status"] == "error"
    assert changed["error_type"] == "intake_verification_failed"

    uncommitted = source / "late.zip"
    with zipfile.ZipFile(uncommitted, "w") as archive:
        archive.writestr("late.txt", "late")
    late = app._tool_dispatch_sync["extract_archive"](
        str(uncommitted), str(tmp_path / "late-extraction")
    )
    assert late["status"] == "error"
    assert late["error_type"] == "intake_verification_failed"


def test_nested_archive_member_uses_verified_outer_materialization(tmp_path: Path) -> None:
    inner_bytes = io.BytesIO()
    with zipfile.ZipFile(inner_bytes, "w") as inner:
        inner.writestr("payload.txt", "committed")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("nested/inner.zip", inner_bytes.getvalue())
    db_dir = tmp_path / "cases"
    prepare_evidence_case(outer, "case-a", db_dir)
    app.init_server(db_dir, mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")

    first = app._tool_dispatch_sync["extract_archive"](str(outer))
    assert first["status"] == "success"
    materialized_inner = db_dir / "extracted" / "outer" / "nested" / "inner.zip"
    second = app._tool_dispatch_sync["extract_archive"](
        str(materialized_inner), str(tmp_path / "inner-output")
    )
    assert second["status"] == "success"
    assert (tmp_path / "inner-output" / "payload.txt").read_text() == "committed"

    materialized_inner.chmod(0o600)
    materialized_inner.write_bytes(b"changed")
    rejected = app._tool_dispatch_sync["extract_archive"](
        str(materialized_inner), str(tmp_path / "changed-inner-output")
    )
    assert rejected["status"] == "error"
    assert rejected["error_type"] == "intake_verification_failed"


def test_directory_intake_nested_archive_uses_committed_materialization(
    tmp_path: Path,
) -> None:
    inner_bytes = io.BytesIO()
    with zipfile.ZipFile(inner_bytes, "w") as inner:
        inner.writestr("payload.txt", "committed")
    source = tmp_path / "evidence"
    source.mkdir()
    outer = source / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("nested/inner.zip", inner_bytes.getvalue())
    db_dir = tmp_path / "cases"
    prepare_evidence_case(source, "case-a", db_dir)
    app.init_server(db_dir, mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")

    first = app._tool_dispatch_sync["extract_archive"](str(outer))
    assert first["status"] == "success"
    materialized_inner = db_dir / "extracted" / "outer" / "nested" / "inner.zip"
    second = app._tool_dispatch_sync["extract_archive"](
        str(materialized_inner),
        str(db_dir / "extracted" / "inner"),
    )

    assert second["status"] == "success"
    assert (db_dir / "extracted" / "inner" / "payload.txt").read_text() == "committed"


def test_derived_archive_swap_during_verification_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    committed = io.BytesIO()
    with zipfile.ZipFile(committed, "w") as inner:
        inner.writestr("committed.txt", "committed")
    substituted = io.BytesIO()
    with zipfile.ZipFile(substituted, "w") as inner:
        inner.writestr("substituted.txt", "substituted")
    source = tmp_path / "evidence"
    source.mkdir()
    outer = source / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("nested/inner.zip", committed.getvalue())
    db_dir = tmp_path / "cases"
    prepare_evidence_case(source, "case-a", db_dir)
    app.init_server(db_dir, mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")

    first = app._tool_dispatch_sync["extract_archive"](str(outer))
    assert first["status"] == "success"
    materialized_inner = db_dir / "extracted" / "outer" / "nested" / "inner.zip"
    original_verify = case_tools.verify_intake_source

    def swap_after_source_verification(manifest: IntakeManifest) -> None:
        original_verify(manifest)
        materialized_inner.write_bytes(substituted.getvalue())

    monkeypatch.setattr(case_tools, "verify_intake_source", swap_after_source_verification)
    result = app._tool_dispatch_sync["extract_archive"](
        str(materialized_inner), str(db_dir / "extracted" / "inner")
    )

    assert result["status"] == "error"
    assert result["error_type"] == "intake_verification_failed"
    assert not (db_dir / "extracted" / "inner" / "substituted.txt").exists()


def test_nested_archive_is_receipted_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    committed = io.BytesIO()
    with zipfile.ZipFile(committed, "w") as inner:
        inner.writestr("committed.txt", "committed")
    substituted = io.BytesIO()
    with zipfile.ZipFile(substituted, "w") as inner:
        inner.writestr("substituted.txt", "substituted")
    source = tmp_path / "evidence"
    source.mkdir()
    outer = source / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("nested/inner.zip", committed.getvalue())
    db_dir = tmp_path / "cases"
    prepare_evidence_case(source, "case-a", db_dir)
    app.init_server(db_dir, mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")
    public_destination = db_dir / "extracted" / "outer"
    original_write = case_tools._write_materialization_receipt

    def substitute_public_destination(
        commitment: case_tools._ArchiveCommitment,
        archive: Path,
        *,
        materialized: Path,
        destination: Path,
    ) -> list[dict[str, object]]:
        assert destination == public_destination
        (destination / "nested").mkdir(parents=True)
        (destination / "nested" / "inner.zip").write_bytes(substituted.getvalue())
        return original_write(
            commitment,
            archive,
            materialized=materialized,
            destination=destination,
        )

    monkeypatch.setattr(
        case_tools,
        "_write_materialization_receipt",
        substitute_public_destination,
    )
    first = app._tool_dispatch_sync["extract_archive"](str(outer))
    monkeypatch.setattr(case_tools, "_write_materialization_receipt", original_write)
    second = app._tool_dispatch_sync["extract_archive"](
        str(public_destination / "nested" / "inner.zip"),
        str(db_dir / "extracted" / "inner"),
    )

    assert first["status"] == "error"
    assert second["status"] == "error"
    assert second["error_type"] == "intake_verification_failed"
    assert not (db_dir / "extracted" / "inner" / "substituted.txt").exists()


def test_staged_archive_change_after_receipt_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    committed = io.BytesIO()
    with zipfile.ZipFile(committed, "w") as inner:
        inner.writestr("committed.txt", "committed")
    substituted = io.BytesIO()
    with zipfile.ZipFile(substituted, "w") as inner:
        inner.writestr("substituted.txt", "substituted")
    source = tmp_path / "evidence"
    source.mkdir()
    outer = source / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("nested/inner.zip", committed.getvalue())
    db_dir = tmp_path / "cases"
    prepare_evidence_case(source, "case-a", db_dir)
    app.init_server(db_dir, mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")
    original_write = case_tools._write_materialization_receipt

    def substitute_staging_after_receipt(
        commitment: case_tools._ArchiveCommitment,
        archive: Path,
        *,
        materialized: Path,
        destination: Path,
    ) -> list[dict[str, object]]:
        entries = original_write(
            commitment,
            archive,
            materialized=materialized,
            destination=destination,
        )
        (materialized / "nested" / "inner.zip").write_bytes(substituted.getvalue())
        return entries

    monkeypatch.setattr(
        case_tools,
        "_write_materialization_receipt",
        substitute_staging_after_receipt,
    )
    result = app._tool_dispatch_sync["extract_archive"](str(outer))
    monkeypatch.setattr(case_tools, "_write_materialization_receipt", original_write)
    published_inner = db_dir / "extracted" / "outer" / "nested" / "inner.zip"
    nested = app._tool_dispatch_sync["extract_archive"](
        str(published_inner), str(db_dir / "extracted" / "inner")
    )

    assert result["status"] == "error"
    assert result["error_type"] == "intake_verification_failed"
    assert nested["status"] == "error"
    assert nested["error_type"] == "intake_verification_failed"


def test_committed_archive_classification_never_reopens_public_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    committed = io.BytesIO()
    with zipfile.ZipFile(committed, "w") as inner:
        inner.writestr("committed.txt", "committed")
    substituted = io.BytesIO()
    with zipfile.ZipFile(substituted, "w") as inner:
        inner.writestr("substituted.txt", "substituted")
    source = tmp_path / "evidence"
    source.mkdir()
    outer = source / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("nested/inner.zip", committed.getvalue())
    db_dir = tmp_path / "cases"
    prepare_evidence_case(source, "case-a", db_dir)
    app.init_server(db_dir, mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")
    public_destination = db_dir / "extracted" / "outer"
    public_inner = public_destination / "nested" / "inner.zip"
    original_inventory = case_tools._materialization_inventory
    original_classify = EvidenceClassifier.classify
    classified_roots: list[Path] = []

    def replace_after_public_inventory(destination: Path) -> list[dict[str, object]]:
        entries = original_inventory(destination)
        if destination == public_destination:
            public_inner.chmod(0o600)
            public_inner.write_bytes(substituted.getvalue())
        return entries

    def record_classification(
        self: EvidenceClassifier, evidence_root: Path
    ) -> list[ClassifiedEvidence]:
        classified_roots.append(evidence_root)
        return original_classify(self, evidence_root)

    monkeypatch.setattr(
        case_tools,
        "_materialization_inventory",
        replace_after_public_inventory,
    )
    monkeypatch.setattr(EvidenceClassifier, "classify", record_classification)
    result = app._tool_dispatch_sync["extract_archive"](str(outer))

    assert result["status"] == "success"
    assert classified_roots
    assert public_destination not in classified_roots
    with zipfile.ZipFile(public_inner) as archive:
        assert archive.namelist() == ["substituted.txt"]


def test_dedicated_autoruns_seat_reads_only_committed_artifact_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    autoruns = source / "Autoruns.csv"
    autoruns.write_text(
        "Entry Location,Entry,Image Path,Profile\nHKLM\\Run,Bad,C:\\bad.exe,HOST-A\n"
    )
    manifest = prepare_evidence_case(source, "case-a", tmp_path / "cases")
    app.init_server(tmp_path / "cases", mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")
    secret = "dedicated-autoruns-test-secret"
    identity = identity_for_phase("autoruns_ingest", "single")
    monkeypatch.setenv(DELEGATION_SECRET_ENV, secret)
    monkeypatch.setenv(DELEGATION_GRANT_ENV, create_delegation_grant(identity, secret))

    result = app._tool_dispatch_sync["parse_autoruns"](
        artifact_ids=[f"{manifest.collection_digest}:0"]
    )

    assert result["status"] == "success"
    assert result["result_count"] == 1
    assert result["sources"] == [
        "autoruns.host-a",
        "autoruns.intake." + manifest.collection_digest.removeprefix("sha256:"),
    ]


def test_dedicated_autoruns_seat_requires_the_complete_exact_manifest_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    for name in ("Autoruns-a.csv", "Autoruns-b.csv"):
        (source / name).write_text("Entry,Image Path\nRun,C:\\good.exe\n")
    manifest = prepare_evidence_case(source, "case-a", tmp_path / "cases")
    app.init_server(tmp_path / "cases", mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")
    secret = "dedicated-autoruns-test-secret"
    identity = identity_for_phase("autoruns_ingest", "single")
    monkeypatch.setenv(DELEGATION_SECRET_ENV, secret)
    monkeypatch.setenv(DELEGATION_GRANT_ENV, create_delegation_grant(identity, secret))
    expected = [
        f"{manifest.collection_digest}:{index}"
        for index, entry in enumerate(manifest.entries)
        if "autoruns" in evidence_types(entry)
    ]

    subset = app._tool_dispatch_sync["parse_autoruns"](artifact_ids=expected[:1])
    duplicate = app._tool_dispatch_sync["parse_autoruns"](artifact_ids=[*expected, expected[-1]])

    assert subset["status"] == "error"
    assert "every committed" in subset["error_message"]
    assert duplicate["status"] == "error"
    assert "exactly once" in duplicate["error_message"]


def test_dedicated_autoruns_seat_rejects_changed_or_non_autoruns_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    autoruns = source / "Autoruns.csv"
    autoruns.write_text("Entry,Image Path\nRun,C:\\good.exe\n")
    (source / "notes.txt").write_text("not autoruns")
    manifest = prepare_evidence_case(source, "case-a", tmp_path / "cases")
    app.init_server(tmp_path / "cases", mem_percent_limit=0, cpu_percent_limit=0)
    app._tool_dispatch_sync["open_case"]("case-a")
    secret = "dedicated-autoruns-test-secret"
    identity = identity_for_phase("autoruns_ingest", "single")
    monkeypatch.setenv(DELEGATION_SECRET_ENV, secret)
    monkeypatch.setenv(DELEGATION_GRANT_ENV, create_delegation_grant(identity, secret))
    by_name = {entry.relative_path: index for index, entry in enumerate(manifest.entries)}

    wrong_type = app._tool_dispatch_sync["parse_autoruns"](
        artifact_ids=[f"{manifest.collection_digest}:{by_name['notes.txt']}"]
    )
    assert wrong_type["status"] == "error"
    assert "every committed" in wrong_type["error_message"]

    autoruns.write_text("Entry,Image Path\nRun,C:\\changed.exe\n")
    changed = app._tool_dispatch_sync["parse_autoruns"](
        artifact_ids=[f"{manifest.collection_digest}:{by_name['Autoruns.csv']}"]
    )
    assert changed["status"] == "error"
    assert "changed" in changed["error_message"]
