"""Tests for relocatable sealed case manifests and offline verification."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest
from click.testing import CliRunner

from mulder.audit import AuditLog
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.models import AtomicClaimInput, EvidenceAnchorInput, Finding, WindowRow
from mulder.receipt import CaseVerificationResult, SealError, seal_case, verify_case


@dataclass(frozen=True)
class SealedFixture:
    """Paths belonging to one realistic sealed test case."""

    bundle: Path
    case_dir: Path
    evidence: Path
    database: Path
    audit: Path
    report: Path
    manifest: Path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_sealed_case(tmp_path: Path, *, legacy_audit: bool = False) -> SealedFixture:
    bundle = tmp_path / "portable-case"
    case_dir = bundle / "case"
    evidence_root = bundle / "evidence"
    case_dir.mkdir(parents=True)
    evidence_root.mkdir()
    evidence = evidence_root / "host.log"
    evidence_bytes = b"PID 1234 cmd.exe parent 500\n"
    evidence.write_bytes(evidence_bytes)

    db = CaseDB.create("fixture", str(evidence_root), case_dir)
    db.register_evidence_file(str(evidence), _sha256(evidence_bytes), len(evidence_bytes))
    source_id = db.register_source(
        "host.processes",
        str(evidence),
        "sha256:" + _sha256(evidence_bytes),
        "fixture-extractor",
        1,
    )
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=1,
                line_end=1,
                event_time=None,
                raw_text=evidence_bytes.decode().strip(),
            )
        ],
    )
    window = db.get_windows_by_source("host.processes")[0]
    assert window.window_id is not None
    finding = Finding(
        finding_id="finding-1",
        case_id="fixture",
        title="Process observed",
        description="Process 1234 is cmd.exe",
        severity="high",
        confidence="inference",
        evidence_refs=["tc-1"],
        sources=["host.processes"],
        submitted_at="2026-01-01T00:00:00+00:00",
    )
    db.insert_finding(
        finding,
        [
            AtomicClaimInput(
                statement="Process 1234 is cmd.exe",
                subject="process:1234",
                predicate="image_name",
                object_value="cmd.exe",
                anchors=[
                    EvidenceAnchorInput(
                        tool_call_id="tc-1",
                        window_id=window.window_id,
                        char_start=9,
                        char_end=16,
                        expected_text="cmd.exe",
                    )
                ],
            )
        ],
    )
    db.update_extractor_versions({"fixture-extractor": "2.1.0"})
    db.close()

    audit = case_dir / "fixture.audit.jsonl"
    if legacy_audit:
        audit.write_text(
            json.dumps(
                {
                    "type": "tool_call",
                    "tool_call_id": "legacy-1",
                    "tool_name": "search",
                    "params": {},
                    "output_hash": "sha256:legacy",
                    "duration_ms": 1,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                }
            )
            + "\n",
            encoding="utf-8",
        )
    else:
        log = AuditLog(audit)
        log.log_tool_call("tc-1", "search", {"query": "cmd.exe"}, "sha256:one")
        log.log_finding_submission("finding-1", ["tc-1"])

    report = case_dir / "fixture.report.md"
    report.write_text("# Fixture report\n\nProcess 1234 is cmd.exe.\n", encoding="utf-8")
    manifest = seal_case("fixture", case_dir)
    return SealedFixture(
        bundle=bundle,
        case_dir=case_dir,
        evidence=evidence,
        database=case_dir / "fixture.db",
        audit=audit,
        report=report,
        manifest=manifest,
    )


def _codes(result: CaseVerificationResult) -> set[str]:
    return {diagnostic.code for diagnostic in result.diagnostics}


def test_clean_case_verifies_and_binds_claims_tools_and_reports(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)

    result = verify_case(sealed.manifest)
    manifest = json.loads(sealed.manifest.read_text(encoding="utf-8"))

    assert result.ok
    assert result.status == "verified"
    assert result.diagnostics == ()
    assert result.artifacts_checked == 4  # database, audit, evidence, report
    assert manifest["schema"] == "mulder.case-manifest"
    assert manifest["version"] == 1
    assert manifest["integrity"]["signature"] == {"status": "unsigned"}
    assert manifest["audit"]["entry_count"] == 2
    assert manifest["audit"]["head_hash"].startswith("sha256:")
    assert manifest["database"]["record_sets"]["claims"]["row_count"] == 1
    assert manifest["database"]["record_sets"]["evidence_anchors"]["row_count"] == 1
    assert manifest["methodology"]["extractor_versions"] == {"fixture-extractor": "2.1.0"}
    assert manifest["methodology"]["audit_tool_counts"] == {"search": 1}
    assert [report["name"] for report in manifest["reports"]] == ["fixture.report.md"]


def test_outbound_manifest_is_bound_as_a_standard_case_artifact(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    outbound = sealed.case_dir / "fixture.outbound.jsonl"
    outbound.write_text('{"schema_version":1,"decision":"allow"}\n', encoding="utf-8")

    manifest_path = seal_case("fixture", sealed.case_dir, overwrite=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    names = [report["name"] for report in manifest["reports"]]

    assert "fixture.outbound.jsonl" in names
    assert verify_case(manifest_path).ok


@pytest.mark.parametrize(
    ("replacement", "expected_codes"),
    [
        (b"PID 9876 cmd.exe parent 500\n", {"evidence.content_mismatch"}),
        (
            b"PID 1234 cmd.exe parent 500\nappended\n",
            {"evidence.content_mismatch", "evidence.size_mismatch"},
        ),
    ],
)
def test_evidence_mutation_is_detected_even_at_same_size(
    tmp_path: Path, replacement: bytes, expected_codes: set[str]
) -> None:
    sealed = _build_sealed_case(tmp_path)
    sealed.evidence.write_bytes(replacement)

    result = verify_case(sealed.manifest)

    assert result.status == "invalid"
    assert expected_codes <= _codes(result)


def test_missing_evidence_is_named_precisely(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    sealed.evidence.unlink()

    result = verify_case(sealed.manifest)

    assert result.status == "invalid"
    assert "evidence.missing" in _codes(result)
    diagnostic = next(item for item in result.diagnostics if item.code == "evidence.missing")
    assert "host.log" in diagnostic.message


@pytest.mark.parametrize(
    ("attribute", "expected_code"),
    [("database", "database.missing"), ("audit", "audit.missing")],
)
def test_missing_core_case_artifact_is_named(
    tmp_path: Path, attribute: str, expected_code: str
) -> None:
    sealed = _build_sealed_case(tmp_path)
    getattr(sealed, attribute).unlink()

    result = verify_case(sealed.manifest)

    assert result.status == "invalid"
    assert expected_code in _codes(result)


def test_evidence_path_substitution_is_detected(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    original_size = sealed.evidence.stat().st_size
    substitute = tmp_path / "substitute.log"
    substitute.write_bytes(b"Z" * original_size)
    sealed.evidence.unlink()
    sealed.evidence.symlink_to(substitute)

    result = verify_case(sealed.manifest)

    assert result.status == "invalid"
    assert "evidence.content_mismatch" in _codes(result)
    assert "evidence.size_mismatch" not in _codes(result)


def test_report_same_size_mutation_and_missing_report_are_detected(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    original = sealed.report.read_bytes()
    sealed.report.write_bytes(b"X" * len(original))

    changed = verify_case(sealed.manifest)
    assert changed.status == "invalid"
    assert "report.content_mismatch" in _codes(changed)
    assert "report.size_mismatch" not in _codes(changed)

    sealed.report.unlink()
    missing = verify_case(sealed.manifest)
    assert missing.status == "invalid"
    assert "report.missing" in _codes(missing)


def test_database_mutation_names_the_changed_table(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    connection = sqlite3.connect(sealed.database)
    try:
        connection.execute("UPDATE case_metadata SET narrative = 'changed after sealing'")
        connection.commit()
    finally:
        connection.close()

    result = verify_case(sealed.manifest)

    assert result.status == "invalid"
    assert "database.content_mismatch" in _codes(result)
    assert any(item.subject == "database:case_metadata" for item in result.diagnostics)
    assert "database.logical_digest_mismatch" in _codes(result)


def test_database_schema_change_is_reported_separately(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    connection = sqlite3.connect(sealed.database)
    try:
        connection.execute("ALTER TABLE progress ADD COLUMN external_note TEXT")
        connection.commit()
    finally:
        connection.close()

    result = verify_case(sealed.manifest)

    assert result.status == "invalid"
    assert "database.schema_mismatch" in _codes(result)
    assert any(item.subject == "database:progress" for item in result.diagnostics)


def test_live_database_journal_is_not_treated_as_a_portable_snapshot(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    Path(str(sealed.database) + "-wal").write_bytes(b"uncheckpointed")

    result = verify_case(sealed.manifest)

    assert result.status == "invalid"
    assert "database.active_journal" in _codes(result)


def test_audit_suffix_truncation_is_caught_by_sealed_count_and_head(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    lines = sealed.audit.read_text(encoding="utf-8").splitlines(keepends=True)
    sealed.audit.write_text("".join(lines[:-1]), encoding="utf-8")

    result = verify_case(sealed.manifest)

    assert result.status == "invalid"
    assert {
        "audit.content_mismatch",
        "audit.size_mismatch",
        "audit.entry_count_mismatch",
        "audit.head_mismatch",
    } <= _codes(result)


def test_unsupported_manifest_schema_is_not_reported_as_corruption(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    manifest = json.loads(sealed.manifest.read_text(encoding="utf-8"))
    manifest["version"] = 999
    sealed.manifest.write_text(json.dumps(manifest), encoding="utf-8")

    result = verify_case(sealed.manifest)

    assert result.status == "unsupported_manifest"
    assert _codes(result) == {"manifest.unsupported_schema"}


def test_case_bundle_remains_valid_after_relocation(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    relocated = tmp_path / "offline" / "renamed-case"
    relocated.parent.mkdir()
    shutil.move(str(sealed.bundle), relocated)

    result = verify_case(relocated / "case" / "fixture.manifest.json")

    assert result.status == "verified"


def test_evidence_root_override_supports_independent_relocation(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    relocated_evidence = tmp_path / "detached-evidence"
    shutil.move(str(sealed.evidence.parent), relocated_evidence)

    without_override = verify_case(sealed.manifest)
    with_override = verify_case(sealed.manifest, evidence_root=relocated_evidence)

    assert "evidence.missing" in _codes(without_override)
    assert with_override.status == "verified"


def test_metadata_only_touch_does_not_invalidate_content_receipt(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    before = sealed.evidence.stat()
    os.utime(sealed.evidence, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))

    assert verify_case(sealed.manifest).status == "verified"


def test_legacy_audit_is_explicitly_unverified_not_corrupt(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path, legacy_audit=True)

    result = verify_case(sealed.manifest)

    assert result.status == "legacy_unverified"
    assert _codes(result) == {"audit.legacy_unverified"}
    assert all(item.severity == "warning" for item in result.diagnostics)


def test_sealing_refuses_stale_registered_evidence(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    sealed.manifest.unlink()
    sealed.evidence.write_bytes(b"changed")

    with pytest.raises(SealError, match="changed before sealing"):
        seal_case("fixture", sealed.case_dir)


def test_cli_seal_and_offline_verify_contract(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path)
    sealed.manifest.unlink()
    runner = CliRunner()

    created = runner.invoke(
        cli,
        ["seal-case", "fixture", "--db-dir", str(sealed.case_dir)],
    )
    verified = runner.invoke(cli, ["verify-case", str(sealed.manifest), "--json"])

    assert created.exit_code == 0, created.output
    assert "Signature: unsigned" in created.output
    assert verified.exit_code == 0, verified.output
    payload = json.loads(verified.output)
    assert payload["status"] == "verified"
    assert payload["signature_status"] == "unsigned"


def test_cli_legacy_and_unsupported_exit_codes(tmp_path: Path) -> None:
    sealed = _build_sealed_case(tmp_path, legacy_audit=True)
    runner = CliRunner()

    legacy = runner.invoke(cli, ["verify-case", str(sealed.manifest)])
    assert legacy.exit_code == 2
    assert "LEGACY UNVERIFIED" in legacy.output

    manifest = json.loads(sealed.manifest.read_text(encoding="utf-8"))
    manifest["version"] = 2
    sealed.manifest.write_text(json.dumps(manifest), encoding="utf-8")
    unsupported = runner.invoke(cli, ["verify-case", str(sealed.manifest)])
    assert unsupported.exit_code == 3
    assert "UNSUPPORTED MANIFEST" in unsupported.output
