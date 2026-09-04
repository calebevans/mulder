"""Contract tests for default-deny, immutable reviewed connectors."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import SecretStr

import mulder.connectors.exports as exports_module
from mulder.connectors import (
    ApprovedCaseState,
    ApprovedExporter,
    CaseManifestApprovalAuthority,
    CloudSnapshotAdapter,
    ConnectorIntegrityError,
    ConnectorPolicyError,
    ExportCredential,
    ExportPolicy,
    ExportRequest,
    ExportScope,
    FilesystemImportScope,
    FilesystemSnapshotRequest,
    ImmutableImporter,
    ImportCredential,
    ImportPolicy,
    QueryTerm,
    RemoteImportScope,
    RemoteSnapshotRequest,
    SiemExportAdapter,
    SnapshotTransportRequest,
    SnapshotTransportResponse,
    SplunkSnapshotAdapter,
    SyslogSnapshotAdapter,
    TheHiveExportAdapter,
    WazuhSnapshotAdapter,
    verify_import_bundle,
)
from mulder.connectors.imports import RemoteSnapshotAdapter
from mulder.connectors.models import RemoteImportKind
from mulder.connectors.transports import (
    ExportTransportRequest,
    ExportTransportResponse,
)
from mulder.models import Finding
from mulder.receipt import CaseVerificationResult


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeSnapshotTransport:
    def __init__(self, body: bytes = b'{"events":[{"id":1}]}') -> None:
        self.body = body
        self.requests: list[SnapshotTransportRequest] = []

    def fetch(self, request: SnapshotTransportRequest) -> SnapshotTransportResponse:
        self.requests.append(request)
        return SnapshotTransportResponse(
            body=self.body,
            content_type="application/json",
            request_id="request-7",
        )


class FakeExportTransport:
    def __init__(self) -> None:
        self.requests: list[ExportTransportRequest] = []

    def deliver(self, request: ExportTransportRequest) -> ExportTransportResponse:
        self.requests.append(request)
        return ExportTransportResponse(remote_reference="remote-42")


class FakeAuthority:
    def __init__(self, state: ApprovedCaseState, *, drift: bool = False) -> None:
        self.state = state
        self.calls = 0
        self.drift = drift

    def authorize(self, request: ExportRequest) -> ApprovedCaseState:
        self.calls += 1
        if self.drift and self.calls == 2:
            return replace(self.state, audit_head_digest="sha256:changed")
        return self.state


def _import_policy(tmp_path: Path, source: Path, *, enabled: bool = True) -> ImportPolicy:
    return ImportPolicy(
        intake_root=tmp_path / "intake",
        enabled=enabled,
        filesystem_scopes=(FilesystemImportScope("disk", (source,)),),
    )


def test_filesystem_import_is_exact_immutable_deterministic_and_provenance_preserving(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    artifact = source / "auth.log"
    artifact.write_bytes(b"login ok\n")
    importer = ImmutableImporter(_import_policy(tmp_path, source))
    source_before = artifact.stat()

    first = importer.import_snapshot(FilesystemSnapshotRequest("disk", artifact))
    second = importer.import_snapshot(FilesystemSnapshotRequest("disk", artifact))
    manifest = verify_import_bundle(first.bundle_path)

    assert first == second
    assert (first.bundle_path / "payload.bin").read_bytes() == b"login ok\n"
    assert manifest["provenance"] == {
        "allowed_root": str(source),
        "original_locator": str(artifact),
        "resolved_locator": str(artifact),
    }
    assert manifest["credential_id"] is None
    source_after = artifact.stat()
    assert (source_after.st_size, source_after.st_mtime_ns, source_after.st_mode) == (
        source_before.st_size,
        source_before.st_mtime_ns,
        source_before.st_mode,
    )
    assert not (first.bundle_path.stat().st_mode & 0o222)
    assert not ((first.bundle_path / "payload.bin").stat().st_mode & 0o222)

    os.chmod(first.bundle_path / "payload.bin", 0o644)
    (first.bundle_path / "payload.bin").write_bytes(b"login no\n")  # same size
    os.chmod(first.bundle_path / "payload.bin", 0o444)
    with pytest.raises(ConnectorIntegrityError, match="content commitment"):
        verify_import_bundle(first.bundle_path)


def test_import_defaults_off_and_denies_escape_and_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    inside = source / "inside.log"
    outside = tmp_path / "outside.log"
    inside.write_text("inside", encoding="utf-8")
    outside.write_text("outside", encoding="utf-8")
    disabled = ImmutableImporter(_import_policy(tmp_path, source, enabled=False))
    with pytest.raises(ConnectorPolicyError, match="disabled"):
        disabled.import_snapshot(FilesystemSnapshotRequest("disk", inside))

    importer = ImmutableImporter(_import_policy(tmp_path, source))
    with pytest.raises(ConnectorPolicyError, match="escapes"):
        importer.import_snapshot(FilesystemSnapshotRequest("disk", outside))
    link = source / "escape"
    link.symlink_to(outside)
    with pytest.raises(ConnectorPolicyError, match="symbolic links"):
        importer.import_snapshot(FilesystemSnapshotRequest("disk", link))


@pytest.mark.parametrize(
    ("connector", "path"),
    [
        ("splunk", "/services/search/jobs/export"),
        ("wazuh", "/api/v1/events/search"),
        ("syslog", "/api/v1/snapshots"),
        ("cloud", "/api/v1/log-snapshots"),
    ],
)
def test_remote_snapshot_adapters_are_read_only_typed_and_preserve_exact_bytes(
    tmp_path: Path, connector: RemoteImportKind, path: str
) -> None:
    credential = ImportCredential(
        "reader-1",
        "source-1",
        connector,
        "https://logs.example",
        SecretStr("import-secret"),
    )
    transport = FakeSnapshotTransport()
    adapter: RemoteSnapshotAdapter
    if connector == "splunk":
        adapter = SplunkSnapshotAdapter(
            source_id="source-1", credential=credential, transport=transport
        )
    elif connector == "wazuh":
        adapter = WazuhSnapshotAdapter(
            source_id="source-1", credential=credential, transport=transport
        )
    elif connector == "syslog":
        adapter = SyslogSnapshotAdapter(
            source_id="source-1", credential=credential, transport=transport
        )
    else:
        adapter = CloudSnapshotAdapter(
            source_id="source-1", credential=credential, transport=transport
        )
    policy = ImportPolicy(
        intake_root=tmp_path / "intake",
        enabled=True,
        remote_scopes=(
            RemoteImportScope(
                "source-1",
                connector,
                "https://logs.example",
                ("auth",),
                allowed_fields=("host",),
            ),
        ),
    )
    importer = ImmutableImporter(policy, (adapter,))
    receipt = importer.import_snapshot(
        RemoteSnapshotRequest(
            "source-1",
            connector,
            "auth",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T01:00:00+00:00",
            10,
            (QueryTerm("host", "eq", "server-1"),),
        )
    )
    manifest_text = (receipt.bundle_path / "manifest.json").read_text(encoding="utf-8")

    assert (receipt.bundle_path / "payload.bin").read_bytes() == transport.body
    assert receipt.record_count == 1
    assert transport.requests[0].path == path
    assert transport.requests[0].method == "POST"
    assert "import-secret" not in manifest_text
    assert json.loads(manifest_text)["provenance"]["request_id"] == "request-7"


def test_remote_query_and_direction_specific_credentials_fail_before_transport(
    tmp_path: Path,
) -> None:
    import_credential = ImportCredential(
        "reader", "source", "splunk", "https://logs.example", SecretStr("read")
    )
    transport = FakeSnapshotTransport()
    adapter = SplunkSnapshotAdapter(
        source_id="source", credential=import_credential, transport=transport
    )
    importer = ImmutableImporter(
        ImportPolicy(
            intake_root=tmp_path / "intake",
            enabled=True,
            remote_scopes=(
                RemoteImportScope(
                    "source", "splunk", "https://logs.example", ("auth",), ("host",)
                ),
            ),
        ),
        (adapter,),
    )
    with pytest.raises(ConnectorPolicyError, match="query field"):
        importer.import_snapshot(
            RemoteSnapshotRequest(
                "source",
                "splunk",
                "auth",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T01:00:00+00:00",
                10,
                (QueryTerm("raw_search", "contains", "| delete"),),
            )
        )
    assert transport.requests == []

    wrong = cast(
        "ExportCredential",
        ImportCredential("reader", "thehive", "splunk", "https://hive.example", SecretStr("read")),
    )
    with pytest.raises(ConnectorPolicyError, match="direction-specific"):
        TheHiveExportAdapter(
            destination_id="thehive", credential=wrong, transport=FakeExportTransport()
        )


def _approved_state(tmp_path: Path) -> ApprovedCaseState:
    database = tmp_path / "fixture.db"
    database.touch()
    return ApprovedCaseState(
        case_id="fixture",
        manifest_path=tmp_path / "fixture.case-manifest.json",
        manifest_sha256="sha256:manifest-file",
        manifest_hash="sha256:manifest-content",
        database_path=database,
        claim_set_digest="sha256:claims",
        audit_head_digest="sha256:audit",
        approval_request_id="request-1",
        approval_decision_id="decision-1",
        reviewer="examiner",
        signer_fingerprint="sha256:signer",
    )


def _fake_review() -> SimpleNamespace:
    finding = Finding(
        finding_id="finding-1",
        case_id="fixture",
        title="External listener",
        description="Connected to 8.8.8.8",
        severity="high",
        confidence="confirmed",
        evidence_refs=["tool-1"],
        sources=["network"],
        submitted_at="2026-01-01T00:00:00+00:00",
    )
    page = SimpleNamespace(truncated=False, returned=1)
    findings = SimpleNamespace(page=page, active=(SimpleNamespace(finding=finding),))
    return SimpleNamespace(
        findings=findings,
        model_dump=lambda **_kwargs: {"schema": "mulder.case-review", "finding": "finding-1"},
    )


def test_approved_export_is_policy_bound_exact_and_uses_fixed_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exports_module, "query_case_review", lambda _query: _fake_review())
    state = _approved_state(tmp_path)
    authority = FakeAuthority(state)
    transport = FakeExportTransport()
    credential = ExportCredential(
        "writer-1", "hive", "thehive", "https://hive.example", SecretStr("export-secret")
    )
    adapter = TheHiveExportAdapter(
        destination_id="hive", credential=credential, transport=transport
    )
    request = ExportRequest(
        "fixture", state.manifest_path, state.manifest_sha256, "hive", "thehive", "iocs"
    )
    disabled = ApprovedExporter(ExportPolicy(), authority, (adapter,))
    with pytest.raises(ConnectorPolicyError, match="disabled"):
        disabled.export(request)
    exporter = ApprovedExporter(
        ExportPolicy(
            enabled=True,
            scopes=(
                ExportScope(
                    "hive",
                    "thehive",
                    "https://hive.example",
                    ("iocs",),
                    ("sha256:signer",),
                    case_ids=("fixture",),
                ),
            ),
        ),
        authority,
        (adapter,),
    )

    receipt = exporter.export(request)
    body = json.loads(transport.requests[0].body)

    assert authority.calls == 2
    assert transport.requests[0].path == "/api/v1/alert"
    assert body["approval"]["approval_decision_id"] == "decision-1"
    assert body["records"][0]["value"] == "8.8.8.8"
    assert "export-secret" not in transport.requests[0].body.decode()
    assert receipt.manifest_sha256 == state.manifest_sha256
    assert receipt.remote_reference == "remote-42"


def test_export_blocks_stale_case_before_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exports_module, "query_case_review", lambda _query: _fake_review())
    state = _approved_state(tmp_path)
    authority = FakeAuthority(state, drift=True)
    transport = FakeExportTransport()
    credential = ExportCredential(
        "writer", "siem", "siem", "https://siem.example", SecretStr("write")
    )
    adapter = SiemExportAdapter(destination_id="siem", credential=credential, transport=transport)
    exporter = ApprovedExporter(
        ExportPolicy(
            enabled=True,
            scopes=(
                ExportScope(
                    "siem",
                    "siem",
                    "https://siem.example",
                    ("case",),
                    ("sha256:signer",),
                ),
            ),
        ),
        authority,
        (adapter,),
    )
    with pytest.raises(ConnectorIntegrityError, match="changed"):
        exporter.export(
            ExportRequest(
                "fixture", state.manifest_path, state.manifest_sha256, "siem", "siem", "case"
            )
        )
    assert transport.requests == []


def test_manifest_authority_requires_consistent_signed_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "fixture.db"
    database.touch()
    manifest_path = tmp_path / "fixture.case-manifest.json"
    manifest = {
        "case": {"case_id": "fixture"},
        "database": {"path": "fixture.db"},
        "audit": {"head_hash": "sha256:audit"},
        "review_approval": {
            "state": "approved",
            "claim_set_digest": "sha256:claims",
            "audit_head_digest": "sha256:audit",
            "request": {
                "request_id": "request-1",
                "case_id": "fixture",
                "claim_set_digest": "sha256:claims",
                "audit_head_digest": "sha256:audit",
            },
            "decision": {
                "decision_id": "decision-1",
                "request_id": "request-1",
                "decision": "approve",
                "reviewer": "examiner",
                "claim_set_digest": "sha256:claims",
                "audit_head_digest": "sha256:audit",
            },
        },
        "integrity": {"manifest_hash": "sha256:content"},
    }
    raw = json.dumps(manifest, sort_keys=True).encode()
    manifest_path.write_bytes(raw)
    monkeypatch.setattr(
        exports_module,
        "verify_case",
        lambda _path: CaseVerificationResult(
            "verified",
            str(manifest_path),
            "fixture",
            3,
            (),
            signature_status="valid",
            public_key={"fingerprint": "sha256:signer"},
        ),
    )
    request = ExportRequest("fixture", manifest_path, _sha256(raw), "hive", "thehive", "case")

    approved = CaseManifestApprovalAuthority().authorize(request)

    assert approved.claim_set_digest == "sha256:claims"
    assert approved.approval_decision_id == "decision-1"
    approval = cast(dict[str, object], manifest["review_approval"])
    decision = cast(dict[str, object], approval["decision"])
    decision["decision"] = "reject"
    changed = json.dumps(manifest, sort_keys=True).encode()
    manifest_path.write_bytes(changed)
    with pytest.raises(ConnectorIntegrityError, match="exact approved"):
        CaseManifestApprovalAuthority().authorize(request)
    rejected_request = replace(request, manifest_sha256=_sha256(changed))
    with pytest.raises(ConnectorPolicyError, match="consistent case state"):
        CaseManifestApprovalAuthority().authorize(rejected_request)
