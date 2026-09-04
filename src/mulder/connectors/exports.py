"""Exact-approved-state IOC and case export connectors.

Export authorization is a property of a fully verified signed case manifest,
not merely of a destination token.  The authority is checked again immediately
before delivery so stale approval or evidence mutation fails closed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from mulder.connectors.models import (
    ApprovedCaseState,
    ConnectorIntegrityError,
    ConnectorPolicyError,
    ExportArtifact,
    ExportCredential,
    ExportPolicy,
    ExportReceipt,
    ExportRequest,
    ExportScope,
)
from mulder.connectors.transports import (
    ExportTransport,
    ExportTransportRequest,
)
from mulder.receipt import verify_case
from mulder.report.ioc_export import extract_classified_iocs
from mulder.review.model import MAX_FINDING_LIMIT, ReviewQuery, query_case_review

EXPORT_SCHEMA = "mulder.connector-export"
EXPORT_VERSION = 1


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ConnectorPolicyError(f"approved manifest {label} must be an object")
    return cast(Mapping[str, object], value)


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConnectorPolicyError(f"approved manifest {label} must be non-empty text")
    return value


class ApprovalAuthority(Protocol):
    def authorize(self, request: ExportRequest) -> ApprovedCaseState:
        """Verify and bind one exact manifest state for export."""


class CaseManifestApprovalAuthority:
    """Recognize PR 5.3's canonical approval commitment in a signed case manifest."""

    def authorize(self, request: ExportRequest) -> ApprovedCaseState:
        path = Path(request.manifest_path).expanduser().resolve(strict=True)
        before = path.read_bytes()
        observed_sha = _sha256(before)
        if observed_sha != request.manifest_sha256:
            raise ConnectorIntegrityError("case manifest is not the exact approved export state")
        verification = verify_case(path)
        after = path.read_bytes()
        if before != after:
            raise ConnectorIntegrityError("case manifest changed during export authorization")
        if verification.status != "verified" or verification.signature_status != "valid":
            raise ConnectorPolicyError("export requires a fully verified signed case manifest")
        if verification.case_id != request.case_id:
            raise ConnectorPolicyError("export case ID does not match the verified manifest")
        public_key = verification.public_key
        if public_key is None:
            raise ConnectorPolicyError("signed manifest has no public-key metadata")
        signer = _required_text(public_key.get("fingerprint"), "signer fingerprint")
        try:
            manifest_raw = json.loads(before)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConnectorIntegrityError(f"approved case manifest is unreadable: {exc}") from exc
        manifest = _mapping(manifest_raw, "root")
        approval = _mapping(manifest.get("review_approval"), "review_approval")
        if approval.get("state") != "approved":
            raise ConnectorPolicyError("export requires an approved review state")
        claim_digest = _required_text(
            approval.get("claim_set_digest"), "review_approval.claim_set_digest"
        )
        audit_digest = _required_text(
            approval.get("audit_head_digest"), "review_approval.audit_head_digest"
        )
        request_data = _mapping(approval.get("request"), "review_approval.request")
        decision = _mapping(approval.get("decision"), "review_approval.decision")
        approval_request_id = _required_text(request_data.get("request_id"), "request_id")
        approval_decision_id = _required_text(decision.get("decision_id"), "decision_id")
        reviewer = _required_text(decision.get("reviewer"), "reviewer")
        exact_values = (
            request_data.get("case_id") == request.case_id,
            request_data.get("claim_set_digest") == claim_digest,
            request_data.get("audit_head_digest") == audit_digest,
            decision.get("request_id") == approval_request_id,
            decision.get("decision") == "approve",
            decision.get("claim_set_digest") == claim_digest,
            decision.get("audit_head_digest") == audit_digest,
        )
        if not all(exact_values):
            raise ConnectorPolicyError("review approval does not bind one consistent case state")
        audit = _mapping(manifest.get("audit"), "audit")
        if audit.get("head_hash") != audit_digest:
            raise ConnectorPolicyError("review approval does not bind the sealed audit head")
        integrity = _mapping(manifest.get("integrity"), "integrity")
        manifest_hash = _required_text(integrity.get("manifest_hash"), "manifest hash")
        database = _mapping(manifest.get("database"), "database")
        database_relative = Path(_required_text(database.get("path"), "database path"))
        if database_relative.is_absolute():
            raise ConnectorPolicyError("approved manifest database path must be relative")
        database_path = (path.parent / database_relative).resolve(strict=True)
        return ApprovedCaseState(
            case_id=request.case_id,
            manifest_path=path,
            manifest_sha256=observed_sha,
            manifest_hash=manifest_hash,
            database_path=database_path,
            claim_set_digest=claim_digest,
            audit_head_digest=audit_digest,
            approval_request_id=approval_request_id,
            approval_decision_id=approval_decision_id,
            reviewer=reviewer,
            signer_fingerprint=signer,
        )


class DestinationAdapter(Protocol):
    connector: str
    destination_id: str
    credential: ExportCredential

    def deliver(self, artifact: ExportArtifact, payload: bytes, scope: ExportScope) -> str:
        """Deliver one artifact to a fixed reviewed endpoint."""


class _HttpDestinationAdapter:
    connector: str
    _paths: Mapping[ExportArtifact, str]

    def __init__(
        self,
        *,
        destination_id: str,
        credential: ExportCredential,
        transport: ExportTransport,
    ) -> None:
        if not isinstance(credential, ExportCredential):
            raise ConnectorPolicyError("adapter requires a direction-specific export credential")
        if credential.destination_id != destination_id or credential.connector != self.connector:
            raise ConnectorPolicyError("export credential is not scoped to this adapter")
        self.destination_id = destination_id
        self.credential = credential
        self.transport = transport

    def deliver(self, artifact: ExportArtifact, payload: bytes, scope: ExportScope) -> str:
        response = self.transport.deliver(
            ExportTransportRequest(
                origin=scope.origin,
                path=self._paths[artifact],
                headers=(
                    ("accept", "application/json"),
                    ("authorization", f"Bearer {self.credential.token.get_secret_value()}"),
                    ("content-type", "application/json"),
                ),
                body=payload,
            )
        )
        return response.remote_reference


class TheHiveExportAdapter(_HttpDestinationAdapter):
    """TheHive alert/case creation only; it exposes no observable-response operation."""

    connector = "thehive"
    _paths = {"iocs": "/api/v1/alert", "case": "/api/v1/case"}


class SiemExportAdapter(_HttpDestinationAdapter):
    """Generic reviewed SIEM ingestion only; it exposes no live-action operation."""

    connector = "siem"
    _paths = {"iocs": "/api/v1/iocs", "case": "/api/v1/cases"}


class ApprovedExporter:
    """Authorize and publish exact-state exports through fixed destinations."""

    def __init__(
        self,
        policy: ExportPolicy,
        authority: ApprovalAuthority,
        adapters: tuple[DestinationAdapter, ...],
    ) -> None:
        self._policy = policy
        self._authority = authority
        self._adapters = {(item.connector, item.destination_id): item for item in adapters}
        if len(self._adapters) != len(adapters):
            raise ConnectorPolicyError("duplicate export adapter")

    def export(self, request: ExportRequest) -> ExportReceipt:
        """Export one deterministic artifact after two exact-state authorization checks."""
        scope = self._scope(request)
        adapter = self._adapters.get((request.connector, request.destination_id))
        if adapter is None:
            raise ConnectorPolicyError("export destination has no reviewed adapter")
        credential = adapter.credential
        if (
            credential.destination_id != scope.destination_id
            or credential.connector != scope.connector
            or credential.origin != scope.origin
        ):
            raise ConnectorPolicyError("export credential does not match destination policy")
        approved = self._authority.authorize(request)
        if approved.signer_fingerprint not in scope.trusted_signer_fingerprints:
            raise ConnectorPolicyError("case signer is not trusted by destination policy")
        payload_data, record_count = self._payload(request.artifact, approved, scope.max_records)
        payload = _canonical_json(payload_data)
        # The delivery check is intentionally after all local projection work.
        current = self._authority.authorize(request)
        if current != approved:
            raise ConnectorIntegrityError("approved case state changed before export delivery")
        remote_reference = adapter.deliver(request.artifact, payload, scope)
        payload_sha = _sha256(payload)
        return ExportReceipt(
            export_id=payload_sha,
            case_id=request.case_id,
            destination_id=request.destination_id,
            connector=request.connector,
            artifact=request.artifact,
            manifest_sha256=approved.manifest_sha256,
            manifest_hash=approved.manifest_hash,
            claim_set_digest=approved.claim_set_digest,
            audit_head_digest=approved.audit_head_digest,
            approval_request_id=approved.approval_request_id,
            approval_decision_id=approved.approval_decision_id,
            signer_fingerprint=approved.signer_fingerprint,
            payload_sha256=payload_sha,
            record_count=record_count,
            credential_id=credential.credential_id,
            remote_reference=remote_reference,
        )

    def _scope(self, request: ExportRequest) -> ExportScope:
        if not self._policy.enabled:
            raise ConnectorPolicyError("connector exports are disabled by policy")
        scopes = [
            item
            for item in self._policy.scopes
            if item.destination_id == request.destination_id
            and item.connector == request.connector
        ]
        if len(scopes) != 1:
            raise ConnectorPolicyError("export destination is not uniquely enabled by policy")
        scope = scopes[0]
        if request.artifact not in scope.artifacts:
            raise ConnectorPolicyError("artifact is not enabled for this destination")
        if scope.case_ids and request.case_id not in scope.case_ids:
            raise ConnectorPolicyError("case is not enabled for this destination")
        return scope

    def _payload(
        self, artifact: ExportArtifact, approved: ApprovedCaseState, max_records: int
    ) -> tuple[dict[str, object], int]:
        review = query_case_review(
            ReviewQuery(
                case_id=approved.case_id,
                db_dir=approved.database_path.parent,
                finding_limit=min(MAX_FINDING_LIMIT, max_records),
                manifest_path=approved.manifest_path,
            )
        )
        if review.findings.page.truncated:
            raise ConnectorPolicyError("approved case exceeds destination record limit")
        findings = [item.finding for item in review.findings.active]
        approval = {
            "manifest_sha256": approved.manifest_sha256,
            "manifest_hash": approved.manifest_hash,
            "claim_set_digest": approved.claim_set_digest,
            "audit_head_digest": approved.audit_head_digest,
            "approval_request_id": approved.approval_request_id,
            "approval_decision_id": approved.approval_decision_id,
            "reviewer": approved.reviewer,
            "signer_fingerprint": approved.signer_fingerprint,
        }
        if artifact == "iocs":
            classified = extract_classified_iocs(findings)
            records = sorted(
                (
                    {
                        "category": category,
                        "type": item["type"],
                        "value": item["value"],
                        "context": item.get("context", ""),
                    }
                    for category, items in classified.items()
                    for item in items
                ),
                key=lambda item: (item["category"], item["type"], item["value"], item["context"]),
            )
            if len(records) > max_records:
                raise ConnectorPolicyError("IOC export exceeds destination record limit")
            body: object = records
            count = len(records)
        else:
            body = review.model_dump(mode="json", by_alias=True)
            count = review.findings.page.returned
        return (
            {
                "schema": EXPORT_SCHEMA,
                "version": EXPORT_VERSION,
                "artifact": artifact,
                "case_id": approved.case_id,
                "approval": approval,
                "records": body,
            },
            count,
        )
