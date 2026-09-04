"""Policy and receipt models for reviewed import/export connectors.

The models deliberately separate import from export authority.  A credential or
scope accepted by one direction cannot be reused by the other by accident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypeAlias

from pydantic import SecretStr

ImportKind: TypeAlias = Literal["filesystem", "splunk", "wazuh", "syslog", "cloud"]
RemoteImportKind: TypeAlias = Literal["splunk", "wazuh", "syslog", "cloud"]
ExportKind: TypeAlias = Literal["thehive", "siem"]
ExportArtifact: TypeAlias = Literal["iocs", "case"]
QueryOperator: TypeAlias = Literal["eq", "contains", "prefix"]


class ConnectorPolicyError(ValueError):
    """A connector operation is outside its explicit examiner policy."""


class ConnectorIntegrityError(ValueError):
    """Imported or approved state changed while an operation was running."""


class ConnectorTransportError(RuntimeError):
    """A bounded connector transport did not complete successfully."""


def _safe_id(value: str, label: str) -> None:
    if not value or len(value) > 128 or Path(value).name != value or value in {".", ".."}:
        raise ConnectorPolicyError(f"{label} must be one safe non-empty path segment")


def normalize_origin(value: str, *, allow_insecure_http: bool = False) -> str:
    """Normalize an exact HTTP origin; paths, queries, fragments and userinfo are denied."""
    from urllib.parse import urlsplit

    parsed = urlsplit(value)
    if parsed.scheme not in ({"https"} if not allow_insecure_http else {"https", "http"}):
        raise ConnectorPolicyError("connector origin must use an allowed HTTP scheme")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ConnectorPolicyError("connector origin must contain a host and no userinfo")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ConnectorPolicyError("connector origin must not contain a path, query, or fragment")
    host = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{host}{port}"


@dataclass(frozen=True)
class ImportCredential:
    credential_id: str
    source_id: str
    connector: RemoteImportKind
    origin: str
    token: SecretStr = field(repr=False)
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        _safe_id(self.credential_id, "credential_id")
        _safe_id(self.source_id, "source_id")
        if not self.token.get_secret_value():
            raise ConnectorPolicyError("import credential token must not be empty")
        object.__setattr__(
            self,
            "origin",
            normalize_origin(self.origin, allow_insecure_http=self.allow_insecure_http),
        )


@dataclass(frozen=True)
class ExportCredential:
    credential_id: str
    destination_id: str
    connector: ExportKind
    origin: str
    token: SecretStr = field(repr=False)
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        _safe_id(self.credential_id, "credential_id")
        _safe_id(self.destination_id, "destination_id")
        if not self.token.get_secret_value():
            raise ConnectorPolicyError("export credential token must not be empty")
        object.__setattr__(
            self,
            "origin",
            normalize_origin(self.origin, allow_insecure_http=self.allow_insecure_http),
        )


@dataclass(frozen=True)
class FilesystemImportScope:
    source_id: str
    allowed_roots: tuple[Path, ...]
    max_files: int = 10_000
    max_payload_bytes: int = 1_000_000_000

    def __post_init__(self) -> None:
        _safe_id(self.source_id, "source_id")
        if not self.allowed_roots:
            raise ConnectorPolicyError("filesystem scope requires at least one allowed root")
        if self.max_files < 1 or self.max_payload_bytes < 1:
            raise ConnectorPolicyError("filesystem scope limits must be positive")


@dataclass(frozen=True)
class RemoteImportScope:
    source_id: str
    connector: RemoteImportKind
    origin: str
    datasets: tuple[str, ...]
    allowed_fields: tuple[str, ...] = ()
    max_records: int = 10_000
    max_window_seconds: int = 86_400
    max_payload_bytes: int = 50_000_000
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        _safe_id(self.source_id, "source_id")
        normalized = normalize_origin(self.origin, allow_insecure_http=self.allow_insecure_http)
        object.__setattr__(self, "origin", normalized)
        if not self.datasets or any(not item for item in self.datasets):
            raise ConnectorPolicyError("remote import scope requires named datasets")
        if min(self.max_records, self.max_window_seconds, self.max_payload_bytes) < 1:
            raise ConnectorPolicyError("remote import scope limits must be positive")


@dataclass(frozen=True)
class ImportPolicy:
    """Default-deny acquisition policy and a separate content-addressed intake root."""

    intake_root: Path
    enabled: bool = False
    filesystem_scopes: tuple[FilesystemImportScope, ...] = ()
    remote_scopes: tuple[RemoteImportScope, ...] = ()


@dataclass(frozen=True)
class QueryTerm:
    field: str
    operator: QueryOperator
    value: str

    def __post_init__(self) -> None:
        if not self.field or not self.value or len(self.value) > 4_096:
            raise ConnectorPolicyError("query terms require a field and bounded value")


@dataclass(frozen=True)
class FilesystemSnapshotRequest:
    source_id: str
    path: Path


@dataclass(frozen=True)
class RemoteSnapshotRequest:
    source_id: str
    connector: RemoteImportKind
    dataset: str
    start_time: str
    end_time: str
    max_records: int
    terms: tuple[QueryTerm, ...] = ()


ImportRequest: TypeAlias = FilesystemSnapshotRequest | RemoteSnapshotRequest


@dataclass(frozen=True)
class ImportReceipt:
    import_id: str
    connector: ImportKind
    source_id: str
    bundle_path: Path
    manifest_sha256: str
    payload_sha256: str
    payload_size: int
    credential_id: str | None
    record_count: int | None


@dataclass(frozen=True)
class ExportScope:
    destination_id: str
    connector: ExportKind
    origin: str
    artifacts: tuple[ExportArtifact, ...]
    trusted_signer_fingerprints: tuple[str, ...]
    case_ids: tuple[str, ...] = ()
    max_records: int = 10_000
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        _safe_id(self.destination_id, "destination_id")
        normalized = normalize_origin(self.origin, allow_insecure_http=self.allow_insecure_http)
        object.__setattr__(self, "origin", normalized)
        if not self.artifacts or not self.trusted_signer_fingerprints:
            raise ConnectorPolicyError("export scope requires artifacts and trusted signers")
        if self.max_records < 1:
            raise ConnectorPolicyError("export max_records must be positive")


@dataclass(frozen=True)
class ExportPolicy:
    enabled: bool = False
    scopes: tuple[ExportScope, ...] = ()


@dataclass(frozen=True)
class ExportRequest:
    case_id: str
    manifest_path: Path
    manifest_sha256: str
    destination_id: str
    connector: ExportKind
    artifact: ExportArtifact


@dataclass(frozen=True)
class ApprovedCaseState:
    case_id: str
    manifest_path: Path
    manifest_sha256: str
    manifest_hash: str
    database_path: Path
    claim_set_digest: str
    audit_head_digest: str
    approval_request_id: str
    approval_decision_id: str
    reviewer: str
    signer_fingerprint: str


@dataclass(frozen=True)
class ExportReceipt:
    export_id: str
    case_id: str
    destination_id: str
    connector: ExportKind
    artifact: ExportArtifact
    manifest_sha256: str
    manifest_hash: str
    claim_set_digest: str
    audit_head_digest: str
    approval_request_id: str
    approval_decision_id: str
    signer_fingerprint: str
    payload_sha256: str
    record_count: int
    credential_id: str
    remote_reference: str
