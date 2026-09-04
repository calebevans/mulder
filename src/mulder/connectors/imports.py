"""Immutable, provenance-preserving connector intake.

This module never writes a case database or evidence registry.  It creates a
separate content-addressed intake bundle which can later be reviewed and
ingested through Mulder's normal evidence path.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol, cast

from mulder.connectors.models import (
    ConnectorIntegrityError,
    ConnectorPolicyError,
    FilesystemImportScope,
    FilesystemSnapshotRequest,
    ImportCredential,
    ImportKind,
    ImportPolicy,
    ImportReceipt,
    ImportRequest,
    RemoteImportKind,
    RemoteImportScope,
    RemoteSnapshotRequest,
)
from mulder.connectors.transports import (
    SnapshotTransport,
    SnapshotTransportRequest,
    SnapshotTransportResponse,
)

IMPORT_SCHEMA = "mulder.connector-import"
IMPORT_VERSION = 1
_REMOTE_PATHS = {
    "splunk": "/services/search/jobs/export",
    "wazuh": "/api/v1/events/search",
    "syslog": "/api/v1/snapshots",
    "cloud": "/api/v1/log-snapshots",
}


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConnectorPolicyError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ConnectorPolicyError(f"{label} must include a timezone")
    return parsed


def _within(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


@dataclass(frozen=True)
class PreparedSnapshot:
    transport_request: SnapshotTransportRequest
    provenance: dict[str, object]


class RemoteSnapshotAdapter(Protocol):
    @property
    def connector(self) -> RemoteImportKind:
        """Reviewed connector family."""

    @property
    def source_id(self) -> str:
        """Policy source identity."""

    @property
    def credential(self) -> ImportCredential:
        """Direction-specific credential."""

    @property
    def transport(self) -> SnapshotTransport:
        """Injected bounded transport."""

    def prepare(
        self, request: RemoteSnapshotRequest, scope: RemoteImportScope
    ) -> PreparedSnapshot:
        """Build one bounded vendor request from typed query inputs."""

    def record_count(self, response: SnapshotTransportResponse) -> int | None:
        """Return a non-authoritative count without altering exact response bytes."""


class _JsonSnapshotAdapter:
    connector: RemoteImportKind
    _path: str
    _method: Literal["GET", "POST"]

    def __init__(
        self,
        *,
        source_id: str,
        credential: ImportCredential,
        transport: SnapshotTransport,
    ) -> None:
        if not isinstance(credential, ImportCredential):
            raise ConnectorPolicyError("adapter requires a direction-specific import credential")
        if credential.source_id != source_id or credential.connector != self.connector:
            raise ConnectorPolicyError("import credential is not scoped to this adapter")
        self.source_id = source_id
        self.credential = credential
        self.transport = transport

    def prepare(
        self, request: RemoteSnapshotRequest, scope: RemoteImportScope
    ) -> PreparedSnapshot:
        payload = {
            "dataset": request.dataset,
            "start_time": request.start_time,
            "end_time": request.end_time,
            "limit": request.max_records,
            "terms": [
                {"field": term.field, "operator": term.operator, "value": term.value}
                for term in request.terms
            ],
        }
        body = _canonical_json(payload)
        headers = (
            ("accept", "application/json"),
            ("authorization", f"Bearer {self.credential.token.get_secret_value()}"),
            ("content-type", "application/json"),
        )
        return PreparedSnapshot(
            transport_request=SnapshotTransportRequest(
                origin=scope.origin,
                path=self._path,
                method=self._method,
                headers=headers,
                body=body if self._method == "POST" else None,
                max_response_bytes=scope.max_payload_bytes,
            ),
            provenance={
                "origin": scope.origin,
                "path": self._path,
                "method": self._method,
                "dataset": request.dataset,
                "start_time": request.start_time,
                "end_time": request.end_time,
                "max_records": request.max_records,
                "terms": payload["terms"],
            },
        )

    def record_count(self, response: SnapshotTransportResponse) -> int | None:
        if "json" not in response.content_type.lower():
            return None
        try:
            value = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if isinstance(value, list):
            return len(value)
        if isinstance(value, dict):
            for key in ("results", "events", "items", "records"):
                rows = value.get(key)
                if isinstance(rows, list):
                    return len(rows)
        return None


class SplunkSnapshotAdapter(_JsonSnapshotAdapter):
    connector = "splunk"
    _path = "/services/search/jobs/export"
    _method = "POST"


class WazuhSnapshotAdapter(_JsonSnapshotAdapter):
    connector = "wazuh"
    _path = "/api/v1/events/search"
    _method = "POST"


class SyslogSnapshotAdapter(_JsonSnapshotAdapter):
    connector = "syslog"
    _path = "/api/v1/snapshots"
    _method = "POST"


class CloudSnapshotAdapter(_JsonSnapshotAdapter):
    connector = "cloud"
    _path = "/api/v1/log-snapshots"
    _method = "POST"


class ImmutableImporter:
    """Authorize, acquire, seal, and store one immutable intake snapshot."""

    def __init__(
        self,
        policy: ImportPolicy,
        adapters: tuple[RemoteSnapshotAdapter, ...] = (),
    ) -> None:
        self._policy = policy
        self._adapters = {(item.connector, item.source_id): item for item in adapters}
        if len(self._adapters) != len(adapters):
            raise ConnectorPolicyError("duplicate remote import adapter")

    def import_snapshot(self, request: ImportRequest) -> ImportReceipt:
        """Create a sealed content-addressed bundle without changing case evidence."""
        if not self._policy.enabled:
            raise ConnectorPolicyError("connector imports are disabled by policy")
        connector: ImportKind
        if isinstance(request, FilesystemSnapshotRequest):
            manifest, payload = self._filesystem_snapshot(request)
            credential_id: str | None = None
            record_count: int | None = None
            connector = "filesystem"
        else:
            manifest, payload, credential_id, record_count = self._remote_snapshot(request)
            connector = request.connector
        sealed = dict(manifest)
        sealed["integrity"] = {"algorithm": "sha256"}
        manifest_sha = _sha256(_canonical_json(sealed))
        cast(dict[str, object], sealed["integrity"])["manifest_sha256"] = manifest_sha
        sealed_bytes = _canonical_json(sealed) + b"\n"
        target = self._store_bundle(manifest_sha, sealed_bytes, payload)
        payload_manifest = cast(dict[str, object], manifest["payload"])
        return ImportReceipt(
            import_id=manifest_sha,
            connector=connector,
            source_id=request.source_id,
            bundle_path=target,
            manifest_sha256=manifest_sha,
            payload_sha256=cast(str, payload_manifest["sha256"]),
            payload_size=cast(int, payload_manifest["size_bytes"]),
            credential_id=credential_id,
            record_count=record_count,
        )

    def _filesystem_scope(self, source_id: str) -> FilesystemImportScope:
        scopes = [item for item in self._policy.filesystem_scopes if item.source_id == source_id]
        if len(scopes) != 1:
            raise ConnectorPolicyError("filesystem source is not uniquely enabled by policy")
        return scopes[0]

    def _remote_scope(self, request: RemoteSnapshotRequest) -> RemoteImportScope:
        scopes = [
            item
            for item in self._policy.remote_scopes
            if item.source_id == request.source_id and item.connector == request.connector
        ]
        if len(scopes) != 1:
            raise ConnectorPolicyError("remote source is not uniquely enabled by policy")
        scope = scopes[0]
        if request.dataset not in scope.datasets:
            raise ConnectorPolicyError("dataset is not enabled by policy")
        if request.max_records < 1 or request.max_records > scope.max_records:
            raise ConnectorPolicyError("record limit exceeds remote import policy")
        if any(term.field not in scope.allowed_fields for term in request.terms):
            raise ConnectorPolicyError("query field is not enabled by policy")
        start = _parse_time(request.start_time, "start_time")
        end = _parse_time(request.end_time, "end_time")
        seconds = (end - start).total_seconds()
        if seconds < 0 or seconds > scope.max_window_seconds:
            raise ConnectorPolicyError("snapshot time window exceeds remote import policy")
        return scope

    def _filesystem_snapshot(
        self, request: FilesystemSnapshotRequest
    ) -> tuple[dict[str, object], bytes]:
        scope = self._filesystem_scope(request.source_id)
        raw_path = Path(request.path).expanduser()
        if not raw_path.is_absolute():
            raise ConnectorPolicyError("filesystem import path must be absolute")
        try:
            if raw_path.is_symlink():
                raise ConnectorPolicyError("filesystem import denies symbolic links")
            resolved = raw_path.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ConnectorPolicyError(f"filesystem source does not exist: {raw_path}") from exc
        roots = tuple(root.expanduser().resolve(strict=True) for root in scope.allowed_roots)
        if not _within(resolved, roots):
            raise ConnectorPolicyError("filesystem source escapes the configured roots")
        intake = self._policy.intake_root.expanduser().resolve(strict=False)
        if resolved == intake or resolved in intake.parents or intake in resolved.parents:
            raise ConnectorPolicyError("filesystem source and immutable intake must not overlap")
        if resolved.is_file():
            before = resolved.stat()
            payload = resolved.read_bytes()
            after = resolved.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ino,
            ):
                raise ConnectorIntegrityError("filesystem source changed during acquisition")
            if len(payload) > scope.max_payload_bytes:
                raise ConnectorPolicyError("filesystem source exceeds policy byte limit")
            entries = [
                {
                    "path": resolved.name,
                    "size_bytes": len(payload),
                    "sha256": _sha256(payload),
                }
            ]
            encoding = "exact-file"
        elif resolved.is_dir():
            payload, entries = self._archive_directory(resolved, scope)
            encoding = "deterministic-zip"
        else:
            raise ConnectorPolicyError("filesystem source must be a regular file or directory")
        payload_info = {
            "encoding": encoding,
            "sha256": _sha256(payload),
            "size_bytes": len(payload),
            "entries": entries,
        }
        return (
            {
                "schema": IMPORT_SCHEMA,
                "version": IMPORT_VERSION,
                "connector": "filesystem",
                "source_id": request.source_id,
                "provenance": {
                    "original_locator": str(request.path),
                    "resolved_locator": str(resolved),
                    "allowed_root": str(
                        next(root for root in roots if _within(resolved, (root,)))
                    ),
                },
                "credential_id": None,
                "payload": payload_info,
            },
            payload,
        )

    def _archive_directory(
        self, root: Path, scope: FilesystemImportScope
    ) -> tuple[bytes, list[dict[str, object]]]:
        paths = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
        files: list[Path] = []
        for path in paths:
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ConnectorPolicyError("filesystem directory import denies symbolic links")
            if stat.S_ISREG(mode):
                files.append(path)
            elif not stat.S_ISDIR(mode):
                raise ConnectorPolicyError("filesystem directory contains a non-regular entry")
        if len(files) > scope.max_files:
            raise ConnectorPolicyError("filesystem directory exceeds policy file limit")
        output = io.BytesIO()
        entries: list[dict[str, object]] = []
        total = 0
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for path in files:
                before = path.stat()
                data = path.read_bytes()
                after = path.stat()
                if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ino,
                ):
                    raise ConnectorIntegrityError("filesystem source changed during acquisition")
                total += len(data)
                if total > scope.max_payload_bytes:
                    raise ConnectorPolicyError("filesystem directory exceeds policy byte limit")
                relative = path.relative_to(root).as_posix()
                info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100444 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, data)
                entries.append(
                    {"path": relative, "size_bytes": len(data), "sha256": _sha256(data)}
                )
        observed = sorted(
            item.relative_to(root).as_posix()
            for item in root.rglob("*")
            if item.is_file() and not item.is_symlink()
        )
        if observed != [cast(str, item["path"]) for item in entries]:
            raise ConnectorIntegrityError("filesystem directory changed during acquisition")
        return output.getvalue(), entries

    def _remote_snapshot(
        self, request: RemoteSnapshotRequest
    ) -> tuple[dict[str, object], bytes, str, int | None]:
        scope = self._remote_scope(request)
        adapter = self._adapters.get((request.connector, request.source_id))
        if adapter is None:
            raise ConnectorPolicyError("remote source has no reviewed adapter")
        credential = adapter.credential
        if (
            credential.source_id != scope.source_id
            or credential.connector != scope.connector
            or credential.origin != scope.origin
        ):
            raise ConnectorPolicyError("import credential does not match the exact source policy")
        prepared = adapter.prepare(request, scope)
        transport_request = prepared.transport_request
        if (
            transport_request.origin != scope.origin
            or transport_request.path != _REMOTE_PATHS[request.connector]
            or transport_request.method != "POST"
            or transport_request.max_response_bytes > scope.max_payload_bytes
        ):
            raise ConnectorPolicyError("adapter attempted a transport operation outside policy")
        response = adapter.transport.fetch(transport_request)
        if len(response.body) > scope.max_payload_bytes:
            raise ConnectorPolicyError("remote response exceeds policy byte limit")
        count = adapter.record_count(response)
        if count is not None and count > request.max_records:
            raise ConnectorIntegrityError("remote source returned more records than requested")
        manifest = {
            "schema": IMPORT_SCHEMA,
            "version": IMPORT_VERSION,
            "connector": request.connector,
            "source_id": request.source_id,
            "provenance": {
                **prepared.provenance,
                "content_type": response.content_type,
                "request_id": response.request_id,
            },
            "credential_id": credential.credential_id,
            "payload": {
                "encoding": "exact-remote-response",
                "sha256": _sha256(response.body),
                "size_bytes": len(response.body),
                "record_count": count,
            },
        }
        return manifest, response.body, credential.credential_id, count

    def _store_bundle(self, manifest_sha: str, manifest: bytes, payload: bytes) -> Path:
        intake = self._policy.intake_root.expanduser().resolve(strict=False)
        intake.mkdir(parents=True, exist_ok=True)
        key = manifest_sha.removeprefix("sha256:")
        target = intake / key
        if target.exists():
            verify_import_bundle(target)
            return target
        temporary = Path(tempfile.mkdtemp(prefix=".mulder-import-", dir=intake))
        try:
            manifest_path = temporary / "manifest.json"
            payload_path = temporary / "payload.bin"
            manifest_path.write_bytes(manifest)
            payload_path.write_bytes(payload)
            os.chmod(manifest_path, 0o444)
            os.chmod(payload_path, 0o444)
            os.chmod(temporary, 0o555)
            try:
                os.replace(temporary, target)
            except FileExistsError:
                verify_import_bundle(target)
            return target
        finally:
            if temporary.exists():
                os.chmod(temporary, 0o755)
                shutil.rmtree(temporary)


def verify_import_bundle(bundle_path: Path) -> dict[str, object]:
    """Verify an immutable connector bundle without network or case writes."""
    root = Path(bundle_path).expanduser().resolve(strict=True)
    manifest_path = root / "manifest.json"
    payload_path = root / "payload.bin"
    if sorted(item.name for item in root.iterdir()) != ["manifest.json", "payload.bin"]:
        raise ConnectorIntegrityError("import bundle contains unexpected or missing artifacts")
    for path in (root, manifest_path, payload_path):
        if path != root and (path.is_symlink() or not path.is_file()):
            raise ConnectorIntegrityError("import bundle artifacts must be regular files")
        if path.stat().st_mode & 0o222:
            raise ConnectorIntegrityError("import bundle is writable")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorIntegrityError(f"import manifest is unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConnectorIntegrityError("import manifest must be an object")
    integrity = raw.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        raise ConnectorIntegrityError("import manifest integrity block is unsupported")
    expected_manifest = integrity.get("manifest_sha256")
    committed = dict(raw)
    committed_integrity = dict(integrity)
    committed_integrity.pop("manifest_sha256", None)
    committed["integrity"] = committed_integrity
    actual_manifest = _sha256(_canonical_json(committed))
    if expected_manifest != actual_manifest or root.name != actual_manifest.removeprefix(
        "sha256:"
    ):
        raise ConnectorIntegrityError("import manifest content commitment does not match")
    payload = raw.get("payload")
    data = payload_path.read_bytes()
    if not isinstance(payload, dict) or payload.get("sha256") != _sha256(data):
        raise ConnectorIntegrityError("import payload content commitment does not match")
    if payload.get("size_bytes") != len(data):
        raise ConnectorIntegrityError("import payload size commitment does not match")
    return raw
