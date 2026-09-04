"""Portable, offline-verifiable and optionally examiner-signed case manifests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, cast

from mulder import __version__
from mulder.audit import AuditIntegrityResult, AuditLog
from mulder.case_signing import (
    SIGNATURE_ALGORITHM,
    SIGNATURE_PROFILE,
    ExaminerKeyProvider,
    SigningKeyError,
    create_signature_block,
    embedded_public_key,
    load_public_key,
    public_key_metadata,
    verify_manifest_signature,
)

MANIFEST_SCHEMA = "mulder.case-manifest"
MANIFEST_VERSION = 1
SQLITE_LOGICAL_PROFILE = "sqlite-logical-v1"

VerificationStatus = Literal["verified", "legacy_unverified", "invalid", "unsupported_manifest"]
DiagnosticSeverity = Literal["error", "warning"]
SignatureStatus = Literal["unsigned", "valid", "invalid", "unverifiable", "unknown"]
ReplayStatus = Literal["EXACT", "DRIFTED", "NON_DETERMINISTIC", "UNSUPPORTED"]

_STANDARD_ARTIFACT_SUFFIXES = (
    ".report.md",
    ".report.html",
    ".report.pdf",
    ".model_usage.json",
    ".outbound.jsonl",
    ".iocs.csv",
    ".iocs.stix.json",
    ".navigator.json",
)


class SealError(ValueError):
    """Raised when current case state cannot be sealed consistently."""


@dataclass(frozen=True)
class VerificationDiagnostic:
    """One precise problem or trust limitation found by ``verify_case``."""

    code: str
    severity: DiagnosticSeverity
    subject: str
    message: str
    expected: object | None = None
    actual: object | None = None

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe diagnostic dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class ReplayInventory:
    """Version inventory of the local environment proposed for replay."""

    mulder_version: str
    extractor_versions: Mapping[str, str]
    tool_versions: Mapping[str, str]
    parser_versions: Mapping[str, str]

    @classmethod
    def current(cls) -> ReplayInventory:
        """Return what the verifier can establish without invoking any tools."""
        return cls(__version__, {}, {}, {})

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> ReplayInventory:
        """Validate a JSON-like examiner-supplied replay inventory."""
        def versions(name: str) -> dict[str, str]:
            value = raw.get(name, {})
            if not isinstance(value, dict) or not all(
                isinstance(key, str) and isinstance(version, str)
                for key, version in value.items()
            ):
                raise ValueError(f"replay inventory {name} must be a string-to-string object")
            return cast(dict[str, str], value)

        mulder_version = raw.get("mulder_version", __version__)
        if not isinstance(mulder_version, str):
            raise ValueError("replay inventory mulder_version must be a string")
        return cls(
            mulder_version,
            versions("extractor_versions"),
            versions("tool_versions"),
            versions("parser_versions"),
        )


@dataclass(frozen=True)
class ReplayAssessment:
    """Replay compatibility, intentionally separate from tamper detection."""

    status: ReplayStatus
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {"status": self.status, "reasons": list(self.reasons)}


@dataclass(frozen=True)
class CaseVerificationResult:
    """Complete result of an offline case-manifest verification."""

    status: VerificationStatus
    manifest_path: str
    case_id: str | None
    artifacts_checked: int
    diagnostics: tuple[VerificationDiagnostic, ...]
    signature_status: SignatureStatus = "unknown"
    public_key: Mapping[str, str] | None = None
    replay: ReplayAssessment = ReplayAssessment("UNSUPPORTED", ("not assessed",))

    @property
    def ok(self) -> bool:
        """Whether every committed artifact and the audit chain verified."""
        return self.status == "verified"

    def as_dict(self) -> dict[str, object]:
        """Return a stable machine-readable representation."""
        return {
            "status": self.status,
            "manifest_path": self.manifest_path,
            "case_id": self.case_id,
            "artifacts_checked": self.artifacts_checked,
            "signature_status": self.signature_status,
            "public_key": dict(self.public_key) if self.public_key is not None else None,
            "replay": self.replay.as_dict(),
            "diagnostics": [diagnostic.as_dict() for diagnostic in self.diagnostics],
        }


@dataclass(frozen=True)
class _DatabaseSnapshot:
    case_id: str
    ingested_at: str
    evidence_root: str
    extractor_versions: dict[str, str]
    registry_status: Literal["present", "legacy_absent"]
    evidence_registry: tuple[dict[str, object], ...]
    normalized_sources: tuple[dict[str, object], ...]
    logical_digest: str
    schema_objects: tuple[dict[str, object], ...]
    tables: tuple[dict[str, object], ...]


def _canonical_json(value: object) -> bytes:
    """Encode JSON in the stable representation used for commitments."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_json_constant(value: str) -> object:
    """Reject the non-standard NaN/Infinity tokens accepted by ``json``."""
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate keys instead of silently choosing the final value."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key is not permitted: {key!r}")
        result[key] = value
    return result


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    """Return a full-content digest and size from one opened regular file."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(f"not a regular file: {path}")
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return "sha256:" + digest.hexdigest(), size


def _stored_sha256(value: object) -> str | None:
    """Normalize the historical bare SHA-256 registry format."""
    if not isinstance(value, str):
        return None
    lowered = value.lower()
    if lowered.startswith("sha256:"):
        lowered = lowered[7:]
    if len(lowered) != 64 or any(char not in "0123456789abcdef" for char in lowered):
        return None
    return "sha256:" + lowered


def _sqlite_value(value: object) -> dict[str, object]:
    """Losslessly tag one SQLite value for canonical hashing."""
    if value is None:
        return {"type": "null"}
    if isinstance(value, bytes):
        return {"type": "blob", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, str):
        return {"type": "text", "value": value}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        return {"type": "real", "value": value.hex()}
    raise TypeError(f"unsupported SQLite value type: {type(value).__name__}")


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _table_commitment(
    connection: sqlite3.Connection,
    name: str,
    schema_sql: str | None,
) -> dict[str, object]:
    """Commit a table schema and all rows in deterministic value order."""
    quoted = _quote_identifier(name)
    columns_raw = connection.execute(f"PRAGMA table_xinfo({quoted})").fetchall()
    columns = [
        {
            "cid": row[0],
            "name": row[1],
            "type": row[2],
            "notnull": row[3],
            "default": row[4],
            "pk": row[5],
            "hidden": row[6],
        }
        for row in columns_raw
    ]
    readable = [cast(str, row[1]) for row in columns_raw if row[6] in (0, 2, 3)]
    table_header = {
        "name": name,
        "schema_sql": schema_sql,
        "columns": columns,
    }
    schema_digest = _sha256_bytes(_canonical_json(table_header))
    content = hashlib.sha256()
    content.update(b"mulder.sqlite-logical:v1:table\0")
    content.update(_canonical_json(table_header))
    content.update(b"\n")

    row_count = 0
    if readable:
        projection = ", ".join(_quote_identifier(column) for column in readable)
        # Ordering by every projected value gives rowid-independent output.  Equal
        # rows have identical encodings, so their relative order is immaterial.
        ordering = ", ".join(_quote_identifier(column) for column in readable)
        cursor = connection.execute(f"SELECT {projection} FROM {quoted} ORDER BY {ordering}")
        for row in cursor:
            encoded = [_sqlite_value(value) for value in row]
            content.update(_canonical_json(encoded))
            content.update(b"\n")
            row_count += 1

    return {
        "name": name,
        "schema_digest": schema_digest,
        "content_digest": "sha256:" + content.hexdigest(),
        "row_count": row_count,
    }


def _connect_read_only(path: Path) -> sqlite3.Connection:
    """Open SQLite without creating or migrating a database."""
    uri = path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    connection.execute("PRAGMA query_only=ON")
    return connection


def _snapshot_database(path: Path) -> _DatabaseSnapshot:
    """Capture one read transaction over metadata and every logical DB table."""
    try:
        connection = _connect_read_only(path)
    except sqlite3.Error as exc:
        raise SealError(f"Cannot open case database read-only: {path}: {exc}") from exc

    try:
        connection.execute("BEGIN")
        schema_rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name"
        ).fetchall()
        schema_objects = tuple(
            {
                "type": row[0],
                "name": row[1],
                "table": row[2],
                "sql": row[3],
            }
            for row in schema_rows
        )
        table_rows = [(row[1], row[3]) for row in schema_rows if row[0] == "table"]
        table_names = {cast(str, row[0]) for row in table_rows}
        if "case_metadata" not in table_names:
            raise SealError("Database is not a Mulder case: case_metadata table is absent")

        metadata_row = connection.execute(
            "SELECT case_id, ingested_at, evidence_root, extractor_versions "
            "FROM case_metadata LIMIT 1"
        ).fetchone()
        if metadata_row is None:
            raise SealError("Database is not a Mulder case: case metadata is empty")
        if not all(isinstance(metadata_row[index], str) for index in range(3)):
            raise SealError(
                "Case metadata contains a non-text case ID, timestamp, or evidence root"
            )
        try:
            extractor_versions_raw = json.loads(cast(str, metadata_row[3]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise SealError("Case extractor_versions is not valid JSON") from exc
        if not isinstance(extractor_versions_raw, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in extractor_versions_raw.items()
        ):
            raise SealError("Case extractor_versions must be a string-to-string object")
        extractor_versions = cast(dict[str, str], extractor_versions_raw)

        registry: list[dict[str, object]] = []
        registry_status: Literal["present", "legacy_absent"] = "legacy_absent"
        if "evidence_registry" in table_names:
            registry_status = "present"
            registry_rows = connection.execute(
                "SELECT id, file_path, sha256, size_bytes, registered_at "
                "FROM evidence_registry ORDER BY id"
            ).fetchall()
            registry = [
                {
                    "registry_id": row[0],
                    "original_path": row[1],
                    "sha256": row[2],
                    "size_bytes": row[3],
                    "registered_at": row[4],
                }
                for row in registry_rows
            ]

        normalized_sources: list[dict[str, object]] = []
        if "sources" in table_names:
            source_columns = {
                cast(str, row[1])
                for row in connection.execute('PRAGMA table_xinfo("sources")').fetchall()
            }
            windows_expr = "windows_hash" if "windows_hash" in source_columns else "NULL"
            source_rows = connection.execute(
                "SELECT source_id, source_name, source_hash, extractor, line_count, "
                f"{windows_expr} FROM sources ORDER BY source_id"
            ).fetchall()
            normalized_sources = [
                {
                    "source_id": row[0],
                    "source_name": row[1],
                    "source_hash": row[2],
                    "extractor": row[3],
                    "line_count": row[4],
                    "windows_hash": row[5],
                }
                for row in source_rows
            ]

        tables = tuple(
            _table_commitment(connection, cast(str, name), cast(str | None, schema_sql))
            for name, schema_sql in table_rows
        )
        logical = hashlib.sha256()
        logical.update(b"mulder.sqlite-logical:v1:database\0")
        for schema_object in schema_objects:
            logical.update(_canonical_json(schema_object))
            logical.update(b"\n")
        for table in tables:
            logical.update(_canonical_json(table))
            logical.update(b"\n")
        connection.rollback()
        return _DatabaseSnapshot(
            case_id=cast(str, metadata_row[0]),
            ingested_at=cast(str, metadata_row[1]),
            evidence_root=cast(str, metadata_row[2]),
            extractor_versions=extractor_versions,
            registry_status=registry_status,
            evidence_registry=tuple(registry),
            normalized_sources=tuple(normalized_sources),
            logical_digest="sha256:" + logical.hexdigest(),
            schema_objects=schema_objects,
            tables=tables,
        )
    except SealError:
        raise
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise SealError(f"Cannot snapshot case database {path}: {exc}") from exc
    finally:
        connection.close()


def _portable_path(path: Path, manifest_parent: Path) -> str:
    """Return a normalized relative locator, including sibling directories."""
    return Path(os.path.relpath(path.resolve(strict=False), manifest_parent.resolve())).as_posix()


def _relative_to(path: Path, root: Path) -> str | None:
    try:
        return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except ValueError:
        return None


def _assert_quiescent_database(path: Path) -> None:
    """Reject a live SQLite write journal that would be easy to omit from a copy."""
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(path) + suffix)
        try:
            size = sidecar.stat().st_size
        except FileNotFoundError:
            continue
        if size:
            raise SealError(
                f"Case database is not quiescent ({sidecar.name} is non-empty); "
                "stop the writer/checkpoint SQLite before sealing"
            )


def _stable_file_commitment(path: Path) -> tuple[str, int]:
    """Hash a stable file snapshot, rejecting concurrent changes."""
    for _attempt in range(3):
        before = path.stat()
        digest, size = _sha256_file(path)
        after = path.stat()
        fingerprint_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        fingerprint_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if fingerprint_before == fingerprint_after and size == after.st_size:
            return digest, size
    raise SealError(f"Artifact changed while it was being sealed: {path}")


def _audit_commitment(path: Path) -> tuple[AuditIntegrityResult, str, int, dict[str, int]]:
    """Capture a stable audit file, including its externally retained head."""
    for _attempt in range(3):
        first = AuditLog(path)
        first_result = first.verify_integrity()
        digest, size = _stable_file_commitment(path)
        second = AuditLog(path)
        second_result = second.verify_integrity()
        second_digest, second_size = _stable_file_commitment(path)
        if first_result == second_result and digest == second_digest and size == second_size:
            if not first_result.ok:
                raise SealError(
                    "Cannot seal an invalid audit chain: "
                    f"{first_result.error_code or 'invalid'}: {first_result.message}"
                )
            return first_result, digest, size, dict(first.summary().tool_call_counts)
    raise SealError(f"Audit log changed while it was being sealed: {path}")


def _manifest_hash(manifest: Mapping[str, object]) -> str:
    """Hash the manifest with the self-referential field omitted."""
    copy = dict(manifest)
    integrity_raw = copy.get("integrity")
    if isinstance(integrity_raw, dict):
        integrity = dict(cast(dict[str, object], integrity_raw))
        integrity.pop("manifest_hash", None)
        copy["integrity"] = integrity
    return _sha256_bytes(b"mulder.case-manifest:v1\0" + _canonical_json(copy))


def _discover_reports(case_id: str, db_dir: Path) -> list[Path]:
    """Find the standard report/export artifacts produced by Mulder's CLI."""
    reports: list[Path] = []
    for suffix in _STANDARD_ARTIFACT_SUFFIXES:
        candidate = db_dir / f"{case_id}{suffix}"
        if candidate.is_file():
            reports.append(candidate)
    return reports


def _replay_contract(case_id: str, db_path: Path, db_dir: Path) -> dict[str, object]:
    """Record versioned inputs without running a parser, model, or forensic tool."""
    tools: dict[str, str] = {}
    parsers: dict[str, str] = {}
    unknown: list[str] = []
    connection = _connect_read_only(db_path)
    try:
        table_names = {
            cast(str, row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
        }
        if "coverage_register" in table_names:
            rows = connection.execute(
                "SELECT system_name, evidence_domain, check_name, coverage "
                "FROM coverage_register ORDER BY system_name, evidence_domain, check_name"
            ).fetchall()
            for system_name, evidence_domain, check_name, coverage_json in rows:
                key = f"{system_name}/{evidence_domain}/{check_name}"
                try:
                    coverage = json.loads(cast(str, coverage_json))
                except (json.JSONDecodeError, TypeError):
                    unknown.append(f"coverage:{key}:invalid")
                    continue
                if not isinstance(coverage, dict):
                    unknown.append(f"coverage:{key}:invalid")
                    continue
                tool_version = coverage.get("tool_version")
                parser_version = coverage.get("parser_version")
                if isinstance(tool_version, str) and tool_version:
                    tools[key] = tool_version
                else:
                    unknown.append(f"tool:{key}")
                if isinstance(parser_version, str) and parser_version:
                    parsers[key] = parser_version
                else:
                    unknown.append(f"parser:{key}")
        if "claim_verifications" in table_names:
            rows = connection.execute(
                "SELECT DISTINCT verifier_name, verifier_version FROM claim_verifications "
                "ORDER BY verifier_name, verifier_version"
            ).fetchall()
            for verifier_name, verifier_version in rows:
                key = f"claim-verifier:{verifier_name}"
                if isinstance(verifier_version, str) and verifier_version:
                    previous = tools.get(key)
                    if previous is not None and previous != verifier_version:
                        unknown.append(f"tool:{key}:multiple_versions")
                    tools[key] = verifier_version
                else:
                    unknown.append(f"tool:{key}")
    finally:
        connection.close()

    models: list[str] = []
    usage_path = db_dir / f"{case_id}.model_usage.json"
    if usage_path.is_file():
        try:
            usage = json.loads(usage_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            unknown.append("models:model_usage_sidecar_invalid")
        else:
            if not isinstance(usage, list):
                unknown.append("models:model_usage_sidecar_invalid")
            else:
                for index, item in enumerate(usage):
                    if isinstance(item, dict) and isinstance(item.get("model"), str):
                        models.append(cast(str, item["model"]))
                    else:
                        unknown.append(f"models:model_usage_entry:{index}")

    return {
        "schema": "mulder.replay-inputs",
        "version": 1,
        "mulder_version": __version__,
        "extractor_versions": {},  # filled from the transactional DB snapshot
        "tool_versions": dict(sorted(tools.items())),
        "parser_versions": dict(sorted(parsers.items())),
        "model_inputs": sorted(set(models)),
        "unknown_versions": sorted(set(unknown)),
    }


def assess_replay(
    manifest: Mapping[str, object],
    inventory: ReplayInventory | Mapping[str, object] | None = None,
) -> ReplayAssessment:
    """Classify replay feasibility without changing artifact-integrity status."""
    methodology = manifest.get("methodology")
    contract = methodology.get("replay") if isinstance(methodology, dict) else None
    if not isinstance(contract, dict) or (
        contract.get("schema") != "mulder.replay-inputs" or contract.get("version") != 1
    ):
        return ReplayAssessment("UNSUPPORTED", ("manifest has no supported replay contract",))
    models = contract.get("model_inputs")
    if isinstance(models, list) and models:
        names = ", ".join(str(model) for model in models)
        return ReplayAssessment(
            "NON_DETERMINISTIC",
            (f"recorded model inputs cannot guarantee byte-identical replay: {names}",),
        )
    unknown = contract.get("unknown_versions")
    if isinstance(unknown, list) and unknown:
        return ReplayAssessment(
            "UNSUPPORTED",
            tuple(f"recorded input has no usable version: {item}" for item in unknown),
        )
    try:
        current = (
            ReplayInventory.current()
            if inventory is None
            else inventory
            if isinstance(inventory, ReplayInventory)
            else ReplayInventory.from_mapping(inventory)
        )
    except ValueError as exc:
        return ReplayAssessment("UNSUPPORTED", (str(exc),))

    reasons: list[str] = []
    missing: list[str] = []
    recorded_mulder = contract.get("mulder_version")
    if not isinstance(recorded_mulder, str):
        missing.append("recorded Mulder version is absent")
    elif recorded_mulder != current.mulder_version:
        reasons.append(
            f"mulder version drift: recorded {recorded_mulder}, current {current.mulder_version}"
        )
    for field, observed in (
        ("extractor_versions", current.extractor_versions),
        ("tool_versions", current.tool_versions),
        ("parser_versions", current.parser_versions),
    ):
        recorded = contract.get(field)
        if not isinstance(recorded, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in recorded.items()
        ):
            missing.append(f"recorded {field} inventory is invalid")
            continue
        for name, version in cast(dict[str, str], recorded).items():
            current_version = observed.get(name)
            if current_version is None:
                missing.append(f"current {field}:{name} is unavailable")
            elif current_version != version:
                reasons.append(
                    f"{field}:{name} drift: recorded {version}, current {current_version}"
                )
    if missing:
        return ReplayAssessment("UNSUPPORTED", tuple(missing))
    if reasons:
        return ReplayAssessment("DRIFTED", tuple(reasons))
    return ReplayAssessment("EXACT", ())


def _write_manifest(path: Path, manifest: Mapping[str, object], overwrite: bool) -> None:
    """Atomically persist a completed manifest."""
    if path.exists() and not overwrite:
        raise SealError(f"Manifest already exists (pass --force to replace it): {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(manifest, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def seal_case(
    case_id: str,
    db_dir: Path,
    *,
    manifest_path: Path | None = None,
    report_artifacts: Sequence[Path] = (),
    overwrite: bool = False,
    key_provider: ExaminerKeyProvider | None = None,
) -> Path:
    """Create a versioned manifest binding one complete case snapshot.

    Standard Mulder report/export files are discovered next to the case DB.
    ``report_artifacts`` adds explicitly named artifacts outside that set.  The
    command refuses stale registry entries and invalid audit chains so a newly
    created receipt verifies at the moment it is written.
    """
    db_dir = Path(db_dir).expanduser().resolve(strict=False)
    db_path = db_dir / f"{case_id}.db"
    audit_path = db_dir / f"{case_id}.audit.jsonl"
    output = (
        Path(manifest_path).expanduser().resolve(strict=False)
        if manifest_path is not None
        else db_dir / f"{case_id}.manifest.json"
    )
    if not db_path.is_file():
        raise SealError(f"Case database not found: {db_path}")
    if not audit_path.is_file():
        raise SealError(f"Case audit log not found: {audit_path}")

    _assert_quiescent_database(db_path)
    database = _snapshot_database(db_path)
    _assert_quiescent_database(db_path)
    if database.case_id != case_id:
        raise SealError(
            f"Case ID mismatch: requested {case_id!r}, database contains {database.case_id!r}"
        )

    evidence_root = Path(database.evidence_root).expanduser().resolve(strict=False)
    evidence_root_kind = "file" if evidence_root.is_file() else "directory"
    evidence_entries: list[dict[str, object]] = []
    evidence_digests: dict[Path, tuple[str, int]] = {}
    for registry_entry in database.evidence_registry:
        registered_path = registry_entry["original_path"]
        if not isinstance(registered_path, str) or not registered_path:
            raise SealError(
                f"Evidence registry entry {registry_entry['registry_id']} has no valid path"
            )
        original_path = Path(registered_path).expanduser()
        actual_path = (
            original_path if original_path.is_absolute() else evidence_root / original_path
        ).resolve(strict=False)
        if not actual_path.is_file():
            raise SealError(f"Registered evidence artifact is missing: {original_path}")
        expected_hash = _stored_sha256(registry_entry["sha256"])
        if expected_hash is None:
            raise SealError(
                "Registered evidence artifact has an invalid SHA-256 value: "
                f"{original_path}: {registry_entry['sha256']!r}"
            )
        commitment = evidence_digests.get(actual_path)
        if commitment is None:
            commitment = _stable_file_commitment(actual_path)
            evidence_digests[actual_path] = commitment
        actual_hash, actual_size = commitment
        expected_size = registry_entry["size_bytes"]
        if actual_hash != expected_hash or actual_size != expected_size:
            raise SealError(
                "Registered evidence artifact changed before sealing: "
                f"{original_path} (expected {expected_hash}/{expected_size}, "
                f"actual {actual_hash}/{actual_size})"
            )
        root_relative = _relative_to(actual_path, evidence_root)
        evidence_entries.append(
            {
                **registry_entry,
                "sha256": expected_hash,
                "location": {
                    "root": "evidence" if root_relative is not None else "manifest",
                    "path": (
                        root_relative
                        if root_relative is not None
                        else _portable_path(actual_path, output.parent)
                    ),
                },
            }
        )

    audit_result, audit_hash, audit_size, tool_counts = _audit_commitment(audit_path)

    reports: list[dict[str, object]] = []
    candidates = [*_discover_reports(case_id, db_dir), *(Path(p) for p in report_artifacts)]
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.expanduser().resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        if not resolved.is_file():
            raise SealError(f"Report artifact not found: {candidate}")
        digest, size = _stable_file_commitment(resolved)
        reports.append(
            {
                "name": resolved.name,
                "path": _portable_path(resolved, output.parent),
                "sha256": digest,
                "size_bytes": size,
            }
        )

    table_by_name = {cast(str, table["name"]): table for table in database.tables}
    record_sets: dict[str, object] = {}
    for name in ("claims", "evidence_anchors"):
        table = table_by_name.get(name)
        record_sets[name] = (
            {
                "status": "present",
                "row_count": table["row_count"],
                "content_digest": table["content_digest"],
            }
            if table is not None
            else {"status": "absent_legacy"}
        )

    replay = _replay_contract(case_id, db_path, db_dir)
    replay["extractor_versions"] = dict(sorted(database.extractor_versions.items()))
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "version": MANIFEST_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "case": {
            "case_id": database.case_id,
            "ingested_at": database.ingested_at,
        },
        "locations": {
            "manifest": {"path": ".", "kind": "directory"},
            "evidence": {
                "path": _portable_path(evidence_root, output.parent),
                "kind": evidence_root_kind,
                "original_path": database.evidence_root,
            },
        },
        "database": {
            "path": _portable_path(db_path, output.parent),
            "profile": SQLITE_LOGICAL_PROFILE,
            "logical_digest": database.logical_digest,
            "schema_objects": list(database.schema_objects),
            "tables": list(database.tables),
            "record_sets": record_sets,
            "normalized_sources": list(database.normalized_sources),
        },
        "evidence_registry": {
            "status": database.registry_status,
            "entries": evidence_entries,
        },
        "audit": {
            "path": _portable_path(audit_path, output.parent),
            "sha256": audit_hash,
            "size_bytes": audit_size,
            "chain_status": audit_result.status,
            "entry_count": audit_result.entries_checked,
            "legacy_entries": audit_result.legacy_entries,
            "head_hash": audit_result.head_hash,
        },
        "methodology": {
            "profile": "mulder-case-v1",
            "mulder_version": __version__,
            "extractor_versions": database.extractor_versions,
            "audit_tool_counts": dict(sorted(tool_counts.items())),
            "replay": replay,
        },
        "reports": reports,
        "integrity": {
            "algorithm": "sha256",
            "signature": {"status": "unsigned"},
        },
    }
    if key_provider is not None:
        cast(dict[str, object], manifest["integrity"])["signature"] = create_signature_block(
            manifest, key_provider
        )
    cast(dict[str, object], manifest["integrity"])["manifest_hash"] = _manifest_hash(manifest)
    _write_manifest(output, manifest, overwrite)
    return output


def _diagnostic(
    diagnostics: list[VerificationDiagnostic],
    code: str,
    subject: str,
    message: str,
    *,
    severity: DiagnosticSeverity = "error",
    expected: object | None = None,
    actual: object | None = None,
) -> None:
    diagnostics.append(
        VerificationDiagnostic(
            code=code,
            severity=severity,
            subject=subject,
            message=message,
            expected=expected,
            actual=actual,
        )
    )


def _resolve_relative(parent: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("artifact path must be a non-empty string")
    path = Path(value)
    if path.is_absolute():
        raise ValueError("artifact path must be relative to its declared root")
    return (parent / path).resolve(strict=False)


def _verify_file(
    *,
    path: Path,
    expected_hash: object,
    expected_size: object,
    subject: str,
    code_prefix: str,
    diagnostics: list[VerificationDiagnostic],
) -> bool:
    if not path.exists():
        _diagnostic(
            diagnostics,
            f"{code_prefix}.missing",
            subject,
            f"Committed artifact is missing: {path}",
            expected=str(path),
            actual=None,
        )
        return False
    if not path.is_file():
        _diagnostic(
            diagnostics,
            f"{code_prefix}.not_regular_file",
            subject,
            f"Committed artifact is not a regular file: {path}",
        )
        return False
    try:
        actual_hash, actual_size = _sha256_file(path)
    except OSError as exc:
        _diagnostic(
            diagnostics,
            f"{code_prefix}.unreadable",
            subject,
            f"Cannot read committed artifact {path}: {exc}",
        )
        return False
    if actual_size != expected_size:
        _diagnostic(
            diagnostics,
            f"{code_prefix}.size_mismatch",
            subject,
            f"Artifact size changed: {path}",
            expected=expected_size,
            actual=actual_size,
        )
    if actual_hash != expected_hash:
        _diagnostic(
            diagnostics,
            f"{code_prefix}.content_mismatch",
            subject,
            f"Artifact content digest changed: {path}",
            expected=expected_hash,
            actual=actual_hash,
        )
    return True


def _verify_database(
    manifest_parent: Path,
    raw: Mapping[str, object],
    expected_case_id: str | None,
    diagnostics: list[VerificationDiagnostic],
) -> int:
    try:
        path = _resolve_relative(manifest_parent, raw.get("path"))
    except ValueError as exc:
        _diagnostic(diagnostics, "database.invalid_path", "database", str(exc))
        return 0
    if not path.is_file():
        _diagnostic(
            diagnostics,
            "database.missing",
            "database",
            f"Case database is missing: {path}",
        )
        return 0
    if raw.get("profile") != SQLITE_LOGICAL_PROFILE:
        _diagnostic(
            diagnostics,
            "database.unsupported_profile",
            "database",
            "Database commitment profile is unsupported.",
            expected=SQLITE_LOGICAL_PROFILE,
            actual=raw.get("profile"),
        )
        return 0
    try:
        _assert_quiescent_database(path)
    except SealError as exc:
        _diagnostic(
            diagnostics,
            "database.active_journal",
            "database",
            str(exc),
        )
        return 0
    try:
        actual = _snapshot_database(path)
    except (SealError, OSError) as exc:
        _diagnostic(
            diagnostics,
            "database.unreadable",
            "database",
            f"Cannot verify case database {path}: {exc}",
        )
        return 0

    if actual.case_id != expected_case_id:
        _diagnostic(
            diagnostics,
            "database.case_id_mismatch",
            "database:case_metadata",
            "Database case ID differs from the manifest case ID.",
            expected=expected_case_id,
            actual=actual.case_id,
        )

    expected_schema_raw = raw.get("schema_objects")
    if not isinstance(expected_schema_raw, list):
        _diagnostic(
            diagnostics,
            "database.invalid_schema_manifest",
            "database",
            "Database schema-object commitments must be a list.",
        )
    else:
        expected_schema: dict[tuple[str, str, str], dict[str, object]] = {}
        for index, schema_raw in enumerate(expected_schema_raw):
            if not isinstance(schema_raw, dict) or not all(
                isinstance(schema_raw.get(field), str) for field in ("type", "name", "table")
            ):
                _diagnostic(
                    diagnostics,
                    "database.invalid_schema_entry",
                    f"database:schema:{index}",
                    "Database schema entry must name its type, object, and table.",
                )
                continue
            schema = cast(dict[str, object], schema_raw)
            key = (
                cast(str, schema["type"]),
                cast(str, schema["name"]),
                cast(str, schema["table"]),
            )
            if key in expected_schema:
                _diagnostic(
                    diagnostics,
                    "database.duplicate_schema_entry",
                    f"database:schema:{key[1]}",
                    f"Database schema entry is duplicated: {key[1]}",
                )
            expected_schema[key] = schema
        actual_schema = {
            (
                cast(str, schema["type"]),
                cast(str, schema["name"]),
                cast(str, schema["table"]),
            ): schema
            for schema in actual.schema_objects
        }
        for key in sorted(set(expected_schema) - set(actual_schema)):
            _diagnostic(
                diagnostics,
                "database.schema_object_missing",
                f"database:schema:{key[1]}",
                f"Committed database {key[0]} is missing: {key[1]}",
            )
        for key in sorted(set(actual_schema) - set(expected_schema)):
            _diagnostic(
                diagnostics,
                "database.schema_object_added",
                f"database:schema:{key[1]}",
                f"Uncommitted database {key[0]} was added: {key[1]}",
            )
        for key in sorted(set(expected_schema) & set(actual_schema)):
            expected_object = expected_schema[key]
            actual_object = actual_schema[key]
            if expected_object != actual_object:
                _diagnostic(
                    diagnostics,
                    "database.schema_object_mismatch",
                    f"database:schema:{key[1]}",
                    f"Database {key[0]} definition changed: {key[1]}",
                    expected=_sha256_bytes(_canonical_json(expected_object)),
                    actual=_sha256_bytes(_canonical_json(actual_object)),
                )

    expected_tables_raw = raw.get("tables")
    if not isinstance(expected_tables_raw, list):
        _diagnostic(
            diagnostics,
            "database.invalid_table_manifest",
            "database",
            "Database table commitments must be a list.",
        )
        return 1
    expected_tables: dict[str, dict[str, object]] = {}
    for index, row_raw in enumerate(expected_tables_raw):
        if not isinstance(row_raw, dict) or not isinstance(row_raw.get("name"), str):
            _diagnostic(
                diagnostics,
                "database.invalid_table_entry",
                f"database:table:{index}",
                "Database table commitment must be an object with a string name.",
            )
            continue
        row = cast(dict[str, object], row_raw)
        name = cast(str, row["name"])
        if name in expected_tables:
            _diagnostic(
                diagnostics,
                "database.duplicate_table_entry",
                f"database:table:{name}",
                f"Database table commitment is duplicated: {name}",
            )
        expected_tables[name] = row
    actual_tables: dict[str, dict[str, object]] = {
        cast(str, row["name"]): row for row in actual.tables
    }
    for name in sorted(set(expected_tables) - set(actual_tables), key=str):
        _diagnostic(
            diagnostics,
            "database.table_missing",
            f"database:{name}",
            f"Committed database table is missing: {name}",
        )
    for name in sorted(set(actual_tables) - set(expected_tables), key=str):
        _diagnostic(
            diagnostics,
            "database.table_added",
            f"database:{name}",
            f"Uncommitted database table was added: {name}",
        )
    for name in sorted(set(expected_tables) & set(actual_tables), key=str):
        expected = expected_tables[name]
        observed = actual_tables[name]
        if expected.get("schema_digest") != observed.get("schema_digest"):
            _diagnostic(
                diagnostics,
                "database.schema_mismatch",
                f"database:{name}",
                f"Database table schema changed: {name}",
                expected=expected.get("schema_digest"),
                actual=observed.get("schema_digest"),
            )
        if expected.get("row_count") != observed.get("row_count"):
            _diagnostic(
                diagnostics,
                "database.row_count_mismatch",
                f"database:{name}",
                f"Database table row count changed: {name}",
                expected=expected.get("row_count"),
                actual=observed.get("row_count"),
            )
        if expected.get("content_digest") != observed.get("content_digest"):
            _diagnostic(
                diagnostics,
                "database.content_mismatch",
                f"database:{name}",
                f"Database table content changed: {name}",
                expected=expected.get("content_digest"),
                actual=observed.get("content_digest"),
            )
    if raw.get("logical_digest") != actual.logical_digest:
        _diagnostic(
            diagnostics,
            "database.logical_digest_mismatch",
            "database",
            "Case database logical digest changed.",
            expected=raw.get("logical_digest"),
            actual=actual.logical_digest,
        )
    return 1


def _verify_audit(
    manifest_parent: Path,
    raw: Mapping[str, object],
    diagnostics: list[VerificationDiagnostic],
) -> tuple[int, bool]:
    try:
        path = _resolve_relative(manifest_parent, raw.get("path"))
    except ValueError as exc:
        _diagnostic(diagnostics, "audit.invalid_path", "audit", str(exc))
        return 0, False
    if not _verify_file(
        path=path,
        expected_hash=raw.get("sha256"),
        expected_size=raw.get("size_bytes"),
        subject="audit",
        code_prefix="audit",
        diagnostics=diagnostics,
    ):
        return 0, False

    result = AuditLog(path).verify_integrity()
    if not result.ok:
        _diagnostic(
            diagnostics,
            "audit.chain_invalid",
            "audit",
            result.message,
            expected="valid chained or explicit legacy audit",
            actual={
                "error_code": result.error_code,
                "line": result.first_error_line,
                "sequence": result.first_error_sequence,
            },
        )
    expected_count = raw.get("entry_count")
    if result.entries_checked != expected_count:
        _diagnostic(
            diagnostics,
            "audit.entry_count_mismatch",
            "audit",
            "Audit entry count differs from the sealed count; a suffix may have been removed.",
            expected=expected_count,
            actual=result.entries_checked,
        )
    if result.head_hash != raw.get("head_hash"):
        _diagnostic(
            diagnostics,
            "audit.head_mismatch",
            "audit",
            "Audit chain head differs from the externally sealed head.",
            expected=raw.get("head_hash"),
            actual=result.head_hash,
        )
    if result.status != raw.get("chain_status"):
        _diagnostic(
            diagnostics,
            "audit.status_mismatch",
            "audit",
            "Audit integrity status changed since sealing.",
            expected=raw.get("chain_status"),
            actual=result.status,
        )

    legacy = result.status in {"legacy_unverified", "empty"}
    if result.status == "legacy_unverified":
        _diagnostic(
            diagnostics,
            "audit.legacy_unverified",
            "audit",
            "Legacy audit entries are readable and content-bound but were never hash-chained.",
            severity="warning",
        )
    elif result.status == "empty":
        _diagnostic(
            diagnostics,
            "audit.empty_unverified",
            "audit",
            "The sealed audit is empty and provides no event-chain assurance.",
            severity="warning",
        )
    return 1, legacy


def _verify_evidence(
    manifest_parent: Path,
    raw: Mapping[str, object],
    locations: Mapping[str, object],
    evidence_root_override: Path | None,
    diagnostics: list[VerificationDiagnostic],
) -> tuple[int, bool]:
    legacy = raw.get("status") == "legacy_absent"
    if legacy:
        _diagnostic(
            diagnostics,
            "evidence.registry_legacy_absent",
            "evidence_registry",
            "This legacy database has no evidence registry; original evidence is unverified.",
            severity="warning",
        )
    entries = raw.get("entries")
    if not isinstance(entries, list):
        _diagnostic(
            diagnostics,
            "evidence.invalid_registry",
            "evidence_registry",
            "Evidence registry entries must be a list.",
        )
        return 0, legacy

    evidence_location = locations.get("evidence")
    evidence_kind = None
    try:
        if evidence_root_override is not None:
            evidence_base = evidence_root_override.expanduser().resolve(strict=False)
        elif isinstance(evidence_location, dict):
            evidence_base = _resolve_relative(
                manifest_parent, cast(dict[str, object], evidence_location).get("path")
            )
        else:
            raise ValueError("manifest has no evidence root location")
        if isinstance(evidence_location, dict):
            evidence_kind = evidence_location.get("kind")
    except ValueError as exc:
        _diagnostic(diagnostics, "evidence.invalid_root", "evidence_registry", str(exc))
        return 0, legacy

    checked = 0
    for index, entry_raw in enumerate(entries):
        if not isinstance(entry_raw, dict):
            _diagnostic(
                diagnostics,
                "evidence.invalid_entry",
                f"evidence:{index}",
                "Evidence registry entry must be an object.",
            )
            continue
        entry = cast(dict[str, object], entry_raw)
        location = entry.get("location")
        if not isinstance(location, dict):
            _diagnostic(
                diagnostics,
                "evidence.invalid_location",
                f"evidence:{index}",
                "Evidence registry entry has no valid location.",
            )
            continue
        root_name = location.get("root")
        try:
            if root_name == "evidence":
                relative = location.get("path")
                if evidence_kind == "file" or evidence_base.is_file():
                    if relative not in (".", ""):
                        raise ValueError("file evidence root can only resolve the '.' entry")
                    artifact_path = evidence_base
                else:
                    artifact_path = _resolve_relative(evidence_base, relative)
            elif root_name == "manifest":
                artifact_path = _resolve_relative(manifest_parent, location.get("path"))
            else:
                raise ValueError(f"unsupported evidence location root: {root_name!r}")
        except ValueError as exc:
            _diagnostic(
                diagnostics,
                "evidence.invalid_location",
                f"evidence:{index}",
                str(exc),
            )
            continue
        _verify_file(
            path=artifact_path,
            expected_hash=entry.get("sha256"),
            expected_size=entry.get("size_bytes"),
            subject=f"evidence:{entry.get('registry_id', index)}:{entry.get('original_path')}",
            code_prefix="evidence",
            diagnostics=diagnostics,
        )
        checked += 1
    return checked, legacy


def _verify_reports(
    manifest_parent: Path,
    raw: object,
    diagnostics: list[VerificationDiagnostic],
) -> int:
    if not isinstance(raw, list):
        _diagnostic(
            diagnostics,
            "report.invalid_manifest",
            "reports",
            "Report commitments must be a list.",
        )
        return 0
    checked = 0
    for index, report_raw in enumerate(raw):
        if not isinstance(report_raw, dict):
            _diagnostic(
                diagnostics,
                "report.invalid_entry",
                f"report:{index}",
                "Report commitment must be an object.",
            )
            continue
        report = cast(dict[str, object], report_raw)
        try:
            path = _resolve_relative(manifest_parent, report.get("path"))
        except ValueError as exc:
            _diagnostic(diagnostics, "report.invalid_path", f"report:{index}", str(exc))
            continue
        _verify_file(
            path=path,
            expected_hash=report.get("sha256"),
            expected_size=report.get("size_bytes"),
            subject=f"report:{report.get('name', index)}",
            code_prefix="report",
            diagnostics=diagnostics,
        )
        checked += 1
    return checked


def _verify_signature(
    manifest: Mapping[str, object],
    integrity: Mapping[str, object],
    public_key_path: Path | None,
    diagnostics: list[VerificationDiagnostic],
) -> tuple[SignatureStatus, Mapping[str, str] | None]:
    """Verify optional Ed25519 approval independently of artifact checks."""
    signature_raw = integrity.get("signature")
    if not isinstance(signature_raw, dict):
        _diagnostic(
            diagnostics,
            "signature.invalid_block",
            "manifest:signature",
            "Manifest integrity block has no signature status.",
        )
        return "invalid", None
    signature = cast(dict[str, object], signature_raw)
    if signature.get("status") == "unsigned":
        if public_key_path is not None:
            _diagnostic(
                diagnostics,
                "signature.manifest_unsigned",
                "manifest:signature",
                "A verification key was supplied, but this manifest is explicitly unsigned.",
                severity="warning",
            )
        return "unsigned", None
    if (
        signature.get("status") != "signed"
        or signature.get("algorithm") != SIGNATURE_ALGORITHM
        or signature.get("profile") != SIGNATURE_PROFILE
    ):
        _diagnostic(
            diagnostics,
            "signature.unsupported",
            "manifest:signature",
            "Manifest signature status, algorithm, or profile is unsupported.",
            expected={"status": "signed", "algorithm": SIGNATURE_ALGORITHM,
                      "profile": SIGNATURE_PROFILE},
            actual={
                "status": signature.get("status"),
                "algorithm": signature.get("algorithm"),
                "profile": signature.get("profile"),
            },
        )
        return "unverifiable", None

    try:
        embedded = embedded_public_key(signature)
        embedded_metadata = public_key_metadata(embedded)
    except SigningKeyError as exc:
        _diagnostic(diagnostics, "signature.invalid_public_key", "manifest:signature", str(exc))
        return "invalid", None

    metadata = embedded_metadata.as_dict()
    metadata["source"] = "embedded"
    if isinstance(signature.get("key_id"), str):
        metadata["key_id_assertion"] = cast(str, signature["key_id"])
    if isinstance(signature.get("examiner"), str):
        metadata["examiner_assertion"] = cast(str, signature["examiner"])
    if signature.get("fingerprint") != embedded_metadata.fingerprint:
        _diagnostic(
            diagnostics,
            "signature.fingerprint_mismatch",
            "manifest:signature",
            "Embedded public-key bytes do not match the signed fingerprint metadata.",
            expected=signature.get("fingerprint"),
            actual=embedded_metadata.fingerprint,
        )
        return "invalid", metadata

    key = embedded
    if public_key_path is not None:
        try:
            key = load_public_key(public_key_path)
        except (OSError, SigningKeyError) as exc:
            _diagnostic(
                diagnostics,
                "signature.verification_key_unreadable",
                "verification-key",
                str(exc),
            )
            return "unverifiable", metadata
        supplied = public_key_metadata(key)
        metadata = supplied.as_dict()
        metadata["source"] = "provided"
        if isinstance(signature.get("key_id"), str):
            metadata["key_id_assertion"] = cast(str, signature["key_id"])
        if isinstance(signature.get("examiner"), str):
            metadata["examiner_assertion"] = cast(str, signature["examiner"])
        if supplied.fingerprint != embedded_metadata.fingerprint:
            _diagnostic(
                diagnostics,
                "signature.wrong_key",
                "verification-key",
                "Supplied public key does not match the key embedded in the signed manifest.",
                expected=embedded_metadata.fingerprint,
                actual=supplied.fingerprint,
            )
            return "invalid", metadata
    try:
        valid = verify_manifest_signature(manifest, signature, key)
    except SigningKeyError as exc:
        _diagnostic(diagnostics, "signature.invalid_value", "manifest:signature", str(exc))
        return "invalid", metadata
    if not valid:
        _diagnostic(
            diagnostics,
            "signature.invalid",
            "manifest:signature",
            "Ed25519 signature does not cover the current canonical manifest.",
        )
        return "invalid", metadata
    return "valid", metadata


def verify_case(
    manifest_path: Path,
    *,
    evidence_root: Path | None = None,
    public_key_path: Path | None = None,
    replay_inventory: ReplayInventory | Mapping[str, object] | None = None,
) -> CaseVerificationResult:
    """Verify a sealed case without MCP, an inference provider, or network I/O."""
    path = Path(manifest_path).expanduser().resolve(strict=False)
    diagnostics: list[VerificationDiagnostic] = []
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
    except FileNotFoundError:
        _diagnostic(
            diagnostics,
            "manifest.missing",
            "manifest",
            f"Case manifest is missing: {path}",
        )
        return CaseVerificationResult("invalid", str(path), None, 0, tuple(diagnostics))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        _diagnostic(
            diagnostics,
            "manifest.unreadable",
            "manifest",
            f"Cannot read case manifest {path}: {exc}",
        )
        return CaseVerificationResult("invalid", str(path), None, 0, tuple(diagnostics))
    if not isinstance(raw, dict):
        _diagnostic(
            diagnostics,
            "manifest.invalid_structure",
            "manifest",
            "Case manifest must be a JSON object.",
        )
        return CaseVerificationResult("invalid", str(path), None, 0, tuple(diagnostics))
    manifest = cast(dict[str, object], raw)
    replay = assess_replay(manifest, replay_inventory)
    case_raw = manifest.get("case")
    case_id = case_raw.get("case_id") if isinstance(case_raw, dict) else None
    case_id = case_id if isinstance(case_id, str) else None

    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("version") != MANIFEST_VERSION:
        _diagnostic(
            diagnostics,
            "manifest.unsupported_schema",
            "manifest",
            "Case manifest schema or version is unsupported.",
            expected={"schema": MANIFEST_SCHEMA, "version": MANIFEST_VERSION},
            actual={"schema": manifest.get("schema"), "version": manifest.get("version")},
        )
        return CaseVerificationResult(
            "unsupported_manifest", str(path), case_id, 0, tuple(diagnostics)
        )

    integrity = manifest.get("integrity")
    signature_status: SignatureStatus = "unknown"
    key_metadata: Mapping[str, str] | None = None
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        _diagnostic(
            diagnostics,
            "manifest.invalid_integrity",
            "manifest",
            "Manifest has no supported integrity block.",
        )
    else:
        try:
            observed_hash = _manifest_hash(manifest)
        except (TypeError, ValueError) as exc:
            _diagnostic(
                diagnostics,
                "manifest.noncanonical_content",
                "manifest",
                f"Manifest contains a value that cannot be canonically encoded: {exc}",
            )
        else:
            if integrity.get("manifest_hash") != observed_hash:
                _diagnostic(
                    diagnostics,
                    "manifest.content_mismatch",
                    "manifest",
                    "Manifest content does not match its embedded commitment.",
                    expected=integrity.get("manifest_hash"),
                    actual=observed_hash,
                )
        signature_status, key_metadata = _verify_signature(
            manifest, cast(dict[str, object], integrity), public_key_path, diagnostics
        )

    locations = manifest.get("locations")
    database = manifest.get("database")
    evidence = manifest.get("evidence_registry")
    audit = manifest.get("audit")
    if not all(isinstance(section, dict) for section in (locations, database, evidence, audit)):
        _diagnostic(
            diagnostics,
            "manifest.invalid_structure",
            "manifest",
            "Manifest is missing a locations, database, evidence_registry, or audit object.",
        )
        return CaseVerificationResult(
            "invalid",
            str(path),
            case_id,
            0,
            tuple(diagnostics),
            signature_status,
            key_metadata,
            replay,
        )

    checked = _verify_database(
        path.parent, cast(dict[str, object], database), case_id, diagnostics
    )
    audit_checked, legacy_audit = _verify_audit(
        path.parent, cast(dict[str, object], audit), diagnostics
    )
    checked += audit_checked
    evidence_checked, legacy_registry = _verify_evidence(
        path.parent,
        cast(dict[str, object], evidence),
        cast(dict[str, object], locations),
        evidence_root,
        diagnostics,
    )
    checked += evidence_checked
    checked += _verify_reports(path.parent, manifest.get("reports"), diagnostics)

    has_errors = any(diagnostic.severity == "error" for diagnostic in diagnostics)
    if has_errors:
        status: VerificationStatus = "invalid"
    elif legacy_audit or legacy_registry:
        status = "legacy_unverified"
    else:
        status = "verified"
    return CaseVerificationResult(
        status,
        str(path),
        case_id,
        checked,
        tuple(diagnostics),
        signature_status,
        key_metadata,
        replay,
    )


def format_verification_result(result: CaseVerificationResult) -> str:
    """Render a concise human-readable verification report."""
    label = result.status.upper().replace("_", " ")
    case = result.case_id or "unknown"
    trust = f" — signature {result.signature_status}"
    lines = [
        f"Case {case}: {label}{trust} ({result.artifacts_checked} artifacts checked)",
        f"Replay: {result.replay.status}",
    ]
    if result.public_key is not None:
        lines.append(
            "Verification key: "
            f"{result.public_key.get('fingerprint', 'unknown')} "
            f"({result.public_key.get('source', 'unknown')} source)"
        )
        examiner = result.public_key.get("examiner_assertion")
        if examiner is not None:
            lines.append(f"Examiner assertion: {examiner!r} (metadata only)")
    for reason in result.replay.reasons:
        lines.append(f"  {reason}")
    for diagnostic in result.diagnostics:
        lines.append(
            f"[{diagnostic.severity.upper()}] {diagnostic.code} "
            f"({diagnostic.subject}): {diagnostic.message}"
        )
        if diagnostic.expected is not None or diagnostic.actual is not None:
            lines.append(f"  expected: {diagnostic.expected!r}")
            lines.append(f"  actual:   {diagnostic.actual!r}")
    return "\n".join(lines)


def manifest_report_paths(manifest: Mapping[str, object]) -> Iterable[str]:
    """Expose report locators for future bundle/export integrations."""
    reports = manifest.get("reports")
    if not isinstance(reports, list):
        return ()
    return tuple(
        cast(str, report["path"])
        for report in reports
        if isinstance(report, dict) and isinstance(report.get("path"), str)
    )
