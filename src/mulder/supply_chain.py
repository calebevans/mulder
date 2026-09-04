"""Deterministic offline release SBOM and build-provenance documents."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

RELEASE_METADATA_SCHEMA: Literal["mulder.release-supply-chain"] = (
    "mulder.release-supply-chain"
)
RELEASE_METADATA_VERSION = 1
SBOM_SCHEMA: Literal["mulder.release-sbom"] = "mulder.release-sbom"
PROVENANCE_SCHEMA: Literal["mulder.build-provenance"] = "mulder.build-provenance"

_PACKAGE_START = re.compile(r"^\[\[package\]\]\s*$")
_NAME = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')
_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')
_SOURCE = re.compile(r"^source\s*=\s*\{\s*([^}]*)\}\s*$")
_HASH = re.compile(r'hash\s*=\s*"(sha256:[0-9a-f]{64})"')


class SupplyChainError(ValueError):
    """Raised when release metadata cannot be generated safely."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReleaseArtifact(_FrozenModel):
    path: str
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)


class SBOMComponent(_FrozenModel):
    name: str
    version: str
    source: str
    sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


class ReleaseSBOM(_FrozenModel):
    schema_name: Literal["mulder.release-sbom"] = Field(alias="schema")
    version: Literal[1] = 1
    format: Literal["CycloneDX-compatible"] = "CycloneDX-compatible"
    project_name: str
    project_version: str
    created_at: str
    components: tuple[SBOMComponent, ...]
    artifacts: tuple[ReleaseArtifact, ...]


class BuildProvenance(_FrozenModel):
    schema_name: Literal["mulder.build-provenance"] = Field(alias="schema")
    version: Literal[1] = 1
    predicate_type: Literal["https://slsa.dev/provenance/v1"] = (
        "https://slsa.dev/provenance/v1"
    )
    builder_id: str
    source_revision: str
    source_date_epoch: int = Field(ge=0)
    build_started_on: str
    dependency_lock: ReleaseArtifact
    subjects: tuple[ReleaseArtifact, ...]
    sbom_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    invocation: dict[str, str]


class ReleaseSupplyChainDocument(_FrozenModel):
    schema_name: Literal["mulder.release-supply-chain"] = Field(alias="schema")
    version: Literal[1] = 1
    sbom: ReleaseSBOM
    provenance: BuildProvenance
    document_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _matching_subjects(self) -> ReleaseSupplyChainDocument:
        if self.sbom.artifacts != self.provenance.subjects:
            raise ValueError("SBOM artifacts and provenance subjects differ")
        return self


class ReleaseMetadataRequest(_FrozenModel):
    project_root: Path
    artifact_paths: tuple[Path, ...] = Field(min_length=1)
    output_path: Path
    project_name: str = Field(min_length=1)
    project_version: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    source_date_epoch: int = Field(ge=0)
    builder_id: str = Field(min_length=1)
    invocation: dict[str, str] = Field(default_factory=dict)
    dependency_lock_path: Path = Path("uv.lock")


class ReleaseMetadataVerification(_FrozenModel):
    status: Literal["verified", "invalid"]
    document_digest: str | None
    artifacts_checked: int
    diagnostics: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.status == "verified"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _safe_file(path: Path, root: Path) -> Path:
    root_absolute = root.expanduser().absolute()
    if root_absolute.is_symlink():
        raise SupplyChainError(f"release root is a symlink: {root}")
    try:
        root_resolved = root_absolute.resolve(strict=True)
        candidate_absolute = path.expanduser()
        if not candidate_absolute.is_absolute():
            candidate_absolute = root_resolved / candidate_absolute
        if candidate_absolute.is_symlink():
            raise SupplyChainError(f"release input is a symlink: {path}")
        candidate = candidate_absolute.resolve(strict=True)
        candidate.relative_to(root_resolved)
    except SupplyChainError:
        raise
    except ValueError as exc:
        raise SupplyChainError(f"release input escapes project root: {path}") from exc
    except (OSError, RuntimeError) as exc:
        raise SupplyChainError(f"cannot resolve release input {path}: {exc}") from exc
    if not candidate.is_file():
        raise SupplyChainError(f"release input is not a regular file: {path}")
    current = root_resolved
    for part in candidate.relative_to(root_resolved).parts:
        current = current / part
        if current.is_symlink():
            raise SupplyChainError(f"release input crosses a symlink: {current}")
    return candidate


def _commit_file(path: Path, root: Path) -> ReleaseArtifact:
    resolved_root = root.resolve(strict=True)
    resolved = _safe_file(path, resolved_root)
    digest = hashlib.sha256()
    size = 0
    before = resolved.stat()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise SupplyChainError(f"release input is not regular: {path}")
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    after = resolved.stat()
    fingerprints = {
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
    }
    if size != after.st_size or len(fingerprints) != 1:
        raise SupplyChainError(f"release input changed while hashing: {path}")
    return ReleaseArtifact(
        path=resolved.relative_to(resolved_root).as_posix(),
        sha256="sha256:" + digest.hexdigest(),
        size_bytes=size,
    )


def _source_label(raw: str) -> str:
    for key in ("registry", "git", "url", "path", "editable"):
        match = re.search(rf'{key}\s*=\s*"([^"]+)"', raw)
        if match:
            return f"{key}:{match.group(1)}"
    return raw.strip() or "unknown"


def _components_from_uv_lock(path: Path) -> tuple[SBOMComponent, ...]:
    """Read the checked-in uv lock without invoking a package manager."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise SupplyChainError(f"cannot read dependency lock {path}: {exc}") from exc

    records: list[dict[str, str | None]] = []
    current: dict[str, str | None] | None = None
    for line in lines:
        if _PACKAGE_START.match(line):
            if current is not None:
                records.append(current)
            current = {"name": None, "version": None, "source": None, "sha256": None}
            continue
        if current is None:
            continue
        if (match := _NAME.match(line)) and current["name"] is None:
            current["name"] = match.group(1)
        elif (match := _VERSION.match(line)) and current["version"] is None:
            current["version"] = match.group(1)
        elif (match := _SOURCE.match(line)) and current["source"] is None:
            current["source"] = _source_label(match.group(1))
        elif (match := _HASH.search(line)) and current["sha256"] is None:
            current["sha256"] = match.group(1)
    if current is not None:
        records.append(current)

    components: dict[tuple[str, str, str], SBOMComponent] = {}
    for record in records:
        name = record["name"]
        version = record["version"]
        source = record["source"]
        # uv may omit the version for the editable workspace root.  The
        # released project is already represented by SBOM project metadata.
        if (
            name is not None
            and version is None
            and source is not None
            and source.startswith("editable:")
        ):
            continue
        if name is None or version is None or source is None:
            raise SupplyChainError("uv.lock contains an incomplete package record")
        component = SBOMComponent(
            name=name,
            version=version,
            source=source,
            sha256=record["sha256"],
        )
        components[(name, version, source)] = component
    if not components:
        raise SupplyChainError("uv.lock contains no package records")
    return tuple(components[key] for key in sorted(components))


def _document_payload(
    sbom: ReleaseSBOM,
    provenance: BuildProvenance,
) -> dict[str, object]:
    return {
        "schema": RELEASE_METADATA_SCHEMA,
        "version": RELEASE_METADATA_VERSION,
        "sbom": sbom.model_dump(mode="json", by_alias=True),
        "provenance": provenance.model_dump(mode="json", by_alias=True),
    }


def generate_release_metadata(request: ReleaseMetadataRequest) -> ReleaseSupplyChainDocument:
    """Generate and atomically write deterministic release supply-chain metadata."""
    try:
        root = request.project_root.expanduser().absolute().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SupplyChainError(f"cannot resolve project root: {exc}") from exc
    if not root.is_dir() or request.project_root.expanduser().absolute().is_symlink():
        raise SupplyChainError("project root must be a non-symlink directory")

    lock = _commit_file(request.dependency_lock_path, root)
    lock_path = root / lock.path
    artifacts_by_path = {
        item.path: item
        for item in (_commit_file(path, root) for path in request.artifact_paths)
    }
    if len(artifacts_by_path) != len(request.artifact_paths):
        raise SupplyChainError("release artifact paths must be unique")
    artifacts = tuple(artifacts_by_path[path] for path in sorted(artifacts_by_path))
    components = _components_from_uv_lock(lock_path)
    created_at = datetime.fromtimestamp(request.source_date_epoch, timezone.utc).isoformat()
    sbom = ReleaseSBOM(
        schema=SBOM_SCHEMA,
        project_name=request.project_name,
        project_version=request.project_version,
        created_at=created_at,
        components=components,
        artifacts=artifacts,
    )
    sbom_digest = _sha256_bytes(
        b"mulder.release-sbom:v1\0" + _canonical_json(sbom.model_dump(mode="json", by_alias=True))
    )
    provenance = BuildProvenance(
        schema=PROVENANCE_SCHEMA,
        builder_id=request.builder_id,
        source_revision=request.source_revision,
        source_date_epoch=request.source_date_epoch,
        build_started_on=created_at,
        dependency_lock=lock,
        subjects=artifacts,
        sbom_digest=sbom_digest,
        invocation=dict(sorted(request.invocation.items())),
    )
    payload = _document_payload(sbom, provenance)
    document = ReleaseSupplyChainDocument.model_validate(
        {
            **payload,
            "document_digest": _sha256_bytes(
                b"mulder.release-supply-chain:v1\0" + _canonical_json(payload)
            ),
        }
    )
    encoded = json.dumps(
        document.model_dump(mode="json", by_alias=True),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"
    output = request.output_path.expanduser().absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return document


def _load_document(path: Path) -> ReleaseSupplyChainDocument:
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        return ReleaseSupplyChainDocument.model_validate(raw)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupplyChainError(f"invalid release metadata: {exc}") from exc


def verify_release_metadata(
    metadata_path: Path,
    release_root: Path,
) -> ReleaseMetadataVerification:
    """Verify metadata structure and every bound local artifact entirely offline."""
    diagnostics: list[str] = []
    try:
        document = _load_document(metadata_path)
    except SupplyChainError as exc:
        return ReleaseMetadataVerification(
            status="invalid",
            document_digest=None,
            artifacts_checked=0,
            diagnostics=(str(exc),),
        )

    payload = _document_payload(document.sbom, document.provenance)
    expected_document = _sha256_bytes(
        b"mulder.release-supply-chain:v1\0" + _canonical_json(payload)
    )
    if expected_document != document.document_digest:
        diagnostics.append("document digest does not match canonical metadata")
    expected_sbom = _sha256_bytes(
        b"mulder.release-sbom:v1\0"
        + _canonical_json(document.sbom.model_dump(mode="json", by_alias=True))
    )
    if expected_sbom != document.provenance.sbom_digest:
        diagnostics.append("provenance SBOM digest does not match the embedded SBOM")

    commitments = (document.provenance.dependency_lock, *document.sbom.artifacts)
    checked = 0
    for expected in commitments:
        try:
            actual = _commit_file(Path(expected.path), release_root)
        except SupplyChainError as exc:
            diagnostics.append(str(exc))
            continue
        checked += 1
        if actual != expected:
            diagnostics.append(f"artifact drift: {expected.path}")
    return ReleaseMetadataVerification(
        status="invalid" if diagnostics else "verified",
        document_digest=document.document_digest,
        artifacts_checked=checked,
        diagnostics=tuple(diagnostics),
    )


__all__ = [
    "PROVENANCE_SCHEMA",
    "RELEASE_METADATA_SCHEMA",
    "RELEASE_METADATA_VERSION",
    "SBOM_SCHEMA",
    "BuildProvenance",
    "ReleaseArtifact",
    "ReleaseMetadataRequest",
    "ReleaseMetadataVerification",
    "ReleaseSBOM",
    "ReleaseSupplyChainDocument",
    "SBOMComponent",
    "SupplyChainError",
    "generate_release_metadata",
    "verify_release_metadata",
]
