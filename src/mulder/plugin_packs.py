"""Opt-in declarative plugin-pack discovery and activation.

Discovery reads only examiner-selected roots or manifest files.  It validates
the complete pack tree, capability ceiling, component compatibility, and
content digests before returning an activatable record.  Version 1 packs are
deliberately data-only: Python imports, entry points, executable resources,
and dynamic tool registration are outside this interface.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy import (
    Column,
    Connection,
    ForeignKey,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
    select,
)

PLUGIN_MANIFEST_SCHEMA = "mulder.plugin-pack"
PLUGIN_MANIFEST_VERSION = 1
PLUGIN_CATALOG_SCHEMA = "mulder.plugin-catalog"
PLUGIN_CATALOG_VERSION = 1
PLUGIN_ACTIVATION_SCHEMA_VERSION: Literal["1"] = "1"
PLUGIN_MANIFEST_NAME = "mulder-plugin.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_PACK_BYTES = 256 * 1024 * 1024

Sha256 = str
ComponentKind = Literal["tool", "parser", "binary"]
NetworkCapability = Literal["none", "loopback", "outbound"]
PathScope = Literal[
    "pack_read",
    "evidence_read",
    "case_workspace_read",
    "case_workspace_write",
]
WriteScope = Literal["case_database", "case_workspace"]
PackStatus = Literal["READY", "UNSUPPORTED_VERSION"]
CompatibilityStatus = Literal[
    "COMPATIBLE", "MISSING", "UNSUPPORTED_VERSION", "DIGEST_DRIFT"
]

_NETWORK_LEVEL: dict[NetworkCapability, int] = {"none": 0, "loopback": 1, "outbound": 2}
_FORBIDDEN_CODE_SUFFIXES = frozenset(
    {".py", ".pyc", ".pyo", ".so", ".dll", ".dylib", ".wasm", ".exe", ".sh"}
)
_FORBIDDEN_FILENAMES = frozenset(
    {"entry_points.txt", "pyproject.toml", "setup.py", "setup.cfg", "package.json"}
)


class PluginPackError(ValueError):
    """Structured discovery/activation failure suitable for CLI reporting."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


class UnsupportedPluginVersion(PluginPackError):
    """Loud compatibility failure using the universal outcome vocabulary."""

    status: Literal["UNSUPPORTED_VERSION"] = "UNSUPPORTED_VERSION"

    def __init__(self, message: str) -> None:
        super().__init__(self.status, message)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PluginIdentity(_FrozenModel):
    plugin_id: str = Field(pattern=r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100, pattern=r"^[^\s/\\]+$")
    license: str = Field(min_length=1, max_length=200)


class CapabilityDeclaration(_FrozenModel):
    """Symbolic effect request; it cannot carry caller-selected raw paths."""

    tools: tuple[str, ...] = Field(default=(), max_length=256)
    path_scopes: tuple[PathScope, ...] = ()
    write_scopes: tuple[WriteScope, ...] = ()
    network: NetworkCapability = "none"

    @field_validator("tools")
    @classmethod
    def _validate_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("capability tool names must be unique")
        for name in value:
            if not name or not all(char.isalnum() or char in "_-" for char in name):
                raise ValueError(f"invalid declarative tool name: {name!r}")
        return value

    @model_validator(mode="after")
    def _validate_scopes(self) -> CapabilityDeclaration:
        if len(self.path_scopes) != len(set(self.path_scopes)):
            raise ValueError("path scopes must be unique")
        if len(self.write_scopes) != len(set(self.write_scopes)):
            raise ValueError("write scopes must be unique")
        if (
            "case_workspace_write" in self.path_scopes
            and "case_workspace" not in self.write_scopes
        ):
            raise ValueError("case_workspace_write requires the case_workspace write scope")
        return self


class CapabilityApproval(_FrozenModel):
    """Examiner-provided ceiling applied before a pack can activate."""

    tools: tuple[str, ...] = ()
    path_scopes: tuple[PathScope, ...] = ()
    write_scopes: tuple[WriteScope, ...] = ()
    max_network: NetworkCapability = "none"


class ComponentRequirement(_FrozenModel):
    kind: ComponentKind
    name: str = Field(min_length=1, max_length=200)
    supported_versions: tuple[str, ...] = Field(min_length=1, max_length=128)
    supported_digests: tuple[str, ...] = Field(min_length=1, max_length=128)

    @field_validator("supported_versions")
    @classmethod
    def _unique_versions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not item for item in value):
            raise ValueError("supported versions must be unique non-empty strings")
        return value

    @field_validator("supported_digests")
    @classmethod
    def _valid_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("supported digests must be unique")
        normalized = tuple(_require_sha256(digest) for digest in value)
        if len(normalized) != len(set(normalized)):
            raise ValueError("supported digests must be unique after normalization")
        return normalized


class InstalledComponent(_FrozenModel):
    kind: ComponentKind
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    digest: str

    @field_validator("digest")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        return _require_sha256(value)


class ComponentInventory(_FrozenModel):
    components: tuple[InstalledComponent, ...] = Field(default=(), max_length=1024)

    @model_validator(mode="after")
    def _unique_components(self) -> ComponentInventory:
        keys = [(item.kind, item.name) for item in self.components]
        if len(keys) != len(set(keys)):
            raise ValueError("component inventory contains duplicate kind/name entries")
        return self


class PackResource(_FrozenModel):
    path: str = Field(min_length=1, max_length=500)
    sha256: str
    media_type: str = Field(default="application/octet-stream", min_length=1, max_length=200)

    @field_validator("path")
    @classmethod
    def _safe_relative_path(cls, value: str) -> str:
        if "\\" in value:
            raise ValueError("resource paths must use POSIX separators")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "." in path.parts:
            raise ValueError("resource path must stay inside the pack")
        return path.as_posix()

    @field_validator("sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        return _require_sha256(value)


class PluginPackManifest(_FrozenModel):
    schema_name: Literal["mulder.plugin-pack"] = Field(alias="schema")
    schema_version: Literal[1] = Field(alias="version")
    plugin: PluginIdentity
    description: str = Field(default="", max_length=4000)
    capabilities: CapabilityDeclaration = CapabilityDeclaration()
    compatibility: tuple[ComponentRequirement, ...] = Field(default=(), max_length=512)
    resources: tuple[PackResource, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def _validate_declarations(self) -> PluginPackManifest:
        resource_paths = [resource.path for resource in self.resources]
        if len(resource_paths) != len(set(resource_paths)):
            raise ValueError("resource paths must be unique")
        requirement_keys = [(item.kind, item.name) for item in self.compatibility]
        if len(requirement_keys) != len(set(requirement_keys)):
            raise ValueError("compatibility kind/name entries must be unique")
        declared_tools = {
            item.name for item in self.compatibility if item.kind == "tool"
        }
        missing = sorted(set(self.capabilities.tools) - declared_tools)
        if missing:
            raise ValueError(
                "every tool capability requires a version/digest compatibility row: "
                + ", ".join(missing)
            )
        return self


class ResolvedResource(_FrozenModel):
    path: str
    sha256: str
    size_bytes: int = Field(ge=0)
    media_type: str


class CompatibilityCheck(_FrozenModel):
    requirement: ComponentRequirement
    observed: InstalledComponent | None
    status: CompatibilityStatus
    reason: str


class DiscoveredPluginPack(_FrozenModel):
    manifest: PluginPackManifest
    approved_root: str
    manifest_path: str
    manifest_digest: str
    plugin_digest: str
    resources: tuple[ResolvedResource, ...]
    compatibility: tuple[CompatibilityCheck, ...]
    status: PackStatus


class PluginCatalog(_FrozenModel):
    schema_name: Literal["mulder.plugin-catalog"] = Field(
        default="mulder.plugin-catalog", alias="schema"
    )
    schema_version: Literal[1] = Field(default=1, alias="version")
    packs: tuple[DiscoveredPluginPack, ...]


class PluginDiscoveryRequest(_FrozenModel):
    """Only paths explicitly placed here are eligible for discovery."""

    approved_roots: tuple[Path, ...] = ()
    approved_manifests: tuple[Path, ...] = ()
    capability_approval: CapabilityApproval = CapabilityApproval()
    inventory: ComponentInventory = ComponentInventory()


class PluginActivationRequest(_FrozenModel):
    discovery: PluginDiscoveryRequest
    plugin_ids: tuple[str, ...] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def _unique_plugin_ids(self) -> PluginActivationRequest:
        if len(self.plugin_ids) != len(set(self.plugin_ids)):
            raise ValueError("selected plugin IDs must be unique")
        return self


class PluginActivation(_FrozenModel):
    activation_id: str
    schema_version: Literal["1"] = PLUGIN_ACTIVATION_SCHEMA_VERSION
    case_id: str
    plugin: PluginIdentity
    manifest_digest: str
    plugin_digest: str
    capabilities: CapabilityDeclaration
    components: tuple[InstalledComponent, ...]
    manifest_path: str
    activated_at: str


@dataclass(frozen=True)
class _PluginTables:
    activations: Table


def _define_plugin_tables(metadata: MetaData) -> _PluginTables:
    activations = Table(
        "plugin_activations",
        metadata,
        Column("activation_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column("plugin_id", Text, nullable=False),
        Column("plugin_name", Text, nullable=False),
        Column("plugin_version", Text, nullable=False),
        Column("plugin_license", Text, nullable=False),
        Column("manifest_digest", Text, nullable=False),
        Column("plugin_digest", Text, nullable=False),
        Column("capabilities", Text, nullable=False),
        Column("components", Text, nullable=False),
        Column("manifest_path", Text, nullable=False),
        Column("activated_at", Text, nullable=False),
        UniqueConstraint("case_id", "plugin_id", name="uq_case_plugin_activation"),
    )
    return _PluginTables(activations=activations)


def _require_sha256(value: str) -> str:
    lowered = value.lower()
    if not lowered.startswith("sha256:"):
        raise ValueError("digest must use the sha256: prefix")
    encoded = lowered[7:]
    if len(encoded) != 64 or any(char not in "0123456789abcdef" for char in encoded):
        raise ValueError("digest must contain exactly 64 lowercase hexadecimal characters")
    return lowered


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


def _load_json(path: Path) -> tuple[dict[str, object], bytes]:
    try:
        size = path.stat().st_size
        if size > MAX_MANIFEST_BYTES:
            raise PluginPackError(
                "MANIFEST_TOO_LARGE", f"{path} exceeds {MAX_MANIFEST_BYTES} bytes"
            )
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except PluginPackError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PluginPackError("INVALID_MANIFEST", f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PluginPackError("INVALID_MANIFEST", f"{path} must contain one JSON object")
    return cast(dict[str, object], value), raw


def _hash_regular_file(path: Path) -> tuple[str, int]:
    if path.is_symlink():
        raise PluginPackError("SYMLINK_DENIED", f"pack path is a symlink: {path}")
    digest = hashlib.sha256()
    size = 0
    try:
        before = path.stat()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise PluginPackError("NON_REGULAR_FILE", f"pack path is not regular: {path}")
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        after = path.stat()
    except PluginPackError:
        raise
    except OSError as exc:
        raise PluginPackError("PACK_READ_FAILED", f"cannot read {path}: {exc}") from exc
    fingerprints = {
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
    }
    if len(fingerprints) != 1 or size != after.st_size:
        raise PluginPackError("PACK_CHANGED", f"pack file changed while hashing: {path}")
    return "sha256:" + digest.hexdigest(), size


def _validate_directory(root: Path) -> Path:
    expanded = root.expanduser().absolute()
    if expanded.is_symlink():
        raise PluginPackError("SYMLINK_DENIED", f"approved root is a symlink: {root}")
    try:
        resolved = expanded.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PluginPackError(
            "ROOT_UNAVAILABLE", f"cannot resolve approved root {root}: {exc}"
        ) from exc
    if not resolved.is_dir():
        raise PluginPackError("ROOT_NOT_DIRECTORY", f"approved root is not a directory: {root}")
    return resolved


def _validate_manifest_path(path: Path, approved_root: Path) -> Path:
    expanded = path.expanduser().absolute()
    if expanded.is_symlink():
        raise PluginPackError("SYMLINK_DENIED", f"manifest is a symlink: {path}")
    try:
        resolved = expanded.resolve(strict=True)
        resolved.relative_to(approved_root)
    except ValueError as exc:
        raise PluginPackError("PATH_ESCAPE", f"manifest escapes approved root: {path}") from exc
    except (OSError, RuntimeError) as exc:
        raise PluginPackError(
            "MANIFEST_UNAVAILABLE", f"cannot resolve manifest {path}: {exc}"
        ) from exc
    if not resolved.is_file():
        raise PluginPackError("MANIFEST_NOT_FILE", f"manifest is not a regular file: {path}")
    current = approved_root
    for part in resolved.relative_to(approved_root).parts:
        current = current / part
        if current.is_symlink():
            raise PluginPackError("SYMLINK_DENIED", f"manifest path crosses a symlink: {current}")
    return resolved


def _manifest_candidates(request: PluginDiscoveryRequest) -> tuple[tuple[Path, Path], ...]:
    roots = tuple(_validate_directory(root) for root in request.approved_roots)
    candidates: list[tuple[Path, Path]] = []
    for root in roots:
        direct = root / PLUGIN_MANIFEST_NAME
        if direct.exists() or direct.is_symlink():
            candidates.append((root, _validate_manifest_path(direct, root)))
        for child in sorted(root.iterdir(), key=lambda item: item.name):
            if child.is_symlink():
                raise PluginPackError(
                    "SYMLINK_DENIED", f"approved root contains a symlink: {child}"
                )
            nested = child / PLUGIN_MANIFEST_NAME
            if child.is_dir() and (nested.exists() or nested.is_symlink()):
                candidates.append((root, _validate_manifest_path(nested, root)))

    for raw_manifest in request.approved_manifests:
        parent = _validate_directory(raw_manifest.expanduser().absolute().parent)
        candidates.append((parent, _validate_manifest_path(raw_manifest, parent)))

    by_path: dict[Path, tuple[Path, Path]] = {}
    for root, manifest in candidates:
        by_path.setdefault(manifest, (root, manifest))
    return tuple(by_path[path] for path in sorted(by_path, key=lambda item: item.as_posix()))


def _validate_capabilities(
    declaration: CapabilityDeclaration,
    approval: CapabilityApproval,
    plugin_id: str,
) -> None:
    excess_tools = sorted(set(declaration.tools) - set(approval.tools))
    excess_paths = sorted(set(declaration.path_scopes) - set(approval.path_scopes))
    excess_writes = sorted(set(declaration.write_scopes) - set(approval.write_scopes))
    if excess_tools or excess_paths or excess_writes or (
        _NETWORK_LEVEL[declaration.network] > _NETWORK_LEVEL[approval.max_network]
    ):
        details: list[str] = []
        if excess_tools:
            details.append(f"tools={excess_tools}")
        if excess_paths:
            details.append(f"path_scopes={excess_paths}")
        if excess_writes:
            details.append(f"write_scopes={excess_writes}")
        if _NETWORK_LEVEL[declaration.network] > _NETWORK_LEVEL[approval.max_network]:
            details.append(f"network={declaration.network!r}>{approval.max_network!r}")
        raise PluginPackError(
            "CAPABILITY_ESCALATION",
            f"plugin {plugin_id!r} exceeds examiner approval: " + "; ".join(details),
        )


def _inventory_map(inventory: ComponentInventory) -> dict[tuple[str, str], InstalledComponent]:
    return {(component.kind, component.name): component for component in inventory.components}


def _compatibility_checks(
    requirements: tuple[ComponentRequirement, ...],
    inventory: ComponentInventory,
) -> tuple[CompatibilityCheck, ...]:
    installed = _inventory_map(inventory)
    checks: list[CompatibilityCheck] = []
    for requirement in sorted(requirements, key=lambda item: (item.kind, item.name)):
        observed = installed.get((requirement.kind, requirement.name))
        if observed is None:
            status: CompatibilityStatus = "MISSING"
            reason = "required component is absent from the examiner-provided inventory"
        elif observed.version not in requirement.supported_versions:
            status = "UNSUPPORTED_VERSION"
            reason = (
                f"observed version {observed.version!r} is not one of "
                f"{sorted(requirement.supported_versions)!r}"
            )
        elif observed.digest not in requirement.supported_digests:
            status = "DIGEST_DRIFT"
            reason = "observed component digest is not approved by the pack manifest"
        else:
            status = "COMPATIBLE"
            reason = "version and digest are approved"
        checks.append(
            CompatibilityCheck(
                requirement=requirement,
                observed=observed,
                status=status,
                reason=reason,
            )
        )
    return tuple(checks)


def _pack_files(pack_root: Path, manifest_path: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    for path in sorted(pack_root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise PluginPackError("SYMLINK_DENIED", f"pack contains a symlink: {path}")
        if path.is_dir():
            continue
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(pack_root)
        except ValueError as exc:
            raise PluginPackError("PATH_ESCAPE", f"pack file escapes its root: {path}") from exc
        if resolved != manifest_path:
            files.append(resolved)
    return tuple(files)


def _resolved_resources(
    manifest: PluginPackManifest,
    pack_root: Path,
    manifest_path: Path,
) -> tuple[ResolvedResource, ...]:
    files = _pack_files(pack_root, manifest_path)
    declared = {resource.path: resource for resource in manifest.resources}
    actual = {path.relative_to(pack_root).as_posix(): path for path in files}
    undeclared = sorted(set(actual) - set(declared))
    missing = sorted(set(declared) - set(actual))
    if undeclared:
        raise PluginPackError(
            "UNDECLARED_FILE",
            "pack contains files absent from resources: " + ", ".join(undeclared),
        )
    if missing:
        raise PluginPackError(
            "MISSING_RESOURCE", "declared pack resources are absent: " + ", ".join(missing)
        )
    resolved: list[ResolvedResource] = []
    total_size = 0
    for relative in sorted(declared):
        resource = declared[relative]
        path = actual[relative]
        lowered = path.name.lower()
        if path.suffix.lower() in _FORBIDDEN_CODE_SUFFIXES or lowered in _FORBIDDEN_FILENAMES:
            raise PluginPackError(
                "EXECUTABLE_RESOURCE_DENIED",
                f"declarative pack cannot contain executable/import metadata: {relative}",
            )
        if path.stat().st_mode & 0o111:
            raise PluginPackError(
                "EXECUTABLE_RESOURCE_DENIED",
                f"declarative pack resource has executable permission bits: {relative}",
            )
        digest, size = _hash_regular_file(path)
        if size > MAX_RESOURCE_BYTES:
            raise PluginPackError(
                "RESOURCE_TOO_LARGE", f"resource {relative} exceeds {MAX_RESOURCE_BYTES} bytes"
            )
        total_size += size
        if total_size > MAX_PACK_BYTES:
            raise PluginPackError("PACK_TOO_LARGE", f"pack exceeds {MAX_PACK_BYTES} bytes")
        if digest != resource.sha256:
            raise PluginPackError(
                "DIGEST_DRIFT",
                f"resource {relative} expected {resource.sha256}, observed {digest}",
            )
        resolved.append(
            ResolvedResource(
                path=relative,
                sha256=digest,
                size_bytes=size,
                media_type=resource.media_type,
            )
        )
    return tuple(resolved)


def _discover_one(
    approved_root: Path,
    manifest_path: Path,
    approval: CapabilityApproval,
    inventory: ComponentInventory,
) -> DiscoveredPluginPack:
    raw, manifest_bytes = _load_json(manifest_path)
    try:
        manifest = PluginPackManifest.model_validate(raw)
    except ValidationError as exc:
        raise PluginPackError("INVALID_MANIFEST", f"{manifest_path}: {exc}") from exc
    _validate_capabilities(manifest.capabilities, approval, manifest.plugin.plugin_id)
    resources = _resolved_resources(manifest, manifest_path.parent, manifest_path)
    checks = _compatibility_checks(manifest.compatibility, inventory)
    manifest_digest = _sha256_bytes(manifest_bytes)
    plugin_digest = _sha256_bytes(
        b"mulder.plugin-pack:v1\0"
        + _canonical_json(
            {
                "manifest_digest": manifest_digest,
                "resources": [resource.model_dump(mode="json") for resource in resources],
            }
        )
    )
    return DiscoveredPluginPack(
        manifest=manifest,
        approved_root=str(approved_root),
        manifest_path=manifest_path.relative_to(approved_root).as_posix(),
        manifest_digest=manifest_digest,
        plugin_digest=plugin_digest,
        resources=resources,
        compatibility=checks,
        status=(
            "READY"
            if all(check.status == "COMPATIBLE" for check in checks)
            else "UNSUPPORTED_VERSION"
        ),
    )


def discover_plugin_packs(request: PluginDiscoveryRequest) -> PluginCatalog:
    """Discover and fully validate only examiner-approved declarative packs."""
    packs = tuple(
        _discover_one(
            approved_root,
            manifest_path,
            request.capability_approval,
            request.inventory,
        )
        for approved_root, manifest_path in _manifest_candidates(request)
    )
    ids: dict[str, list[str]] = {}
    for pack in packs:
        ids.setdefault(pack.manifest.plugin.plugin_id, []).append(pack.manifest_path)
    duplicates = {plugin_id: paths for plugin_id, paths in ids.items() if len(paths) > 1}
    if duplicates:
        detail = "; ".join(
            f"{plugin_id}: {sorted(paths)}" for plugin_id, paths in sorted(duplicates.items())
        )
        raise PluginPackError("DUPLICATE_PLUGIN_ID", detail)
    return PluginCatalog(
        packs=tuple(sorted(packs, key=lambda pack: pack.manifest.plugin.plugin_id))
    )


def _select_activations(request: PluginActivationRequest) -> tuple[DiscoveredPluginPack, ...]:
    catalog = discover_plugin_packs(request.discovery)
    by_id = {pack.manifest.plugin.plugin_id: pack for pack in catalog.packs}
    missing = sorted(set(request.plugin_ids) - set(by_id))
    if missing:
        raise PluginPackError("PLUGIN_NOT_FOUND", ", ".join(missing))
    selected = tuple(by_id[plugin_id] for plugin_id in sorted(request.plugin_ids))
    incompatible = [pack for pack in selected if pack.status != "READY"]
    if incompatible:
        reasons = []
        for pack in incompatible:
            failures = [
                f"{check.requirement.kind}:{check.requirement.name}={check.status}"
                for check in pack.compatibility
                if check.status != "COMPATIBLE"
            ]
            reasons.append(f"{pack.manifest.plugin.plugin_id} ({', '.join(failures)})")
        raise UnsupportedPluginVersion("; ".join(reasons))
    return selected


def _activation_from_row(row: Any) -> PluginActivation:
    return PluginActivation(
        activation_id=row.activation_id,
        case_id=row.case_id,
        plugin=PluginIdentity(
            plugin_id=row.plugin_id,
            name=row.plugin_name,
            version=row.plugin_version,
            license=row.plugin_license,
        ),
        manifest_digest=row.manifest_digest,
        plugin_digest=row.plugin_digest,
        capabilities=CapabilityDeclaration.model_validate_json(row.capabilities),
        components=tuple(
            InstalledComponent.model_validate(item) for item in json.loads(row.components)
        ),
        manifest_path=row.manifest_path,
        activated_at=row.activated_at,
    )


def _persist_activations(
    conn: Connection,
    case_id: str,
    request: PluginActivationRequest,
) -> tuple[PluginActivation, ...]:
    from mulder.db import plugin_activations_t

    selected = _select_activations(request)
    results: list[PluginActivation] = []
    for pack in selected:
        plugin = pack.manifest.plugin
        prior = conn.execute(
            select(plugin_activations_t).where(
                (plugin_activations_t.c.case_id == case_id)
                & (plugin_activations_t.c.plugin_id == plugin.plugin_id)
            )
        ).fetchone()
        if prior is not None:
            existing = _activation_from_row(prior)
            if (
                existing.plugin.version != plugin.version
                or existing.plugin_digest != pack.plugin_digest
                or existing.manifest_digest != pack.manifest_digest
            ):
                raise PluginPackError(
                    "ACTIVATION_DRIFT",
                    f"plugin {plugin.plugin_id!r} is already activated with different metadata",
                )
            results.append(existing)
            continue
        components = tuple(
            check.observed
            for check in pack.compatibility
            if check.observed is not None
        )
        activation = PluginActivation(
            activation_id=f"pa_{uuid4().hex[:16]}",
            case_id=case_id,
            plugin=plugin,
            manifest_digest=pack.manifest_digest,
            plugin_digest=pack.plugin_digest,
            capabilities=pack.manifest.capabilities,
            components=components,
            manifest_path=pack.manifest_path,
            activated_at=datetime.now(timezone.utc).isoformat(),
        )
        conn.execute(
            plugin_activations_t.insert().values(
                activation_id=activation.activation_id,
                case_id=case_id,
                plugin_id=plugin.plugin_id,
                plugin_name=plugin.name,
                plugin_version=plugin.version,
                plugin_license=plugin.license,
                manifest_digest=activation.manifest_digest,
                plugin_digest=activation.plugin_digest,
                capabilities=activation.capabilities.model_dump_json(),
                components=json.dumps(
                    [item.model_dump(mode="json") for item in activation.components],
                    sort_keys=True,
                ),
                manifest_path=activation.manifest_path,
                activated_at=activation.activated_at,
            )
        )
        results.append(activation)
    return tuple(results)


def _read_activations(conn: Connection, case_id: str) -> tuple[PluginActivation, ...]:
    from mulder.db import plugin_activations_t

    if not conn.dialect.has_table(conn, "plugin_activations"):
        return ()
    rows = conn.execute(
        select(plugin_activations_t)
        .where(plugin_activations_t.c.case_id == case_id)
        .order_by(plugin_activations_t.c.plugin_id)
    ).fetchall()
    return tuple(_activation_from_row(row) for row in rows)


__all__ = [
    "MAX_MANIFEST_BYTES",
    "MAX_PACK_BYTES",
    "MAX_RESOURCE_BYTES",
    "PLUGIN_ACTIVATION_SCHEMA_VERSION",
    "PLUGIN_CATALOG_SCHEMA",
    "PLUGIN_CATALOG_VERSION",
    "PLUGIN_MANIFEST_NAME",
    "PLUGIN_MANIFEST_SCHEMA",
    "PLUGIN_MANIFEST_VERSION",
    "CapabilityApproval",
    "CapabilityDeclaration",
    "CompatibilityCheck",
    "ComponentInventory",
    "ComponentRequirement",
    "DiscoveredPluginPack",
    "InstalledComponent",
    "PackResource",
    "PluginActivation",
    "PluginActivationRequest",
    "PluginCatalog",
    "PluginDiscoveryRequest",
    "PluginIdentity",
    "PluginPackError",
    "PluginPackManifest",
    "ResolvedResource",
    "UnsupportedPluginVersion",
    "discover_plugin_packs",
]
