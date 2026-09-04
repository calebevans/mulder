"""Deterministic, sealed Linux live-state collection.

Collection is deliberately implemented as typed filesystem reads.  There is no
subprocess, shell, SSH, socket, or caller-supplied command path.  The physical
root is injected by an examiner-controlled scope, which also makes the same
implementation usable against hermetic fixture roots.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import socket
import stat
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mulder import __version__
from mulder.models import CoverageMetadata, ToolOutcome, ToolOutcomeStatus
from mulder.path_policy import PathPolicyError, resolve_allowed_path

LINUX_LIVE_COLLECTOR_VERSION = "1.0.0"
BUNDLE_SCHEMA = "mulder.linux-live-bundle"
BUNDLE_SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"
SEAL_PROFILE = "mulder.linux-live-bundle:v1"

_HOST_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$"
_BUNDLE_PATTERN = r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$"
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_MAX_FILES_HARD = 50_000
_MAX_FILE_BYTES_HARD = 64 * 1024 * 1024
_MAX_TOTAL_BYTES_HARD = 512 * 1024 * 1024


class LinuxLiveCollectionError(ValueError):
    """The requested scope is unsafe or collection cannot produce a bundle."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class LinuxCheck(str, Enum):
    """Only operations implemented by the Linux live-state collector."""

    JOURNAL_AUTH = "journal_auth"
    SYSTEMD = "systemd"
    CRON_AT = "cron_at"
    PACKAGES_REPOS = "packages_repos"
    SHELL_HISTORY = "shell_history"
    PROCESS_NETWORK_MODULES = "process_network_modules"
    WEB_ROOTS_LOGS = "web_roots_logs"
    CONTAINER_KUBERNETES = "container_kubernetes"


ALL_LINUX_CHECKS: tuple[LinuxCheck, ...] = tuple(LinuxCheck)


class LinuxCollectionScope(_StrictModel):
    """Examiner-granted boundary for one local-host collection invocation."""

    host_id: str = Field(pattern=_HOST_PATTERN)
    physical_root: Path
    output_root: Path
    allowed_checks: tuple[LinuxCheck, ...] = ALL_LINUX_CHECKS

    @model_validator(mode="after")
    def _validate_scope(self) -> LinuxCollectionScope:
        if not self.physical_root.is_absolute() or not self.output_root.is_absolute():
            raise ValueError("physical_root and output_root must be absolute")
        if not self.allowed_checks:
            raise ValueError("allowed_checks cannot be empty")
        if len(set(self.allowed_checks)) != len(self.allowed_checks):
            raise ValueError("allowed_checks cannot contain duplicates")
        return self

    @classmethod
    def for_local_host(
        cls,
        *,
        output_root: Path,
        allowed_checks: Sequence[LinuxCheck] = ALL_LINUX_CHECKS,
    ) -> LinuxCollectionScope:
        """Create an explicit scope for the actual local host and root."""
        return cls(
            host_id=socket.gethostname(),
            physical_root=Path("/"),
            output_root=output_root.absolute(),
            allowed_checks=tuple(allowed_checks),
        )


class LinuxCollectionRequest(_StrictModel):
    """Bounded typed request; intentionally contains no command or remote host."""

    host_id: str = Field(pattern=_HOST_PATTERN)
    checks: tuple[LinuxCheck, ...] = Field(min_length=1)
    bundle_name: str = Field(pattern=_BUNDLE_PATTERN)
    max_files_per_check: int = Field(default=2_000, ge=1, le=_MAX_FILES_HARD)
    max_bytes_per_file: int = Field(default=2 * 1024 * 1024, ge=1, le=_MAX_FILE_BYTES_HARD)
    max_total_bytes: int = Field(default=64 * 1024 * 1024, ge=1, le=_MAX_TOTAL_BYTES_HARD)

    @model_validator(mode="after")
    def _validate_checks(self) -> LinuxCollectionRequest:
        if len(set(self.checks)) != len(self.checks):
            raise ValueError("checks cannot contain duplicates")
        return self


CoverageState = Literal["success", "empty", "partial", "failed"]


class CheckCoverage(_StrictModel):
    """What one check could and could not acquire."""

    check: LinuxCheck
    status: CoverageState
    logical_paths: tuple[str, ...]
    sources_attempted: int = Field(ge=0)
    sources_present: int = Field(ge=0)
    files_examined: int = Field(ge=0)
    files_discovered: int = Field(ge=0)
    bytes_examined: int = Field(ge=0)
    bytes_discovered: int = Field(ge=0)
    totals_known: bool = True
    omitted_files: int = Field(ge=0)
    errors: tuple[str, ...] = ()
    reason: str | None = None
    tool_version: str = LINUX_LIVE_COLLECTOR_VERSION
    parser_version: str = "linux-filesystem-v1"

    @model_validator(mode="after")
    def _validate_semantics(self) -> CheckCoverage:
        if self.files_examined > self.files_discovered:
            raise ValueError("files_examined cannot exceed files_discovered")
        if self.totals_known and self.bytes_examined > self.bytes_discovered:
            raise ValueError("bytes_examined cannot exceed known discovered bytes")
        limited = bool(self.errors or self.omitted_files)
        if self.status == "success" and (not self.files_examined or limited):
            raise ValueError("success requires examined files and no limitations")
        if self.status == "empty" and (self.files_examined or limited):
            raise ValueError("empty cannot contain examined files or limitations")
        if self.status == "partial" and (not self.files_examined or not limited):
            raise ValueError("partial requires examined files and a limitation")
        if self.status == "failed" and (self.files_examined or not limited):
            raise ValueError("failed requires zero examined files and a limitation")
        return self

    def tool_outcome(self) -> ToolOutcome:
        """Map acquisition state to Mulder's authoritative coverage vocabulary."""
        statuses: Mapping[CoverageState, ToolOutcomeStatus] = {
            "success": ToolOutcomeStatus.SUCCESS_NONEMPTY,
            "empty": ToolOutcomeStatus.SUCCESS_EMPTY,
            "partial": ToolOutcomeStatus.PARTIAL,
            "failed": ToolOutcomeStatus.FAILED,
        }
        return ToolOutcome(
            status=statuses[self.status],
            coverage=CoverageMetadata(
                bytes_examined=self.bytes_examined,
                bytes_total=(
                    None if self.errors or not self.totals_known else self.bytes_discovered
                ),
                rows_examined=self.files_examined,
                rows_total=None if self.errors else self.files_discovered,
                truncation_reason=self.reason if self.status == "partial" else None,
                tool_version=self.tool_version,
                parser_version=self.parser_version,
            ),
            reason=self.reason,
        )


class ArtifactEntry(_StrictModel):
    """One exact ZIP member committed by the manifest."""

    bundle_path: str
    check: LinuxCheck
    artifact_type: Literal["source", "inventory"]
    source_path: str | None = None
    source_size: int | None = Field(default=None, ge=0)
    captured_size: int = Field(ge=0)
    sha256: str = Field(pattern=_SHA256_PATTERN)
    capture: Literal["full", "prefix", "inventory"]
    media_type: str

    @model_validator(mode="after")
    def _validate_artifact_coordinates(self) -> ArtifactEntry:
        path = PurePosixPath(self.bundle_path)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != self.bundle_path:
            raise ValueError("artifact bundle_path must be normalized and relative")
        if self.artifact_type == "inventory":
            expected = f"inventory/{self.check.value}.json"
            if (
                self.bundle_path != expected
                or self.capture != "inventory"
                or self.source_path is not None
                or self.source_size is not None
            ):
                raise ValueError("inventory artifact coordinates are inconsistent")
        else:
            if (
                not self.bundle_path.startswith(f"evidence/{self.check.value}/")
                or self.capture == "inventory"
                or self.source_path is None
                or self.source_size is None
            ):
                raise ValueError("source artifact coordinates are inconsistent")
        return self


class CollectionScopeRecord(_StrictModel):
    """Portable scope declaration committed into the bundle."""

    source: Literal["local-filesystem"] = "local-filesystem"
    host_id: str = Field(pattern=_HOST_PATTERN)
    logical_root: Literal["/"] = "/"
    checks: tuple[LinuxCheck, ...]
    paths_by_check: Mapping[str, tuple[str, ...]]
    tool_methods: tuple[Literal["filesystem-read", "procfs-read"], ...] = (
        "filesystem-read",
        "procfs-read",
    )
    network_access: Literal[False] = False
    command_execution: Literal[False] = False
    remote_access: Literal[False] = False

    @model_validator(mode="after")
    def _validate_declared_scope(self) -> CollectionScopeRecord:
        if not self.checks or len(set(self.checks)) != len(self.checks):
            raise ValueError("scope checks must be non-empty and unique")
        expected_paths = {check.value: logical_paths_for(check) for check in self.checks}
        if dict(self.paths_by_check) != expected_paths:
            raise ValueError("path scope differs from the built-in typed check catalog")
        if not self.tool_methods or len(set(self.tool_methods)) != len(self.tool_methods):
            raise ValueError("tool methods must be non-empty and unique")
        if tuple(sorted(self.tool_methods)) != self.tool_methods:
            raise ValueError("tool methods must use stable lexical order")
        return self


class CollectorRecord(_StrictModel):
    name: Literal["mulder-linux-live"] = "mulder-linux-live"
    collector_version: str = LINUX_LIVE_COLLECTOR_VERSION
    mulder_version: str = __version__
    parser_versions: Mapping[str, str] = Field(default_factory=lambda: {"linux-filesystem": "1"})


class ContentSeal(_StrictModel):
    algorithm: Literal["sha256"] = "sha256"
    profile: Literal["mulder.linux-live-bundle:v1"] = "mulder.linux-live-bundle:v1"
    digest: str = Field(pattern=_SHA256_PATTERN)


class LinuxBundleManifest(_StrictModel):
    """Canonical content manifest embedded as the first ZIP member."""

    schema_name: Literal["mulder.linux-live-bundle"] = Field(
        default="mulder.linux-live-bundle", alias="schema"
    )
    schema_version: Literal[1] = 1
    scope: CollectionScopeRecord
    collector: CollectorRecord = CollectorRecord()
    limits: Mapping[str, int]
    coverage: tuple[CheckCoverage, ...]
    artifacts: tuple[ArtifactEntry, ...]
    seal: ContentSeal

    @model_validator(mode="after")
    def _validate_graph_and_order(self) -> LinuxBundleManifest:
        checks = tuple(item.check for item in self.coverage)
        if checks != self.scope.checks:
            raise ValueError("coverage must contain each scoped check in stable order")
        if tuple(sorted(checks, key=lambda item: item.value)) != checks:
            raise ValueError("scoped checks must use stable lexical order")
        if set(self.scope.paths_by_check) != {check.value for check in checks}:
            raise ValueError("path scope must contain exactly the selected checks")
        artifact_paths = tuple(item.bundle_path for item in self.artifacts)
        if len(set(artifact_paths)) != len(artifact_paths):
            raise ValueError("artifact bundle paths must be unique")
        if tuple(sorted(artifact_paths)) != artifact_paths:
            raise ValueError("artifacts must use stable lexical order")
        inventory_checks = tuple(
            item.check for item in self.artifacts if item.artifact_type == "inventory"
        )
        if len(inventory_checks) != len(checks) or set(inventory_checks) != set(checks):
            raise ValueError("each selected check must have one committed inventory")
        return self

    def payload_bytes(self) -> bytes:
        """Canonical bytes covered by ``seal``, excluding its digest."""
        raw = self.model_dump(mode="json", by_alias=True)
        seal = raw.get("seal")
        assert isinstance(seal, dict)
        seal["digest"] = None
        return _canonical_json(raw)

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json", by_alias=True))

    @property
    def expected_seal(self) -> str:
        return _digest(SEAL_PROFILE.encode("ascii") + b"\0" + self.payload_bytes())


class CollectionResult(_StrictModel):
    """Result returned by collection adapters without leaking artifact content."""

    bundle_path: Path
    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest: LinuxBundleManifest


class VerificationDiagnostic(_StrictModel):
    code: str
    subject: str
    message: str
    expected: str | int | None = None
    actual: str | int | None = None


class BundleVerification(_StrictModel):
    status: Literal["valid", "invalid", "unsupported"]
    bundle_path: Path
    host_id: str | None = None
    artifacts_checked: int = Field(default=0, ge=0)
    diagnostics: tuple[VerificationDiagnostic, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status == "valid"


class _PathKind(str, Enum):
    FILE = "file"
    TREE = "tree"
    HOME_GLOB = "home_glob"
    PROC = "proc"


class _PathRule(_StrictModel):
    logical_path: str
    kind: _PathKind


_CHECK_RULES: Mapping[LinuxCheck, tuple[_PathRule, ...]] = {
    LinuxCheck.JOURNAL_AUTH: (
        _PathRule(logical_path="/var/log/auth.log", kind=_PathKind.FILE),
        _PathRule(logical_path="/var/log/secure", kind=_PathKind.FILE),
        _PathRule(logical_path="/var/log/messages", kind=_PathKind.FILE),
        _PathRule(logical_path="/var/log/syslog", kind=_PathKind.FILE),
        _PathRule(logical_path="/var/log/journal", kind=_PathKind.TREE),
    ),
    LinuxCheck.SYSTEMD: (
        _PathRule(logical_path="/etc/systemd/system", kind=_PathKind.TREE),
        _PathRule(logical_path="/run/systemd/system", kind=_PathKind.TREE),
        _PathRule(logical_path="/usr/lib/systemd/system", kind=_PathKind.TREE),
        _PathRule(logical_path="/lib/systemd/system", kind=_PathKind.TREE),
    ),
    LinuxCheck.CRON_AT: (
        _PathRule(logical_path="/etc/crontab", kind=_PathKind.FILE),
        _PathRule(logical_path="/etc/cron.d", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/cron.hourly", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/cron.daily", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/cron.weekly", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/cron.monthly", kind=_PathKind.TREE),
        _PathRule(logical_path="/var/spool/cron", kind=_PathKind.TREE),
        _PathRule(logical_path="/var/spool/at", kind=_PathKind.TREE),
        _PathRule(logical_path="/var/spool/atjobs", kind=_PathKind.TREE),
    ),
    LinuxCheck.PACKAGES_REPOS: (
        _PathRule(logical_path="/var/lib/dpkg/status", kind=_PathKind.FILE),
        _PathRule(logical_path="/var/lib/dpkg/info", kind=_PathKind.TREE),
        _PathRule(logical_path="/var/lib/rpm", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/apt/sources.list", kind=_PathKind.FILE),
        _PathRule(logical_path="/etc/apt/sources.list.d", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/yum.repos.d", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/zypp/repos.d", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/apk/repositories", kind=_PathKind.FILE),
    ),
    LinuxCheck.SHELL_HISTORY: (
        _PathRule(logical_path="/root/.*_history", kind=_PathKind.HOME_GLOB),
        _PathRule(logical_path="/root/.local/share/fish/fish_history", kind=_PathKind.FILE),
        _PathRule(logical_path="/home/*/.*_history", kind=_PathKind.HOME_GLOB),
        _PathRule(logical_path="/home/*/.local/share/fish/fish_history", kind=_PathKind.HOME_GLOB),
    ),
    LinuxCheck.PROCESS_NETWORK_MODULES: (
        _PathRule(logical_path="/proc", kind=_PathKind.PROC),
        _PathRule(logical_path="/proc/modules", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net", kind=_PathKind.TREE),
        _PathRule(logical_path="/proc/net/arp", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/netlink", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/packet", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/route", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/tcp", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/tcp6", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/udp", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/udp6", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/unix", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/nf_conntrack", kind=_PathKind.FILE),
        _PathRule(logical_path="/proc/net/ip_tables_names", kind=_PathKind.FILE),
    ),
    LinuxCheck.WEB_ROOTS_LOGS: (
        _PathRule(logical_path="/var/www", kind=_PathKind.TREE),
        _PathRule(logical_path="/srv/www", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/nginx", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/apache2", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/httpd", kind=_PathKind.TREE),
        _PathRule(logical_path="/var/log/nginx", kind=_PathKind.TREE),
        _PathRule(logical_path="/var/log/apache2", kind=_PathKind.TREE),
        _PathRule(logical_path="/var/log/httpd", kind=_PathKind.TREE),
    ),
    LinuxCheck.CONTAINER_KUBERNETES: (
        _PathRule(logical_path="/etc/docker", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/containerd", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/crio", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/containers", kind=_PathKind.TREE),
        _PathRule(logical_path="/etc/kubernetes", kind=_PathKind.TREE),
        _PathRule(logical_path="/var/lib/kubelet/config.yaml", kind=_PathKind.FILE),
        _PathRule(logical_path="/root/.kube/config", kind=_PathKind.FILE),
        _PathRule(logical_path="/home/*/.kube/config", kind=_PathKind.HOME_GLOB),
    ),
}


def logical_paths_for(check: LinuxCheck) -> tuple[str, ...]:
    """Return stable declared paths for a check (also used by pack metadata)."""
    return tuple(rule.logical_path for rule in _CHECK_RULES[check])


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _logical_to_physical(root: Path, logical: str) -> Path:
    path = PurePosixPath(logical)
    if not path.is_absolute() or ".." in path.parts:
        raise LinuxLiveCollectionError(f"unsafe built-in logical path: {logical}")
    return root.joinpath(*path.parts[1:])


def _logical_path(root: Path, path: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise LinuxLiveCollectionError(f"path escaped collection root: {path}") from exc
    return "/" + relative.as_posix() if relative.parts else "/"


def _safe_output_path(scope: LinuxCollectionScope, bundle_name: str) -> Path:
    try:
        output_root = resolve_allowed_path(scope.output_root, [scope.output_root])
        output_root.mkdir(parents=True, exist_ok=True)
        output = resolve_allowed_path(output_root / f"{bundle_name}.mlive", [output_root])
    except (OSError, PathPolicyError) as exc:
        raise LinuxLiveCollectionError(f"unsafe output scope: {exc}") from exc
    return output


def _iter_tree(path: Path, max_entries: int) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Inventory a tree in lexical order without following directory symlinks."""
    pending = [path]
    discovered: list[Path] = []
    errors: list[str] = []
    capped = False
    while pending:
        current = pending.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            errors.append(f"{current}: cannot enumerate: {exc}")
            continue
        directories: list[Path] = []
        for entry in entries:
            if len(discovered) >= max_entries:
                errors.append(
                    f"{path}: inventory candidate limit {max_entries} reached; "
                    "remaining total is unknown"
                )
                capped = True
                break
            discovered.append(entry)
            try:
                mode = entry.lstat().st_mode
            except OSError as exc:
                errors.append(f"{entry}: cannot inspect while enumerating: {exc}")
                continue
            if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
                directories.append(entry)
        if capped:
            break
        pending.extend(reversed(directories))
    return tuple(discovered), tuple(errors)


def _safe_entry(root: Path, path: Path) -> Path:
    """Resolve parent components inside *root* while preserving a final symlink."""
    parent = resolve_allowed_path(path.parent, [root])
    return parent / path.name


def _expand_home_glob(
    root: Path, logical_pattern: str, max_entries: int
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Expand the two supported home-history forms without following user links."""
    parts = PurePosixPath(logical_pattern).parts[1:]
    wildcard_indices = [index for index, part in enumerate(parts) if "*" in part]
    if not wildcard_indices:
        return (_logical_to_physical(root, logical_pattern),), ()
    first = wildcard_indices[0]
    directory_parts = parts[:first]
    pattern = parts[first]
    suffix = parts[first + 1 :]
    try:
        directory = resolve_allowed_path(root.joinpath(*directory_parts), [root])
        entries = sorted(directory.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        return (), ()
    except (OSError, PathPolicyError) as exc:
        return (), (f"{logical_pattern}: cannot expand safely: {exc}",)

    matches: list[Path] = []
    errors: list[str] = []
    for entry in entries:
        if not fnmatch.fnmatch(entry.name, pattern):
            continue
        try:
            mode = entry.lstat().st_mode
        except OSError as exc:
            errors.append(f"{entry}: cannot inspect glob entry: {exc}")
            continue
        if suffix and (not stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
            if stat.S_ISLNK(mode):
                errors.append(f"{entry}: refusing to traverse symlinked home directory")
            continue
        candidates: tuple[Path, ...]
        if suffix and any(character in suffix[-1] for character in "*?["):
            try:
                suffix_parent = resolve_allowed_path(entry.joinpath(*suffix[:-1]), [root])
                candidates = tuple(
                    item
                    for item in sorted(suffix_parent.iterdir(), key=lambda item: item.name)
                    if fnmatch.fnmatch(item.name, suffix[-1])
                )
            except FileNotFoundError:
                candidates = ()
            except (OSError, PathPolicyError) as exc:
                errors.append(f"{entry}: cannot expand history files safely: {exc}")
                continue
        else:
            candidates = (entry.joinpath(*suffix),)
        for candidate in candidates:
            if len(matches) >= max_entries:
                errors.append(
                    f"{logical_pattern}: inventory candidate limit {max_entries} reached; "
                    "remaining total is unknown"
                )
                return tuple(matches), tuple(errors)
            matches.append(candidate)
    return tuple(matches), tuple(errors)


def _expand_rule(
    root: Path, rule: _PathRule, max_entries: int
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    if max_entries <= 0:
        return (), ("inventory candidate limit reached; remaining total is unknown",)
    if rule.kind is _PathKind.HOME_GLOB:
        try:
            return _expand_home_glob(root, rule.logical_path, max_entries)
        except LinuxLiveCollectionError as exc:
            return (), (str(exc),)
    original_path = _logical_to_physical(root, rule.logical_path)
    try:
        path = _safe_entry(root, original_path)
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return (original_path,), ()
    except (OSError, PathPolicyError) as exc:
        return (), (f"{rule.logical_path}: cannot inspect safely: {exc}",)
    if stat.S_ISLNK(mode):
        return (path,), ()
    if rule.kind is _PathKind.PROC:
        if not stat.S_ISDIR(mode):
            return (path,), ()
        try:
            pids = sorted(
                (entry for entry in path.iterdir() if entry.name.isdigit()),
                key=lambda item: int(item.name),
            )
        except OSError as exc:
            return (), (f"{rule.logical_path}: cannot enumerate processes: {exc}",)
        process_files = ("cgroup", "cmdline", "exe", "stat", "status")
        matches = tuple(pid / name for pid in pids for name in process_files)
        if len(matches) > max_entries:
            return matches[:max_entries], (
                f"{rule.logical_path}: inventory candidate limit {max_entries} reached; "
                "remaining total is unknown",
            )
        return matches, ()
    if rule.kind is _PathKind.TREE and stat.S_ISDIR(mode):
        return _iter_tree(path, max_entries)
    return (path,), ()


def _symlink_target(root: Path, path: Path) -> tuple[str, bool]:
    raw = os.readlink(path)
    target = PurePosixPath(raw)
    candidate = root.joinpath(*target.parts[1:]) if target.is_absolute() else path.parent / raw
    try:
        resolved = candidate.resolve(strict=False)
        safe = resolved.is_relative_to(root)
    except (OSError, RuntimeError):
        safe = False
    return raw, safe


def _bundle_source_path(check: LinuxCheck, source_path: str) -> str:
    token = hashlib.sha256(source_path.encode("utf-8")).hexdigest()[:20]
    basename = PurePosixPath(source_path).name or "root"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", basename)[:80] or "artifact"
    return f"evidence/{check.value}/{token}-{safe_name}"


def _read_prefix(path: Path, limit: int) -> tuple[bytes, bool]:
    """Read at most *limit* bytes and report whether EOF was observed."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError("source changed type before read")
        chunks: list[bytes] = []
        remaining = limit + 1
        eof = False
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                eof = True
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        return raw[:limit], eof and len(raw) <= limit
    finally:
        os.close(descriptor)


def _coverage_state(
    *, examined: int, errors: Sequence[str], omitted: int
) -> tuple[CoverageState, str | None]:
    limitations: list[str] = []
    if omitted:
        limitations.append(f"{omitted} discovered file(s) omitted by collection limits")
    if errors:
        limitations.append(f"{len(errors)} source error(s); see check inventory")
    if limitations:
        return ("partial" if examined else "failed"), "; ".join(limitations)
    if examined:
        return "success", None
    return "empty", "no declared source files were present"


def _collect_check(
    root: Path,
    check: LinuxCheck,
    request: LinuxCollectionRequest,
    remaining_total: int,
) -> tuple[CheckCoverage, list[ArtifactEntry], dict[str, bytes]]:
    rules = _CHECK_RULES[check]
    errors: list[str] = []
    records: list[dict[str, object]] = []
    artifacts: list[ArtifactEntry] = []
    content: dict[str, bytes] = {}
    seen: set[str] = set()
    present = 0
    examined = 0
    discovered = 0
    bytes_examined = 0
    bytes_discovered = 0
    totals_known = True
    omitted = 0
    inventory_limit = request.max_files_per_check * 2

    root = root.resolve(strict=True)
    for rule in rules:
        candidates, expansion_errors = _expand_rule(root, rule, inventory_limit - len(seen))
        for error in expansion_errors:
            errors.append(error.replace(str(root), ""))
        for candidate in candidates:
            try:
                logical = _logical_path(root, candidate)
            except LinuxLiveCollectionError as exc:
                errors.append(str(exc))
                continue
            if logical in seen:
                continue
            seen.add(logical)
            try:
                safe_candidate = _safe_entry(root, candidate)
                info = safe_candidate.lstat()
            except FileNotFoundError:
                continue
            except (OSError, PathPolicyError) as exc:
                errors.append(f"{logical}: cannot inspect: {exc}")
                continue
            present += 1

            if stat.S_ISDIR(info.st_mode):
                records.append({"path": logical, "type": "directory"})
                continue
            if stat.S_ISLNK(info.st_mode):
                discovered += 1
                try:
                    target, safe = _symlink_target(root, safe_candidate)
                except OSError as exc:
                    errors.append(f"{logical}: cannot read symlink: {exc}")
                    continue
                if not safe:
                    errors.append(f"{logical}: symlink target escapes collection root")
                elif examined >= request.max_files_per_check:
                    omitted += 1
                else:
                    examined += 1
                records.append(
                    {"path": logical, "type": "symlink", "target": target, "safe": safe}
                )
                continue
            if not stat.S_ISREG(info.st_mode):
                records.append({"path": logical, "type": "special", "mode": info.st_mode})
                continue

            discovered += 1
            size = max(info.st_size, 0)
            bytes_discovered += size
            if examined >= request.max_files_per_check or remaining_total <= 0:
                omitted += 1
                records.append(
                    {"path": logical, "type": "file", "size": size, "capture": "omitted"}
                )
                continue
            limit = min(request.max_bytes_per_file, remaining_total)
            try:
                resolved = resolve_allowed_path(safe_candidate, [root])
                raw, reached_eof = _read_prefix(resolved, limit)
            except (OSError, PathPolicyError) as exc:
                errors.append(f"{logical}: cannot read: {exc}")
                continue
            bundle_path = _bundle_source_path(check, logical)
            content[bundle_path] = raw
            capture: Literal["full", "prefix"] = "full" if reached_eof else "prefix"
            if capture == "prefix":
                omitted += 1
            if len(raw) != size:
                totals_known = False
            artifact = ArtifactEntry(
                bundle_path=bundle_path,
                check=check,
                artifact_type="source",
                source_path=logical,
                source_size=size,
                captured_size=len(raw),
                sha256=_digest(raw),
                capture=capture,
                media_type="application/octet-stream",
            )
            artifacts.append(artifact)
            records.append(
                {
                    "path": logical,
                    "type": "file",
                    "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                    "mtime_ns": info.st_mtime_ns,
                    "source_size": size,
                    "capture": capture,
                    "bundle_path": bundle_path,
                    "sha256": artifact.sha256,
                }
            )
            examined += 1
            bytes_examined += len(raw)
            remaining_total -= len(raw)

    state, reason = _coverage_state(examined=examined, errors=errors, omitted=omitted)
    inventory_path = f"inventory/{check.value}.json"
    inventory = _canonical_json(
        {
            "schema": "mulder.linux-live-check-inventory",
            "schema_version": 1,
            "check": check.value,
            "records": sorted(records, key=lambda item: str(item["path"])),
            "errors": sorted(errors),
        }
    )
    content[inventory_path] = inventory
    artifacts.append(
        ArtifactEntry(
            bundle_path=inventory_path,
            check=check,
            artifact_type="inventory",
            captured_size=len(inventory),
            sha256=_digest(inventory),
            capture="inventory",
            media_type="application/json",
        )
    )
    coverage = CheckCoverage(
        check=check,
        status=state,
        logical_paths=logical_paths_for(check),
        sources_attempted=len(rules),
        sources_present=present,
        files_examined=examined,
        files_discovered=discovered,
        bytes_examined=bytes_examined,
        bytes_discovered=bytes_discovered,
        totals_known=totals_known,
        omitted_files=omitted,
        errors=tuple(sorted(errors)),
        reason=reason,
    )
    return coverage, artifacts, content


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _write_bundle(path: Path, manifest: LinuxBundleManifest, content: Mapping[str, bytes]) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
        with zipfile.ZipFile(temporary, mode="w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(_zip_info(MANIFEST_NAME), manifest.canonical_bytes() + b"\n")
            for name in sorted(content):
                archive.writestr(_zip_info(name), content[name])
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def collect_linux_live_state(
    scope: LinuxCollectionScope,
    request: LinuxCollectionRequest,
) -> CollectionResult:
    """Collect selected built-in Linux state and emit a deterministic sealed bundle."""
    if request.host_id != scope.host_id:
        raise LinuxLiveCollectionError(
            f"host scope mismatch: requested {request.host_id!r}, allowed {scope.host_id!r}"
        )
    denied = sorted(set(request.checks) - set(scope.allowed_checks), key=lambda item: item.value)
    if denied:
        names = ", ".join(item.value for item in denied)
        raise LinuxLiveCollectionError(f"check scope denied: {names}")
    try:
        root = scope.physical_root.resolve(strict=True)
    except OSError as exc:
        raise LinuxLiveCollectionError(f"collection root is unavailable: {exc}") from exc
    if not root.is_dir():
        raise LinuxLiveCollectionError("collection root must be a directory")
    output = _safe_output_path(scope, request.bundle_name)

    coverages: list[CheckCoverage] = []
    artifacts: list[ArtifactEntry] = []
    content: dict[str, bytes] = {}
    remaining = request.max_total_bytes
    for check in sorted(request.checks, key=lambda item: item.value):
        coverage, check_artifacts, check_content = _collect_check(root, check, request, remaining)
        coverages.append(coverage)
        artifacts.extend(check_artifacts)
        content.update(check_content)
        remaining -= coverage.bytes_examined

    ordered_checks = tuple(sorted(request.checks, key=lambda item: item.value))
    ordered_artifacts = tuple(sorted(artifacts, key=lambda item: item.bundle_path))
    methods: list[Literal["filesystem-read", "procfs-read"]] = []
    if any(check is not LinuxCheck.PROCESS_NETWORK_MODULES for check in ordered_checks):
        methods.append("filesystem-read")
    if LinuxCheck.PROCESS_NETWORK_MODULES in ordered_checks:
        methods.append("procfs-read")
    scope_record = CollectionScopeRecord(
        host_id=request.host_id,
        checks=ordered_checks,
        paths_by_check={check.value: logical_paths_for(check) for check in ordered_checks},
        tool_methods=tuple(methods),
    )
    placeholder = "sha256:" + "0" * 64
    manifest = LinuxBundleManifest(
        scope=scope_record,
        limits={
            "max_files_per_check": request.max_files_per_check,
            "max_bytes_per_file": request.max_bytes_per_file,
            "max_total_bytes": request.max_total_bytes,
        },
        coverage=tuple(coverages),
        artifacts=ordered_artifacts,
        seal=ContentSeal(digest=placeholder),
    )
    manifest = manifest.model_copy(update={"seal": ContentSeal(digest=manifest.expected_seal)})
    _write_bundle(output, manifest, content)
    return CollectionResult(
        bundle_path=output,
        bundle_sha256=_digest(output.read_bytes()),
        manifest=manifest,
    )


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts


def verify_linux_live_bundle(bundle_path: Path) -> BundleVerification:
    """Verify a Linux live bundle with no MCP, model, command, or network use."""
    diagnostics: list[VerificationDiagnostic] = []
    checked = 0
    host_id: str | None = None
    try:
        archive = zipfile.ZipFile(bundle_path, mode="r")
    except (OSError, zipfile.BadZipFile) as exc:
        return BundleVerification(
            status="invalid",
            bundle_path=bundle_path,
            diagnostics=(
                VerificationDiagnostic(
                    code="bundle_unreadable",
                    subject=str(bundle_path),
                    message=f"cannot open bundle: {exc}",
                ),
            ),
        )

    with archive:
        names = archive.namelist()
        duplicates = sorted({name for name in names if names.count(name) > 1})
        for name in duplicates:
            diagnostics.append(
                VerificationDiagnostic(
                    code="duplicate_member",
                    subject=name,
                    message="ZIP contains duplicate member names",
                )
            )
        for name in names:
            if not _safe_member(name):
                diagnostics.append(
                    VerificationDiagnostic(
                        code="unsafe_member",
                        subject=name,
                        message="ZIP member path is absolute or traverses a parent",
                    )
                )
        if MANIFEST_NAME not in names:
            diagnostics.append(
                VerificationDiagnostic(
                    code="manifest_missing",
                    subject=MANIFEST_NAME,
                    message="bundle manifest is missing",
                )
            )
            return BundleVerification(
                status="invalid",
                bundle_path=bundle_path,
                diagnostics=tuple(diagnostics),
            )
        try:
            raw_manifest = json.loads(archive.read(MANIFEST_NAME))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
            diagnostics.append(
                VerificationDiagnostic(
                    code="manifest_invalid_json",
                    subject=MANIFEST_NAME,
                    message=f"manifest is not valid UTF-8 JSON: {exc}",
                )
            )
            return BundleVerification(
                status="invalid",
                bundle_path=bundle_path,
                diagnostics=tuple(diagnostics),
            )
        if not isinstance(raw_manifest, dict):
            diagnostics.append(
                VerificationDiagnostic(
                    code="manifest_invalid_shape",
                    subject=MANIFEST_NAME,
                    message="manifest must be a JSON object",
                )
            )
            return BundleVerification(
                status="invalid", bundle_path=bundle_path, diagnostics=tuple(diagnostics)
            )
        if (
            raw_manifest.get("schema") != BUNDLE_SCHEMA
            or raw_manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION
        ):
            return BundleVerification(
                status="unsupported",
                bundle_path=bundle_path,
                diagnostics=(
                    VerificationDiagnostic(
                        code="unsupported_manifest",
                        subject=MANIFEST_NAME,
                        message="unsupported Linux live bundle schema or version",
                        expected=f"{BUNDLE_SCHEMA}@{BUNDLE_SCHEMA_VERSION}",
                        actual=(
                            f"{raw_manifest.get('schema')}@{raw_manifest.get('schema_version')}"
                        ),
                    ),
                ),
            )
        try:
            manifest = LinuxBundleManifest.model_validate(raw_manifest)
        except ValueError as exc:
            diagnostics.append(
                VerificationDiagnostic(
                    code="manifest_schema_invalid",
                    subject=MANIFEST_NAME,
                    message=str(exc),
                )
            )
            return BundleVerification(
                status="invalid", bundle_path=bundle_path, diagnostics=tuple(diagnostics)
            )
        host_id = manifest.scope.host_id
        if manifest.seal.digest != manifest.expected_seal:
            diagnostics.append(
                VerificationDiagnostic(
                    code="seal_mismatch",
                    subject=MANIFEST_NAME,
                    message="manifest content seal does not match canonical content",
                    expected=manifest.seal.digest,
                    actual=manifest.expected_seal,
                )
            )
        expected_names = {MANIFEST_NAME}
        for artifact in manifest.artifacts:
            expected_names.add(artifact.bundle_path)
            if not _safe_member(artifact.bundle_path):
                diagnostics.append(
                    VerificationDiagnostic(
                        code="unsafe_artifact_path",
                        subject=artifact.bundle_path,
                        message="manifest artifact path is unsafe",
                    )
                )
                continue
            try:
                payload = archive.read(artifact.bundle_path)
            except KeyError:
                diagnostics.append(
                    VerificationDiagnostic(
                        code="artifact_missing",
                        subject=artifact.bundle_path,
                        message="manifest-committed artifact is missing",
                    )
                )
                continue
            checked += 1
            actual_digest = _digest(payload)
            if actual_digest != artifact.sha256:
                diagnostics.append(
                    VerificationDiagnostic(
                        code="artifact_digest_mismatch",
                        subject=artifact.bundle_path,
                        message="artifact content digest does not match manifest",
                        expected=artifact.sha256,
                        actual=actual_digest,
                    )
                )
            if len(payload) != artifact.captured_size:
                diagnostics.append(
                    VerificationDiagnostic(
                        code="artifact_size_mismatch",
                        subject=artifact.bundle_path,
                        message="artifact size does not match manifest",
                        expected=artifact.captured_size,
                        actual=len(payload),
                    )
                )
        extras = sorted(set(names) - expected_names)
        for name in extras:
            diagnostics.append(
                VerificationDiagnostic(
                    code="uncommitted_artifact",
                    subject=name,
                    message="bundle contains an artifact not committed by the manifest",
                )
            )
    return BundleVerification(
        status="invalid" if diagnostics else "valid",
        bundle_path=bundle_path,
        host_id=host_id,
        artifacts_checked=checked,
        diagnostics=tuple(diagnostics),
    )
