"""Immutable, content-addressed KAPE and Velociraptor collection intake.

The adapter reads a directory or ZIP export without executing collector
content.  It validates every logical path, hashes every byte, records
collector provenance separately from inferred format metadata, and writes one
case-bound manifest.  Re-importing identical bytes is idempotent; attempting
to replace a case's intake with different bytes is a loud error.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import tempfile
import zipfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mulder.db import CaseDB

INTAKE_SCHEMA: Literal["mulder.collection-intake"] = "mulder.collection-intake"
INTAKE_VERSION: Literal[1] = 1
CollectionFormat = Literal["kape", "velociraptor"]
SourceKind = Literal["directory", "zip"]
AssertionField = Literal["collector_version", "collection_id", "host"]


class IntakeError(ValueError):
    """Raised when a collection cannot be classified or read immutably."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)


class IntakeLimits(_FrozenModel):
    """Hard resource limits applied before a manifest is accepted."""

    max_files: int = Field(default=100_000, ge=1, le=1_000_000)
    max_total_bytes: int = Field(default=1 << 40, ge=1)
    max_file_bytes: int = Field(default=1 << 38, ge=1)
    max_metadata_bytes: int = Field(default=1 << 20, ge=1, le=16 << 20)
    max_archive_ratio: int = Field(default=250, ge=1, le=10_000)
    max_container_bytes: int = Field(default=64 << 30, ge=1, le=64 << 30)
    max_archive_entries: int = Field(default=200_000, ge=1, le=1_000_000)
    max_central_directory_bytes: int = Field(default=128 << 20, ge=1, le=1 << 30)


class ExaminerAssertion(_FrozenModel):
    """One caller-supplied statement kept separate from collector metadata."""

    field: AssertionField
    value: str = Field(min_length=1, max_length=4096)


class CollectorProvenance(_FrozenModel):
    """Collector assertions and their immutable metadata source."""

    collector: CollectionFormat
    collector_version: str | None = None
    collection_id: str | None = None
    host: str | None = None
    acquisition_started: str | None = None
    acquisition_ended: str | None = None
    metadata_source: str | None = None
    metadata_sha256: str | None = None
    assertion_source: Literal["collector_metadata", "format_only"]
    examiner_assertions: tuple[ExaminerAssertion, ...] = ()


class IntakeEntry(_FrozenModel):
    """One stable physical or archive-member commitment."""

    relative_path: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    artifact_type: str
    storage: Literal["file", "zip_member"]

    @model_validator(mode="after")
    def _safe_path(self) -> IntakeEntry:
        path = PurePosixPath(self.relative_path)
        if (
            path.is_absolute()
            or ".." in path.parts
            or path.as_posix() in {"", "."}
            or "\\" in self.relative_path
        ):
            raise ValueError("intake entry path must be normalized and relative")
        return self


class IntakeManifest(_FrozenModel):
    """Complete deterministic inventory plus collector provenance."""

    intake_schema: Literal["mulder.collection-intake"] = Field(
        default=INTAKE_SCHEMA, alias="schema"
    )
    version: Literal[1] = INTAKE_VERSION
    case_id: str
    source_kind: SourceKind
    source_path: str
    source_sha256: str | None
    collection_format: CollectionFormat
    provenance: CollectorProvenance
    entries: tuple[IntakeEntry, ...]
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    collection_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    created_at: str
    integrity: dict[str, str]

    @model_validator(mode="after")
    def _coherent_inventory(self) -> IntakeManifest:
        if not self.case_id or Path(self.case_id).name != self.case_id:
            raise ValueError("case_id must be one safe path segment")
        if not Path(self.source_path).is_absolute():
            raise ValueError("source_path must be absolute")
        if self.file_count != len(self.entries):
            raise ValueError("file_count does not match entries")
        if self.total_bytes != sum(entry.size_bytes for entry in self.entries):
            raise ValueError("total_bytes does not match entries")
        paths = [entry.relative_path for entry in self.entries]
        if paths != sorted(paths) or len({path.casefold() for path in paths}) != len(paths):
            raise ValueError("entries must be sorted without case-folding collisions")
        if self.source_kind == "zip" and self.source_sha256 is None:
            raise ValueError("ZIP intake requires a source_sha256")
        if self.source_kind == "directory" and self.source_sha256 is not None:
            raise ValueError("directory intake cannot carry a container hash")
        if self.integrity.get("algorithm") != "sha256" or re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.integrity.get("manifest_hash", "")
        ) is None:
            raise ValueError("manifest integrity fields are invalid")
        return self


class IntakeResult(_FrozenModel):
    """Outcome returned by :func:`ingest_collection`."""

    manifest_path: str
    collection_digest: str
    created: bool
    database_created: bool
    registered_files: int = Field(ge=0)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _descriptor_flags(*, directory: bool = False) -> int:
    """Return fail-closed flags for an evidence descriptor."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise IntakeError("this platform cannot enforce no-follow evidence reads")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _descriptor_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _hash_descriptor(fd: int, expected_size: int | None = None) -> tuple[str, int]:
    """Hash one already-open regular file and detect in-place mutation."""
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise IntakeError("collection member is not a regular file")
    if expected_size is not None and before.st_size != expected_size:
        raise IntakeError("collection member size changed before hashing")
    digest = hashlib.sha256()
    size = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    after = os.fstat(fd)
    if _descriptor_identity(before) != _descriptor_identity(after) or size != before.st_size:
        raise IntakeError("collection member changed while hashing")
    return "sha256:" + digest.hexdigest(), size


@contextmanager
def _open_nofollow(path: Path, *, directory: bool = False) -> Iterator[int]:
    try:
        fd = os.open(path, _descriptor_flags(directory=directory))
    except OSError as exc:
        raise IntakeError(f"cannot safely open collection source {path}: {exc}") from exc
    try:
        actual = os.fstat(fd)
        expected = stat.S_ISDIR(actual.st_mode) if directory else stat.S_ISREG(actual.st_mode)
        if not expected:
            kind = "directory" if directory else "regular file"
            raise IntakeError(f"collection source is not a {kind}: {path}")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _open_directory_member(root_fd: int, relative_path: str) -> Iterator[int]:
    """Open a member beneath ``root_fd`` without following any symlink."""
    parts = PurePosixPath(relative_path).parts
    if not parts:
        raise IntakeError("collection member path is empty")
    parent_fd = os.dup(root_fd)
    member_fd: int | None = None
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                _descriptor_flags(directory=True),
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = next_fd
        member_fd = os.open(parts[-1], _descriptor_flags(), dir_fd=parent_fd)
        if not stat.S_ISREG(os.fstat(member_fd).st_mode):
            raise IntakeError(f"collection member is not a regular file: {relative_path}")
        yield member_fd
    except OSError as exc:
        raise IntakeError(f"cannot safely open collection member {relative_path}: {exc}") from exc
    finally:
        if member_fd is not None:
            os.close(member_fd)
        os.close(parent_fd)


def _read_descriptor(fd: int, *, expected_size: int, max_bytes: int) -> tuple[bytes, str]:
    if expected_size > max_bytes:
        raise IntakeError(
            f"collection member exceeds requested byte limit: {expected_size} > {max_bytes}"
        )
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
        raise IntakeError("collection member size changed before reading")
    digest = hashlib.sha256()
    content = bytearray()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, min(1024 * 1024, max_bytes + 1 - len(content))):
        content.extend(chunk)
        digest.update(chunk)
        if len(content) > max_bytes:
            raise IntakeError("collection member expanded past requested byte limit")
    after = os.fstat(fd)
    if (
        _descriptor_identity(before) != _descriptor_identity(after)
        or len(content) != expected_size
    ):
        raise IntakeError("collection member changed while reading")
    return bytes(content), "sha256:" + digest.hexdigest()


@contextmanager
def _zip_snapshot(
    path: Path,
    *,
    max_bytes: int,
) -> Iterator[tuple[tempfile.SpooledTemporaryFile[bytes], str, int]]:
    """Yield one stable snapshot copied from a single no-follow descriptor."""
    with _open_nofollow(path) as source_fd, tempfile.SpooledTemporaryFile(
        max_size=8 << 20,
        mode="w+b",
    ) as snapshot:
        before = os.fstat(source_fd)
        if before.st_size > max_bytes:
            raise IntakeError(
                f"ZIP collection exceeds max_container_bytes: "
                f"{before.st_size} > {max_bytes}"
            )
        digest = hashlib.sha256()
        size = 0
        os.lseek(source_fd, 0, os.SEEK_SET)
        while chunk := os.read(source_fd, 1024 * 1024):
            snapshot.write(chunk)
            digest.update(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise IntakeError(
                    f"ZIP collection exceeds max_container_bytes: {size} > {max_bytes}"
                )
        after = os.fstat(source_fd)
        if _descriptor_identity(before) != _descriptor_identity(after) or size != before.st_size:
            raise IntakeError(f"ZIP collection changed while snapshotting: {path}")
        snapshot.flush()
        snapshot.seek(0)
        yield snapshot, "sha256:" + digest.hexdigest(), size


def _preflight_zip_directory(
    snapshot: tempfile.SpooledTemporaryFile[bytes],
    container_size: int,
    limits: IntakeLimits,
) -> None:
    """Bound ZIP metadata before ``zipfile`` materializes its entry list."""
    if container_size < 22:
        raise IntakeError("ZIP collection lacks an end-of-central-directory record")
    tail_size = min(container_size, 22 + 65_535)
    snapshot.seek(container_size - tail_size)
    tail = snapshot.read(tail_size)
    search_end = len(tail)
    eocd_index = -1
    eocd: tuple[bytes, int, int, int, int, int, int, int] | None = None
    while search_end >= 22:
        candidate = tail.rfind(b"PK\x05\x06", 0, search_end)
        if candidate < 0 or candidate + 22 > len(tail):
            break
        parsed = struct.unpack_from("<4s4H2LH", tail, candidate)
        if candidate + 22 + parsed[-1] == len(tail):
            eocd_index = candidate
            eocd = parsed
            break
        search_end = candidate
    if eocd is None:
        raise IntakeError("ZIP collection lacks a valid end-of-central-directory record")

    (
        _signature,
        disk_number,
        central_disk,
        entries_on_disk,
        entry_count,
        central_size,
        central_offset,
        _comment_size,
    ) = eocd
    eocd_offset = container_size - tail_size + eocd_index
    central_end = eocd_offset
    locator_offset = eocd_offset - 20
    locator = b""
    if locator_offset >= 0:
        snapshot.seek(locator_offset)
        locator = snapshot.read(20)
    zip64 = locator.startswith(b"PK\x06\x07") or (
        entry_count == 0xFFFF
        or entries_on_disk == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    )
    if zip64:
        if locator_offset < 0 or not locator.startswith(b"PK\x06\x07"):
            raise IntakeError("ZIP64 collection lacks a locator record")
        if len(locator) != 20:
            raise IntakeError("ZIP64 collection has a truncated locator record")
        locator_signature, zip64_disk, zip64_offset, total_disks = struct.unpack(
            "<4sLQL", locator
        )
        if locator_signature != b"PK\x06\x07":
            raise IntakeError("ZIP64 collection lacks a locator record")
        snapshot.seek(zip64_offset)
        record = snapshot.read(56)
        if len(record) != 56:
            raise IntakeError("ZIP64 end-of-central-directory record is truncated")
        (
            zip64_signature,
            _record_size,
            _made_by,
            _needed,
            disk_number,
            central_disk,
            entries_on_disk,
            entry_count,
            central_size,
            central_offset,
        ) = struct.unpack("<4sQ2H2L4Q", record)
        if (
            zip64_signature != b"PK\x06\x06"
            or _record_size < 44
            or zip64_offset + 12 + _record_size != locator_offset
        ):
            raise IntakeError("ZIP64 end-of-central-directory record is invalid")
        if zip64_disk != 0 or total_disks != 1:
            raise IntakeError("multi-disk ZIP collections are not accepted")
        central_end = zip64_offset

    if disk_number != 0 or central_disk != 0 or entries_on_disk != entry_count:
        raise IntakeError("multi-disk ZIP collections are not accepted")
    if entry_count > limits.max_archive_entries:
        raise IntakeError(
            f"ZIP collection exceeds max_archive_entries: "
            f"{entry_count} > {limits.max_archive_entries}"
        )
    if central_size > limits.max_central_directory_bytes:
        raise IntakeError(
            f"ZIP collection exceeds max_central_directory_bytes: "
            f"{central_size} > {limits.max_central_directory_bytes}"
        )
    if central_offset + central_size > central_end:
        raise IntakeError("ZIP central directory lies outside the container")
    central_start = central_end - central_size
    snapshot.seek(central_start)
    counted_entries = 0
    remaining = central_size
    while remaining:
        if remaining < 4:
            raise IntakeError("ZIP central directory is truncated")
        signature = snapshot.read(4)
        if signature == b"PK\x05\x05":
            if remaining < 6:
                raise IntakeError("ZIP central-directory signature is truncated")
            signature_size_raw = snapshot.read(2)
            signature_size = struct.unpack("<H", signature_size_raw)[0]
            if remaining != 6 + signature_size:
                raise IntakeError("ZIP central-directory signature has an invalid size")
            snapshot.seek(signature_size, os.SEEK_CUR)
            remaining = 0
            break
        if signature != b"PK\x01\x02" or remaining < 46:
            raise IntakeError("ZIP central directory contains an invalid entry record")
        fixed_tail = snapshot.read(42)
        fields = struct.unpack("<6H3L5H2L", fixed_tail)
        name_size, extra_size, comment_size = fields[9:12]
        disk_start = fields[12]
        variable_size = name_size + extra_size + comment_size
        record_size = 46 + variable_size
        if disk_start != 0:
            raise IntakeError("multi-disk ZIP collections are not accepted")
        if record_size > remaining:
            raise IntakeError("ZIP central-directory entry is truncated")
        counted_entries += 1
        if counted_entries > limits.max_archive_entries:
            raise IntakeError(
                f"ZIP collection exceeds max_archive_entries: "
                f"{counted_entries} > {limits.max_archive_entries}"
            )
        snapshot.seek(variable_size, os.SEEK_CUR)
        remaining -= record_size
    if counted_entries != entry_count:
        raise IntakeError("ZIP central-directory entry count is inconsistent")
    snapshot.seek(0)


def _artifact_type(relative_path: str) -> str:
    lower = relative_path.casefold()
    name = PurePosixPath(lower).name
    if lower.endswith(".evtx"):
        return "windows.evtx"
    if name in {"$mft", "$usnjrnl", "$logfile"}:
        return "windows.ntfs"
    if name in {"ntuser.dat", "usrclass.dat", "system", "software", "sam", "security"}:
        return "windows.registry"
    if lower.endswith(".pf"):
        return "windows.prefetch"
    if "cloudtrail" in lower and lower.endswith((".json", ".json.gz")):
        return "cloud.aws.cloudtrail"
    if "kubernetes" in lower or "/k8s/" in f"/{lower}/" or "audit.k8s" in lower:
        return "container.kubernetes"
    if lower.endswith((".pcap", ".pcapng")):
        return "network.capture"
    if lower.endswith((".log", ".txt", ".json", ".jsonl", ".csv")):
        return "structured.log"
    return "collector.other"


def _normalized_member(name: str) -> str:
    if "\\" in name or "\x00" in name:
        raise IntakeError(f"archive member path is not normalized: {name!r}")
    path = PurePosixPath(name)
    normalized = path.as_posix()
    if path.is_absolute() or ".." in path.parts or normalized in {"", "."}:
        raise IntakeError(f"archive member path escapes the collection: {name!r}")
    return normalized.rstrip("/")


def _directory_paths(root_fd: int) -> Iterable[str]:
    """Enumerate regular files beneath a held root descriptor."""
    for current, directories, files, current_fd in os.fwalk(
        ".", follow_symlinks=False, dir_fd=root_fd
    ):
        directories.sort()
        base = "" if current == "." else PurePosixPath(current).as_posix().removeprefix("./")
        for name in directories:
            relative = f"{base}/{name}" if base else name
            mode = os.stat(name, dir_fd=current_fd, follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode):
                raise IntakeError(
                    f"symbolic links are not accepted in collections: {relative}"
                )
            if not stat.S_ISDIR(mode):
                raise IntakeError(f"collection entry is not a directory: {relative}")
        for name in sorted(files):
            relative = f"{base}/{name}" if base else name
            mode = os.stat(name, dir_fd=current_fd, follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode):
                raise IntakeError(
                    f"symbolic links are not accepted in collections: {relative}"
                )
            if not stat.S_ISREG(mode):
                raise IntakeError(f"collection member is not a regular file: {relative}")
            yield relative


def _read_directory(root_fd: int, limits: IntakeLimits) -> tuple[tuple[IntakeEntry, ...], int]:
    entries: list[IntakeEntry] = []
    total = 0
    seen: set[str] = set()
    for relative in _directory_paths(root_fd):
        folded = relative.casefold()
        if folded in seen:
            raise IntakeError(f"case-folding path collision in collection: {relative}")
        seen.add(folded)
        with _open_directory_member(root_fd, relative) as member_fd:
            size = os.fstat(member_fd).st_size
            if size > limits.max_file_bytes:
                raise IntakeError(f"collection member exceeds max_file_bytes: {relative}")
            total += size
            if len(entries) + 1 > limits.max_files or total > limits.max_total_bytes:
                raise IntakeError("collection exceeds configured file or byte limits")
            digest, actual_size = _hash_descriptor(member_fd, size)
        entries.append(
            IntakeEntry(
                relative_path=relative,
                size_bytes=actual_size,
                sha256=digest,
                artifact_type=_artifact_type(relative),
                storage="file",
            )
        )
    return tuple(sorted(entries, key=lambda item: item.relative_path)), total


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _read_zip(
    archive: zipfile.ZipFile, limits: IntakeLimits
) -> tuple[tuple[IntakeEntry, ...], int]:
    entries: list[IntakeEntry] = []
    total = 0
    seen: set[str] = set()
    for info in sorted(archive.infolist(), key=lambda item: item.filename):
        if info.is_dir():
            continue
        relative = _normalized_member(info.filename)
        if _is_zip_symlink(info):
            raise IntakeError(f"archive symbolic link is not accepted: {relative}")
        if info.flag_bits & 0x1:
            raise IntakeError(f"encrypted archive member is not accepted: {relative}")
        folded = relative.casefold()
        if folded in seen:
            raise IntakeError(f"duplicate or case-folding archive path: {relative}")
        seen.add(folded)
        if info.file_size > limits.max_file_bytes:
            raise IntakeError(f"archive member exceeds max_file_bytes: {relative}")
        if info.compress_size == 0 and info.file_size > 0:
            raise IntakeError(f"archive member has an unsafe compression ratio: {relative}")
        if info.compress_size and info.file_size / info.compress_size > limits.max_archive_ratio:
            raise IntakeError(f"archive member exceeds max_archive_ratio: {relative}")
        total += info.file_size
        if len(entries) + 1 > limits.max_files or total > limits.max_total_bytes:
            raise IntakeError("collection exceeds configured file or byte limits")
        digest = hashlib.sha256()
        read_size = 0
        with archive.open(info, "r") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                read_size += len(chunk)
                if read_size > info.file_size:
                    raise IntakeError(
                        f"archive member expanded past declared size: {relative}"
                    )
        if read_size != info.file_size:
            raise IntakeError(f"archive member size mismatch: {relative}")
        entries.append(
            IntakeEntry(
                relative_path=relative,
                size_bytes=read_size,
                sha256="sha256:" + digest.hexdigest(),
                artifact_type=_artifact_type(relative),
                storage="zip_member",
            )
        )
    return tuple(entries), total


def _format_from_names(names: set[str]) -> CollectionFormat:
    lowered = {name.casefold() for name in names}
    velociraptor = any(
        name.endswith("collection_context.json")
        or name.endswith("uploads.json")
        or name.startswith("uploads/")
        for name in lowered
    )
    kape = any(
        name.endswith("_kape.log") or name.endswith("kape.log") or "!basiccollection" in name
        for name in lowered
    )
    if velociraptor == kape:
        reason = "ambiguous" if velociraptor else "unrecognized"
        raise IntakeError(
            f"{reason} collection format; specify --format kape or --format velociraptor"
        )
    return "velociraptor" if velociraptor else "kape"


def _directory_member_bytes(
    root_fd: int,
    entry: IntakeEntry,
    limit: int,
) -> bytes | None:
    if entry.size_bytes > limit:
        return None
    with _open_directory_member(root_fd, entry.relative_path) as member_fd:
        content, digest = _read_descriptor(
            member_fd,
            expected_size=entry.size_bytes,
            max_bytes=limit,
        )
    if digest != entry.sha256:
        raise IntakeError(f"collection member changed: {entry.relative_path}")
    return content


def _zip_member_bytes(
    archive: zipfile.ZipFile,
    entry: IntakeEntry,
    limit: int,
) -> bytes | None:
    if entry.size_bytes > limit:
        return None
    matches = [info for info in archive.infolist() if info.filename == entry.relative_path]
    if len(matches) != 1:
        raise IntakeError(f"archive member is missing or duplicated: {entry.relative_path}")
    info = matches[0]
    if info.file_size != entry.size_bytes:
        raise IntakeError(f"archive member size changed: {entry.relative_path}")
    digest = hashlib.sha256()
    content = bytearray()
    with archive.open(info, "r") as handle:
        while chunk := handle.read(min(1024 * 1024, limit + 1 - len(content))):
            content.extend(chunk)
            digest.update(chunk)
            if len(content) > limit:
                raise IntakeError(
                    f"archive member expanded past requested limit: {entry.relative_path}"
                )
    if len(content) != entry.size_bytes:
        raise IntakeError(f"archive member size mismatch: {entry.relative_path}")
    actual_digest = "sha256:" + digest.hexdigest()
    if actual_digest != entry.sha256:
        raise IntakeError(f"archive member changed: {entry.relative_path}")
    return bytes(content)


def _first_name(entries: tuple[IntakeEntry, ...], suffixes: tuple[str, ...]) -> str | None:
    for entry in entries:
        if entry.relative_path.casefold().endswith(suffixes):
            return entry.relative_path
    return None


def _entry_by_name(entries: tuple[IntakeEntry, ...], name: str | None) -> IntakeEntry | None:
    if name is None:
        return None
    return next((entry for entry in entries if entry.relative_path == name), None)


def _mapping_value(raw: Mapping[str, object], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = raw.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    request = raw.get("Request")
    if isinstance(request, dict):
        return _mapping_value(cast(Mapping[str, object], request), names)
    return None


def _provenance(
    collection_format: CollectionFormat,
    entries: tuple[IntakeEntry, ...],
    assertions: Mapping[str, str | None],
    metadata: bytes | None,
) -> CollectorProvenance:
    metadata_name = _first_name(
        entries,
        ("collection_context.json",)
        if collection_format == "velociraptor"
        else ("_kape.log", "kape.log"),
    )
    values: dict[str, str | None] = {
        "collector_version": None,
        "collection_id": None,
        "host": None,
        "acquisition_started": None,
        "acquisition_ended": None,
    }
    if metadata:
        if collection_format == "velociraptor":
            try:
                decoded = json.loads(metadata.decode("utf-8-sig"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                decoded = None
            if isinstance(decoded, dict):
                mapping = cast(Mapping[str, object], decoded)
                values.update(
                    {
                        "collector_version": _mapping_value(mapping, ("Version", "version")),
                        "collection_id": _mapping_value(
                            mapping, ("FlowId", "flow_id", "SessionId", "session_id")
                        ),
                        "host": _mapping_value(
                            mapping, ("Hostname", "hostname", "ClientId", "client_id")
                        ),
                        "acquisition_started": _mapping_value(
                            mapping, ("StartTime", "start_time", "Created")
                        ),
                        "acquisition_ended": _mapping_value(
                            mapping, ("EndTime", "end_time", "Updated")
                        ),
                    }
                )
        else:
            text = metadata.decode("utf-8-sig", errors="replace")
            patterns = {
                "collector_version": r"(?im)^\s*KAPE(?:\s+version)?\s*[:=]\s*(\S+)",
                "collection_id": r"(?im)^\s*(?:Collection|Run)\s*ID\s*[:=]\s*(\S+)",
                "host": r"(?im)^\s*(?:Host|Computer)\s*(?:Name)?\s*[:=]\s*(\S+)",
            }
            for key, pattern in patterns.items():
                match = re.search(pattern, text)
                values[key] = match.group(1) if match else None
    examiner_assertions = tuple(
        ExaminerAssertion(field=cast(AssertionField, key), value=value.strip())
        for key, value in sorted(assertions.items())
        if value is not None and value.strip()
    )
    return CollectorProvenance(
        collector=collection_format,
        **values,
        metadata_source=metadata_name,
        metadata_sha256=_digest_bytes(metadata) if metadata is not None else None,
        assertion_source="collector_metadata" if metadata is not None else "format_only",
        examiner_assertions=examiner_assertions,
    )


def _manifest_hash(value: dict[str, object]) -> str:
    copied = dict(value)
    integrity = dict(cast(dict[str, str], copied.get("integrity", {})))
    integrity.pop("manifest_hash", None)
    copied["integrity"] = integrity
    return _digest_bytes(b"mulder.collection-intake:v1\0" + _canonical_json(copied))


def _collection_digest(manifest: IntakeManifest) -> str:
    return _digest_bytes(
        b"mulder.collection-content:v1\0" + _canonical_json(_content_identity(manifest))
    )


def _content_identity(manifest: IntakeManifest) -> dict[str, object]:
    """Return only evidence-derived identity, excluding examiner assertions."""
    provenance = manifest.provenance.model_dump(mode="json")
    provenance.pop("examiner_assertions", None)
    return {
        "case_id": manifest.case_id,
        "source_kind": manifest.source_kind,
        "source_sha256": manifest.source_sha256,
        "collection_format": manifest.collection_format,
        "provenance": provenance,
        "entries": [entry.model_dump(mode="json") for entry in manifest.entries],
        "file_count": manifest.file_count,
        "total_bytes": manifest.total_bytes,
    }


def _verify_manifest_commitments(manifest: IntakeManifest) -> None:
    raw = cast(
        dict[str, object],
        manifest.model_dump(mode="json", by_alias=True),
    )
    if manifest.integrity.get("manifest_hash") != _manifest_hash(raw):
        raise IntakeError("intake manifest integrity check failed")
    if manifest.collection_digest != _collection_digest(manifest):
        raise IntakeError("intake collection commitment is invalid")


def _verification_limits(manifest: IntakeManifest) -> IntakeLimits:
    largest = max((entry.size_bytes for entry in manifest.entries), default=0)
    return IntakeLimits(
        max_files=max(1, manifest.file_count),
        max_total_bytes=max(1, manifest.total_bytes),
        max_file_bytes=max(1, largest),
        max_archive_ratio=10_000,
    )


def _entry_bytes_identity(entry: IntakeEntry) -> tuple[str, int, str, str]:
    return (entry.relative_path, entry.size_bytes, entry.sha256, entry.storage)


def verify_intake_source(manifest: IntakeManifest) -> None:
    """Verify the complete live source against a committed intake manifest.

    The check is exact: missing, additional, renamed, linked, or changed members
    fail. ZIP verification uses one stable snapshot for the container and every
    decompressed member.
    """
    _verify_manifest_commitments(manifest)
    source = Path(manifest.source_path)
    try:
        mode = os.lstat(source).st_mode
    except OSError as exc:
        raise IntakeError(f"intake source is unavailable: {source}") from exc

    if manifest.source_kind == "directory":
        if not stat.S_ISDIR(mode):
            raise IntakeError("intake directory source changed type")
        with _open_nofollow(source, directory=True) as root_fd:
            actual_paths = tuple(_directory_paths(root_fd))
            expected_paths = tuple(entry.relative_path for entry in manifest.entries)
            if sorted(actual_paths) != sorted(expected_paths):
                raise IntakeError("intake directory inventory changed")
            for entry in manifest.entries:
                if entry.storage != "file":
                    raise IntakeError("directory intake contains a non-file entry")
                with _open_directory_member(root_fd, entry.relative_path) as member_fd:
                    digest, size = _hash_descriptor(member_fd, entry.size_bytes)
                if digest != entry.sha256 or size != entry.size_bytes:
                    raise IntakeError(f"intake member changed: {entry.relative_path}")
        return

    if not stat.S_ISREG(mode):
        raise IntakeError("intake ZIP source changed type")
    if manifest.source_sha256 is None:
        raise IntakeError("ZIP intake is missing its container commitment")
    verification_limits = _verification_limits(manifest)
    try:
        with _zip_snapshot(
            source, max_bytes=verification_limits.max_container_bytes
        ) as (snapshot, source_digest, source_size):
            if source_digest != manifest.source_sha256:
                raise IntakeError("ZIP intake source changed")
            _preflight_zip_directory(snapshot, source_size, verification_limits)
            with zipfile.ZipFile(snapshot) as archive:
                entries, _total = _read_zip(archive, verification_limits)
    except (NotImplementedError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise IntakeError(f"intake ZIP cannot be verified safely: {exc}") from exc
    actual = tuple(_entry_bytes_identity(entry) for entry in entries)
    expected = tuple(_entry_bytes_identity(entry) for entry in manifest.entries)
    if actual != expected:
        raise IntakeError("ZIP intake member inventory changed")


def read_intake_member(
    manifest: IntakeManifest,
    relative_path: str,
    *,
    max_bytes: int,
) -> bytes:
    """Return one fully verified member, never a truncated or unverified prefix."""
    if max_bytes < 1:
        raise IntakeError("max_bytes must be positive")
    normalized = _normalized_member(relative_path)
    entry = _entry_by_name(manifest.entries, normalized)
    if entry is None:
        raise IntakeError(f"intake member is not committed: {normalized}")
    if entry.size_bytes > max_bytes:
        raise IntakeError(
            f"intake member exceeds requested byte limit: {entry.size_bytes} > {max_bytes}"
        )

    verify_intake_source(manifest)
    source = Path(manifest.source_path)
    if manifest.source_kind == "directory":
        with _open_nofollow(source, directory=True) as root_fd:
            content = _directory_member_bytes(root_fd, entry, max_bytes)
    else:
        if manifest.source_sha256 is None:
            raise IntakeError("ZIP intake is missing its container commitment")
        verification_limits = _verification_limits(manifest)
        try:
            with _zip_snapshot(
                source, max_bytes=verification_limits.max_container_bytes
            ) as (snapshot, source_digest, source_size):
                if source_digest != manifest.source_sha256:
                    raise IntakeError("ZIP intake source changed")
                _preflight_zip_directory(snapshot, source_size, verification_limits)
                with zipfile.ZipFile(snapshot) as archive:
                    content = _zip_member_bytes(archive, entry, max_bytes)
        except (
            NotImplementedError,
            RuntimeError,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
        ) as exc:
            raise IntakeError(f"intake ZIP member cannot be read safely: {exc}") from exc
    if content is None:
        raise IntakeError(f"intake member exceeds requested byte limit: {normalized}")
    return content


def materialize_intake(
    manifest: IntakeManifest,
    destination: Path,
    *,
    max_file_bytes: int,
    max_total_bytes: int,
) -> tuple[str, ...]:
    """Create one bounded verified read-only view of a committed intake.

    ZIP inputs are copied to one stable snapshot and never delegated to an
    external fallback extractor.  ``destination`` must be absent or empty so
    committed members cannot be merged with stale or attacker-created files.
    """
    if max_file_bytes < 1 or max_total_bytes < 1:
        raise IntakeError("materialization byte limits must be positive")
    if manifest.total_bytes > max_total_bytes:
        raise IntakeError("intake exceeds the safe total materialization limit")
    if any(entry.size_bytes > max_file_bytes for entry in manifest.entries):
        raise IntakeError("intake member exceeds the safe materialization limit")
    destination = Path(destination).expanduser().resolve(strict=False)
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise IntakeError("intake materialization destination must be absent or empty")
    destination.mkdir(parents=True, exist_ok=True)

    def persist(entry: IntakeEntry, content: bytes | None) -> None:
        if content is None:
            raise IntakeError(
                f"intake member exceeds materialization limit: {entry.relative_path}"
            )
        target = destination.joinpath(*PurePosixPath(entry.relative_path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        target.chmod(0o444)

    _verify_manifest_commitments(manifest)
    source = Path(manifest.source_path)
    if manifest.source_kind == "directory":
        with _open_nofollow(source, directory=True) as root_fd:
            actual_paths = tuple(_directory_paths(root_fd))
            expected_paths = tuple(entry.relative_path for entry in manifest.entries)
            if sorted(actual_paths) != sorted(expected_paths):
                raise IntakeError("intake directory inventory changed")
            for entry in manifest.entries:
                persist(
                    entry,
                    _directory_member_bytes(root_fd, entry, max_file_bytes),
                )
    else:
        if manifest.source_sha256 is None:
            raise IntakeError("ZIP intake is missing its container commitment")
        verification_limits = _verification_limits(manifest)
        try:
            with _zip_snapshot(
                source, max_bytes=verification_limits.max_container_bytes
            ) as (snapshot, source_digest, source_size):
                if source_digest != manifest.source_sha256:
                    raise IntakeError("ZIP intake source changed")
                _preflight_zip_directory(snapshot, source_size, verification_limits)
                with zipfile.ZipFile(snapshot) as archive:
                    actual_entries, _total = _read_zip(
                        archive,
                        verification_limits,
                    )
                    if tuple(map(_entry_bytes_identity, actual_entries)) != tuple(
                        map(_entry_bytes_identity, manifest.entries)
                    ):
                        raise IntakeError("ZIP intake member inventory changed")
                    for entry in manifest.entries:
                        persist(
                            entry,
                            _zip_member_bytes(archive, entry, max_file_bytes),
                        )
        except (
            NotImplementedError,
            RuntimeError,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
        ) as exc:
            raise IntakeError(f"intake ZIP cannot be materialized safely: {exc}") from exc
    return tuple(entry.relative_path for entry in manifest.entries)


def scan_collection(
    source: Path,
    case_id: str,
    *,
    collection_format: Literal["auto", "kape", "velociraptor"] = "auto",
    limits: IntakeLimits | None = None,
    collector_version: str | None = None,
    collection_id: str | None = None,
    host: str | None = None,
) -> IntakeManifest:
    """Read and commit one collection without writing or registering it."""
    if not case_id or Path(case_id).name != case_id or case_id in {".", ".."}:
        raise IntakeError("case_id must be one safe path segment")
    original = Path(source).expanduser()
    if original.is_symlink():
        raise IntakeError("collection source cannot be a symbolic link")
    try:
        resolved = original.resolve(strict=True)
    except OSError as exc:
        raise IntakeError(f"collection source is unavailable: {original}") from exc
    limits = limits or IntakeLimits()
    try:
        source_mode = os.lstat(resolved).st_mode
    except OSError as exc:
        raise IntakeError(f"collection source is unavailable: {resolved}") from exc
    metadata: bytes | None
    if stat.S_ISDIR(source_mode):
        source_kind: SourceKind = "directory"
        with _open_nofollow(resolved, directory=True) as root_fd:
            entries, total = _read_directory(root_fd, limits)
            if not entries:
                raise IntakeError("collection contains no regular files")
            selected_format = (
                _format_from_names({entry.relative_path for entry in entries})
                if collection_format == "auto"
                else collection_format
            )
            metadata_name = _first_name(
                entries,
                ("collection_context.json",)
                if selected_format == "velociraptor"
                else ("_kape.log", "kape.log"),
            )
            metadata_entry = _entry_by_name(entries, metadata_name)
            metadata = (
                _directory_member_bytes(root_fd, metadata_entry, limits.max_metadata_bytes)
                if metadata_entry is not None
                else None
            )
        source_sha256: str | None = None
    elif stat.S_ISREG(source_mode):
        source_kind = "zip"
        try:
            with _zip_snapshot(
                resolved, max_bytes=limits.max_container_bytes
            ) as (snapshot, source_sha256, source_size):
                _preflight_zip_directory(snapshot, source_size, limits)
                with zipfile.ZipFile(snapshot) as archive:
                    entries, total = _read_zip(archive, limits)
                    if not entries:
                        raise IntakeError("collection contains no regular files")
                    selected_format = (
                        _format_from_names({entry.relative_path for entry in entries})
                        if collection_format == "auto"
                        else collection_format
                    )
                    metadata_name = _first_name(
                        entries,
                        ("collection_context.json",)
                        if selected_format == "velociraptor"
                        else ("_kape.log", "kape.log"),
                    )
                    metadata_entry = _entry_by_name(entries, metadata_name)
                    metadata = (
                        _zip_member_bytes(
                            archive, metadata_entry, limits.max_metadata_bytes
                        )
                        if metadata_entry is not None
                        else None
                    )
        except (
            NotImplementedError,
            RuntimeError,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
        ) as exc:
            raise IntakeError(f"collection ZIP cannot be read safely: {exc}") from exc
    else:
        raise IntakeError("collection source must be a directory or ZIP archive")
    provenance = _provenance(
        selected_format,
        entries,
        {
            "collector_version": collector_version,
            "collection_id": collection_id,
            "host": host,
        },
        metadata,
    )
    content = {
        "case_id": case_id,
        "source_kind": source_kind,
        "source_sha256": source_sha256,
        "collection_format": selected_format,
        "provenance": provenance.model_dump(mode="json"),
        "entries": [entry.model_dump(mode="json") for entry in entries],
        "file_count": len(entries),
        "total_bytes": total,
    }
    identity = dict(content)
    identity_provenance = provenance.model_dump(mode="json")
    identity_provenance.pop("examiner_assertions", None)
    identity["provenance"] = identity_provenance
    collection_digest = _digest_bytes(
        b"mulder.collection-content:v1\0" + _canonical_json(identity)
    )
    raw: dict[str, object] = {
        "schema": INTAKE_SCHEMA,
        "version": INTAKE_VERSION,
        **content,
        "source_path": str(resolved),
        "collection_digest": collection_digest,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "integrity": {"algorithm": "sha256"},
    }
    cast(dict[str, str], raw["integrity"])["manifest_hash"] = _manifest_hash(raw)
    return IntakeManifest.model_validate(raw)


def _atomic_create(path: Path, content: bytes) -> None:
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as f:
            temporary = Path(f.name)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise
        temporary.unlink()
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def load_intake_manifest(path: Path) -> IntakeManifest:
    """Load and verify an intake manifest without touching its evidence."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeError(f"existing intake manifest is unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise IntakeError("existing intake manifest is not an object")
    try:
        manifest = IntakeManifest.model_validate(raw)
    except ValueError as exc:
        raise IntakeError(f"existing intake manifest is invalid: {exc}") from exc
    _verify_manifest_commitments(manifest)
    verify_intake_source(manifest)
    return manifest


def _register_evidence(manifest: IntakeManifest, db_dir: Path) -> tuple[bool, int]:
    db_path = db_dir / f"{manifest.case_id}.db"
    database_created = not db_path.exists()
    db = (
        CaseDB.create(manifest.case_id, manifest.source_path, db_dir)
        if database_created
        else CaseDB.open(manifest.case_id, db_dir)
    )
    try:
        metadata = db.get_case_metadata()
        if metadata.case_id != manifest.case_id:
            raise IntakeError("case database identity does not match intake case")
        registered_root = Path(metadata.evidence_root).expanduser().resolve(strict=False)
        manifest_root = Path(manifest.source_path).expanduser().resolve(strict=False)
        if registered_root != manifest_root:
            raise IntakeError("case database evidence root does not match intake source")
        existing: set[tuple[str, str, int]] = set()
        for row in db.get_evidence_registry():
            size_value = row["size_bytes"]
            if not isinstance(size_value, int):
                raise IntakeError("case evidence registry contains an invalid size")
            existing.add((str(row["file_path"]), str(row["sha256"]), size_value))
        registrations: list[tuple[str, str, int]] = []
        source = Path(manifest.source_path)
        if manifest.source_kind == "zip":
            if manifest.source_sha256 is None:
                raise IntakeError("ZIP intake is missing its container commitment")
            with _zip_snapshot(
                source,
                max_bytes=_verification_limits(manifest).max_container_bytes,
            ) as (_snapshot, actual_digest, actual_size):
                pass
            if actual_digest != manifest.source_sha256:
                raise IntakeError("ZIP collection changed after manifest creation")
            registrations.append((str(source), manifest.source_sha256, actual_size))
        else:
            with _open_nofollow(source, directory=True) as root_fd:
                for entry in manifest.entries:
                    with _open_directory_member(root_fd, entry.relative_path) as member_fd:
                        actual_digest, actual_size = _hash_descriptor(
                            member_fd, entry.size_bytes
                        )
                    if actual_digest != entry.sha256:
                        raise IntakeError(
                            f"collection member changed after manifest creation: "
                            f"{entry.relative_path}"
                        )
                    member = source / entry.relative_path
                    registrations.append((str(member), entry.sha256, actual_size))
        missing = [item for item in registrations if item not in existing]
        for file_path, digest, size in missing:
            db.register_evidence_file(file_path, digest, size)
    finally:
        db.close()
    return database_created, len(missing)


def ingest_collection(
    source: Path,
    case_id: str,
    db_dir: Path,
    *,
    collection_format: Literal["auto", "kape", "velociraptor"] = "auto",
    limits: IntakeLimits | None = None,
    collector_version: str | None = None,
    collection_id: str | None = None,
    host: str | None = None,
) -> IntakeResult:
    """Create an immutable manifest and idempotently register its evidence."""
    target_dir = Path(db_dir).expanduser().resolve(strict=False)
    manifest_path = target_dir / f"{case_id}.intake.json"
    scanned = scan_collection(
        source,
        case_id,
        collection_format=collection_format,
        limits=limits,
        collector_version=collector_version,
        collection_id=collection_id,
        host=host,
    )
    created = False
    if manifest_path.exists():
        existing = load_intake_manifest(manifest_path)
        if existing.case_id != case_id or existing.collection_digest != scanned.collection_digest:
            raise IntakeError(
                "case already has a different immutable intake; choose a new case_id"
            )
        selected = existing
    else:
        content = scanned.model_dump_json(indent=2, by_alias=True).encode("utf-8") + b"\n"
        try:
            _atomic_create(manifest_path, content)
            selected = scanned
            created = True
        except FileExistsError:
            selected = load_intake_manifest(manifest_path)
            if selected.collection_digest != scanned.collection_digest:
                raise IntakeError("concurrent intake created different case content") from None
    database_created, registered = _register_evidence(selected, target_dir)
    return IntakeResult(
        manifest_path=str(manifest_path),
        collection_digest=selected.collection_digest,
        created=created,
        database_created=database_created,
        registered_files=registered,
    )


__all__ = [
    "CollectorProvenance",
    "ExaminerAssertion",
    "INTAKE_SCHEMA",
    "INTAKE_VERSION",
    "IntakeEntry",
    "IntakeError",
    "IntakeLimits",
    "IntakeManifest",
    "IntakeResult",
    "ingest_collection",
    "load_intake_manifest",
    "read_intake_member",
    "scan_collection",
    "verify_intake_source",
]
