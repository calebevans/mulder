"""Bounded read-only projections of an immutable evidence intake manifest."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Final

from mulder.adapters.intake import IntakeEntry, IntakeManifest
from mulder.patterns import DISK_IMAGE_EXTS

CATALOG_PAGE_MAX_BYTES: Final[int] = 32 * 1024
CATALOG_PAGE_MAX_ITEMS: Final[int] = 128
_COMPACT_PATH_MAX_BYTES: Final[int] = 256
_COMPACT_METADATA_TEXT_MAX_BYTES: Final[int] = 512

_MEMORY_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {".raw", ".vmem", ".mem", ".img", ".dmp", ".lime", ".001"}
)
_ARCHIVE_SUFFIXES: Final[tuple[str, ...]] = (
    ".7z",
    ".zip",
    ".gz",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".xz",
    ".bz2",
    ".tar.bz2",
    ".rar",
    ".zst",
)
_NETWORK_EXTENSIONS: Final[frozenset[str]] = frozenset({".pcap", ".pcapng", ".cap"})


def evidence_types(entry: IntakeEntry) -> tuple[str, ...]:
    """Return conservative extraction categories for one committed entry."""
    lower = entry.relative_path.casefold()
    name = PurePosixPath(lower).name
    suffix = PurePosixPath(lower).suffix
    kinds: list[str] = []
    if lower.endswith(_ARCHIVE_SUFFIXES):
        kinds.append("archive")
    if suffix in _NETWORK_EXTENSIONS or entry.artifact_type == "network.capture":
        kinds.append("network_capture")
    if suffix in DISK_IMAGE_EXTS:
        kinds.append("disk_image")
    if suffix in _MEMORY_EXTENSIONS:
        kinds.append("memory_dump")
    if "autorun" in name and suffix in {".csv", ".tsv"}:
        kinds.append("autoruns")
    if suffix == ".evtx" or entry.artifact_type == "windows.evtx":
        kinds.append("event_log")
    if not kinds:
        kinds.append(entry.artifact_type.replace(".", "_"))
    return tuple(dict.fromkeys(kinds))


def committed_entry_path(manifest: IntakeManifest, entry: IntakeEntry) -> str:
    """Return the only live path corresponding to a committed entry."""
    source = Path(manifest.source_path)
    if manifest.source_kind == "directory":
        return str(source.joinpath(*PurePosixPath(entry.relative_path).parts))
    return str(source)


def extraction_entries(manifest: IntakeManifest) -> tuple[dict[str, object], ...]:
    """Return exact manifest-backed inputs suitable for extraction planning.

    A ZIP intake is represented by its committed outer container.  Its members
    are not live filesystem paths until the authorized archive tool creates a
    verified materialization.
    """
    if manifest.source_kind == "zip":
        return (
            {
                "artifact_id": f"{manifest.collection_digest}:container",
                "path": manifest.source_path,
                "relative_path": Path(manifest.source_path).name,
                "sha256": manifest.source_sha256,
                "size_bytes": None,
                "evidence_types": ["archive"],
                "storage": "zip",
                "committed_members": manifest.file_count,
            },
        )
    rows: list[dict[str, object]] = []
    for index, entry in enumerate(manifest.entries):
        rows.append(
            {
                "artifact_id": f"{manifest.collection_digest}:{index}",
                "path": committed_entry_path(manifest, entry),
                "relative_path": entry.relative_path,
                "sha256": entry.sha256,
                "size_bytes": entry.size_bytes,
                "evidence_types": list(evidence_types(entry)),
                "storage": entry.storage,
            }
        )
    return tuple(rows)


def _bounded_text(value: str, *, max_bytes: int) -> str:
    """Bound a non-authorizing display string without invalid UTF-8."""
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    marker = f"…[truncated;{digest}]"
    prefix_bytes = max(0, max_bytes - len(marker.encode("utf-8")))
    prefix = encoded[:prefix_bytes].decode("utf-8", errors="ignore")
    return prefix + marker


def _compact_relative_path(relative_path: str) -> tuple[str, str]:
    """Return a bounded display path and its independent commitment."""
    encoded = relative_path.encode("utf-8")
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    return _bounded_text(relative_path, max_bytes=_COMPACT_PATH_MAX_BYTES), digest


def _compact_catalog_rows(manifest: IntakeManifest, index: int) -> Iterator[dict[str, object]]:
    """Yield increasingly small rows retaining tool-authorizing commitments."""
    entry = manifest.entries[index]
    relative_path, relative_path_sha256 = _compact_relative_path(entry.relative_path)
    common: dict[str, object] = {
        "artifact_id": f"{manifest.collection_digest}:{index}",
        "sha256": entry.sha256,
        "size_bytes": entry.size_bytes,
        "storage": entry.storage,
        "entry_truncated": True,
    }
    yield {
        **common,
        "relative_path": relative_path,
        "relative_path_sha256": relative_path_sha256,
        "artifact_type": _bounded_text(entry.artifact_type, max_bytes=128),
        "evidence_types": list(evidence_types(entry)),
    }
    yield {**common, "relative_path_sha256": relative_path_sha256}
    yield common


def manifest_catalog_page(
    manifest: IntakeManifest,
    *,
    cursor: int = 0,
    max_items: int = CATALOG_PAGE_MAX_ITEMS,
    max_bytes: int = CATALOG_PAGE_MAX_BYTES,
) -> dict[str, object]:
    """Project one deterministic JSON-bounded page from ``manifest``.

    The projection is derived solely from the already prepared manifest.  It
    never enumerates the live evidence path or a mutable extracted directory.
    """
    if cursor < 0 or cursor > manifest.file_count:
        raise ValueError("catalog cursor is outside the committed inventory")
    if max_items < 1 or max_items > CATALOG_PAGE_MAX_ITEMS:
        raise ValueError(f"max_items must be between 1 and {CATALOG_PAGE_MAX_ITEMS}")
    if max_bytes < 1024 or max_bytes > CATALOG_PAGE_MAX_BYTES:
        raise ValueError(f"max_bytes must be between 1024 and {CATALOG_PAGE_MAX_BYTES}")

    counts: Counter[str] = Counter()
    for entry in manifest.entries:
        counts.update(evidence_types(entry))
    raw_provenance = manifest.provenance.model_dump(
        mode="json",
        exclude={"examiner_assertions"},
    )
    provenance = {
        key: (
            _bounded_text(value, max_bytes=_COMPACT_METADATA_TEXT_MAX_BYTES)
            if isinstance(value, str)
            else value
        )
        for key, value in raw_provenance.items()
    }
    base: dict[str, object] = {
        "schema": "mulder.evidence-catalog-page",
        "version": 1,
        "case_id": _bounded_text(
            manifest.case_id,
            max_bytes=_COMPACT_METADATA_TEXT_MAX_BYTES,
        ),
        "evidence_root": _bounded_text(
            manifest.source_path,
            max_bytes=_COMPACT_METADATA_TEXT_MAX_BYTES * 2,
        ),
        "source_kind": manifest.source_kind,
        "collection_format": manifest.collection_format,
        "collection_digest": manifest.collection_digest,
        "provenance": provenance,
        "file_count": manifest.file_count,
        "total_bytes": manifest.total_bytes,
        "evidence_type_counts": dict(sorted(counts.items())),
        "cursor": cursor,
        "entries": [],
        "next_cursor": cursor,
        # Reserve the maximum decimal width while fitting rows so the final
        # page-size field cannot evict an otherwise fitting entry.
        "page_bytes": max_bytes,
    }
    encoded_base = json.dumps(base, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded_base) > max_bytes:
        raise ValueError("catalog metadata exceeds the bounded page size")

    page_entries: list[dict[str, object]] = []
    for index in range(cursor, min(manifest.file_count, cursor + max_items)):
        entry = manifest.entries[index]
        row: dict[str, object] = {
            "artifact_id": f"{manifest.collection_digest}:{index}",
            "relative_path": entry.relative_path,
            "sha256": entry.sha256,
            "size_bytes": entry.size_bytes,
            "artifact_type": entry.artifact_type,
            "evidence_types": list(evidence_types(entry)),
            "storage": entry.storage,
            "path": committed_entry_path(manifest, entry),
        }
        if manifest.source_kind == "zip":
            row["container_member"] = entry.relative_path
            row["requires_container_extraction"] = True
        candidate = dict(base)
        candidate["entries"] = [*page_entries, row]
        candidate["next_cursor"] = index + 1
        encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > max_bytes:
            if not page_entries:
                for compact_row in _compact_catalog_rows(manifest, index):
                    compact_candidate = dict(candidate)
                    compact_candidate["entries"] = [compact_row]
                    compact_encoded = json.dumps(
                        compact_candidate, sort_keys=True, separators=(",", ":")
                    ).encode()
                    if len(compact_encoded) <= max_bytes:
                        row = compact_row
                        encoded = compact_encoded
                        break
            if len(encoded) > max_bytes:
                if not page_entries:
                    raise ValueError(
                        "catalog page metadata leaves no room for a committed entry"
                    )
                break
        page_entries.append(row)

    next_cursor = cursor + len(page_entries)
    base["entries"] = page_entries
    base["next_cursor"] = next_cursor if next_cursor < manifest.file_count else None
    base["page_bytes"] = 0
    while True:
        encoded_size = len(
            json.dumps(base, sort_keys=True, separators=(",", ":")).encode()
        )
        if encoded_size > max_bytes:
            raise ValueError("catalog page exceeded the bounded page size")
        if base["page_bytes"] == encoded_size:
            break
        base["page_bytes"] = encoded_size
    return base


__all__ = [
    "CATALOG_PAGE_MAX_BYTES",
    "CATALOG_PAGE_MAX_ITEMS",
    "committed_entry_path",
    "evidence_types",
    "extraction_entries",
    "manifest_catalog_page",
]
