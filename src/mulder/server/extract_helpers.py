"""Shared helpers for Tier 2 on-demand extraction tools.

Provides ``extract_and_index`` (the store pipeline used by every
extraction tool) and ``mount_disk_image`` (a context manager for safely
mounting E01/raw disk images with thread-safe caching).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from mulder.extractors.disk import _mount_image, _unmount_image
from mulder.models import WindowRow

logger = logging.getLogger(__name__)

_WINDOW_CHAR_BUDGET = 4096

# Chainsaw falls back to the whole event document for `event_data`, which is
# 2-4 KB of JSON. 400 characters cut everything past the first few keys --
# Image, ParentCommandLine, TargetUserName -- so the fields an analyst
# actually searches for were truncated away. 2000 still leaves room for the
# other nine columns inside one 4096-character window.
_RECORD_FIELD_CHARS = 2000


def _record_field(value: object) -> str:
    """Render one field of a structured record as a single-line string."""
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bool, int, float)):
        text = str(value)
    else:
        text = json.dumps(value, default=str, separators=(",", ":"), sort_keys=True)
    text = text.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return text[:_RECORD_FIELD_CHARS]


def format_records(
    records: Sequence[Mapping[str, object]],
    fields: Sequence[str] | None = None,
) -> list[str]:
    """Render structured tool output as one tab-separated line per record.

    ``extract_and_index`` stores exactly the text it is handed. Several tools
    handed it a summary -- "Total findings: 412" -- so not one rule name, host
    or command line ever reached the case database, and the FTS index could
    not answer the questions the tool was run to answer. This turns the
    records themselves into indexable text.

    One record per line matters twice over: the window builder splits on line
    boundaries, so no detection is cut in half, and timestamp extraction runs
    per window rather than finding a single timestamp for a whole summary.

    Args:
        records: The parsed records.
        fields: Field order to emit. When *None* each record uses its own key
            order, which is what tabular sources (LEAPP TSV) want.

    Returns:
        One tab-separated line per record. Non-scalar values are JSON-encoded
        so nested event data stays searchable; every field is truncated to
        keep one pathological value from filling a window.
    """
    lines: list[str] = []
    for record in records:
        keys = list(record) if fields is None else fields
        lines.append("\t".join(_record_field(record.get(k)) for k in keys))
    return lines


_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_PLASO_DATE_RE = re.compile(r"(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})")
_SYSLOG_RE = re.compile(
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})"
)
_SYSLOG_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _parse_timestamp(text: str, reference_year: int | None = None) -> str | None:
    """Best-effort timestamp extraction from a text window.

    Args:
        text: Raw text window to search for a recognizable timestamp.
        reference_year: Year to assume for syslog timestamps that omit a
            year field.  Falls back to the current year when *None*.
    """
    m = _ISO_RE.search(text)
    if m:
        try:
            return datetime.fromisoformat(m.group(0)).isoformat()
        except ValueError:
            pass

    m = _SYSLOG_RE.search(text)
    if m:
        month_str, day, hour, minute, second = m.groups()
        try:
            dt = datetime(
                year=reference_year or datetime.now().year,
                month=_SYSLOG_MONTHS[month_str],
                day=int(day),
                hour=int(hour),
                minute=int(minute),
                second=int(second),
            )
            return dt.isoformat()
        except ValueError:
            pass

    m = _PLASO_DATE_RE.search(text)
    if m:
        month, day, year, hour, minute, second = m.groups()
        try:
            dt = datetime(
                year=int(year),
                month=int(month),
                day=int(day),
                hour=int(hour),
                minute=int(minute),
                second=int(second),
            )
            return dt.isoformat()
        except ValueError:
            pass

    logger.debug("No timestamp pattern matched in window text (first 80 chars): %r", text[:80])
    return None


_INSERT_BATCH_SIZE = 5000


def extract_and_index(
    raw_output: str,
    source_name: str,
    source_path: str,
    extractor_name: str,
) -> dict[str, object]:
    """Split raw tool output into windows and store in the case DB.

    Registers a source, splits text into fixed-size windows (4 lines
    each), extracts timestamps, and inserts into the database in
    batches of ``_INSERT_BATCH_SIZE`` to bound peak memory.

    Returns a summary dict with ``source_name``, ``windows_indexed``,
    ``line_count``, and ``status``.
    """
    from mulder.server.app import get_ctx

    ctx = get_ctx()

    if not raw_output or not raw_output.strip():
        source_id = ctx.db.register_source(
            source_name=source_name,
            source_path=source_path,
            source_hash="blake2b:empty",
            extractor=extractor_name,
            line_count=0,
        )
        return {
            "source_name": source_name,
            "source_id": source_id,
            "windows_indexed": 0,
            "line_count": 0,
            "status": "indexed_empty",
        }

    original_line_count = raw_output.count("\n") + 1

    h = hashlib.blake2b(digest_size=32)
    chunk_size = 65536
    for i in range(0, len(raw_output), chunk_size):
        h.update(raw_output[i : i + chunk_size].encode())
    content_hash = "blake2b:" + h.hexdigest()

    source_id = ctx.db.register_source(
        source_name=source_name,
        source_path=source_path,
        source_hash=content_hash,
        extractor=extractor_name,
        line_count=original_line_count,
    )

    total_indexed = 0
    batch: list[WindowRow] = []
    budget = _WINDOW_CHAR_BUDGET

    for offset in range(0, len(raw_output), budget):
        chunk = raw_output[offset : offset + budget]
        if not chunk.strip():
            continue
        event_time = _parse_timestamp(chunk)
        batch.append(
            WindowRow(
                source_id=source_id,
                line_start=offset,
                line_end=offset + len(chunk),
                event_time=event_time,
                raw_text=chunk,
            )
        )
        if len(batch) >= _INSERT_BATCH_SIZE:
            ctx.db.insert_windows(source_id, batch)
            total_indexed += len(batch)
            batch = []

    del raw_output

    if batch:
        ctx.db.insert_windows(source_id, batch)
        total_indexed += len(batch)

    return {
        "source_name": source_name,
        "source_id": source_id,
        "windows_indexed": total_indexed,
        "line_count": original_line_count,
        "status": "indexed",
    }


@dataclass
class _MountEntry:
    """Internal bookkeeping for a single cached mount point."""

    mount_dir: Path
    refcount: int = 0
    ready: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None
    mounted: bool = False


class _MountCache:
    """Thread-safe cache that deduplicates concurrent disk image mounts.

    Each unique image path (canonicalized via ``os.path.realpath``) gets at
    most one active FUSE mount.  Concurrent callers block until the initial
    mount completes, then share the resulting mount point.  The mount is
    torn down only when the last caller releases it.
    """

    def __init__(self) -> None:
        """Initialize an empty cache with its protecting lock."""
        self._lock = threading.Lock()
        self._entries: dict[str, _MountEntry] = {}

    @contextmanager
    def acquire(self, image_path: str) -> Iterator[str]:
        """Yield a shared mount point for *image_path*, mounting if needed.

        The first caller performs the actual mount; subsequent concurrent
        callers for the same canonical path block until that mount finishes,
        then receive the same mount point.  On context exit the reference
        count is decremented, and the last caller unmounts and cleans up.

        Args:
            image_path: Filesystem path to the disk image file.

        Yields:
            The directory where the image is mounted.

        Raises:
            RuntimeError: If the underlying mount operation fails.
        """
        canonical = os.path.realpath(image_path)
        is_owner = False

        with self._lock:
            if canonical not in self._entries:
                mount_dir = Path(tempfile.mkdtemp(prefix="mulder_mount_"))
                self._entries[canonical] = _MountEntry(mount_dir=mount_dir)
                is_owner = True
            entry = self._entries[canonical]
            entry.refcount += 1

        if is_owner:
            try:
                mounted = _mount_image(Path(image_path), entry.mount_dir)
                if mounted:
                    entry.mounted = True
                else:
                    entry.error = RuntimeError(f"Failed to mount disk image: {image_path}")
            except Exception as exc:
                entry.error = exc
            finally:
                entry.ready.set()
        else:
            entry.ready.wait()

        if entry.error is not None:
            self._release(canonical, entry)
            raise RuntimeError(f"Failed to mount disk image: {image_path}") from entry.error

        try:
            yield str(entry.mount_dir)
        finally:
            self._release(canonical, entry)

    def _release(self, canonical: str, entry: _MountEntry) -> None:
        """Decrement refcount, unmounting and cleaning up if last user.

        Args:
            canonical: Canonical (realpath) cache key.
            entry: The mount entry being released.
        """
        do_cleanup = False
        with self._lock:
            entry.refcount -= 1
            if entry.refcount == 0:
                self._entries.pop(canonical, None)
                do_cleanup = True

        if do_cleanup:
            if entry.mounted:
                _unmount_image(entry.mount_dir)
            with suppress(OSError):
                shutil.rmtree(entry.mount_dir, ignore_errors=True)


_mount_cache = _MountCache()


@contextmanager
def mount_disk_image(image_path: str) -> Iterator[str]:
    """Mount a disk image (E01 or raw) read-only and yield the mount point.

    Uses a thread-safe cache so that concurrent callers for the same image
    share a single mount.  The image is unmounted and the temp directory
    cleaned up when the last caller exits.

    Raises ``RuntimeError`` if the image cannot be mounted.
    """
    with _mount_cache.acquire(image_path) as mount_point:
        yield mount_point
