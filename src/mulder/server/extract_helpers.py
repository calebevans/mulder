"""Shared helpers for Tier 2 on-demand extraction tools.

Provides ``extract_and_index`` (the store pipeline used by every
extraction tool) and ``mount_disk_image`` (a context manager for safely
mounting E01/raw disk images).
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path

from mulder.extractors.disk import _mount_image, _unmount_image
from mulder.models import WindowRow

logger = logging.getLogger(__name__)

_WINDOW_CHAR_BUDGET = 4096

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


@contextmanager
def mount_disk_image(image_path: str) -> Iterator[str]:
    """Mount a disk image (E01 or raw) read-only and yield the mount point.

    On exit, the image is unmounted and the temp directory cleaned up.
    Raises ``RuntimeError`` if the image cannot be mounted.
    """
    img = Path(image_path)
    mount_dir = Path(tempfile.mkdtemp(prefix="mulder_mount_"))
    mounted = False

    try:
        mounted = _mount_image(img, mount_dir)

        if not mounted:
            raise RuntimeError(f"Failed to mount disk image: {image_path}")

        yield str(mount_dir)
    finally:
        if mounted:
            _unmount_image(mount_dir)
        with suppress(OSError):
            shutil.rmtree(mount_dir, ignore_errors=True)
