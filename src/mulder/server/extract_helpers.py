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
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path

from mulder.extractors.disk import _detect_mount_offset
from mulder.models import WindowRow

logger = logging.getLogger(__name__)

_WINDOW_SIZE = 4

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


def _parse_timestamp(text: str) -> str | None:
    """Best-effort timestamp extraction from a text window."""
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
                year=datetime.now().year,
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

    raw_bytes = raw_output.encode()
    content_hash = "blake2b:" + hashlib.blake2b(raw_bytes, digest_size=32).hexdigest()

    source_id = ctx.db.register_source(
        source_name=source_name,
        source_path=source_path,
        source_hash=content_hash,
        extractor=extractor_name,
        line_count=original_line_count,
    )

    all_lines = raw_output.splitlines()
    del raw_output

    total_indexed = 0
    batch: list[WindowRow] = []

    for i in range(0, len(all_lines), _WINDOW_SIZE):
        block = all_lines[i : i + _WINDOW_SIZE]
        raw = "\n".join(block)
        if not raw.strip():
            continue
        event_time = _parse_timestamp(raw)
        batch.append(
            WindowRow(
                source_id=source_id,
                line_start=i + 1,
                line_end=i + len(block),
                event_time=event_time,
                raw_text=raw,
            )
        )
        if len(batch) >= _INSERT_BATCH_SIZE:
            ctx.db.insert_windows(source_id, batch)
            total_indexed += len(batch)
            batch = []

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


def _unmount_path(path: Path) -> None:
    """Best-effort unmount via umount or fusermount."""
    for cmd in (["umount", str(path)], ["fusermount", "-u", str(path)]):
        try:
            subprocess.run(cmd, capture_output=True, timeout=30, check=True)
            return
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            continue
    logger.warning("Could not unmount %s", path)


def _mount_e01(image_path: Path, mount_point: Path) -> bool:
    """Mount an E01 image via ewfmount -> mount."""
    if not shutil.which("ewfmount"):
        logger.error("ewfmount not found -- cannot mount E01 images")
        return False

    ewf_mount = mount_point / "_ewf"
    ewf_mount.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            ["ewfmount", str(image_path), str(ewf_mount)],
            capture_output=True,
            timeout=60,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.error("ewfmount failed on %s: %s", image_path, exc)
        return False

    raw_device = ewf_mount / "ewf1"
    if not raw_device.exists():
        logger.error("ewfmount did not produce ewf1 device in %s", ewf_mount)
        _unmount_path(ewf_mount)
        return False

    offset_bytes = _detect_mount_offset(str(image_path))
    mount_opts = "ro,loop,noexec,nodev"
    if offset_bytes > 0:
        mount_opts += f",offset={offset_bytes}"

    try:
        subprocess.run(
            ["mount", "-o", mount_opts, str(raw_device), str(mount_point)],
            capture_output=True,
            timeout=60,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.error("Failed to mount ewf device %s: %s", raw_device, exc)
        _unmount_path(ewf_mount)
        return False


def _mount_raw(image_path: Path, mount_point: Path) -> bool:
    """Mount a raw / dd image read-only."""
    offset_bytes = _detect_mount_offset(str(image_path))
    mount_opts = "ro,loop,noexec,nodev"
    if offset_bytes > 0:
        mount_opts += f",offset={offset_bytes}"

    try:
        subprocess.run(
            ["mount", "-o", mount_opts, str(image_path), str(mount_point)],
            capture_output=True,
            timeout=60,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # guestmount handles partitions natively via -i
    if shutil.which("guestmount"):
        try:
            subprocess.run(
                ["guestmount", "-a", str(image_path), "-i", "--ro", str(mount_point)],
                capture_output=True,
                timeout=120,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    logger.error("Could not mount %s -- tried mount and guestmount", image_path)
    return False


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
        ext = img.suffix.lower()
        mounted = _mount_e01(img, mount_dir) if ext == ".e01" else _mount_raw(img, mount_dir)

        if not mounted:
            raise RuntimeError(f"Failed to mount disk image: {image_path}")

        yield str(mount_dir)
    finally:
        if mounted:
            _unmount_path(mount_dir)
            ewf_sub = mount_dir / "_ewf"
            if ewf_sub.exists():
                _unmount_path(ewf_sub)
        with suppress(OSError):
            shutil.rmtree(mount_dir, ignore_errors=True)
