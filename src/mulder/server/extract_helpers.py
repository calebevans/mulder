"""Shared helpers for Tier 2 on-demand extraction tools.

Provides ``extract_and_index`` (the store pipeline used by every
extraction tool) and ``mount_disk_image`` (a context manager for safely
mounting E01/raw disk images with thread-safe caching).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from mulder.execution.privileged import MountBroker, SubprocessMountBroker
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


@dataclass
class _MountEntry:
    """Internal bookkeeping for a single cached mount point."""

    mount_dir: Path
    leases: set[object] = field(default_factory=set)
    ready: threading.Event = field(default_factory=threading.Event)
    closed: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None
    mount_attempted: bool = False
    closing: bool = False
    cleanup_lease: object | None = None
    cleanup_started: bool = False
    cleanup_verified: bool | None = None

    @property
    def refcount(self) -> int:
        """Return the number of live, independently releasable callers."""
        return len(self.leases)


class _MountCache:
    """Thread-safe cache that deduplicates concurrent disk image mounts.

    Each unique image path (canonicalized via ``os.path.realpath``) gets at
    most one active FUSE mount.  Concurrent callers block until the initial
    mount completes, then share the resulting mount point.  The mount is
    torn down only when the last caller releases it.
    """

    def __init__(self, broker: MountBroker | None = None) -> None:
        """Initialize an empty cache with its broker and protecting lock."""
        self._lock = threading.Lock()
        self._entries: dict[str, _MountEntry] = {}
        self._broker = broker or SubprocessMountBroker()

    @contextmanager
    def acquire(self, image_path: str) -> Iterator[str]:
        """Yield a shared mount point for *image_path*, mounting if needed.

        The first caller performs the actual mount; subsequent concurrent
        callers for the same canonical path block until that mount finishes,
        then receive the same mount point.  On context exit the reference
        count is decremented, and the last caller unmounts. The empty mountpoint
        path is intentionally retained because deleting it would introduce a
        pathname race with a replacement or remounted tree.

        Args:
            image_path: Filesystem path to the disk image file.

        Yields:
            The directory where the image is mounted.

        Raises:
            RuntimeError: If the underlying mount operation fails.
        """
        canonical = os.path.realpath(image_path)
        lease = object()
        entry: _MountEntry | None = None
        is_owner = False
        entered = False
        try:
            try:
                while True:
                    wait_for_close: threading.Event | None = None
                    with self._lock:
                        entry = self._entries.get(canonical)
                        if entry is None:
                            mount_dir = Path(tempfile.mkdtemp(prefix="mulder_mount_"))
                            entry = _MountEntry(
                                mount_dir=mount_dir,
                                leases={lease},
                            )
                            is_owner = True
                            self._entries[canonical] = entry
                        elif entry.closing:
                            wait_for_close = entry.closed
                        else:
                            entry.leases.add(lease)
                    if wait_for_close is None:
                        break
                    entry = None
                    wait_for_close.wait()

                if is_owner:
                    # Once a mount attempt begins, cleanup must conservatively prove
                    # the target unmounted.  A broker can fail after the helper has
                    # already mounted, so its False return is not absence proof.
                    entry.mount_attempted = True
                    try:
                        mounted = self._broker.mount_read_only(
                            Path(image_path), entry.mount_dir
                        )
                    except Exception as exc:
                        failure = RuntimeError(
                            f"Failed to mount disk image: {image_path}"
                        )
                        entry.error = failure
                        raise failure from exc
                    except BaseException as exc:
                        entry.error = exc
                        raise
                    if not mounted:
                        failure = RuntimeError(
                            f"Failed to mount disk image: {image_path}"
                        )
                        entry.error = failure
                        raise failure
                    entry.ready.set()
                else:
                    entry.ready.wait()
                    if entry.error is not None:
                        raise RuntimeError(
                            f"Failed to mount disk image: {image_path}"
                        ) from entry.error

                entered = True
                yield str(entry.mount_dir)
            except BaseException as exc:
                if entry is not None and is_owner and not entered:
                    if entry.error is None:
                        entry.error = exc
                    entry.ready.set()
                raise
            finally:
                if entry is not None:
                    self._release(canonical, entry, lease)
        except BaseException as exc:
            # This handler is established before a lease can be registered.
            # It therefore catches a one-shot cancellation on the first line
            # of the inner finally block or at the _release() invocation itself.
            if entry is not None and not isinstance(exc, Exception):
                self._release(canonical, entry, lease)
            raise

    def _release(self, canonical: str, entry: _MountEntry, lease: object) -> None:
        """Release one lease and finish last-user cleanup before cancellation.

        Args:
            canonical: Canonical (realpath) cache key.
            entry: The mount entry being released.
        """
        try:
            self._release_once(canonical, entry, lease)
        except BaseException as exc:
            if isinstance(exc, Exception):
                raise
            # Retry after a cancellation at any boundary, including the first
            # executable line of this method.  The transaction is idempotent,
            # so a partially completed attempt safely resumes here.
            while True:
                try:
                    self._release_once(canonical, entry, lease)
                    break
                except BaseException as retry_exc:
                    if isinstance(retry_exc, Exception):
                        raise
            raise exc

    def _release_once(
        self,
        canonical: str,
        entry: _MountEntry,
        lease: object,
    ) -> None:
        """Run one idempotent attempt at the lease-release transaction."""
        if self._mark_lease_released(canonical, entry, lease):
            self._finish_cleanup(canonical, entry)

    def _mark_lease_released(
        self,
        canonical: str,
        entry: _MountEntry,
        lease: object,
    ) -> bool:
        """Idempotently detach a lease and identify the last-user transition."""
        with self._lock:
            current = self._entries.get(canonical)
            if current is not entry:
                return False
            if lease in entry.leases:
                if len(entry.leases) == 1:
                    entry.closing = True
                    entry.cleanup_lease = lease
                entry.leases.remove(lease)
            # Even if close notification was published just before a
            # cancellation, the cleanup owner must retry until this same
            # entry has actually been evicted from the protected cache.
            return entry.cleanup_lease is lease

    def _finish_cleanup(self, canonical: str, entry: _MountEntry) -> None:
        """Idempotently unmount, preserve the path, and publish cache closure."""
        if entry.cleanup_verified is None:
            if not entry.mount_attempted:
                entry.cleanup_verified = True
            elif entry.cleanup_started:
                # The prior call may have unmounted successfully before an
                # asynchronous cancellation prevented its result being stored.
                # Never repeat that pathname side effect: a replacement mount
                # could now occupy the intentionally retained directory.
                try:
                    entry.cleanup_verified = self._broker.is_unmounted(
                        entry.mount_dir
                    )
                except Exception:
                    logger.exception(
                        "Mount broker could not verify interrupted cleanup: %s",
                        entry.mount_dir,
                    )
                    entry.cleanup_verified = False
            else:
                # Commit the one-shot side effect before invoking the broker.
                # A retry may verify its outcome, but must not unmount again.
                entry.cleanup_started = True
                try:
                    entry.cleanup_verified = self._broker.unmount(entry.mount_dir)
                except Exception:
                    logger.exception(
                        "Mount broker raised during cleanup: %s", entry.mount_dir
                    )
                    entry.cleanup_verified = False
        if entry.cleanup_verified:
            logger.debug(
                "Preserving verified-unmounted mount point to avoid "
                "pathname cleanup races: %s",
                entry.mount_dir,
            )
        else:
            logger.error(
                "Preserving mount point because unmount could not be verified: %s",
                entry.mount_dir,
            )
        with self._lock:
            # Publish closure while eviction is still protected by the cache
            # lock.  Waiters cannot overtake this transition and create a new
            # mount between eviction and the close notification.
            entry.closed.set()
            if self._entries.get(canonical) is entry:
                self._entries.pop(canonical)


_mount_cache = _MountCache()


@contextmanager
def mount_disk_image(image_path: str) -> Iterator[str]:
    """Mount a disk image (E01 or raw) read-only and yield the mount point.

    Uses a thread-safe cache so that concurrent callers for the same image
    share a single mount. The image is unmounted when the last caller exits.
    Its empty temporary mountpoint is retained for race-free operator cleanup;
    Mulder never recursively deletes a path that may have been replaced.

    Raises ``RuntimeError`` if the image cannot be mounted.
    """
    with _mount_cache.acquire(image_path) as mount_point:
        yield mount_point
