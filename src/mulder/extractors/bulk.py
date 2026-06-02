"""Bulk Extractor disk-image IOC carving extractor.

Runs ``bulk_extractor`` against disk images at ingest time to carve
indicators of compromise (emails, URLs, domains, IPs, credit card
numbers, etc.) from unallocated space and file slack.  Each feature
file produced by ``bulk_extractor`` becomes its own source for
windowing and indexing.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from mulder.extractors.base import ExtractionResult
from mulder.patterns import DISK_IMAGE_EXTS

logger = logging.getLogger(__name__)
_BULK_EXTRACTOR_BIN = "bulk_extractor"
_BULK_EXTRACTOR_TIMEOUT = 3600  # 1 hour base; scales with image size
_MAX_TIMEOUT = 28800  # 8 hours
_TIMEOUT_PER_GIB = 180  # ~3 min per GiB of image data
_MAX_FEATURE_OUTPUT = 256 * 1024 * 1024  # 256 MiB cap per feature file
_MIN_FREE_SPACE = 1024 * 1024 * 1024  # 1 GiB absolute minimum

_FEATURE_FILE_MAP: dict[str, str] = {
    "email.txt": "bulk.email",
    "url.txt": "bulk.url",
    "domain.txt": "bulk.domain",
    "telephone.txt": "bulk.telephone",
    "ccn.txt": "bulk.ccn",
    "ip.txt": "bulk.ip",
    "elf.txt": "bulk.elf",
    "winpe.txt": "bulk.exe",
}


def _has_sufficient_disk_space(image_path: Path) -> bool:
    """Check that the temp partition has enough free space for extraction.

    Requires at least 10% of the image size or 1 GiB, whichever is
    larger.

    Args:
        image_path: Path to the disk image to be processed.

    Returns:
        True when sufficient space is available or the check cannot be
        performed, False otherwise.
    """
    try:
        image_size = image_path.stat().st_size
    except OSError:
        return True
    needed = max(int(image_size * 0.1), _MIN_FREE_SPACE)
    try:
        usage = shutil.disk_usage(tempfile.gettempdir())
    except OSError:
        return True
    if usage.free < needed:
        free_gib = usage.free / (1024**3)
        needed_gib = needed / (1024**3)
        logger.warning(
            "Insufficient disk space for bulk_extractor output: "
            "%.1f GiB free, estimated %.1f GiB needed; skipping %s",
            free_gib,
            needed_gib,
            image_path.name,
        )
        return False
    return True


def _scaled_timeout(image_path: Path, base: int) -> int:
    """Compute a timeout proportional to image file size.

    Adds ``_TIMEOUT_PER_GIB`` seconds per GiB of image data on top of
    the *base* timeout, capped at ``_MAX_TIMEOUT``.

    Args:
        image_path: Path to the disk image.
        base: Minimum timeout in seconds.

    Returns:
        Timeout in seconds, clamped between *base* and ``_MAX_TIMEOUT``.
    """
    try:
        size_bytes = image_path.stat().st_size
    except OSError:
        return base
    gib = size_bytes / (1024**3)
    return min(base + int(gib * _TIMEOUT_PER_GIB), _MAX_TIMEOUT)


def _parse_feature_file(path: Path) -> str:
    """Read a bulk_extractor feature file, stripping comments and blanks.

    Feature files use tab-separated ``offset\\tfeature\\tcontext`` lines
    with ``#``-prefixed comment headers.  Output is capped at
    ``_MAX_FEATURE_OUTPUT`` accumulated bytes to prevent unbounded
    memory use on large disk images.

    Args:
        path: Path to the feature file.

    Returns:
        Newline-joined feature lines with comments and blanks removed.
    """
    lines: list[str] = []
    accumulated = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.rstrip("\n\r")
            if not stripped or stripped.startswith("#"):
                continue
            accumulated += len(stripped) + 1
            if accumulated > _MAX_FEATURE_OUTPUT:
                logger.warning(
                    "Feature file %s exceeds %d byte cap; truncating",
                    path.name,
                    _MAX_FEATURE_OUTPUT,
                )
                break
            lines.append(stripped)
    return "\n".join(lines)


class BulkExtractorExtractor:
    """Runs ``bulk_extractor`` against disk images to carve IOCs."""

    name: str = "bulk_extractor"

    def __init__(self) -> None:
        """Initialize with an empty version cache."""
        self._cached_version: str | None = None

    def can_handle(self, path: Path) -> bool:
        """Return True for disk image files (.e01/.dd/.img)."""
        return path.suffix.lower() in DISK_IMAGE_EXTS

    def extract(self, path: Path, case_id: str) -> list[ExtractionResult]:
        """Run bulk_extractor on *path* and return one result per non-empty feature file."""
        if not shutil.which(_BULK_EXTRACTOR_BIN):
            logger.info("bulk_extractor not found on $PATH; skipping IOC carving for %s", path)
            return []

        if not _has_sufficient_disk_space(path):
            return []

        outdir = tempfile.mkdtemp(prefix=f"{case_id}_bulk_")
        try:
            return self._run_and_collect(path, outdir)
        finally:
            shutil.rmtree(outdir, ignore_errors=True)

    def version(self) -> str:
        """Return the bulk_extractor version string (cached after first call)."""
        if self._cached_version is not None:
            return self._cached_version

        if not shutil.which(_BULK_EXTRACTOR_BIN):
            self._cached_version = "bulk_extractor (not installed)"
            return self._cached_version

        try:
            proc = subprocess.run(
                [_BULK_EXTRACTOR_BIN, "-V"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            first_line = (proc.stdout or proc.stderr or "").split("\n", 1)[0]
            self._cached_version = first_line.strip() or "bulk_extractor (unknown version)"
        except (subprocess.TimeoutExpired, OSError):
            self._cached_version = "bulk_extractor (unknown version)"
        return self._cached_version

    def _run_and_collect(self, path: Path, outdir: str) -> list[ExtractionResult]:
        """Run bulk_extractor and collect results from feature files.

        On timeout, any feature files already written are still collected
        so that partial results are not lost.

        Args:
            path: Path to the disk image.
            outdir: Output directory for bulk_extractor.

        Returns:
            List of extraction results, one per non-empty feature file.
        """
        image = str(path)
        cmd = [_BULK_EXTRACTOR_BIN, "-o", outdir, image]
        timeout = _scaled_timeout(path, _BULK_EXTRACTOR_TIMEOUT)

        logger.info("Running bulk_extractor on %s (timeout: %ds) ...", path, timeout)
        logger.debug("bulk_extractor command: %s", " ".join(cmd))

        timed_out = False
        proc: subprocess.CompletedProcess[str] | None = None
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            logger.warning(
                "bulk_extractor timed out after %ds on %s; collecting partial results",
                timeout,
                path,
            )

        if proc is not None and proc.returncode != 0:
            stderr_preview = (proc.stderr or "")[:500]
            logger.warning(
                "bulk_extractor exited %d on %s: %s",
                proc.returncode,
                image,
                stderr_preview,
            )
            return []

        results: list[ExtractionResult] = []
        out_path = Path(outdir)

        for filename, source_name in _FEATURE_FILE_MAP.items():
            feature_path = out_path / filename
            if not feature_path.exists():
                continue

            text = _parse_feature_file(feature_path)
            if not text:
                continue

            results.append(
                ExtractionResult(
                    source_name=source_name,
                    source_path=image,
                    extractor=f"bulk_extractor-{filename.removesuffix('.txt')}",
                    text_output=text,
                    line_count=text.count("\n") + 1,
                )
            )

        if timed_out and results:
            logger.info(
                "Salvaged %d feature source(s) from timed-out bulk_extractor run on %s",
                len(results),
                path,
            )
        else:
            logger.info(
                "bulk_extractor produced %d non-empty feature source(s) for %s",
                len(results),
                path,
            )
        return results
