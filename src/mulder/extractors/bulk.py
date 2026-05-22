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

from mulder.extractors import DISK_IMAGE_EXTS
from mulder.extractors.base import ExtractionResult

logger = logging.getLogger(__name__)
_BULK_EXTRACTOR_BIN = "bulk_extractor"
_BULK_EXTRACTOR_TIMEOUT = 3600  # 1 hour -- full-image scans are slow

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


def _parse_feature_file(path: Path) -> str:
    """Read a bulk_extractor feature file, stripping comments and blanks.

    Feature files use tab-separated ``offset\\tfeature\\tcontext`` lines
    with ``#``-prefixed comment headers.
    """
    lines: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.rstrip("\n\r")
            if not stripped or stripped.startswith("#"):
                continue
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
            logger.info("bulk_extractor not found on $PATH -- skipping IOC carving for %s", path)
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
        """Run bulk_extractor and collect results from feature files."""
        image = str(path)
        cmd = [_BULK_EXTRACTOR_BIN, "-o", outdir, image]

        logger.info("Running bulk_extractor on %s (this may take a while) ...", path)
        logger.debug("bulk_extractor command: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_BULK_EXTRACTOR_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.error(
                "bulk_extractor timed out after %ds on %s",
                _BULK_EXTRACTOR_TIMEOUT,
                path,
            )
            return []

        if proc.returncode != 0:
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

        logger.info(
            "bulk_extractor produced %d non-empty feature source(s) for %s",
            len(results),
            path,
        )
        return results
