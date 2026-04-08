"""Plaso/log2timeline disk-image and filesystem extractor.

Runs ``log2timeline.py`` to build a Plaso storage file, then ``psort.py``
to export the super-timeline as L2T CSV text.  The resulting timeline is
returned as a single :class:`ExtractionResult` for windowing and embedding.
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from killjoy.extractors.base import ExtractionResult

logger = logging.getLogger(__name__)

_DISK_IMAGE_EXTS = frozenset({".e01", ".dd", ".img"})
_LOG2TIMELINE_BIN = "log2timeline.py"
_PSORT_BIN = "psort.py"
_LOG2TIMELINE_TIMEOUT = 1800  # 30 minutes
_PSORT_TIMEOUT = 600  # 10 minutes


def _looks_like_mounted_fs(path: Path) -> bool:
    """Heuristic: a directory that contains ``Windows/`` or ``var/log/``."""
    if not path.is_dir():
        return False
    return (path / "Windows").is_dir() or (path / "var" / "log").is_dir()


class PlasoExtractor:
    """Runs Plaso/log2timeline against a disk image or mounted filesystem."""

    name: str = "plaso"

    def __init__(self) -> None:
        self._cached_version: str | None = None

    def can_handle(self, path: Path) -> bool:
        if path.suffix.lower() in _DISK_IMAGE_EXTS:
            return True
        return _looks_like_mounted_fs(path)

    def extract(self, path: Path, case_id: str) -> list[ExtractionResult]:
        if not shutil.which(_LOG2TIMELINE_BIN):
            logger.warning("%s not found on $PATH -- skipping Plaso extraction", _LOG2TIMELINE_BIN)
            return []
        if not shutil.which(_PSORT_BIN):
            logger.warning("%s not found on $PATH -- skipping Plaso extraction", _PSORT_BIN)
            return []

        dump_fd, dump_path = tempfile.mkstemp(prefix=f"{case_id}_plaso_", suffix=".dump")
        try:
            import os

            os.close(dump_fd)

            logger.info("Running log2timeline on %s (this may take a while) ...", path)
            l2t_proc = subprocess.run(
                [_LOG2TIMELINE_BIN, "--storage-file", dump_path, str(path)],
                capture_output=True,
                text=True,
                timeout=_LOG2TIMELINE_TIMEOUT,
                check=False,
            )
            if l2t_proc.returncode != 0:
                stderr_preview = (l2t_proc.stderr or "")[:500]
                logger.warning(
                    "log2timeline exited %d on %s: %s",
                    l2t_proc.returncode,
                    path,
                    stderr_preview,
                )
                return []

            logger.info("Running psort to export L2T CSV ...")
            psort_proc = subprocess.run(
                [_PSORT_BIN, "-o", "l2tcsv", dump_path],
                capture_output=True,
                text=True,
                timeout=_PSORT_TIMEOUT,
                check=False,
            )
            if psort_proc.returncode != 0:
                stderr_preview = (psort_proc.stderr or "")[:500]
                logger.warning(
                    "psort exited %d: %s",
                    psort_proc.returncode,
                    stderr_preview,
                )
                return []

            output = psort_proc.stdout.strip()
            if not output:
                logger.debug("Plaso produced no timeline output for %s", path)
                return []

            return [
                ExtractionResult(
                    source_name="plaso.timeline",
                    source_path=str(path),
                    extractor="plaso",
                    text_output=output,
                    line_count=output.count("\n") + 1,
                )
            ]

        except subprocess.TimeoutExpired as exc:
            logger.error("Plaso timed out on %s: %s", path, exc)
            return []
        finally:
            with contextlib.suppress(OSError):
                Path(dump_path).unlink(missing_ok=True)

    def version(self) -> str:
        if self._cached_version is not None:
            return self._cached_version

        if not shutil.which(_LOG2TIMELINE_BIN):
            self._cached_version = "plaso (not installed)"
            return self._cached_version

        try:
            proc = subprocess.run(
                [_LOG2TIMELINE_BIN, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            first_line = (proc.stdout or proc.stderr or "").split("\n", 1)[0]
            self._cached_version = first_line.strip() or "plaso (unknown version)"
        except (subprocess.TimeoutExpired, OSError):
            self._cached_version = "plaso (unknown version)"
        return self._cached_version
