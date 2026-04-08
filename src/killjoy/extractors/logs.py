"""Already-text log file and log directory extractor.

Ingests ``.log``, ``.txt`` files and directories classified as
``log_directory``.  No external tools are needed -- this is a pure-Python
reader with binary-file detection and a per-file size cap.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from killjoy.extractors.base import ExtractionResult

logger = logging.getLogger(__name__)

_LOG_FILE_EXTS = frozenset({".log", ".txt"})
_MAX_FILE_BYTES = 100 * 1024 * 1024  # 100 MB
_BINARY_CHECK_BYTES = 8192


def _is_text_file(path: Path) -> bool:
    """Return False if *path* appears to be binary (null bytes in header)."""
    try:
        with open(path, "rb") as f:
            head = f.read(_BINARY_CHECK_BYTES)
        return b"\x00" not in head
    except OSError:
        return False


def _read_log_file(path: Path) -> str:
    """Read a text log file, tailing to the last ``_MAX_FILE_BYTES`` for large files."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            if size > _MAX_FILE_BYTES:
                f.seek(-_MAX_FILE_BYTES, os.SEEK_END)
                f.readline()  # discard partial first line
            data = f.read()
        return data.decode("utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return ""


def _source_name_from_file(path: Path) -> str:
    """Derive a source name from the filename.

    ``auth.log`` -> ``log.auth``, ``access.log.1`` -> ``log.access``,
    ``messages`` -> ``log.messages``.
    """
    stem = path.stem.lower()
    stem = re.sub(r"\.?\d+$", "", stem)
    stem = re.sub(r"[^a-z0-9\-]", "-", stem)
    stem = re.sub(r"-+", "-", stem).strip("-")
    return f"log.{stem}" if stem else f"log.{path.name.lower()}"


class LogFileExtractor:
    """Ingests already-text log files and directories."""

    name: str = "logs"

    def can_handle(self, path: Path) -> bool:
        if path.is_dir():
            return True
        return path.suffix.lower() in _LOG_FILE_EXTS

    def extract(self, path: Path, case_id: str) -> list[ExtractionResult]:
        if path.is_dir():
            return self._extract_directory(path)
        return self._extract_single_file(path)

    def version(self) -> str:
        return "builtin"

    def _extract_single_file(self, path: Path) -> list[ExtractionResult]:
        if not _is_text_file(path):
            logger.debug("Skipping binary file %s", path)
            return []

        text = _read_log_file(path)
        if not text:
            return []

        return [
            ExtractionResult(
                source_name=_source_name_from_file(path),
                source_path=str(path),
                extractor="log-reader",
                text_output=text,
                line_count=text.count("\n") + 1,
            )
        ]

    def _extract_directory(self, directory: Path) -> list[ExtractionResult]:
        results: list[ExtractionResult] = []
        for file_path in sorted(directory.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.name.startswith("."):
                continue
            if not _is_text_file(file_path):
                logger.debug("Skipping binary file %s", file_path)
                continue

            text = _read_log_file(file_path)
            if not text:
                continue

            results.append(
                ExtractionResult(
                    source_name=_source_name_from_file(file_path),
                    source_path=str(file_path),
                    extractor="log-reader",
                    text_output=text,
                    line_count=text.count("\n") + 1,
                )
            )
        return results
