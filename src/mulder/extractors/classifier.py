"""Evidence directory scanner and artifact type detection."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_MEMORY_DUMP_EXTS = {".mem", ".vmem", ".dmp"}
_DISK_IMAGE_EXTS = {".e01", ".dd", ".img"}
_EVTX_EXTS = {".evtx"}
_LOG_FILE_EXTS = {".log", ".txt"}
_LOG_DIR_NAMES = {"logs", "log"}


@dataclass
class ClassifiedEvidence:
    """A single evidence item with its detected artifact type."""

    path: Path
    artifact_type: str


class EvidenceClassifier:
    """Walks an evidence directory and classifies files by type.

    Classification is a first-pass heuristic based on extensions and directory
    names.  The actual decision of whether an extractor can handle a file is
    made by ``Extractor.can_handle`` at extraction time.
    """

    def classify(self, evidence_root: Path) -> list[ClassifiedEvidence]:
        evidence_root = Path(evidence_root).resolve()
        if not evidence_root.exists():
            raise FileNotFoundError(f"Evidence path does not exist: {evidence_root}")

        if evidence_root.is_file():
            result = self._classify_file(evidence_root)
            return [result] if result else []

        results: list[ClassifiedEvidence] = []
        seen_log_dirs: set[Path] = set()

        for item in sorted(evidence_root.rglob("*")):
            if _is_hidden(item):
                continue
            self._process_item(item, results, seen_log_dirs)

        return results

    def _process_item(
        self,
        item: Path,
        results: list[ClassifiedEvidence],
        seen_log_dirs: set[Path],
    ) -> None:
        if item.is_dir():
            if self._is_log_directory(item) and item not in seen_log_dirs:
                results.append(ClassifiedEvidence(path=item, artifact_type="log_directory"))
                seen_log_dirs.add(item)
            return

        if any(item.is_relative_to(d) for d in seen_log_dirs):
            return

        classified = self._classify_file(item)
        if classified:
            results.append(classified)
        else:
            logger.debug("Skipping unrecognised file: %s", item)

    def _classify_file(self, path: Path) -> ClassifiedEvidence | None:
        ext = path.suffix.lower()

        if ext in _MEMORY_DUMP_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="memory_dump")

        if ext == ".raw":
            return ClassifiedEvidence(path=path, artifact_type="memory_dump")

        if ext in _DISK_IMAGE_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="disk_image")

        if ext in _EVTX_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="evtx")

        if ext in _LOG_FILE_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="log_file")

        return None

    @staticmethod
    def _is_log_directory(path: Path) -> bool:
        if path.name.lower() in _LOG_DIR_NAMES:
            return True
        parts = [p.lower() for p in path.parts]
        if "var" in parts:
            var_idx = parts.index("var")
            if var_idx + 1 < len(parts) and parts[var_idx + 1] == "log":
                return True
        return False


def _is_hidden(path: Path) -> bool:
    return any(part.startswith(".") for part in path.parts if part != ".")
