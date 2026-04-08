"""Evidence directory scanner and artifact type detection."""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_MEMORY_DUMP_EXTS = {".mem", ".vmem", ".dmp"}
_DISK_IMAGE_EXTS = {".e01", ".dd", ".img"}
_EVTX_EXTS = {".evtx"}
_LOG_FILE_EXTS = {".log", ".txt"}
_LOG_DIR_NAMES = {"logs", "log"}

_SKIP_FILENAMES: set[str] = {
    "readme",
    "readme.txt",
    "readme.md",
    "license",
    "license.txt",
    "contributing.md",
    "changelog",
    "changelog.txt",
    "changelog.md",
    "makefile",
    "dockerfile",
    "requirements.txt",
    ".gitignore",
    ".gitattributes",
}

_SKIP_EXTENSIONS: set[str] = {
    ".md",
    ".rst",
    ".html",
    ".htm",
    ".css",
    ".js",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".toml",
    ".cfg",
    ".ini",
    ".py",
    ".sh",
    ".bat",
    ".ps1",
    ".rb",
    ".pl",
    ".c",
    ".h",
    ".cpp",
    ".java",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".zip",
    ".gz",
    ".tar",
    ".bz2",
    ".7z",
    ".rar",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".bmp",
    ".mp3",
    ".mp4",
    ".avi",
    ".wav",
}


@dataclass
class ClassifiedEvidence:
    """A single evidence item with its detected artifact type."""

    path: Path
    artifact_type: str


@dataclass
class ClassifierConfig:
    """Controls what the classifier includes and excludes."""

    exclude_patterns: list[str] = field(default_factory=list)


class EvidenceClassifier:
    """Walks an evidence directory and classifies files by type.

    Classification is a first-pass heuristic based on extensions and directory
    names.  The actual decision of whether an extractor can handle a file is
    made by ``Extractor.can_handle`` at extraction time.
    """

    def __init__(self, config: ClassifierConfig | None = None) -> None:
        self._config = config or ClassifierConfig()

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
            if self._is_excluded(item, evidence_root):
                continue
            self._process_item(item, results, seen_log_dirs)

        return results

    def _is_excluded(self, item: Path, evidence_root: Path) -> bool:
        """Check user-supplied --exclude glob patterns."""
        rel = str(item.relative_to(evidence_root))
        return any(
            fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(item.name, pat)
            for pat in self._config.exclude_patterns
        )

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
        name = path.name.lower()

        if name in _SKIP_FILENAMES or ext in _SKIP_EXTENSIONS:
            return None

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
