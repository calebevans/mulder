"""Evidence directory scanner and artifact type detection."""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path

from mulder.extractors import DISK_IMAGE_EXTS

logger = logging.getLogger(__name__)

_MEMORY_DUMP_EXTS = {".mem", ".vmem", ".dmp", ".001"}
_NETWORK_CAPTURE_EXTS = {".pcap", ".pcapng", ".cap"}
_ARCHIVE_EXTS = {".zip", ".gz", ".tar", ".bz2", ".7z", ".rar", ".tgz"}
_EVTX_EXTS = {".evtx"}
_YARA_RULE_EXTS = {".yar", ".yara"}
_BROWSER_HISTORY_NAMES = {"index.dat"}
_LOG_FILE_EXTS = {".log", ".txt"}
_LOG_DIR_NAMES = {"logs", "log"}
_PHONE_DUMP_EXTS = {".bin"}
_PHONE_DUMP_MIN_SIZE = 50_000_000
_PHONE_DB_NAMES = {
    "contacts2.db",
    "mmssms.db",
    "telephony.db",
    "calendar.db",
    "external.db",
    "launcher.db",
    "sms.db",
    "call_history.db",
    "addressbook.sqlitedb",
    "callhistory.storedata",
    "photos.sqlite",
    "manifest.db",
    "calllog.db",
    "msgstore.db",
    "wa.db",
    "cache4.db",
    "signal.db",
    "main.db",
    "notestore.sqlite",
    "knowledgec.db",
    "consolidated.db",
    "voicemail.db",
    "accounts.db",
    "downloads.db",
}
_SQLITE_EXTS = {".sqlite", ".sqlitedb", ".db"}

_AUTO_EXCLUDE_DIRS = {"precooked", "baseline-memory", "baseline"}

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
    ".mans",
    ".ioc",
    ".csv",
}


_ALL_EVIDENCE_EXTS = _MEMORY_DUMP_EXTS | DISK_IMAGE_EXTS | {".raw"}


def _is_evidence_sidecar(path: Path) -> bool:
    """Return True for metadata files that accompany evidence images.

    E.g. ``foo.E01.txt`` has stem ``foo.E01`` whose suffix ``.e01`` is a known
    evidence extension, so it is a sidecar -- not a log file.  Also catches
    names like ``win7-nromanoff-memory-raw.txt`` where the stem ends with
    ``-raw``.
    """
    inner_ext = Path(path.stem).suffix.lower()
    if inner_ext in _ALL_EVIDENCE_EXTS:
        return True
    stem_lower = path.stem.lower()
    return stem_lower.endswith("-raw") or stem_lower.endswith("_raw")


@dataclass
class ClassifiedEvidence:
    """A single evidence item with its detected artifact type."""

    path: Path
    artifact_type: str


@dataclass
class ClassifierConfig:
    """Controls what the classifier includes and excludes."""

    exclude_patterns: list[str] = field(default_factory=list[str])


class EvidenceClassifier:
    """Walks an evidence directory and classifies files by type.

    Classification is a first-pass heuristic based on extensions and directory
    names.  The actual decision of whether an extractor can handle a file is
    made by ``Extractor.can_handle`` at extraction time.
    """

    def __init__(self, config: ClassifierConfig | None = None) -> None:
        """Build a classifier; use *config* for glob excludes relative to the evidence root."""
        self._config = config or ClassifierConfig()

    def classify(self, evidence_root: Path) -> list[ClassifiedEvidence]:
        """Resolve *evidence_root* and return classified files and notable directories."""
        evidence_root = Path(evidence_root).resolve()
        if not evidence_root.exists():
            raise FileNotFoundError(f"Evidence path does not exist: {evidence_root}")

        if evidence_root.is_file():
            result = self._classify_file(evidence_root)
            return [result] if result else []

        results: list[ClassifiedEvidence] = []
        seen_log_dirs: set[Path] = set()
        excluded_dirs: set[Path] = set()

        for item in sorted(evidence_root.rglob("*")):
            if _is_hidden(item):
                continue
            if self._is_excluded(item, evidence_root):
                continue
            if any(item.is_relative_to(d) for d in excluded_dirs):
                continue
            if item.is_dir() and item.name.lower() in _AUTO_EXCLUDE_DIRS:
                logger.debug("Auto-excluding directory: %s", item)
                excluded_dirs.add(item)
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
        """Classify *item* and append to *results*; track *seen_log_dirs* for subtree pruning."""
        if item.is_dir():
            if self._is_ios_backup(item):
                results.append(ClassifiedEvidence(path=item, artifact_type="ios_backup"))
                return
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
        """Infer artifact type from *path* name and extension, or return None if skipped."""
        ext = path.suffix.lower()
        name = path.name.lower()

        if name in _SKIP_FILENAMES or ext in _SKIP_EXTENSIONS:
            return None

        if ext in _MEMORY_DUMP_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="memory_dump")

        if ext == ".raw":
            return ClassifiedEvidence(path=path, artifact_type="memory_dump")

        if ext in DISK_IMAGE_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="disk_image")

        if ext in _PHONE_DUMP_EXTS:
            try:
                if path.stat().st_size >= _PHONE_DUMP_MIN_SIZE:
                    return ClassifiedEvidence(path=path, artifact_type="phone_dump")
            except OSError:
                pass

        if ext in _NETWORK_CAPTURE_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="network_capture")

        if ext in _ARCHIVE_EXTS or name.endswith(".tar.gz") or name.endswith(".tar.bz2"):
            return ClassifiedEvidence(path=path, artifact_type="compressed_archive")

        if ext in _EVTX_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="evtx")

        if ext in _YARA_RULE_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="yara_rules")

        if name in _BROWSER_HISTORY_NAMES:
            return ClassifiedEvidence(path=path, artifact_type="browser_history")

        if name in _PHONE_DB_NAMES:
            return ClassifiedEvidence(path=path, artifact_type="phone_database")

        if ext in _SQLITE_EXTS:
            return ClassifiedEvidence(path=path, artifact_type="sqlite_database")

        if ext in _LOG_FILE_EXTS:
            if _is_evidence_sidecar(path):
                return None
            return ClassifiedEvidence(path=path, artifact_type="log_file")

        return None

    @staticmethod
    def _is_ios_backup(path: Path) -> bool:
        """Detect an iTunes/Finder iOS backup directory.

        These contain ``Manifest.db`` (file hash-to-path mapping) and
        typically ``Info.plist`` or ``Status.plist``.
        """
        has_manifest = (path / "Manifest.db").exists()
        has_info = (path / "Info.plist").exists() or (path / "Status.plist").exists()
        return has_manifest and has_info

    @staticmethod
    def _is_log_directory(path: Path) -> bool:
        """Return True if *path* is a conventional log directory (name or ``.../var/log``)."""
        if path.name.lower() in _LOG_DIR_NAMES:
            return True
        parts = [p.lower() for p in path.parts]
        if "var" in parts:
            var_idx = parts.index("var")
            if var_idx + 1 < len(parts) and parts[var_idx + 1] == "log":
                return True
        return False


def _is_hidden(path: Path) -> bool:
    """True if any path component is a dot-prefixed segment other than the root ``.``."""
    return any(part.startswith(".") for part in path.parts if part != ".")
