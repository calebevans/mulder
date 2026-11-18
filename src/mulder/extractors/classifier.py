"""Evidence directory scanner and artifact type detection."""

from __future__ import annotations

import fnmatch
import functools
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from mulder.dirroot import MAX_ENTRIES, detect_collection, walk_files
from mulder.extractors.optical import SECTOR, signature_from_vrs
from mulder.linuxvol import volume_kind
from mulder.patterns import DISK_IMAGE_EXTS

logger = logging.getLogger(__name__)

_NFCAPD_NAME_RE = re.compile(r"^nfcapd\.\d{12}(?:\d{2})?$")  # nfcapd.YYYYMMDDhhmm[ss]
_NFDUMP_MAGIC = b"\x0c\xa5"  # uint16 0xA50C little-endian
_NFDUMP_LAYOUTS = frozenset({1, 2})

_MEMORY_DUMP_EXTS = {".mem", ".vmem", ".dmp", ".001"}

#: Written by disk imagers (dd, FTK Imager) and memory acquirers (DumpIt,
#: winpmem) alike, so their first bytes are checked for a disk signature.
RAW_CONTAINER_EXTS = frozenset({".raw", ".001"})

# Sectors 0-31 of 2048 bytes: boot sector, superblocks and the optical
# volume recognition sequence (sectors 16-31).
_HEAD_BYTES = 32 * SECTOR
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

_AUTORUNS_CSV_PATTERNS: tuple[str, ...] = ("autorunsc", "autoruns")

# Evidence that is never a collector's own output, wherever it was left.
_CONTAINER_TYPES = frozenset(
    {"memory_dump", "disk_image", "network_capture", "compressed_archive"}
)
# What a memory or crash dump copied into a collection is named.
_COLLECTED_DUMP_EXTS = (".dmp", ".mem", ".vmem", ".raw")

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


def _looks_like_mbr(head: bytes) -> bool:
    """Return True for a boot sector carrying a plausible MBR partition table."""
    if head[510:512] != b"\x55\xaa":
        return False
    entries = [head[446 + 16 * i : 462 + 16 * i] for i in range(4)]
    if any(e[0] not in (0x00, 0x80) for e in entries):
        return False
    return any(e[4] != 0 and int.from_bytes(e[12:16], "little") > 0 for e in entries)


def _looks_like_ext(head: bytes) -> bool:
    """Return True for an ext2/3/4 superblock at byte 1024."""
    sb = head[1024:1124]
    if len(sb) < 100 or sb[56:58] != b"\x53\xef":
        return False
    inodes = int.from_bytes(sb[0:4], "little")
    log_block_size = int.from_bytes(sb[24:28], "little")
    return inodes > 0 and log_block_size <= 6


def has_disk_signature(path: Path) -> bool:
    """Return True when *path* starts like a disk, partition or optical image.

    A plain physical-memory dump has no header, so a raw container without
    one of these signatures is still taken for a memory dump.
    """
    if not path.is_file():  # never open a FIFO or device: the read could block
        return False
    try:
        with path.open("rb") as fh:
            head = fh.read(_HEAD_BYTES)
            beyond = fh.read(512)  # the btrfs magic sits just past the head
    except OSError:
        return False
    return (
        volume_kind(head + beyond) is not None  # LVM, XFS, LUKS, btrfs on the whole disk
        or b"EFI PART" in (head[512:520], head[4096:4104])  # GPT
        or head[3:11] in (b"NTFS    ", b"EXFAT   ", b"-FVE-FS-")  # NTFS, exFAT, BitLocker
        or (
            head[510:512] == b"\x55\xaa"
            and (head[54:59] in (b"FAT12", b"FAT16") or head[82:87] == b"FAT32")
        )
        or _looks_like_mbr(head)
        or _looks_like_ext(head)
        or signature_from_vrs(head[16 * SECTOR :]) is not None  # ISO 9660, UDF
    )


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


JSON_LOG_EXTS = {".json", ".jsonl", ".ndjson"}

# GitHub Actions run logs, as downloaded: "1_build.txt", "build/3_Run tests.txt",
# every line opening with a timestamp to seven decimal places.
_CI_LOG_NAME_RE = re.compile(r"^\d+_.+\.txt$")
_CI_LOG_LINE_RE = re.compile(rb"^(?:\xef\xbb\xbf)?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z ")


def is_repository(path: Path) -> bool:
    """A directory holding a source checkout with GitHub Actions workflows."""
    return (path / ".github" / "workflows").is_dir()


def is_ci_run_log_directory(path: Path) -> bool:
    """A directory of downloaded GitHub Actions run logs."""
    try:
        candidates = [p for p in path.iterdir() if _CI_LOG_NAME_RE.match(p.name) and p.is_file()]
    except OSError:
        return False
    for candidate in sorted(candidates)[:3]:
        try:
            with candidate.open("rb") as f:
                if _CI_LOG_LINE_RE.match(f.read(64)):
                    return True
        except OSError:
            continue
    return False


def is_cloud_audit_log(path: Path) -> bool:
    """Sniff the head of a JSON file for the keys a cloud audit log export carries.

    GCP Cloud Audit Logs have ``protoPayload``, AWS CloudTrail ``eventSource`` and
    ``eventName``, GitHub audit logs ``action``, ``actor`` and a timestamp key.
    Deliberately loose: a false positive costs one indexed file, a miss costs
    the log.
    """
    try:
        if not path.is_file():  # a FIFO named x.json would block the open
            return False
        with path.open("rb") as f:
            head = f.read(65536)
    except OSError:
        return False
    return (
        b'"protoPayload"' in head
        or (b'"eventSource"' in head and b'"eventName"' in head)
        or (
            b'"action"' in head
            and b'"actor"' in head
            and (b'"@timestamp"' in head or b'"created_at"' in head)
        )
    )


def has_nfdump_magic(path: Path) -> bool:
    """4-byte header check; empty, short, unreadable and symlinked files fail."""
    try:
        if path.is_symlink():
            return False
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return (
        len(head) == 4
        and head[:2] == _NFDUMP_MAGIC
        and head[2] in _NFDUMP_LAYOUTS
        and head[3] == 0
    )


@functools.lru_cache(maxsize=4096)
def _dir_has_named_nfcapd(parent: str) -> bool:
    """One listdir per directory: does it contain a rotation-named nfcapd file?"""
    try:
        return any(_NFCAPD_NAME_RE.match(p.name.lower()) for p in Path(parent).iterdir())
    except OSError:
        return False


def is_nfcapd(path: Path) -> bool:
    """nfdump capture file: header magic, sniffed only for plausible candidates.

    Candidates: (a) rotation-style names (``nfcapd.YYYYMMDDhhmm[ss]``), or (b) files
    with no suffix or an all-digit suffix (renamed captures, ``nfcapd.current.<pid>``)
    whose directory also holds a rotation-named file. Rule (b) keeps a large disk
    export (memory.001, wtmp, auth.log.1 ...) from costing one ``open()`` per file on
    a large tree. Empty, short and symlinked files fail.
    """
    name = path.name.lower()
    if _NFCAPD_NAME_RE.match(name):
        return has_nfdump_magic(path)
    suffix = path.suffix
    if suffix and not suffix[1:].isdigit():
        return False
    if not _dir_has_named_nfcapd(str(path.parent)):
        return False
    return has_nfdump_magic(path)


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
    names; ``.raw`` and ``.001`` files are also checked for a disk signature.
    The actual decision of whether an extractor can handle a file is made by
    ``Extractor.can_handle`` at extraction time.
    """

    def __init__(self, config: ClassifierConfig | None = None) -> None:
        """Build a classifier; use *config* for glob excludes relative to the evidence root."""
        self._config = config or ClassifierConfig()

    def classify(self, evidence_root: Path) -> list[ClassifiedEvidence]:
        """Resolve *evidence_root* and return classified files and notable directories."""
        # one listdir per directory per WALK: a directory that gained a rotation-named nfcapd
        # file since an earlier classify() in this process must be re-sniffed (never stale)
        _dir_has_named_nfcapd.cache_clear()
        evidence_root = Path(evidence_root).resolve()
        if not evidence_root.exists():
            raise FileNotFoundError(f"Evidence path does not exist: {evidence_root}")

        if evidence_root.is_file():
            result = self._classify_file(evidence_root)
            return [result] if result else []

        if detect_collection(evidence_root) is not None:
            return self._collection_items(evidence_root)

        results: list[ClassifiedEvidence] = []
        seen_log_dirs: set[Path] = set()
        excluded_dirs: set[Path] = set()

        try:
            all_items = sorted(evidence_root.rglob("*"))
        except PermissionError as exc:
            logger.warning("Permission denied during evidence walk: %s", exc)
            all_items = []

        for item in all_items:
            if _is_hidden(item.relative_to(evidence_root)):
                continue
            if self._is_excluded(item, evidence_root):
                continue
            if any(item.is_relative_to(d) for d in excluded_dirs):
                continue
            if item.is_dir() and item.name.lower() in _AUTO_EXCLUDE_DIRS:
                logger.debug("Auto-excluding directory: %s", item)
                excluded_dirs.add(item)
                continue
            if item.is_dir() and not item.is_symlink() and detect_collection(item) is not None:
                results.extend(self._collection_items(item))
                excluded_dirs.add(item)
                continue
            try:
                self._process_item(item, results, seen_log_dirs)
            except (PermissionError, OSError) as exc:
                logger.warning("Skipping inaccessible file %s: %s", item, exc)
                continue

        return results

    def _collection_items(self, path: Path) -> list[ClassifiedEvidence]:
        """The triage collection at *path* as one item, whatever it holds.

        Images, memory dumps, captures and archives left at its top level are
        not part of what the collector wrote, and stay items of their own. So
        do the memory and crash dumps the collector copied (KAPE takes
        ``MEMORY.DMP`` and ``*.dmp``): Volatility reads those, wherever they are.
        """
        collection = detect_collection(path)
        if collection is not None and collection.layout == "export":
            return []  # written by export_linux_files from an image that is the evidence
        items = [ClassifiedEvidence(path=path, artifact_type="triage_collection")]
        try:
            children = sorted(p for p in path.iterdir() if p.is_file() and not p.is_symlink())
        except OSError:
            return items
        for child in children:
            found = None if child.name.startswith(".") else self._classify_file(child)
            if found is not None and found.artifact_type in _CONTAINER_TYPES:
                items.append(found)
        for rel, stored in sorted(walk_files(path, [MAX_ENTRIES])):
            if "/" not in rel or not rel.lower().endswith(_COLLECTED_DUMP_EXTS):
                continue  # at the top level (seen above), or not named as a dump
            found = self._classify_file(Path(stored))
            if found is not None and found.artifact_type == "memory_dump":
                items.append(found)
        return items

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
            # A source tree is evidence as a whole: its workflows are how a CI
            # compromise happens, and they live in a hidden directory the walk
            # never enters.
            if is_repository(item):
                results.append(ClassifiedEvidence(path=item, artifact_type="repository"))
            if is_ci_run_log_directory(item) and item not in seen_log_dirs:
                results.append(ClassifiedEvidence(path=item, artifact_type="ci_run_logs"))
                seen_log_dirs.add(item)
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

        # Autoruns CSV files are classified before the general extension skip
        if ext == ".csv" and any(pat in name for pat in _AUTORUNS_CSV_PATTERNS):
            return ClassifiedEvidence(path=path, artifact_type="autoruns_csv")

        # Likewise for JSON, which is otherwise skipped as project clutter.
        if ext in JSON_LOG_EXTS and is_cloud_audit_log(path):
            return ClassifiedEvidence(path=path, artifact_type="cloud_audit_log")

        if name in _SKIP_FILENAMES or ext in _SKIP_EXTENSIONS:
            return None

        if is_nfcapd(path):
            return ClassifiedEvidence(path=path, artifact_type="netflow_capture")

        if ext in RAW_CONTAINER_EXTS and has_disk_signature(path):
            return ClassifiedEvidence(path=path, artifact_type="disk_image")

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
    """True if any component of *path* is dot-prefixed.

    *path* is relative to the evidence root: a dot-directory above the root
    (``~/.cache/case/evidence``) says nothing about what is inside it.
    """
    return any(part.startswith(".") for part in path.parts if part != ".")
