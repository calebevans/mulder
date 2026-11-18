"""Encryption activity composite: bursts of renames to one extension on an NTFS volume.

Reads the indexed change journal (``ez.usnjrnl``), or the MFT (``ez.mft``) when
no journal is indexed, and reports when many files were renamed to the same
extension at once, how many kinds of file it was appended to, where it started
and which same-named files were dropped across directories. Everything it
returns is a candidate with numbers; it names no process, no account and no
verdict.
"""

from __future__ import annotations

import csv
import io
import re
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import NamedTuple

from mulder.models import SourceRow
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import make_tool_call_id
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.composite.core import (
    _SRC_EZ_MFT,
    _SRC_EZ_USNJRNL,
    _check_missing_sources,
    _invalidate_sources_cache,
    decode_evidence_text,
    finalize_composite_result,
    iter_source_text,
    read_image_file,
)
from mulder.server.tools.composite.ransomware_family import (
    CAVEAT as _FAMILY_CAVEAT,
)
from mulder.server.tools.composite.ransomware_family import (
    family_hints,
    is_known_note_name,
)
from mulder.server.tools.extract.tsk import _resolve_partition_offset

__all__ = ["find_encryption_activity"]

# ---------------------------------------------------------------------------
# Thresholds. Each is a floor for "worth reporting", not a definition of
# ransomware; the output carries the numbers so the reader can judge. They
# were set against the journal of a real WannaCry infection
# (cado-security/kape-wannacry), in which Windows servicing renamed 712 files
# to .mum in one minute and the ransomware 100 files to .WNCRY: volume alone
# picks the wrong burst, which is why bursts are found per extension and a
# candidate needs a signal.
# ---------------------------------------------------------------------------

# A minute is hot for an extension when at least this many files were renamed
# to it (journal) or last changed with it (MFT). Mass encryption runs at
# thousands a minute on a server; encryption throttled below this is not found.
_BURST_MIN_FILES_PER_MINUTE = 50
# Hot minutes separated by at most this many quiet minutes are one burst.
_BURST_MAX_GAP_MINUTES = 2
# Extension bursts examined in detail, largest first; more are counted only.
# The encryption burst is rarely the largest (an OS install on the same volume
# dwarfs it), so this is a memory bound, not a shortlist.
_MAX_BURSTS = 1000
# "Appended" means the extension follows at least this many kinds of data file
# (a.docx.EXT, b.jpg.EXT, c.pdf.EXT) on at least this share of the burst's
# files. In the calibration journal .WNCRY followed 10 kinds on every file;
# .cab followed one (x.xml.cab) and .dll none. Compressing or backing up a
# data directory (x.docx.gz) looks the same and is a known false lead.
_APPENDED_MIN_KINDS = 3
_APPENDED_MIN_SHARE = 0.5
# A file name created in at least this many directories during a burst is
# listed as a ransom note candidate; a name on the known note list needs fewer.
# Installers and profile creation repeat names too (26 directories for one
# settings file in the calibration journal), so a repeated name only makes a
# candidate together with an extension the volume never had before.
_NOTE_MIN_DIRECTORIES = 5
_KNOWN_NOTE_MIN_DIRECTORIES = 2
# Distinct (extension, minute) pairs counted. A volume renamed to a different
# random extension per file would otherwise grow the table without bound.
_MAX_TRACKED = 500_000

_MAX_CANDIDATES = 3
_MAX_BUSY_PERIODS = 3
_TOP_DIRECTORIES = 5
_FIRST_DIRECTORIES = 3
_MAX_NOTE_CANDIDATES = 5
_NOTE_READ_BYTES = 8192
_NOTE_EXCERPT_CHARS = 1200
_NOTE_ENTRIES_KEPT = 3
_NAME_CAP = 120
_PATH_CAP = 160
_MINUTE = "%Y-%m-%d %H:%M"

_TS_RE = re.compile(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d")
_CLEAN_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Extensions of files people keep data in. Only these count as an "original"
# extension, because every dotted name has a last component (System.Net.Http.dll
# is not x.http.dll). The few that coincide (System.Text.Json.dll) stay far
# under the share threshold.
_DATA_EXTENSION_NAMES = (
    "doc docx docm xls xlsx xlsm ppt pptx pdf txt rtf csv odt ods odp one vsd vsdx dwg "
    "jpg jpeg png gif bmp tif tiff psd svg heic raw mp3 mp4 avi mov mkv wav "
    "zip rar 7z tar gz iso vhd vhdx vmdk vmx ova bak "
    "sql mdb accdb db sqlite mdf ldf ndf edb dbf pst ost msg eml kdbx pfx pem key "
    "xml json yaml yml html htm js css php py java c cpp h cs vb ps1 bat cmd vbs "
    "ini cfg conf log dat wim"
)
_DATA_EXTENSIONS = frozenset(_DATA_EXTENSION_NAMES.split())

_USN_COLUMNS = (
    "Name",
    "Extension",
    "EntryNumber",
    "ParentEntryNumber",
    "ParentPath",
    "UpdateTimestamp",
    "UpdateReasons",
    "FileAttributes",
)
_MFT_COLUMNS = (
    "EntryNumber",
    "InUse",
    "ParentEntryNumber",
    "ParentPath",
    "FileName",
    "Extension",
    "IsDirectory",
    "Created0x10",
    "LastRecordChange0x10",
)

_CAVEATS = [
    "A candidate is a lead, not a finding of encryption. Compression, backup and restore, "
    "and bulk renames also give many files one new extension in a minute. Read rows from "
    "the burst (inspect_with) before saying what happened.",
    "The journal and the MFT record that files changed, not which process or account "
    "changed them. Tie a burst to a process and a logon with execution artifacts and "
    "event logs.",
    "No candidate is not no encryption: ransomware that overwrites files in place, that "
    "gives each file a different extension or none, that runs slower than the burst "
    "threshold, or that ran before the oldest journal record is not flagged here. "
    "busiest_periods lists the largest bursts of any kind for that reason.",
    "Times are UTC as written by MFTECmd.",
    "family_hints: " + _FAMILY_CAVEAT,
]
_MFT_BASIS_NOTE = (
    "No change journal is indexed for this volume, so the timeline comes from the MFT. "
    "The MFT keeps one record-change time per file (the last), so earlier changes to the "
    "same file are invisible, every file creation counts as a change, and the times can "
    "be forged."
)


class _Event(NamedTuple):
    """One file change or creation, from either source."""

    ts: str  # "YYYY-MM-DD HH:MM:SS"
    entry: int
    name: str
    ext: str  # lower case, with the dot; "" when the name has none
    parent: int
    parent_path: str
    renamed: bool  # journal: renamed to this name; MFT: record last changed
    overwritten: bool
    created: bool


class _Note(NamedTuple):
    """A file name created across directories during one burst."""

    key: str  # lower-cased name
    name: str
    directories: int
    known: bool


@dataclass
class _Scan:
    """What one read of a source saw."""

    rows: int = 0
    rows_unparsed: int = 0
    windows_unparsed: int = 0
    unreadable: bool = False
    first_record: str = "9999"
    last_record: str = ""


@dataclass
class _Burst:
    """A run of hot minutes, for one extension or (``ext`` None) for all changes."""

    ext: str | None
    start: str  # first hot minute, "YYYY-MM-DD HH:MM"
    end: str
    peak: int
    peak_minute: str
    size: int
    first_ts: str = "9999"
    last_ts: str = ""
    names: dict[int, str] = field(default_factory=dict)  # entry -> latest name
    exts: Counter[str] = field(default_factory=Counter)
    dirs: Counter[int] = field(default_factory=Counter)
    dir_first: dict[int, str] = field(default_factory=dict)
    # Filled in once the burst is complete.
    originals: Counter[str] = field(default_factory=Counter)
    appended_share: float = 0.0
    notes: list[_Note] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)

    def add(self, event: _Event) -> None:
        """Count a changed file."""
        self.first_ts = min(self.first_ts, event.ts)
        self.last_ts = max(self.last_ts, event.ts)
        if event.entry not in self.names:
            self.dirs[event.parent] += 1
            self.exts[event.ext] += 1
        self.names[event.entry] = event.name
        if event.ts < self.dir_first.get(event.parent, "9999"):
            self.dir_first[event.parent] = event.ts

    @property
    def first_directories(self) -> list[int]:
        return sorted(self.dir_first, key=self.dir_first.__getitem__)[:_FIRST_DIRECTORIES]

    def __post_init__(self) -> None:
        # The window widened by the burst gap, as minute strings (which sort by time).
        gap = timedelta(minutes=_BURST_MAX_GAP_MINUTES)
        self.reach_from = (datetime.strptime(self.start, _MINUTE) - gap).strftime(_MINUTE)
        self.reach_to = (datetime.strptime(self.end, _MINUTE) + gap).strftime(_MINUTE)

    def near(self, other: _Burst) -> bool:
        """Whether the two bursts overlap or lie within the burst gap of each other."""
        return self.reach_from <= other.end and other.start <= self.reach_to


def _clean(text: str, cap: int) -> str:
    """A file name or path made safe to show: no control characters, bounded."""
    text = _CLEAN_RE.sub("?", text)
    return text if len(text) <= cap else text[: cap - 3] + "..."


def _iso(ts: str) -> str:
    return ts.replace(" ", "T")


def _valid(ts: str) -> bool:
    """Whether *ts* is a real ``YYYY-MM-DD HH:MM:SS`` time."""
    if not _TS_RE.fullmatch(ts):
        return False
    try:
        datetime.fromisoformat(ts)
    except ValueError:
        return False
    return True


def _source_rows(source: SourceRow, scan: _Scan) -> Iterator[list[str]]:
    """CSV rows of one indexed source in file order, header first.

    Windows never split a line, so each parses on its own. A window the CSV
    parser rejects is counted and skipped rather than ending the scan.
    """
    for text in iter_source_text(source):
        try:
            yield from csv.reader(io.StringIO(text.lstrip("\ufeff")))
        except csv.Error:
            scan.windows_unparsed += 1


def _events(source: SourceRow, is_usn: bool, scan: _Scan) -> Iterator[_Event]:
    """Turn a source's CSV rows into change and creation events.

    Journal: one event per closed handle that renamed, overwrote or created a
    file (the ``Close`` record carries every reason of that handle). MFT: one
    change event at the record-change time and one creation event at the
    creation time of each file in use.
    """
    rows = _source_rows(source, scan)
    header = next(rows, None)
    columns = _USN_COLUMNS if is_usn else _MFT_COLUMNS
    if header is None or not all(c in header for c in columns):
        scan.unreadable = True
        return
    idx = [header.index(c) for c in columns]
    width = max(idx) + 1
    for row in rows:
        if len(row) < width:
            scan.rows_unparsed += 1
            continue
        scan.rows += 1
        values = [row[i] for i in idx]
        try:
            if is_usn:
                name, ext, entry, parent, path, stamp, reasons, attributes = values
                stamp = stamp[:19]
                if not _valid(stamp):
                    scan.rows_unparsed += 1
                    continue
                scan.first_record = min(scan.first_record, stamp)
                scan.last_record = max(scan.last_record, stamp)
                if "Close" not in reasons or "Directory" in attributes:
                    continue
                renamed = "RenameNewName" in reasons
                overwritten = "DataOverwrite" in reasons
                created = "FileCreate" in reasons
                if renamed or overwritten or created:
                    file = (int(entry), name, ext.lower(), int(parent), path)
                    yield _Event(stamp, *file, renamed, overwritten, created)
            else:
                entry, in_use, parent, path, name, ext, is_dir, born, changed_at = values
                if in_use != "True" or is_dir != "False":
                    continue
                file = (int(entry), name, ext.lower(), int(parent), path)
                if _valid(changed_at[:19]):
                    yield _Event(changed_at[:19], *file, True, False, False)
                if _valid(born[:19]):
                    yield _Event(born[:19], *file, False, False, True)
        except ValueError:
            scan.rows_unparsed += 1


def _find_bursts(per_minute: dict[str, int], ext: str | None) -> list[_Burst]:
    """Merge hot minutes into bursts."""
    hot = sorted(m for m, n in per_minute.items() if n >= _BURST_MIN_FILES_PER_MINUTE)
    gap = timedelta(minutes=_BURST_MAX_GAP_MINUTES + 1)
    groups: list[list[str]] = []
    previous: datetime | None = None
    for minute in hot:
        moment = datetime.strptime(minute, _MINUTE)
        if previous is None or moment - previous > gap:
            groups.append([])
        groups[-1].append(minute)
        previous = moment
    bursts = []
    for group in groups:
        peak_minute = max(group, key=per_minute.__getitem__)
        size = sum(per_minute[m] for m in group)
        bursts.append(_Burst(ext, group[0], group[-1], per_minute[peak_minute], peak_minute, size))
    return bursts


def _minutes(burst: _Burst) -> Iterator[str]:
    """Every minute from a burst's first hot minute to its last."""
    moment = datetime.strptime(burst.start, _MINUTE)
    while moment <= datetime.strptime(burst.end, _MINUTE):
        yield moment.strftime(_MINUTE)
        moment += timedelta(minutes=1)


def _assess(
    burst: _Burst, hot: set[str], created: dict[str, dict[str, set[int]]], display: dict[str, str]
) -> None:
    """Work out a finished extension burst's originals, note candidates and signals.

    *hot* holds the extensions with a burst at the same time. A repeated name
    ending in one is an encrypted file (desktop.ini.EXT in every directory),
    not a note, unless it is a data extension, which notes use too. *created*
    maps minute to the names created in it and their directories.
    """
    ext = burst.ext or ""
    for name in burst.names.values():
        stem = name[: len(name) - len(ext)].lower() if name.lower().endswith(ext) else ""
        original = stem.rpartition(".")[2] if "." in stem[1:] else ""
        if original in _DATA_EXTENSIONS:
            burst.originals["." + original] += 1
    if burst.names:
        burst.appended_share = sum(burst.originals.values()) / len(burst.names)

    parents: dict[str, set[int]] = {}
    for minute in _minutes(burst):
        for key, directories in created.get(minute, {}).items():
            parents.setdefault(key, set()).update(directories)
    notes = []
    for key, directories in parents.items():
        suffix = Path(key).suffix
        if suffix == ext or (suffix in hot and suffix[1:] not in _DATA_EXTENSIONS):
            continue
        known = len(directories) >= _KNOWN_NOTE_MIN_DIRECTORIES and is_known_note_name(key)
        if known or len(directories) >= _NOTE_MIN_DIRECTORIES:
            notes.append(_Note(key, display[key], len(directories), known))
    notes.sort(key=lambda n: (not n.known, -n.directories, n.key))
    burst.notes = notes[:_MAX_NOTE_CANDIDATES]

    appended = len(burst.originals) >= _APPENDED_MIN_KINDS
    if appended and burst.appended_share >= _APPENDED_MIN_SHARE:
        burst.signals.append("extension_appended")
    if any(n.known for n in notes):
        burst.signals.append("known_note_name")
    if any(not n.known for n in notes):
        burst.signals.append("repeated_file_across_directories")


def _is_candidate(burst: _Burst, is_usn: bool) -> bool:
    """Whether a burst's signals make it worth reporting as a candidate.

    A new extension plus a repeated file counts only from the journal: in the
    MFT every creation is a change, so unpacking any archive has both.
    """
    signals = set(burst.signals)
    return bool(signals & {"extension_appended", "known_note_name"}) or (
        is_usn and {"extension_new_to_volume", "repeated_file_across_directories"} <= signals
    )


def _mft_facts(
    mft: SourceRow, extensions: set[str], entries: set[int]
) -> tuple[dict[str, tuple[int, str, str]], dict[int, tuple[str, str]]]:
    """One pass over the MFT for what the journal cannot say.

    Returns ``{extension: (files now carrying it, earliest, latest record
    change)}`` and ``{entry: (path, file name)}`` for the in-use entries asked
    about (directories to name, notes to verify).
    """
    rows = _source_rows(mft, _Scan())
    header = next(rows, None)
    if header is None or not all(c in header for c in _MFT_COLUMNS):
        return {}, {}
    col = {c: header.index(c) for c in _MFT_COLUMNS}
    width = max(col.values()) + 1
    by_ext: dict[str, tuple[int, str, str]] = {}
    found: dict[int, tuple[str, str]] = {}
    for row in rows:
        if len(row) < width or row[col["InUse"]] != "True":
            continue
        ext = row[col["Extension"]].lower()
        stamp = row[col["LastRecordChange0x10"]][:19]
        if ext in extensions and _valid(stamp):
            count, earliest, latest = by_ext.get(ext, (0, stamp, stamp))
            by_ext[ext] = (count + 1, min(earliest, stamp), max(latest, stamp))
        entry = row[col["EntryNumber"]]
        if entry.isdigit() and int(entry) in entries:
            name = row[col["FileName"]]
            found[int(entry)] = (f"{row[col['ParentPath']]}\\{name}", name)
    return by_ext, found


def _read_note(
    image: str,
    burst: _Burst,
    entries: dict[str, list[int]],
    names: dict[int, tuple[str, str]],
    check_names: bool,
    verified: bool,
) -> tuple[dict[str, object], str]:
    """Read one note candidate from the image.

    Returns the fields to add to the burst (an excerpt, or why there is none)
    and the text read. A journal entry number can be reused after the note is
    deleted, so with *check_names* (journal plus MFT) a note is read only from
    an entry that still carries its name; *verified* says whether the entry
    number is known to hold the note.
    """
    if not Path(image).is_file():
        return {"note_not_read": "the evidence is not a disk image a file can be read from"}, ""
    offset = _resolve_partition_offset(image)
    reason = "no candidate could be read as text"
    for note in burst.notes:
        for entry in reversed(entries.get(note.key, [])):
            if check_names and names.get(entry, ("", ""))[1].lower() != note.key:
                reason = "the candidates' MFT entries no longer hold files of that name"
                continue
            read = read_image_file(image, str(entry), offset, _NOTE_READ_BYTES)
            text = (decode_evidence_text(read[0]) or "").strip() if read else ""
            if not text:
                continue
            excerpt: dict[str, object] = {
                "name": _clean(note.name, _NAME_CAP),
                "mft_entry": entry,
                "entry_verified_in_mft": verified,
                "text": text[:_NOTE_EXCERPT_CHARS],
                "truncated": bool(read and read[1]) or len(text) > _NOTE_EXCERPT_CHARS,
            }
            return {"note_excerpt": excerpt}, text
    return {"note_not_read": reason}, ""


def _analyse_volume(image: str, usn: SourceRow | None, mft: SourceRow | None) -> dict[str, object]:
    """Find and describe the bursts on one volume."""
    is_usn = usn is not None
    source = usn or mft
    volume: dict[str, object] = {"evidence": image, "basis": "usn_journal" if is_usn else "mft"}
    if source is None:
        return volume

    # Pass 1: files changed per minute, and files renamed to each extension per minute.
    scan = _Scan()
    changed: dict[str, set[int]] = {}
    renamed: Counter[tuple[str, str]] = Counter()
    for event in _events(source, is_usn, scan):
        minute = event.ts[:16]
        if event.renamed or event.overwritten:
            changed.setdefault(minute, set()).add(event.entry)
        key = (event.ext, minute)
        if event.renamed and event.ext and (key in renamed or len(renamed) < _MAX_TRACKED):
            renamed[key] += 1
    volume["records_examined"] = scan.rows
    if scan.rows_unparsed or scan.windows_unparsed:
        volume["rows_unparsed"] = scan.rows_unparsed
        volume["windows_unparsed"] = scan.windows_unparsed
    if scan.unreadable:
        volume["not_parsed"] = "The indexed source is not MFTECmd CSV with the expected columns."
        return volume
    if len(renamed) >= _MAX_TRACKED:
        volume["extensions_not_all_tracked"] = (
            f"More than {_MAX_TRACKED} extension and minute pairs; later ones were not counted."
        )
    if is_usn and scan.last_record:
        volume["journal_window"] = {
            "first_record": _iso(scan.first_record),
            "last_record": _iso(scan.last_record),
        }
    if not is_usn:
        volume["basis_note"] = _MFT_BASIS_NOTE

    hot = {ext for (ext, _minute), n in renamed.items() if n >= _BURST_MIN_FILES_PER_MINUTE}
    first_seen: dict[str, str] = {}
    per_ext: dict[str, dict[str, int]] = {ext: {} for ext in hot}
    for (ext, minute), count in renamed.items():
        if ext in hot:
            per_ext[ext][minute] = count
            first_seen[ext] = min(first_seen.get(ext, minute), minute)
    bursts = [b for ext in sorted(hot) for b in _find_bursts(per_ext[ext], ext)]
    bursts.sort(key=lambda b: -b.size)
    volume["extension_bursts_found"] = len(bursts)
    if len(bursts) > _MAX_BURSTS:
        volume["extension_bursts_not_examined"] = len(bursts) - _MAX_BURSTS
        bursts = bursts[:_MAX_BURSTS]
    busy = _find_bursts({minute: len(files) for minute, files in changed.items()}, None)
    busy = sorted(busy, key=lambda b: -b.size)[:_MAX_BUSY_PERIODS]
    del changed, renamed

    # Pass 2: detail for the minutes that belong to a burst.
    by_ext_minute = {(b.ext, m): b for b in bursts for m in _minutes(b)}
    busy_minute = {m: b for b in busy for m in _minutes(b)}
    created: dict[str, dict[str, set[int]]] = {m: {} for _ext, m in by_ext_minute}
    entries: dict[str, list[int]] = {}
    display: dict[str, str] = {}
    dir_paths: dict[int, str] = {}
    for event in _events(source, is_usn, _Scan()) if bursts or busy else ():
        minute = event.ts[:16]
        found = by_ext_minute.get((event.ext, minute)) if event.renamed else None
        period = busy_minute.get(minute) if event.renamed or event.overwritten else None
        for burst in (found, period):
            if burst is not None:
                burst.add(event)
                if event.parent_path:
                    dir_paths[event.parent] = event.parent_path
        if event.created and minute in created:
            lowered = event.name.lower()
            created[minute].setdefault(lowered, set()).add(event.parent)
            kept = entries.setdefault(lowered, [])
            kept.append(event.entry)
            del kept[:-_NOTE_ENTRIES_KEPT]
            display[lowered] = event.name
    bursts = [b for b in bursts if b.names]
    busy = [b for b in busy if b.names]
    for burst in bursts:
        concurrent = {b.ext or "" for b in bursts if b.near(burst)}
        _assess(burst, concurrent, created, display)
    del created
    signalled = [b for b in bursts if b.signals]

    # What only the MFT knows: whether the extension existed before the burst
    # (a journal that wrapped mid-encryption shows only the end), directory
    # names the journal did not carry, and whether a note's entry still holds it.
    wanted: set[int] = set()
    for burst in signalled + busy:
        wanted.update(p for p, _n in burst.dirs.most_common(_TOP_DIRECTORIES))
        wanted.update(burst.first_directories)
    wanted -= set(dir_paths)
    note_entries = {e for b in signalled for n in b.notes for e in entries.get(n.key, [])}
    on_volume: dict[str, tuple[int, str, str]] = {}
    names: dict[int, tuple[str, str]] = {}
    check_mft = is_usn and mft is not None
    if mft is not None and check_mft and (signalled or wanted):
        extensions = {b.ext or "" for b in signalled}
        on_volume, names = _mft_facts(mft, extensions, wanted | note_entries)
        dir_paths.update({e: path for e, (path, _name) in names.items() if e in wanted})
    for burst in signalled:
        # No file on the volume carried the extension before the burst. The
        # journal alone cannot say this: it only covers its own window.
        ext = burst.ext or ""
        if ext in on_volume:
            earliest = on_volume[ext][1][:16]
        elif not is_usn:
            earliest = first_seen[ext]
        else:
            continue
        if earliest >= burst.start:
            burst.signals.append("extension_new_to_volume")

    ranked = sorted(
        (b for b in signalled if _is_candidate(b, is_usn)),
        key=lambda b: (-len(b.signals), -b.size),
    )
    candidates: list[_Burst] = []
    for burst in ranked:
        if not any(c.near(burst) for c in candidates) and len(candidates) < _MAX_CANDIDATES:
            candidates.append(burst)
    # Other extensions renamed to at the same time belong to the same activity
    # (WannaCry writes x.WNCRYT, then renames it to x.WNCRY). Not from the MFT,
    # where anything created in those minutes would qualify.
    related: dict[int, list[_Burst]] = {}
    for burst in bursts if is_usn else ():
        owner = next((c for c in candidates if c.near(burst)), None)
        if owner is not None and burst not in candidates:
            related.setdefault(id(owner), []).append(burst)

    def _dir(entry: int) -> str:
        return _clean(dir_paths.get(entry) or f"(MFT entry {entry}, path not resolved)", _PATH_CAP)

    def _describe(burst: _Burst) -> dict[str, object]:
        first = datetime.fromisoformat(burst.first_ts)
        last = datetime.fromisoformat(burst.last_ts)
        return {
            "first_time": _iso(burst.first_ts),
            "last_time": _iso(burst.last_ts),
            "duration_seconds": int((last - first).total_seconds()),
            "files_affected": len(burst.names),
            "peak_files_per_minute": burst.peak,
            "peak_minute": _iso(burst.peak_minute),
        }

    reader = "parse_usn_journal" if is_usn else "parse_mft"
    # A burst that starts in the journal's first two minutes started before the journal did.
    journal_edge = ""
    if is_usn and scan.last_record:
        edge = datetime.strptime(scan.first_record[:16], _MINUTE) + timedelta(minutes=1)
        journal_edge = edge.strftime(_MINUTE)

    out_candidates = []
    for burst in candidates:
        ext = burst.ext or ""
        summary: dict[str, object] = {"extension": _clean(ext, _NAME_CAP), **_describe(burst)}
        summary["signals"] = burst.signals
        summary["appended_to_extensions"] = len(burst.originals)
        summary["appended_share"] = round(burst.appended_share, 2)
        summary["original_extensions"] = [e for e, _n in burst.originals.most_common(5)]
        if id(burst) in related:
            summary["related_extensions"] = [
                {
                    "extension": _clean(r.ext or "", _NAME_CAP),
                    "files_affected": len(r.names),
                    "first_time": _iso(r.first_ts),
                    "last_time": _iso(r.last_ts),
                }
                for r in related[id(burst)][:5]
            ]
        summary["directories_affected"] = len(burst.dirs)
        summary["top_directories"] = [
            {"path": _dir(p), "files": n} for p, n in burst.dirs.most_common(_TOP_DIRECTORIES)
        ]
        summary["first_directories"] = [_dir(p) for p in burst.first_directories]
        summary["note_candidates"] = [
            {
                "name": _clean(n.name, _NAME_CAP),
                "directories": n.directories,
                "known_note_name": n.known,
            }
            for n in burst.notes
        ]
        note_text = ""
        if burst.notes:
            verified = check_mft or not is_usn
            fields, note_text = _read_note(image, burst, entries, names, check_mft, verified)
            summary.update(fields)
        hints = family_hints(ext, burst.notes[0].name if burst.notes else "", note_text)
        summary["family_hints"] = hints["hints"]
        if "corpus" in hints:
            summary["family_hints_corpus"] = hints["corpus"]
        if ext in on_volume:
            count, earliest, latest = on_volume[ext]
            summary["mft_cross_check"] = {
                "files_now_with_extension": count,
                "earliest_record_change": _iso(earliest),
                "latest_record_change": _iso(latest),
            }
        if burst.start <= journal_edge:
            summary["starts_at_journal_start"] = (
                "The journal's oldest record is inside this burst, so the burst began "
                "earlier than first_time. See mft_cross_check for the earliest change."
            )
        summary["inspect_with"] = (
            f"{reader}(t_start='{summary['first_time']}', t_end='{summary['last_time']}')"
        )
        out_candidates.append(summary)
    volume["candidates"] = out_candidates
    volume["extension_bursts_not_candidates"] = (
        len(bursts) - len(candidates) - sum(len(r) for r in related.values())
    )

    out_busy = []
    for burst in busy:
        summary = _describe(burst)
        top_ext, count = burst.exts.most_common(1)[0]
        summary["top_extension"] = _clean(top_ext, _NAME_CAP)
        summary["top_extension_share"] = round(count / len(burst.names), 2)
        summary["top_directory"] = _dir(burst.dirs.most_common(1)[0][0])
        summary["overlaps_candidate"] = any(burst.near(c) for c in candidates)
        out_busy.append(summary)
    volume["busiest_periods"] = out_busy
    if out_busy:
        volume["busiest_periods_note"] = (
            "The largest bursts of renames and overwrites of any kind, for context. "
            "Updates, installs, backups and archive extraction look like this; so does "
            "ransomware that encrypts in place without renaming."
        )
    return volume


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR)
def find_encryption_activity() -> dict[str, object]:
    """Find bursts of file renames to one extension that may be ransomware encryption.

    Call when ransomware is suspected, after run_usn_parser (preferred) or
    run_mft_parser has indexed an NTFS volume. Windows evidence only: an empty
    result on anything else is not a negative finding.

    Returns, per volume, candidate bursts with the extension, first and last
    time, duration, files affected, peak files per minute, how many kinds of
    data file the extension was appended to, top and first directories,
    same-named files dropped across directories (ransom note candidates) with
    a bounded excerpt of one, and offline family hints; then the busiest
    periods of any kind. A candidate is a lead: compression, backup and bulk
    renames look the same, and neither source names the process or account.
    Indexed as ``composite.encryption_activity``.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    _invalidate_sources_cache()

    # The newest non-empty source of each kind per evidence path.
    by_image: dict[str, dict[str, SourceRow]] = {}
    for source in ctx.db.get_sources():
        if source.source_name in (_SRC_EZ_USNJRNL, _SRC_EZ_MFT) and source.line_count:
            by_image.setdefault(source.source_path, {})[source.source_name] = source

    results: dict[str, object] = {
        "volumes": [
            _analyse_volume(image, found.get(_SRC_EZ_USNJRNL), found.get(_SRC_EZ_MFT))
            for image, found in sorted(by_image.items())
        ],
        "caveats": _CAVEATS,
    }
    if not by_image:
        results["not_examined"] = (
            "No change journal or MFT is indexed, so nothing was examined. This is not a "
            "negative finding."
        )
    missing = _check_missing_sources(
        [
            (_SRC_EZ_USNJRNL, "run_usn_parser('<image_path>')"),
            (_SRC_EZ_MFT, "run_mft_parser('<image_path>')"),
        ]
    )
    return finalize_composite_result(
        ctx=ctx,
        composite_id=composite_id,
        tool_name="find_encryption_activity",
        results=results,
        coverage_sources=[_SRC_EZ_USNJRNL, _SRC_EZ_MFT],
        missing=missing,
        sub_call_ids=[],
        t0=t0,
        audit_params={"evidence": sorted(by_image)},
    )
