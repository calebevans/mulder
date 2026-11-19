"""Linux file access where Sleuth Kit has none, and a sweep of persistence locations.

``export_linux_files`` reads a disk image through dfVFS by driving plaso's
command-line tools (never by importing them: on SIFT plaso lives in its own
virtualenv).  log2timeline with only the filestat parser lists every file on
every volume; image_export then copies a targeted set into the case
directory as one Linux file tree, each volume at its mount point, which the
directory-root tools read the way they read any directory (``mulder.dirroot``).

``run_linux_persistence`` reads such a directory, a collection, or a Linux
image Sleuth Kit can open.

Everything read here comes from the evidence: names are matched and shown,
never trusted, and every read is bounded.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NamedTuple

from mulder.dirroot import dir_root, icat, listed_name, read_regular, refresh, walk_files
from mulder.linuxvol import (
    EXPORT_MARKER,
    EXPORTS_DIR,
    PRIVATE_KEY,
    SECRET_FILES,
    export_dir,
    probe,
    route,
    unencrypted_partitions,
)
from mulder.patterns import case_extract_dir, fls_file_entries
from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.plaso import (
    _L2T_FLAGS,
    _PLASO_TIMEOUT,
    _failure_detail,
    _find_plaso_cmd,
)
from mulder.server.tools.extract.tsk import _collect_fls_chunks, _index_dir_listing

__all__ = ["export_linux_files", "run_linux_persistence"]

_MIB = 1024 * 1024
_MAX_ENTRIES = 1_000_000
"""Entries of one image kept in the listing; the result says when more were left out."""

_MAX_FILE_BYTES = 64 * _MIB
_MAX_FILES = 50_000
_MAX_REQUESTED = 200
_MAX_RUNS = 40
"""image_export runs spent on one volume; a run that fails is repeated in halves."""
_LISTING_FILE = "filelist.tsv"
_MIN_TMP_FREE = 1024 * _MIB
"""Free temporary space below which no listing is started.

log2timeline and psort took 345 MiB for 85,000 entries. Short of space psort
fails, but log2timeline neither fails nor finishes before its timeout.
"""
# ponytail: a fixed floor, where the need grows with the number of entries
# (about 4 KiB each); estimate it from the image if large disks run short.

# A shell's start-up files, in any home directory.
_PROFILES = (
    r"bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin"
    r"|cshrc|tcshrc|kshrc|xprofile"
)

# What is exported without being asked for, and how many bytes of each kind. A
# path is the file's path on its volume, without the leading slash.
_TARGETS: tuple[tuple[str, int, re.Pattern[str]], ...] = tuple(
    (kind, limit, re.compile(pattern))
    for kind, limit, pattern in (
        (
            "config",
            1024 * _MIB,
            r"etc/|var/spool/(?:cron|at|anacron)/"
            r"|(?:usr/local/|usr/)?lib/(?:systemd/(?:system|user)|modules-load\.d|modprobe\.d"
            r"|udev/rules\.d)/"
            r"|var/lib/(?:dpkg/status[^/]*$|apt/extended_states$|rpm/|dnf/history[^/]*$"
            r"|yum/history/)",
        ),
        ("logs", 2048 * _MIB, r"var/log/|var/lib/docker/containers/[^/]+/[^/]+\.(?:json|log)$"),
        (
            "homes",
            512 * _MIB,
            # An account's home may be anywhere (/var/mail, /usr/php,
            # /var/lib/postgresql): what an intruder leaves in one is taken by
            # name from any directory, and every dotfile from the usual homes.
            r"root/|home/[^/]+/\.[^/]+$"
            r"|(?:.+/)?(?:\.ssh/|\.config/(?:systemd|autostart)/|\.local/share/systemd/"
            rf"|authorized_keys2?$|\.(?:[^/]*history|viminfo|{_PROFILES})$)",
        ),
        ("web", 512 * _MIB, r"(?:var/www|srv/www|usr/share/nginx/html)/"),
        ("tmp", 256 * _MIB, r"(?:tmp|var/tmp)/"),
    )
)

# A name that image_export's YAML filter file cannot carry.
_UNSAFE_NAME = re.compile(r"[^\x20-\x7e\xa0-\U0000d7ff\U0000e000-\U0000fffd\U00010000-\U0010ffff]")
# What image_export stores as "_" in a name: plaso's PathHelper._DIRTY_CHARACTERS
# (20261027), less the control characters, which no exported name holds.
_REPLACED = re.compile(r"[!$%&*+:;<>?@|~]")

_TIME_SLOTS = {
    "Content Modification Time": 0,
    "Metadata Modification Time": 1,
    "Creation Time": 2,
    "Last Access Time": 3,
}
_SELECTOR = re.compile(r"([a-z]{1,8})(\d{1,3})")
_HOME_SIGNS = re.compile(r"[^/]+/\.(?:bashrc|bash_logout|bash_profile|profile|ssh/)")
# Two of these make a guess: one alone is a database's journal directory, an
# application's log beside its lib, or a user called secure.
_VAR_SIGNS = frozenset({"log", "spool", "cache", "backups", "mail"})
_VAR_LOG_SIGNS = frozenset(
    {"journal", "syslog", "auth.log", "messages", "secure", "wtmp", "btmp", "lastlog", "kern.log"}
)
_ENCRYPTED = "Encrypted volume found"
_WARNINGS_RE = re.compile(r"Number of warnings generated while extracting events: (\d+)")
_WARNED_VOLUME_RE = re.compile(r"location: /([a-z]{1,8}\d{1,3})(?:,|$)")

_SHARED = (
    "its place in the export is another file's too (two names image_export stores as one): "
    "ask for one of them alone with paths"
)
_UNDER_MOUNT = (
    "under a mount point, where the running system showed the mounted volume's file of the "
    "same path, which is the one exported: ask for this one alone with paths"
)
_NOT_COPIED = "image_export did not copy it"

_EXPORT_NOTE = (
    "linux.filelist lists every file on the volumes that could be read, exported or not. "
    "A file listed there exists; deleted files are not listed and unallocated space was not "
    "read, so a file that is not listed may still have existed. Only the files under "
    "export_root can be read. It is one Linux file tree, each volume at the place the volumes "
    "list gives: pass export_root as image_path to run_linux_persistence and index_app_files, "
    "and read one file at export_root/<path>. To read a listed file that was not exported, "
    "call export_linux_files again with paths. Password hash files and private keys are not "
    "exported, by their well-known names (etc/shadow, SSH host and user keys, TLS private "
    "keys); a copy of one under another name is. The times on the exported copies are the "
    "modification times from the listing. When status is incomplete, listing_incomplete "
    "names the directories whose entries could not all be read and not_exported the files "
    "that could not be copied: what those hold was not examined. Whatever the status, "
    "not_exported names by reason the files of the targeted set that were left out."
)

# ponytail: one lock for every image; a lock per image if two Linux images of
# one case ever need exporting at the same time.
_export_lock = threading.Lock()


@dataclass(slots=True)
class _Entry:
    """One file, directory or link of a volume."""

    volume: str | None
    """``p5/lvm1``; ``""`` for an image that is one file system; ``?`` when it cannot be told."""
    path: str
    kind: str
    mode: int | None
    uid: int | None
    gid: int | None
    size: int
    times: list[int]
    """Modified, changed, created, accessed: microseconds since 1970, 0 when not recorded."""


class _Listing(NamedTuple):
    """What log2timeline's filestat pass found in an image."""

    entries: list[_Entry]
    """Ordered by volume and path."""
    cut: bool
    file_systems: dict[str, str]
    """The file system dfVFS named for each volume."""
    incomplete: list[str]
    """Directories whose entries could not all be read."""


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _volume(pathspec: object) -> str | None:
    """The volume a dfVFS path specification is on: ``p5/lvm1``, ``""`` for the only one.

    None when the event carries none, as for a directory or a link.
    """
    if not isinstance(pathspec, dict):
        return None
    parts: list[str] = []
    node = pathspec.get("parent")
    while isinstance(node, dict) and isinstance(node.get("parent"), dict):
        location = str(node.get("location") or "").lstrip("/")
        if _SELECTOR.fullmatch(location):
            parts.append(location)
        node = node["parent"]
    return "/".join(reversed(parts))


def _read_listing(jsonl: Path) -> tuple[list[_Entry], bool, dict[str, str]]:
    """Entries from psort's json_line output of a filestat run.

    Returns them ordered by volume and path, whether the listing was cut, and
    the file system dfVFS named for each volume.
    """
    entries: dict[tuple[str | None, str, object], _Entry] = {}
    file_systems: dict[str, str] = {}
    cut = False
    with jsonl.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                event = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if not isinstance(event, dict) or event.get("data_type") != "fs:stat":
                continue
            # A file's path specification holds its name as it is. "filename"
            # spells control characters out, and is all a directory or a link
            # has. A stream inside a file (a gzip member) has a specification
            # with no name of its own, and is not an entry of the volume.
            spec = event.get("pathspec")
            if isinstance(spec, dict) and spec.get("type_indicator") == "OS":
                # plaso found no volume or file system in the source and
                # stat'ed the image file itself: an entry of the host, not of it.
                continue
            path = spec.get("location") if isinstance(spec, dict) else event.get("filename")
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            # Without a path specification, the inode is all that tells the /lib
            # of one volume from the /lib of another.
            inode = None if isinstance(spec, dict) else str(event.get("inode"))
            key = (_volume(spec), path, inode)
            entry = entries.get(key)
            if entry is None:
                if len(entries) >= _MAX_ENTRIES:
                    cut = True
                    continue
                kind = str(event.get("file_entry_type") or "")
                entry = entries[key] = _Entry(
                    key[0],
                    path,
                    kind if re.fullmatch(r"[a-z_]{1,20}", kind) else "?",
                    _int(event.get("mode")),
                    _int(event.get("owner_identifier")),
                    _int(event.get("group_identifier")),
                    _int(event.get("file_size")) or 0,
                    [0, 0, 0, 0],
                )
                fs = str(event.get("file_system_type") or "")
                if key[0] is not None and re.fullmatch(r"[A-Za-z0-9_]{1,16}", fs):
                    file_systems.setdefault(key[0], fs)
            slot = _TIME_SLOTS.get(str(event.get("timestamp_desc")))
            stamp = _int(event.get("timestamp"))
            if slot is not None and stamp:
                entry.times[slot] = stamp

    # A directory or a link carries no path specification. It is on the volume
    # of the nearest directory, at or above it, whose files are on one volume.
    owners: dict[str, set[str]] = {}
    for volume, path, _ in entries:
        while volume is not None and path:
            path = path.rpartition("/")[0]
            seen = owners.setdefault(path, set())
            if volume in seen:
                break
            seen.add(volume)
    for entry in entries.values():
        directory = entry.path
        while entry.volume is None:
            seen = owners.get(directory, set())
            if seen or not directory:
                entry.volume = next(iter(seen)) if len(seen) == 1 else "?"
            directory = directory.rpartition("/")[0]
    return sorted(entries.values(), key=lambda e: (e.volume or "", e.path)), cut, file_systems


def _iso(micros: float) -> str:
    try:
        return datetime.fromtimestamp(micros / 1_000_000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return "-"


def _render(entries: Iterable[_Entry]) -> str:
    """The listing as it is indexed and kept: one tab-separated row per entry."""
    rows = ["volume\ttype\tmode\tuid\tgid\tsize\tmodified\tchanged\tcreated\taccessed\tpath"]
    for e in entries:
        fields = [
            e.volume or "-",
            e.kind,
            "-" if e.mode is None else f"{e.mode & 0o7777:04o}",
            "-" if e.uid is None else str(e.uid),
            "-" if e.gid is None else str(e.gid),
            str(e.size),
            *(_iso(t) if t else "-" for t in e.times),
            listed_name(e.path),
        ]
        rows.append("\t".join(fields))
    return "\n".join(rows)


def _parse(listing: str) -> list[_Entry]:
    """The rows :func:`_render` wrote, for a later call that exports more."""
    entries: list[_Entry] = []
    # Split where _render joined, and nowhere else: a name may hold what
    # str.splitlines takes for a line break.
    for row in listing.split("\n")[1:]:
        f = row.split("\t", 10)
        if len(f) != 11:
            continue
        times = [0, 0, 0, 0]
        with contextlib.suppress(ValueError):
            times[0] = int(datetime.fromisoformat(f[6]).timestamp() * 1_000_000)
        size = int(f[5]) if f[5].isdigit() else 0
        volume = "" if f[0] == "-" else f[0]
        entries.append(_Entry(volume, f[10], f[1], None, None, None, size, times))
    return entries


def _mount(paths: set[str]) -> tuple[str | None, str]:
    """Where a volume belongs in the tree, as a path prefix, and how that is known.

    None when it is not recognised. Only the mount points that most often get
    a volume of their own are guessed, from the volume's top-level names. The
    prefix decides which of the targeted paths apply and where the volume's
    files are put in the export; the result says that it is a guess.
    """
    if "etc/passwd" in paths:
        return "", "the root volume: it holds etc/passwd"
    tops = {p.split("/", 1)[0] for p in paths}
    if "lib" in tops and len(tops & _VAR_SIGNS) > 1:
        return "var/", "read as /var, guessed from its top-level names"
    if len(tops & _VAR_LOG_SIGNS) > 1:
        return "var/log/", "read as /var/log, guessed from its top-level names"
    if any(_HOME_SIGNS.match(p) for p in paths):
        return "home/", "read as /home, guessed from the dotfiles in its directories"
    if any(top.startswith(("vmlinuz", "grub")) for top in tops):
        return "boot/", "read as /boot, guessed from its top-level names"
    return None, "mount point not recognised: read as a root volume"


def _dirname(volume: str | None) -> str:
    """A directory name for a volume that has no place of its own in the tree."""
    return (volume or "").replace("/", "_") or "vol"


def _places(mounts: dict[str, tuple[str | None, str]]) -> dict[str, str]:
    """The directory of the export each volume's files go to, as a prefix.

    Its mount point, so that the export reads as the one tree the system had.
    A volume whose mount point is not known, or is another volume's already,
    gets a directory named after it instead.
    """
    places: dict[str, str] = {}
    for volume in sorted(mounts, key=lambda v: (mounts[v][0] != "", v)):
        prefix = mounts[volume][0]
        if prefix is None or prefix in places.values():
            prefix = f"{_dirname(volume)}/"
        places[volume] = prefix
    return places


def _stored(target: Path, path: str) -> Path | None:
    """Where image_export puts *path* under *target*; None for a path that could leave it."""
    parts = path.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    return target.joinpath(*parts)


def _as_stored(target: Path, path: str) -> Path:
    """Where image_export writes *path* under *target*, as its own sanitising has it.

    "_" for the characters of ``_REPLACED`` and for a segment that is "." or
    "..", and a backslash taken for a separator: ``ssh@.service`` is stored as
    ``ssh_.service`` and ``a\\b`` as ``b`` in a directory ``a``.
    """
    parts = _REPLACED.sub("_", path).replace("\\", "/").split("/")
    return target.joinpath(*("_" if part in (".", "..") else part for part in parts if part))


def _refusal(entry: _Entry, rel: str) -> str | None:
    """Why a file is not exported whoever asks, or None."""
    if SECRET_FILES.search(rel):
        return "not exported (password hashes and private keys, by name)"
    if entry.size > _MAX_FILE_BYTES:
        return f"larger than {_MAX_FILE_BYTES // _MIB} MiB"
    if (
        _UNSAFE_NAME.search(entry.path)
        or listed_name(entry.path) != entry.path
        or _stored(Path(), entry.path) is None
    ):
        return "name holds characters that cannot be passed to image_export"
    return None


def _shown(entry: _Entry) -> str:
    return listed_name(f"{entry.volume}:{entry.path}" if entry.volume else entry.path)


def _some(names: list[str], limit: int = 10) -> list[str]:
    return names if len(names) <= limit else [*names[:limit], f"... and {len(names) - limit} more"]


def _select(
    entries: Sequence[_Entry], mounts: dict[str, tuple[str | None, str]]
) -> tuple[list[_Entry], dict[str, int], dict[str, list[str]]]:
    """The targeted set: the files to export, how many of each kind, and what was left out."""
    found: dict[str, list[_Entry]] = {kind: [] for kind, _, _ in _TARGETS}
    left: dict[str, list[str]] = {}
    for entry in entries:
        mount = mounts.get(entry.volume) if entry.volume is not None else None
        if entry.kind != "file" or mount is None:
            continue
        rel = (mount[0] or "") + entry.path[1:]
        kind = next((k for k, _, pattern in _TARGETS if pattern.match(rel)), None)
        if kind is None:
            continue
        reason = _refusal(entry, rel)
        if reason:
            left.setdefault(reason, []).append(_shown(entry))
        else:
            found[kind].append(entry)
    picks: list[_Entry] = []
    counts: dict[str, int] = {}
    for kind, limit, _ in _TARGETS:
        before = len(picks)
        # The most recently modified first: when a limit cuts, it cuts old rotations.
        for entry in sorted(found[kind], key=lambda e: -e.times[0]):
            if len(picks) >= _MAX_FILES or entry.size > limit:
                left.setdefault(f"over the limit for {kind}", []).append(_shown(entry))
                continue
            limit -= entry.size
            picks.append(entry)
        counts[kind] = len(picks) - before
    return picks, counts, left


def _settle(entry: _Entry, raw: Path, final: Path) -> bool:
    """Give a copy its name and its modification time back; False when there is no copy.

    image_export writes "_" for some characters of a name (ssh@.service is
    stored as ssh_.service) and stamps the copy with the time of the copy.
    """
    with contextlib.suppress(OSError):
        if raw != final and stat.S_ISREG(os.lstat(raw).st_mode):
            final.parent.mkdir(parents=True, exist_ok=True)
            os.replace(raw, final)
    try:
        if not stat.S_ISREG(os.lstat(final).st_mode):
            return False
        if entry.times[0]:
            stamp = entry.times[0] / 1_000_000
            os.utime(final, (stamp, stamp), follow_symlinks=False)
    except OSError:
        return False
    return True


def _export(
    command: list[str],
    image_path: str,
    root: Path,
    picks: Sequence[_Entry],
    places: dict[str, str],
    tmp: Path,
) -> tuple[list[tuple[_Entry, Path]], dict[str, list[str]], list[str]]:
    """Copy *picks* out of the image into *root*, each volume at its place.

    Returns the files copied with where they are, the ones that were not by
    reason, and what image_export reported. Afterwards *root* holds the files
    copied and nothing else.

    image_export merges every volume it is given into one tree and skips the
    second file of the same path, so it is run once per volume. It also stops
    at the first directory it cannot read to the end (one name that is not
    valid UTF-8 is enough) and leaves out everything it had not reached. A
    run that fails is therefore repeated in halves, until what is missing is
    down to the files of one directory: that directory alone is lost.
    """
    left: dict[str, list[str]] = {}
    # By the name image_export stores: (entry, where it writes it, where it belongs).
    plan: dict[Path, list[tuple[_Entry, Path, Path]]] = {}
    for entry in picks:
        target = root / places[entry.volume or ""]
        final = _stored(target, entry.path)
        if final is not None:  # _refusal has seen to that
            raw = _as_stored(target, entry.path)
            plan.setdefault(raw, []).append((entry, raw, final))
    by_volume: dict[str, list[tuple[_Entry, Path, Path]]] = {}
    for group in plan.values():
        if len(group) > 1 and len({final for _, _, final in group}) == 1:
            # One path on two volumes: the root volume holds a file in a directory
            # another volume is mounted on. The volume placed deepest is the one
            # the running system showed there.
            group.sort(key=lambda item: -len(places[item[0].volume or ""]))
            left.setdefault(_UNDER_MOUNT, []).extend(_shown(entry) for entry, _, _ in group[1:])
            del group[1:]
        if len(group) > 1:  # whose content the one stored file would hold cannot be told
            left.setdefault(_SHARED, []).extend(_shown(entry) for entry, _, _ in group)
        else:
            by_volume.setdefault(group[0][0].volume or "", []).append(group[0])

    done: list[tuple[_Entry, Path]] = []
    problems: list[str] = []
    timeout = adaptive_timeout(image_path, base=_PLASO_TIMEOUT)
    filter_file = tmp / "filter.yaml"
    for volume, wanted in sorted(by_volume.items()):
        target = root / places[volume]
        target.mkdir(parents=True, exist_ok=True)
        partition = number = "all"  # p5/lvm1 is --partitions 5 --volumes 1
        for match in map(_SELECTOR.fullmatch, volume.split("/")):
            if match and match.group(1) == "p":
                partition = match.group(2)
            elif match:
                number = match.group(2)
        queue = [sorted(wanted, key=lambda item: item[0].path)]
        runs, said = 0, False
        while queue:
            batch = queue.pop()
            if runs >= _MAX_RUNS:  # out of runs, or of time: what is left was not tried
                left.setdefault(_NOT_COPIED, []).extend(_shown(entry) for entry, _, _ in batch)
                continue
            runs += 1
            # One regular expression per path segment; image_export matches each whole.
            patterns = (
                "/".join(re.escape(part).replace("%", r"\%") for part in entry.path.split("/"))
                for entry, _, _ in batch
            )
            filter_file.write_text(
                "type: include\npath_separator: '/'\npaths:\n"
                + "".join(f"- {json.dumps(p, ensure_ascii=False)}\n" for p in patterns),
                encoding="utf-8",
            )
            cmd = [
                *command,
                "-u",
                "--logfile",
                str(tmp / "image_export.log"),
                "--partitions",
                partition,
                "--volumes",
                number,
                "--vss_stores",
                "none",
                # Without these it drops the second of two files with the same content.
                "--no_hashes",
                "--include_duplicates",
                "-f",
                str(filter_file),
                "-w",
                str(target),
                os.path.abspath(image_path),
            ]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    cwd=tmp,
                )
                failure = _failure_detail("image_export", proc) if proc.returncode else ""
            except subprocess.TimeoutExpired:
                failure, runs = f"image_export timed out after {timeout}s", _MAX_RUNS
            missing = []
            for entry, raw, final in batch:
                if _settle(entry, raw, final):
                    done.append((entry, final))
                else:
                    missing.append((entry, raw, final))
            if failure and missing and not said:
                problems.append(
                    f"{volume or '-'}: an image_export run stopped early and was repeated in "
                    f"parts; not_exported names what stayed out of reach: {failure}"
                )
                said = True
            folders = {entry.path.rpartition("/")[0] for entry, _, _ in missing}
            if failure and len(folders) > 1:
                # The later half first: a run stops where the walk meets the
                # directory it cannot read, so that directory is in the earlier one.
                half = len(missing) // 2
                queue += [missing[:half], missing[half:]]
            elif missing:
                left.setdefault(_NOT_COPIED, []).extend(_shown(entry) for entry, _, _ in missing)

    # Whatever else a run wrote is not kept: a file whose name matched a filter
    # without being the file asked for (image_export matches without case).
    kept = {str(final) for _, final in done}
    for _, path in walk_files(root, [4 * _MAX_FILES]):
        if path not in kept:
            with contextlib.suppress(OSError):
                os.unlink(path)
    return done, left, problems


def _warned(pinfo: list[str] | None, storage: Path, tmp: Path) -> list[str]:
    """Where log2timeline's extraction warnings are, as ``volume:path``.

    With only filestat running, a warning is a directory whose entries could
    not be read to the end. Empty when pinfo is missing or says nothing usable.
    """
    out = tmp / "warnings.json"
    if not pinfo:
        return []
    cmd = [*pinfo, "--sections", "warnings", "--output_format", "json", "-w", str(out)]
    try:
        subprocess.run(
            [*cmd, str(storage)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
            stdin=subprocess.DEVNULL,
            cwd=tmp,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    got = read_regular(out, 16 * _MIB, whole=True)
    try:
        specs = json.loads(got[0])["storage_counters"]["warnings_by_path_spec"] if got else {}
    except (ValueError, KeyError, TypeError, RecursionError):
        return []
    found: set[str] = set()
    for spec in specs if isinstance(specs, dict) else ():
        # One line per layer of the path specification, the image first ("type: OS,
        # location: /evidence/x.raw"), then the volumes ("... location: /p2, ..."),
        # and last the directory ("... inode: 51, location: /tmp").
        lines = str(spec).strip().split("\n")
        volume = "/".join(m.group(1) for m in map(_WARNED_VOLUME_RE.search, lines[:-1]) if m)
        where = lines[-1].partition("location: ")[2]
        found.add(listed_name(f"{volume}:{where}" if volume else where)[:300])
    return sorted(found)


def _list_image(tools: dict[str, list[str] | None], image_path: str, tmp: Path) -> _Listing:
    """Every entry dfVFS can reach in the image.

    log2timeline with only the filestat parser and no hashing stats each file
    and reads none. psort's json_line is the one output that keeps names
    exact and says which volume a file is on.

    Raises:
        RuntimeError: With what plaso reported, when either tool failed.
    """
    storage = tmp / "filestat.plaso"
    jsonl = tmp / "filestat.jsonl"
    log = ["--logfile", str(tmp / "plaso.log")]
    timeout = adaptive_timeout(image_path, base=_PLASO_TIMEOUT)
    # The tools run in tmp, where they leave their own logs: the image is named in full.
    image = os.path.abspath(image_path)
    list_files = [*(tools["log2timeline"] or []), "--storage_file", str(storage), *_L2T_FLAGS]
    list_files += [*log, "--parsers", "filestat", "--hashers", "none", "--skip_compressed_streams"]
    to_json = [*(tools["psort"] or []), "--status_view", "none", "-u", *log]
    to_json += ["-o", "json_line", "-w", str(jsonl), str(storage)]

    def run(tool: str, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                stdin=subprocess.DEVNULL,
                cwd=tmp,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"{tool} timed out after {timeout}s") from None
        except OSError as exc:
            raise RuntimeError(f"{tool} could not be run: {exc}") from None

    proc = run("log2timeline", [*list_files, image])
    if _ENCRYPTED in f"{proc.stdout}{proc.stderr}":
        # plaso stops at a LUKS partition it has no key for: read the others.
        others = unencrypted_partitions(image_path)
        storage.unlink(missing_ok=True)
        if others:
            proc = run("log2timeline", [*list_files, "--partitions", others, image])
    # Both tools exit 0 on an image they read, unreadable directories and all. One
    # that failed (psort out of temporary space) leaves part of a listing behind,
    # in time order: the newest entries are the ones it lacks.
    if proc.returncode or not storage.exists() or _ENCRYPTED in f"{proc.stdout}{proc.stderr}":
        raise RuntimeError(_failure_detail("log2timeline", proc))
    # A directory log2timeline could not read to the end is a warning, not an
    # error: it lists what it reached of it and goes on.
    warned = _WARNINGS_RE.search(proc.stdout or "")
    incomplete = _warned(tools.get("pinfo"), storage, tmp) if warned else []
    if warned and not incomplete:
        incomplete = [f"{warned.group(1)} directories, which pinfo did not name"]
    proc = run("psort", to_json)
    if proc.returncode or not jsonl.exists():
        raise RuntimeError(_failure_detail("psort", proc))
    return _Listing(*_read_listing(jsonl), incomplete)


def _extract_root() -> Path:
    """The case's extraction directory, in full: plaso's tools run in a directory of their own."""
    return Path(os.path.abspath(case_extract_dir(get_cfg().db_dir, get_ctx().case_id)))


def _record(home: Path) -> tuple[dict[str, object], dict[str, str]] | None:
    """What a finished export recorded beside its files: its summary, and where each volume is."""
    done = read_regular(home / EXPORT_MARKER, 4 * _MIB, whole=True)
    if done is None:
        return None
    try:
        record = json.loads(done[0])
        summary, places = record["summary"], record["places"]
    except (ValueError, KeyError, TypeError, RecursionError):
        return None
    if not isinstance(summary, dict) or not isinstance(places, dict):
        return None
    return summary, {str(volume): str(place) for volume, place in places.items()}


def _export_hint(image_path: str) -> str:
    """What to do with a disk image the Linux tools cannot list."""
    dest = export_dir(_extract_root(), image_path)
    if _record(dest.parent) is not None:
        return f"export_linux_files has exported this image: pass {dest} as image_path."
    if any(v.readable for v in probe(image_path)):
        return (
            "This image holds a volume Sleuth Kit cannot read (LVM or XFS): run "
            "export_linux_files on it and pass its export_root as image_path."
        )
    return ""


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def export_linux_files(
    image_path: str, paths: list[str] | None = None, force: bool = False
) -> dict[str, object]:
    """List and export the files of a Linux disk image Sleuth Kit cannot read (LVM, XFS).

    Call on a disk image the evidence context marks as holding Linux volumes
    Sleuth Kit cannot read, instead of run_fls. It reads the image through
    dfVFS (plaso), which opens LVM on one disk, XFS and ext2/3/4.

    Returns status, the volumes found, what could not be read and why, and
    export_root. linux.filelist lists every file on every readable volume
    (volume, type, mode, owner, size, modified, changed, created and
    accessed times, path). A targeted set is copied to export_root as one
    Linux file tree, each volume at its mount point: /etc, cron and systemd
    unit directories, /var/log, /root, the dotfiles and .ssh of each home
    directory (shell histories, shell profiles and .ssh from any directory,
    since an account's home may be anywhere), package manager state, web
    roots and /tmp, each within a size limit. Password hash files and
    private keys are left out by their well-known names. Pass export_root as
    image_path to run_linux_persistence and index_app_files. status
    "incomplete" means a directory could not be listed to the end or a file
    could not be copied: listing_incomplete and not_exported say which.

    Args:
        image_path: Path to the disk image.
        paths: Files or directories to export as well, spelled as the path
            column of linux.filelist shows them (for example
            ["/opt/app/config.php", "/usr/local/bin"]). They go to a
            directory of their own, named in the result as requested.root.
        force: List and export again even if this image was already
            exported. The directories of earlier paths requests are removed
            with the export: ask for those files again.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "export_linux_files"
    params: dict[str, object] = {"image_path": image_path, "paths": paths, "force": force}

    def fail(message: str, error_type: str, suggestion: str | None = None) -> dict[str, object]:
        elapsed = (time.monotonic() - t0) * 1000
        return error_response(tc_id, name, params, message, elapsed, error_type, suggestion)

    if not os.path.isfile(image_path):
        return fail(
            f"Not a disk image file: {image_path}",
            "file_not_found",
            "A directory needs no export: pass it as image_path to the tools directly."
            if dir_root(image_path) is not None
            else None,
        )
    tools = {t: _find_plaso_cmd(t) for t in ("log2timeline", "psort", "image_export", "pinfo")}
    missing = ", ".join(t for t, found in tools.items() if not found and t != "pinfo")
    if missing:
        return fail(f"plaso's {missing} not found", "binary_missing")
    exporter = tools["image_export"] or []

    root = export_dir(_extract_root(), image_path)
    home = root.parent
    try:
        with _export_lock, tempfile.TemporaryDirectory(prefix="mulder_linux_") as tmpdir:
            tmp = Path(tmpdir)
            record = None if force else _record(home)
            first = record is None
            if record is None:
                free = shutil.disk_usage(tmp).free
                if free < _MIN_TMP_FREE:
                    return fail(
                        f"Not enough temporary space to list this image: {free // _MIB} MiB "
                        f"free in {tmp.parent}, and the listing is not started below "
                        f"{_MIN_TMP_FREE // _MIB} MiB (it takes about 4 MiB per 1,000 files).",
                        "no_space",
                        "Nothing was listed or exported, for that reason alone: report the "
                        "image as not examined. TMPDIR names the directory that is used.",
                    )
                try:
                    listing = _list_image(tools, image_path, tmp)
                    detail = "dfVFS found no Linux volume or file system it can read in it"
                except RuntimeError as exc:
                    listing, detail = _Listing([], False, {}, []), str(exc)
                if not listing.entries:
                    held = "; ".join(map(str, probe(image_path)))
                    return fail(
                        f"This image could not be listed: {detail}"
                        + (f". It holds: {held}" if held else ""),
                        "unreadable",
                        "An encrypted volume needs its key, a volume group on several disks "
                        "needs all of them, and btrfs is not supported: report the volume as "
                        "not examined. When the message names a cause outside the image (a "
                        "tool that timed out or ran out of space), nothing was listed for "
                        "that reason alone. run_bulk_extractor still reads the raw image.",
                    )
                record = _export_first(exporter, image_path, root, listing, tmp)
                (home / EXPORT_MARKER).write_text(
                    json.dumps({"summary": record[0], "places": record[1]}), encoding="utf-8"
                )
                refresh()  # the directory has files it did not have when it was last listed
                _index_dir_listing(str(root), force=True)
            summary, places = dict(record[0]), record[1]
            if not first:  # and never as if it were whole when it is not
                whole = summary.get("status") == "exported"
                summary["status"] = "already exported" + ("" if whole else ", incomplete")
            if paths:
                summary["requested"] = _export_more(exporter, image_path, home, paths, places, tmp)
                refresh()
    except OSError as exc:  # no room in the case directory or the temporary one, a tool gone
        return fail(
            f"The export could not be completed: {exc}",
            "write_failed",
            "Whatever this call was to list or export was not examined, for that reason alone.",
        )
    elapsed = (time.monotonic() - t0) * 1000
    # Returned in full rather than as a preview: it is bounded, and it is where
    # the caller learns the directory to read and what was left out.
    return tool_response(tc_id, name, params, summary, None, elapsed)


def _export_first(
    exporter: list[str], image_path: str, root: Path, listing: _Listing, tmp: Path
) -> tuple[dict[str, object], dict[str, str]]:
    """Index the listing, export the targeted set, and describe both.

    Returns the summary, and the place of each volume in the export.
    """
    entries = listing.entries
    by_volume: dict[str, set[str]] = {}
    for entry in entries:
        if entry.volume not in (None, "?") and entry.kind == "file":
            by_volume.setdefault(entry.volume or "", set()).add(entry.path[1:])
    mounts = {volume: _mount(found) for volume, found in by_volume.items()}
    places = _places(mounts)
    picks, counts, left = _select(entries, mounts)
    # What the image holds that is not among the volumes just listed.
    volumes = probe(image_path)
    not_read = [str(v) for v in volumes if not v.readable]
    if any(v.kind == "lvm" and v.readable for v in volumes) and not any(
        "lvm" in volume for volume in by_volume
    ):
        not_read.append("the LVM volume group: dfVFS found no file system in its volumes")
    if route(image_path) == "also":
        not_read.append(
            "the NTFS or exFAT file system on this disk: not listed here, run_fls reads it"
        )

    home = root.parent
    shutil.rmtree(home, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    text = _render(entries)
    (home / _LISTING_FILE).write_text(text, encoding="utf-8")
    extract_and_index(text, "linux.filelist", image_path, "plaso")
    done, failed, problems = _export(exporter, image_path, root, picks, places, tmp)
    for reason, names in failed.items():
        left.setdefault(reason, []).extend(names)

    size = 0
    exported: dict[str, int] = {}
    for entry, path in done:
        with contextlib.suppress(OSError):
            size += os.lstat(path).st_size
        exported[entry.volume or ""] = exported.get(entry.volume or "", 0) + 1

    def described(volume: str) -> str:
        prefix, how = mounts[volume]
        if prefix is not None and places[volume] != prefix:
            how += " (another volume has that place, so its files are under its own name)"
        return (
            f"{volume or '-'} ({listing.file_systems.get(volume, 'unknown file system')}, "
            f"{len(by_volume[volume])} files, {exported.get(volume, 0)} exported to "
            f"{places[volume] or './'}): {how}"
        )

    summary: dict[str, object] = {
        "status": "incomplete" if listing.incomplete or _NOT_COPIED in failed else "exported",
        "image": image_path,
        "export_root": str(root),
        "volumes": [described(volume) for volume in sorted(by_volume)],
        "not_read": not_read,
        "entries_listed": len(entries),
        "listing_truncated": listing.cut,
        "listing_incomplete": _some(listing.incomplete, 20),
        "files_exported": len(done),
        "bytes_exported": size,
        "selected": counts,
        "not_exported": {reason: _some(names) for reason, names in sorted(left.items())},
        "problems": problems,
        "sources": ["linux.filelist", "tsk.filelist"],
        "note": _EXPORT_NOTE,
    }
    return summary, places


def _export_more(
    exporter: list[str],
    image_path: str,
    home: Path,
    paths: list[str],
    places: dict[str, str],
    tmp: Path,
) -> dict[str, object]:
    """Export files named by the caller, found in the listing the first export kept.

    Into a directory of their own, one per request: the tree of the first
    export stays as it was indexed, so a row number taken from its listing
    goes on naming the same file.
    """
    kept = read_regular(home / _LISTING_FILE, 1024 * _MIB, whole=True)
    asked = [p.strip().strip("/") for p in paths]
    wanted = {"/" + p for p in asked[:_MAX_REQUESTED] if p}
    below = tuple(p + "/" for p in wanted)
    picks: list[_Entry] = []
    refused: dict[str, list[str]] = {}
    matched: set[str] = set()
    budget = 1024 * _MIB  # for one call
    for entry in _parse(kept[0].decode("utf-8", "replace")) if kept else []:
        hit = (
            entry.path
            if entry.path in wanted
            else next((p[:-1] for p in below if entry.path.startswith(p)), None)
        )
        if hit is None or entry.kind != "file":
            continue
        matched.add(hit)
        # As _select names it: with the place of its volume, not as the volume alone has it.
        reason = _refusal(entry, places.get(entry.volume or "", "") + entry.path[1:])
        if reason is None and (entry.volume or "") not in places:
            reason = "dfVFS did not say which volume it is on"
        if reason is None and (len(picks) >= _MAX_FILES or entry.size > budget):
            reason = "over the limit for one call"
        if reason:
            refused.setdefault(reason, []).append(_shown(entry))
            continue
        budget -= entry.size
        picks.append(entry)
    request = hashlib.blake2b("\n".join(sorted(wanted)).encode("utf-8", "replace"), digest_size=6)
    root = home / "requested" / request.hexdigest()
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    done, failed, problems = _export(exporter, image_path, root, picks, places, tmp)
    for reason, names in failed.items():
        refused.setdefault(reason, []).extend(names)
    if kept is None:
        problems.append("the listing of the first export is missing: call again with force")
    return {
        "root": str(root),
        "exported": _some([str(path) for _, path in done], 20),
        "files_exported": len(done),
        "not_exported": {reason: _some(names) for reason, names in sorted(refused.items())},
        "not_in_listing": _some(sorted(listed_name(p) for p in wanted - matched), 40),
        "paths_ignored": max(0, len(asked) - _MAX_REQUESTED),
        "problems": problems,
        "note": "The files asked for are under root, a directory of their own laid out as "
        "export_root is: read one with read_evidence_file or scan it where it is, and pass "
        "root as image_path to index_app_files to index a directory of it. A path under "
        "not_in_listing names no file that linux.filelist shows: copy the path column "
        "exactly. A volume lists its files without its mount point (/boot/grub/grub.cfg is "
        f"/grub/grub.cfg on the boot volume). No more than {_MAX_REQUESTED} paths are taken "
        "in one call; paths_ignored counts the rest.",
    }


# --- persistence -----------------------------------------------------------

_HEAD_BYTES = 4096
_ACCOUNT_BYTES = _MIB
_EXCERPT_CHARS = 300
_MAX_ROWS = 5000
_MAX_ACCOUNTS = 200
# A base64 run: a key or an encoded blob. Never one that starts with "/", which
# is a path (ExecStart=/usr/local/..., a cron command), however long it is.
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])(?!/)[A-Za-z0-9+/]{48,}={0,2}")
_NO_LOGIN = ("nologin", "false", "sync", "halt", "shutdown")
_ADMIN_GROUPS = frozenset({"root", "sudo", "wheel", "admin", "adm", "docker", "lxd"})
_MAX_TREES = 20
"""Trees whose etc/passwd is read: the system's own, then copies and container layers."""
_ACCOUNTS = re.compile(r"((?:.*/)?)etc/(passwd-?|group)$")

# (kind, where). A path is matched from its start or from any directory, so
# that a volume's own directory, or a volume mounted below the root, hides nothing.
_PERSISTENCE: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (kind, re.compile(rf"(?:^|/)(?:{pattern})$"))
    for kind, pattern in (
        (
            "cron",
            r"etc/(?:ana)?crontab|etc/cron\.[^/]+/[^/]+|(?:var/)?spool/(?:cron|at|anacron)/.+",
        ),
        (
            "systemd",
            r"(?:etc|usr/local/lib|usr/lib|lib)/systemd/(?:system|user)/(?:.+"
            r"\.(?:service|timer|socket|path|mount|automount)|.+\.d/[^/]+\.conf)"
            r"|\.(?:config|local/share)/systemd/user/.+",
        ),
        (
            "init",
            r"etc/rc\.local|etc/rc\.d/rc\.local|etc/init\.d/[^/]+|etc/init/[^/]+\.conf"
            r"|etc/inittab|etc/x?inetd\.conf|etc/xinetd\.d/[^/]+",
        ),
        ("ld_preload", r"etc/ld\.so\.preload|etc/ld\.so\.conf|etc/ld\.so\.conf\.d/[^/]+"),
        (
            "ssh",
            # authorized_keys wherever AuthorizedKeysFile may point: beside
            # .ssh, a file of that name anywhere, or one per user under etc/ssh.
            r"authorized_keys2?|etc/ssh/authorized_keys[^/]*/[^/]+|\.ssh/(?:rc|config)"
            r"|etc/ssh/sshd_config|etc/ssh/sshd_config\.d/[^/]+|etc/ssh/sshrc",
        ),
        (
            "shell_profile",
            r"etc/(?:profile|bash\.bashrc|bashrc|environment|zsh/[^/]+)|etc/profile\.d/[^/]+"
            rf"|\.(?:{_PROFILES})",
        ),
        ("sudoers", r"etc/sudoers|etc/sudoers\.d/[^/]+"),
        (
            "kernel_modules",
            r"etc/modules|(?:etc|usr/lib|lib)/(?:modules-load\.d|modprobe\.d)/[^/]+",
        ),
        ("pam", r"etc/pam\.d/[^/]+"),
        ("udev", r"(?:etc|usr/lib|lib)/udev/rules\.d/[^/]+"),
        (
            "login_hooks",
            r"etc/update-motd\.d/[^/]+|etc/xdg/autostart/[^/]+|\.config/autostart/[^/]+"
            r"|etc/network/if-[^/]+\.d/[^/]+|etc/NetworkManager/dispatcher\.d/.+",
        ),
    )
)

_PERSISTENCE_NOTE = (
    "Each row is kind, path, modified, size, then the file's first lines without comments "
    "(long keys and blobs shortened, a private key withheld). An account row names the "
    "etc/passwd it is from: one that is not at the top of the tree is a copy, a container's "
    "or a second system's, not the accounts of this one. These are the places a Linux "
    "system starts programs from or grants access through, and most rows are the "
    "distribution's own files. A row shows that the file exists and what it holds: not that "
    "it is malicious, and not that what it names ever ran. A place with no row was not "
    "found in what was examined, which on an export or a triage collection can mean it was "
    "not copied. Symbolic links are not listed, so which units are enabled (the links under "
    "*.wants) is in the file listing. modified is the time on the file as it is stored: the "
    "original time in a directory written by export_linux_files and normally in an unpacked "
    'archive, the time of the copy otherwise, and "unknown" for a disk image, where size is '
    "exact only for a file shorter than what was read of it."
)


def _clean(text: str, limit: int = 64) -> str:
    """A value from the evidence as one bounded, printable field."""
    return listed_name(" ".join(text.split()))[:limit]


def _excerpt(data: bytes, complete: bool) -> str:
    if b"\x00" in data[:1024]:
        return "(binary)"
    if PRIVATE_KEY.search(data):
        return "(a private key: content withheld)"
    lines = (line.strip() for line in data.decode("utf-8", "replace").splitlines())
    kept = (_LONG_TOKEN.sub("<...>", ln) for ln in lines if ln and not ln.startswith("#"))
    text = _clean(" | ".join(kept), _EXCERPT_CHARS + 1)
    if not text:
        return "(only comments or empty)"
    cut = len(text) > _EXCERPT_CHARS or not complete
    return text[:_EXCERPT_CHARS] + (" [cut]" if cut else "")


def _accounts(passwd: bytes, previous: bytes | None, group: bytes | None) -> tuple[list[str], int]:
    """Accounts worth a row, and how many more there were than are shown.

    Worth a row: uid 0, able to log in, or new or changed since
    ``etc/passwd-`` was written. When there are more than are shown, the cut
    takes the accounts that merely have a login shell first, then the new and
    the changed ones, and the uid 0 accounts and the members of the
    privileged groups last.
    """

    def records(data: bytes | None) -> list[list[str]]:
        # A record ends at "\n" and nowhere else, as glibc reads the file: a form
        # feed or U+2028 in a GECOS field is part of the record, not the end of it.
        text = (data or b"").decode("utf-8", "replace")
        return [line.rstrip("\r").split(":") for line in text.split("\n")]

    before = {f[0]: f for f in records(previous)}
    ranked: list[tuple[int, str]] = []
    for f in records(passwd):
        if len(f) < 7 or f[0].startswith("#"):
            continue
        old = before.get(f[0])
        try:
            root = int(f[2]) == 0  # "00" and "+0" are uid 0 to glibc as well
        except ValueError:
            root = False
        marks = [
            *(["uid 0"] if root else []),
            *([] if f[6].rsplit("/", 1)[-1] in _NO_LOGIN else ["has a login shell"]),
            *(["not in etc/passwd-"] if previous is not None and old is None else []),
            # The uid, gid, home or shell: a service account given a shell.
            *(
                ["changed since etc/passwd-"]
                if old and old[2:4] + old[5:7] != f[2:4] + f[5:7]
                else []
            ),
        ]
        if marks:
            rank = 0 if root else 2 if marks[-1].endswith("etc/passwd-") else 3
            row = (
                f"name={_clean(f[0])} uid={_clean(f[2], 12)} gid={_clean(f[3], 12)} "
                f"home={_clean(f[5])} shell={_clean(f[6])} ({', '.join(marks)})"
            )
            ranked.append((rank, row))
    for f in records(group):
        if len(f) >= 4 and f[0] in _ADMIN_GROUPS and f[3].strip():
            ranked.append((1, f"group={f[0]} members={_clean(f[3], 200)}"))
    rows = [row for _, row in sorted(ranked, key=lambda item: item[0])]  # stable within a rank
    return rows[:_MAX_ACCOUNTS], max(0, len(rows) - _MAX_ACCOUNTS)


def _export_gaps(image_path: str) -> dict[str, object]:
    """What the export at *image_path* could not list or copy; empty when it is whole or none.

    An export is recognised by where it is, the place under the case's
    extraction directory that only export_linux_files writes to, and never by
    a file inside the directory, which evidence could carry too.
    """
    root = Path(os.path.abspath(image_path))
    if root.name != "files" or root.parent.parent != _extract_root() / EXPORTS_DIR:
        return {}
    record = _record(root.parent)
    if record is None or record[0].get("status") != "incomplete":
        return {}
    summary = record[0]
    left = summary.get("not_exported")
    return {
        "listing_incomplete": summary.get("listing_incomplete"),
        "not_copied": left.get(_NOT_COPIED, []) if isinstance(left, dict) else [],
        "problems": summary.get("problems"),
        "note": "export_linux_files could not list or copy everything this directory was "
        "meant to hold: a persistence location in a directory named here, or a file named "
        "here, was not examined, and has no row for that reason alone.",
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_linux_persistence(image_path: str, force: bool = False) -> dict[str, object]:
    """List what a Linux system starts on its own and who it lets in, one row per file.

    Call on a directory holding a Linux file tree (the export_root of
    export_linux_files, a UAC or Velociraptor collection) or on a Linux disk
    image Sleuth Kit can read, after its file listing exists. It reads
    crontabs and cron directories, at jobs, systemd units, timers and
    drop-ins, init scripts and rc.local, ld.so.preload, every
    authorized_keys and the sshd configuration, shell profile files, sudoers,
    kernel module and udev configuration, PAM, login hooks, and the accounts
    in etc/passwd that have uid 0, a login shell, or are new or changed
    since etc/passwd- (each etc/passwd found is read with the passwd- and
    group beside it, the one at the top of the tree first, and each account
    row names the file it is from).

    Returns the number of rows per kind and the most recently modified
    files; every row is indexed as linux.persistence with the file's path,
    modification time, size and first lines. It is an inventory: it marks
    nothing as malicious and does not show that anything ran. On an export
    that export_linux_files reported as incomplete, export_incomplete
    repeats what could not be listed or copied.

    Args:
        image_path: The directory, or the disk image.
        force: Run again even if this path was already swept.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "run_linux_persistence"
    params: dict[str, object] = {"image_path": image_path, "force": force}

    if not force:
        existing = sources_already_indexed(["linux.persistence"], evidence_path=image_path)
        if existing:
            skipped: dict[str, object] = {
                "status": "skipped",
                "reason": "Sources already indexed from prior extraction",
                "existing_sources": existing,
            }
            return tool_response(tc_id, name, params, skipped, None, 0.0)

    root = dir_root(image_path)
    groups = _collect_fls_chunks(image_path)

    def head(offset: int, inode: str, limit: int) -> tuple[bytes, str, float | None, bool] | None:
        """A file's first bytes, its size, its modification time if known, and if that is all."""
        if root is None:
            # No more than the limit is read of a file, however large it is.
            try:
                proc = icat(image_path, offset, inode, limit=limit)
            except (subprocess.TimeoutExpired, OSError):
                return None
            if proc.returncode:
                return None
            whole = len(proc.stdout) <= limit
            size = str(len(proc.stdout)) if whole else f"over {limit}"
            return proc.stdout[:limit], size, None, whole
        stored = root.stored(inode)
        got = read_regular(stored, limit) if stored is not None else None
        if stored is None or got is None:
            return None
        try:
            info = os.lstat(stored)
        except OSError:
            return got[0], str(len(got[0])), None, got[1]
        return got[0], str(info.st_size), info.st_mtime, got[1]

    rows: list[tuple[int, float, str]] = []
    # Where the account files of each tree are, by the directory that holds its
    # etc/: a copy under backup/ or in a container layer is not the system's own.
    trees: dict[str, dict[str, tuple[int, str, str]]] = {}
    seen: set[tuple[int, str, str]] = set()
    unread = 0
    for chunks, offset in groups:
        for chunk in chunks:
            for entry in fls_file_entries(chunk):
                account = _ACCOUNTS.match(entry.path)
                order = next(
                    (i for i, (_, where) in enumerate(_PERSISTENCE) if where.search(entry.path)),
                    None,
                )
                if entry.deleted or entry.meta_type == "l":
                    continue  # a deleted inode may hold another file; a link is no file
                if account is None and (order is None or len(rows) >= _MAX_ROWS):
                    continue
                # An image listed a second time (run_fls with force) has each row twice.
                listed = (offset, entry.base_inode, entry.path)
                if listed in seen:
                    continue
                seen.add(listed)
                shown = listed_name(entry.path)
                if account is not None:
                    tree = trees.setdefault(account.group(1), {})
                    tree.setdefault(account.group(2), (offset, entry.base_inode, shown))
                    continue
                got = head(offset, entry.base_inode, _HEAD_BYTES)
                if got is None:
                    unread += 1
                elif order is not None:
                    data, size, mtime, whole = got
                    when = _iso(mtime * 1_000_000) if mtime is not None else "unknown"
                    rows.append(
                        (
                            order,
                            -(mtime or 0.0),
                            f"{_PERSISTENCE[order][0]}\t{shown}\tmodified={when}\tsize={size}"
                            f"\t{_excerpt(data, whole)}",
                        )
                    )

    lines = [line for _, _, line in sorted(rows)]
    counts: dict[str, int] = {}
    for order, _, _ in rows:
        counts[_PERSISTENCE[order][0]] = counts.get(_PERSISTENCE[order][0], 0) + 1
    # Each etc/passwd with the passwd- and group beside it, the tree at the top
    # first and then the shallowest: the system's own before any copy of one.
    with_passwd = sorted(
        (t for t in trees if "passwd" in trees[t]), key=lambda t: (t.count("/"), t)
    )
    hidden = 0
    for top in with_passwd[:_MAX_TREES]:
        held: dict[str, tuple[bytes, float | None, str]] = {}
        for which, (offset, inode, shown) in trees[top].items():
            # New accounts are appended, so the account files are read to the end.
            got = head(offset, inode, _ACCOUNT_BYTES)
            if got is None:
                unread += 1
            else:
                held[which] = (got[0], got[2], shown)
        if "passwd" not in held:
            continue
        data, mtime, shown = held["passwd"]
        when = _iso(mtime * 1_000_000) if mtime is not None else "unknown"
        found, more = _accounts(
            data,
            held["passwd-"][0] if "passwd-" in held else None,
            held["group"][0] if "group" in held else None,
        )
        hidden += more
        lines += [f"account\t{shown}\tmodified={when}\tsize=-\t{row}" for row in found]
        counts["account"] = counts.get("account", 0) + len(found)
    passed_by = len(with_passwd) - len(with_passwd[:_MAX_TREES])
    gaps = _export_gaps(image_path) if root is not None else {}
    if not lines:
        hint = _export_hint(image_path) if root is None else ""
        if not groups:
            return error_response(
                tc_id,
                name,
                params,
                f"No file listing for {image_path}: it is not a directory, and run_fls has "
                "not listed it.",
                error_type="no_filelist",
                suggestion=hint or "Run run_fls on the image first.",
            )
        if unread:  # found, and not one of them read: that is not "none"
            return error_response(
                tc_id,
                name,
                params,
                f"{unread} files at Linux persistence locations are listed for {image_path} "
                "and none of them could be read.",
                error_type="unreadable",
                suggestion="They were not examined, for that reason alone.",
            )
        return error_response(
            tc_id,
            name,
            params,
            f"None of the Linux persistence locations is among the files listed for {image_path}.",
            error_type="not_applicable",
            suggestion=hint
            or "That does not show the system has none: on an export or a triage collection "
            "the files may not have been copied."
            + (f" This export is incomplete: {json.dumps(gaps)[:1500]}" if gaps else ""),
        )

    recent = sorted(rows, key=lambda row: row[1])[:15] if root is not None else []
    summary: dict[str, object] = {
        "source": "linux.persistence",
        "rows": len(lines),
        "by_kind": counts,
        "most_recently_modified": [" ".join(line.split("\t")[:3]) for _, _, line in recent],
        "files_not_readable": unread,
        "truncated": len(rows) >= _MAX_ROWS or hidden > 0 or passed_by > 0,
        "accounts_not_shown": hidden,
        "passwd_files_not_read": passed_by,
        "note": _PERSISTENCE_NOTE,
    }
    header = f"Linux persistence locations in {listed_name(image_path)}. {_PERSISTENCE_NOTE}"
    if gaps:
        summary["export_incomplete"] = gaps
        header += f" INCOMPLETE EXPORT: {gaps['note']} {json.dumps(gaps)[:1500]}"
    if hidden:
        header += f" {hidden} accounts that only have a login shell are not shown."
    if passed_by:
        header += f" {passed_by} more files named etc/passwd, deeper in the tree, were not read."
    extract_and_index(
        "\n".join([_clean(header, 4000), *lines]), "linux.persistence", image_path, "linux"
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, name, params, summary, None, elapsed)
