"""Directories as evidence roots: triage collections and loose volume directories.

A tool that reads a file out of a disk image does it in two steps: find the
file in the ``fls`` listing, then read its inode with ``icat``.  A directory
can answer both, so it can stand where an image stands: :func:`dir_root` gives
the listing and :func:`icat` the bytes.

The root itself is general: a list of ``(original path, stored path)`` pairs.
The layouts recognised here (KAPE target output, a Velociraptor offline
collection, UAC output, a plain Windows volume directory) only decide what
those pairs are.

Evidence is hostile.  Symlinks are never followed, only regular files are
opened, a name is a label and never becomes a path, and every read is bounded.
"""

from __future__ import annotations

import functools
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import NamedTuple
from urllib.parse import unquote

MAX_ENTRIES = 200_000
"""Files and directories walked under one root before the listing is cut."""

MAX_FILE_BYTES = 4 * 1024**3
"""Largest stored file :func:`icat` hands out; a larger one is refused, not cut."""

LISTING_EXTRACTOR = "directory"
"""``extractor`` of a ``tsk.filelist`` source that lists a directory root."""

LAYOUTS: dict[str, str] = {
    "kape": "KAPE target output",
    "velociraptor": "Velociraptor offline collection",
    "uac": "UAC collection",
    "windows": "Windows volume directory",
}

_HEAD_BYTES = 65536

# 2023-03-24T12_39_01_6137377_CopyLog.csv, 2018-09-03T14_51_21_7565737_<Target>_copylog.csv
KAPE_LOG_RE = re.compile(
    r"^\d{4}-\d\d-\d\dT[\d_]+_(?:.*_)?(copylog|skiplog|consolelog)\.", re.IGNORECASE
)
_KAPE_VOLUME_RE = re.compile(r"^(?:[a-z]|vss\d+)$", re.IGNORECASE)
_KAPE_MACHINE_RE = re.compile(rb"Machine name: ([^,\s]+)")
# KAPE stores these NTFS streams under a name of its own; the listing shows the stream.
_KAPE_STORED_AS = {
    "$Extend/$J": "$Extend/$UsnJrnl:$J",
    "$Extend/$Max": "$Extend/$UsnJrnl:$Max",
    "$Extend/$RmMetadata/$TxfLog/$T": "$Extend/$RmMetadata/$TxfLog/$Tops:$T",
    "$Secure_$SDS": "$Secure:$SDS",
}
_UAC_NAME_RE = re.compile(
    r"uac-(.+)-(?:aix|android|esxi|freebsd|linux|macos|netbsd|netscaler|openbsd|solaris)-\d{14}"
)
_NOT_HOST_CHARS = re.compile(r"[^A-Za-z0-9._-]")


class Collection(NamedTuple):
    """A recognised triage collection."""

    root: Path
    layout: str
    """A key of :data:`LAYOUTS`."""
    host: str
    """The host name the collection states, or ``""``."""
    volumes: tuple[tuple[str, Path], ...]
    """``(label, directory)`` per collected volume, the system volume first."""

    @property
    def description(self) -> str:
        """The layout and host, for a line a model reads."""
        return LAYOUTS[self.layout] + (f", host {self.host}" if self.host else "")

    @property
    def windows(self) -> bool:
        """Whether the files came from Windows volumes (a Velociraptor drive has a label)."""
        if self.layout == "velociraptor":
            return any(label for label, _ in self.volumes)
        return self.layout != "uac"


class DirRoot(NamedTuple):
    """The files a directory root holds, addressed the way an fls listing is."""

    files: tuple[tuple[str, str], ...]
    """``(original path, stored path)``; a file's inode is its position."""
    first_inode: int
    """0 when the first file is ``$MFT`` (MFT record 0 on NTFS), else 1."""
    truncated: bool

    def listing(self) -> str:
        """The files as ``fls -r -p`` rows."""
        return "\n".join(
            f"r/r {inode}:\t{original}"
            for inode, (original, _) in enumerate(self.files, self.first_inode)
        )

    def stored(self, inode: str) -> str | None:
        """The stored path of *inode*, or None when the listing has no such row."""
        try:
            index = int(inode.split("-")[0]) - self.first_inode
        except ValueError:
            return None
        return self.files[index][1] if 0 <= index < len(self.files) else None


def read_regular(path: str | Path, limit: int, whole: bool = False) -> tuple[bytes, bool] | None:
    """The first *limit* bytes of a regular file and whether that is all of it.

    None for anything else: a symlink is not followed, and a FIFO or device is
    never read (the open does not block on one). With *whole*, a file larger
    than *limit* is not read at all.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return None
            data = b"" if whole and info.st_size > limit else fh.read(limit)
    except OSError:
        return None
    return data, info.st_size <= len(data)


def _entries(directory: Path) -> dict[str, os.DirEntry[str]]:
    """The directory's entries by lower-cased name; empty when it cannot be listed."""
    try:
        with os.scandir(directory) as it:
            return {e.name.lower(): e for e in it}
    except OSError:
        return {}


def _dir(entry: os.DirEntry[str] | None) -> Path | None:
    """The entry's path when it is a directory and not a symlink to one."""
    return Path(entry.path) if entry is not None and entry.is_dir(follow_symlinks=False) else None


def _file(entry: os.DirEntry[str] | None) -> Path | None:
    """The entry's path when it is a regular file and not a symlink to one."""
    return Path(entry.path) if entry is not None and entry.is_file(follow_symlinks=False) else None


def real_dir(parent: Path, name: str) -> Path | None:
    """The directory *name* in *parent*, in any letter case, unless it is a symlink."""
    return _dir(_entries(parent).get(name.lower()))


def _has_windows_config(volume: Path) -> bool:
    """Whether *volume* holds ``Windows/System32/config``, in any letter case."""
    current: Path | None = volume
    for name in ("windows", "system32", "config"):
        current = real_dir(current, name) if current is not None else None
    return current is not None


def _host(raw: object) -> str:
    """A host name reduced to host-name characters: it is shown to models."""
    return _NOT_HOST_CHARS.sub("", raw)[:64] if isinstance(raw, str) else ""


def _system_first(volumes: list[tuple[str, Path]]) -> tuple[tuple[str, Path], ...]:
    system = {label for label, directory in volumes if _has_windows_config(directory)}
    return tuple(sorted(volumes, key=lambda v: (v[0] not in system, v[0], str(v[1]))))


def _velociraptor_volumes(uploads: Path) -> list[tuple[str, Path]]:
    r"""One volume per device directory under each accessor.

    ``uploads/ntfs/%5C%5C.%5CC%3A`` and ``uploads/auto/C%3A`` are both drive C
    and share a label.  An accessor whose children are not devices (a Unix
    collection: ``uploads/auto/etc``) is itself a volume.
    """
    volumes: list[tuple[str, Path]] = []
    for _, entry in sorted(_entries(uploads).items()):
        accessor = _dir(entry)
        if accessor is None:
            continue
        plain = False
        for _, child in sorted(_entries(accessor).items()):
            device = _dir(child)
            decoded = unquote(child.name)
            last = decoded.rstrip("\\").rsplit("\\", 1)[-1]
            if device is not None and re.fullmatch(r"[A-Za-z]:", last):
                volumes.append((last[0].upper(), device))
            elif device is not None and decoded.startswith("\\\\"):
                volumes.append((_NOT_HOST_CHARS.sub("_", last) or "device", device))
            else:
                plain = True
        if plain:
            volumes.append(("", accessor))
    return volumes


def detect_collection(path: Path) -> Collection | None:
    """Recognise *path* as a triage collection by what its top level holds."""
    entries = _entries(path)
    if not entries:
        return None

    info = _file(entries.get("client_info.json"))
    uploads = _dir(entries.get("uploads"))
    if (info or _file(entries.get("collection_context.json"))) and (
        uploads or _dir(entries.get("results"))
    ):
        host = ""
        head = read_regular(info, _HEAD_BYTES) if info else None
        if head is not None:
            try:
                fields = {str(k).lower(): v for k, v in json.loads(head[0]).items()}
                host = _host(fields.get("hostname") or fields.get("fqdn"))
            except (ValueError, AttributeError):
                pass
        volumes = _velociraptor_volumes(uploads) if uploads else []
        return Collection(path, "velociraptor", host, _system_first(volumes))

    if _file(entries.get("uac.log")) and any(
        _dir(entries.get(name)) for name in ("[root]", "live_response", "bodyfile")
    ):
        named = _UAC_NAME_RE.search(path.name)
        root = _dir(entries.get("[root]"))
        return Collection(
            path, "uac", _host(named.group(1)) if named else "", (("", root),) if root else ()
        )

    drives = [
        (e.name, Path(e.path))
        for name, e in sorted(entries.items())
        if _KAPE_VOLUME_RE.match(name) and _dir(e)
    ]
    logs = [e for name, e in sorted(entries.items()) if KAPE_LOG_RE.match(name) and _file(e)]
    if drives and logs:
        host = ""
        console = next((e.path for e in logs if "consolelog" in e.name.lower()), None)
        head = read_regular(console, _HEAD_BYTES) if console else None
        if head is not None and (machine := _KAPE_MACHINE_RE.search(head[0])):
            host = _host(machine.group(1).decode("ascii", "replace"))
        return Collection(path, "kape", host, _system_first(drives))

    if _dir(entries.get("windows")) and _has_windows_config(path):
        return Collection(path, "windows", "", (("", path),))
    return None


def listed_name(name: str) -> str:
    """A path as a listing shows it: control characters become ``^``, as in fls.

    A name holding a newline or tab could otherwise forge a listing row.
    """
    shown = "".join("^" if ch < " " or ch == "\x7f" else ch for ch in name)
    return shown.encode("utf-8", "replace").decode()


def _decode(component: str) -> str:
    """Undo Velociraptor's percent-encoding, unless the result is not a file name."""
    decoded = unquote(component)
    if decoded in ("", ".", "..") or "/" in decoded or "\\" in decoded:
        return component
    return decoded


def walk_files(top: Path, budget: list[int]) -> list[tuple[str, str]]:
    """``(path below top, stored path)`` of each regular file; symlinks are not followed.

    *budget* holds the number of entries that may still be visited and is counted down.
    """
    found: list[tuple[str, str]] = []
    stack = [("", str(top))]
    while stack and budget[0] > 0:
        rel, directory = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            if budget[0] <= 0:
                break
            budget[0] -= 1
            child = f"{rel}/{entry.name}" if rel else entry.name
            if entry.is_dir(follow_symlinks=False):
                stack.append((child, entry.path))
            elif entry.is_file(follow_symlinks=False):
                found.append((child, entry.path))
    return found


@functools.lru_cache(maxsize=8)
def _build(path: str) -> DirRoot:
    # ponytail: cached for the life of the process, so a directory that gains
    # files after its first use keeps its first listing. Evidence does not change.
    collection = detect_collection(Path(path))
    volumes = collection.volumes if collection else (("", Path(path)),)
    layout = collection.layout if collection else ""
    budget = [MAX_ENTRIES]
    files: dict[str, str] = {}
    for volume, directory in volumes:
        prefix = "" if volume == volumes[0][0] else f"{volume}/"
        for rel, stored in walk_files(directory, budget):
            if layout == "velociraptor":
                rel = "/".join(_decode(part) for part in rel.split("/"))
            elif layout == "kape":
                rel = _KAPE_STORED_AS.get(rel, rel)
            files.setdefault(listed_name(prefix + rel), stored)
    ordered = sorted(files.items(), key=lambda f: (f[0] != "$MFT", f[0]))
    first = 0 if ordered and ordered[0][0] == "$MFT" else 1
    return DirRoot(tuple(ordered), first, budget[0] <= 0)


def dir_root(path: str) -> DirRoot | None:
    """The directory-backed view of *path*, or None when it is not a directory."""
    return _build(path) if os.path.isdir(path) else None


def not_collected(path: str) -> str | None:
    """What "not found" means when *path* is a directory root; None for an image.

    For the ``suggestion`` of a parser's error, so the caller does not read a
    missing artifact as a clean system.
    """
    if dir_root(path) is None:
        return None
    return (
        "This is a directory of collected files, not a disk image: the artifact was not "
        "collected. That does not show it was absent from the system. triage.summary "
        "(written by index_triage_collection) lists what was collected."
    )


def icat(
    image_path: str, offset: int, inode: str, timeout: int = 30
) -> subprocess.CompletedProcess[bytes]:
    """Read the file at *inode* of a listing: ``icat`` on an image, the stored file of a directory.

    The result has the shape ``subprocess.run`` gave the callers that used to
    run ``icat`` themselves, so they treat both kinds of root alike.
    """
    root = dir_root(image_path)
    if root is None:
        cmd = ["icat"]
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.extend([image_path, inode])
        return subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)

    # ponytail: the whole file is held in memory, as icat's output is; copy in
    # chunks if collections with multi-GiB $MFT or $J need it.
    stored = root.stored(inode)
    got = read_regular(stored, MAX_FILE_BYTES, whole=True) if stored is not None else None
    args = ["icat", image_path, inode]
    if got is None:
        return subprocess.CompletedProcess(args, 1, b"", b"no such file in the directory root")
    if not got[1]:
        return subprocess.CompletedProcess(args, 1, b"", b"file exceeds the read limit")
    return subprocess.CompletedProcess(args, 0, got[0], b"")
