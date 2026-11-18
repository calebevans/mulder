"""Linux file access where Sleuth Kit has none, and a sweep of persistence locations.

``export_linux_files`` reads a disk image through dfVFS by driving plaso's
command-line tools (never by importing them: on SIFT plaso lives in its own
virtualenv).  log2timeline with only the filestat parser lists every file on
every volume; image_export then copies a targeted set into the case
directory, one directory per volume, which the directory-root tools read the
way they read a triage collection (``mulder.dirroot``).

``run_linux_persistence`` reads such a directory, a collection, or a Linux
image Sleuth Kit can open.

Everything read here comes from the evidence: names are matched and shown,
never trusted, and every read is bounded.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from mulder.dirroot import dir_root, icat, listed_name, read_regular, refresh, walk_files
from mulder.linuxvol import EXPORT_MARKER, SECRET_FILES, export_dir, probe
from mulder.patterns import case_extract_dir, fls_file_entries
from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    adaptive_timeout,
    cli_path,
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
_LISTING_FILE = "filelist.tsv"

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
            r"root/|home/[^/]+/(?:\.[^/]+$|\.ssh/|\.config/(?:systemd|autostart)/"
            r"|\.local/share/systemd/)",
        ),
        ("web", 512 * _MIB, r"(?:var/www|srv/www|usr/share/nginx/html)/"),
        ("tmp", 256 * _MIB, r"(?:tmp|var/tmp)/"),
    )
)

# A name that image_export's YAML filter file cannot carry.
_UNSAFE_NAME = re.compile(r"[^\x20-\x7e\xa0-\U0000d7ff\U0000e000-\U0000fffd\U00010000-\U0010ffff]")
# Every character image_export might replace in a name it stores.
_NOT_PLAIN = re.compile(r"[^A-Za-z0-9._/-]")

_TIME_SLOTS = {
    "Content Modification Time": 0,
    "Metadata Modification Time": 1,
    "Creation Time": 2,
}
_SELECTOR = re.compile(r"([a-z]{1,8})(\d{1,3})")
_HOME_SIGNS = re.compile(r"[^/]+/\.(?:bashrc|bash_logout|bash_profile|profile|ssh/)")
_VAR_LOG_SIGNS = frozenset({"journal", "syslog", "auth.log", "messages", "secure", "wtmp"})

_EXPORT_NOTE = (
    "linux.filelist lists every file on the volumes that could be read, exported or not. "
    "A file listed there exists; deleted files are not listed and unallocated space was not "
    "read, so a file that is not listed may still have existed. Only the files under "
    "export_root can be read: pass export_root as image_path to run_linux_persistence and "
    "index_app_files, and read one file at export_root/<volume directory>/<path>. To read a "
    "listed file that was not exported, call export_linux_files again with paths. Password "
    "hash files and private keys are never exported. The times on the exported copies are "
    "the modification times from the listing."
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
    """Modified, changed, created: microseconds since 1970, 0 when not recorded."""


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
    entries: dict[tuple[str | None, str], _Entry] = {}
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
            path = spec.get("location") if isinstance(spec, dict) else event.get("filename")
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            key = (_volume(spec), path)
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
                    [0, 0, 0],
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
    for volume, path in entries:
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
    rows = ["volume\ttype\tmode\tuid\tgid\tsize\tmodified\tchanged\tcreated\tpath"]
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
    for row in listing.splitlines()[1:]:
        f = row.split("\t", 9)
        if len(f) != 10:
            continue
        times = [0, 0, 0]
        with contextlib.suppress(ValueError):
            times[0] = int(datetime.fromisoformat(f[6]).timestamp() * 1_000_000)
        size = int(f[5]) if f[5].isdigit() else 0
        volume = "" if f[0] == "-" else f[0]
        entries.append(_Entry(volume, f[9], f[1], None, None, None, size, times))
    return entries


def _mount(paths: set[str]) -> tuple[str, str]:
    """Where a volume belongs in the tree, as a path prefix, and how that is known.

    Only the three mount points that most often get a volume of their own are
    guessed, from the volume's top-level names. The prefix decides which of
    the targeted paths apply; it is never used to move a file.
    """
    if "etc/passwd" in paths:
        return "", "the root volume: it holds etc/passwd"
    tops = {p.split("/", 1)[0] for p in paths}
    if {"log", "lib"} <= tops:
        return "var/", "read as /var, guessed from its top-level names"
    if tops & _VAR_LOG_SIGNS:
        return "var/log/", "read as /var/log, guessed from its top-level names"
    if any(_HOME_SIGNS.match(p) for p in paths):
        return "home/", "read as /home, guessed from the dotfiles in its directories"
    if any(top.startswith(("vmlinuz", "grub")) for top in tops):
        return "boot/", "read as /boot, guessed from its top-level names"
    return "", "mount point not recognised: read as a root volume"


def _refusal(entry: _Entry, rel: str) -> str | None:
    """Why a file is not exported whoever asks, or None."""
    if SECRET_FILES.search(rel):
        return "never exported (password hashes and private keys)"
    if entry.size > _MAX_FILE_BYTES:
        return f"larger than {_MAX_FILE_BYTES // _MIB} MiB"
    if _UNSAFE_NAME.search(entry.path):
        return "name holds characters that cannot be passed to image_export"
    return None


def _shown(entry: _Entry) -> str:
    return listed_name(f"{entry.volume}:{entry.path}" if entry.volume else entry.path)


def _some(names: list[str], limit: int = 10) -> list[str]:
    return names if len(names) <= limit else [*names[:limit], f"... and {len(names) - limit} more"]


def _select(
    entries: Sequence[_Entry], mounts: dict[str, tuple[str, str]]
) -> tuple[list[_Entry], dict[str, int], dict[str, list[str]]]:
    """The targeted set: the files to export, how many of each kind, and what was left out."""
    found: dict[str, list[_Entry]] = {kind: [] for kind, _, _ in _TARGETS}
    left: dict[str, list[str]] = {}
    for entry in entries:
        mount = mounts.get(entry.volume) if entry.volume is not None else None
        if entry.kind != "file" or mount is None:
            continue
        rel = mount[0] + entry.path[1:]
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


def _dirname(volume: str | None) -> str:
    """The directory of the export that holds a volume's files."""
    return (volume or "").replace("/", "_") or "vol"


def _stored(target: Path, path: str) -> Path | None:
    """Where image_export puts *path* under *target*; None for a path that could leave it."""
    parts = path.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    return target.joinpath(*parts)


def _export(
    command: list[str], image_path: str, dest: Path, picks: Sequence[_Entry], tmp: Path
) -> list[str]:
    """Copy *picks* out of the image, each volume into its own directory; returns problems.

    image_export merges every volume it is given into one tree and skips the
    second file of the same path, so it is run once per volume.
    """
    by_volume: dict[str, list[_Entry]] = {}
    for entry in picks:
        by_volume.setdefault(entry.volume or "", []).append(entry)
    problems: list[str] = []
    timeout = adaptive_timeout(image_path, base=_PLASO_TIMEOUT)
    for volume, entries in sorted(by_volume.items()):
        target = dest / _dirname(volume)
        target.mkdir(parents=True, exist_ok=True)
        # One regular expression per path segment; image_export matches each whole.
        patterns = (
            "/".join(re.escape(part).replace("%", r"\%") for part in entry.path.split("/"))
            for entry in entries
        )
        filter_file = tmp / f"{_dirname(volume)}.yaml"
        filter_file.write_text(
            "type: include\npath_separator: '/'\npaths:\n"
            + "".join(f"- {json.dumps(p, ensure_ascii=False)}\n" for p in patterns),
            encoding="utf-8",
        )
        partition = number = "all"  # p5/lvm1 is --partitions 5 --volumes 1
        for match in map(_SELECTOR.fullmatch, volume.split("/")):
            if match and match.group(1) == "p":
                partition = match.group(2)
            elif match:
                number = match.group(2)
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
            cli_path(image_path),
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
            if proc.returncode != 0:
                problems.append(f"{volume or '-'}: {_failure_detail('image_export', proc)}")
        except subprocess.TimeoutExpired:
            problems.append(f"{volume or '-'}: image_export timed out after {timeout}s")
        # image_export writes "_" for some characters of a name (ssh@.service is
        # stored as ssh_.service) and stamps the copy with the time of the copy.
        # Give each file its name and its modification time back; two names it
        # stored as one are left as they are, since only one of them was written.
        named: dict[str, _Entry | None] = {}
        for entry in entries:
            key = _NOT_PLAIN.sub("_", entry.path)
            named[key] = None if key in named else entry
        for rel, path in walk_files(target, [4 * _MAX_FILES]):
            found = named.get(_NOT_PLAIN.sub("_", f"/{rel}"))
            wanted = _stored(target, found.path) if found is not None else None
            with contextlib.suppress(OSError):
                if SECRET_FILES.search(rel):  # whatever the filter let through
                    os.unlink(path)
                elif found is not None and wanted is not None:
                    if str(wanted) != path:
                        wanted.parent.mkdir(parents=True, exist_ok=True)
                        os.rename(path, wanted)
                    if found.times[0]:
                        stamp = found.times[0] / 1_000_000
                        os.utime(wanted, (stamp, stamp), follow_symlinks=False)
        merged = sum(found is None for found in named.values())
        if merged:
            problems.append(
                f"{volume or '-'}: {merged} stored names each stand for several files whose "
                "names differ only in characters image_export replaces; one file of each was "
                "exported, under the stored name"
            )
    return problems


def _list_image(
    l2t: list[str], psort: list[str], image_path: str, tmp: Path
) -> tuple[list[_Entry], bool, dict[str, str]]:
    """Every entry dfVFS can reach in the image.

    log2timeline with only the filestat parser and no hashing stats each file
    and reads none. psort's json_line is the one output that keeps names
    exact and says which volume a file is on.

    Raises:
        RuntimeError: With what plaso reported, when it produced no listing.
    """
    storage = tmp / "filestat.plaso"
    jsonl = tmp / "filestat.jsonl"
    log = ["--logfile", str(tmp / "plaso.log")]
    timeout = adaptive_timeout(image_path, base=_PLASO_TIMEOUT)
    list_files = [*l2t, "--storage_file", str(storage), *_L2T_FLAGS, *log]
    list_files += ["--parsers", "filestat", "--hashers", "none", cli_path(image_path)]
    to_json = [*psort, "--status_view", "none", "-u", *log]
    to_json += ["-o", "json_line", "-w", str(jsonl), str(storage)]
    for tool, output, cmd in (("log2timeline", storage, list_files), ("psort", jsonl, to_json)):
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
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"{tool} timed out after {timeout}s") from None
        if not output.exists():
            raise RuntimeError(_failure_detail(tool, proc))
    return _read_listing(jsonl)


def _export_hint(image_path: str) -> str:
    """What to do with a disk image the Linux tools cannot list."""
    dest = export_dir(case_extract_dir(get_cfg().db_dir, get_ctx().case_id), image_path)
    if (dest / EXPORT_MARKER).is_file():
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

    Returns the volumes found, what could not be read and why, and
    export_root. linux.filelist lists every file on every readable volume
    (volume, type, mode, owner, size, modified, changed and created times,
    path). A targeted set is copied to export_root, one directory per
    volume: /etc, cron and systemd unit directories, /var/log, /root, the
    dotfiles and .ssh of each home directory, package manager state, web
    roots and /tmp, each within a size limit. Password hash files and
    private keys are never copied. Pass export_root as image_path to
    run_linux_persistence and index_app_files.

    Args:
        image_path: Path to the disk image.
        paths: Files or directories to export as well, spelled as the path
            column of linux.filelist shows them (for example
            ["/opt/app/config.php", "/usr/local/bin"]).
        force: List and export again even if this image was already exported.
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
    tools = {t: _find_plaso_cmd(t) for t in ("log2timeline", "psort", "image_export")}
    if not all(tools.values()):
        missing = ", ".join(t for t, found in tools.items() if not found)
        return fail(f"plaso's {missing} not found", "binary_missing")
    exporter = tools["image_export"] or []

    dest = export_dir(case_extract_dir(get_cfg().db_dir, get_ctx().case_id), image_path)
    marker = dest / EXPORT_MARKER
    with _export_lock, tempfile.TemporaryDirectory(prefix="mulder_linux_") as tmpdir:
        tmp = Path(tmpdir)
        summary: dict[str, object] | None = None
        done = read_regular(marker, _MIB, whole=True) if not force else None
        if done is not None:
            with contextlib.suppress(ValueError):
                summary = {"status": "already exported", **json.loads(done[0])}
        first = summary is None
        if summary is None:
            try:
                listed = _list_image(
                    tools["log2timeline"] or [], tools["psort"] or [], image_path, tmp
                )
                detail = "dfVFS found no file in it"
            except RuntimeError as exc:
                listed, detail = ([], False, {}), str(exc)
            if not listed[0]:
                held = "; ".join(map(str, probe(image_path)))
                return fail(
                    f"This image could not be listed: {detail}"
                    + (f". It holds: {held}" if held else ""),
                    "unreadable",
                    "An encrypted volume needs its key, a volume group on several disks needs "
                    "all of them, and btrfs is not supported: report the volume as not "
                    "examined. run_bulk_extractor still reads the raw image.",
                )
            summary = _export_first(exporter, image_path, dest, listed, tmp)
            marker.write_text(json.dumps(summary), encoding="utf-8")
        if paths:
            summary["requested"] = _export_more(exporter, image_path, dest, paths, tmp)
        refresh()  # the directory has files it did not have when it was last listed
        if first:
            _index_dir_listing(str(dest), force=True)
    elapsed = (time.monotonic() - t0) * 1000
    # Returned in full rather than as a preview: it is bounded, and it is where
    # the caller learns the directory to read and what was left out.
    return tool_response(tc_id, name, params, summary, None, elapsed)


def _export_first(
    exporter: list[str],
    image_path: str,
    dest: Path,
    listed: tuple[list[_Entry], bool, dict[str, str]],
    tmp: Path,
) -> dict[str, object]:
    """Index the listing, export the targeted set, and describe both."""
    entries, cut, file_systems = listed
    by_volume: dict[str, set[str]] = {}
    for entry in entries:
        if entry.volume not in (None, "?") and entry.kind == "file":
            by_volume.setdefault(entry.volume or "", set()).add(entry.path[1:])
    mounts = {volume: _mount(found) for volume, found in by_volume.items()}
    picks, counts, left = _select(entries, mounts)
    # What the image holds that is not among the volumes just listed.
    volumes = probe(image_path)
    not_read = [str(v) for v in volumes if not v.readable]
    if any(v.kind == "lvm" and v.readable for v in volumes) and not any(
        "lvm" in volume for volume in by_volume
    ):
        not_read.append("the LVM volume group: dfVFS found no file system in its volumes")

    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    listing = _render(entries)
    (dest / _LISTING_FILE).write_text(listing, encoding="utf-8")
    extract_and_index(listing, "linux.filelist", image_path, "plaso")
    problems = _export(exporter, image_path, dest, picks, tmp)

    size = 0
    exported: dict[str, int] = {}
    for volume in by_volume:
        for _, path in walk_files(dest / _dirname(volume), [4 * _MAX_FILES]):
            with contextlib.suppress(OSError):
                size += os.lstat(path).st_size
                exported[volume] = exported.get(volume, 0) + 1
    return {
        "image": image_path,
        "export_root": str(dest),
        "volumes": [
            f"{volume or '-'} ({file_systems.get(volume, 'unknown file system')}, "
            f"{len(found)} files, {exported.get(volume, 0)} exported to {_dirname(volume)}/): "
            f"{mounts[volume][1]}"
            for volume, found in sorted(by_volume.items())
        ],
        "not_read": not_read,
        "entries_listed": len(entries),
        "listing_truncated": cut,
        "files_exported": sum(exported.values()),
        "bytes_exported": size,
        "selected": counts,
        "not_exported": {reason: _some(names) for reason, names in sorted(left.items())},
        "problems": problems,
        "sources": ["linux.filelist", "tsk.filelist"],
        "note": _EXPORT_NOTE,
    }


def _export_more(
    exporter: list[str], image_path: str, dest: Path, paths: list[str], tmp: Path
) -> dict[str, object]:
    """Export files named by the caller, found in the listing the first export kept."""
    kept = read_regular(dest / _LISTING_FILE, 1024 * _MIB, whole=True)
    wanted = {"/" + p.strip().strip("/") for p in paths[:_MAX_REQUESTED] if p.strip().strip("/")}
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
        reason = _refusal(entry, entry.path[1:])
        if reason is None and (len(picks) >= _MAX_FILES or entry.size > budget):
            reason = "over the limit for one call"
        if reason:
            refused.setdefault(reason, []).append(_shown(entry))
            continue
        budget -= entry.size
        picks.append(entry)
    problems = _export(exporter, image_path, dest, picks, tmp)
    if kept is None:
        problems.append("the listing of the first export is missing: call again with force")
    stored = [
        str(path)
        for entry in picks
        if (path := _stored(dest / _dirname(entry.volume), entry.path)) and path.is_file()
    ]
    return {
        "exported": _some(stored, 40),
        "files_exported": len(stored),
        "not_exported": {reason: _some(names) for reason, names in sorted(refused.items())},
        "not_in_listing": _some(sorted(listed_name(p) for p in wanted - matched), 40),
        "problems": problems,
        "note": "Each path under exported is an ordinary file: read it with read_evidence_file "
        "or scan it where it is. A path under not_in_listing names no file that "
        "linux.filelist shows: copy the path column exactly. A volume lists its files "
        "without its mount point (/boot/grub/grub.cfg is /grub/grub.cfg on the boot volume).",
    }


# --- persistence -----------------------------------------------------------

_HEAD_BYTES = 4096
_ACCOUNT_BYTES = _MIB
_EXCERPT_CHARS = 300
_MAX_ROWS = 5000
_MAX_ACCOUNTS = 200
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=]{48,}")
_NO_LOGIN = ("nologin", "false", "sync", "halt", "shutdown")
_ADMIN_GROUPS = frozenset({"root", "sudo", "wheel", "admin", "adm", "docker", "lxd"})
_ACCOUNTS = re.compile(r"(?:^|/)etc/(passwd-?|group)$")

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
            r"(?:etc|usr/local/lib|usr/lib|lib)/systemd/(?:system|user)/.+"
            r"\.(?:service|timer|socket|path|mount|automount)"
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
            r"\.ssh/(?:authorized_keys2?|rc|config)|etc/ssh/sshd_config"
            r"|etc/ssh/sshd_config\.d/[^/]+|etc/ssh/sshrc",
        ),
        (
            "shell_profile",
            r"etc/(?:profile|bash\.bashrc|bashrc|environment|zsh/[^/]+)|etc/profile\.d/[^/]+"
            r"|\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv"
            r"|zlogin|cshrc|tcshrc|kshrc|xprofile)",
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
    "(long keys and blobs shortened). These are the places a Linux system starts programs "
    "from or grants access through, and most rows are the distribution's own files. A row "
    "shows that the file exists and what it holds: not that it is malicious, and not that "
    "what it names ever ran. A place with no row was not found in what was examined, which "
    "on an export or a triage collection can mean it was not copied. Symbolic links are not "
    "listed, so which units are enabled (the links under *.wants) is in the file listing. "
    "modified is the time on the file as it is stored: the original time in a directory "
    "written by export_linux_files and normally in an unpacked archive, the time of the copy "
    'otherwise, and "unknown" for a disk image.'
)


def _clean(text: str, limit: int = 64) -> str:
    """A value from the evidence as one bounded, printable field."""
    return listed_name(" ".join(text.split()))[:limit]


def _excerpt(data: bytes, complete: bool) -> str:
    if b"\x00" in data[:1024]:
        return "(binary)"
    lines = (line.strip() for line in data.decode("utf-8", "replace").splitlines())
    kept = (_LONG_TOKEN.sub("<...>", ln) for ln in lines if ln and not ln.startswith("#"))
    text = _clean(" | ".join(kept), _EXCERPT_CHARS + 1)
    if not text:
        return "(only comments or empty)"
    cut = len(text) > _EXCERPT_CHARS or not complete
    return text[:_EXCERPT_CHARS] + (" [cut]" if cut else "")


def _accounts(passwd: bytes, previous: bytes | None, group: bytes | None) -> list[str]:
    """Accounts worth a row: uid 0, able to log in, or new since ``etc/passwd-`` was written."""
    before = {
        line.split(":", 1)[0] for line in (previous or b"").decode("utf-8", "replace").splitlines()
    }
    rows: list[str] = []
    for line in passwd.decode("utf-8", "replace").splitlines():
        f = line.split(":")
        if len(f) < 7 or line.startswith("#"):
            continue
        marks = [
            *(["uid 0"] if f[2] == "0" else []),
            *([] if f[6].rsplit("/", 1)[-1] in _NO_LOGIN else ["has a login shell"]),
            *(["not in etc/passwd-"] if previous is not None and f[0] not in before else []),
        ]
        if marks:
            rows.append(
                f"name={_clean(f[0])} uid={_clean(f[2], 12)} gid={_clean(f[3], 12)} "
                f"home={_clean(f[5])} shell={_clean(f[6])} ({', '.join(marks)})"
            )
    for line in (group or b"").decode("utf-8", "replace").splitlines():
        f = line.split(":")
        if len(f) >= 4 and f[0] in _ADMIN_GROUPS and f[3].strip():
            rows.append(f"group={f[0]} members={_clean(f[3], 200)}")
    return rows[:_MAX_ACCOUNTS]


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_linux_persistence(image_path: str, force: bool = False) -> dict[str, object]:
    """List what a Linux system starts on its own and who it lets in, one row per file.

    Call on a directory holding a Linux file tree (the export_root of
    export_linux_files, a UAC or Velociraptor collection) or on a Linux disk
    image Sleuth Kit can read, after its file listing exists. It reads
    crontabs and cron directories, at jobs, systemd units and timers, init
    scripts and rc.local, ld.so.preload, every authorized_keys and the sshd
    configuration, shell profile files, sudoers, kernel module and udev
    configuration, PAM, login hooks, and the accounts in etc/passwd that
    have uid 0, a login shell, or are missing from etc/passwd-.

    Returns the number of rows per kind and the most recently modified
    files; every row is indexed as linux.persistence with the file's path,
    modification time, size and first lines. It is an inventory: it marks
    nothing as malicious and does not show that anything ran.

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

    def head(offset: int, inode: str, limit: int) -> tuple[bytes, int, float | None] | None:
        """A file's first bytes, its size, and its modification time when it has one."""
        if root is None:
            proc = icat(image_path, offset, inode)
            return None if proc.returncode else (proc.stdout[:limit], len(proc.stdout), None)
        stored = root.stored(inode)
        got = read_regular(stored, limit) if stored is not None else None
        if stored is None or got is None:
            return None
        try:
            info = os.lstat(stored)
        except OSError:
            return got[0], len(got[0]), None
        return got[0], info.st_size, info.st_mtime

    rows: list[tuple[int, float, str]] = []
    accounts: dict[str, tuple[bytes, float | None, str]] = {}
    unread = 0
    for chunks, offset in groups:
        for chunk in chunks:
            for entry in fls_file_entries(chunk):
                account = _ACCOUNTS.search(entry.path)
                order = next(
                    (i for i, (_, where) in enumerate(_PERSISTENCE) if where.search(entry.path)),
                    None,
                )
                if entry.deleted or entry.meta_type == "l" or len(rows) >= _MAX_ROWS:
                    continue  # a deleted inode may hold another file; a link is no file
                if account is None and order is None:
                    continue
                # New accounts are appended, so the account files are read to the end.
                limit = _HEAD_BYTES if account is None else _ACCOUNT_BYTES
                got = head(offset, entry.base_inode, limit)
                if got is None:
                    unread += 1
                    continue
                data, size, mtime = got
                shown = listed_name(entry.path)
                if account is not None:
                    accounts.setdefault(account.group(1), (data, mtime, shown))
                elif order is not None:
                    when = _iso(mtime * 1_000_000) if mtime is not None else "unknown"
                    excerpt = _excerpt(data, size <= len(data))
                    rows.append(
                        (
                            order,
                            -(mtime or 0.0),
                            f"{_PERSISTENCE[order][0]}\t{shown}\tmodified={when}\tsize={size}"
                            f"\t{excerpt}",
                        )
                    )

    lines = [line for _, _, line in sorted(rows)]
    counts: dict[str, int] = {}
    for order, _, _ in rows:
        counts[_PERSISTENCE[order][0]] = counts.get(_PERSISTENCE[order][0], 0) + 1
    if "passwd" in accounts:
        data, mtime, shown = accounts["passwd"]
        when = _iso(mtime * 1_000_000) if mtime is not None else "unknown"
        found = _accounts(
            data,
            accounts["passwd-"][0] if "passwd-" in accounts else None,
            accounts["group"][0] if "group" in accounts else None,
        )
        lines += [f"account\t{shown}\tmodified={when}\tsize=-\t{row}" for row in found]
        counts["account"] = len(found)
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
        return error_response(
            tc_id,
            name,
            params,
            f"None of the Linux persistence locations is among the files listed for {image_path}.",
            error_type="not_applicable",
            suggestion=hint
            or "That does not show the system has none: on an export or a triage collection "
            "the files may not have been copied.",
        )

    recent = sorted(rows, key=lambda row: row[1])[:15] if root is not None else []
    summary: dict[str, object] = {
        "source": "linux.persistence",
        "rows": len(lines),
        "by_kind": counts,
        "most_recently_modified": [" ".join(line.split("\t")[:3]) for _, _, line in recent],
        "files_not_readable": unread,
        "truncated": len(rows) >= _MAX_ROWS,
        "note": _PERSISTENCE_NOTE,
    }
    header = f"Linux persistence locations in {listed_name(image_path)}. {_PERSISTENCE_NOTE}"
    extract_and_index("\n".join([header, *lines]), "linux.persistence", image_path, "linux")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, name, params, summary, None, elapsed)
