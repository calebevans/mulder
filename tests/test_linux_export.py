"""export_linux_files: a Linux image Sleuth Kit cannot read, listed and exported through plaso.

Every test uses a real case database. plaso's command-line tools are stood in
for by :class:`FakePlaso`, which answers the way the real ones were seen to:
psort writes one JSON event per line with a path specification only for
files, and image_export matches each path segment whole and without case,
merges nothing across runs, and stores some characters of a name as ``_``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mulder import dirroot
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.dirroot import LISTING_EXTRACTOR, detect_collection, dir_root
from mulder.linuxvol import EXPORT_MARKER, Volume, export_dir
from mulder.patterns import case_extract_dir
from mulder.server import app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools import linux

ROOT = "p5/lvm1"
HOME = "p5/lvm2"
MODIFIED = 1_570_274_078  # 2019-10-05T11:14:38Z


def _arg(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


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
    ]


class FakePlaso:
    """subprocess.run stand-in for log2timeline, psort and image_export."""

    def __init__(self, files: dict[str, dict[str, bytes]], extra: list[dict[str, Any]] = ()):  # type: ignore[assignment]
        self.files = files
        self.events = [e for v, held in files.items() for p in held for e in _events(p, v)]
        self.events += list(extra)
        self.calls: list[list[str]] = []
        self.filters: dict[str, list[str]] = {}
        self.fail = ""
        self.leak: list[str] = []

    def ran(self, tool: str) -> list[list[str]]:
        return [argv for argv in self.calls if Path(argv[0]).name == tool]

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        assert kwargs.get("stdin") is subprocess.DEVNULL, "plaso must never wait on stdin"
        tool = Path(argv[0]).name
        if tool == "log2timeline":
            if self.fail:
                return subprocess.CompletedProcess(argv, 1, stdout=self.fail, stderr="")
            Path(_arg(argv, "--storage_file")).write_bytes(b"plaso")
        elif tool == "psort":
            lines = "\n".join(json.dumps(e) for e in self.events)
            Path(_arg(argv, "-w")).write_text(lines, encoding="utf-8")
        elif tool == "image_export":
            parts = [f"p{_arg(argv, '--partitions')}", f"lvm{_arg(argv, '--volumes')}"]
            volume = "/".join(p for p in parts if not p.endswith("all"))
            text = Path(_arg(argv, "-f")).read_text(encoding="utf-8")
            wanted = [json.loads(line[2:]) for line in text.splitlines() if line.startswith("- ")]
            self.filters[volume] = wanted
            for path, data in self.files.get(volume, {}).items():
                if path in self.leak or any(self._matches(w, path) for w in wanted):
                    stored = Path(_arg(argv, "-w")) / re.sub(r"[@+~%]", "_", path).lstrip("/")
                    stored.parent.mkdir(parents=True, exist_ok=True)
                    if not stored.exists():
                        stored.write_bytes(data)
        else:
            raise AssertionError(f"unexpected command: {argv}")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

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
    monkeypatch.setattr(linux, "probe", lambda image: ())
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
    listing = _text(case, "linux.filelist")
    assert listing.startswith("volume\ttype\tmode\tuid\tgid\tsize\tmodified\tchanged\tcreated\t")
    row = "p5/lvm1\tfile\t0644\t0\t0\t10\t2019-10-05T11:14:38Z\t-\t2016-04-03T16:05:51Z\t"
    assert row + "/etc/passwd\n" in listing
    assert "p1\tfile\t0644\t0\t0\t10\t2019-10-05T11:14:38Z\t-\t" in listing
    # A link has no path specification: it is on the volume its directory's files are on.
    assert re.search(r"^p5/lvm1\tlink\t.*\t/etc/rc2\.d/S20ssh$", listing, re.MULTILINE)
    # Nothing says which volume an empty top-level directory is on, and none is guessed.
    assert re.search(r"^\?\tdirectory\t.*\t/home$", listing, re.MULTILINE)
    # Not a tsk.filelist: the image tools would hand these inode numbers to icat.
    sources = {s.source_name: (s.extractor, s.source_path) for s in case.get_sources()}
    assert sources["linux.filelist"] == ("plaso", image)
    assert sources["tsk.filelist"][0] == LISTING_EXTRACTOR and sources["tsk.filelist"][1] != image


def test_the_files_are_listed_without_reading_or_hashing_them(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso(SERVER)
    _run(monkeypatch, fake, image)

    (l2t,) = fake.ran("log2timeline")
    assert _arg(l2t, "--parsers") == "filestat" and _arg(l2t, "--hashers") == "none"
    assert "-u" in l2t and _arg(l2t, "--volumes") == "all" and l2t[-1] == image
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
    assert "\t10\t2019-10-05T11:14:38Z\t-\t2016-04-03T16:05:51Z\t/var/log/syslog.1.gz" in _text(
        case, "linux.filelist"
    )


def test_a_listing_past_the_limit_is_cut_and_says_so(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(linux, "_MAX_ENTRIES", 3)

    result = _run(monkeypatch, FakePlaso(SERVER), image)["results"]

    assert result["entries_listed"] == 3 and result["listing_truncated"] is True


# --- the export ------------------------------------------------------------


def test_the_targeted_set_is_exported_one_directory_per_volume(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso(SERVER)
    result = _run(monkeypatch, fake, image)["results"]

    root = Path(result["export_root"])
    # Where the planner was told it would be, before it existed.
    assert root == export_dir(case_extract_dir(tmp_path / "cases", "test-case"), image)
    held = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    assert held == [
        EXPORT_MARKER,
        "filelist.tsv",
        "p5_lvm1/etc/cron.d/backup",
        "p5_lvm1/etc/hostname",
        "p5_lvm1/etc/passwd",
        "p5_lvm1/lib/systemd/system/ssh@.service",
        "p5_lvm1/root/.bash_history",
        "p5_lvm1/tmp/apache-xTRhUVX",
        "p5_lvm1/var/log/auth.log",
        "p5_lvm1/var/www/html/index.php",
    ]
    assert result["files_exported"] == 8
    assert result["selected"] == {"config": 4, "logs": 1, "homes": 1, "web": 1, "tmp": 1}
    assert result["volumes"] == [
        "p1 (EXT, 2 files, 0 exported to p1/): read as /boot, guessed from its top-level names",
        "p5/lvm1 (EXT, 10 files, 8 exported to p5_lvm1/): the root volume: it holds etc/passwd",
    ]
    # One run per volume that has something to export, selected as dfVFS names it.
    (export,) = fake.ran("image_export")
    assert _arg(export, "--partitions") == "5" and _arg(export, "--volumes") == "1"
    assert "--include_duplicates" in export and "--no_hashes" in export and "-u" in export
    assert _arg(export, "-w") == str(root / "p5_lvm1") and export[-1] == image
    assert "/etc/passwd" in fake.filters[ROOT] and "/usr/bin/python3" not in fake.filters[ROOT]
    assert (Path(image).parent / "disk.E01").read_bytes() == b"EVF"
    assert sorted(p.name for p in Path(image).parent.iterdir()) == ["disk.E01"]


def test_an_exported_file_gets_its_name_and_its_time_back(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """image_export stored ssh@.service as ssh_.service, stamped with the time of the copy."""
    root = Path(_run(monkeypatch, FakePlaso(SERVER), image)["results"]["export_root"])

    unit = root / "p5_lvm1/lib/systemd/system/ssh@.service"
    assert unit.read_bytes().startswith(b"[Service]")
    assert not (unit.parent / "ssh_.service").exists()
    assert int(unit.stat().st_mtime) == MODIFIED
    assert int((root / "p5_lvm1/etc/passwd").stat().st_mtime) == MODIFIED


def test_two_names_image_export_stores_as_one_are_reported(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {ROOT: {"/etc/passwd": b"x\n", "/etc/hosts~": b"old\n", "/etc/hosts+": b"new\n"}}

    result = _run(monkeypatch, FakePlaso(files), image)["results"]

    root = Path(result["export_root"])
    assert (root / "p5_lvm1/etc/hosts_").read_bytes() == b"old\n"  # which one, nobody can say
    assert not (root / "p5_lvm1/etc/hosts~").exists()
    assert result["problems"][0].startswith("p5/lvm1: 1 stored names each stand for several")


def test_the_export_is_read_as_a_directory_root_with_the_root_volume_first(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {**SERVER, HOME: {"/alice/.bashrc": b"alias l=ls\n", "/alice/thesis.odt": b"PK"}}
    result = _run(monkeypatch, FakePlaso(files), image)["results"]
    root = result["export_root"]

    collection = detect_collection(Path(root))
    assert collection is not None and collection.layout == "export" and collection.host == "web01"
    assert [label for label, _ in collection.volumes] == ["p5_lvm1", "p5_lvm2"]
    assert collection.linux and not collection.windows
    listing = dir_root(root).listing()  # type: ignore[union-attr]
    assert "\tetc/passwd\n" in listing and "\tp5_lvm2/alice/.bashrc" in listing
    assert EXPORT_MARKER not in listing and "filelist.tsv" not in listing
    assert "\tetc/passwd\n" in _text(case, "tsk.filelist")
    assert "read as /home, guessed from the dotfiles" in result["volumes"][2]
    assert not (Path(root) / "p5_lvm2/alice/thesis.odt").exists()  # dotfiles and .ssh only


def test_var_and_var_log_on_volumes_of_their_own_still_yield_their_logs(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hardened layout: a file's path on its volume lacks the mount point."""
    files = {
        ROOT: {"/etc/passwd": b"x\n"},
        "p5/lvm2": {"/lib/dpkg/status": b"Package: x\n", "/www/html/a.php": b"<?php\n"},
        "p5/lvm3": {"/auth.log": b"Oct  5 sshd\n", "/journal/abc/system.journal": b"LPKSHHRH"},
        "p5/lvm4": {"/data/blob.bin": b"\x00"},
    }
    files["p5/lvm2"]["/log/placeholder"] = b""  # the mount point of the third volume

    result = _run(monkeypatch, FakePlaso(files), image)["results"]

    root = Path(result["export_root"])
    held = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    assert held[2:] == [
        "p5_lvm1/etc/passwd",
        "p5_lvm2/lib/dpkg/status",
        "p5_lvm2/log/placeholder",
        "p5_lvm2/www/html/a.php",
        "p5_lvm3/auth.log",
        "p5_lvm3/journal/abc/system.journal",
    ]
    said = [line.split("): ", 1)[1] for line in result["volumes"]]
    assert said == [
        "the root volume: it holds etc/passwd",
        "read as /var, guessed from its top-level names",
        "read as /var/log, guessed from its top-level names",
        "mount point not recognised: read as a root volume",
    ]


def test_a_single_file_system_needs_no_volume_selector(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso({"": {"/etc/passwd": b"root:x:0:0::/root:/bin/sh\n"}})

    result = _run(monkeypatch, fake, image)["results"]

    (export,) = fake.ran("image_export")
    assert _arg(export, "--partitions") == "all" and _arg(export, "--volumes") == "all"
    assert (Path(result["export_root"]) / "vol/etc/passwd").is_file()
    assert _text(case, "linux.filelist").splitlines()[1].startswith("-\tfile\t")


def test_password_hashes_and_private_keys_never_reach_the_case_directory(
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
    ]
    public = ["/etc/passwd", "/etc/ssh/ssh_host_rsa_key.pub", "/root/.ssh/id_ed25519.pub"]
    fake = FakePlaso({ROOT: dict.fromkeys(secrets + public, b"secret\n")})
    fake.leak = ["/etc/shadow"]  # even if the filter were to let one through

    result = _run(monkeypatch, fake, image)["results"]

    root = Path(result["export_root"])
    held = {str(p.relative_to(root / "p5_lvm1")) for p in (root / "p5_lvm1").rglob("*")}
    assert {p.lstrip("/") for p in public} <= held
    assert not {p.lstrip("/") for p in secrets} & held
    assert not set(secrets) & set(fake.filters[ROOT])
    refused = result["not_exported"]["never exported (password hashes and private keys)"]
    assert "p5/lvm1:/etc/shadow" in refused and len(refused) == len(secrets)
    # Listed all the same: that the file exists, its size and its times are evidence.
    assert "\t/etc/shadow\n" in _text(case, "linux.filelist")

    again = _run(monkeypatch, fake, image, paths=["/etc/shadow", "/root/.ssh"])["results"]
    assert list(again["requested"]["not_exported"]) == [
        "never exported (password hashes and private keys)"
    ]
    assert not (root / "p5_lvm1/etc/shadow").exists()
    assert not (root / "p5_lvm1/root/.ssh/id_ed25519").exists()


def test_size_limits_keep_the_newest_and_name_what_was_left(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    mib = 1024 * 1024
    fake = FakePlaso({ROOT: {"/etc/passwd": b"x\n"}})
    for day, name in enumerate(["old", "mid", "new", "newest", "latest"]):
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


def test_a_name_from_the_evidence_cannot_forge_a_row_or_leave_the_export(
    case: CaseDB, image: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forged = "/etc/x\np5/lvm1\tfile\t0644\t0\t0\t1\t-\t-\t-\t/etc/planted"
    fake = FakePlaso({ROOT: {"/etc/passwd": b"x\n"}})
    fake.events += _events(forged) + _events("/etc/../../../outside") + _events("/etc/a%b{c}.conf")
    outside = tmp_path / "cases/extracted/outside"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"mine")
    before = outside.stat().st_mtime_ns

    result = _run(monkeypatch, fake, image)["results"]

    listing = _text(case, "linux.filelist")
    assert "/etc/x^p5/lvm1^file^" in listing and "\n" + forged.split("\n")[1] not in listing
    assert result["not_exported"]["name holds characters that cannot be passed to image_export"]
    assert not any("\n" in p for p in fake.filters[ROOT])
    # Every character of a name is matched as itself, and % cannot start a variable.
    assert "/etc/a\\%b\\{c\\}\\.conf" in fake.filters[ROOT]
    assert outside.stat().st_mtime_ns == before and outside.read_bytes() == b"mine"


# --- what cannot be read ---------------------------------------------------


def test_an_encrypted_volume_is_an_error_that_says_why(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso({})
    fake.fail = "Unable to proceed. Encrypted volume found but no mediator to determine how\n"
    monkeypatch.setattr(linux, "probe", lambda image: (Volume(2048, "luks"),))

    result = _run(monkeypatch, fake, image)

    assert result["status"] == "error" and result["error_type"] == "unreadable"
    assert "Encrypted volume found" in result["error_message"]
    assert "LUKS-encrypted volume at sector 2048" in result["error_message"]
    assert "not examined" in result["suggestion"]
    assert not fake.ran("psort") and not fake.ran("image_export")
    assert case.get_sources() == []


def test_a_volume_group_on_several_disks_is_named_as_not_read(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """dfVFS reads the plain partition and nothing of the group; the result must not look whole."""
    monkeypatch.setattr(linux, "probe", lambda image: (Volume(501760, "lvm", "vg0", 2),))

    result = _run(monkeypatch, FakePlaso({"p1": SERVER["p1"]}), image)["results"]

    assert result["not_read"] == [
        "LVM physical volume at sector 501760, volume group vg0 on 2 disks of which this "
        "image is one"
    ]
    assert result["files_exported"] == 0


def test_a_volume_group_that_yields_no_file_system_is_named_too(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(linux, "probe", lambda image: (Volume(501760, "lvm", "vg0", 1),))

    result = _run(monkeypatch, FakePlaso({"p1": SERVER["p1"]}), image)["results"]

    assert result["not_read"] == [
        "the LVM volume group: dfVFS found no file system in its volumes"
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


# --- later calls -----------------------------------------------------------


def test_a_second_call_is_answered_from_the_first(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso(SERVER)
    first = _run(monkeypatch, fake, image)["results"]
    calls = len(fake.calls)

    second = _run(monkeypatch, fake, image)["results"]

    assert second == {"status": "already exported", **first}
    assert len(fake.calls) == calls
    assert [s.source_name for s in case.get_sources()].count("linux.filelist") == 1

    _run(monkeypatch, fake, image, force=True)
    assert len(fake.ran("log2timeline")) == 2


def test_a_listed_file_is_exported_on_request_without_listing_again(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePlaso(SERVER)
    root = Path(_run(monkeypatch, fake, image)["results"]["export_root"])
    assert not (root / "p5_lvm1/opt/app/config.php").exists()

    result = _run(monkeypatch, fake, image, paths=["/opt/app", "usr/bin/python3", "/nope"])
    asked = result["results"]["requested"]

    assert len(fake.ran("log2timeline")) == 1, "the listing the first call kept is enough"
    assert asked["exported"] == [
        str(root / "p5_lvm1/opt/app/config.php"),
        str(root / "p5_lvm1/usr/bin/python3"),
    ]
    assert asked["not_in_listing"] == ["/nope"]
    assert int((root / "p5_lvm1/opt/app/config.php").stat().st_mtime) == MODIFIED
    # The live listing of the directory root has it at once.
    assert "\topt/app/config.php" in dir_root(str(root)).listing()  # type: ignore[union-attr]


def test_the_first_call_may_name_extra_paths(
    case: CaseDB, image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run(monkeypatch, FakePlaso(SERVER), image, paths=["/opt/app/config.php"])["results"]

    assert result["requested"]["files_exported"] == 1 and result["files_exported"] == 8
    assert os.path.isfile(result["requested"]["exported"][0])
    assert "\topt/app/config.php" in _text(case, "tsk.filelist")
