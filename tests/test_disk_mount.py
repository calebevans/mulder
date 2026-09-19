"""``_mount_image`` is pure user-space FUSE: xmount + a filesystem driver.

The kernel ``mount -o loop`` path needs root and a loop device; a
``--cap-add SYS_ADMIN --device /dev/fuse`` container has neither, even for
root (issue #172).  There is also no ``guestmount`` fallback: libguestfs
boots a supermin appliance, which needs a kernel image the container does
not ship.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Collection
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.extractors import disk

_MMLS_NTFS = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000020479   0000018432   NTFS / exFAT (0x07)
"""


def _which(name: str) -> str | None:
    return f"/usr/bin/{name}"


def _fake_run(
    calls: list[list[str]], fail: Collection[str] = (), mmls: str = ""
) -> Callable[..., subprocess.CompletedProcess[Any]]:
    """Return a ``subprocess.run`` stand-in that records commands.

    ``xmount`` creates the ``.dd`` file a real xmount would expose; commands
    named in *fail* exit non-zero; ``mmls`` prints *mmls* (as text, like the
    real call).
    """

    def run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[Any]:
        calls.append(cmd)
        if cmd[0] in fail:
            return subprocess.CompletedProcess(cmd, 12, stderr=b"NTFS signature is missing.\n")
        if cmd[0] == "mmls":
            return subprocess.CompletedProcess(cmd, 0 if mmls else 1, stdout=mmls, stderr="")
        if cmd[0] == "xmount":
            (Path(cmd[-1]) / "image.dd").touch()
        return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

    return run


def test_e01_is_xmounted_at_partition_offset_then_fuse_mounted(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    with (
        patch("mulder.extractors.disk.shutil.which", _which),
        patch("mulder.extractors.disk.subprocess.run", _fake_run(calls, mmls=_MMLS_NTFS)),
    ):
        assert disk._mount_image(tmp_path / "image.E01", tmp_path / "mnt") is True

    assert [c[0] for c in calls] == ["mmls", "xmount", "ntfs-3g"]
    xmount = calls[1]
    assert xmount[1:5] == ["--in", "ewf", str(tmp_path / "image.E01"), "--out"]
    assert xmount[xmount.index("--offset") + 1] == str(2048 * 512)
    assert xmount[-1] == str(tmp_path / "mnt.raw")
    assert calls[2] == [
        "ntfs-3g",
        "-o",
        "ro,noexec,no_def_opts",
        str(tmp_path / "mnt.raw" / "image.dd"),
        str(tmp_path / "mnt"),
    ]
    assert not any(c[0] in {"mount", "sudo", "guestmount", "ewfmount"} for c in calls)


@pytest.mark.parametrize("first", ["image.E01", "image.e01", "image.s01"])
def test_split_ewf_passes_every_segment_to_xmount_in_order(tmp_path: Path, first: str) -> None:
    # xmount does not glob .E02.. itself; given only .E01 it exits 1 with
    # "Unable to read end of data! Did you specify all EWF segments?!"
    names = [first[:-2] + f"{n:02d}" for n in range(1, 5)]
    for name in names:
        (tmp_path / name).touch()
    calls: list[list[str]] = []
    with (
        patch("mulder.extractors.disk.shutil.which", _which),
        patch("mulder.extractors.disk.subprocess.run", _fake_run(calls)),
    ):
        assert disk._mount_image(tmp_path / first, tmp_path / "mnt") is True

    xmount = calls[1]
    assert xmount[1 : 3 + len(names)] == ["--in", "ewf", *(str(tmp_path / n) for n in names)]
    assert xmount[3 + len(names)] == "--out"


def test_split_ewf_with_missing_middle_segment_stops_at_the_gap(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    for name in ["image.E01", "image.E02", "image.E04"]:
        (tmp_path / name).touch()
    calls: list[list[str]] = []
    with (
        patch("mulder.extractors.disk.shutil.which", _which),
        patch("mulder.extractors.disk.subprocess.run", _fake_run(calls)),
        caplog.at_level("WARNING", logger="mulder.extractors.disk"),
    ):
        disk._mount_image(tmp_path / "image.E01", tmp_path / "mnt")

    assert calls[1][2:5] == ["ewf", str(tmp_path / "image.E01"), str(tmp_path / "image.E02")]
    assert "image.E03 is missing but 1 later segment(s) exist" in caplog.text


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        (".E01", ".E02"),
        (".E99", ".EAA"),
        (".EAZ", ".EBA"),
        (".EZZ", ".FAA"),
        (".e99", ".eaa"),
        (".s09", ".s10"),
    ],
)
def test_next_ewf_suffix_follows_libewf_naming(suffix: str, expected: str) -> None:
    assert disk._next_ewf_suffix(suffix) == expected


def test_failed_command_logs_stdout_and_argv_when_stderr_is_empty(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # xmount prints "ERROR: main@3689 : ..." on stdout, leaving stderr empty.
    def run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[Any]:
        return subprocess.CompletedProcess(
            cmd, 1, stdout=b"\nERROR: main : no segments\n", stderr=b""
        )

    with (
        patch("mulder.extractors.disk.subprocess.run", run),
        caplog.at_level("WARNING", logger="mulder.extractors.disk"),
    ):
        assert disk._run(["xmount", "--in", "ewf", "a b.E01"], 1) is False

    assert (
        "xmount exited 1: ERROR: main : no segments (argv: xmount --in ewf 'a b.E01')"
        in caplog.text
    )


def test_raw_image_without_partition_table_falls_through_to_next_driver(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    with (
        patch("mulder.extractors.disk.shutil.which", _which),
        patch("mulder.extractors.disk.subprocess.run", _fake_run(calls, {"ntfs-3g"})),
    ):
        assert disk._mount_image(tmp_path / "image.dd", tmp_path / "mnt") is True

    assert [c[0] for c in calls] == ["mmls", "xmount", "ntfs-3g", "fuse2fs"]
    assert calls[1][1:3] == ["--in", "raw"]
    assert "--offset" not in calls[1]


@pytest.mark.parametrize("name", ["image.E01", "image.dd"])
def test_xmount_failure_stops_before_any_driver(tmp_path: Path, name: str) -> None:
    calls: list[list[str]] = []
    with (
        patch("mulder.extractors.disk.shutil.which", _which),
        patch("mulder.extractors.disk.subprocess.run", _fake_run(calls, {"xmount"})),
    ):
        assert disk._mount_image(tmp_path / name, tmp_path / "mnt") is False

    assert [c[0] for c in calls] == ["mmls", "xmount"]
    assert not (tmp_path / "mnt.raw").exists()


def test_all_drivers_failing_unmounts_the_raw_file(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    with (
        patch("mulder.extractors.disk.shutil.which", _which),
        patch("mulder.extractors.disk.subprocess.run", _fake_run(calls, {"ntfs-3g", "fuse2fs"})),
    ):
        assert disk._mount_image(tmp_path / "image.dd", tmp_path / "mnt") is False

    assert [c[0] for c in calls] == ["mmls", "xmount", "ntfs-3g", "fuse2fs", "fusermount"]
    assert calls[-1] == ["fusermount", "-u", str(tmp_path / "mnt.raw")]
    assert not (tmp_path / "mnt.raw").exists()


def test_unmount_releases_filesystem_then_raw_file(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    (tmp_path / "mnt.raw").mkdir(parents=True)
    with patch("mulder.extractors.disk.subprocess.run", _fake_run(calls)):
        disk._unmount_image(tmp_path / "mnt")

    assert calls == [
        ["fusermount", "-u", str(tmp_path / "mnt")],
        ["fusermount", "-u", "-z", str(tmp_path / "mnt.raw")],
    ]
    assert not (tmp_path / "mnt.raw").exists()
