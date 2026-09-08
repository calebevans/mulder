"""A deleted Security.evtx must still be extracted from a disk image.

This is the user-visible consequence of the fls row-regex bug, exercised
through ``_extract_evtx_from_image`` -- whose signature this fix does not
change, so these tests run unmodified against ``origin/main`` and fail there
on the assertion rather than on an import or a signature mismatch.

Clearing the Windows Security log is a standard anti-forensic step; the
cleared original is often recoverable as a deleted entry. Missing it is
exactly the evidence an examiner came for.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools.extract.evtx import _extract_evtx_from_image

#: Genuine ``fls -r -p`` output (TSK 4.12.1). Inode 22 is deleted.
FLS_WITH_DELETED_EVTX = (
    "d/d 20:\tWindows/System32/winevt\n"
    "d/d 21:\tWindows/System32/winevt/Logs\n"
    "r/r * 22:\tWindows/System32/winevt/Logs/Deleted.evtx\n"
    "r/r 23:\tWindows/System32/winevt/Logs/Security.evtx\n"
)


@pytest.fixture
def icat_calls(tmp_path: Path) -> list[list[str]]:
    """Record the argv of every icat invocation."""
    return []


def _run_extraction(dest: Path, calls: list[list[str]]) -> list[Path]:
    def fake_run(cmd: list[str], **_: object) -> MagicMock:
        calls.append(cmd)
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = b"ElfFile\x00evtx-bytes"
        return proc

    with (
        patch(
            "mulder.server.tools.extract.evtx._collect_fls_chunks",
            return_value=[([FLS_WITH_DELETED_EVTX], 0)],
        ),
        patch("mulder.server.tools.extract.evtx.subprocess.run", side_effect=fake_run),
    ):
        return _extract_evtx_from_image("/evidence/disk.dd", str(dest))


def test_a_deleted_evtx_is_extracted(tmp_path: Path, icat_calls: list[list[str]]) -> None:
    """The bug: the deleted log was skipped while its sibling was extracted."""
    extracted = _run_extraction(tmp_path, icat_calls)
    names = {p.name for p in extracted}

    assert "Windows_System32_winevt_Logs_Deleted.evtx" in names


def test_icat_is_asked_for_the_deleted_inode(tmp_path: Path, icat_calls: list[list[str]]) -> None:
    """Proves the inode reached ``icat``, not merely that a name was listed."""
    _run_extraction(tmp_path, icat_calls)
    inodes = {cmd[-1] for cmd in icat_calls}

    assert "22" in inodes, f"icat was never asked for the deleted inode: {icat_calls}"


def test_the_undeleted_sibling_still_works(tmp_path: Path, icat_calls: list[list[str]]) -> None:
    """Narrowness: the entries that already worked must keep working.

    This is why the loss was silent -- Security.evtx in the same directory
    matched fine, so the extraction looked successful.
    """
    extracted = _run_extraction(tmp_path, icat_calls)
    names = {p.name for p in extracted}

    assert "Windows_System32_winevt_Logs_Security.evtx" in names


def test_directories_are_not_extracted(tmp_path: Path, icat_calls: list[list[str]]) -> None:
    """Narrowness: the ``Logs`` directory itself is not a file."""
    _run_extraction(tmp_path, icat_calls)
    inodes = {cmd[-1] for cmd in icat_calls}

    assert "21" not in inodes
    assert "20" not in inodes


def test_a_timeout_on_one_file_does_not_abort_the_rest(tmp_path: Path) -> None:
    """Unchanged behaviour: one bad icat must not lose the other logs."""
    seen: list[str] = []

    def flaky(cmd: list[str], **_: object) -> MagicMock:
        seen.append(cmd[-1])
        if cmd[-1] == "22":
            raise subprocess.TimeoutExpired(cmd, 30)
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = b"ElfFile\x00"
        return proc

    with (
        patch(
            "mulder.server.tools.extract.evtx._collect_fls_chunks",
            return_value=[([FLS_WITH_DELETED_EVTX], 0)],
        ),
        patch("mulder.server.tools.extract.evtx.subprocess.run", side_effect=flaky),
    ):
        extracted = _extract_evtx_from_image("/evidence/disk.dd", str(tmp_path))

    assert "22" in seen
    assert {p.name for p in extracted} == {"Windows_System32_winevt_Logs_Security.evtx"}
