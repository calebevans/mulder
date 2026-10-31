"""Special-file tar members must not be extracted.

``_safe_tar_filter`` only checked member names and link targets, and returned
every other member unchanged.  A FIFO member named ``disk.dd`` was therefore
created on disk; the classifier typed it as a disk image by its suffix and the
optical probe opened it for reading, which blocks forever with no writer.
``extract_archive`` never returned.  Only regular files, directories and links
belong in an evidence archive.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools.case import _safe_tar_filter, extract_archive

_TIMEOUT = 30


def _build_tar(path: Path) -> None:
    with tarfile.open(path, "w:gz") as tf:
        fifo = tarfile.TarInfo("disk.dd")
        fifo.type = tarfile.FIFOTYPE
        tf.addfile(fifo)
        data = b"hello"
        reg = tarfile.TarInfo("notes.txt")
        reg.size = len(data)
        tf.addfile(reg, io.BytesIO(data))


def _invoke(cases_dir: Path, archive: Path, dest: Path) -> Any:
    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
    ):
        return extract_archive.__wrapped__(  # type: ignore[attr-defined]
            str(archive), extract_to=str(dest)
        )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_fifo_member_is_not_created_and_extraction_finishes(tmp_path: Path) -> None:
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    archive = tmp_path / "evidence.tar.gz"
    _build_tar(archive)
    dest = cases_dir / "extracted" / "out"

    result: dict[str, Any] = {}

    def run() -> None:
        result["value"] = _invoke(cases_dir, archive, dest)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(_TIMEOUT)
    if worker.is_alive():
        # Release the reader blocked on the FIFO so the thread can exit.
        fd = os.open(dest / "disk.dd", os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        pytest.fail("extract_archive blocked on a FIFO member")

    fifo = dest / "disk.dd"
    assert not (fifo.exists() and stat.S_ISFIFO(fifo.lstat().st_mode))
    assert (dest / "notes.txt").read_bytes() == b"hello"
    assert result["value"]["status"] == "success"


@pytest.mark.parametrize("member_type", [tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE])
def test_filter_rejects_special_files(member_type: bytes) -> None:
    member = tarfile.TarInfo("disk.dd")
    member.type = member_type
    assert _safe_tar_filter(member, "/tmp/dest") is None


def test_filter_keeps_regular_files_and_directories() -> None:
    reg = tarfile.TarInfo("notes.txt")
    directory = tarfile.TarInfo("sub")
    directory.type = tarfile.DIRTYPE
    assert _safe_tar_filter(reg, "/tmp/dest") is reg
    assert _safe_tar_filter(directory, "/tmp/dest") is directory
