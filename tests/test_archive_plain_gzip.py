"""A gzipped disk image must actually be decompressed.

``extract_archive`` routed every bare ``.gz``/``.bz2`` to the *tar* extractor:

    or (ext in (".gz", ".bz2") and ".tar" not in name_lower)

``evidence.dd.gz`` is one compressed file, not an archive of files.  Feeding it
to ``tarfile`` does not raise -- tarfile opens the gzip wrapper, finds no tar
members, and returns an empty list.  ``extract_archive`` then reported
``status: success`` with ``total_files_extracted: 0`` and the disk image was
never written.  A failure to unpack the central piece of evidence in a case was
reported as a successful extraction of nothing.
"""

from __future__ import annotations

import bz2
import gzip
import tarfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools.case import extract_archive

_IMAGE = b"\x00" * 4096 + b"EVIDENCE-MAGIC"


@pytest.fixture
def cases_dir(tmp_path: Path) -> Path:
    d = tmp_path / "cases"
    d.mkdir()
    return d


def _invoke(cases_dir: Path, archive: Path, dest: Path) -> Any:
    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
        patch("mulder.server.tools.case.EvidenceClassifier", create=True),
    ):
        return extract_archive.__wrapped__(  # type: ignore[attr-defined]
            str(archive), extract_to=str(dest)
        )


def test_a_gzipped_disk_image_is_actually_decompressed(cases_dir: Path, tmp_path: Path) -> None:
    """The headline case: evidence.dd.gz must produce evidence.dd."""
    archive = tmp_path / "evidence.dd.gz"
    archive.write_bytes(gzip.compress(_IMAGE))
    dest = tmp_path / "out"

    result = _invoke(cases_dir, archive, dest)

    assert result["status"] == "success"
    assert result["total_files_extracted"] == 1, f"the image was not written: {result}"
    assert (dest / "evidence.dd").read_bytes() == _IMAGE


def test_a_bzipped_image_is_decompressed(cases_dir: Path, tmp_path: Path) -> None:
    archive = tmp_path / "memory.raw.bz2"
    archive.write_bytes(bz2.compress(_IMAGE))
    dest = tmp_path / "out"

    result = _invoke(cases_dir, archive, dest)

    assert result["status"] == "success"
    assert (dest / "memory.raw").read_bytes() == _IMAGE


def test_a_tar_gz_still_goes_to_the_tar_extractor(cases_dir: Path, tmp_path: Path) -> None:
    """Pins narrowness: real tarballs must keep working."""
    inner = tmp_path / "one.txt"
    inner.write_bytes(b"1")
    tar_gz = tmp_path / "bundle.tar.gz"
    with tarfile.open(tar_gz, "w:gz") as tf:
        tf.add(inner, arcname="one.txt")
    dest = tmp_path / "out"

    result = _invoke(cases_dir, tar_gz, dest)

    assert result["status"] == "success"
    assert (dest / "one.txt").read_bytes() == b"1"


def test_a_tar_misnamed_as_plain_gz_is_still_untarred(cases_dir: Path, tmp_path: Path) -> None:
    """The name is not authoritative, so the content is consulted.

    ``tarfile.is_tarfile`` cannot help here -- it returns True for a plain
    gzipped file too, because it only sees the gzip wrapper.
    """
    inner = tmp_path / "two.txt"
    inner.write_bytes(b"2")
    real_tar = tmp_path / "scratch.tar"
    with tarfile.open(real_tar, "w") as tf:
        tf.add(inner, arcname="two.txt")
    misnamed = tmp_path / "bundle.gz"
    misnamed.write_bytes(gzip.compress(real_tar.read_bytes()))
    dest = tmp_path / "out"

    result = _invoke(cases_dir, misnamed, dest)

    assert result["status"] == "success"
    assert (dest / "two.txt").read_bytes() == b"2"


def test_is_tarfile_says_yes_to_a_gzipped_disk_image(tmp_path: Path) -> None:
    """Documents why the fix counts members instead of trusting is_tarfile.

    A tar header block is 512 bytes, and a disk image starts with a run of
    zeroes, so any realistic gzipped image looks like a tar to ``is_tarfile``.
    Verified: 512 zero bytes is already enough. Only a payload far too small to
    be evidence (9 bytes here) is correctly rejected -- which is why the name
    cannot be trusted and the member count must be consulted.
    """
    image = tmp_path / "image.gz"
    image.write_bytes(gzip.compress(_IMAGE))
    assert tarfile.is_tarfile(image) is True

    tiny = tmp_path / "tiny.gz"
    tiny.write_bytes(gzip.compress(b"too small"))
    assert tarfile.is_tarfile(tiny) is False

    # The member count is the honest test, and it separates them.
    with tarfile.open(image, "r:*") as tf:
        assert sum(1 for _ in tf) == 0
