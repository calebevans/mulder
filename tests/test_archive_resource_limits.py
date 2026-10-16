"""``extract_archive`` must not unpack an archive that cannot fit on disk.

Nothing bounded how much a single archive could expand to, so a small
attacker-supplied archive could fill the disk the case database lives on.

The bound is the destination filesystem's *free space*, applied at one point
for every format (zip, tar, 7z, bare .gz/.bz2).  It is never a fixed cap or a
per-member compression ratio: a ratio cannot tell an attack from evidence (a
zeroed 64 MiB region of a disk image compresses about 1029x, and so does a
freshly allocated VM memory dump), and a fixed cap refuses ordinary large
evidence.  Tests shrink the free space instead of writing huge fixtures.
"""

from __future__ import annotations

import bz2
import gzip
import io
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools import case
from mulder.server.tools.case import extract_archive

RESERVE = case._EXTRACT_RESERVE_BYTES
needs_7z = pytest.mark.skipif(shutil.which("7z") is None, reason="7z not installed")


@pytest.fixture
def cases_dir(tmp_path: Path) -> Path:
    d = tmp_path / "cases"
    d.mkdir()
    return d


def _invoke(cases_dir: Path, archive: Path) -> Any:
    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
        patch("mulder.server.tools.case.EvidenceClassifier", create=True),
    ):
        return extract_archive.__wrapped__(str(archive))  # type: ignore[attr-defined]


def _free(monkeypatch: pytest.MonkeyPatch, usable: int) -> None:
    """Make the destination filesystem report *usable* bytes beyond the reserve."""
    monkeypatch.setattr(case, "_free_bytes", lambda dest: RESERVE + usable)


def _files_under(cases_dir: Path) -> list[Path]:
    return [f for f in (cases_dir / "extracted").rglob("*") if f.is_file()]


def _assert_refused_for_space(result: Any, cases_dir: Path, name: str) -> None:
    assert result["status"] == "error"
    assert result["error_type"] == "disk_space"
    message = str(result["error_message"])
    assert name in message
    # The refusal is about absolute size, not about how well it compressed.
    assert "ratio" not in message.lower()
    assert _files_under(cases_dir) == []


def _tar_with(tmp_path: Path, name: str, members: dict[str, bytes], mode: str = "w:gz") -> Path:
    archive = tmp_path / name
    with tarfile.open(archive, mode) as tf:  # type: ignore[call-overload]
        for member_name, data in members.items():
            info = tarfile.TarInfo(member_name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return archive


def test_a_zip_larger_than_free_space_is_refused(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _free(monkeypatch, 1024)
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", b"\x00" * 64_000)

    _assert_refused_for_space(_invoke(cases_dir, archive), cases_dir, "bomb.zip")


def test_a_tar_larger_than_free_space_is_refused(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _free(monkeypatch, 1024)
    archive = _tar_with(tmp_path, "bomb.tar.gz", {"big.bin": b"\x00" * 64_000})

    _assert_refused_for_space(_invoke(cases_dir, archive), cases_dir, "bomb.tar.gz")


def test_a_tar_member_count_over_the_free_inodes_is_refused(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(case, "_free_inodes", lambda dest: 5)
    archive = _tar_with(tmp_path, "many.tar", {f"f{i}.txt": b"x" for i in range(20)}, "w")

    result = _invoke(cases_dir, archive)

    _assert_refused_for_space(result, cases_dir, "many.tar")
    assert "inodes" in str(result["error_message"])


def test_a_zip_member_count_over_the_free_inodes_is_refused(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(case, "_free_inodes", lambda dest: 5)
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(20):
            zf.writestr(f"f{i}.txt", b"x")

    result = _invoke(cases_dir, archive)

    _assert_refused_for_space(result, cases_dir, "many.zip")
    assert "inodes" in str(result["error_message"])


@pytest.mark.parametrize(
    ("name", "compress"),
    [("bomb.dd.bz2", bz2.compress), ("bomb.dd.gz", gzip.compress)],
)
def test_a_bare_compressed_stream_larger_than_free_space_is_refused(
    cases_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    compress: Any,
) -> None:
    _free(monkeypatch, 1024)
    archive = tmp_path / name
    archive.write_bytes(compress(b"\x00" * 5_000_000))
    assert archive.stat().st_size < 10_000  # tiny on disk, 5 MB expanded

    # No partial output survives: the stream is copied in counted chunks.
    _assert_refused_for_space(_invoke(cases_dir, archive), cases_dir, name)


@needs_7z
@pytest.mark.parametrize("suffix", [".7z", ".zip"])
def test_a_7z_larger_than_free_space_is_refused_even_when_renamed(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    """A renamed .7z reaches ``7z`` through the zip BadZipFile fallback."""
    _free(monkeypatch, 1024)
    src = tmp_path / "src"
    src.mkdir()
    (src / "big.bin").write_bytes(b"\x00" * 5_000_000)
    real = tmp_path / "bomb.7z"
    subprocess.run(["7z", "a", str(real), str(src / "big.bin")], check=True, capture_output=True)
    archive = real if suffix == ".7z" else real.rename(tmp_path / "bomb.zip")

    _assert_refused_for_space(_invoke(cases_dir, archive), cases_dir, archive.name)


@needs_7z
def test_an_ordinary_7z_still_extracts(cases_dir: Path, tmp_path: Path) -> None:
    src = tmp_path / "evidence.raw"
    src.write_bytes(b"MEMORY" * 100)
    archive = tmp_path / "evidence.7z"
    subprocess.run(["7z", "a", str(archive), str(src)], check=True, capture_output=True)

    result = _invoke(cases_dir, archive)

    assert result["status"] == "success"
    assert result["total_files_extracted"] == 1


def test_7z_listing_totals_are_parsed_from_slt_output() -> None:
    listing = (
        "Path = a.7z\nType = 7z\nPhysical Size = 100\n\n----------\n"
        "Path = one\nSize = 10\nPacked Size = 5\n\nPath = two\nSize = 32\n"
    )
    proc = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
    with patch("mulder.server.tools.case.subprocess.run", return_value=proc):
        assert case._7z_listing_totals(Path("a.7z")) == (2, 42)


def test_an_unlistable_7z_is_still_attempted(tmp_path: Path) -> None:
    proc = subprocess.CompletedProcess([], 2, stdout="", stderr="boom")
    with patch("mulder.server.tools.case.subprocess.run", return_value=proc):
        assert case._7z_listing_totals(Path("a.7z")) is None


def test_the_refusal_does_not_claim_files_were_written(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unrelated files already in the destination must not be reported as extracted."""
    _free(monkeypatch, 1024)
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("big.bin", b"\x00" * 64_000)
    dest = cases_dir / "extracted" / "bomb"
    dest.mkdir(parents=True)
    for i in range(3):
        (dest / f"unrelated{i}.txt").write_text("x")

    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
    ):
        result = extract_archive.__wrapped__(str(archive), str(dest))  # type: ignore[attr-defined]

    message = str(result["error_message"])
    assert "Nothing was extracted" in message
    assert "were written" not in message
    assert "3 file" not in message


def test_free_space_is_what_decides_not_a_fixed_size(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same archive extracts when it fits and is refused when it does not."""
    archive = tmp_path / "evidence.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("memory.raw", b"M" * 10_000)

    _free(monkeypatch, 10_000)
    assert _invoke(cases_dir, archive)["status"] == "success"

    other = tmp_path / "other.zip"
    other.write_bytes(archive.read_bytes())
    _free(monkeypatch, 9_999)
    assert _invoke(cases_dir, other)["error_type"] == "disk_space"


def test_an_ordinary_archive_still_extracts(cases_dir: Path, tmp_path: Path) -> None:
    """Pins narrowness: real evidence on a real disk is untouched (no patching)."""
    archive = tmp_path / "evidence.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("memory.raw", b"MEMORY" * 100)

    result = _invoke(cases_dir, archive)

    assert result["status"] == "success"
    assert result["total_files_extracted"] == 1


def test_a_zeroed_evidence_region_is_not_treated_as_a_bomb(
    cases_dir: Path, tmp_path: Path
) -> None:
    """The test that killed the compression-ratio heuristic.

    A 4 MiB run of zeroes -- an unallocated region of a disk image, or a fresh
    VM memory dump -- compresses by roughly three orders of magnitude.  Any
    ratio-based bomb detector refuses it.  It is ordinary evidence and must
    extract.
    """
    archive = tmp_path / "disk.zip"
    payload = b"\x00" * (4 * 1024 * 1024)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("unallocated.dd", payload)

    ratio = len(payload) / archive.stat().st_size
    assert ratio > 500, f"fixture only compressed {ratio:.0f}x; it must be extreme"

    result = _invoke(cases_dir, archive)

    assert result["status"] == "success", (
        f"a {ratio:.0f}x-compressible evidence region was refused: {result.get('error_message')}"
    )
    assert result["total_files_extracted"] == 1
