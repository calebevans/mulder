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
import contextlib
import gzip
import io
import shutil
import subprocess
import tarfile
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
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


def test_a_failed_7z_listing_yields_no_totals(tmp_path: Path) -> None:
    proc = subprocess.CompletedProcess([], 2, stdout="", stderr="boom")
    with patch("mulder.server.tools.case.subprocess.run", return_value=proc):
        assert case._7z_listing_totals(Path("a.7z")) is None


def _falsify_declared_size(archive: Path, size: int) -> None:
    """Rewrite the uncompressed size the central directory records for the last member."""
    data = bytearray(archive.read_bytes())
    entry = data.rindex(b"PK\x01\x02")
    data[entry + 24 : entry + 28] = size.to_bytes(4, "little")
    archive.write_bytes(bytes(data))


def test_a_zip_whose_size_cannot_be_established_is_refused(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A falsified central directory passes the declared-size check, then 7z cannot list it.

    ``7z x`` still writes the whole 5 MB stream before it reports the damage,
    so without a listing there is no bound to apply and the archive is refused.
    """
    _free(monkeypatch, 1024)
    archive = tmp_path / "liar.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", b"\x00" * 5_000_000)
    _falsify_declared_size(archive, 10)

    def no_unbounded_extraction(cmd: list[str], *args: Any, **kwargs: Any) -> None:
        raise AssertionError(f"7z ran without a size bound: {cmd}")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(case, "_7z_listing_totals", lambda archive: None)
    monkeypatch.setattr(subprocess, "run", no_unbounded_extraction)

    result = _invoke(cases_dir, archive)

    _assert_refused_for_space(result, cases_dir, "liar.zip")
    assert "expanded size is unknown" in str(result["error_message"])


@needs_7z
def test_a_zip_with_a_falsified_size_is_refused_by_the_real_7z_fallback(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: 7-Zip 26.00 fails to list this zip, yet ``7z x`` writes all 5 MB."""
    _free(monkeypatch, 1024)
    archive = tmp_path / "liar.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", b"\x00" * 5_000_000)
    _falsify_declared_size(archive, 10)

    _assert_refused_for_space(_invoke(cases_dir, archive), cases_dir, "liar.zip")


def _bytes_under(cases_dir: Path) -> int:
    return sum(
        f.stat().st_size for f in _files_under(cases_dir) if f.name != case._COMPLETION_MARKER
    )


def test_concurrent_extractions_share_one_free_space_budget(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two archives that each fit must not both pass the check and fill the disk together.

    The catalog extracts archives concurrently.  Free space here is the budget
    minus what is already extracted, and a barrier holds an extraction that has
    passed its check until the other has checked too: without serialization of
    check *and* extraction, both pass against the same budget.
    """
    budget = 10_000
    cfg = MagicMock()
    cfg.db_dir = cases_dir
    # Patched once, here: mock.patch inside each thread would race on restore.
    monkeypatch.setattr(case, "get_cfg", lambda: cfg)
    monkeypatch.setattr(case, "has_ctx", lambda: False)
    monkeypatch.setattr(
        case, "_free_bytes", lambda dest: RESERVE + budget - _bytes_under(cases_dir)
    )
    barrier = threading.Barrier(2, timeout=1)
    check = case._require_space

    def check_then_wait(*args: Any, **kwargs: Any) -> None:
        check(*args, **kwargs)
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait()

    monkeypatch.setattr(case, "_require_space", check_then_wait)
    archives = []
    for name in ("one.zip", "two.zip"):
        archive = tmp_path / name
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("memory.raw", b"M" * budget)
        archives.append(archive)

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda a: extract_archive.__wrapped__(str(a)), archives))  # type: ignore[attr-defined]

    assert sorted(str(r["status"]) for r in results) == ["error", "success"]
    assert _bytes_under(cases_dir) <= budget


def _zip_with_bad_second_member(archive: Path) -> None:
    """A 600-byte good member, then a member whose stored data fails its CRC."""
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("first.bin", b"F" * 600)
        zf.writestr("bad.bin", b"B" * 100)
    data = bytearray(archive.read_bytes())
    start = data.index(b"bad.bin") + len(b"bad.bin")  # local header: data follows the name
    data[start] ^= 0xFF
    archive.write_bytes(bytes(data))


def _refuse_in_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Send zipfile's BadZipFile to a 7z fallback that refuses for space."""

    def refuse(archive: Path, dest: Path) -> list[str]:
        raise case.InsufficientSpaceError(f"{archive.name} expands past the free space")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(case, "_extract_7z", refuse)


def test_a_refusal_after_partial_output_removes_it(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """zipfile writes the first member before the bad one sends it to the refusing fallback."""
    _refuse_in_fallback(monkeypatch)
    archive = tmp_path / "partial.zip"
    _zip_with_bad_second_member(archive)

    result = _invoke(cases_dir, archive)

    assert result["error_type"] == "disk_space"
    assert "Nothing was extracted" in str(result["error_message"])
    assert _files_under(cases_dir) == []


def test_a_refusal_keeps_files_that_were_already_in_the_destination(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _refuse_in_fallback(monkeypatch)
    archive = tmp_path / "partial.zip"
    _zip_with_bad_second_member(archive)
    dest = cases_dir / "extracted" / "mine"
    (dest / "notes").mkdir(parents=True)
    (dest / "notes" / "unrelated.txt").write_text("keep me")

    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
    ):
        result = extract_archive.__wrapped__(str(archive), str(dest))  # type: ignore[attr-defined]

    assert "Nothing was extracted" in str(result["error_message"])
    assert _files_under(cases_dir) == [dest / "notes" / "unrelated.txt"]
    assert (dest / "notes" / "unrelated.txt").read_text() == "keep me"


def test_a_refusal_that_overwrote_a_file_reports_partial_output(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An overwritten file cannot be restored, so the response must not claim a clean slate."""
    _refuse_in_fallback(monkeypatch)
    archive = tmp_path / "partial.zip"
    _zip_with_bad_second_member(archive)
    dest = cases_dir / "extracted" / "mine"
    dest.mkdir(parents=True)
    (dest / "first.bin").write_text("older content")

    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
    ):
        result = extract_archive.__wrapped__(str(archive), str(dest))  # type: ignore[attr-defined]

    message = str(result["error_message"])
    assert "Nothing was extracted" not in message
    assert "partial output" in message


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
