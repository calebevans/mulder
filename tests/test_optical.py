"""Optical media (UDF / ISO 9660) support.

Sleuth Kit cannot read a burned CD-R: ``fls`` exits 1 with "Possible
encryption detected (High entropy)", so every model in the NDLC benchmark
gave up on the disc.  The UDF fixture is the metadata sectors (69 of 52513)
of the real NIST CFReDS 2015 RM#3 image, a Windows 7 "Live File System"
CD-R with nine VAT sessions.
"""

from __future__ import annotations

import gzip
import json
import struct
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.extractors.optical import (
    SECTOR,
    OpticalError,
    extract_optical,
    list_optical,
    probe_optical,
    signature_from_vrs,
)
from mulder.server.tool_access import Role, get_tools_for_role

_FIXTURE = Path(__file__).parent / "fixtures" / "rm3_udf_metadata.json.gz"
_RM3_SECTORS = 52513
_TSK = "mulder.server.tools.extract.tsk"
_OPT = "mulder.server.tools.extract.optical"

_CONFIDENTIAL = {
    "/design/winter_storm.amr",
    "/design/winter_whether_advisory.zip",
    "/pricing decision/my_favorite_cars.db",
    "/pricing decision/my_favorite_movies.7z",
    "/pricing decision/new_years_day.jpg",
    "/pricing decision/super_bowl.avi",
    "/progress/my_friends.svg",
    "/progress/my_smartphone.png",
    "/progress/new_year_calendar.one",
    "/proposal/a_gift_from_you.gif",
    "/proposal/landscape.png",
    "/technical review/diary_#1d.txt",
    "/technical review/diary_#1p.txt",
    "/technical review/diary_#2d.txt",
    "/technical review/diary_#2p.txt",
    "/technical review/diary_#3d.txt",
    "/technical review/diary_#3p.txt",
}


def _vrs(*idents: bytes) -> bytes:
    out = bytearray(16 * SECTOR)
    for i, ident in enumerate(idents):
        out[i * SECTOR + 1 : i * SECTOR + 6] = ident
    return bytes(out)


@pytest.fixture()
def rm3_image(tmp_path: Path) -> Path:
    """The RM#3 disc rebuilt as a sparse file: real metadata, zeroed file data."""
    sectors = json.loads(gzip.decompress(_FIXTURE.read_bytes()))
    img = tmp_path / "rm3.dd"
    with open(img, "wb") as fh:
        for sec, hexdata in sectors.items():
            fh.seek(int(sec) * SECTOR)
            fh.write(bytes.fromhex(hexdata))
        fh.truncate(_RM3_SECTORS * SECTOR)
    return img


def _iso_record(name: bytes, extent: int, size: int, flags: int) -> bytes:
    length = 33 + len(name) + (33 + len(name)) % 2
    r = bytearray(length)
    r[0] = length
    struct.pack_into("<I", r, 2, extent)
    struct.pack_into(">I", r, 6, extent)
    struct.pack_into("<I", r, 10, size)
    struct.pack_into(">I", r, 14, size)
    r[18:25] = bytes([115, 3, 24, 16, 58, 15]) + struct.pack("<b", -16)  # UTC-4
    r[25] = flags
    r[28], r[31] = 1, 1
    r[32] = len(name)
    r[33 : 33 + len(name)] = name
    return bytes(r)


@pytest.fixture()
def iso_image(tmp_path: Path) -> Path:
    """A hand-built ISO 9660 disc: /HELLO.TXT and /SUB/INNER.TXT."""
    img = bytearray(22 * SECTOR)
    pvd = img[16 * SECTOR : 17 * SECTOR]
    pvd[0], pvd[1:6], pvd[6] = 1, b"CD001", 1
    pvd[40:72] = b"TESTDISC".ljust(32)
    pvd[156:190] = _iso_record(b"\x00", 18, SECTOR, 2)
    img[16 * SECTOR : 17 * SECTOR] = pvd
    img[17 * SECTOR] = 255
    img[17 * SECTOR + 1 : 17 * SECTOR + 6] = b"CD001"
    root = (
        _iso_record(b"\x00", 18, SECTOR, 2)
        + _iso_record(b"\x01", 18, SECTOR, 2)
        + _iso_record(b"HELLO.TXT;1", 19, 5, 0)
        + _iso_record(b"SUB", 20, SECTOR, 2)
    )
    img[18 * SECTOR : 18 * SECTOR + len(root)] = root
    img[19 * SECTOR : 19 * SECTOR + 5] = b"hello"
    sub = (
        _iso_record(b"\x00", 20, SECTOR, 2)
        + _iso_record(b"\x01", 18, SECTOR, 2)
        + _iso_record(b"INNER.TXT;1", 21, 3, 0)
    )
    img[20 * SECTOR : 20 * SECTOR + len(sub)] = sub
    img[21 * SECTOR : 21 * SECTOR + 3] = b"abc"
    path = tmp_path / "disc.iso"
    path.write_bytes(bytes(img))
    return path


# ---------------------------------------------------------------------------
# Signature detection
# ---------------------------------------------------------------------------


class TestSignature:
    def test_udf_bridge_and_bare_udf(self) -> None:
        assert signature_from_vrs(_vrs(b"BEA01", b"NSR03", b"TEA01")) == "udf"
        assert signature_from_vrs(_vrs(b"CD001", b"CD001", b"BEA01", b"NSR02")) == "udf"

    def test_iso9660_only(self) -> None:
        assert signature_from_vrs(_vrs(b"CD001", b"CD001")) == "iso9660"

    def test_not_optical(self) -> None:
        assert signature_from_vrs(_vrs()) is None
        assert signature_from_vrs(b"\xebR\x90NTFS    " * 10) is None
        assert signature_from_vrs(b"") is None

    def test_probe_raw_image(self, tmp_path: Path, iso_image: Path, rm3_image: Path) -> None:
        assert probe_optical(str(iso_image)) == "iso9660"
        assert probe_optical(str(rm3_image)) == "udf"
        ntfs = tmp_path / "usb.dd"
        ntfs.write_bytes(b"\xebR\x90NTFS    " + b"\0" * (40 * SECTOR))
        assert probe_optical(str(ntfs)) is None
        assert probe_optical(str(tmp_path / "missing.dd")) is None

    def test_probe_e01_uses_img_cat(self) -> None:
        """EWF images are probed through TSK img_cat with 2048-byte sectors, no mount."""
        proc = subprocess.CompletedProcess(["img_cat"], 0, stdout=_vrs(b"BEA01", b"NSR03"))
        with (
            patch("mulder.extractors.optical.shutil.which", return_value="/usr/bin/img_cat"),
            patch("mulder.extractors.optical.subprocess.run", return_value=proc) as run,
        ):
            assert probe_optical("/evidence/rm3.E01") == "udf"
        cmd = run.call_args.args[0]
        assert cmd[:7] == ["img_cat", "-b", "2048", "-s", "16", "-e", "31"]

        with patch("mulder.extractors.optical.shutil.which", return_value=None):
            assert probe_optical("/evidence/rm3.E01") is None


# ---------------------------------------------------------------------------
# UDF reader on the real RM#3 metadata
# ---------------------------------------------------------------------------


class TestUdfListing:
    def test_volume_and_current_session(self, rm3_image: Path) -> None:
        listing = list_optical(rm3_image)

        assert listing.fs_type == "UDF (write-once, VAT)"
        assert listing.volume_label == "IAMAN CD"
        assert listing.sectors == _RM3_SECTORS
        assert listing.generations == 9
        present = {e.path: e for e in listing.entries if not e.deleted}
        assert set(present) == {"/Koala.jpg", "/Penguins.jpg", "/Tulips.jpg"}
        assert present["/Koala.jpg"].size == 780831
        assert present["/Koala.jpg"].mtime == "2009-07-14T05:32:31Z"
        assert present["/Koala.jpg"].ctime == "2015-03-24T20:57:00Z"

    def test_deleted_files_from_earlier_sessions(self, rm3_image: Path) -> None:
        listing = list_optical(rm3_image)
        deleted = {e.path: e for e in listing.entries if e.deleted and not e.is_dir}

        assert set(deleted) >= _CONFIDENTIAL
        # the same 17 files under their renamed directories (design -> de ...)
        assert "/de/winter_storm.amr" in deleted
        assert "/tr/diary_#3p.txt" in deleted
        assert deleted["/design/winter_storm.amr"].size == 14547968
        assert deleted["/design/winter_storm.amr"].extents == [(669696, 14547968)]
        assert deleted["/design/winter_storm.amr"].generation < 0

    def test_text_is_fls_like(self, rm3_image: Path) -> None:
        text = list_optical(rm3_image).to_text()
        lines = text.splitlines()

        assert lines[0].startswith(
            "Optical media: UDF (write-once, VAT)\tvolume label: 'IAMAN CD'"
        )
        assert "sessions (VAT generations): 9" in lines[0]
        assert any(
            line.startswith("r/r ") and "\t/Koala.jpg\tsize=780831\t" in line for line in lines
        )
        assert any(
            line.startswith("* r/r ") and "/proposal/a_gift_from_you.gif" in line for line in lines
        )

    def test_extract_reads_the_extents(self, rm3_image: Path, tmp_path: Path) -> None:
        listing = list_optical(rm3_image)
        entry = next(e for e in listing.entries if e.path == "/Koala.jpg")
        with open(rm3_image, "r+b") as fh:
            fh.seek(entry.extents[0][0])
            fh.write(b"\xff\xd8\xff\xe0")
        dest = tmp_path / "koala.jpg"

        assert extract_optical(rm3_image, entry, dest) == 780831
        assert dest.read_bytes()[:4] == b"\xff\xd8\xff\xe0"

    def test_not_optical_raises(self, tmp_path: Path) -> None:
        blank = tmp_path / "blank.dd"
        blank.write_bytes(b"\0" * (40 * SECTOR))
        with pytest.raises(OpticalError):
            list_optical(blank)


class TestIsoListing:
    def test_walks_directories(self, iso_image: Path, tmp_path: Path) -> None:
        listing = list_optical(iso_image)

        assert listing.fs_type == "ISO 9660"
        assert listing.volume_label == "TESTDISC"
        by_path = {e.path: e for e in listing.entries}
        assert set(by_path) == {"/HELLO.TXT", "/SUB", "/SUB/INNER.TXT"}
        assert by_path["/SUB"].is_dir
        assert by_path["/HELLO.TXT"].size == 5
        assert by_path["/HELLO.TXT"].mtime == "2015-03-24T20:58:15Z"
        dest = tmp_path / "inner.txt"
        assert extract_optical(iso_image, by_path["/SUB/INNER.TXT"], dest) == 3
        assert dest.read_bytes() == b"abc"


# ---------------------------------------------------------------------------
# Sleuth Kit tools redirect instead of reporting "high entropy"
# ---------------------------------------------------------------------------


_TSK_FAIL = subprocess.CompletedProcess(
    ["fls"], 1, stdout=b"", stderr=b"Possible encryption detected (High entropy (7.65))\n"
)


class TestFlsFallback:
    @patch(f"{_TSK}.get_ctx")
    @patch(f"{_TSK}.sources_already_indexed", return_value=[])
    @patch(f"{_TSK}.require_binary", return_value="/usr/bin/fls")
    @patch(f"{_TSK}._detect_partition_offset", return_value=0)
    @patch(f"{_TSK}.subprocess.run", return_value=_TSK_FAIL)
    @patch(f"{_TSK}.probe_optical", return_value="udf")
    def test_run_fls_names_optical_media(self, probe: MagicMock, *_: MagicMock) -> None:
        from mulder.server.tools.extract.tsk import run_fls

        result = run_fls.__wrapped__("/evidence/rm3.E01")  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert result["error_type"] == "optical_media"
        assert result["error_message"].startswith("optical media (UDF) - Sleuth Kit cannot read")
        assert "run_optical_listing" in result["error_message"]
        assert "run_optical_listing(image_path='/evidence/rm3.E01')" in result["suggestion"]
        assert "entropy" not in result["error_message"]
        probe.assert_called_once_with("/evidence/rm3.E01")

    @patch(f"{_TSK}.get_ctx")
    @patch(f"{_TSK}.sources_already_indexed", return_value=[])
    @patch(f"{_TSK}.require_binary", return_value="/usr/bin/fls")
    @patch(f"{_TSK}._detect_partition_offset", return_value=0)
    @patch(f"{_TSK}.subprocess.run", return_value=_TSK_FAIL)
    @patch(f"{_TSK}.probe_optical", return_value=None)
    def test_run_fls_keeps_tsk_error_for_hard_disks(self, *_: MagicMock) -> None:
        from mulder.server.tools.extract.tsk import run_fls

        result = run_fls.__wrapped__("/evidence/pc.E01")  # type: ignore[attr-defined]

        assert result["error_type"] == "extraction_failed"
        assert "Run run_mmls first" in result["error_message"]

    @patch(f"{_TSK}.get_ctx")
    @patch(f"{_TSK}._resolve_partition_offset", return_value=0)
    @patch(f"{_TSK}.require_binary", return_value="/usr/bin/fsstat")
    @patch(f"{_TSK}.subprocess.run", return_value=_TSK_FAIL)
    @patch(f"{_TSK}.probe_optical", return_value="udf")
    def test_run_fsstat_and_mmls_redirect(self, *_: MagicMock) -> None:
        from mulder.server.tools.extract.tsk import run_fsstat, run_mmls

        for tool in (run_fsstat, run_mmls):
            result = tool.__wrapped__("/evidence/rm3.E01")  # type: ignore[attr-defined]
            assert result["error_type"] == "optical_media", tool.__name__


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


def test_tools_are_extract_executor_only() -> None:
    executor = set(get_tools_for_role(Role.EXTRACT_EXECUTOR))
    analyst = set(get_tools_for_role(Role.EXTRACT_ANALYST))

    assert {"mcp__mulder__run_optical_listing", "mcp__mulder__extract_optical_file"} <= executor
    assert "mcp__mulder__run_optical_listing" not in analyst


@contextmanager
def _raw(path: Path) -> Iterator[Path]:
    yield path


class TestOpticalTools:
    def test_run_optical_listing_indexes_the_disc(self, rm3_image: Path) -> None:
        from mulder.server.tools.extract.optical import run_optical_listing

        with (
            patch(f"{_OPT}.raw_image", side_effect=lambda p: _raw(rm3_image)),
            patch(f"{_OPT}.sources_already_indexed", return_value=[]),
            patch(f"{_OPT}.extract_and_index", return_value={"line_count": 58}) as index,
        ):
            result = run_optical_listing.__wrapped__("/evidence/rm3.E01")  # type: ignore[attr-defined]

        assert result["status"] == "success"
        assert result["source"] == "optical.listing"
        assert '"volume_label": "IAMAN CD"' in result["preview"]
        assert '"files_present": 3' in result["preview"]
        assert '"files_deleted": 34' in result["preview"]
        text, source, path, extractor = index.call_args.args
        assert source == "optical.listing" and path == "/evidence/rm3.E01"
        assert "/design/winter_storm.amr" in text

    def test_run_optical_listing_rejects_hard_disks(self, tmp_path: Path) -> None:
        from mulder.server.tools.extract.optical import run_optical_listing

        ntfs = tmp_path / "usb.dd"
        ntfs.write_bytes(b"\0" * (40 * SECTOR))
        with patch(f"{_OPT}.sources_already_indexed", return_value=[]):
            result = run_optical_listing.__wrapped__(str(ntfs))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert result["error_type"] == "not_optical_media"

    def test_extract_optical_file(self, rm3_image: Path, tmp_path: Path) -> None:
        from mulder.server.tools.extract.optical import extract_optical_file

        cfg = MagicMock(db_dir=tmp_path / "cases")
        with (
            patch(f"{_OPT}.raw_image", side_effect=lambda p: _raw(rm3_image)),
            patch(f"{_OPT}.get_cfg", return_value=cfg),
        ):
            result = extract_optical_file.__wrapped__(  # type: ignore[attr-defined]
                "/evidence/rm3.E01", "design/winter_storm.amr"
            )
            missing = extract_optical_file.__wrapped__(  # type: ignore[attr-defined]
                "/evidence/rm3.E01", "/nope.txt"
            )

        assert result["status"] == "success"
        out = result["results"]
        dest = Path(out["extracted_to"])
        assert (
            dest
            == tmp_path / "cases" / "extracted" / "rm3_optical" / "design" / "winter_storm.amr"
        )
        assert dest.stat().st_size == 14547968 == out["size_bytes"]
        assert out["deleted_on_disc"] is True
        assert len(out["sha256"]) == 64
        assert missing["error_type"] == "file_not_found"
        assert "/Koala.jpg" in missing["error_message"]


def test_catalog_marks_optical_disk_images(tmp_path: Path) -> None:
    from mulder.extractors.classifier import ClassifiedEvidence
    from mulder.server.tools.case import _manifest_entry

    disc = tmp_path / "rm3.E01"
    disc.write_bytes(b"x")
    with patch("mulder.server.tools.case.probe_optical", return_value="udf"):
        entry = _manifest_entry(ClassifiedEvidence(path=disc, artifact_type="disk_image"))
    with patch("mulder.server.tools.case.probe_optical", return_value=None):
        plain = _manifest_entry(ClassifiedEvidence(path=disc, artifact_type="disk_image"))

    assert entry["media"] == "optical (udf)"
    assert "run_optical_listing" in str(entry["note"])
    assert "media" not in plain
