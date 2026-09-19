"""Unknown bulk_extractor scanner names must be rejected before the binary runs.

A planner asked ``run_bulk_extractor`` for scanner ``ccn``; the job failed at
the binary (``bulk_extractor exited 5: no such scanner: ccn``) and a job and a
turn were burned before the executor retried with a corrected list.  Names now
resolve through a wider alias table and are checked against the scanner set
parsed from ``bulk_extractor -h``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.extract import carving
from mulder.server.tools.extract.carving import (
    _FALLBACK_SCANNERS,
    _build_bulk_extractor_cmd,
    _parse_scanner_help,
    _resolve_scanners,
    run_bulk_extractor,
)

# Scanner section of ``bulk_extractor -h``, bulk_extractor 2.2.1-dev as built by
# the Dockerfile (docker run --rm mulder:main bulk_extractor -h).
BULK_EXTRACTOR_HELP = """\
These scanners enabled; disable with -x:
   -x accts - disable scanner accts
     -S ssn_mode=0    0=Normal; 1=No `SSN' required; 2=No dashes required
     -S min_phone_digits=7    Min. digits required in a phone
   -x aes - disable scanner aes
     -S scan_aes_128=1    Scan for 128-bit AES keys; 0=No, 1=Yes
     -S scan_aes_192=0    Scan for 192-bit AES keys; 0=No, 1=Yes
     -S scan_aes_256=1    Scan for 256-bit AES keys; 0=No, 1=Yes
   -x base64 - disable scanner base64
   -x elf - disable scanner elf
   -x email - disable scanner email
   -x evtx - disable scanner evtx
   -x exif - disable scanner exif
     -S jpeg_min_carve_size=200    Minimum JPEG size to carve
     -S jpeg_max_carve_size=16777216    Maximum JPEG size to carve
     -S exif_debug=0    debug exif decoder
   -x facebook - disable scanner facebook
   -x find - disable scanner find
   -x gps - disable scanner gps
   -x gzip - disable scanner gzip
     -S gzip_max_uncompr_size=268435456    maximum size for decompressing GZIP objects
   -x httplogs - disable scanner httplogs
   -x json - disable scanner json
   -x kml_carved - disable scanner kml_carved
   -x msxml - disable scanner msxml
   -x net - disable scanner net
     -S carve_net_memory=0    Carve network  memory structures
     -S min_carve_packet_bytes=40    Smallest network packet to carve
   -x ntfsindx - disable scanner ntfsindx
   -x ntfslogfile - disable scanner ntfslogfile
   -x ntfsmft - disable scanner ntfsmft
   -x ntfsusn - disable scanner ntfsusn
   -x pdf - disable scanner pdf
     -S pdf_dump_hex=0    Dump the contents of PDF buffers as hex
     -S pdf_dump_text=0    Dump the contents of PDF buffers showing extracted text
   -x rar - disable scanner rar
     -S rar_find_components=1    Search for RAR components
     -S rar_find_volumes=1    Search for RAR volumes
   -x rtti - disable scanner rtti
   -x sqlite - disable scanner sqlite
   -x utmp - disable scanner utmp
   -x vcard_carved - disable scanner vcard_carved
   -x vin - disable scanner vin
     -S vin_debug=0    Enable VIN scanner debugging
   -x windirs - disable scanner windirs
     -S opt_weird_file_size=157286400    Threshold for FAT32 scanner
     -S opt_weird_file_size2=536870912    Threshold for FAT32 scanner
     -S opt_weird_cluster_count=67108864    Threshold for FAT32 scanner
     -S opt_weird_cluster_count2=268435456    Threshold for FAT32 scanner
     -S opt_max_bits_in_attrib=3    Ignore FAT32 entries with more attributes set than this
     -S opt_max_weird_count=2    Number of 'weird' counts to ignore a FAT32 entry
     -S opt_last_year=2031    Ignore FAT32 entries with a later year than this
   -x winlnk - disable scanner winlnk
   -x winpe - disable scanner winpe
   -x winprefetch - disable scanner winprefetch
   -x zip - disable scanner zip
     -S zip_min_uncompr_size=6    Minimum size of a ZIP uncompressed object
     -S zip_max_uncompr_size=268435456    Maximum size of a ZIP uncompressed object
     -S zip_name_len_max=1024    Maximum name of a ZIP component filename
     -S max_zip_depth=4    Maximum nested ZIP recursion depth
These scanners disabled; enable with -e:
   -e base16 - enable scanner base16
   -e hiberfile - enable scanner hiberfile
   -e outlook - enable scanner outlook
   -e wordlist - enable scanner wordlist
     -S word_min=6    Minimum word size
     -S word_max=16    Maximum word size
     -S max_output_file_size=100000000    Maximum size of the words output file
     -S strings=0    Scan for strings instead of words
   -e xor - enable scanner xor
     -S xor_mask=255    XOR mask value, in decimal
"""

REAL_SCANNERS = frozenset(
    {
        "accts", "aes", "base16", "base64", "elf", "email", "evtx", "exif",
        "facebook", "find", "gps", "gzip", "hiberfile", "httplogs", "json",
        "kml_carved", "msxml", "net", "ntfsindx", "ntfslogfile", "ntfsmft",
        "ntfsusn", "outlook", "pdf", "rar", "rtti", "sqlite", "utmp",
        "vcard_carved", "vin", "windirs", "winlnk", "winpe", "winprefetch",
        "wordlist", "xor", "zip",
    }
)  # fmt: skip


@pytest.fixture(autouse=True)
def _fresh_cache() -> Any:
    carving._known_scanners.cache_clear()
    yield
    carving._known_scanners.cache_clear()


@pytest.fixture
def image(tmp_path: Path) -> Path:
    path = tmp_path / "evidence.dd"
    path.write_bytes(b"\x00" * 4096)
    return path


def _invoke(image: Path, scanners: list[str]) -> tuple[Any, list[list[str]]]:
    """Run the tool with subprocess mocked; return (result, argv of each run call)."""
    calls: list[list[str]] = []

    def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if cmd[:2] == ["bulk_extractor", "-h"]:
            return subprocess.CompletedProcess(cmd, 1, stdout=BULK_EXTRACTOR_HELP, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    with (
        patch("mulder.server.tools.extract.carving.require_binary", return_value=True),
        patch("mulder.server.tools.extract.carving.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.extract.carving._check_disk_space", return_value=None),
        patch("mulder.server.tools.extract.carving.subprocess.run", side_effect=_run),
        patch("mulder.server.tools.extract.carving.extract_and_index", return_value={}),
    ):
        result = run_bulk_extractor.__wrapped__(str(image), scanners=scanners)  # type: ignore[attr-defined]
    return result, calls


def test_help_output_parses_to_the_real_scanner_set() -> None:
    assert _parse_scanner_help(BULK_EXTRACTOR_HELP) == REAL_SCANNERS
    assert _FALLBACK_SCANNERS == REAL_SCANNERS


def test_garbage_help_falls_back_to_builtin_list() -> None:
    proc = subprocess.CompletedProcess(["bulk_extractor", "-h"], 1, stdout="nope", stderr="")
    with patch("mulder.server.tools.extract.carving.subprocess.run", return_value=proc):
        assert carving._known_scanners() == _FALLBACK_SCANNERS


def test_missing_binary_falls_back_to_builtin_list() -> None:
    with patch("mulder.server.tools.extract.carving.subprocess.run", side_effect=OSError):
        assert carving._known_scanners() == _FALLBACK_SCANNERS


@pytest.mark.parametrize(
    ("alias", "scanner"),
    [
        ("ccn", "accts"),
        ("credit_card", "accts"),
        ("CreditCard", "accts"),
        ("phone", "accts"),
        ("ssn", "accts"),
        ("urls", "email"),
        ("emails", "email"),
        ("ip", "net"),
        ("domains", "net"),
        ("http", "httplogs"),
        ("jpeg", "exif"),
        ("lnk", "winlnk"),
        ("prefetch", "winprefetch"),
        ("mft", "ntfsmft"),
        ("email_lg", "email"),
    ],
)
def test_aliases_resolve_to_real_scanners(alias: str, scanner: str) -> None:
    assert _resolve_scanners([alias]) == [scanner]
    assert scanner in REAL_SCANNERS


def test_every_alias_target_is_a_real_scanner() -> None:
    assert set(carving._SCANNER_ALIASES.values()) <= REAL_SCANNERS


def test_valid_scanners_pass_through_unchanged_and_deduped() -> None:
    cmd = _build_bulk_extractor_cmd("img.dd", "out", ["email", "net", "httplogs", "net"], None)
    assert cmd[cmd.index("-E") :] == ["-E", "email", "-e", "net", "-e", "httplogs", "img.dd"]


def test_unknown_scanner_is_rejected_without_running_the_binary(image: Path) -> None:
    result, calls = _invoke(image, ["bogus", "email"])

    assert result["status"] == "error"
    assert result["error_type"] == "invalid_scanner"
    assert "bogus" in result["error_message"]
    assert "email" not in result["error_message"]
    for name in ("accts", "email", "net", "httplogs"):
        assert name in result["suggestion"]
    assert [c for c in calls if c[:2] != ["bulk_extractor", "-h"]] == []


def test_ccn_now_runs_as_accts(image: Path) -> None:
    result, calls = _invoke(image, ["ccn", "email"])

    assert result["status"] != "error"
    (run_cmd,) = [c for c in calls if c[:2] != ["bulk_extractor", "-h"]]
    assert run_cmd[run_cmd.index("-E") :] == ["-E", "accts", "-e", "email", str(image)]


def test_published_example_scanner_lists_are_accepted() -> None:
    known = _parse_scanner_help(BULK_EXTRACTOR_HELP)
    for name in ("email", "net", "httplogs", "exif", "zip", "rar", "pdf", "winpe"):
        assert name in known
