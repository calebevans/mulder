"""A raw disk image named .raw or .001 is classified as a disk image.

Disk imagers write ``.raw`` and ``.001`` as readily as memory acquirers, but
the classifier called every such file a memory dump.  A dd disk image was then
listed as ``[memory_dump]``, its optical check was skipped,
``audit_tool_coverage`` asked for Volatility instead of the disk tools, and
the catalog gate counted no disk images.  The investigate evidence context
offered the same image as "ready for Volatility".

A disk signature now makes a disk image; without one the file is still a
memory dump, because a plain physical-memory dump has no header.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.extractors.classifier import EvidenceClassifier
from mulder.orchestrator.evidence import EvidenceContext
from mulder.orchestrator.gates import reset_gate_failure_counters, validate_catalog
from mulder.server.tools import yara

SIZE = 65536
MEMORY_HEADING = "Extracted memory dumps (ready for Volatility):"


def _image(fields: dict[int, bytes]) -> bytes:
    """A zero-filled image head with each ``offset: bytes`` written in place."""
    buf = bytearray(SIZE)
    for offset, data in fields.items():
        buf[offset : offset + len(data)] = data
    return bytes(buf)


MBR_ENTRY = bytes([0x80, 0, 0, 0, 0x07, 0, 0, 0]) + struct.pack("<II", 2048, 20480)
EXT_SUPERBLOCK = (
    struct.pack("<I", 1024) + bytes(20) + struct.pack("<I", 2) + bytes(28) + b"\x53\xef"
)

MBR_DISK = _image({446: MBR_ENTRY, 510: b"\x55\xaa"})
NTFS_VOLUME = _image({3: b"NTFS    ", 510: b"\x55\xaa"})
NO_SIGNATURE = bytes(SIZE)


def _classify(path: Path, data: bytes) -> str:
    path.write_bytes(data)
    (result,) = EvidenceClassifier().classify(path)
    return result.artifact_type


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("mbr.raw", MBR_DISK),
        ("gpt.raw", _image({510: b"\x55\xaa", 512: b"EFI PART"})),
        ("ntfs.001", NTFS_VOLUME),
        ("fat32.raw", _image({82: b"FAT32   ", 510: b"\x55\xaa"})),
        ("ext4.001", _image({1024: EXT_SUPERBLOCK})),
        ("cdrom.raw", _image({32769: b"CD001"})),
    ],
)
def test_a_disk_signature_makes_a_disk_image(tmp_path: Path, name: str, data: bytes) -> None:
    assert _classify(tmp_path / name, data) == "disk_image"


@pytest.mark.parametrize("name", ["memory.raw", "memory.001"])
def test_without_a_disk_signature_it_is_still_a_memory_dump(tmp_path: Path, name: str) -> None:
    assert _classify(tmp_path / name, NO_SIGNATURE) == "memory_dump"


def test_a_boot_signature_without_a_partition_table_is_not_a_disk(tmp_path: Path) -> None:
    stray = _image({446: b"\x13" * 64, 510: b"\x55\xaa"})
    assert _classify(tmp_path / "memory.raw", stray) == "memory_dump"


def test_other_extensions_are_not_sniffed(tmp_path: Path) -> None:
    """Pins narrowness: only .raw and .001 are checked."""
    assert _classify(tmp_path / "dump.mem", NTFS_VOLUME) == "memory_dump"
    assert _classify(tmp_path / "memory.img", NO_SIGNATURE) == "disk_image"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a POSIX FIFO")
def test_a_fifo_named_raw_is_not_opened(tmp_path: Path) -> None:
    """Opening a FIFO blocks until a writer appears; classification must not hang."""
    os.mkfifo(tmp_path / "pipe.raw")
    results = EvidenceClassifier().classify(tmp_path)
    assert [r.artifact_type for r in results] == ["memory_dump"]


def test_scan_evidence_marks_a_raw_iso_as_optical_media(tmp_path: Path) -> None:
    from mulder.server.tools.case import _manifest_entry

    iso = tmp_path / "cdrom.raw"
    iso.write_bytes(_image({32769: b"CD001"}))
    (item,) = EvidenceClassifier().classify(iso)
    assert _manifest_entry(item).get("media") == "optical (iso9660)"


def _context(evidence: Path, home: Path) -> str:
    with patch("pathlib.Path.home", return_value=home):
        return EvidenceContext(str(evidence)).build_evidence_context("host-a")


def test_evidence_context_does_not_offer_a_raw_disk_to_volatility(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "host-a-disk.raw").write_bytes(MBR_DISK)
    (evidence / "host-a-memory.raw").write_bytes(NO_SIGNATURE)

    ctx = _context(evidence, tmp_path / "home")
    memory_part = ctx.split(MEMORY_HEADING)[1]

    assert "host-a-disk.raw" in ctx.split(MEMORY_HEADING)[0]
    assert "host-a-disk.raw" not in memory_part
    # Without a signature the listing is unchanged: the dump is in both lists.
    assert "host-a-memory.raw" in memory_part


def test_evidence_context_lists_an_extracted_raw_disk_as_a_disk(tmp_path: Path) -> None:
    home = tmp_path / "home"
    slot = home / ".mulder" / "cases" / "extracted" / "host-a-disk"
    slot.mkdir(parents=True)
    (slot / "host-a-disk.raw").write_bytes(NTFS_VOLUME)
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    ctx = _context(evidence, home)

    assert "Disk images:" in ctx
    assert MEMORY_HEADING not in ctx


def test_catalog_gate_counts_raw_disk_images(tmp_path: Path) -> None:
    reset_gate_failure_counters()
    (tmp_path / "ws01.raw").write_bytes(NTFS_VOLUME)
    (tmp_path / "ws02.001").write_bytes(MBR_DISK)
    (tmp_path / "ws01-memory.raw").write_bytes(NO_SIGNATURE)
    catalog = {
        "case_id": "c",
        "evidence_root": str(tmp_path),
        "systems": [{"name": "ws01", "evidence": ["disk_image"]}],
    }

    result = validate_catalog(catalog, str(tmp_path))

    assert not result.passed
    assert "2 disk image(s)" in result.gaps[0]


def _find_memory(cases_dir: Path) -> str:
    ctx = MagicMock()
    ctx.db.get_sources.return_value = []
    ctx.db.get_case_metadata.return_value = MagicMock(evidence_root="")
    with (
        patch.object(yara, "get_ctx", return_value=ctx),
        patch("mulder.server.app.get_cfg", return_value=MagicMock(db_dir=cases_dir)),
    ):
        return yara._find_memory_image()


def test_yara_fallback_skips_a_raw_disk_image(tmp_path: Path) -> None:
    slot = tmp_path / "extracted" / "host-a"
    slot.mkdir(parents=True)
    (slot / "host-a-disk.raw").write_bytes(MBR_DISK)
    with pytest.raises(RuntimeError, match="No memory sources"):
        _find_memory(tmp_path)

    (slot / "host-a-memory.raw").write_bytes(NO_SIGNATURE)
    assert _find_memory(tmp_path) == str(slot / "host-a-memory.raw")
