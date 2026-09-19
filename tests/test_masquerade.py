"""Tests for detect_masquerading: signature table, mismatch logic, bounded walk (issue #223)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.orchestrator.phases import EXTRACTION
from mulder.server.tool_access import Role, get_tools_for_role
from mulder.server.tools.extract import masquerade
from mulder.server.tools.extract.masquerade import (
    detect_masquerading,
    identify_content,
    is_mismatch,
    parse_fls_long,
)

MOD = "mulder.server.tools.extract.masquerade"
_tool: Any = detect_masquerading.__wrapped__  # type: ignore[attr-defined]  # sync body under the async bridge


def _zip(*names: bytes) -> bytes:
    """A fake zip head: one local-file header per name, no data."""
    out = b""
    for n in names:
        out += b"PK\x03\x04" + b"\x00" * 22 + len(n).to_bytes(2, "little") + b"\x00\x00" + n
    return out


@pytest.mark.parametrize(
    ("head", "family"),
    [
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 24, "ole"),
        (b"%PDF-1.7\n", "pdf"),
        (b"\xff\xd8\xff\xe0\x00\x10JFIF", "jpeg"),
        (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "png"),
        (b"GIF89a\x01\x00", "gif"),
        (b"BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00", "bmp"),
        (b"II*\x00\x08\x00\x00\x00", "tiff"),
        (b"7z\xbc\xaf\x27\x1c\x00\x04", "7z"),
        (b"Rar!\x1a\x07\x01\x00", "rar"),
        (b"\x1f\x8b\x08\x00", "gzip"),
        (b"MZ\x90\x00\x03\x00", "pe"),
        (b"\x7fELF\x02\x01\x01", "elf"),
        (b"{\\rtf1\\ansi", "rtf"),
        (b"ID3\x03\x00", "mp3"),
        (b"#!AMR\n", "amr"),
        (b"\x00\x00\x00\x18ftypmp42", "mp4"),
        (b"RIFF\x00\x00\x00\x00AVI LIST", "avi"),
        (b"SQLite format 3\x00", "sqlite"),
        (_zip(b"lib/foo.class", b"META-INF/MANIFEST.MF"), "zip"),
        (b"PK\x05\x06" + b"\x00" * 18, "zip"),
        (_zip(b"[Content_Types].xml", b"_rels/.rels", b"ppt/presentation.xml"), "pptx"),
        (_zip(b"[Content_Types].xml", b"xl/workbook.xml"), "xlsx"),
        (_zip(b"[Content_Types].xml", b"word/document.xml"), "docx"),
        (_zip(b"[Content_Types].xml", b"docProps/app.xml"), "ooxml"),
        (b"Dear diary,\nnothing happened today.\n", "text"),
        (b"BMW is a car maker\n", "text"),
        (b"", None),
        (bytes(range(256)), None),
    ],
)
def test_identify_content(head: bytes, family: str | None) -> None:
    assert identify_content(head) == family


@pytest.mark.parametrize(
    ("path", "detected", "hit"),
    [
        # OOXML inside a .zip is a masquerade of the document, not of "zip".
        ("design/winter_whether_advisory.zip", "pptx", True),
        ("design/winter_storm.amr", "ole", True),
        ("price/my_favorite_movies.7z", "xlsx", True),
        ("price/my_favorite_cars.db", "ole", True),
        ("notes/diary_#1d.txt", "docx", True),
        # Same family: no hit.
        ("a/genuine.zip", "zip", False),
        ("a/deck.pptx", "pptx", False),
        ("a/deck.PPTX", "ooxml", False),
        ("a/deck.docx", "zip", False),
        ("a/photo.jpeg", "jpeg", False),
        ("a/old.doc", "rtf", False),
        ("a/Thumbs.db", "ole", False),
        # Unknown extension or unidentified content: cannot judge, no hit.
        ("a/blob.dat", "pe", False),
        ("a/noext", "pdf", False),
        ("a/utf16.txt", None, False),
    ],
)
def test_is_mismatch(path: str, detected: str | None, hit: bool) -> None:
    assert is_mismatch(path, detected) is hit


FLS_LONG = (
    "r/r 3:\tVOL (Volume Label Entry)\t2015-03-24 17:02:36 (UTC)\t0000-00-00 00:00:00 (UTC)"
    "\t0000-00-00 00:00:00 (UTC)\t0000-00-00 00:00:00 (UTC)\t0\t0\t0\n"
    "v/v 33423363:\t$MBR\t0000-00-00 00:00:00 (UTC)\t0000-00-00 00:00:00 (UTC)"
    "\t0000-00-00 00:00:00 (UTC)\t0000-00-00 00:00:00 (UTC)\t512\t0\t0\n"
    "-/d * 133:\t$OrphanFiles/design\t2015-03-24 09:57:14 (UTC)\t2015-03-24 00:00:00 (UTC)"
    "\t0000-00-00 00:00:00 (UTC)\t2015-03-24 09:59:26 (UTC)\t4096\t0\t0\n"
    "r/r * 263:\t$OrphanFiles/design/winter_storm.amr\t2015-01-23 16:47:10 (UTC)"
    "\t2015-03-24 00:00:00 (UTC)\t0000-00-00 00:00:00 (UTC)\t2015-03-24 09:59:27 (UTC)"
    "\t14547968\t0\t0\n"
    "r/r 4-128-1:\tUsers/bob/real.zip\t2015-01-01 00:00:00 (UTC)\t2015-01-01 00:00:00 (UTC)"
    "\t2015-01-01 00:00:00 (UTC)\t2015-01-01 00:00:00 (UTC)\t100\t0\t0\n"
    "r/r 5:\tUsers/bob/movie.7z\t2015-01-01 00:00:00 (UTC)\t2015-01-01 00:00:00 (UTC)"
    "\t2015-01-01 00:00:00 (UTC)\t2015-01-01 00:00:00 (UTC)\t100\t0\t0\n"
    "r/r 6:\tUsers/bob/readme.txt\t2015-01-01 00:00:00 (UTC)\t2015-01-01 00:00:00 (UTC)"
    "\t2015-01-01 00:00:00 (UTC)\t2015-01-01 00:00:00 (UTC)\t100\t0\t0\n"
    "r/r 7:\tUsers/bob/mystery.dat\t2015-01-01 00:00:00 (UTC)\t2015-01-01 00:00:00 (UTC)"
    "\t2015-01-01 00:00:00 (UTC)\t2015-01-01 00:00:00 (UTC)\t100\t0\t0\n"
)


def test_parse_fls_long_keeps_regular_nonempty_files_only() -> None:
    entries = parse_fls_long(FLS_LONG)
    assert [e.path for e in entries] == [
        "$OrphanFiles/design/winter_storm.amr",
        "Users/bob/real.zip",
        "Users/bob/movie.7z",
        "Users/bob/readme.txt",
        "Users/bob/mystery.dat",
    ]
    amr = entries[0]
    assert amr.deleted and amr.size == 14547968 and amr.inode == "263"
    assert amr.mtime == "2015-01-23 16:47:10 (UTC)"
    assert amr.crtime == "2015-03-24 09:59:27 (UTC)"
    assert entries[1].inode == "4"  # NTFS attribute suffix stripped for icat
    assert not entries[1].deleted


HEADS = {
    "263": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 24,
    "4": _zip(b"lib/foo.class"),
    "5": _zip(b"[Content_Types].xml", b"xl/workbook.xml"),
    "6": b"plain text\n",
    "7": b"MZ\x90\x00",
}


def _run(**kwargs: Any) -> tuple[dict[str, object], MagicMock, list[str]]:
    fls = MagicMock(returncode=0, stdout=FLS_LONG.encode(), stderr=b"")
    read: list[str] = []

    def fake_head(_image: str, _offset: int, inode: str, _n: int) -> bytes:
        read.append(inode)
        return HEADS[inode]

    with (
        patch(f"{MOD}.subprocess.run", return_value=fls),
        patch(f"{MOD}._read_head", side_effect=fake_head),
        patch(f"{MOD}.require_binary", return_value="/usr/bin/x"),
        patch(f"{MOD}.sources_already_indexed", return_value=[]),
        patch(f"{MOD}.extract_and_index") as index,
    ):
        index.return_value = {
            "source_name": "tsk.masquerade",
            "line_count": 2,
            "status": "indexed",
        }
        resp: dict[str, object] = _tool("/ev/rm2.E01", partition_offset=128, **kwargs)
    return resp, index, read


def test_walk_reports_mismatches_and_indexes_them() -> None:
    resp, index, read = _run()
    # mystery.dat has no known extension family, so it is never sampled.
    assert read == ["263", "4", "5", "6"]
    text = index.call_args.args[0]
    assert index.call_args.args[1:] == ("tsk.masquerade", "/ev/rm2.E01", "sleuthkit")
    lines = text.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith(
        "$OrphanFiles/design/winter_storm.amr | ext=amr | detected=ole | size=14547968 | deleted"
    )
    assert "mtime=2015-01-23 16:47:10 (UTC)" in lines[0]
    assert lines[1].startswith(
        "Users/bob/movie.7z | ext=7z | detected=xlsx | size=100 | allocated"
    )

    assert resp["status"] == "success"
    assert resp["source"] == "tsk.masquerade"
    assert resp["line_count"] == 2
    assert "search(query, source='tsk.masquerade')" in str(resp["hint"])
    preview = str(resp["preview"])
    assert preview.startswith(
        '{"mismatches": 2, "partitions_scanned": [{"partition_offset": 128, '
        '"description": "explicit", "files_listed": 5, "mismatches": 2}], '
        '"partitions_skipped": [], "files_listed": 5, "files_sampled": 4, "truncated": false, '
        '"hits": [{"path": "$OrphanFiles/design/winter_storm.amr"'
    )


def test_walk_is_bounded_by_max_files() -> None:
    resp, index, read = _run(max_files=2)
    assert read == ["263", "4"]
    assert index.call_args.args[0].count("\n") == 0  # only the .amr hit
    assert '"files_sampled": 2, "truncated": true' in str(resp["preview"])


def test_fls_command_uses_long_listing_and_offset() -> None:
    with patch(f"{MOD}.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
        with (
            patch(f"{MOD}.require_binary", return_value="/usr/bin/x"),
            patch(f"{MOD}.sources_already_indexed", return_value=[]),
            patch(f"{MOD}.extract_and_index", return_value={}),
        ):
            _tool("/ev/rm2.E01", partition_offset=128)
    assert run.call_args.args[0] == ["fls", "-r", "-p", "-l", "-o", "128", "/ev/rm2.E01"]


def test_fls_failure_is_an_error_response() -> None:
    with (
        patch(f"{MOD}.subprocess.run", return_value=MagicMock(returncode=1, stderr=b"bad fs")),
        patch(f"{MOD}.require_binary", return_value="/usr/bin/x"),
        patch(f"{MOD}.sources_already_indexed", return_value=[]),
    ):
        resp = _tool("/ev/x.E01", partition_offset=0)
    assert resp["status"] == "error"
    assert resp["error_type"] == "extraction_failed"
    assert "bad fs" in str(resp["error_message"])


def test_registered_for_extract_executor_only() -> None:
    assert "mcp__mulder__detect_masquerading" in get_tools_for_role(Role.EXTRACT_EXECUTOR)
    assert "mcp__mulder__detect_masquerading" not in get_tools_for_role(Role.EXTRACT_ANALYST)
    assert masquerade.__name__ == MOD


def test_prompts_mention_the_tool() -> None:
    assert "detect_masquerading" in EXTRACTION.planner_system_prompt
    assert "tsk.masquerade" in EXTRACTION.analyst_system_prompt


MMLS_TWO = (
    "DOS Partition Table\n"
    "Offset Sector: 0\n"
    "Units are in 512-byte sectors\n"
    "\n"
    "     Slot    Start        End          Length       Description\n"
    "000:000   0000000000   0000000000   0000000001   Primary Table (#0)\n"
    "001:000   0000000000   0000000127   0000000128   Unallocated\n"
    "002:000   0000000128   0000409727   0000409600   NTFS (0x07)\n"
    "003:001   0000409728   0007864319   0007454592   Win95 FAT32 (0x0B)\n"
)


def test_no_offset_scans_every_partition_and_reports_skipped() -> None:
    """Issue #227: RM2 has an empty NTFS partition before the FAT32 one holding the hits."""

    def fake_fls(cmd: list[str], **_: Any) -> MagicMock:
        offset = cmd[cmd.index("-o") + 1]
        if offset == "128":
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        if offset == "409728":
            return MagicMock(returncode=0, stdout=FLS_LONG.encode(), stderr=b"")
        return MagicMock(returncode=1, stdout=b"", stderr=b"no fs")

    with (
        patch(f"{MOD}.subprocess.run", side_effect=fake_fls) as run,
        patch(f"{MOD}._partition_table_text", return_value=MMLS_TWO),
        patch(f"{MOD}._read_head", side_effect=lambda _i, _o, inode, _n: HEADS[inode]),
        patch(f"{MOD}.require_binary", return_value="/usr/bin/x"),
        patch(f"{MOD}.sources_already_indexed", return_value=[]),
        patch(f"{MOD}.extract_and_index", return_value={}) as index,
    ):
        resp = _tool("/ev/rm2.E01")

    # Table and unallocated rows are not filesystems; both real partitions get an fls call.
    assert [c.args[0][c.args[0].index("-o") + 1] for c in run.call_args_list] == ["128", "409728"]
    preview = str(resp["preview"])
    assert '"mismatches": 2' in preview
    assert (
        '"partitions_scanned": [{"partition_offset": 128, "description": "ntfs (0x07)", '
        '"files_listed": 0, "mismatches": 0}, {"partition_offset": 409728, '
        '"description": "win95 fat32 (0x0b)", "files_listed": 5, "mismatches": 2}]'
    ) in preview
    assert '"partitions_skipped": []' in preview
    assert all(line.endswith("| offset=409728") for line in index.call_args.args[0].splitlines())


def test_unopenable_partition_is_reported_not_silenced() -> None:
    def fake_fls(cmd: list[str], **_: Any) -> MagicMock:
        if cmd[cmd.index("-o") + 1] == "128":
            return MagicMock(returncode=1, stdout=b"", stderr=b"Cannot determine file system type")
        return MagicMock(returncode=0, stdout=FLS_LONG.encode(), stderr=b"")

    with (
        patch(f"{MOD}.subprocess.run", side_effect=fake_fls),
        patch(f"{MOD}._partition_table_text", return_value=MMLS_TWO),
        patch(f"{MOD}._read_head", side_effect=lambda _i, _o, inode, _n: HEADS[inode]),
        patch(f"{MOD}.require_binary", return_value="/usr/bin/x"),
        patch(f"{MOD}.sources_already_indexed", return_value=[]),
        patch(f"{MOD}.extract_and_index", return_value={}),
    ):
        resp = _tool("/ev/rm2.E01")
    assert resp["status"] == "success"
    preview = str(resp["preview"])
    assert (
        '"partitions_skipped": [{"partition_offset": 128, "description": "ntfs (0x07)", '
        '"reason": "fls exited 1: Cannot determine file system type"}]'
    ) in preview
