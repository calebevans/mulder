"""run_usn_parser: the change journal is found, streamed without its sparse zeros, and bounded.

``$UsnJrnl:$J`` is a sparse file: on the image this was checked against (NIST
Data Leakage Case, TSK 4.12) ``icat`` emits 32 MiB of zeros before 37 MiB of
records, and ``fls`` lists the stream as ``r/r 59016-128-3:\\t$UsnJrnl:$J``.
"""

from __future__ import annotations

import io
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server import app
from mulder.server.extract_helpers import extract_and_index
from mulder.server.tools.extract import usn
from mulder.server.tools.extract.usn import run_usn_parser

MIB = 1024 * 1024
EXTEND_LISTING = (
    "r/r 25-144-6:\t$ObjId:$O\n"
    "d/d 27-144-2:\t$RmMetadata\n"
    "r/r 59016-128-3:\t$UsnJrnl:$J\n"
    "r/r 59016-128-5:\t$UsnJrnl:$Max\n"
)
IMAGE = "/evidence/pc.E01"


class FakeIcat:
    """``subprocess.Popen`` stand-in that streams fixed bytes."""

    def __init__(self, data: bytes, returncode: int = 0) -> None:
        self.data = data
        self.returncode = returncode
        self.commands: list[list[str]] = []

    def __call__(self, cmd: list[str], **_kwargs: object) -> FakeIcat:
        self.commands.append(list(cmd))
        self.stdout = io.BytesIO(self.data)
        return self

    def __enter__(self) -> FakeIcat:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def kill(self) -> None:
        return None


@pytest.fixture
def case(tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    return tmp_case_db


def parse(
    monkeypatch: pytest.MonkeyPatch,
    stream: bytes,
    listing: str = EXTEND_LISTING,
    filesystem: str = "ntfs",
    returncode: int = 0,
    **kwargs: Any,
) -> tuple[Any, FakeIcat, list[list[str]], list[bytes]]:
    """Run the tool with fls, icat and MFTECmd replaced.

    Returns the response, the fake icat, the fls commands and the journal
    bytes MFTECmd was handed.
    """
    icat = FakeIcat(stream, returncode)
    fls_commands: list[list[str]] = []
    journals: list[bytes] = []

    def fake_fls(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        fls_commands.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout=listing, stderr="")

    def fake_ez(
        dll: str, args: list[str], source: str, path: str, *rest: object
    ) -> dict[str, object]:
        assert (dll, source, path) == ("MFTECmd.dll", "ez.usnjrnl", IMAGE)
        journal = Path(args[args.index("-f") + 1])
        assert journal.name == "$J"
        journals.append(journal.read_bytes())
        return {"status": "success", "source": source}

    monkeypatch.setattr(usn, "_resolve_partition_offset", lambda _image: 206848)
    monkeypatch.setattr(usn, "_detect_filesystem_type", lambda _image, _offset: filesystem)
    monkeypatch.setattr(usn, "require_binary", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(usn, "run_subprocess", fake_fls)
    monkeypatch.setattr("mulder.server.tools.extract.usn.subprocess.Popen", icat)
    monkeypatch.setattr(usn, "_run_ez_tool", fake_ez)
    result = run_usn_parser.__wrapped__(IMAGE, **kwargs)  # type: ignore[attr-defined]
    return result, icat, fls_commands, journals


def test_the_journal_is_found_in_extend_and_read_by_its_full_stream_inode(
    case: CaseDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = b"\x80\x00\x00\x00\x02\x00" + b"\x01" * (MIB // 2)
    result, icat, fls_commands, journals = parse(monkeypatch, bytes(3 * MIB) + records)

    # $Extend is MFT entry 11 on every NTFS volume: one listing, no indexed file list.
    assert fls_commands == [["fls", "-o", "206848", IMAGE, "11"]]
    # 59016-128-3 names the $J stream; the bare inode would read the unnamed one.
    assert icat.commands == [["icat", "-o", "206848", IMAGE, "59016-128-3"]] * 2
    assert journals == [records], "the sparse zero region must not reach MFTECmd"
    assert result["status"] == "success"
    assert result["journal_bytes_parsed"] == len(records)
    assert "truncated" not in result


def test_a_journal_over_the_cap_keeps_its_newest_records_and_says_so(
    case: CaseDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(usn, "_MAX_JOURNAL_BYTES", 2 * MIB)
    pages = (bytes([i % 255 + 1]) * 4096 for i in range(5 * MIB // 4096))
    data = b"".join(pages) + b"\xee" * 1000
    stream = bytes(MIB) + data

    result, _icat, _fls, journals = parse(monkeypatch, stream)

    kept = journals[0]
    # Records never cross a 4096-byte page, so the cut lands on a record boundary.
    start = (len(stream) - 2 * MIB) // 4096 * 4096
    assert kept == stream[start:]
    assert len(kept) % 4096 == 1000 and 2 * MIB <= len(kept) < 2 * MIB + 4096
    assert result["journal_bytes_parsed"] == len(kept)
    assert "only the newest" in result["truncated"]
    assert "Older records were not examined" in result["truncated"]


def test_no_journal_is_reported_as_unexamined_not_as_clean(
    case: CaseDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = "r/r 25-144-6:\t$ObjId:$O\nr/r * 59016-128-3:\tdeleted-lookalike\n"

    result, icat, _fls, journals = parse(monkeypatch, b"", listing=listing)

    assert result["status"] == "error" and result["error_type"] == "no_journal"
    assert "deletejournal" in result["error_message"]
    assert "not evidence that nothing changed" in result["error_message"]
    assert icat.commands == [] and journals == []


def test_icat_failing_or_returning_only_zeros_is_an_error(
    case: CaseDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed, _icat, _fls, journals = parse(monkeypatch, b"\x01" * 100, returncode=1)
    empty, _icat, _fls, more = parse(monkeypatch, bytes(2 * MIB))

    assert failed["error_type"] == empty["error_type"] == "tool_failed"
    assert journals == more == []


def test_a_volume_that_is_not_ntfs_is_skipped(
    case: CaseDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, icat, fls_commands, _journals = parse(monkeypatch, b"", filesystem="ext4")

    assert result["status"] == "success" and "ext4" in result["preview"]
    assert icat.commands == [] and fls_commands == []


def test_an_indexed_journal_is_not_parsed_again_unless_forced(
    case: CaseDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    extract_and_index("Name,Extension\na.txt,.txt\n", "ez.usnjrnl", IMAGE, "eztools")

    skipped, icat, _fls, _journals = parse(monkeypatch, b"\x01" * 100)
    forced, forced_icat, _fls, journals = parse(monkeypatch, b"\x01" * 100, force=True)

    assert "skipped" in skipped["preview"] and icat.commands == []
    assert forced["status"] == "success" and journals == [b"\x01" * 100]
    assert len(forced_icat.commands) == 2
