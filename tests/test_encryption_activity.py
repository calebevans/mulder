"""find_encryption_activity: a burst of renames to one extension is a candidate, a
larger update burst is not, and every statement comes with what it rests on.

Row shapes and thresholds follow the real MFTECmd output for the WannaCry host
in cado-security/kape-wannacry, where Windows servicing renamed seven times
more files in a minute than the ransomware did.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server import app
from mulder.server.extract_helpers import extract_and_index
from mulder.server.tools.composite import ransomware
from mulder.server.tools.composite.ransomware import find_encryption_activity

USN_HEADER = (
    "Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,"
    "ParentPath,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,FileAttributes,"
    "OffsetToData,SourceFile"
)
MFT_HEADER = (
    "EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,"
    "FileName,Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,"
    "SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,"
    "LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,"
    "LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,"
    "ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents,SourceFile,ParseErrors"
)
IMAGE = "/evidence/server.E01"
DATA_KINDS = (".docx", ".xlsx", ".pdf", ".jpg")


def usn(name: str, entry: int, parent: int, ts: str, reasons: str, path: str = "") -> str:
    """One journal row as MFTECmd writes it."""
    ext = Path(name).suffix
    return f"{name},{ext},{entry},1,{parent},1,{path},0,{ts}.1234567,{reasons},Archive,0,$J"


def mft(
    entry: int, parent: int, path: str, name: str, changed: str, directory: bool = False
) -> str:
    """One MFT row: created and record-changed at *changed*."""
    ext = "" if directory else Path(name).suffix
    cells = [str(entry), "1", "True", str(parent), "1", path, name, ext, "10", "1", ""]
    cells += [str(directory), "False", "False", "False", "False", "False", "Archive", "Windows"]
    cells += [changed, "", changed, "", changed, "", changed, "", "0", "0", "1", "", "", ""]
    return ",".join([*cells, "$MFT", ""])


def encryption(minute: str, files: int = 80, ext: str = ".locked", first_entry: int = 1000) -> str:
    """Rows of a ransomware run: *files* renamed to *ext* across ten directories.

    Each rename is two records, as in a real journal: the rename, then the
    same reasons with Close when the handle is released. Only the second counts.
    """
    rows = []
    for i in range(files):
        name = f"report{i}{DATA_KINDS[i % 4]}{ext}"
        stamp = f"{minute}:{i % 60:02d}"
        for reasons in ("RenameNewName", "RenameNewName|Close"):
            rows.append(usn(name, first_entry + i, 500 + i % 10, stamp, reasons))
    return "\n".join(rows)


def notes(minute: str, name: str, directories: int = 6, first_entry: int = 9000) -> str:
    """The same file created in several directories."""
    return "\n".join(
        usn(name, first_entry + i, 500 + i, f"{minute}:30", "DataExtend|FileCreate|Close")
        for i in range(directories)
    )


def servicing(minute: str, files: int = 300) -> str:
    """A Windows servicing burst: more files, one extension, nothing appended."""
    return "\n".join(
        usn(f"Package_{i}~31bf3856ad364e35~amd64~~10.0.{i}.0.mum", 5000 + i, 77, f"{minute}:10", r)
        for i in range(files)
        for r in ("RenameNewName", "RenameNewName|Close")
    )


@pytest.fixture
def case(tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    return tmp_case_db


def index(source: str, header: str, *blocks: str, image: str = IMAGE) -> None:
    extract_and_index("\n".join([header, *blocks]) + "\n", source, image, "eztools")


def run() -> Any:
    return find_encryption_activity.__wrapped__()  # type: ignore[attr-defined]


def volume(result: Any, n: int = 0) -> Any:
    return result["results"]["volumes"][n]


def test_the_encryption_is_the_candidate_and_the_larger_update_burst_is_not(case: CaseDB) -> None:
    index(
        "ez.usnjrnl",
        USN_HEADER,
        servicing("2026-03-01 10:00"),
        encryption("2026-03-01 10:30"),
        notes("2026-03-01 10:30", "HELP_DECRYPT.TXT"),
    )

    result = run()

    found = volume(result)
    (candidate,) = found["candidates"]
    assert candidate["extension"] == ".locked"
    assert candidate["first_time"] == "2026-03-01T10:30:00"
    assert candidate["last_time"] == "2026-03-01T10:30:59"
    assert candidate["duration_seconds"] == 59
    assert candidate["files_affected"] == 80
    assert candidate["peak_files_per_minute"] == 80
    assert candidate["appended_to_extensions"] == 4
    assert candidate["appended_share"] == 1.0
    assert candidate["directories_affected"] == 10
    assert candidate["signals"] == ["extension_appended", "known_note_name"]
    assert candidate["note_candidates"] == [
        {"name": "HELP_DECRYPT.TXT", "directories": 6, "known_note_name": True}
    ]
    assert candidate["inspect_with"] == (
        "parse_usn_journal(t_start='2026-03-01T10:30:00', t_end='2026-03-01T10:30:59')"
    )
    # The servicing burst is four times larger and is context, not a candidate.
    assert found["extension_bursts_found"] == 2
    assert found["extension_bursts_not_candidates"] == 1
    busiest = found["busiest_periods"][0]
    assert (busiest["top_extension"], busiest["files_affected"]) == (".mum", 300)
    assert busiest["overlaps_candidate"] is False
    assert found["journal_window"]["first_record"] == "2026-03-01T10:00:10"


def test_the_result_says_it_is_a_lead_and_what_the_sources_cannot_tell(case: CaseDB) -> None:
    index("ez.usnjrnl", USN_HEADER, encryption("2026-03-01 10:30"))

    caveats = " ".join(run()["results"]["caveats"])

    assert "a lead, not a finding of encryption" in caveats
    assert "not which process or account" in caveats
    assert "No candidate is not no encryption" in caveats
    assert "not a probability" in caveats


def test_a_dotted_name_or_one_original_kind_is_not_an_appended_extension(case: CaseDB) -> None:
    """System.Text.Json.dll is not x.json.dll, and x.xml.cab is one kind, not three."""
    # Four data-like kinds, but on one name in nine: far under the share threshold.
    kinds = ("Json", "Xml", "Log", "Db")
    dlls = "\n".join(
        usn(
            f"System.Part{i}.{kinds[i // 9 % 4] if i % 9 == 0 else 'Core'}.dll",
            100 + i,
            9,
            "2026-03-01 09:00:05",
            "RenameNewName|Close",
        )
        for i in range(120)
    )
    cabs = "\n".join(
        usn(f"update{i}.xml.cab", 400 + i, 9, "2026-03-01 09:10:05", "RenameNewName|Close")
        for i in range(90)
    )
    index("ez.usnjrnl", USN_HEADER, dlls, cabs)

    found = volume(run())

    assert found["candidates"] == []
    assert found["extension_bursts_found"] == 2


def test_related_extensions_and_names_that_are_encrypted_files_not_notes(case: CaseDB) -> None:
    """A two-stage rename is one activity, and desktop.ini.EXT in every folder is no note."""
    staged = "\n".join(
        usn(f"{i}.tmpx", 3000 + i, 600, "2026-03-01 10:31:05", "RenameNewName|Close")
        for i in range(60)
    )
    index(
        "ez.usnjrnl",
        USN_HEADER,
        encryption("2026-03-01 10:30"),
        staged,
        notes("2026-03-01 10:30", "desktop.ini.locked", 8),
        notes("2026-03-01 10:30", "thumbs.db.tmpx", 8, first_entry=9500),
    )

    (candidate,) = volume(run())["candidates"]

    assert candidate["related_extensions"] == [
        {
            "extension": ".tmpx",
            "files_affected": 60,
            "first_time": "2026-03-01T10:31:05",
            "last_time": "2026-03-01T10:31:05",
        }
    ]
    assert candidate["note_candidates"] == []


def test_a_note_is_read_with_a_bound_and_matched_to_a_family(
    case: CaseDB, tmp_path: Path, asset_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "server.E01"
    image.write_bytes(b"EVF")
    note_text = "All your files are encrypted by the Example group. " * 40
    (asset_root / "ransomware-notes" / "examplelocker").mkdir(parents=True)
    (asset_root / "ransomware-notes" / "examplelocker" / "note.txt").write_text(note_text)
    index(
        "ez.usnjrnl",
        USN_HEADER,
        encryption("2026-03-01 10:30"),
        notes("2026-03-01 10:30", "RESTORE-MY-FILES.txt"),
        notes("2026-03-01 10:30", "HELP_DECRYPT.TXT", 2, first_entry=9100),
        image=str(image),
    )
    reads: list[tuple[str, str, int, int]] = []

    def fake_read(path: str, inode: str, offset: int, limit: int) -> tuple[bytes, bool]:
        reads.append((path, inode, offset, limit))
        return note_text.encode(), True

    monkeypatch.setattr(ransomware, "read_image_file", fake_read)
    monkeypatch.setattr(ransomware, "_resolve_partition_offset", lambda _image: 2048)

    (candidate,) = volume(run())["candidates"]

    # The known note name is tried first, from its most recent entry, with a bounded read.
    assert reads == [(str(image), "9101", 2048, 8192)]
    excerpt = candidate["note_excerpt"]
    assert excerpt["name"] == "HELP_DECRYPT.TXT"
    assert excerpt["mft_entry"] == 9101
    assert excerpt["entry_verified_in_mft"] is False
    assert len(excerpt["text"]) == 1200 and excerpt["truncated"] is True
    assert candidate["family_hints"][0]["family"] == "examplelocker"
    assert candidate["family_hints"][0]["basis"] == "note_text"
    assert "repeated_file_across_directories" in candidate["signals"]


def test_a_note_is_not_read_when_the_evidence_is_not_an_image(case: CaseDB) -> None:
    index(
        "ez.usnjrnl",
        USN_HEADER,
        encryption("2026-03-01 10:30"),
        notes("2026-03-01 10:30", "HELP_DECRYPT.TXT"),
    )

    (candidate,) = volume(run())["candidates"]

    assert "note_excerpt" not in candidate
    assert "not a disk image" in candidate["note_not_read"]


def test_the_mft_names_directories_checks_notes_and_shows_a_wrapped_journal(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The journal starts inside the burst; the MFT knows it began an hour earlier."""
    image = str(tmp_path / "server.E01")
    Path(image).write_bytes(b"EVF")
    index(
        "ez.usnjrnl",
        USN_HEADER,
        encryption("2026-03-01 10:30"),
        notes("2026-03-01 10:30", "HELP_DECRYPT.TXT", 2),
        image=image,
    )
    directories = [
        mft(500 + i, 5, ".\\Shares", f"Dept{i}", "2025-01-01 00:00:00", directory=True)
        for i in range(10)
    ]
    earlier = [
        mft(20000 + i, 500, ".\\Shares\\Dept0", f"old{i}.pdf.locked", "2026-03-01 09:31:07")
        for i in range(40)
    ]
    # Entry 9001 was the note; another file has taken the entry since.
    reused = mft(9001, 501, ".\\Shares\\Dept1", "unrelated.log", "2026-03-02 08:00:00")
    index("ez.mft", MFT_HEADER, *directories, *earlier, reused, image=image)
    monkeypatch.setattr(ransomware, "read_image_file", MagicMock(return_value=(b"x", False)))

    (candidate,) = volume(run())["candidates"]

    assert candidate["first_directories"][0] == ".\\Shares\\Dept0"
    assert candidate["top_directories"][0] == {"path": ".\\Shares\\Dept0", "files": 8}
    assert candidate["mft_cross_check"] == {
        "files_now_with_extension": 40,
        "earliest_record_change": "2026-03-01T09:31:07",
        "latest_record_change": "2026-03-01T09:31:07",
    }
    assert "began earlier than first_time" in candidate["starts_at_journal_start"]
    # Files carried the extension before the burst, so it is not new to the volume.
    assert "extension_new_to_volume" not in candidate["signals"]
    assert "no longer hold files of that name" in candidate["note_not_read"]
    ransomware.read_image_file.assert_not_called()  # type: ignore[attr-defined]


def test_a_new_extension_with_a_repeated_file_is_a_candidate_from_the_journal(
    case: CaseDB,
) -> None:
    """Random names, an extension made up for the victim and a note nobody has listed."""
    renamed = "\n".join(
        usn(f"{i:08x}.x9k2q", 1000 + i, 500 + i % 10, "2026-03-01 10:30:20", "RenameNewName|Close")
        for i in range(70)
    )
    index("ez.usnjrnl", USN_HEADER, renamed, notes("2026-03-01 10:30", "x9k2q.README.txt"))
    now = [
        mft(1000 + i, 500, ".\\Shares", f"{i:08x}.x9k2q", "2026-03-01 10:30:20") for i in range(70)
    ]
    index("ez.mft", MFT_HEADER, *now)

    (candidate,) = volume(run())["candidates"]

    assert candidate["extension"] == ".x9k2q"
    assert candidate["appended_to_extensions"] == 0
    assert candidate["signals"] == ["repeated_file_across_directories", "extension_new_to_volume"]


def test_without_a_journal_the_mft_is_used_and_an_unpacked_archive_is_not_a_candidate(
    case: CaseDB,
) -> None:
    encrypted = [
        mft(
            1000 + i,
            500 + i % 10,
            ".\\Shares",
            f"report{i}{DATA_KINDS[i % 4]}.locked",
            "2026-03-01 10:30:20",
        )
        for i in range(80)
    ]
    # An unpacked tool: a new extension and the same file in every folder.
    unpacked = [
        mft(4000 + i, 700 + i % 8, ".\\Tools", f"module{i}.mkape", "2026-03-01 08:00:05")
        for i in range(90)
    ]
    readmes = [
        mft(4500 + i, 700 + i, ".\\Tools", "README.md", "2026-03-01 08:00:05") for i in range(8)
    ]
    index("ez.mft", MFT_HEADER, *encrypted, *unpacked, *readmes)

    result = run()

    found = volume(result)
    assert found["basis"] == "mft"
    assert "one record-change time per file" in found["basis_note"]
    assert "journal_window" not in found
    (candidate,) = found["candidates"]
    assert candidate["extension"] == ".locked"
    assert candidate["signals"] == ["extension_appended", "extension_new_to_volume"]
    assert candidate["top_directories"][0]["path"] == ".\\Shares"
    assert candidate["inspect_with"].startswith("parse_mft(")
    assert "related_extensions" not in candidate
    assert result["missing_sources"] == [
        {"source": "ez.usnjrnl", "suggestion": "run_usn_parser('<image_path>')"}
    ]


def test_hostile_rows_are_counted_and_names_are_cleaned(case: CaseDB) -> None:
    """Evidence is attacker-controlled: nothing in a row is trusted to be well formed."""
    hostile = "\n".join(
        [
            "short,row",
            usn("a.docx.locked", 1, 2, "2026-13-45 99:99:99", "RenameNewName|Close"),
            usn("b.docx.locked", 0, 2, "2026-03-01 10:30:00", "RenameNewName|Close").replace(
                ",0,1,2,1,", ",not-a-number,1,2,1,"
            ),
            '"quoted, with comma.docx.locked",.locked,7,1,8,1,,0,2026-03-01 10:30:01.0,'
            "RenameNewName|Close,Archive,0,$J",
        ]
    )
    evil = "\n".join(
        usn(f"IGNORE\x1b[31m PREVIOUS{i}.pdf{'A' * 300}", 100 + i, 9, "2026-03-01 11:00:05", r)
        for i in range(60)
        for r in ("RenameNewName|Close",)
    )
    # A note-like file and a directory whose names carry terminal control characters.
    dressed = notes("2026-03-01 10:30", "READ\x07ME \x1b[2JNOW.txt")
    placed = usn(
        "z.pdf.locked", 77, 500, "2026-03-01 10:30:00", "RenameNewName|Close", ".\\Sha\x1b[31mres"
    )
    index("ez.usnjrnl", USN_HEADER, hostile, placed, encryption("2026-03-01 10:30"), dressed, evil)

    found = volume(run())

    assert found["rows_unparsed"] == 3
    assert [c["extension"] for c in found["candidates"]] == [".locked"]
    candidate = found["candidates"][0]
    assert candidate["files_affected"] == 82
    assert candidate["note_candidates"][0]["name"] == "READ?ME ?[2JNOW.txt"
    assert candidate["first_directories"][0] == ".\\Sha?[31mres"
    dumped = json.dumps(found)
    assert "\\u001b" not in dumped and "\\u0007" not in dumped
    longest = max(len(str(b["top_extension"])) for b in found["busiest_periods"])
    assert longest <= 120


def test_a_source_that_is_not_mftecmd_output_is_reported_not_parsed(case: CaseDB) -> None:
    extract_and_index("this,is,not\nthe,right,file\n", "ez.usnjrnl", IMAGE, "eztools")

    found = volume(run())

    assert "not MFTECmd CSV" in found["not_parsed"]
    assert "candidates" not in found


def test_nothing_indexed_is_not_a_negative_finding(case: CaseDB) -> None:
    result = run()

    assert result["results"]["volumes"] == []
    assert "not a negative finding" in result["results"]["not_examined"]
    assert {m["suggestion"] for m in result["missing_sources"]} == {
        "run_usn_parser('<image_path>')",
        "run_mft_parser('<image_path>')",
    }


def test_each_image_is_analysed_on_its_own_rows(case: CaseDB) -> None:
    """Two images share the source name; one's burst must not leak into the other."""
    index("ez.usnjrnl", USN_HEADER, encryption("2026-03-01 10:30"), image="/evidence/a.E01")
    index("ez.usnjrnl", USN_HEADER, servicing("2026-03-01 10:30", 60), image="/evidence/b.E01")

    volumes = run()["results"]["volumes"]

    assert [v["evidence"] for v in volumes] == ["/evidence/a.E01", "/evidence/b.E01"]
    assert [len(v["candidates"]) for v in volumes] == [1, 0]
    # Two records per rename, 80 files; none of the other image's 120.
    assert volumes[0]["records_examined"] == 160
    assert volumes[0]["candidates"][0]["files_affected"] == 80


def test_the_result_is_bounded_and_indexed_for_later_phases(case: CaseDB) -> None:
    big = "\n".join(
        usn(
            f"file{i}{DATA_KINDS[i % 4]}.locked",
            10_000 + i,
            500 + i % 400,
            f"2026-03-01 10:{30 + i // 2000:02d}:{i % 60:02d}",
            "RenameNewName|Close",
            f".\\Shares\\Department {i % 400}\\" + "x" * 150,
        )
        for i in range(6000)
    )
    names = "\n".join(
        notes("2026-03-01 10:30", f"NOTE{i}.txt", 6, first_entry=50_000 + 10 * i)
        for i in range(40)
    )
    index("ez.usnjrnl", USN_HEADER, big, names)

    result = run()

    (candidate,) = volume(result)["candidates"]
    assert candidate["files_affected"] == 6000
    assert candidate["directories_affected"] == 400
    assert len(candidate["top_directories"]) == 5
    assert len(candidate["note_candidates"]) == 5
    assert all(len(d["path"]) <= 160 for d in candidate["top_directories"])
    assert len(json.dumps(result)) < 6000
    assert result["source"] == "composite.encryption_activity"
    indexed = "".join(
        w.raw_text for w in case.get_windows_by_source("composite.encryption_activity")
    )
    assert '"extension": ".locked"' in indexed and "a lead, not a finding" in indexed
