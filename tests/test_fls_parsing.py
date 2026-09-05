"""Every fls-driven extractor was blind to deleted files.

Six modules carried eleven copies of the same regex::

    ^[rd]/[rd*]\\s+(\\d+(?:-\\d+-\\d+)?):\\s+(.+)$

Two things about it are wrong, and the fixtures below come from The Sleuth
Kit 4.12.1 run against a real image built for this test:

* the deleted marker is a **separate ``*`` token after the type pair** --
  ``r/r * 6:\\tdeleted.evtx`` -- not a character inside it. ``[rd*]`` in the
  second position matches a format fls does not emit, so after ``r/r`` the
  regex required a digit and found ``*``. **Every deleted entry failed to
  match**, in every extractor: evtx, registry hives, pcaps, browser
  databases, plists and generic app files. A deleted Security.evtx is
  exactly the thing an investigator is looking for.
* the type characters are not limited to ``r`` and ``d``. TSK also emits
  ``v``, ``V``, ``l``, ``s``, ``c``, ``b``, ``p``, ``h``, ``w`` and ``-``
  for unknown -- and ``-/r`` is what an unallocated or orphaned file looks
  like.
"""

from __future__ import annotations

from mulder.patterns import FlsEntry, fls_file_entries, parse_fls_rows

# Verbatim `fls -r -p` output from sleuthkit 4.12.1 on a FAT16 image
# containing one deleted file.
REAL_FLS = (
    "r/r * 6:\tdeleted.evtx\n"
    "v/v 523203:\t$MBR\n"
    "v/v 523204:\t$FAT1\n"
    "v/v 523205:\t$FAT2\n"
    "d/d 4:\tWindows\n"
    "d/d 518:\tWindows/System32\n"
    "d/d 581:\tWindows/System32/winevt\n"
    "d/d 646:\tWindows/System32/winevt/Logs\n"
    "r/r 710:\tWindows/System32/winevt/Logs/Security.evtx\n"
    "r/r 712:\tWindows/System32/winevt/Logs/System.evtx\n"
    "V/V 523206:\t$OrphanFiles\n"
)

# NTFS-shaped rows, which a FAT image cannot produce: attribute-qualified
# inodes, deleted files, and the unknown-type entries that orphans present as.
NTFS_FLS = (
    "r/r 4512-128-4:\tWindows/System32/config/SYSTEM\n"
    "r/r * 9911-128-1:\tWindows/System32/winevt/Logs/Security.evtx\n"
    "-/r * 10233-128-1:\t$OrphanFiles/Application.evtx\n"
    "r/- 7003-128-1:\tUsers/alice/NTUSER.DAT\n"
    "l/l 8100-128-1:\tUsers/alice/link\n"
)


class TestParsesRealOutput:
    def test_every_row_is_parsed(self) -> None:
        assert len(parse_fls_rows(REAL_FLS)) == 11

    def test_the_deleted_entry_is_found(self) -> None:
        """The bug: this row matched nothing before."""
        entries = {e.path: e for e in parse_fls_rows(REAL_FLS)}
        assert "deleted.evtx" in entries
        assert entries["deleted.evtx"].deleted is True
        assert entries["deleted.evtx"].inode == "6"

    def test_live_entries_are_not_flagged_deleted(self) -> None:
        entries = {e.path: e for e in parse_fls_rows(REAL_FLS)}
        assert entries["Windows/System32/winevt/Logs/Security.evtx"].deleted is False

    def test_paths_are_full_and_untruncated(self) -> None:
        paths = [e.path for e in parse_fls_rows(REAL_FLS)]
        assert "Windows/System32/winevt/Logs/Security.evtx" in paths

    def test_directories_are_dropped_from_file_entries(self) -> None:
        files = fls_file_entries(REAL_FLS)
        assert not any(e.path == "Windows/System32" for e in files)
        assert any(e.path.endswith("Security.evtx") for e in files)

    def test_the_virtual_entries_survive(self) -> None:
        """v/v and V/V are not directories; icat can read them."""
        paths = [e.path for e in fls_file_entries(REAL_FLS)]
        assert "$MBR" in paths
        assert "$OrphanFiles" in paths


class TestNtfsShapes:
    def test_attribute_qualified_inodes(self) -> None:
        entries = {e.path: e for e in parse_fls_rows(NTFS_FLS)}
        system = entries["Windows/System32/config/SYSTEM"]
        assert system.inode == "4512-128-4"
        assert system.base_inode == "4512", "icat wants the inode without attributes"

    def test_a_deleted_event_log_is_found(self) -> None:
        entries = {e.path: e for e in parse_fls_rows(NTFS_FLS)}
        target = entries["Windows/System32/winevt/Logs/Security.evtx"]
        assert target.deleted is True
        assert target.base_inode == "9911"

    def test_an_unknown_name_type_is_found(self) -> None:
        """``-/r`` is how orphaned files present; ``[rd]/`` excluded them."""
        paths = [e.path for e in parse_fls_rows(NTFS_FLS)]
        assert "$OrphanFiles/Application.evtx" in paths

    def test_an_unknown_meta_type_is_found(self) -> None:
        entries = {e.path: e for e in parse_fls_rows(NTFS_FLS)}
        assert entries["Users/alice/NTUSER.DAT"].meta_type == "-"

    def test_a_symlink_is_kept(self) -> None:
        paths = [e.path for e in fls_file_entries(NTFS_FLS)]
        assert "Users/alice/link" in paths


class TestGrammarEdges:
    def test_a_path_may_contain_spaces(self) -> None:
        """The inode/path separator is a tab, which is what makes this safe."""
        text = "r/r 900:\tProgram Files/Some App/config file.ini\n"
        assert parse_fls_rows(text)[0].path == "Program Files/Some App/config file.ini"

    def test_a_path_may_contain_a_colon(self) -> None:
        text = "r/r 901:\tUsers/bob/notes:2024.txt\n"
        assert parse_fls_rows(text)[0].path == "Users/bob/notes:2024.txt"

    def test_non_fls_text_is_ignored(self) -> None:
        assert parse_fls_rows("this is not fls output\nnor is this\n") == []

    def test_empty(self) -> None:
        assert parse_fls_rows("") == []

    def test_entries_are_comparable_tuples(self) -> None:
        entry = parse_fls_rows("r/r 5:\ta.txt\n")[0]
        assert isinstance(entry, FlsEntry)
        assert entry == ("5", "a.txt", False, "r", "r")


class TestTheOldRegexWouldHaveMissedThese:
    """Pins the specific rows the previous spelling could not match."""

    MISSED = [
        "r/r * 6:\tdeleted.evtx",
        "-/r * 10233-128-1:\t$OrphanFiles/Application.evtx",
        "v/v 523203:\t$MBR",
    ]

    def test_each_is_parsed_now(self) -> None:
        for row in self.MISSED:
            entries = parse_fls_rows(row + "\n")
            assert len(entries) == 1, row

    def test_the_old_pattern_really_did_miss_them(self) -> None:
        import re

        old = re.compile(r"^[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.+)\s*$", re.IGNORECASE | re.M)
        for row in self.MISSED:
            assert old.search(row) is None, row


class TestEvtxExtractionFindsDeletedLogs:
    """The parser change has to reach the extractor that uses it."""

    FLS = (
        "d/d 646:\tWindows/System32/winevt/Logs\n"
        "r/r 710:\tWindows/System32/winevt/Logs/Security.evtx\n"
        "r/r * 9911-128-1:\tWindows/System32/winevt/Logs/Application.evtx\n"
        "-/r * 10233-128-1:\t$OrphanFiles/System.evtx\n"
    )

    def test_deleted_and_orphaned_logs_are_extracted(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        import subprocess
        from unittest.mock import patch

        from mulder.server.tools.extract import evtx as ev

        icat_calls: list[str] = []

        def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
            icat_calls.append(cmd[-1])
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"ElfFile\x00")

        with (
            patch.object(ev, "_collect_fls_chunks", return_value=[([self.FLS], 0)]),
            patch.object(ev.subprocess, "run", side_effect=fake_run),
        ):
            extracted = ev._extract_evtx_from_image("/img.raw", str(tmp_path))

        assert sorted(icat_calls) == ["10233", "710", "9911"]
        assert len(extracted) == 3
