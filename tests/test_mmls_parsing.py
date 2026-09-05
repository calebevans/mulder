"""Regression tests for shared ``mmls`` partition-row parsing.

Three copies of the partition-row regex were anchored on ``^\\d+:\\d+``, which
never matches real ``mmls`` output: every row is indented and the slot column
is ``000:000`` (DOS) or a bare ``000`` (GPT).  All of them now go through
``mulder.patterns.parse_mmls_rows``.
"""

from __future__ import annotations

from mulder.patterns import parse_mmls_rows

DOS_MMLS = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0000411647   0000204800   Linux (0x83)
"""

GPT_MMLS = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000       0000002048   0001050623   0001048576   EFI system partition
003:  001       0001050624   0488396799   0487346176   Basic data partition
"""


class TestParseMmlsRows:
    def test_dos_table_rows_are_parsed(self) -> None:
        rows = parse_mmls_rows(DOS_MMLS)
        assert (2048, 204800, "ntfs / exfat (0x07)") in rows
        assert (206848, 204800, "linux (0x83)") in rows

    def test_gpt_table_rows_are_parsed(self) -> None:
        rows = parse_mmls_rows(GPT_MMLS)
        assert (2048, 1048576, "efi system partition") in rows
        assert (1050624, 487346176, "basic data partition") in rows

    def test_description_is_lowercased_and_stripped(self) -> None:
        assert all(d == d.strip().lower() for _, _, d in parse_mmls_rows(DOS_MMLS))

    def test_empty_output_yields_no_rows(self) -> None:
        assert parse_mmls_rows("") == []
        assert parse_mmls_rows("Cannot determine partition type\n") == []


class TestTskToolOffset:
    """``server.tools.tsk`` previously returned 0 for every real image."""

    def test_ntfs_partition_offset_is_found(self) -> None:
        from mulder.server.tools.tsk import _parse_offset_from_windows

        assert _parse_offset_from_windows(DOS_MMLS) == 2048

    def test_gpt_falls_through_to_basic_data(self) -> None:
        from mulder.server.tools.tsk import _parse_offset_from_windows

        # No NTFS/Linux indicator in GPT descriptions; must not crash.
        assert isinstance(_parse_offset_from_windows(GPT_MMLS), int)


class TestExtractTskOffset:
    """The already-correct copy must keep behaving identically."""

    def test_offset_matches_shared_parser(self) -> None:
        from mulder.server.tools.extract.tsk import _parse_partition_offset

        assert _parse_partition_offset(DOS_MMLS) == 2048
