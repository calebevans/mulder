"""Every fls-driven extractor must see deleted files.

``fls`` marks a deleted entry with a ``*`` token placed *after* the type pair
and *before* the inode::

    r/r * 22:\tWindows/System32/winevt/Logs/Deleted.evtx

Eleven copies of a row regex spelled that as ``[rd]/[rd*]`` -- treating ``*``
as a character *inside* the type pair -- so the pattern expected a digit where
the real output has ``*`` and every deleted entry failed to match. The same
spelling also restricted the type characters to ``r`` and ``d``, dropping
symlinks (``l/l``) and the virtual ``$OrphanFiles`` node (``V/V``) that holds
recovered deleted content.

The fixture below is genuine output from The Sleuth Kit 4.12.1 (``fls -r -p``)
against a purpose-built ext4 image containing two deleted files.
"""

from __future__ import annotations

import re

from mulder.patterns import FLS_ROW_RE, fls_file_entries, parse_fls_rows

#: Verbatim ``fls -r -p`` output from TSK 4.12.1.
REAL_FLS_OUTPUT = (
    "d/d 13:\tUsers\n"
    "d/d 14:\tUsers/alice\n"
    "r/r 15:\tUsers/alice/NTUSER.DAT\n"
    "r/r * 16:\tUsers/alice/capture.pcap\n"
    "l/l 17:\tUsers/alice/link_to_passwd\n"
    "d/d 11:\tlost+found\n"
    "d/d 18:\tWindows\n"
    "d/d 19:\tWindows/System32\n"
    "d/d 20:\tWindows/System32/winevt\n"
    "d/d 21:\tWindows/System32/winevt/Logs\n"
    "r/r * 22:\tWindows/System32/winevt/Logs/Deleted.evtx\n"
    "r/r 23:\tWindows/System32/winevt/Logs/Security.evtx\n"
    "r/r 24:\tWindows/System32/winevt/Logs/System.evtx\n"
    "V/V 1025:\t$OrphanFiles\n"
)

#: The regex spelling this fix replaces, kept so the tests can prove the bug.
OLD_ROW_RE = re.compile(
    r"^[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def test_a_deleted_file_is_parsed() -> None:
    """The bug: deleted entries were invisible to every extractor."""
    paths = {e.path for e in parse_fls_rows(REAL_FLS_OUTPUT)}

    assert "Windows/System32/winevt/Logs/Deleted.evtx" in paths
    assert "Users/alice/capture.pcap" in paths


def test_deleted_entries_are_flagged_as_deleted() -> None:
    """The ``*`` token is data, not noise -- callers may need to report it."""
    by_path = {e.path: e for e in parse_fls_rows(REAL_FLS_OUTPUT)}

    assert by_path["Windows/System32/winevt/Logs/Deleted.evtx"].deleted is True
    assert by_path["Users/alice/capture.pcap"].deleted is True
    assert by_path["Windows/System32/winevt/Logs/Security.evtx"].deleted is False


def test_the_old_spelling_really_did_miss_them() -> None:
    """Pins the premise: this is what the eleven copies actually did.

    If this ever fails, the bug being fixed was not the bug described.
    """
    old_paths = {m.group(2).strip() for m in OLD_ROW_RE.finditer(REAL_FLS_OUTPUT)}

    assert "Windows/System32/winevt/Logs/Deleted.evtx" not in old_paths
    assert "Users/alice/capture.pcap" not in old_paths
    # ...while the undeleted sibling in the same directory matched fine,
    # which is why the loss was silent.
    assert "Windows/System32/winevt/Logs/Security.evtx" in old_paths


def test_non_rd_type_characters_are_parsed() -> None:
    """Symlinks and the virtual $OrphanFiles node were dropped by ``[rd]``."""
    by_path = {e.path: e for e in parse_fls_rows(REAL_FLS_OUTPUT)}

    assert by_path["Users/alice/link_to_passwd"].meta_type == "l"
    assert by_path["$OrphanFiles"].meta_type == "V"


def test_every_row_of_real_output_is_parsed() -> None:
    """No row of genuine TSK output may be silently skipped."""
    expected = {line.split(":\t", 1)[1] for line in REAL_FLS_OUTPUT.splitlines()}
    got = {e.path for e in parse_fls_rows(REAL_FLS_OUTPUT)}

    assert got == expected


def test_directories_are_dropped_from_file_entries() -> None:
    """``fls_file_entries`` is the extractor-facing view: content only."""
    entries = fls_file_entries(REAL_FLS_OUTPUT)
    paths = {e.path for e in entries}

    assert "Users/alice/NTUSER.DAT" in paths
    assert "Windows/System32/winevt/Logs/Deleted.evtx" in paths
    assert "Windows/System32/winevt/Logs" not in paths
    assert "Users" not in paths


def test_ntfs_attribute_inodes_are_reduced_for_icat() -> None:
    """NTFS inodes print as ``inode-type-id``; ``icat`` wants the base."""
    ntfs = "r/r * 6083-128-1:\tUsers/bob/secret.docx\n"
    (entry,) = parse_fls_rows(ntfs)

    assert entry.inode == "6083-128-1"
    assert entry.base_inode == "6083"
    assert entry.deleted is True


def test_a_path_containing_spaces_survives() -> None:
    """The inode/path separator is a tab, so spaces in names are safe."""
    row = "r/r 42:\tDocuments and Settings/All Users/My Notes.txt\n"
    (entry,) = parse_fls_rows(row)

    assert entry.path == "Documents and Settings/All Users/My Notes.txt"


def test_the_parser_does_not_over_match() -> None:
    """Narrowness: prose and bodyfile lines must not be read as entries."""
    noise = (
        "Processing image /evidence/disk.dd\n"
        "0|/Users/alice|15|r/rrwxrwxrwx|0|0|1024|1700000000\n"
        "r/r not-an-inode:\tnope\n"
        "\n"
    )

    assert parse_fls_rows(noise) == []


def test_fls_row_re_is_multiline() -> None:
    """The parser is handed multi-row chunks, not single lines."""
    assert FLS_ROW_RE.flags & re.MULTILINE
