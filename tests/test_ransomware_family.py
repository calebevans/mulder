"""Offline ransomware family hints: lookups that rank families and never name one."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server import app
from mulder.server.tools.composite import ransomware_family
from mulder.server.tools.composite.ransomware_family import (
    family_hints,
    is_known_note_name,
    ransomware_family_hints,
)

NOTE = (
    "Your network has been breached and all data was encrypted. Personal data, financial "
    "reports and important documents are ready to disclose. To decrypt all the data and "
    "to prevent exfiltrated files from being disclosed you will need to purchase our "
    "decryption software. Please contact our sales department at the address below. "
    "Do not rename the encrypted files or try to decrypt them with third party tools."
)


@pytest.fixture
def corpus(asset_root: Path) -> Path:
    """A small corpus laid out like ThreatLabz/ransomware_notes."""
    root = asset_root / "ransomware-notes"
    for family, name, text in (
        ("alphalock", "[rand].README_TO_RESTORE.txt", NOTE),
        ("alphalock", "second.txt", NOTE.replace("sales", "support")),
        (
            "betacrypt",
            "HOW_TO_RECOVER_DATA.html",
            "<html>" + NOTE[:200] + " pay us in monero</html>",
        ),
        ("gamma", "readme.txt", "gamma has your files. " * 30),
        ("delta", "note.bin", "binary\x00note " * 30),
    ):
        (root / family).mkdir(parents=True, exist_ok=True)
        (root / family / name).write_text(text)
    (root / "README.md").write_text("This is a collection of ransomware notes.")
    return root


def hints(**kwargs: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = family_hints(**kwargs)["hints"]  # type: ignore[assignment]
    return found


def test_an_extension_is_looked_up_case_insensitively_with_or_without_the_dot() -> None:
    for spelling in (".WNCRY", "wncry", " .wncry "):
        (hint,) = hints(extension=spelling)
        assert (hint["family"], hint["basis"], hint["score"]) == ("WannaCry", "extension", 0.5)
        assert "*.wncry" in hint["detail"]


def test_an_extension_many_families_share_scores_lower() -> None:
    (hint,) = hints(extension=".encrypted")

    assert "Others" in hint["family"]
    assert hint["score"] == 0.3


def test_an_unknown_extension_gives_no_hint_and_says_what_a_hint_is() -> None:
    result = family_hints(extension=".docx")

    assert result["hints"] == []
    assert "not a probability" in str(result["caveat"])
    assert "not the family" in str(result["caveat"])


def test_wildcards_in_the_tables_match_only_as_wildcards() -> None:
    assert is_known_note_name("@Please_Read_Me@.txt")
    assert is_known_note_name("xx-README_DECRYPT_HYDRA_ID_99.TXT") is False
    assert is_known_note_name("README_DECRYPT_HYDRA_ID_99.txt")
    assert is_known_note_name("_H_e_l_p_RECOVER_INSTRUCTIONS+abc.txt")
    # "+" and "." in a table row are literal, not regular expression syntax.
    assert is_known_note_name("_H_e_l_p_RECOVER_INSTRUCTIONSSSabcXtxt") is False
    assert is_known_note_name("notes.txt") is False
    assert is_known_note_name("") is False


def test_note_text_is_matched_to_the_closest_note_of_each_family(corpus: Path) -> None:
    victim_copy = NOTE.replace("sales department", "sales department (case 4471-A, Contoso)")

    found = hints(note_text=victim_copy)

    # betacrypt reuses the opening of the same template, as real families do:
    # it is listed, one hint per family, below the closer match.
    assert [h["family"] for h in found] == ["alphalock", "betacrypt"]
    assert {h["basis"] for h in found} == {"note_text"}
    assert found[0]["score"] > 0.9 > found[1]["score"] >= 0.4
    assert "alphalock/[rand].README_TO_RESTORE.txt" in found[0]["detail"]


def test_unrelated_or_short_text_is_not_compared_into_a_hint(corpus: Path) -> None:
    assert hints(note_text="Quarterly results were strong across all regions. " * 20) == []
    short = family_hints(note_text="files encrypted pay now")
    assert short["hints"] == [] and "fewer than" in str(short["note_text"])


def test_a_note_name_matches_corpus_names_with_placeholders_but_not_generic_ones(
    corpus: Path,
) -> None:
    (hint,) = hints(note_name="a8f3c1.README_TO_RESTORE.txt")
    assert (hint["family"], hint["basis"], hint["score"]) == ("alphalock", "note_name", 0.4)
    assert "name only" in hint["detail"]
    # "readme.txt" is in the corpus under one family and is nobody's name.
    assert hints(note_name="readme.txt") == []
    assert family_hints(note_name="HELP_DECRYPT.TXT")["known_note_name"] is True


def test_hints_are_ranked_and_capped(corpus: Path) -> None:
    found = hints(extension=".locked", note_name="x.README_TO_RESTORE.txt", note_text=NOTE)

    assert [h["basis"] for h in found] == ["note_text", "note_text", "note_name", "extension"]
    assert [h["score"] for h in found] == sorted((h["score"] for h in found), reverse=True)
    assert len(found) <= 5


def test_a_missing_corpus_is_said_not_silently_skipped(asset_root: Path) -> None:
    result = family_hints(extension=".wncry", note_text=NOTE)

    assert [h["basis"] for h in hints(extension=".wncry", note_text=NOTE)] == ["extension"]
    assert "not installed" in str(result["corpus"])


def test_the_corpus_reader_skips_binary_files_links_and_oversized_reads(
    corpus: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text(NOTE)
    (corpus / "alphalock" / "link.txt").symlink_to(outside)
    (corpus / "linked-family").symlink_to(tmp_path)
    (corpus / "alphalock" / "huge.txt").write_text("word " * 100_000)
    ransomware_family._corpus.cache_clear()

    notes = {(family, name): words for family, name, words in ransomware_family._corpus()}

    assert ("delta", "note.bin") not in notes
    assert ("alphalock", "link.txt") not in notes
    assert not any(family == "linked-family" for family, _name in notes)
    assert len(notes[("alphalock", "huge.txt")]) <= 64 * 1024 // 5 + 1


def test_the_tool_needs_an_input_and_is_audited(
    tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    call = ransomware_family_hints.__wrapped__  # type: ignore[attr-defined]

    empty = call()
    found = call(extension=".wncry")

    assert empty["status"] == "error" and empty["error_type"] == "invalid_argument"
    assert found["status"] == "success" and found["hints"][0]["family"] == "WannaCry"
    assert tmp_audit_log.has_tool_call(found["tool_call_id"])
