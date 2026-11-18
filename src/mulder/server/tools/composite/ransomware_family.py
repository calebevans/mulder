"""Offline ransomware family hints from an extension, a note name or note text.

Three independent lookups, none of which identifies anything:

* extension -> family, from Splunk's ``ransomware_extensions_lookup.csv``
  (vendored under ``server/data/ransomware``);
* note file name -> family, from the file names in the ThreatLabz ransom note
  corpus (the ``ransomware-notes`` asset). Splunk's ``ransomware_notes_lookup.csv``
  has no family column, so it only says a name is a known ransom note name;
* note text -> family, by similarity to the notes in that corpus.
"""

from __future__ import annotations

import csv
import functools
import re
from difflib import SequenceMatcher
from pathlib import Path
from typing import NamedTuple

from mulder.assets.paths import asset_path, register_cache_clear
from mulder.server.app import mcp
from mulder.server.helpers import audited_tool
from mulder.server.tool_access import ANALYSTS, Role, tool_access
from mulder.server.tools.composite.core import decode_evidence_text

__all__ = ["family_hints", "is_known_note_name", "ransomware_family_hints"]

_DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "ransomware"
_NOTES_DIRNAME = "ransomware-notes"

_MAX_NAME_CHARS = 255
_MAX_HINTS = 5
_NOTE_READ_BYTES = 64 * 1024
_NOTE_MAX_WORDS = 2000
# Below this many words a note is too short to tell templates apart.
_NOTE_MIN_WORDS = 25
# Word-sequence similarity (0..1) below which a note-text match is not reported.
# On the corpus itself half of all notes score under 0.3 against every other
# family and a quarter score over 0.58, because families share templates: the
# threshold removes unrelated text, it cannot separate related families.
_NOTE_TEXT_MIN_SCORE = 0.4
# A corpus file name needs this many literal letters and digits (placeholders
# and the extension excluded) to be matched; "readme" and "note" are not names.
_NOTE_NAME_MIN_LITERAL = 8
_SCORE_EXTENSION = 0.5
_SCORE_EXTENSION_SHARED = 0.3
_SCORE_NOTE_NAME = 0.4

_WORD_RE = re.compile(r"[a-z0-9]+")
_PLACEHOLDER_RE = re.compile(r"\\\[[a-z_]+\\\]")

CAVEAT = (
    "Hints from lookup tables and note-text similarity. A score only ranks the hints; "
    "it is not a probability. Families share extensions, note names and note templates "
    "(leaked builders, rebrands), so a hint names a family to check, not the family."
)


class _Hint(NamedTuple):
    family: str
    basis: str
    score: float  # ranks hints against each other; not a probability
    detail: str


def _wildcard(pattern: str) -> re.Pattern[str]:
    """Splunk's WILDCARD match: ``*`` only, case-insensitive, whole value."""
    return re.compile(re.escape(pattern.strip()).replace(r"\*", ".*"), re.IGNORECASE | re.DOTALL)


def _read_lookup(name: str) -> list[list[str]]:
    with (_DATA_DIR / name).open(encoding="utf-8", newline="") as fh:
        return [row for row in list(csv.reader(fh))[1:] if row and row[0].strip()]


@functools.lru_cache(maxsize=1)
def _extension_table() -> tuple[tuple[re.Pattern[str], str, str], ...]:
    """``(matcher, pattern, family)`` per row of the extension lookup."""
    return tuple(
        (_wildcard(row[0]), row[0].strip(), row[1].strip())
        for row in _read_lookup("ransomware_extensions_lookup.csv")
        if len(row) > 1
    )


@functools.lru_cache(maxsize=1)
def _note_name_table() -> tuple[re.Pattern[str], ...]:
    return tuple(_wildcard(row[0]) for row in _read_lookup("ransomware_notes_lookup.csv"))


@functools.lru_cache(maxsize=1)
def _corpus() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """``(family, note file name, words)`` for every text note in the corpus asset."""
    root = asset_path(_NOTES_DIRNAME)
    if root is None:
        return ()
    notes: list[tuple[str, str, tuple[str, ...]]] = []
    for family in sorted(root.iterdir()):
        if family.is_symlink() or not family.is_dir() or family.name.startswith("."):
            continue
        for note in sorted(family.iterdir()):
            if note.is_symlink() or not note.is_file():
                continue
            try:
                with note.open("rb") as fh:
                    text = decode_evidence_text(fh.read(_NOTE_READ_BYTES))
            except OSError:
                continue
            if text:
                notes.append((family.name, note.name, tuple(_WORD_RE.findall(text.lower()))))
    return tuple(notes)


register_cache_clear(_corpus.cache_clear)


def is_known_note_name(name: str) -> bool:
    """Whether *name* matches Splunk's list of ransom note file names."""
    name = name.strip()[:_MAX_NAME_CHARS]
    return bool(name) and any(p.fullmatch(name) for p in _note_name_table())


def _extension_hints(extension: str) -> list[_Hint]:
    ext = extension.strip()[:_MAX_NAME_CHARS]
    if not ext:
        return []
    probe = "x" + (ext if ext.startswith(".") else f".{ext}")
    hints = []
    for matcher, pattern, family in _extension_table():
        if matcher.fullmatch(probe):
            shared = "/" in family or "others" in family.lower()
            score = _SCORE_EXTENSION_SHARED if shared else _SCORE_EXTENSION
            detail = f"extension matches {pattern} in the Splunk lookup"
            hints.append(_Hint(family, "extension", score, detail))
    return hints


def _note_name_hints(name: str) -> list[_Hint]:
    name = name.strip()[:_MAX_NAME_CHARS].lower()
    if not name:
        return []
    families: dict[str, str] = {}
    for family, corpus_name, _words in _corpus():
        escaped = re.escape(corpus_name.lower())
        literal = _PLACEHOLDER_RE.sub("", escaped).rsplit(r"\.", 1)[0]
        if sum(c.isalnum() for c in literal) < _NOTE_NAME_MIN_LITERAL:
            continue
        if re.fullmatch(_PLACEHOLDER_RE.sub(".+", escaped), name, re.DOTALL):
            families.setdefault(family, corpus_name)
    detail = "file name matches {} in the ThreatLabz corpus (name only)"
    return [
        _Hint(family, "note_name", _SCORE_NOTE_NAME, detail.format(corpus_name))
        for family, corpus_name in sorted(families.items())
    ]


def _note_text_hints(text: str) -> list[_Hint]:
    words = _WORD_RE.findall(text.lower())[:_NOTE_MAX_WORDS]
    if len(words) < _NOTE_MIN_WORDS:
        return []
    matcher = SequenceMatcher(None, autojunk=False)
    matcher.set_seq2(words)
    best: dict[str, tuple[float, str]] = {}
    for family, corpus_name, corpus_words in _corpus():
        matcher.set_seq1(corpus_words)
        # The two quick ratios are cheap upper bounds on ratio().
        if (
            matcher.real_quick_ratio() < _NOTE_TEXT_MIN_SCORE
            or matcher.quick_ratio() < _NOTE_TEXT_MIN_SCORE
        ):
            continue
        score = matcher.ratio()
        if score >= _NOTE_TEXT_MIN_SCORE and score > best.get(family, (0.0, ""))[0]:
            best[family] = (score, corpus_name)
    detail = "note text resembles {}/{} in the ThreatLabz corpus"
    return [
        _Hint(family, "note_text", round(score, 2), detail.format(family, corpus_name))
        for family, (score, corpus_name) in best.items()
    ]


def family_hints(
    extension: str = "", note_name: str = "", note_text: str = ""
) -> dict[str, object]:
    """Ranked family hints for whatever of the three inputs is given."""
    hints = _extension_hints(extension) + _note_name_hints(note_name) + _note_text_hints(note_text)
    hints.sort(key=lambda h: (-h.score, h.family))
    result: dict[str, object] = {
        "hints": [h._asdict() for h in hints[:_MAX_HINTS]],
        "hints_found": len(hints),
        "caveat": CAVEAT,
    }
    if note_name.strip():
        result["known_note_name"] = is_known_note_name(note_name)
    if (note_name.strip() or note_text.strip()) and not _corpus():
        result["corpus"] = (
            "The ransom note corpus is not installed (run 'mulder setup'), so note names "
            "and note text were not compared to known notes."
        )
    elif note_text.strip() and len(_WORD_RE.findall(note_text.lower())) < _NOTE_MIN_WORDS:
        result["note_text"] = f"Not compared: fewer than {_NOTE_MIN_WORDS} words."
    return result


@mcp.tool()
@tool_access(ANALYSTS | Role.CROSS_EXECUTOR)
@audited_tool("ransomware_family_hints")
def ransomware_family_hints(
    extension: str = "", note_name: str = "", note_text: str = ""
) -> dict[str, object]:
    """Suggest ransomware families for a file extension, a ransom note name or note text.

    Call when encrypted files or a ransom note were found by other means (a file
    listing, a note read from the evidence) and find_encryption_activity did
    not already give hints. Works offline from lookup tables and a corpus
    of known notes; give any of the three inputs.

    Returns ranked hints (family, basis, score, detail). A hint is a family to
    check against the malware and the attacker's tooling, never an
    identification: families share extensions, note names and note templates.
    No hint does not mean no ransomware; new and renamed families are not in
    the tables.

    Args:
        extension: Extension added to encrypted files, e.g. ".lockbit".
        note_name: File name of the ransom note.
        note_text: Text of the ransom note (the first few thousand characters).
    """
    if not (extension.strip() or note_name.strip() or note_text.strip()):
        return {
            "status": "error",
            "error_type": "invalid_argument",
            "error_message": "Give at least one of extension, note_name or note_text.",
        }
    return {"status": "success", **family_hints(extension, note_name, note_text)}
