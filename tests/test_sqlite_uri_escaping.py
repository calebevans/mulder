"""Evidence filenames were pasted into a SQLite URI without being escaped.

Every read-only connection in the tree was opened as::

    sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

``db_path`` comes out of an evidence tree, and a URI is not a string format --
``#``, ``?`` and ``%`` are syntax. Three ordinary filenames break it, each in a
different and silent way:

``sms#2024-03-12.db``
    ``#`` opens a fragment, so the path is truncated to ``sms`` and the
    ``?mode=ro`` the caller asked for is inside the discarded fragment. SQLite
    creates and opens an empty ``sms`` **in the evidence directory**, and the
    tool reports that the database has no tables -- a wrong answer about the
    wrong file, plus a write into the evidence tree.

``chat?mode=rwc.db``
    ``?`` starts the query string, so the caller's parameters are appended to
    whatever the filename contained and the connection is refused. The
    surrounding ``except sqlite3.Error`` drops the database from the analysis
    without saying so.

``report%20final.db``
    SQLite percent-decodes ``%`` followed by two hex digits, so this names
    ``report final.db`` -- a different file, and normally a missing one.
    ``100%_full.db`` is *not* affected: ``%_f`` is not a valid escape and is
    left alone. The bug is a percent sign in front of two hex digits, not any
    percent sign, and the tests below pin both directions.

These are not adversarial names. ``#`` and ``%`` appear in exported chat
databases, dated backups and app cache filenames as a matter of course. A name
chosen deliberately does more than confuse the path, though -- see
``test_a_chosen_name_reaches_mode_rwc``.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mulder.server.helpers import readonly_sqlite_uri


def _make_db(path: Path) -> None:
    """A minimal evidence database with one message in it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE message(body TEXT)")
    conn.execute("INSERT INTO message VALUES ('the evidence')")
    conn.commit()
    conn.close()


HOSTILE_NAMES = [
    "sms#2024-03-12.db",
    "chat?mode=rwc&cache=shared.db",
    "100%_full.db",
    "report%20final.db",
    "my backup.db",
    "j..smith's phone.db",
    "中文.db",
    "ordinary.db",
]


class TestThePremise:
    """What the old expression actually did, asserted rather than described."""

    def test_a_hash_truncates_the_path_and_opens_the_wrong_file(self, tmp_path: Path) -> None:
        evidence = tmp_path / "sms#2024-03-12.db"
        _make_db(evidence)

        conn = sqlite3.connect(f"file:{evidence}?mode=ro", uri=True)
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        conn.close()

        assert tables == [], "the old form did not open the evidence at all"
        assert (tmp_path / "sms").exists(), (
            "and it created an empty database inside the evidence directory"
        )

    def test_a_percent_hex_pair_is_decoded_into_a_different_path(self, tmp_path: Path) -> None:
        evidence = tmp_path / "report%20final.db"
        _make_db(evidence)

        with pytest.raises(sqlite3.Error):
            sqlite3.connect(f"file:{evidence}?mode=ro", uri=True)

    def test_a_bare_percent_was_actually_fine(self, tmp_path: Path) -> None:
        """Stated so the fix is not credited with more than it fixes.

        ``%_f`` is not a valid escape, so ``100%_full.db`` opened correctly
        under the old expression too.
        """
        evidence = tmp_path / "100%_full.db"
        _make_db(evidence)

        conn = sqlite3.connect(f"file:{evidence}?mode=ro", uri=True)
        assert [r[0] for r in conn.execute("SELECT body FROM message")] == ["the evidence"]
        conn.close()

    def test_a_chosen_name_reaches_mode_rwc(self, tmp_path: Path) -> None:
        """Why this is a security fix and not only a parsing one.

        A file named ``chat.db?mode=rwc&x=`` makes the caller's ``?mode=ro``
        land in the value of ``x``, so ``mode=rwc`` wins and the evidence is
        opened read-write.
        """
        evidence = tmp_path / "chat.db"
        _make_db(evidence)
        hostile = tmp_path / "chat.db?mode=rwc&x="

        conn = sqlite3.connect(f"file:{hostile}?mode=ro", uri=True)
        conn.execute("CREATE TABLE injected(x)")
        conn.commit()
        conn.close()

        opened = sqlite3.connect(evidence)
        tables = [r[0] for r in opened.execute("SELECT name FROM sqlite_master")]
        opened.close()
        assert "injected" in tables, "read-only was defeated and the evidence was written"

    def test_a_question_mark_makes_the_connection_fail(self, tmp_path: Path) -> None:
        evidence = tmp_path / "chat?mode=rwc&cache=shared.db"
        _make_db(evidence)

        with pytest.raises(sqlite3.Error):
            sqlite3.connect(f"file:{evidence}?mode=ro", uri=True)


class TestReadonlySqliteUri:
    @pytest.mark.parametrize("name", HOSTILE_NAMES)
    def test_the_named_file_is_the_file_that_opens(self, tmp_path: Path, name: str) -> None:
        evidence = tmp_path / name
        _make_db(evidence)
        before = sorted(p.name for p in tmp_path.iterdir())

        conn = sqlite3.connect(readonly_sqlite_uri(evidence), uri=True)
        rows = [r[0] for r in conn.execute("SELECT body FROM message")]
        conn.close()

        assert rows == ["the evidence"]
        assert sorted(p.name for p in tmp_path.iterdir()) == before, (
            "opening evidence must not create files next to it"
        )

    @pytest.mark.parametrize("name", HOSTILE_NAMES)
    def test_the_connection_is_read_only(self, tmp_path: Path, name: str) -> None:
        """mode=ro must survive the escaping, or evidence becomes writable."""
        evidence = tmp_path / name
        _make_db(evidence)

        conn = sqlite3.connect(readonly_sqlite_uri(evidence), uri=True)
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM message")
        conn.close()

    def test_a_string_path_works_too(self, tmp_path: Path) -> None:
        """Call sites pass both Path and str."""
        evidence = tmp_path / "sms#1.db"
        _make_db(evidence)

        conn = sqlite3.connect(readonly_sqlite_uri(str(evidence)), uri=True)
        assert [r[0] for r in conn.execute("SELECT body FROM message")] == ["the evidence"]
        conn.close()

    def test_a_percent_escape_is_not_decoded(self, tmp_path: Path) -> None:
        """The file named report%20final.db, not the file named 'report final.db'."""
        evidence = tmp_path / "report%20final.db"
        _make_db(evidence)
        decoy = tmp_path / "report final.db"
        _make_db(decoy)
        conn = sqlite3.connect(decoy)
        conn.execute("UPDATE message SET body = 'the wrong file'")
        conn.commit()
        conn.close()

        conn = sqlite3.connect(readonly_sqlite_uri(evidence), uri=True)
        assert [r[0] for r in conn.execute("SELECT body FROM message")] == ["the evidence"]
        conn.close()


class TestEveryCallSiteUsesIt:
    """A new read-only connection built by hand would reintroduce the bug."""

    def test_no_module_formats_a_sqlite_uri_by_hand(self) -> None:
        import mulder

        root = Path(mulder.__file__).parent
        offenders = [
            str(path.relative_to(root))
            for path in root.rglob("*.py")
            if 'sqlite3.connect(f"file:' in path.read_text()
        ]
        assert offenders == []
