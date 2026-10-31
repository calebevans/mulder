"""Table names read from an evidence database must be quoted as identifiers.

``decrypt_app_data`` lists the tables in every SQLite file it finds and
dumps the first rows of each with ``SELECT * FROM [<name>]``. The names come
from the evidence's own ``sqlite_master``, and a bracket identifier ends at
the first ``]``, so a table called ``t] UNION SELECT ...`` turned into extra
SQL and a table called ``x]y`` could not be read at all. Names are now
quoted the standard way: wrapped in ``"`` with any embedded ``"`` doubled.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

from mulder.server.tools.phone import decrypt_app_data

_INJECTED = "t] UNION SELECT 'INJECTED' --"


def _output(app_dir: Path) -> str:
    """Run the tool and return the text it would have indexed."""
    indexed: list[str] = []

    def _record(text: str, *_: object, **__: object) -> dict[str, object]:
        indexed.append(text)
        return {"status": "success"}

    with patch("mulder.server.tools.phone.extract_and_index", side_effect=_record):
        decrypt_app_data.__wrapped__(str(app_dir))  # type: ignore[attr-defined]
    assert indexed, "nothing was indexed"
    return indexed[0]


def _make_db(db_path: Path, tables: dict[str, str]) -> None:
    conn = sqlite3.connect(db_path)
    for name, value in tables.items():
        quoted = '"' + name.replace('"', '""') + '"'
        conn.execute(f"CREATE TABLE {quoted} (v TEXT)")
        conn.execute(f"INSERT INTO {quoted} VALUES (?)", (value,))
    conn.commit()
    conn.close()


def test_bracket_in_table_name_does_not_extend_the_query(tmp_path: Path) -> None:
    """A ``]`` in a table name must not let the rest of the name run as SQL."""
    _make_db(tmp_path / "app.db", {"t": "plain-row", _INJECTED: "crafted-row"})

    out = _output(tmp_path)

    assert "crafted-row" in out
    # The literal only appears inside the table name, never as a row value.
    assert "INJECTED" not in out.replace(_INJECTED, "")


def test_table_names_with_quote_characters_are_read(tmp_path: Path) -> None:
    """Names containing ``]`` or ``"`` are read like any other table."""
    _make_db(tmp_path / "app.db", {"x]y": "bracket-row", 'a"b': "quote-row"})

    out = _output(tmp_path)

    assert "bracket-row" in out
    assert "quote-row" in out


def test_evidence_db_is_not_modified(tmp_path: Path) -> None:
    """The evidence database is opened read-only and left untouched."""
    db_path = tmp_path / "app.db"
    _make_db(db_path, {"t": "plain-row", _INJECTED: "crafted-row"})
    before = db_path.read_bytes()

    _output(tmp_path)

    assert db_path.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["app.db"]
