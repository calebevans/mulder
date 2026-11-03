"""Regression tests for phone databases that are found but cannot be read."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server import app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools import phone  # noqa: F401 ensure tools are registered

SMS = "com.android.providers.telephony/databases/mmssms.db"
WHATSAPP = "com.whatsapp/databases/msgstore.db"
SIGNAL = "org.thoughtcrime.securesms/databases/signal.db"
SMS_FILE_ID = "3d0d7e5fb2ce288813306e4d4636395e047a3d28"


@pytest.fixture()
def ctx(tmp_path: Path) -> Iterator[MagicMock]:
    case_db = CaseDB.create(case_id="phone", evidence_root=str(tmp_path), db_dir=tmp_path)
    context = MagicMock(db=case_db, audit=AuditLog(tmp_path / "phone.audit.jsonl"))
    with patch.object(app, "_ctx", context):
        yield context
    case_db.close()


def _db(path: Path, ddl: str, rows: list[tuple[Any, ...]] | None = None, insert: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(ddl)
    if rows:
        conn.executemany(insert, rows)
    conn.commit()
    conn.close()


def _sms(root: Path, rows: list[tuple[Any, ...]] | None = None) -> None:
    _db(
        root / SMS,
        "CREATE TABLE sms(address TEXT, body TEXT, date INTEGER, type INTEGER);",
        [("+821012345678", "meet at 5", 1700000000000, 1)] if rows is None else rows,
        "INSERT INTO sms VALUES (?,?,?,?)",
    )


def _whatsapp_without_messages_table(root: Path) -> None:
    _db(
        root / WHATSAPP,
        "CREATE TABLE message(_id INTEGER PRIMARY KEY, text_data TEXT, timestamp INTEGER);",
        [(1, "delete this", 1700000300000)],
        "INSERT INTO message VALUES (?,?,?)",
    )


def _unreadable_signal(root: Path) -> None:
    (root / SIGNAL).parent.mkdir(parents=True, exist_ok=True)
    (root / SIGNAL).write_bytes(os.urandom(8192))


def _entry(artifact_type: str, database: str, error: str) -> dict[str, str]:
    return {"artifact_type": artifact_type, "database": database, "error": error}


WHATSAPP_ENTRY = _entry("whatsapp", "msgstore.db", "no such table: messages")
SIGNAL_ENTRY = _entry("signal", "signal.db", "file is not a database")
VOICEMAIL_ENTRY = _entry("voicemail", "voicemail.db", "file is not a database")


def _android(root: Path, **kwargs: Any) -> dict[str, Any]:
    result: dict[str, Any] = _tool_dispatch_sync["parse_android_artifacts"](
        evidence_path=str(root), **kwargs
    )
    return result


def _ios(root: Path, **kwargs: Any) -> dict[str, Any]:
    result: dict[str, Any] = _tool_dispatch_sync["parse_ios_artifacts"](
        evidence_path=str(root), **kwargs
    )
    return result


def _in_preview(result: dict[str, Any], entry: dict[str, str]) -> bool:
    return json.dumps(entry) in str(result["preview"])


def _audit_status(ctx: MagicMock, result: dict[str, Any]) -> object:
    entry = ctx.audit.get_tool_call(result["tool_call_id"])
    assert entry is not None
    return entry.get("status")


class TestAndroid:
    def test_unreadable_databases_are_listed_next_to_the_parsed_ones(
        self, ctx: MagicMock, tmp_path: Path
    ) -> None:
        _sms(tmp_path)
        _whatsapp_without_messages_table(tmp_path)
        _unreadable_signal(tmp_path)

        result = _android(tmp_path)

        assert result["status"] == "success"
        assert '"parsed_types": ["sms"]' in str(result["preview"])
        assert '"unreadable_count": 2' in str(result["preview"])
        assert _in_preview(result, WHATSAPP_ENTRY)
        assert _in_preview(result, SIGNAL_ENTRY)
        windows = ctx.db.get_windows_by_source("phone.android")
        assert "meet at 5" in "".join(w.raw_text for w in windows)

    def test_a_run_that_could_read_none_of_its_databases_is_an_error(
        self, ctx: MagicMock, tmp_path: Path
    ) -> None:
        _whatsapp_without_messages_table(tmp_path)

        result = _android(tmp_path, artifact_types=["whatsapp"])

        assert result["status"] == "error"
        assert result["error_type"] == "database_unreadable"
        assert result["unreadable_databases"] == [WHATSAPP_ENTRY]
        assert _audit_status(ctx, result) == "error"

    def test_an_empty_database_next_to_an_unreadable_one_is_no_artifacts(
        self, ctx: MagicMock, tmp_path: Path
    ) -> None:
        _sms(tmp_path, rows=[])
        _whatsapp_without_messages_table(tmp_path)

        result = _android(tmp_path, artifact_types=["sms", "whatsapp"])

        assert result["status"] == "success"
        assert "No Android artifacts found" in str(result["preview"])
        assert '"unreadable_count": 1' in str(result["preview"])
        assert _in_preview(result, WHATSAPP_ENTRY)
        assert _audit_status(ctx, result) is None

    def test_unreadable_databases_are_counted(self, ctx: MagicMock, tmp_path: Path) -> None:
        _sms(tmp_path)
        for i in range(8):
            _whatsapp_without_messages_table(tmp_path / f"user{i}")

        result = _android(tmp_path)

        assert result["status"] == "success"
        assert '"unreadable_count": 8' in str(result["preview"])

    def test_no_database_is_still_no_artifacts(self, ctx: MagicMock, tmp_path: Path) -> None:
        result = _android(tmp_path)

        assert result["status"] == "success"
        assert "No Android artifacts found" in str(result["preview"])
        assert _audit_status(ctx, result) is None

    def test_a_readable_database_with_no_rows_is_still_no_artifacts(
        self, ctx: MagicMock, tmp_path: Path
    ) -> None:
        _sms(tmp_path, rows=[])

        result = _android(tmp_path, artifact_types=["sms"])

        assert result["status"] == "success"
        assert "No Android artifacts found" in str(result["preview"])
        assert "unreadable" not in str(result["preview"])


class TestIos:
    def test_a_notes_database_with_another_schema_is_an_error(
        self, ctx: MagicMock, tmp_path: Path
    ) -> None:
        _db(
            tmp_path / "NoteStore.sqlite",
            "CREATE TABLE ZICCLOUDSYNCINGOBJECT(Z_PK INTEGER PRIMARY KEY, ZTITLE1 TEXT);",
        )

        result = _ios(tmp_path, artifact_types=["notes"])

        assert result["status"] == "error"
        assert result["error_type"] == "database_unreadable"
        assert result["unreadable_databases"] == [
            _entry("notes", "NoteStore.sqlite", "no such table: ZSFNOTE")
        ]

    def test_a_backup_database_found_through_the_manifest_is_reported(
        self, ctx: MagicMock, tmp_path: Path
    ) -> None:
        _db(
            tmp_path / "Manifest.db",
            "CREATE TABLE Files(fileID TEXT, relativePath TEXT, domain TEXT);",
            [(SMS_FILE_ID, "Library/SMS/sms.db", "HomeDomain")],
            "INSERT INTO Files VALUES (?,?,?)",
        )
        _db(tmp_path / SMS_FILE_ID[:2] / SMS_FILE_ID, "CREATE TABLE chat(guid TEXT);")

        result = _ios(tmp_path, artifact_types=["sms"])

        assert result["status"] == "error"
        assert result["unreadable_databases"] == [
            _entry("sms", "sms.db", "no such table: message")
        ]

    def test_an_unreadable_manifest_is_reported(self, ctx: MagicMock, tmp_path: Path) -> None:
        (tmp_path / "Manifest.db").write_bytes(os.urandom(4096))
        _db(tmp_path / SMS_FILE_ID[:2] / SMS_FILE_ID, "CREATE TABLE message(text TEXT);")

        result = _ios(tmp_path, artifact_types=["sms"])

        assert result["status"] == "error"
        assert result["error_type"] == "database_unreadable"
        assert result["unreadable_databases"] == [
            _entry("manifest", "Manifest.db", "file is not a database")
        ]

    def test_unreadable_databases_are_listed_next_to_the_parsed_ones(
        self, ctx: MagicMock, tmp_path: Path
    ) -> None:
        _db(
            tmp_path / "call_history.db",
            "CREATE TABLE call(address TEXT, duration INTEGER, date REAL, flags INTEGER);",
            [("+821012345678", 42, 700000000.0, 4)],
            "INSERT INTO call VALUES (?,?,?,?)",
        )
        (tmp_path / "voicemail.db").write_bytes(os.urandom(4096))

        result = _ios(tmp_path, artifact_types=["calls", "voicemail"])

        assert result["status"] == "success"
        assert '"parsed_types": ["calls"]' in str(result["preview"])
        assert _in_preview(result, VOICEMAIL_ENTRY)

    def test_an_empty_database_next_to_an_unreadable_one_is_no_artifacts(
        self, ctx: MagicMock, tmp_path: Path
    ) -> None:
        _db(
            tmp_path / "call_history.db",
            "CREATE TABLE call(address TEXT, duration INTEGER, date REAL, flags INTEGER);",
        )
        (tmp_path / "voicemail.db").write_bytes(os.urandom(4096))

        result = _ios(tmp_path, artifact_types=["calls", "voicemail"])

        assert result["status"] == "success"
        assert "No iOS artifacts found" in str(result["preview"])
        assert _in_preview(result, VOICEMAIL_ENTRY)
        assert _audit_status(ctx, result) is None

    def test_no_database_is_still_no_artifacts(self, ctx: MagicMock, tmp_path: Path) -> None:
        result = _ios(tmp_path)

        assert result["status"] == "success"
        assert "No iOS artifacts found" in str(result["preview"])


class _FakeSqlcipherError(Exception):
    pass


class _FakeCursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows
        self.description = [("body",)]

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


class _FakeSqlcipherConnection:
    def __init__(self, tables: bool) -> None:
        self._tables = tables

    def execute(self, sql: str) -> _FakeCursor:
        if "sqlite_master" in sql:
            return _FakeCursor([("message",)] if self._tables else [])
        return _FakeCursor([("secret plan",)])

    def close(self) -> None:
        pass


def _sqlcipher(monkeypatch: pytest.MonkeyPatch, **by_name: str) -> None:
    """Stand in for pysqlcipher3; each database stem maps to "data", "empty" or "fails"."""

    def connect(path: str) -> _FakeSqlcipherConnection:
        behaviour = by_name[Path(path).stem]
        if behaviour == "fails":
            raise _FakeSqlcipherError("file is not a database")
        return _FakeSqlcipherConnection(tables=behaviour == "data")

    dbapi2 = types.SimpleNamespace(connect=connect, Error=_FakeSqlcipherError)
    monkeypatch.setitem(sys.modules, "pysqlcipher3", types.SimpleNamespace(dbapi2=dbapi2))


def _no_sqlcipher(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "pysqlcipher3", None)


def _encrypted_db(root: Path, name: str = "messages.db") -> None:
    (root / "databases").mkdir(parents=True, exist_ok=True)
    (root / "databases" / name).write_bytes(os.urandom(8192))


MESSAGES_WITHOUT_SQLCIPHER = {
    "database": "messages.db",
    "error": "file is not a database; pysqlcipher3 is not installed",
}


def _decrypt(root: Path, **kwargs: Any) -> dict[str, Any]:
    result: dict[str, Any] = _tool_dispatch_sync["decrypt_app_data"](
        app_data_path=str(root), **kwargs
    )
    return result


class TestDecryptAppData:
    def test_a_database_that_needs_the_missing_sqlcipher_module_is_an_error(
        self, ctx: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _no_sqlcipher(monkeypatch)
        _encrypted_db(tmp_path / "app")

        result = _decrypt(tmp_path / "app")

        assert result["status"] == "error"
        assert result["error_type"] == "database_unreadable"
        assert result["unreadable_databases"] == [MESSAGES_WITHOUT_SQLCIPHER]
        assert _audit_status(ctx, result) == "error"

    def test_a_database_no_password_opens_is_an_error(
        self, ctx: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _sqlcipher(monkeypatch, messages="fails")
        _encrypted_db(tmp_path / "app")

        result = _decrypt(tmp_path / "app", known_passwords=["hunter2"])

        assert result["status"] == "error"
        assert result["unreadable_databases"] == [
            {
                "database": "messages.db",
                "error": "file is not a database; SQLCipher could not open it with 2 password(s)",
            }
        ]

    def test_a_decrypted_database_is_parsed(
        self, ctx: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _sqlcipher(monkeypatch, messages="data")
        _encrypted_db(tmp_path / "app")

        result = _decrypt(tmp_path / "app")

        assert result["status"] == "success"
        assert '"encrypted_dbs_decrypted": 1' in str(result["preview"])
        assert "unreadable" not in str(result["preview"])

    def test_unreadable_databases_are_listed_next_to_a_readable_one(
        self, ctx: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _no_sqlcipher(monkeypatch)
        _encrypted_db(tmp_path / "app")
        _db(
            tmp_path / "app" / "databases" / "settings.db",
            "CREATE TABLE prefs(key TEXT, value TEXT);",
            [("theme", "dark")],
            "INSERT INTO prefs VALUES (?,?)",
        )

        result = _decrypt(tmp_path / "app")

        assert result["status"] == "success"
        assert '"plaintext_dbs_found": 1' in str(result["preview"])
        assert '"unreadable_count": 1' in str(result["preview"])
        assert _in_preview(result, MESSAGES_WITHOUT_SQLCIPHER)

    def test_an_empty_database_next_to_an_unreadable_one_is_no_results(
        self, ctx: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _no_sqlcipher(monkeypatch)
        _encrypted_db(tmp_path / "app")
        _db(tmp_path / "app" / "databases" / "empty.db", "CREATE TABLE t(x TEXT); DROP TABLE t;")

        result = _decrypt(tmp_path / "app")

        assert result["status"] == "success"
        assert "No parseable data found" in str(result["preview"])
        assert '"unreadable_count": 1' in str(result["preview"])
        assert _audit_status(ctx, result) is None

    def test_an_empty_decrypted_database_is_no_results(
        self, ctx: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _sqlcipher(monkeypatch, vault="empty")
        _encrypted_db(tmp_path / "app", "vault.db")

        result = _decrypt(tmp_path / "app")

        assert result["status"] == "success"
        assert "No parseable data found" in str(result["preview"])
        assert "unreadable" not in str(result["preview"])
        assert _audit_status(ctx, result) is None

    def test_an_empty_decrypted_database_next_to_an_unreadable_one_is_no_results(
        self, ctx: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _sqlcipher(monkeypatch, vault="empty", messages="fails")
        _encrypted_db(tmp_path / "app", "vault.db")
        _encrypted_db(tmp_path / "app")

        result = _decrypt(tmp_path / "app")

        assert result["status"] == "success"
        assert "No parseable data found" in str(result["preview"])
        assert _in_preview(
            result,
            {
                "database": "messages.db",
                "error": "file is not a database; SQLCipher could not open it with 1 password(s)",
            },
        )

    def test_a_folder_without_databases_is_still_no_results(
        self, ctx: MagicMock, tmp_path: Path
    ) -> None:
        (tmp_path / "app").mkdir()

        result = _decrypt(tmp_path / "app")

        assert result["status"] == "success"
        assert "No parseable data found" in str(result["preview"])
        assert "unreadable" not in str(result["preview"])
