"""A ``CaseDB`` that was opened, then failed a query, was never closed.

``CaseDB.open`` starts a daemon writer thread (``db-writer``) and holds a
SQLAlchemy engine. Two call sites released it with a trailing ``close()``
*inside* the same ``try`` as the queries::

    db = CaseDB.open(cid, cfg.db_dir)
    meta = db.get_case_metadata()      # <- raises
    count = db.get_source_count()
    ...
    db.close()                          # <- never reached

The failure the ``except`` was written for -- a corrupt database, a schema
older than the migrations -- is exactly the path that skips the close. Because
the exception is caught and turned into a per-case ``error`` entry, the tool
reports ``status: success`` and the caller has no reason to stop calling it, so
the leak accumulates: one thread and one engine per unreadable case, per call.

Measured before the fix, with three cases on disk and metadata reads raising:

    writer threads before: 0
    writer threads after : 3
"""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.db import CaseDB


def _writer_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "db-writer"]


@pytest.fixture
def case_dir(tmp_path: Path) -> Path:
    """Three real case databases, closed again."""
    db_dir = tmp_path / "cases"
    db_dir.mkdir()
    for cid in ("case-a", "case-b", "case-c"):
        CaseDB.create(cid, str(tmp_path / "evidence"), db_dir).close()
    return db_dir


@pytest.fixture
def initialised(case_dir: Path):
    from mulder.server.app import init_server

    init_server(db_dir=case_dir)
    return case_dir


def _boom(self: CaseDB) -> None:
    raise RuntimeError("schema drift: no such column: ingested_at")


class TestListCases:
    def test_a_failing_case_does_not_leak_a_writer_thread(self, initialised: Path) -> None:
        from mulder.server.tools.case import list_cases

        before = len(_writer_threads())
        with patch.object(CaseDB, "get_case_metadata", _boom):
            result = list_cases.__wrapped__()  # type: ignore[attr-defined]

        assert len(_writer_threads()) == before

        # The premise: the failure path really was taken for every case.
        assert [c.get("case_id") for c in result["results"]] == [  # type: ignore[index]
            "case-a",
            "case-b",
            "case-c",
        ]
        assert all("error" in c for c in result["results"])  # type: ignore[union-attr]

    def test_the_healthy_path_still_reports_the_cases(self, initialised: Path) -> None:
        from mulder.server.tools.case import list_cases

        before = len(_writer_threads())
        result = list_cases.__wrapped__()  # type: ignore[attr-defined]

        assert len(_writer_threads()) == before
        assert result["result_count"] == 3
        assert all("error" not in c for c in result["results"])  # type: ignore[union-attr]

    def test_the_leak_scales_with_the_number_of_cases(self, initialised: Path) -> None:
        """Two calls over three cases would have leaked six threads."""
        from mulder.server.tools.case import list_cases

        before = len(_writer_threads())
        with patch.object(CaseDB, "get_case_metadata", _boom):
            list_cases.__wrapped__()  # type: ignore[attr-defined]
            list_cases.__wrapped__()  # type: ignore[attr-defined]

        assert len(_writer_threads()) == before


class TestOpenExistingCase:
    def test_a_failing_query_does_not_leak(self, case_dir: Path) -> None:
        """app.py had the same shape: opened, queried, closed in one try."""
        from mulder.server.app import _try_open_existing

        before = len(_writer_threads())
        with patch.object(CaseDB, "get_case_metadata", _boom):
            result = _try_open_existing("case-a", str(case_dir / "ev"), False, case_dir)

        assert len(_writer_threads()) == before
        assert isinstance(result, dict)
        assert result["error_type"] == "database_error"

    def test_a_missing_database_is_unaffected(self, case_dir: Path) -> None:
        """CaseDB.open itself raised, so there is nothing to close."""
        from mulder.server.app import _try_open_existing

        before = len(_writer_threads())
        result = _try_open_existing("no-such-case", str(case_dir / "ev"), False, case_dir)

        assert len(_writer_threads()) == before
        assert isinstance(result, dict)
        assert result["error_type"] == "database_error"
