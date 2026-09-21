"""``search(source=[...])`` searches any of the listed sources (#242).

``source`` was typed ``str`` and concatenated with ``".%"`` in the DB
layer, so the list a model passes through ``run_parallel`` blew up as a
``TypeError`` traceback instead of a tool error.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mulder.db import CaseDB
from mulder.models import WindowRow
from mulder.server import helpers
from mulder.server.tools import core


def _add(db: CaseDB, name: str, lines: list[str]) -> int:
    sid = db.register_source(
        source_name=name, source_path="/evidence/x", source_hash="h", extractor="t", line_count=1
    )
    db.insert_windows(
        sid,
        [
            WindowRow(
                window_id=None,
                source_id=sid,
                line_start=i,
                line_end=i,
                event_time=None,
                raw_text=t,
            )
            for i, t in enumerate(lines, 1)
        ],
    )
    return sid


@pytest.fixture
def ctx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[CaseDB]:
    db = CaseDB.create(case_id="c242", evidence_root="/evidence", db_dir=tmp_path)
    _add(db, "tsk.filelist", ["secret plan.docx", "nothing here"])
    _add(db, "registry.system", ["USBSTOR secret serial"])
    _add(db, "evtx.security", ["secret logon 4624"])

    class _Ctx:
        class audit:  # noqa: N801 - mirrors the real context's shape
            @staticmethod
            def log_tool_call(**kwargs: object) -> None:
                pass

    _Ctx.db = db  # type: ignore[attr-defined]
    monkeypatch.setattr(core, "get_ctx", lambda: _Ctx())
    monkeypatch.setattr(helpers, "get_ctx", lambda: _Ctx())  # audited_tool's copy
    yield db
    db.close()


def _search(**kwargs: Any) -> dict[str, Any]:
    resp: dict[str, Any] = core.search.__wrapped__(query="secret", **kwargs)  # type: ignore[attr-defined]
    return resp


def _sources(resp: dict[str, Any]) -> set[str]:
    return {r["source_name"] for r in resp["results"]}


@pytest.mark.parametrize("regex", [False, True])
def test_source_list_searches_any_of_them(ctx: CaseDB, regex: bool) -> None:
    resp = _search(source=["tsk.filelist", "registry.system"], regex=regex)

    assert resp["status"] == "success"
    assert resp["total_matches"] == 2
    assert _sources(resp) == {"tsk.filelist", "registry.system"}
    assert resp["source"] == ["tsk.filelist", "registry.system"]


@pytest.mark.parametrize("regex", [False, True])
def test_source_string_still_scopes(ctx: CaseDB, regex: bool) -> None:
    resp = _search(source="registry", regex=regex)

    assert resp["status"] == "success"
    assert _sources(resp) == {"registry.system"}


def test_source_list_with_evidence_path(ctx: CaseDB) -> None:
    resp = _search(source=["tsk.filelist", "evtx.security"], evidence_path="x")

    assert _sources(resp) == {"tsk.filelist", "evtx.security"}


@pytest.mark.parametrize("bad", [42, {"a": 1}, ["tsk.filelist", 7]])
def test_bad_source_type_returns_invalid_params(ctx: CaseDB, bad: object) -> None:
    resp = _search(source=bad)

    assert resp["status"] == "error"
    assert resp["error_type"] == "invalid_params"
    assert "source" in resp["error_message"]


def test_exclude_sources_string_and_bad_type(ctx: CaseDB) -> None:
    resp = _search(exclude_sources="tsk")
    assert _sources(resp) == {"registry.system", "evtx.security"}

    resp = _search(exclude_sources=42)
    assert resp["error_type"] == "invalid_params"
