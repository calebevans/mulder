"""``search(regex=True)`` without a source must scan every source (#234).

``_search_regex`` paged with ``get_windows_page("")``, whose filter
``source_name == "" OR source_name LIKE ".%"`` matches nothing, so every
unscoped regex search returned zero hits. The FTS path never went through
that filter, which is why only ``regex=True`` was affected.
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
    db = CaseDB.create(case_id="c234", evidence_root="/evidence", db_dir=tmp_path)
    _add(db, "tsk.files", ["secret_project plan", "nothing here"])
    _add(db, "reg.software", ["FileZilla installed", "WinSCP installed"])

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


PATTERN = r"secret_pr|(FileZilla|WinSCP)"


def _sources(resp: dict[str, Any]) -> set[str]:
    return {r["source_name"] for r in resp["results"]}


def test_no_source_scans_every_source(ctx: CaseDB) -> None:
    resp = core.search.__wrapped__(query=PATTERN, regex=True)  # type: ignore[attr-defined]

    assert resp["status"] == "success"
    assert resp["result_count"] == 3
    assert _sources(resp) == {"tsk.files", "reg.software"}


def test_source_scopes_hits(ctx: CaseDB) -> None:
    resp = core.search.__wrapped__(  # type: ignore[attr-defined]
        query=PATTERN, regex=True, source="reg.software"
    )

    assert resp["result_count"] == 2
    assert _sources(resp) == {"reg.software"}


def test_exclude_sources_still_applies(ctx: CaseDB) -> None:
    resp = core.search.__wrapped__(  # type: ignore[attr-defined]
        query=PATTERN, regex=True, exclude_sources=["reg"]
    )

    assert resp["result_count"] == 1
    assert _sources(resp) == {"tsk.files"}


def test_get_windows_page_no_filter(ctx: CaseDB) -> None:
    for prefix in (None, ""):
        page, total = ctx.get_windows_page(prefix)
        assert total == 4
        assert len(page) == 4
