"""Query tools must not hand one image another image's rows (#232).

Extractors register one source per image under the same name
(``tsk.masquerade`` for RM1 and for RM2), told apart only by
``source_path``. ``get_raw_output`` and ``search`` resolved by name alone,
so on the v1.5.2 NDLC run the RM1 analyst read RM2's FAT32 masquerade rows
and reported them as RM1's.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from mulder.db import CaseDB
from mulder.models import WindowRow
from mulder.server import helpers
from mulder.server.tools import core

RM1 = "/evidence/rm1.E01"
RM2 = "/evidence/rm2.E01"


def _add(db: CaseDB, name: str, path: str, lines: list[str]) -> int:
    sid = db.register_source(
        source_name=name, source_path=path, source_hash="h", extractor="tsk", line_count=len(lines)
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
    db = CaseDB.create(case_id="c232", evidence_root="/evidence", db_dir=tmp_path)
    _add(db, "tsk.masquerade", RM1, ["rm1 masquerade row"])
    _add(db, "tsk.masquerade", RM2, ["rm2 masquerade row one", "rm2 masquerade row two"])
    _add(db, "tsk.fsstat", RM1, ["rm1 fsstat exFAT"])

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


class TestGetRawOutput:
    def test_evidence_path_returns_only_that_image(self, ctx: CaseDB) -> None:
        resp = core.get_raw_output.__wrapped__(  # type: ignore[attr-defined]
            "tsk.masquerade", evidence_path=RM2
        )

        assert resp["status"] == "success"
        assert resp["total_windows"] == 2
        assert "rm1" not in str(resp["raw_text"])
        assert resp["source_paths"] == [RM2]

    def test_basename_matches_too(self, ctx: CaseDB) -> None:
        resp = core.get_raw_output.__wrapped__(  # type: ignore[attr-defined]
            "tsk.masquerade", evidence_path="rm1.E01"
        )

        assert resp["status"] == "success"
        assert resp["raw_text"] == "rm1 masquerade row"

    def test_ambiguous_name_is_an_error_not_a_mix(self, ctx: CaseDB) -> None:
        resp = core.get_raw_output.__wrapped__(  # type: ignore[attr-defined]
            "tsk.masquerade"
        )

        assert resp["status"] == "error"
        assert resp["source_paths"] == [RM1, RM2]
        assert "evidence_path" in str(resp["error_message"])
        assert "raw_text" not in resp

    def test_single_image_name_needs_no_evidence_path(self, ctx: CaseDB) -> None:
        resp = core.get_raw_output.__wrapped__(  # type: ignore[attr-defined]
            "tsk.fsstat"
        )

        assert resp["status"] == "success"
        assert resp["raw_text"] == "rm1 fsstat exFAT"

    def test_unknown_evidence_path_is_an_error(self, ctx: CaseDB) -> None:
        resp = core.get_raw_output.__wrapped__(  # type: ignore[attr-defined]
            "tsk.masquerade", evidence_path="/evidence/rm3.E01"
        )

        assert resp["status"] == "error"


class TestSearch:
    def test_hits_carry_source_path(self, ctx: CaseDB) -> None:
        resp = core.search.__wrapped__(  # type: ignore[attr-defined]
            query="masquerade", source="tsk.masquerade"
        )

        assert resp["result_count"] == 3
        assert {r["source_path"] for r in resp["results"]} == {RM1, RM2}

    @pytest.mark.parametrize("regex", [False, True])
    def test_evidence_path_scopes_hits(self, ctx: CaseDB, regex: bool) -> None:
        resp = core.search.__wrapped__(  # type: ignore[attr-defined]
            query="masquerade", source="tsk.masquerade", evidence_path=RM2, regex=regex
        )

        assert resp["result_count"] == 2
        assert resp["total_matches"] == 2
        assert {r["source_path"] for r in resp["results"]} == {RM2}
