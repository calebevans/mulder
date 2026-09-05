"""Keyword-bag searches must match something, and the right thing first.

Every one of the 23 ``_keyword_sub_query`` call sites across the composite
hunting tools passes a bag of keywords::

    "failed logon event 4625 authentication failure brute force"

FTS5's implicit operator is AND, so all seven terms had to appear inside one
4096-character window. They never do. ``find_lateral_movement_indicators``,
``find_persistence_mechanisms``, ``find_defense_evasion``,
``find_data_exfiltration_indicators`` and the rest therefore reported no
indicators from any of their keyword searches -- a clean bill of health
produced by a query that could not match.

Plain OR is not the whole fix. Ordered by ``event_time`` and cut at k=20 the
caller would get an arbitrary sample of every window containing the word
"event", and the callers' own filters (``"4625" in raw_text``) would discard
nearly all of it. ``match="any"`` therefore also orders by FTS5's bm25 rank,
which weights the rare terms (4625, 4648) over the common ones.

These tests use a real FTS5 case database, not a mock.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mulder.db import CaseDB, _fts5_any_query
from mulder.models import WindowRow

KEYWORD_BAG = "failed logon event 4625 authentication failure brute force"

# The one window an analyst is looking for, among noise that shares its
# common words.
SIGNAL = (
    "An account failed to log on. EventID 4625 Logon Type 3 "
    "authentication failure brute force from 10.4.19.203"
)
NOISE = "a logon event occurred normally"


@pytest.fixture
def case_db(tmp_path: Path) -> CaseDB:
    db = CaseDB.create(case_id="fts", evidence_root="/ev", db_dir=tmp_path)
    source_id = db.register_source(
        source_name="evtx.security",
        source_path="/evidence/Security.evtx",
        source_hash="h",
        extractor="evtx",
        line_count=31,
    )
    windows = [
        WindowRow(
            window_id=None,
            source_id=source_id,
            line_start=i + 1,
            line_end=i + 1,
            event_time=f"2024-03-11T09:{i:02d}:00",
            raw_text=NOISE,
        )
        for i in range(30)
    ]
    # Last in time, so a time-ordered query would not surface it first.
    windows.append(
        WindowRow(
            window_id=None,
            source_id=source_id,
            line_start=99,
            line_end=99,
            event_time="2024-03-11T23:59:00",
            raw_text=SIGNAL,
        )
    )
    db.insert_windows(source_id, windows)
    yield db
    db.close()


class TestAnyQueryConstruction:
    def test_terms_are_or_joined(self) -> None:
        assert _fts5_any_query("alpha beta gamma") == "alpha OR beta OR gamma"

    def test_existing_operators_are_preserved(self) -> None:
        assert _fts5_any_query("alpha AND beta") == "alpha AND beta"

    def test_special_characters_are_still_quoted(self) -> None:
        assert _fts5_any_query("spinlock.exe rundll32") == '"spinlock.exe" OR rundll32'

    def test_a_trailing_operator_is_dropped(self) -> None:
        """A dangling AND/OR is an FTS5 syntax error."""
        assert _fts5_any_query("alpha OR") == "alpha"

    def test_empty(self) -> None:
        assert _fts5_any_query("") == ""

    def test_single_term(self) -> None:
        assert _fts5_any_query("4625") == "4625"


class TestKeywordBagAgainstARealDatabase:
    def test_implicit_and_matches_nothing(self, case_db: CaseDB) -> None:
        """The bug, stated as a test: the default mode finds zero windows."""
        assert case_db.search_windows(KEYWORD_BAG, source_name="evtx.security") == []

    def test_any_mode_finds_windows(self, case_db: CaseDB) -> None:
        results = case_db.search_windows(
            KEYWORD_BAG, source_name="evtx.security", max_results=20, match="any"
        )
        assert len(results) == 20

    def test_the_signal_window_ranks_first(self, case_db: CaseDB) -> None:
        """Why rank and not event_time: the match is the newest row of 31."""
        results = case_db.search_windows(
            KEYWORD_BAG, source_name="evtx.security", max_results=20, match="any"
        )
        assert "4625" in results[0][0].raw_text

    def test_the_signal_survives_a_narrow_k(self, case_db: CaseDB) -> None:
        """The callers take k windows and then filter for '4625'."""
        results = case_db.search_windows(
            KEYWORD_BAG, source_name="evtx.security", max_results=3, match="any"
        )
        assert any("4625" in w.raw_text for w, _ in results)

    def test_all_mode_still_orders_by_time(self, case_db: CaseDB) -> None:
        results = case_db.search_windows(
            "logon", source_name="evtx.security", max_results=5, match="all"
        )
        times = [w.event_time for w, _ in results]
        assert times == sorted(times)

    def test_all_mode_is_the_default(self, case_db: CaseDB) -> None:
        assert case_db.search_windows("logon", source_name="evtx.security", max_results=5) == (
            case_db.search_windows(
                "logon", source_name="evtx.security", max_results=5, match="all"
            )
        )

    def test_an_explicit_boolean_query_is_untouched(self, case_db: CaseDB) -> None:
        results = case_db.search_windows(
            "4625 AND brute", source_name="evtx.security", match="all"
        )
        assert len(results) == 1
        assert "4625" in results[0][0].raw_text

    def test_source_scoping_still_applies(self, case_db: CaseDB) -> None:
        assert case_db.search_windows(KEYWORD_BAG, source_name="plaso.timeline", match="any") == []

    def test_a_query_of_only_noise_returns_nothing(self, case_db: CaseDB) -> None:
        assert case_db.search_windows("zzzznotpresent", source_name="evtx.security") == []


class TestCompositeKeywordSubQuery:
    def test_it_asks_for_any(self, case_db: CaseDB, monkeypatch: pytest.MonkeyPatch) -> None:
        """The composite hunts are the callers this exists for."""
        from mulder.server.tools.composite import core as cc

        captured: dict[str, object] = {}

        class _Ctx:
            db = case_db

            class audit:  # noqa: N801 - mirrors the real context's shape
                @staticmethod
                def log_tool_call(**kwargs: object) -> None:
                    captured.update(kwargs)

        monkeypatch.setattr(cc, "get_ctx", lambda: _Ctx())
        monkeypatch.setattr(cc, "_source_exists", lambda _name: True)

        windows, _tc = cc._keyword_sub_query(
            KEYWORD_BAG, "find_lateral_movement_indicators", source_name="evtx.security", k=20
        )
        assert windows, "the composite hunts found nothing at all before this fix"
        assert "4625" in windows[0].raw_text
        assert captured["params"]["match"] == "any"  # type: ignore[index]
