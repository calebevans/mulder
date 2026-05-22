"""Tests for mulder.db -- CaseDB CRUD, FTS, pagination, integrity."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text

from mulder.db import CaseDB, _sanitize_fts5_query
from mulder.models import Finding, WindowRow


class TestCaseLifecycle:
    def test_create_and_get_metadata(self, tmp_case_db: CaseDB) -> None:
        meta = tmp_case_db.get_case_metadata()
        assert meta.case_id == "test-case"
        assert meta.evidence_root == "/evidence"
        assert meta.extractor_versions == {}

    def test_open_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Case database not found"):
            CaseDB.open("nonexistent", tmp_path)

    def test_open_existing(self, tmp_path: Path) -> None:
        db1 = CaseDB.create(case_id="reopen", evidence_root="/ev", db_dir=tmp_path)
        db1.close()
        db2 = CaseDB.open("reopen", tmp_path)
        assert db2.get_case_metadata().case_id == "reopen"
        db2.close()

    def test_context_manager(self, tmp_path: Path) -> None:
        with CaseDB.create(case_id="ctx", evidence_root="/ev", db_dir=tmp_path) as db:
            assert db.get_case_metadata().case_id == "ctx"


class TestSources:
    def test_register_and_get_sources(self, tmp_case_db: CaseDB) -> None:
        sid = tmp_case_db.register_source(
            source_name="volatility.pslist",
            source_path="/evidence/memdump.mem",
            source_hash="abc123",
            extractor="volatility",
            line_count=42,
        )
        assert isinstance(sid, int)

        sources = tmp_case_db.get_sources()
        assert len(sources) == 1
        assert sources[0].source_name == "volatility.pslist"
        assert sources[0].line_count == 42

    def test_get_source_count(self, tmp_case_db: CaseDB) -> None:
        assert tmp_case_db.get_source_count() == 0
        tmp_case_db.register_source("s1", "/p", "h", "ext", 10)
        assert tmp_case_db.get_source_count() == 1


class TestWindows:
    @pytest.fixture(autouse=True)
    def _setup_source(self, tmp_case_db: CaseDB) -> None:
        self.db = tmp_case_db
        self.sid = tmp_case_db.register_source("src", "/p", "h", "ext", 100)

    def _make_windows(self, texts: list[str], time_base: str = "2025-01-15T") -> list[WindowRow]:
        return [
            WindowRow(
                source_id=self.sid,
                line_start=i * 10,
                line_end=(i + 1) * 10,
                event_time=f"{time_base}{i:02d}:00:00Z",
                raw_text=t,
            )
            for i, t in enumerate(texts)
        ]

    def test_insert_and_search_fts_match(self) -> None:
        windows = self._make_windows(["spinlock.exe launched", "normal process"])
        self.db.insert_windows(self.sid, windows)
        results = self.db.search_windows("spinlock")
        assert len(results) == 1
        assert "spinlock" in results[0][0].raw_text

    def test_search_fts_no_match(self) -> None:
        windows = self._make_windows(["nothing relevant here"])
        self.db.insert_windows(self.sid, windows)
        results = self.db.search_windows("nonexistent_term_xyz")
        assert results == []

    def test_search_with_source_filter(self, tmp_case_db: CaseDB) -> None:
        sid2 = tmp_case_db.register_source("other", "/p2", "h2", "ext", 10)
        tmp_case_db.insert_windows(
            self.sid,
            [
                WindowRow(
                    source_id=self.sid,
                    line_start=0,
                    line_end=5,
                    event_time=None,
                    raw_text="target data",
                )
            ],
        )
        tmp_case_db.insert_windows(
            sid2,
            [
                WindowRow(
                    source_id=sid2,
                    line_start=0,
                    line_end=5,
                    event_time=None,
                    raw_text="target data",
                )
            ],
        )
        results = tmp_case_db.search_windows("target", source_name="src")
        assert len(results) == 1
        assert results[0][1] == "src"

    def test_get_windows_by_source_time_range(self) -> None:
        windows = self._make_windows(["early", "middle", "late"])
        self.db.insert_windows(self.sid, windows)
        results = self.db.get_windows_by_source(
            "src",
            time_start="2025-01-15T01:00:00Z",
            time_end="2025-01-15T01:00:00Z",
        )
        assert len(results) == 1
        assert results[0].raw_text == "middle"

    def test_get_windows_page_pagination(self) -> None:
        windows = self._make_windows([f"line {i}" for i in range(5)])
        self.db.insert_windows(self.sid, windows)

        page1, total = self.db.get_windows_page("src", after_id=0, limit=2)
        assert len(page1) == 2
        assert total == 5

        last_id = page1[-1].window_id
        assert last_id is not None
        page2, _ = self.db.get_windows_page("src", after_id=last_id, limit=2)
        assert len(page2) == 2
        assert page2[0].window_id != page1[0].window_id


class TestFindings:
    def test_insert_and_get_findings(self, tmp_case_db: CaseDB, sample_finding: Finding) -> None:
        tmp_case_db.insert_finding(sample_finding)
        findings = tmp_case_db.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_id == "f-001"
        assert f.evidence_refs == ["tc_aabbccdd"]
        assert f.mitre_attack_ids == ["T1059.001"]


class TestExtractorVersions:
    def test_update_and_reload(self, tmp_path: Path) -> None:
        db = CaseDB.create(case_id="ver", evidence_root="/ev", db_dir=tmp_path)
        db.update_extractor_versions({"volatility": "2.7.0", "plaso": "20240101"})
        meta = db.get_case_metadata()
        assert meta.extractor_versions == {"volatility": "2.7.0", "plaso": "20240101"}
        db.close()


class TestEvidenceIntegrity:
    def test_verified(self, tmp_case_db: CaseDB) -> None:
        """Source with windows should verify successfully."""
        sid = tmp_case_db.register_source("src.log", "/p", "h", "ext", 10)
        windows = [
            WindowRow(source_id=sid, line_start=0, line_end=5, event_time=None, raw_text="hello"),
            WindowRow(source_id=sid, line_start=5, line_end=10, event_time=None, raw_text="world"),
        ]
        tmp_case_db.insert_windows(sid, windows)
        results = tmp_case_db.verify_evidence_integrity()
        assert len(results) == 1
        assert results[0]["status"] == "verified"
        assert results[0]["window_count"] == 2

    def test_modified(self, tmp_case_db: CaseDB) -> None:
        """Tampering with window text should be detected."""
        sid = tmp_case_db.register_source("src.log", "/p", "h", "ext", 10)
        windows = [
            WindowRow(
                source_id=sid, line_start=0, line_end=5, event_time=None, raw_text="original"
            ),
        ]
        tmp_case_db.insert_windows(sid, windows)

        with tmp_case_db._engine.begin() as conn:
            conn.execute(
                text("UPDATE windows SET raw_text = 'tampered' WHERE source_id = :sid"),
                {"sid": sid},
            )

        results = tmp_case_db.verify_evidence_integrity()
        assert len(results) == 1
        assert results[0]["status"] == "modified"

    def test_no_hash_for_legacy_source(self, tmp_case_db: CaseDB) -> None:
        """Source without windows_hash (legacy) should report no_hash_recorded."""
        tmp_case_db.register_source("legacy.log", "/p", "h", "ext", 10)
        results = tmp_case_db.verify_evidence_integrity()
        assert len(results) == 1
        assert results[0]["status"] == "no_hash_recorded"

    def test_get_evidence_registry(self, tmp_case_db: CaseDB) -> None:
        tmp_case_db.register_evidence_file("/a.dd", "hash_a", 100)
        tmp_case_db.register_evidence_file("/b.dd", "hash_b", 200)
        reg = tmp_case_db.get_evidence_registry()
        assert len(reg) == 2
        assert reg[0]["file_path"] == "/a.dd"


class TestFtsBatchDeduplication:
    """Verify FTS index doesn't duplicate entries across batch inserts."""

    @pytest.fixture(autouse=True)
    def _setup_source(self, tmp_case_db: CaseDB) -> None:
        self.db = tmp_case_db
        self.sid = tmp_case_db.register_source("src", "/p", "h", "ext", 100)

    def test_no_fts_duplicates_across_batches(self) -> None:
        """Two sequential insert_windows calls must not create duplicate FTS rows."""
        batch1 = [
            WindowRow(
                source_id=self.sid,
                line_start=i * 10,
                line_end=(i + 1) * 10,
                event_time=None,
                raw_text=f"unique_marker process_{i}",
            )
            for i in range(3)
        ]
        self.db.insert_windows(self.sid, batch1)

        batch2 = [
            WindowRow(
                source_id=self.sid,
                line_start=30 + i * 10,
                line_end=40 + i * 10,
                event_time=None,
                raw_text=f"other_data item_{i}",
            )
            for i in range(3)
        ]
        self.db.insert_windows(self.sid, batch2)

        results = self.db.search_windows("unique_marker")
        assert len(results) == 3, f"Expected 3 results, got {len(results)} (FTS duplicates?)"


class TestSanitizeFts5Query:
    """Unit tests for the _sanitize_fts5_query helper."""

    def test_special_chars_quoted(self) -> None:
        """Tokens with FTS5 special chars should be double-quoted."""
        result = _sanitize_fts5_query("file.exe")
        assert '"file.exe"' in result

    def test_preserves_operators(self) -> None:
        """Boolean operators AND/OR/NOT/NEAR should pass through unquoted."""
        result = _sanitize_fts5_query("malware AND trojan")
        assert "AND" in result
        assert "malware" in result
        assert "trojan" in result

    def test_already_quoted_preserved(self) -> None:
        """Already-quoted phrases should not be re-quoted."""
        result = _sanitize_fts5_query('"exact phrase"')
        assert '"exact phrase"' in result

    def test_plain_words_unchanged(self) -> None:
        """Plain alphanumeric tokens should not be modified."""
        result = _sanitize_fts5_query("simple query")
        assert result == "simple query"


class TestMigrations:
    """Verify migration idempotency."""

    def test_migration_tolerates_duplicate_column(self, tmp_case_db: CaseDB) -> None:
        """Running migrations twice should not raise (duplicate column is tolerated)."""
        db_path = tmp_case_db.db_path
        tmp_case_db.close()
        db2 = CaseDB(db_path)
        meta = db2.get_case_metadata()
        assert meta.case_id == "test-case"
        db2.close()


class TestWindowsByTimeRange:
    """Tests for get_windows_by_time_range grouping and filtering."""

    def test_groups_by_source(self, tmp_case_db: CaseDB) -> None:
        """Windows from different sources should be grouped by source_name."""
        sid1 = tmp_case_db.register_source("src1", "/p1", "h1", "ext", 10)
        sid2 = tmp_case_db.register_source("src2", "/p2", "h2", "ext", 10)

        wins1 = [
            WindowRow(
                source_id=sid1,
                line_start=0,
                line_end=5,
                event_time="2025-01-15T12:00:00Z",
                raw_text="event in src1",
            )
        ]
        wins2 = [
            WindowRow(
                source_id=sid2,
                line_start=0,
                line_end=5,
                event_time="2025-01-15T12:30:00Z",
                raw_text="event in src2",
            )
        ]
        tmp_case_db.insert_windows(sid1, wins1)
        tmp_case_db.insert_windows(sid2, wins2)

        result = tmp_case_db.get_windows_by_time_range(
            "2025-01-15T11:00:00Z", "2025-01-15T13:00:00Z"
        )
        assert "src1" in result
        assert "src2" in result
        assert len(result["src1"]) == 1
        assert len(result["src2"]) == 1

    def test_excludes_outside_range(self, tmp_case_db: CaseDB) -> None:
        """Windows outside the queried time range should not appear."""
        sid = tmp_case_db.register_source("src", "/p", "h", "ext", 10)
        wins = [
            WindowRow(
                source_id=sid,
                line_start=0,
                line_end=5,
                event_time="2025-01-15T06:00:00Z",
                raw_text="early event",
            ),
            WindowRow(
                source_id=sid,
                line_start=5,
                line_end=10,
                event_time="2025-01-15T18:00:00Z",
                raw_text="late event",
            ),
        ]
        tmp_case_db.insert_windows(sid, wins)

        result = tmp_case_db.get_windows_by_time_range(
            "2025-01-15T10:00:00Z", "2025-01-15T14:00:00Z"
        )
        assert result == {}
