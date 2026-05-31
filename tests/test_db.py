"""Tests for mulder.db -- CaseDB CRUD, FTS, pagination, integrity."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text

from mulder.db import (
    CaseDB,
    ProgressRecord,
    ProgressSummary,
    _QueueResult,
    _sanitize_fts5_query,
)
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


class TestProgress:
    """Tests for the progress table CRUD methods."""

    def test_record_and_get_all_progress(self, tmp_case_db: CaseDB) -> None:
        """Recorded progress entries should be retrievable in insertion order."""
        tmp_case_db.record_progress(
            system_name="memory",
            tools_completed=["run_volatility"],
            questions_addressed=["Q1"],
            notes="Analyzed memory dump",
        )
        tmp_case_db.record_progress(
            system_name="disk",
            tools_completed=["run_fls", "run_bulk_extractor"],
            questions_addressed=["Q2", "Q3"],
        )
        records = tmp_case_db.get_all_progress()
        assert len(records) == 2
        assert records[0]["system_name"] == "memory"
        assert records[0]["tools_completed"] == ["run_volatility"]
        assert records[0]["questions_addressed"] == ["Q1"]
        assert records[0]["notes"] == "Analyzed memory dump"
        assert records[0]["recorded_at"] is not None
        assert records[1]["system_name"] == "disk"
        assert records[1]["tools_completed"] == ["run_fls", "run_bulk_extractor"]

    def test_get_all_progress_empty(self, tmp_case_db: CaseDB) -> None:
        """Empty database should return an empty list."""
        assert tmp_case_db.get_all_progress() == []

    def test_get_progress_summary(self, tmp_case_db: CaseDB) -> None:
        """Summary should aggregate systems, questions, and tools across records."""
        tmp_case_db.record_progress("memory", ["run_volatility"], ["Q1", "Q2"])
        tmp_case_db.record_progress("disk", ["run_fls"], ["Q2", "Q3"])
        summary = tmp_case_db.get_progress_summary()
        assert summary["systems_analyzed"] == ["disk", "memory"]
        assert summary["questions_covered"] == ["Q1", "Q2", "Q3"]
        assert summary["tools_used"] == ["run_fls", "run_volatility"]
        assert summary["total_progress_records"] == 2

    def test_get_progress_summary_empty(self, tmp_case_db: CaseDB) -> None:
        """Summary of empty progress should return empty collections."""
        summary = tmp_case_db.get_progress_summary()
        assert summary["systems_analyzed"] == []
        assert summary["questions_covered"] == []
        assert summary["total_progress_records"] == 0

    def test_record_progress_empty_notes(self, tmp_case_db: CaseDB) -> None:
        """Default empty notes should be stored correctly."""
        tmp_case_db.record_progress("net", ["run_pcap_analysis"], ["Q4"])
        records = tmp_case_db.get_all_progress()
        assert records[0]["notes"] == ""

    def test_progress_survives_reopen(self, tmp_path: Path) -> None:
        """Progress records should persist across database close/reopen."""
        db1 = CaseDB.create(case_id="progress-persist", evidence_root="/ev", db_dir=tmp_path)
        db1.record_progress("memory", ["run_volatility"], ["Q1"])
        db1.close()

        db2 = CaseDB.open("progress-persist", tmp_path)
        records = db2.get_all_progress()
        assert len(records) == 1
        assert records[0]["system_name"] == "memory"
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


class TestQueueResult:
    """Tests for the _QueueResult dataclass."""

    def test_defaults(self) -> None:
        """Fresh _QueueResult should have None value and no error."""
        qr = _QueueResult()
        assert qr.value is None
        assert qr.error is None

    def test_stores_value(self) -> None:
        qr = _QueueResult()
        qr.value = 42
        assert qr.value == 42
        assert qr.error is None

    def test_stores_error(self) -> None:
        exc = ValueError("boom")
        qr = _QueueResult(error=exc)
        assert qr.error is exc
        assert qr.value is None


class TestCappedWindowsBySources:
    """Tests for get_capped_windows_by_sources batch query."""

    def test_returns_capped_windows_across_sources(self, tmp_case_db: CaseDB) -> None:
        """Multiple sources should each return at most max_per_source windows."""
        sid1 = tmp_case_db.register_source("alpha", "/p1", "h1", "ext", 10)
        sid2 = tmp_case_db.register_source("beta", "/p2", "h2", "ext", 10)

        wins1 = [
            WindowRow(
                source_id=sid1, line_start=i, line_end=i + 1, event_time=None, raw_text=f"a{i}"
            )
            for i in range(5)
        ]
        wins2 = [
            WindowRow(
                source_id=sid2, line_start=i, line_end=i + 1, event_time=None, raw_text=f"b{i}"
            )
            for i in range(3)
        ]
        tmp_case_db.insert_windows(sid1, wins1)
        tmp_case_db.insert_windows(sid2, wins2)

        result = tmp_case_db.get_capped_windows_by_sources(["alpha", "beta"], max_per_source=2)
        assert len(result["alpha"][0]) == 2
        assert result["alpha"][1] == 5
        assert len(result["beta"][0]) == 2
        assert result["beta"][1] == 3

    def test_empty_sources_list(self, tmp_case_db: CaseDB) -> None:
        """Empty input should return empty dict."""
        assert tmp_case_db.get_capped_windows_by_sources([]) == {}

    def test_missing_source_returns_zero(self, tmp_case_db: CaseDB) -> None:
        """Source with no windows should appear with ([], 0)."""
        tmp_case_db.register_source("empty_src", "/p", "h", "ext", 0)
        result = tmp_case_db.get_capped_windows_by_sources(["empty_src"])
        assert result["empty_src"] == ([], 0)

    def test_cap_larger_than_total(self, tmp_case_db: CaseDB) -> None:
        """When max_per_source exceeds available windows, return all."""
        sid = tmp_case_db.register_source("small", "/p", "h", "ext", 3)
        wins = [
            WindowRow(
                source_id=sid, line_start=i, line_end=i + 1, event_time=None, raw_text=f"w{i}"
            )
            for i in range(3)
        ]
        tmp_case_db.insert_windows(sid, wins)

        result = tmp_case_db.get_capped_windows_by_sources(["small"], max_per_source=100)
        assert len(result["small"][0]) == 3
        assert result["small"][1] == 3


class TestStreamingHash:
    """Verify that the streaming hash computation produces correct results."""

    def test_hash_consistent_across_batches(self, tmp_case_db: CaseDB) -> None:
        """Hash after two batch inserts should equal hash of all windows together."""
        import hashlib

        sid = tmp_case_db.register_source("hash_test", "/p", "h", "ext", 10)

        batch1 = [
            WindowRow(source_id=sid, line_start=0, line_end=5, event_time=None, raw_text="hello"),
        ]
        batch2 = [
            WindowRow(source_id=sid, line_start=5, line_end=10, event_time=None, raw_text="world"),
        ]
        tmp_case_db.insert_windows(sid, batch1)
        tmp_case_db.insert_windows(sid, batch2)

        sources = tmp_case_db.get_sources()
        src = next(s for s in sources if s.source_name == "hash_test")

        h = hashlib.blake2b(digest_size=32)
        h.update(b"hello")
        h.update(b"world")
        expected = "blake2b:" + h.hexdigest()
        assert src.windows_hash == expected


class TestProgressTypedDicts:
    """Verify ProgressRecord and ProgressSummary TypedDicts."""

    def test_get_all_progress_returns_typed_records(self, tmp_case_db: CaseDB) -> None:
        tmp_case_db.record_progress("net", ["run_pcap"], ["Q1"], notes="note")
        records = tmp_case_db.get_all_progress()
        assert len(records) == 1

        r: ProgressRecord = records[0]
        assert r["system_name"] == "net"
        assert r["tools_completed"] == ["run_pcap"]
        assert r["questions_addressed"] == ["Q1"]
        assert r["notes"] == "note"
        assert isinstance(r["id"], int)
        assert isinstance(r["recorded_at"], str)

    def test_get_progress_summary_returns_typed(self, tmp_case_db: CaseDB) -> None:
        tmp_case_db.record_progress("memory", ["run_vol"], ["Q1"])
        summary: ProgressSummary = tmp_case_db.get_progress_summary()
        assert summary["systems_analyzed"] == ["memory"]
        assert summary["tools_used"] == ["run_vol"]
        assert summary["questions_covered"] == ["Q1"]
        assert summary["total_progress_records"] == 1
