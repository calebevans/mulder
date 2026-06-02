"""Tests for the Correlator cross-source time-range joins."""

from __future__ import annotations

from pathlib import Path

import pytest

from mulder.db import CaseDB
from mulder.index.correlator import CorrelationResult, Correlator
from mulder.models import WindowRow


@pytest.fixture()
def populated_db(tmp_path: Path) -> CaseDB:
    """Create a CaseDB with sources and windows spanning a time range."""
    db = CaseDB.create(case_id="corr-case", evidence_root="/evidence", db_dir=tmp_path)

    sid_pslist = db.register_source(
        source_name="volatility.pslist",
        source_path="/evidence/memdump.mem",
        source_hash="abc",
        extractor="volatility",
        line_count=10,
    )
    sid_netscan = db.register_source(
        source_name="volatility.netscan",
        source_path="/evidence/memdump.mem",
        source_hash="def",
        extractor="volatility",
        line_count=5,
    )
    sid_fls = db.register_source(
        source_name="tsk.filelist",
        source_path="/evidence/disk.dd",
        source_hash="ghi",
        extractor="sleuthkit",
        line_count=20,
    )

    db.insert_windows(
        sid_pslist,
        [
            WindowRow(
                source_id=sid_pslist,
                line_start=1,
                line_end=5,
                event_time="2025-01-15T08:00:00Z",
                raw_text="PID 1234 cmd.exe",
            ),
            WindowRow(
                source_id=sid_pslist,
                line_start=6,
                line_end=10,
                event_time="2025-01-15T09:30:00Z",
                raw_text="PID 5678 svchost.exe",
            ),
        ],
    )
    db.insert_windows(
        sid_netscan,
        [
            WindowRow(
                source_id=sid_netscan,
                line_start=1,
                line_end=3,
                event_time="2025-01-15T08:15:00Z",
                raw_text="TCP 192.168.1.10:4444",
            ),
            WindowRow(
                source_id=sid_netscan,
                line_start=4,
                line_end=5,
                event_time="2025-01-15T10:00:00Z",
                raw_text="TCP 10.0.0.1:80",
            ),
        ],
    )
    db.insert_windows(
        sid_fls,
        [
            WindowRow(
                source_id=sid_fls,
                line_start=1,
                line_end=5,
                event_time="2025-01-15T07:00:00Z",
                raw_text="malware.exe created",
            ),
            WindowRow(
                source_id=sid_fls,
                line_start=6,
                line_end=10,
                event_time="2025-01-15T08:30:00Z",
                raw_text="log.txt modified",
            ),
        ],
    )

    return db


class TestCorrelateBasicTimeRange:
    """Tests for basic time-range correlation queries."""

    def test_correlate_basic_time_range(self, populated_db: CaseDB) -> None:
        """Basic time-range query returns windows within range."""
        correlator = Correlator(populated_db)
        result = correlator.correlate_across_sources(
            time_start="2025-01-15T08:00:00Z",
            time_end="2025-01-15T09:00:00Z",
        )

        assert isinstance(result, CorrelationResult)
        assert result.time_start == "2025-01-15T08:00:00Z"
        assert result.time_end == "2025-01-15T09:00:00Z"
        assert result.total_windows > 0

        all_windows = [w for ws in result.windows_by_source.values() for w in ws]
        for w in all_windows:
            assert w.event_time is not None
            assert w.event_time >= "2025-01-15T08:00:00Z"
            assert w.event_time <= "2025-01-15T09:00:00Z"

    def test_correlate_source_filter(self, populated_db: CaseDB) -> None:
        """Source parameter limits results to specified sources."""
        correlator = Correlator(populated_db)
        result = correlator.correlate_across_sources(
            time_start="2025-01-15T07:00:00Z",
            time_end="2025-01-15T11:00:00Z",
            sources=["volatility.pslist"],
        )

        assert set(result.windows_by_source.keys()) == {"volatility.pslist"}
        assert "volatility.netscan" not in result.windows_by_source
        assert "tsk.filelist" not in result.windows_by_source

    def test_correlate_empty_range(self, populated_db: CaseDB) -> None:
        """Empty time range returns no results."""
        correlator = Correlator(populated_db)
        result = correlator.correlate_across_sources(
            time_start="2020-01-01T00:00:00Z",
            time_end="2020-01-01T01:00:00Z",
        )

        assert result.total_windows == 0
        all_windows = [w for ws in result.windows_by_source.values() for w in ws]
        assert len(all_windows) == 0

    def test_total_windows_count(self, populated_db: CaseDB) -> None:
        """total_windows field matches actual result count."""
        correlator = Correlator(populated_db)
        result = correlator.correlate_across_sources(
            time_start="2025-01-15T07:00:00Z",
            time_end="2025-01-15T11:00:00Z",
        )

        actual_count = sum(len(ws) for ws in result.windows_by_source.values())
        assert result.total_windows == actual_count
