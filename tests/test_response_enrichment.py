"""Tests for response enrichment: search pagination and composite coverage metadata."""

from __future__ import annotations

from unittest.mock import patch

from mulder.db import CaseDB
from mulder.models import WindowRow
from mulder.server.tools.composite.core import _build_coverage_metadata


class TestCountSearchWindows:
    """Verify count_search_windows returns accurate FTS match counts."""

    def test_count_matches_search_results(self, tmp_case_db: CaseDB) -> None:
        """Count should equal len(search_windows) when under the limit."""
        sid = tmp_case_db.register_source("src", "/p", "h", "ext", 100)
        windows = [
            WindowRow(
                source_id=sid,
                line_start=i * 10,
                line_end=(i + 1) * 10,
                event_time=None,
                raw_text=f"spinlock process {i}",
            )
            for i in range(5)
        ]
        tmp_case_db.insert_windows(sid, windows)

        count = tmp_case_db.count_search_windows("spinlock")
        results = tmp_case_db.search_windows("spinlock")
        assert count == len(results) == 5

    def test_count_with_source_filter(self, tmp_case_db: CaseDB) -> None:
        """Count should respect source_name filtering."""
        sid1 = tmp_case_db.register_source("alpha", "/p1", "h1", "ext", 10)
        sid2 = tmp_case_db.register_source("beta", "/p2", "h2", "ext", 10)

        tmp_case_db.insert_windows(
            sid1,
            [
                WindowRow(
                    source_id=sid1,
                    line_start=0,
                    line_end=5,
                    event_time=None,
                    raw_text="target data alpha",
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
                    raw_text="target data beta",
                )
            ],
        )

        total = tmp_case_db.count_search_windows("target")
        alpha_count = tmp_case_db.count_search_windows("target", source_name="alpha")
        assert total == 2
        assert alpha_count == 1

    def test_count_no_matches(self, tmp_case_db: CaseDB) -> None:
        """Count should be zero when nothing matches."""
        sid = tmp_case_db.register_source("src", "/p", "h", "ext", 10)
        tmp_case_db.insert_windows(
            sid,
            [
                WindowRow(
                    source_id=sid,
                    line_start=0,
                    line_end=5,
                    event_time=None,
                    raw_text="irrelevant content",
                )
            ],
        )
        count = tmp_case_db.count_search_windows("nonexistent_xyz_query")
        assert count == 0

    def test_count_with_time_filter(self, tmp_case_db: CaseDB) -> None:
        """Count should respect time range filtering."""
        sid = tmp_case_db.register_source("src", "/p", "h", "ext", 30)
        windows = [
            WindowRow(
                source_id=sid,
                line_start=0,
                line_end=10,
                event_time="2025-01-15T08:00:00Z",
                raw_text="target early",
            ),
            WindowRow(
                source_id=sid,
                line_start=10,
                line_end=20,
                event_time="2025-01-15T12:00:00Z",
                raw_text="target midday",
            ),
            WindowRow(
                source_id=sid,
                line_start=20,
                line_end=30,
                event_time="2025-01-15T18:00:00Z",
                raw_text="target evening",
            ),
        ]
        tmp_case_db.insert_windows(sid, windows)

        all_count = tmp_case_db.count_search_windows("target")
        assert all_count == 3

        filtered = tmp_case_db.count_search_windows(
            "target",
            time_start="2025-01-15T10:00:00Z",
            time_end="2025-01-15T14:00:00Z",
        )
        assert filtered == 1

    def test_count_with_exclude_sources(self, tmp_case_db: CaseDB) -> None:
        """Count should respect source exclusion."""
        sid1 = tmp_case_db.register_source("keep.this", "/p1", "h1", "ext", 10)
        sid2 = tmp_case_db.register_source("drop.this", "/p2", "h2", "ext", 10)

        tmp_case_db.insert_windows(
            sid1,
            [
                WindowRow(
                    source_id=sid1,
                    line_start=0,
                    line_end=5,
                    event_time=None,
                    raw_text="needle in keep",
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
                    raw_text="needle in drop",
                )
            ],
        )

        total = tmp_case_db.count_search_windows("needle")
        excluded = tmp_case_db.count_search_windows("needle", exclude_source_names=["drop.this"])
        assert total == 2
        assert excluded == 1

    def test_count_exceeds_search_limit(self, tmp_case_db: CaseDB) -> None:
        """Count should return total even when search_windows would be limited."""
        sid = tmp_case_db.register_source("src", "/p", "h", "ext", 200)
        windows = [
            WindowRow(
                source_id=sid,
                line_start=i * 10,
                line_end=(i + 1) * 10,
                event_time=None,
                raw_text=f"searchterm record {i}",
            )
            for i in range(20)
        ]
        tmp_case_db.insert_windows(sid, windows)

        count = tmp_case_db.count_search_windows("searchterm")
        limited_results = tmp_case_db.search_windows("searchterm", max_results=5)
        assert count == 20
        assert len(limited_results) == 5


class TestBuildCoverageMetadata:
    """Verify _build_coverage_metadata computes correct coverage info."""

    _PATCH_TARGET = "mulder.server.tools.composite.core._get_cached_sources"

    def test_all_sources_present(self, tmp_case_db: CaseDB) -> None:
        """When all required sources are indexed, no coverage_note is emitted."""
        tmp_case_db.register_source("volatility.pslist", "/p", "h", "ext", 10)
        tmp_case_db.register_source("volatility.pstree", "/p", "h", "ext", 10)

        with patch(self._PATCH_TARGET, return_value=tmp_case_db.get_sources()):
            meta = _build_coverage_metadata(["volatility.pslist", "volatility.pstree"])

        assert meta["sources_queried"] == 2
        assert meta["total_sources_available"] == 2
        assert "coverage_note" not in meta

    def test_missing_sources_noted(self, tmp_case_db: CaseDB) -> None:
        """When required sources are missing, coverage_note lists them."""
        tmp_case_db.register_source("volatility.pslist", "/p", "h", "ext", 10)

        with patch(self._PATCH_TARGET, return_value=tmp_case_db.get_sources()):
            meta = _build_coverage_metadata(
                ["volatility.pslist", "evtx.security", "plaso.timeline"]
            )

        assert meta["sources_queried"] == 1
        assert meta["total_sources_available"] == 1
        assert "coverage_note" in meta
        note = str(meta["coverage_note"])
        assert "evtx.security" in note
        assert "plaso.timeline" in note

    def test_prefix_matching(self, tmp_case_db: CaseDB) -> None:
        """Source names should match by prefix (e.g. 'volatility.pslist.host1')."""
        tmp_case_db.register_source("volatility.pslist.host1", "/p", "h", "ext", 10)
        tmp_case_db.register_source("volatility.pslist.host2", "/p", "h", "ext", 10)

        with patch(self._PATCH_TARGET, return_value=tmp_case_db.get_sources()):
            meta = _build_coverage_metadata(["volatility.pslist"])

        assert meta["sources_queried"] == 2
        names = meta["sources_queried_names"]
        assert isinstance(names, list)
        assert "volatility.pslist.host1" in names
        assert "volatility.pslist.host2" in names
        assert "coverage_note" not in meta

    def test_empty_db(self, tmp_case_db: CaseDB) -> None:
        """With no sources indexed, all required sources are reported missing."""
        with patch(self._PATCH_TARGET, return_value=tmp_case_db.get_sources()):
            meta = _build_coverage_metadata(["volatility.pslist", "evtx.security"])

        assert meta["sources_queried"] == 0
        assert meta["total_sources_available"] == 0
        assert "coverage_note" in meta
        note = str(meta["coverage_note"])
        assert "volatility.pslist" in note
        assert "evtx.security" in note

    def test_network_source_alternatives(self, tmp_case_db: CaseDB) -> None:
        """Network sources (netscan/connscan/sockscan) are interchangeable."""
        tmp_case_db.register_source("volatility.connscan", "/p", "h", "ext", 10)

        with patch(self._PATCH_TARGET, return_value=tmp_case_db.get_sources()):
            meta = _build_coverage_metadata(["volatility.netscan"])

        assert meta["sources_queried"] == 1
        names = meta["sources_queried_names"]
        assert isinstance(names, list)
        assert "volatility.connscan" in names
        assert "coverage_note" not in meta
