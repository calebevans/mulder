"""Tests for mulder.server.extract_helpers -- windowing and indexing logic."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.index.correlator import Correlator
from mulder.server.app import ServerContext
from mulder.server.extract_helpers import (
    _WINDOW_CHAR_CAP,
    _WINDOW_SIZE,
    _parse_timestamp,
    extract_and_index,
)


class TestWindowConstants:
    """Verify windowing constants are defined with expected values."""

    def test_window_size(self) -> None:
        assert _WINDOW_SIZE == 4

    def test_window_char_cap(self) -> None:
        assert _WINDOW_CHAR_CAP == 4096


class TestParseTimestamp:
    """Verify timestamp extraction from raw text windows."""

    def test_iso_format(self) -> None:
        assert _parse_timestamp("2025-01-15T08:00:00") == "2025-01-15T08:00:00"

    def test_syslog_format(self) -> None:
        result = _parse_timestamp("Jan  5 12:30:45 host sshd[123]", reference_year=2025)
        assert result == "2025-01-05T12:30:45"

    def test_plaso_format(self) -> None:
        result = _parse_timestamp("01/15/2025 08:00:00,File,NTFS")
        assert result == "2025-01-15T08:00:00"

    def test_no_timestamp(self) -> None:
        assert _parse_timestamp("no timestamp here") is None


@pytest.fixture()
def _mock_server_ctx(
    tmp_case_db: CaseDB,
    tmp_audit_log: AuditLog,
) -> ServerContext:
    """Build a minimal ServerContext backed by temp storage."""
    return ServerContext(
        case_id="test-case",
        db=tmp_case_db,
        correlator=Correlator(tmp_case_db),
        audit=tmp_audit_log,
    )


class TestExtractAndIndex:
    """Integration tests for the extract-and-index pipeline."""

    @staticmethod
    def _patch_ctx(ctx: ServerContext) -> patch:  # type: ignore[type-arg]
        """Return a context-manager that patches ``get_ctx`` to return *ctx*."""
        return patch("mulder.server.app.get_ctx", return_value=ctx)

    def test_basic_indexing(self, _mock_server_ctx: ServerContext) -> None:
        """Normal-length output is indexed without truncation."""
        lines = [f"line-{i}" for i in range(8)]
        raw_output = "\n".join(lines)

        with self._patch_ctx(_mock_server_ctx):
            result = extract_and_index(
                raw_output=raw_output,
                source_name="test.log",
                source_path="/evidence/test.log",
                extractor_name="test",
            )

        assert result["status"] == "indexed"
        assert result["windows_indexed"] == 2
        assert result["line_count"] == 8

    def test_empty_input(self, _mock_server_ctx: ServerContext) -> None:
        """Empty input produces zero windows."""
        with self._patch_ctx(_mock_server_ctx):
            result = extract_and_index(
                raw_output="",
                source_name="empty.log",
                source_path="/evidence/empty.log",
                extractor_name="test",
            )

        assert result["status"] == "indexed_empty"
        assert result["windows_indexed"] == 0

    def test_long_lines_are_truncated(self, _mock_server_ctx: ServerContext) -> None:
        """Windows exceeding _WINDOW_CHAR_CAP are truncated in raw_text."""
        long_line = "A" * 2000
        raw_output = "\n".join([long_line] * _WINDOW_SIZE)

        with self._patch_ctx(_mock_server_ctx):
            result = extract_and_index(
                raw_output=raw_output,
                source_name="blob.log",
                source_path="/evidence/blob.log",
                extractor_name="test",
            )

        assert result["status"] == "indexed"
        assert result["windows_indexed"] == 1

        windows = _mock_server_ctx.db.get_windows_by_source("blob.log")
        assert len(windows) == 1

        stored_text = windows[0].raw_text
        assert len(stored_text) <= _WINDOW_CHAR_CAP

    def test_line_range_preserved_after_truncation(
        self, _mock_server_ctx: ServerContext
    ) -> None:
        """line_start / line_end reflect original lines, not truncated text."""
        long_line = "B" * 3000
        raw_output = "\n".join([long_line] * _WINDOW_SIZE)

        with self._patch_ctx(_mock_server_ctx):
            extract_and_index(
                raw_output=raw_output,
                source_name="hex.log",
                source_path="/evidence/hex.log",
                extractor_name="test",
            )

        windows = _mock_server_ctx.db.get_windows_by_source("hex.log")
        assert windows[0].line_start == 1
        assert windows[0].line_end == _WINDOW_SIZE

    def test_short_lines_not_truncated(self, _mock_server_ctx: ServerContext) -> None:
        """Windows under the cap are stored verbatim."""
        lines = ["short line 1", "short line 2", "short line 3", "short line 4"]
        raw_output = "\n".join(lines)
        expected_text = "\n".join(lines)

        with self._patch_ctx(_mock_server_ctx):
            extract_and_index(
                raw_output=raw_output,
                source_name="normal.log",
                source_path="/evidence/normal.log",
                extractor_name="test",
            )

        windows = _mock_server_ctx.db.get_windows_by_source("normal.log")
        assert windows[0].raw_text == expected_text
