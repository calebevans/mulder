"""Tests for mulder.server.extract_helpers -- windowing and indexing logic."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.index.correlator import Correlator
from mulder.server.app import ServerContext
from mulder.server.extract_helpers import (
    _WINDOW_CHAR_BUDGET,
    _parse_timestamp,
    extract_and_index,
)


class TestWindowConstants:
    """Verify windowing constants are defined with expected values."""

    def test_window_char_budget(self) -> None:
        assert _WINDOW_CHAR_BUDGET == 4096


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
    def _patch_ctx(ctx: ServerContext) -> AbstractContextManager[Any]:
        """Return a context-manager that patches ``get_ctx`` to return *ctx*."""
        return patch("mulder.server.app.get_ctx", return_value=ctx)

    def test_basic_indexing(self, _mock_server_ctx: ServerContext) -> None:
        """Normal-length output is indexed and all content preserved."""
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
        assert result["windows_indexed"] is not None
        assert result["windows_indexed"] >= 1  # type: ignore[operator]
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

    def test_no_data_lost(self, _mock_server_ctx: ServerContext) -> None:
        """All input characters are preserved across windows."""
        raw_output = "A" * 10000

        with self._patch_ctx(_mock_server_ctx):
            extract_and_index(
                raw_output=raw_output,
                source_name="big.log",
                source_path="/evidence/big.log",
                extractor_name="test",
            )

        windows = _mock_server_ctx.db.get_windows_by_source("big.log")
        reconstructed = "".join(w.raw_text for w in windows)
        assert reconstructed == raw_output

    def test_uniform_window_sizes(self, _mock_server_ctx: ServerContext) -> None:
        """Windows are uniformly sized at the char budget (except the last)."""
        raw_output = "X" * (_WINDOW_CHAR_BUDGET * 3 + 500)

        with self._patch_ctx(_mock_server_ctx):
            extract_and_index(
                raw_output=raw_output,
                source_name="uniform.log",
                source_path="/evidence/uniform.log",
                extractor_name="test",
            )

        windows = _mock_server_ctx.db.get_windows_by_source("uniform.log")
        assert len(windows) == 4
        for w in windows[:-1]:
            assert len(w.raw_text) == _WINDOW_CHAR_BUDGET
        assert len(windows[-1].raw_text) == 500

    def test_short_input_single_window(self, _mock_server_ctx: ServerContext) -> None:
        """Input smaller than the budget fits in one window."""
        raw_output = "short content\nwith newlines\n"

        with self._patch_ctx(_mock_server_ctx):
            extract_and_index(
                raw_output=raw_output,
                source_name="short.log",
                source_path="/evidence/short.log",
                extractor_name="test",
            )

        windows = _mock_server_ctx.db.get_windows_by_source("short.log")
        assert len(windows) == 1
        assert windows[0].raw_text == raw_output

    def test_lines_split_across_windows(self, _mock_server_ctx: ServerContext) -> None:
        """A line crossing a window boundary is split, not truncated."""
        half = _WINDOW_CHAR_BUDGET - 10
        raw_output = "A" * half + "BOUNDARY_MARKER" + "B" * half

        with self._patch_ctx(_mock_server_ctx):
            extract_and_index(
                raw_output=raw_output,
                source_name="split.log",
                source_path="/evidence/split.log",
                extractor_name="test",
            )

        windows = _mock_server_ctx.db.get_windows_by_source("split.log")
        reconstructed = "".join(w.raw_text for w in windows)
        assert "BOUNDARY_MARKER" in reconstructed
        assert reconstructed == raw_output
