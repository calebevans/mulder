"""Tests for mulder.server.tools.tsk -- query-time TSK tool helpers.

Covers the _resolve_image_and_offset function for single-image,
multi-image, and error scenarios.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mulder.models import SourceRow, WindowRow
from mulder.server.tools.tsk import (
    _cached_image_info,
    _image_info_lock,
    _resolve_image_and_offset,
)


def _make_source(
    source_id: int,
    source_name: str,
    source_path: str,
) -> SourceRow:
    """Create a minimal SourceRow for testing."""
    return SourceRow(
        source_id=source_id,
        case_id="test-case",
        source_name=source_name,
        source_path=source_path,
        source_hash="abc123",
        extractor="tsk",
        line_count=10,
    )


def _make_window(source_id: int, raw_text: str) -> WindowRow:
    """Create a minimal WindowRow for testing."""
    return WindowRow(
        window_id=1,
        source_id=source_id,
        line_start=1,
        line_end=5,
        event_time=None,
        raw_text=raw_text,
    )


MMLS_IMAGE_A = (
    "DOS Partition Table\n002:000   0000002048   0041943039   0041940992   NTFS (0x07)\n"
)
MMLS_IMAGE_B = (
    "DOS Partition Table\n002:000   0000004096   0083886079   0083881984   NTFS (0x07)\n"
)


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    """Clear the module-level image info cache before each test."""
    with _image_info_lock:
        _cached_image_info.clear()


class TestResolveImageAndOffsetSingleImage:
    """Backward-compatible: no image_path argument (single-image case)."""

    @patch("mulder.server.tools.tsk._detect_filesystem_type", return_value="ntfs")
    @patch("mulder.server.tools.tsk.get_ctx")
    def test_single_source_returns_correct_offset(
        self,
        mock_ctx: MagicMock,
        mock_fstype: MagicMock,
    ) -> None:
        """Single tsk.partitions source resolves without image_path."""
        src = _make_source(1, "tsk.partitions", "/images/disk1.dd")
        win = _make_window(1, MMLS_IMAGE_A)

        ctx = MagicMock()
        ctx.case_id = "case-001"
        ctx.db.get_sources.return_value = [src]
        ctx.db.get_windows_by_source.return_value = [win]
        mock_ctx.return_value = ctx

        path, offset, fs = _resolve_image_and_offset()
        assert path == "/images/disk1.dd"
        assert offset == 2048
        assert fs == "ntfs"

    @patch("mulder.server.tools.tsk._detect_filesystem_type", return_value="ntfs")
    @patch("mulder.server.tools.tsk.get_ctx")
    def test_result_is_cached(
        self,
        mock_ctx: MagicMock,
        mock_fstype: MagicMock,
    ) -> None:
        """Subsequent calls hit cache and do not re-query the DB."""
        src = _make_source(1, "tsk.partitions", "/images/disk1.dd")
        win = _make_window(1, MMLS_IMAGE_A)

        ctx = MagicMock()
        ctx.case_id = "case-001"
        ctx.db.get_sources.return_value = [src]
        ctx.db.get_windows_by_source.return_value = [win]
        mock_ctx.return_value = ctx

        result1 = _resolve_image_and_offset()
        result2 = _resolve_image_and_offset()
        assert result1 == result2
        ctx.db.get_sources.assert_called_once()


class TestResolveImageAndOffsetMultiImage:
    """Multi-image case where image_path is specified."""

    @patch("mulder.server.tools.tsk._detect_filesystem_type", return_value="ntfs")
    @patch("mulder.server.tools.tsk.get_ctx")
    def test_selects_correct_image_by_path(
        self,
        mock_ctx: MagicMock,
        mock_fstype: MagicMock,
    ) -> None:
        """When image_path is specified, only that image's partitions are used."""
        src_a = _make_source(1, "tsk.partitions", "/images/disk_a.dd")
        src_b = _make_source(2, "tsk.partitions", "/images/disk_b.dd")
        win_a = _make_window(1, MMLS_IMAGE_A)
        win_b = _make_window(2, MMLS_IMAGE_B)

        ctx = MagicMock()
        ctx.case_id = "case-multi"
        ctx.db.get_sources.return_value = [src_a, src_b]
        ctx.db.get_windows_by_source.return_value = [win_a, win_b]
        mock_ctx.return_value = ctx

        path, offset, fs = _resolve_image_and_offset("/images/disk_b.dd")
        assert path == "/images/disk_b.dd"
        assert offset == 4096

    @patch("mulder.server.tools.tsk._detect_filesystem_type", return_value="ntfs")
    @patch("mulder.server.tools.tsk.get_ctx")
    def test_different_images_cached_separately(
        self,
        mock_ctx: MagicMock,
        mock_fstype: MagicMock,
    ) -> None:
        """Each (case_id, image_path) pair is cached independently."""
        src_a = _make_source(1, "tsk.partitions", "/images/disk_a.dd")
        src_b = _make_source(2, "tsk.partitions", "/images/disk_b.dd")
        win_a = _make_window(1, MMLS_IMAGE_A)
        win_b = _make_window(2, MMLS_IMAGE_B)

        ctx = MagicMock()
        ctx.case_id = "case-multi"
        ctx.db.get_sources.return_value = [src_a, src_b]
        ctx.db.get_windows_by_source.return_value = [win_a, win_b]
        mock_ctx.return_value = ctx

        result_a = _resolve_image_and_offset("/images/disk_a.dd")
        result_b = _resolve_image_and_offset("/images/disk_b.dd")
        assert result_a[0] == "/images/disk_a.dd"
        assert result_a[1] == 2048
        assert result_b[0] == "/images/disk_b.dd"
        assert result_b[1] == 4096

    @patch("mulder.server.tools.tsk._detect_filesystem_type", return_value="ntfs")
    @patch("mulder.server.tools.tsk.get_ctx")
    def test_filters_windows_by_source_id(
        self,
        mock_ctx: MagicMock,
        mock_fstype: MagicMock,
    ) -> None:
        """Only windows belonging to the matched source are parsed."""
        src_a = _make_source(1, "tsk.partitions", "/images/disk_a.dd")
        src_b = _make_source(2, "tsk.partitions", "/images/disk_b.dd")
        # Both windows returned by get_windows_by_source (the bug scenario)
        win_a = _make_window(1, MMLS_IMAGE_A)
        win_b = _make_window(2, MMLS_IMAGE_B)

        ctx = MagicMock()
        ctx.case_id = "case-filter"
        ctx.db.get_sources.return_value = [src_a, src_b]
        ctx.db.get_windows_by_source.return_value = [win_a, win_b]
        mock_ctx.return_value = ctx

        # Request disk_a; should get offset 2048, not 4096
        path, offset, _ = _resolve_image_and_offset("/images/disk_a.dd")
        assert offset == 2048

        # Clear cache and request disk_b; should get offset 4096
        with _image_info_lock:
            _cached_image_info.clear()
        path, offset, _ = _resolve_image_and_offset("/images/disk_b.dd")
        assert offset == 4096


class TestResolveImageAndOffsetErrors:
    """Error cases for _resolve_image_and_offset."""

    @patch("mulder.server.tools.tsk.get_ctx")
    def test_raises_valueerror_for_unknown_image_path(
        self,
        mock_ctx: MagicMock,
    ) -> None:
        """ValueError raised when image_path doesn't match any source."""
        src = _make_source(1, "tsk.partitions", "/images/disk1.dd")

        ctx = MagicMock()
        ctx.case_id = "case-err"
        ctx.db.get_sources.return_value = [src]
        mock_ctx.return_value = ctx

        with pytest.raises(ValueError, match="No tsk.partitions source found"):
            _resolve_image_and_offset("/images/nonexistent.dd")

    @patch("mulder.server.tools.tsk._detect_filesystem_type", return_value=None)
    @patch("mulder.server.tools.tsk._find_tsk_source_path", return_value="/images/raw.dd")
    @patch("mulder.server.tools.tsk.get_ctx")
    def test_no_partition_source_falls_back(
        self,
        mock_ctx: MagicMock,
        mock_find: MagicMock,
        mock_fstype: MagicMock,
    ) -> None:
        """When no tsk.partitions source exists, falls back to _find_tsk_source_path."""
        ctx = MagicMock()
        ctx.case_id = "case-fallback"
        ctx.db.get_sources.return_value = [_make_source(1, "tsk.filelist", "/images/raw.dd")]
        mock_ctx.return_value = ctx

        path, offset, fs = _resolve_image_and_offset()
        assert path == "/images/raw.dd"
        assert offset == 0
        assert fs is None
