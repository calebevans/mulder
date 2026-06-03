"""Tests for mulder.server.tools.extract.tsk -- TSK tool helpers."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from mulder.server.tools.extract.tsk import _classify_mmls_failure, _parse_partition_offset


class TestClassifyMmlsFailure:
    """Tests for _classify_mmls_failure error classification."""

    def test_empty_stderr_returns_no_partition_table(self) -> None:
        error_type, msg, suggestion = _classify_mmls_failure(1, "")
        assert error_type == "no_partition_table"
        assert "no partition table" in msg
        assert "partition_offset=0" in suggestion

    def test_whitespace_only_stderr_returns_no_partition_table(self) -> None:
        error_type, msg, suggestion = _classify_mmls_failure(1, "   \n  ")
        assert error_type == "no_partition_table"

    def test_ewf_keyword_in_stderr(self) -> None:
        error_type, msg, suggestion = _classify_mmls_failure(
            1, "Cannot determine file type (libewf)"
        )
        assert error_type == "ewf_unsupported"
        assert "E01" in msg
        assert "ewfmount" in suggestion

    def test_e01_keyword_in_stderr(self) -> None:
        error_type, _, _ = _classify_mmls_failure(1, "unsupported image type: E01")
        assert error_type == "ewf_unsupported"

    def test_expert_witness_keyword_in_stderr(self) -> None:
        error_type, _, _ = _classify_mmls_failure(1, "Expert Witness format not supported")
        assert error_type == "ewf_unsupported"

    def test_generic_stderr_returns_mmls_failed(self) -> None:
        error_type, msg, suggestion = _classify_mmls_failure(1, "Error reading sector 0")
        assert error_type == "mmls_failed"
        assert "Error reading sector 0" in msg
        assert "partition_offset=0" in suggestion

    def test_long_stderr_is_truncated(self) -> None:
        long_err = "x" * 500
        _, msg, _ = _classify_mmls_failure(1, long_err)
        assert len(msg) < 400

    def test_returncode_preserved_in_message(self) -> None:
        _, msg, _ = _classify_mmls_failure(2, "")
        assert "exit 2" in msg

        _, msg2, _ = _classify_mmls_failure(3, "some error")
        assert "exited 3" in msg2


class TestParsePartitionOffset:
    """Tests for _parse_partition_offset mmls output parsing."""

    def test_ntfs_partition_detected(self) -> None:
        mmls_output = (
            "DOS Partition Table\n"
            "Offset Sector: 0\n"
            "Units are in 512-byte sectors\n"
            "\n"
            "     Slot    Start        End          Length       Description\n"
            "000:000   0000000000   0000000000   0000000001   Primary Table (#0)\n"
            "001:000   0000000000   0000002047   0000002048   Unallocated\n"
            "002:000   0000002048   0000206847   0000204800   NTFS (0x07)\n"
            "003:001   0000206848   0041943039   0041736192   NTFS (0x07)\n"
        )
        offset = _parse_partition_offset(mmls_output)
        assert offset == 2048

    def test_no_ntfs_returns_zero(self) -> None:
        mmls_output = (
            "DOS Partition Table\n001:000   0000002048   0000206847   0000204800   Linux (0x83)\n"
        )
        offset = _parse_partition_offset(mmls_output)
        assert offset == 0

    def test_empty_string_returns_zero(self) -> None:
        assert _parse_partition_offset("") == 0


class TestRunMmls:
    """Integration-style tests for run_mmls with mocked subprocess."""

    @patch("mulder.server.tools.extract.tsk.require_binary", return_value=None)
    def test_missing_binary(self, mock_req: MagicMock) -> None:
        from mulder.server.tools.extract.tsk import run_mmls

        result = run_mmls.__wrapped__("/fake/image.dd")  # type: ignore[attr-defined]
        assert result["status"] == "error"
        assert result["error_type"] == "binary_missing"

    @patch("mulder.server.tools.extract.tsk.require_binary", return_value="/usr/bin/mmls")
    @patch("mulder.server.tools.extract.tsk.subprocess.run")
    def test_no_partition_table_error(self, mock_run: MagicMock, mock_req: MagicMock) -> None:
        from mulder.server.tools.extract.tsk import run_mmls

        mock_run.return_value = subprocess.CompletedProcess(
            args=["mmls", "/fake/image.dd"],
            returncode=1,
            stdout="",
            stderr="",
        )
        result = run_mmls.__wrapped__("/fake/image.dd")  # type: ignore[attr-defined]
        assert result["status"] == "error"
        assert result["error_type"] == "no_partition_table"
        assert "suggestion" in result
        assert "partition_offset=0" in result["suggestion"]

    @patch("mulder.server.tools.extract.tsk.require_binary", return_value="/usr/bin/mmls")
    @patch("mulder.server.tools.extract.tsk.subprocess.run")
    def test_ewf_error(self, mock_run: MagicMock, mock_req: MagicMock) -> None:
        from mulder.server.tools.extract.tsk import run_mmls

        mock_run.return_value = subprocess.CompletedProcess(
            args=["mmls", "/fake/image.E01"],
            returncode=1,
            stdout="",
            stderr="Cannot determine file type (libewf)",
        )
        result = run_mmls.__wrapped__("/fake/image.E01")  # type: ignore[attr-defined]
        assert result["status"] == "error"
        assert result["error_type"] == "ewf_unsupported"
        assert "suggestion" in result

    @patch("mulder.server.tools.extract.tsk.require_binary", return_value="/usr/bin/mmls")
    @patch("mulder.server.tools.extract.tsk.subprocess.run")
    def test_generic_mmls_error(self, mock_run: MagicMock, mock_req: MagicMock) -> None:
        from mulder.server.tools.extract.tsk import run_mmls

        mock_run.return_value = subprocess.CompletedProcess(
            args=["mmls", "/fake/image.dd"],
            returncode=1,
            stdout="",
            stderr="Cannot determine partition type",
        )
        result = run_mmls.__wrapped__("/fake/image.dd")  # type: ignore[attr-defined]
        assert result["status"] == "error"
        assert result["error_type"] == "mmls_failed"
        assert "suggestion" in result

    @patch("mulder.server.tools.extract.tsk.require_binary", return_value="/usr/bin/mmls")
    @patch(
        "mulder.server.tools.extract.tsk.subprocess.run",
        side_effect=subprocess.TimeoutExpired("mmls", 60),
    )
    def test_timeout(self, mock_run: MagicMock, mock_req: MagicMock) -> None:
        from mulder.server.tools.extract.tsk import run_mmls

        result = run_mmls.__wrapped__("/fake/image.dd")  # type: ignore[attr-defined]
        assert result["status"] == "error"
        assert result["error_type"] == "timeout"
