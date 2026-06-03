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

    def test_ntfs_partition_simple_slot_format(self) -> None:
        """Slot format without spaces (e.g. TSK compact output)."""
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

    def test_ntfs_partition_spaced_slot_format(self) -> None:
        """Slot format with spaces between parts (standard TSK 4.x output)."""
        mmls_output = (
            "DOS Partition Table\n"
            "Offset Sector: 0\n"
            "Units are in 512-byte sectors\n"
            "\n"
            "      Slot      Start        End          Length       Description\n"
            "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
            "001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
            "002:  000:000   0000002048   0041943039   0041940992   NTFS / exFAT (0x07)\n"
            "003:  -------   0041943040   0041943039   0000000000   Unallocated\n"
        )
        offset = _parse_partition_offset(mmls_output)
        assert offset == 2048

    def test_ntfs_partition_with_leading_whitespace(self) -> None:
        """Lines with leading whitespace for column alignment."""
        mmls_output = (
            "DOS Partition Table\n"
            "Offset Sector: 0\n"
            "Units are in 512-byte sectors\n"
            "\n"
            "      Slot      Start        End          Length       Description\n"
            "  000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
            "  001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
            "  002:  000:000   0000002048   0060823551   0060821504   NTFS (0x07)\n"
        )
        offset = _parse_partition_offset(mmls_output)
        assert offset == 2048

    def test_gpt_basic_data_partition(self) -> None:
        """GPT partition table with 'Basic data partition' description."""
        mmls_output = (
            "GUID Partition Table (EFI)\n"
            "Offset Sector: 0\n"
            "Units are in 512-byte sectors\n"
            "\n"
            "      Slot      Start        End          Length       Description\n"
            "000:  000   0000000034   0000032767   0000032734   Microsoft reserved partition\n"
            "001:  001   0000032768   0976564223   0976531456   Basic data partition\n"
            "002:  002   0976564224   0976773134   0000208911   EFI System partition\n"
        )
        offset = _parse_partition_offset(mmls_output)
        assert offset == 32768

    def test_linux_partition_fallback(self) -> None:
        """Falls back to Linux partition when no NTFS found."""
        mmls_output = (
            "DOS Partition Table\n001:000   0000002048   0000206847   0000204800   Linux (0x83)\n"
        )
        offset = _parse_partition_offset(mmls_output)
        assert offset == 2048

    def test_fallback_to_largest_partition(self) -> None:
        """Falls back to largest partition when no known type matches."""
        mmls_output = (
            "DOS Partition Table\n"
            "001:000   0000000063   0000001000   0000000937   Unknown Type\n"
            "002:000   0000002048   0041943039   0041940992   Some Other Type\n"
        )
        offset = _parse_partition_offset(mmls_output)
        assert offset == 2048

    def test_empty_string_returns_zero(self) -> None:
        assert _parse_partition_offset("") == 0

    def test_no_data_rows_returns_zero(self) -> None:
        mmls_output = "DOS Partition Table\nOffset Sector: 0\n"
        assert _parse_partition_offset(mmls_output) == 0


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


class TestRunFlsRetry:
    """Tests for run_fls self-contained mmls retry when partition_offset is None."""

    @patch("mulder.server.tools.extract.tsk.extract_and_index")
    @patch("mulder.server.tools.extract.tsk.require_binary", return_value="/usr/bin/fls")
    @patch("mulder.server.tools.extract.tsk.sources_already_indexed", return_value=[])
    @patch("mulder.server.tools.extract.tsk.get_ctx")
    @patch("mulder.server.tools.extract.tsk.subprocess.run")
    def test_retry_with_mmls_on_offset_zero_failure(
        self,
        mock_run: MagicMock,
        mock_ctx: MagicMock,
        mock_sources: MagicMock,
        mock_req: MagicMock,
        mock_extract: MagicMock,
    ) -> None:
        """run_fls retries with mmls-detected offset when offset 0 fails."""
        from mulder.server.tools.extract.tsk import run_fls

        mock_db = MagicMock()
        mock_db.get_kv.return_value = None
        mock_ctx.return_value.db = mock_db
        mock_extract.return_value = {"indexed": True}

        mmls_output = (
            "DOS Partition Table\n"
            "002:  000:000   0000002048   0041943039   0041940992   NTFS / exFAT (0x07)\n"
        )

        fls_fail = subprocess.CompletedProcess(
            args=["fls", "-r", "-p", "/fake/image.E01"],
            returncode=1,
            stdout=b"",
            stderr=b"Cannot determine file system type",
        )
        mmls_success = subprocess.CompletedProcess(
            args=["mmls", "/fake/image.E01"],
            returncode=0,
            stdout=mmls_output,
            stderr="",
        )
        fls_success = subprocess.CompletedProcess(
            args=["fls", "-r", "-p", "-o", "2048", "/fake/image.E01"],
            returncode=0,
            stdout=b"r/r 66-128-3:\tWindows/System32/config/SYSTEM\n",
            stderr=b"",
        )
        mock_run.side_effect = [fls_fail, mmls_success, fls_success]

        result = run_fls.__wrapped__(  # type: ignore[attr-defined]
            "/fake/image.E01", partition_offset=None
        )
        assert result["status"] == "success"
        mock_db.set_kv.assert_called_with("tsk_partition_offset:/fake/image.E01", "2048")

    @patch("mulder.server.tools.extract.tsk.extract_and_index")
    @patch("mulder.server.tools.extract.tsk.require_binary", return_value="/usr/bin/fls")
    @patch("mulder.server.tools.extract.tsk.sources_already_indexed", return_value=[])
    @patch("mulder.server.tools.extract.tsk.get_ctx")
    @patch("mulder.server.tools.extract.tsk.subprocess.run")
    def test_offset_zero_succeeds_without_retry(
        self,
        mock_run: MagicMock,
        mock_ctx: MagicMock,
        mock_sources: MagicMock,
        mock_req: MagicMock,
        mock_extract: MagicMock,
    ) -> None:
        """run_fls succeeds on offset 0 for partition-dump images without retry."""
        from mulder.server.tools.extract.tsk import run_fls

        mock_db = MagicMock()
        mock_db.get_kv.return_value = None
        mock_ctx.return_value.db = mock_db
        mock_extract.return_value = {"indexed": True}

        fls_success = subprocess.CompletedProcess(
            args=["fls", "-r", "-p", "/fake/partition.dd"],
            returncode=0,
            stdout=b"r/r 66-128-3:\tWindows/System32/config/SYSTEM\n",
            stderr=b"",
        )
        mock_run.return_value = fls_success

        result = run_fls.__wrapped__(  # type: ignore[attr-defined]
            "/fake/partition.dd", partition_offset=None
        )
        assert result["status"] == "success"
        mock_run.assert_called_once()
        mock_db.set_kv.assert_called_with("tsk_partition_offset:/fake/partition.dd", "0")
