"""Tests for mulder.server.tools.extract.disk_pcap.

Covers PCAP discovery from fls output, size filtering, protocol
analysis, credential extraction, IDS integration, source naming,
empty results, multiple PCAPs, and corrupt file handling.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from mulder.server.tools.extract.disk_pcap import (
    _CREDENTIAL_FILTERS,
    _discover_pcap_files,
    _extract_credentials,
    _run_tshark_summary,
)

# ---------------------------------------------------------------------------
# Sample fls output for testing discovery
# ---------------------------------------------------------------------------

_FLS_WITH_PCAPS = (
    "r/r 1001:\tDocuments and Settings/Admin/My Documents/capture_20040315.pcap\n"
    "r/r 1002:\tDocuments and Settings/Admin/Desktop/network.pcapng\n"
    "r/r 1003:\tProgram Files/Wireshark/readme.txt\n"
    "r/r 1004:\ttmp/tcpdump_out.cap\n"
    "r/r 1005:\tvar/log/syslog\n"
    "r/r 1006:\tDocuments and Settings/Admin/ethereal.eth\n"
    "r/r 1007:\tDocuments and Settings/Admin/sunsnoop.snoop\n"
)

_FLS_NO_PCAPS = (
    "r/r 2001:\tDocuments and Settings/Admin/report.docx\n"
    "r/r 2002:\tProgram Files/App/config.ini\n"
    "r/r 2003:\tWindows/System32/kernel32.dll\n"
)

_FLS_MULTI_PCAPS = (
    "r/r 3001:\tCaptures/internal_scan.pcap\n"
    "r/r 3002:\tCaptures/external_traffic.pcapng\n"
    "r/r 3003:\tCaptures/wifi_monitor.cap\n"
)


class TestDiscoverPcapFiles:
    """Tests for _discover_pcap_files discovery logic."""

    def test_discovers_all_pcap_extensions(self) -> None:
        """Finds .pcap, .pcapng, .cap, .eth, and .snoop files."""
        matches = _discover_pcap_files([_FLS_WITH_PCAPS], offset=63)
        filenames = [m[1] for m in matches]
        assert len(matches) == 5
        assert any(".pcap" in f for f in filenames)
        assert any(".pcapng" in f for f in filenames)
        assert any(".cap" in f for f in filenames)
        assert any(".eth" in f for f in filenames)
        assert any(".snoop" in f for f in filenames)

    def test_ignores_non_pcap_files(self) -> None:
        """Does not match .txt, .docx, .dll, or extensionless files."""
        matches = _discover_pcap_files([_FLS_WITH_PCAPS], offset=63)
        filenames = [m[1] for m in matches]
        assert not any("readme.txt" in f for f in filenames)
        assert not any("syslog" in f for f in filenames)

    def test_no_pcaps_returns_empty(self) -> None:
        """Returns empty list when no PCAP files exist."""
        matches = _discover_pcap_files([_FLS_NO_PCAPS], offset=63)
        assert matches == []

    def test_multiple_pcaps_discovered(self) -> None:
        """Returns all three PCAPs from a multi-file listing."""
        matches = _discover_pcap_files([_FLS_MULTI_PCAPS], offset=63)
        assert len(matches) == 3
        filenames = [m[1] for m in matches]
        assert "Captures/internal_scan.pcap" in filenames
        assert "Captures/external_traffic.pcapng" in filenames
        assert "Captures/wifi_monitor.cap" in filenames

    def test_deduplicates_same_inode_and_offset(self) -> None:
        """Same inode at same offset is not returned twice."""
        duplicate_fls = "r/r 4001:\tCaptures/test.pcap\nr/r 4001:\tCaptures/test.pcap\n"
        matches = _discover_pcap_files([duplicate_fls], offset=63)
        assert len(matches) == 1

    def test_case_insensitive_extension_matching(self) -> None:
        """Matches .PCAP and .Pcap as well as lowercase."""
        fls = "r/r 5001:\tCaptures/upper.PCAP\nr/r 5002:\tCaptures/mixed.PcApNg\n"
        matches = _discover_pcap_files([fls], offset=63)
        assert len(matches) == 2

    def test_preserves_partition_offset(self) -> None:
        """Returned tuples contain the correct partition offset."""
        matches = _discover_pcap_files([_FLS_MULTI_PCAPS], offset=128)
        for _inode, _path, offset in matches:
            assert offset == 128


class TestExtractCredentials:
    """Tests for the _extract_credentials function."""

    @patch("mulder.server.tools.extract.disk_pcap.subprocess.run")
    def test_ftp_credentials_extracted(self, mock_run: MagicMock) -> None:
        """FTP USER/PASS lines are parsed into credential records."""
        ftp_output = "2004-03-15 12:00:00\t192.168.1.10\t10.0.0.1\tUSER admin"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=ftp_output,
        )

        creds = _extract_credentials(Path("/tmp/test.pcap"))
        ftp_creds = [c for c in creds if c["protocol"] == "ftp_credentials"]
        assert len(ftp_creds) >= 1
        assert ftp_creds[0]["source_ip"] == "192.168.1.10"
        assert ftp_creds[0]["dest_ip"] == "10.0.0.1"
        assert "admin" in ftp_creds[0]["raw_data"]

    @patch("mulder.server.tools.extract.disk_pcap.subprocess.run")
    def test_http_basic_auth_extracted(self, mock_run: MagicMock) -> None:
        """HTTP Basic Auth header is captured."""
        http_output = "2004-03-15 13:00:00\t192.168.1.10\t10.0.0.2\tBasic YWRtaW46cGFzcw=="
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=http_output,
        )

        creds = _extract_credentials(Path("/tmp/test.pcap"))
        http_creds = [c for c in creds if c["protocol"] == "http_basic_auth"]
        assert len(http_creds) >= 1
        assert "Basic" in http_creds[0]["raw_data"]

    @patch("mulder.server.tools.extract.disk_pcap.subprocess.run")
    def test_empty_credentials_on_encrypted_traffic(self, mock_run: MagicMock) -> None:
        """Returns empty list when no cleartext credentials found."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
        )

        creds = _extract_credentials(Path("/tmp/encrypted.pcap"))
        assert creds == []

    @patch("mulder.server.tools.extract.disk_pcap.subprocess.run")
    def test_tshark_failure_handled_gracefully(self, mock_run: MagicMock) -> None:
        """tshark errors do not crash; returns empty list."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
        )

        creds = _extract_credentials(Path("/tmp/corrupt.pcap"))
        assert creds == []

    @patch("mulder.server.tools.extract.disk_pcap.subprocess.run")
    def test_timeout_handled_gracefully(self, mock_run: MagicMock) -> None:
        """Subprocess timeout does not crash; returns empty list."""
        from subprocess import TimeoutExpired

        mock_run.side_effect = TimeoutExpired(cmd="tshark", timeout=30)

        creds = _extract_credentials(Path("/tmp/huge.pcap"))
        assert creds == []

    def test_credential_filters_cover_required_protocols(self) -> None:
        """Verify all required protocol filters are defined."""
        assert "ftp_credentials" in _CREDENTIAL_FILTERS
        assert "http_basic_auth" in _CREDENTIAL_FILTERS
        assert "smtp_auth" in _CREDENTIAL_FILTERS
        assert "telnet_data" in _CREDENTIAL_FILTERS
        assert "pop3_credentials" in _CREDENTIAL_FILTERS
        assert "imap_login" in _CREDENTIAL_FILTERS


class TestTsharkSummary:
    """Tests for the _run_tshark_summary function."""

    @patch("mulder.server.tools.extract.disk_pcap.subprocess.run")
    def test_produces_protocol_hierarchy(self, mock_run: MagicMock) -> None:
        """Successful tshark run produces protocol hierarchy output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Protocol Hierarchy Statistics\n  eth  100.0%\n    ip  100.0%\n",
            stderr="",
        )

        output = _run_tshark_summary(Path("/tmp/test.pcap"))
        assert "Protocol Hierarchy" in output

    @patch("mulder.server.tools.extract.disk_pcap.subprocess.run")
    def test_tshark_error_reported(self, mock_run: MagicMock) -> None:
        """tshark errors are reported in output without crashing."""
        mock_run.return_value = MagicMock(
            returncode=2,
            stdout="",
            stderr="tshark: The file isn't a capture file",
        )

        output = _run_tshark_summary(Path("/tmp/corrupt.pcap"))
        assert "tshark error" in output

    @patch("mulder.server.tools.extract.disk_pcap.subprocess.run")
    def test_timeout_reported(self, mock_run: MagicMock) -> None:
        """Timeout during tshark is reported without crashing."""
        from subprocess import TimeoutExpired

        mock_run.side_effect = TimeoutExpired(cmd="tshark", timeout=120)

        output = _run_tshark_summary(Path("/tmp/large.pcap"))
        assert "timed out" in output


class TestAnalyzeDiskPcapsTool:
    """Integration tests for the analyze_disk_pcaps MCP tool."""

    @staticmethod
    def _get_sync_fn() -> Any:
        """Get the unwrapped sync function from the tool dispatch."""
        from mulder.server.app import _tool_dispatch_sync

        return _tool_dispatch_sync["analyze_disk_pcaps"]

    @patch("mulder.server.tools.extract.disk_pcap.require_binary")
    @patch("mulder.server.tools.extract.disk_pcap._collect_fls_chunks")
    @patch("mulder.server.tools.extract.disk_pcap.get_ctx")
    def test_no_filelist_returns_error(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_binary: MagicMock,
    ) -> None:
        """When no TSK file listing exists, returns an error."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_binary.return_value = True
        mock_chunks.return_value = []

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
        )
        assert result["status"] == "error"
        assert result["error_type"] == "no_filelist"
        assert result["outcome"]["status"] == "UNAVAILABLE"

    @patch("mulder.server.tools.extract.disk_pcap.require_binary")
    @patch("mulder.server.tools.extract.disk_pcap._collect_fls_chunks")
    @patch("mulder.server.tools.extract.disk_pcap.get_ctx")
    def test_no_pcaps_found_returns_zero_results(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_binary: MagicMock,
    ) -> None:
        """Returns informative message when no PCAPs in file listing."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_binary.return_value = True
        mock_chunks.return_value = [([_FLS_NO_PCAPS], 63)]

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
        )
        assert result["status"] == "success"
        assert result["results"]["pcaps_discovered"] == 0
        assert result["results"]["pcaps_analyzed"] == 0
        assert result["outcome"]["status"] == "SUCCESS_EMPTY"

    @patch("mulder.server.tools.extract.disk_pcap.extract_and_index")
    @patch("mulder.server.tools.extract.disk_pcap._extract_pcap_via_icat")
    @patch("mulder.server.tools.extract.disk_pcap._run_tshark_summary")
    @patch("mulder.server.tools.extract.disk_pcap.require_binary")
    @patch("mulder.server.tools.extract.disk_pcap._collect_fls_chunks")
    @patch("mulder.server.tools.extract.disk_pcap.get_ctx")
    def test_size_filtering_skips_large_pcaps(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_binary: MagicMock,
        mock_tshark: MagicMock,
        mock_icat: MagicMock,
        mock_index: MagicMock,
    ) -> None:
        """PCAPs exceeding max_pcap_size_mb are skipped."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_binary.return_value = True

        fls = "r/r 9001:\tCaptures/huge.pcap\n"
        mock_chunks.return_value = [([fls], 63)]

        def fake_icat(image_path: str, inode: str, offset: int, dest: Path) -> bool:
            dest.write_bytes(b"\x00" * (200 * 1024 * 1024))
            return True

        mock_icat.side_effect = fake_icat

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            max_pcap_size_mb=100,
            run_ids=False,
            extract_credentials=False,
        )
        assert result["status"] == "success"
        assert "Captures/huge.pcap" in result["results"]["pcaps_skipped_oversize"]
        assert result["results"]["pcaps_analyzed"] == 0
        assert result["outcome"]["status"] == "PARTIAL"
        assert result["outcome"]["coverage"]["rows_examined"] == 0
        assert result["outcome"]["coverage"]["rows_total"] == 1

    @patch("mulder.server.tools.extract.disk_pcap.extract_and_index")
    @patch("mulder.server.tools.extract.disk_pcap._extract_pcap_via_icat")
    @patch("mulder.server.tools.extract.disk_pcap._run_tshark_summary")
    @patch("mulder.server.tools.extract.disk_pcap._extract_credentials")
    @patch("mulder.server.tools.extract.disk_pcap.require_binary")
    @patch("mulder.server.tools.extract.disk_pcap._collect_fls_chunks")
    @patch("mulder.server.tools.extract.disk_pcap.get_ctx")
    def test_successful_analysis_pipeline(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_binary: MagicMock,
        mock_creds: MagicMock,
        mock_tshark: MagicMock,
        mock_icat: MagicMock,
        mock_index: MagicMock,
    ) -> None:
        """Successful discovery, extraction, and analysis produces results."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_binary.return_value = True

        fls = "r/r 6001:\tCaptures/network.pcap\n"
        mock_chunks.return_value = [([fls], 63)]

        def fake_icat(image_path: str, inode: str, offset: int, dest: Path) -> bool:
            dest.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
            return True

        mock_icat.side_effect = fake_icat
        mock_tshark.return_value = "=== Protocol Hierarchy ===\neth 100%"
        mock_creds.return_value = [
            {
                "protocol": "ftp_credentials",
                "timestamp": "t",
                "source_ip": "1.2.3.4",
                "dest_ip": "5.6.7.8",
                "raw_data": "USER admin",
            }
        ]
        mock_index.return_value = {"windows_indexed": 5, "status": "indexed"}

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            run_ids=False,
            extract_credentials=True,
        )
        assert result["status"] == "success"
        assert result["results"]["pcaps_discovered"] == 1
        assert result["results"]["pcaps_analyzed"] == 1
        assert result["results"]["total_credentials_found"] == 1
        assert result["results"]["analyses"][0]["source_name"] == "pcap.disk.network"

    @patch("mulder.server.tools.extract.disk_pcap.extract_and_index")
    @patch("mulder.server.tools.extract.disk_pcap._extract_pcap_via_icat")
    @patch("mulder.server.tools.extract.disk_pcap._run_tshark_summary")
    @patch("mulder.server.tools.extract.disk_pcap._extract_credentials")
    @patch("mulder.server.tools.extract.disk_pcap.require_binary")
    @patch("mulder.server.tools.extract.disk_pcap._collect_fls_chunks")
    @patch("mulder.server.tools.extract.disk_pcap.get_ctx")
    def test_multiple_pcaps_analyzed_independently(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_binary: MagicMock,
        mock_creds: MagicMock,
        mock_tshark: MagicMock,
        mock_icat: MagicMock,
        mock_index: MagicMock,
    ) -> None:
        """Each PCAP gets its own analysis and source name."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_binary.return_value = True
        mock_chunks.return_value = [([_FLS_MULTI_PCAPS], 63)]

        def fake_icat(image_path: str, inode: str, offset: int, dest: Path) -> bool:
            dest.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 50)
            return True

        mock_icat.side_effect = fake_icat
        mock_tshark.return_value = "=== Protocol Hierarchy ===\neth 100%"
        mock_creds.return_value = []
        mock_index.return_value = {"windows_indexed": 2, "status": "indexed"}

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            run_ids=False,
            extract_credentials=True,
        )
        assert result["status"] == "success"
        assert result["results"]["pcaps_discovered"] == 3
        assert result["results"]["pcaps_analyzed"] == 3
        source_names = [a["source_name"] for a in result["results"]["analyses"]]
        assert "pcap.disk.internal_scan" in source_names
        assert "pcap.disk.external_traffic" in source_names
        assert "pcap.disk.wifi_monitor" in source_names

    @patch("mulder.server.tools.extract.disk_pcap._extract_pcap_via_icat")
    @patch("mulder.server.tools.extract.disk_pcap.require_binary")
    @patch("mulder.server.tools.extract.disk_pcap._collect_fls_chunks")
    @patch("mulder.server.tools.extract.disk_pcap.get_ctx")
    def test_corrupt_pcap_handled_without_crash(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_binary: MagicMock,
        mock_icat: MagicMock,
    ) -> None:
        """A file that fails icat extraction is reported in failures."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_binary.return_value = True

        fls = "r/r 7001:\tCaptures/corrupt.pcap\n"
        mock_chunks.return_value = [([fls], 63)]
        mock_icat.return_value = False

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            run_ids=False,
            extract_credentials=False,
        )
        assert result["status"] == "success"
        assert result["results"]["pcaps_discovered"] == 1
        assert result["results"]["pcaps_analyzed"] == 0
        assert len(result["results"]["pcaps_failed"]) == 1
        assert "corrupt.pcap" in result["results"]["pcaps_failed"][0]["filename"]

    @patch("mulder.server.tools.extract.disk_pcap.require_binary")
    @patch("mulder.server.tools.extract.disk_pcap.get_ctx")
    def test_missing_tshark_returns_error(
        self,
        mock_ctx: MagicMock,
        mock_binary: MagicMock,
    ) -> None:
        """Missing tshark binary returns a binary_missing error."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx

        def check_binary(name: str) -> bool:
            return name != "tshark"

        mock_binary.side_effect = check_binary

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
        )
        assert result["status"] == "error"
        assert result["error_type"] == "binary_missing"

    @patch("mulder.server.tools.extract.disk_pcap.require_binary")
    @patch("mulder.server.tools.extract.disk_pcap.get_ctx")
    def test_missing_icat_returns_error(
        self,
        mock_ctx: MagicMock,
        mock_binary: MagicMock,
    ) -> None:
        """Missing icat binary returns a binary_missing error."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx

        def check_binary(name: str) -> bool:
            return name != "icat"

        mock_binary.side_effect = check_binary

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
        )
        assert result["status"] == "error"
        assert result["error_type"] == "binary_missing"
