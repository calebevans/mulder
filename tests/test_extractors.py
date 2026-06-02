"""Tests for Tier 1 extractor output parsing with canned fixtures."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from mulder.extractors.base import ExtractionResult
from mulder.extractors.sleuthkit import SleuthKitExtractor, _parse_partition_offset
from mulder.extractors.volatility import VolatilityExtractor, _plugin_short_name

# --- Canned output fixtures ---

VOLATILITY_PSLIST_OUTPUT = """\
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime
4	0	System	0xfa8000c7e040	108	0		False	2025-01-15 07:58:31.000000	N/A
308	4	smss.exe	0xfa8001a48b30	2	29		False	2025-01-15 07:58:31.000000	N/A
388	308	csrss.exe	0xfa8001a9eb30	10	425	0	False	2025-01-15 07:58:33.000000	N/A
432	308	wininit.exe	0xfa8001ab4b30	3	75	0	False	2025-01-15 07:58:34.000000	N/A
1234	432	cmd.exe	0xfa8002b12b30	1	18	1	False	2025-01-15 08:15:00.000000	N/A
5678	1234	spinlock.exe	0xfa8003c450	4	112	1	False	2025-01-15 08:30:00	N/A"""

FLS_OUTPUT = """\
r/r 66-128-1:	Windows/System32/config/SAM
r/r 67-128-1:	Windows/System32/config/SECURITY
r/r 68-128-1:	Windows/System32/config/SOFTWARE
r/r 69-128-1:	Windows/System32/config/SYSTEM
d/d 70-144-4:	Windows/System32/drivers
r/r * 71-128-1:	Windows/Temp/malware.exe
r/r 72-128-1:	Users/admin/Desktop/notes.txt"""

MMLS_OUTPUT = """\
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:000   0000002048   0001023999   0001021952   NTFS / exFAT (0x07)
000:001   0001024000   0001048575   0000024576   Unallocated"""


class TestVolatilityExtractor:
    """Tests for Volatility extractor output parsing."""

    def test_parse_volatility_pslist(self) -> None:
        """Volatility pslist output parsed into correct ExtractionResult."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = VOLATILITY_PSLIST_OUTPUT
        mock_proc.stderr = ""

        with (
            patch("subprocess.run", return_value=mock_proc),
            patch("shutil.which", return_value="/usr/bin/vol"),
        ):
            result = VolatilityExtractor._run_plugin(
                ["vol"],
                Path("/evidence/memdump.mem"),
                "windows.pslist.PsList",
                timeout=60,
            )

        assert result is not None
        assert isinstance(result, ExtractionResult)
        assert result.source_name == "volatility.pslist"
        assert result.extractor == "volatility3"
        assert result.line_count == VOLATILITY_PSLIST_OUTPUT.count("\n") + 1
        assert "cmd.exe" in result.text_output
        assert "spinlock.exe" in result.text_output

    def test_plugin_failure_returns_none(self) -> None:
        """Failed plugin invocation returns None."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Unsupported plugin"

        with (
            patch("subprocess.run", return_value=mock_proc),
            patch("shutil.which", return_value="/usr/bin/vol"),
        ):
            result = VolatilityExtractor._run_plugin(
                ["vol"],
                Path("/evidence/memdump.mem"),
                "windows.pslist.PsList",
                timeout=60,
            )

        assert result is None

    def test_empty_output_returns_none(self) -> None:
        """Plugin that produces no output returns None."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""

        with (
            patch("subprocess.run", return_value=mock_proc),
            patch("shutil.which", return_value="/usr/bin/vol"),
        ):
            result = VolatilityExtractor._run_plugin(
                ["vol"],
                Path("/evidence/memdump.mem"),
                "windows.malfind.Malfind",
                timeout=60,
            )

        assert result is None


class TestPluginShortName:
    """Tests for plugin name extraction helper."""

    def test_standard_plugin_name(self) -> None:
        """Standard three-part plugin path extracts middle segment."""
        assert _plugin_short_name("windows.pslist.PsList") == "pslist"

    def test_linux_plugin_name(self) -> None:
        """Linux plugin path extracts correctly."""
        assert _plugin_short_name("linux.bash.Bash") == "bash"


class TestSleuthKitExtractor:
    """Tests for Sleuth Kit extractor output parsing."""

    def test_parse_fls_output(self) -> None:
        """TSK fls output parsed into file listing ExtractionResult."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = FLS_OUTPUT
        mock_proc.stderr = ""

        extractor = SleuthKitExtractor()

        with (
            patch("shutil.which", return_value="/usr/bin/fls"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = extractor._run_fls_listing("/evidence/disk.dd", offset=2048)

        assert result == FLS_OUTPUT
        assert "malware.exe" in result
        assert "SAM" in result

    def test_fls_failure_returns_empty(self) -> None:
        """Failed fls invocation returns empty string."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Cannot determine file system type"

        extractor = SleuthKitExtractor()

        with (
            patch("shutil.which", return_value="/usr/bin/fls"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = extractor._run_fls_listing("/evidence/disk.dd", offset=0)

        assert result == ""


class TestMmlsParsing:
    """Tests for mmls partition table offset parsing."""

    def test_parse_ntfs_partition(self) -> None:
        """NTFS partition offset correctly extracted from mmls output."""
        offset = _parse_partition_offset(MMLS_OUTPUT)
        assert offset == 2048

    def test_parse_empty_output(self) -> None:
        """Empty mmls output returns offset 0."""
        offset = _parse_partition_offset("")
        assert offset == 0

    def test_parse_linux_partition(self) -> None:
        """Linux partition type is detected when no NTFS present."""
        linux_mmls = """\
      Slot      Start        End          Length       Description
000:000   0000002048   0041943039   0041940992   Linux (0x83)"""
        offset = _parse_partition_offset(linux_mmls)
        assert offset == 2048
