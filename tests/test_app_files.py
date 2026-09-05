"""Tests for mulder.server.tools.extract.app_files.

Covers file discovery from fls output, extension filtering, size limits,
file count caps, binary content detection, source name derivation, and
empty-result handling.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from mulder.server.tools.extract.app_files import (
    _DEFAULT_EXTENSIONS,
    _derive_source_name,
    _find_matching_files,
    _is_binary_content,
)

# Sample fls output lines for testing
_SAMPLE_FLS = (
    "r/r 1234:\tProgram Files/mIRC/mirc.ini\n"
    "r/r 1235:\tProgram Files/mIRC/mirc.exe\n"
    "r/r 1236:\tProgram Files/mIRC/servers.ini\n"
    "r/r 1237:\tProgram Files/mIRC/mirc.dll\n"
    "r/r 1238:\tProgram Files/mIRC/changelog.txt\n"
    "r/r 1239:\tProgram Files/mIRC/scripts/perform.ini\n"
    "r/r 1240:\tProgram Files/mIRC/data.dat\n"
    "r/r 1241:\tProgram Files/mIRC/debug.log\n"
)

_MULTI_USER_FLS = (
    "r/r 2001:\tDocuments and Settings/Alice/Application Data/Thunderbird/profiles.ini\n"
    "r/r 2002:\tDocuments and Settings/Alice/Application Data/Thunderbird/prefs.js\n"
    "r/r 2003:\tDocuments and Settings/Bob/Application Data/Thunderbird/profiles.ini\n"
    "r/r 2004:\tDocuments and Settings/Bob/Application Data/Thunderbird/config.cfg\n"
    "r/r 2005:\tDocuments and Settings/Bob/Application Data/Thunderbird/notes.txt\n"
)


class TestFindMatchingFiles:
    """Tests for _find_matching_files file discovery logic."""

    def test_basic_discovery_filters_by_extension(self) -> None:
        """Only .ini files are returned from a directory with mixed extensions."""
        matches = _find_matching_files(
            [_SAMPLE_FLS],
            "Program Files/mIRC",
            frozenset({".ini"}),
            offset=0,
        )
        paths = [m[1] for m in matches]
        assert len(paths) == 3
        assert all(p.endswith(".ini") for p in paths)
        assert "Program Files/mIRC/mirc.ini" in paths
        assert "Program Files/mIRC/servers.ini" in paths
        assert "Program Files/mIRC/scripts/perform.ini" in paths

    def test_default_extensions_include_ini_and_log(self) -> None:
        """Default extension set includes .ini, .log, and .txt but not .exe, .dll, .dat."""
        matches = _find_matching_files(
            [_SAMPLE_FLS],
            "Program Files/mIRC",
            _DEFAULT_EXTENSIONS,
            offset=0,
        )
        paths = [m[1] for m in matches]
        assert "Program Files/mIRC/mirc.ini" in paths
        assert "Program Files/mIRC/debug.log" in paths
        assert "Program Files/mIRC/changelog.txt" in paths
        assert "Program Files/mIRC/mirc.exe" not in paths
        assert "Program Files/mIRC/mirc.dll" not in paths
        assert "Program Files/mIRC/data.dat" not in paths

    def test_wildcard_pattern_matches_multiple_users(self) -> None:
        """Wildcard in pattern matches files across multiple user directories."""
        matches = _find_matching_files(
            [_MULTI_USER_FLS],
            "Documents and Settings/*/Application Data/Thunderbird",
            frozenset({".ini", ".cfg", ".txt"}),
            offset=0,
        )
        paths = [m[1] for m in matches]
        assert len(paths) == 4
        alice_paths = [p for p in paths if "Alice" in p]
        bob_paths = [p for p in paths if "Bob" in p]
        assert len(alice_paths) >= 1
        assert len(bob_paths) >= 1

    def test_custom_extensions(self) -> None:
        """Custom extension list overrides defaults."""
        fls = (
            "r/r 3001:\tAppDir/data.sqlite\n"
            "r/r 3002:\tAppDir/cache.db\n"
            "r/r 3003:\tAppDir/config.ini\n"
        )
        matches = _find_matching_files(
            [fls],
            "AppDir",
            frozenset({".sqlite", ".db"}),
            offset=0,
        )
        paths = [m[1] for m in matches]
        assert len(paths) == 2
        assert "AppDir/data.sqlite" in paths
        assert "AppDir/cache.db" in paths
        assert "AppDir/config.ini" not in paths

    def test_listing_alone_cannot_apply_a_size_limit(self) -> None:
        """``fls -r -p`` prints no size column, so nothing is filtered here.

        This test used to be called ``test_size_limit_with_tab_delimited_sizes``
        and claimed that "files with tab-delimited sizes above threshold are
        excluded" -- while asserting that all three files came back, from a
        fixture that contained no sizes at all. It documented a feature that
        never worked: sizes require ``fls -l``. The threshold is now applied
        to the bytes ``icat`` returns; see ``TestSizeLimitIsEnforced``.
        """
        fls = (
            "r/r 4001:\tSmallDir/small.txt\n"
            "r/r 4002:\tSmallDir/medium.txt\n"
            "r/r 4003:\tSmallDir/large.txt\n"
        )
        matches = _find_matching_files(
            [fls],
            "SmallDir",
            frozenset({".txt"}),
            offset=0,
        )
        assert len(matches) == 3

    def test_empty_pattern_no_matches(self) -> None:
        """Pattern matching no directory returns empty list."""
        matches = _find_matching_files(
            [_SAMPLE_FLS],
            "NonExistent/Directory",
            _DEFAULT_EXTENSIONS,
            offset=0,
        )
        assert matches == []

    def test_deduplicates_same_inode(self) -> None:
        """Same inode at same offset is not returned twice."""
        duplicate_fls = "r/r 5001:\tAppDir/config.ini\nr/r 5001:\tAppDir/config.ini\n"
        matches = _find_matching_files(
            [duplicate_fls],
            "AppDir",
            frozenset({".ini"}),
            offset=0,
        )
        assert len(matches) == 1

    def test_case_insensitive_matching(self) -> None:
        """Pattern matching is case-insensitive."""
        fls = "r/r 6001:\tPROGRAM FILES/MyApp/config.INI\n"
        matches = _find_matching_files(
            [fls],
            "program files/myapp",
            frozenset({".ini"}),
            offset=0,
        )
        assert len(matches) == 1


class TestDeriveSourceName:
    """Tests for source name derivation from directory patterns."""

    def test_simple_path(self) -> None:
        """Simple two-segment path produces expected source name."""
        assert _derive_source_name("Program Files/mIRC") == "appfiles.program_files.mirc"

    def test_wildcards_stripped(self) -> None:
        """Wildcard segments are removed from the source name."""
        result = _derive_source_name("Documents and Settings/*/Application Data")
        assert result == "appfiles.documents_and_settings.application_data"

    def test_backslash_path(self) -> None:
        """Backslash separators are normalized to forward slashes."""
        result = _derive_source_name("Program Files\\mIRC\\scripts")
        assert result == "appfiles.program_files.mirc.scripts"

    def test_truncated_to_three_segments(self) -> None:
        """Source name is capped at three path segments."""
        result = _derive_source_name("a/b/c/d/e")
        assert result == "appfiles.a.b.c"

    def test_spaces_replaced(self) -> None:
        """Spaces in path segments are replaced with underscores."""
        result = _derive_source_name("Program Files/My App")
        assert result == "appfiles.program_files.my_app"


class TestIsBinaryContent:
    """Tests for binary content detection."""

    def test_text_content_not_binary(self) -> None:
        """Plain text content is not flagged as binary."""
        assert _is_binary_content(b"Hello, world!\nLine 2\n") is False

    def test_binary_with_null_bytes(self) -> None:
        """Content with null bytes in first 1024 is flagged as binary."""
        data = b"MZ\x00\x00" + b"\x90" * 100
        assert _is_binary_content(data) is True

    def test_null_byte_after_1024_not_detected(self) -> None:
        """Null bytes after the first 1024 bytes are not checked."""
        data = b"A" * 1024 + b"\x00" * 100
        assert _is_binary_content(data) is False

    def test_empty_content_not_binary(self) -> None:
        """Empty content is not flagged as binary."""
        assert _is_binary_content(b"") is False


class TestIndexAppFilesTool:
    """Integration tests for the index_app_files MCP tool."""

    @staticmethod
    def _get_sync_fn() -> Any:
        """Get the unwrapped sync function from the tool dispatch."""
        from mulder.server.app import _tool_dispatch_sync

        return _tool_dispatch_sync["index_app_files"]

    @patch("mulder.server.tools.extract.app_files._collect_fls_chunks")
    @patch("mulder.server.tools.extract.app_files.get_ctx")
    def test_no_filelist_returns_error(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
    ) -> None:
        """When no TSK file listing exists, returns an error."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_chunks.return_value = []

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            directory_pattern="Program Files/mIRC",
        )
        assert result["status"] == "error"
        assert result["error_type"] == "no_filelist"

    @patch("mulder.server.tools.extract.app_files._collect_fls_chunks")
    @patch("mulder.server.tools.extract.app_files.get_ctx")
    def test_empty_directory_returns_zero_results(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
    ) -> None:
        """Pattern matching no files returns informative zero-result response."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_chunks.return_value = [([_SAMPLE_FLS], 63)]

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            directory_pattern="NonExistent/Path",
        )
        assert result["status"] == "success"
        assert result["results"]["files_discovered"] == 0
        assert "NonExistent/Path" in result["results"]["pattern"]

    @patch("mulder.server.tools.extract.app_files.extract_and_index")
    @patch("mulder.server.tools.extract.app_files._extract_and_read_file")
    @patch("mulder.server.tools.extract.app_files._collect_fls_chunks")
    @patch("mulder.server.tools.extract.app_files.get_ctx")
    def test_file_count_cap(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_extract: MagicMock,
        mock_index: MagicMock,
    ) -> None:
        """When more files match than max_files, only max_files are extracted."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx

        lines = "".join(f"r/r {7000 + i}:\tBigDir/file{i}.txt\n" for i in range(300))
        mock_chunks.return_value = [([lines], 63)]
        mock_extract.return_value = "[content]"
        mock_index.return_value = {"windows_indexed": 1}

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            directory_pattern="BigDir",
            max_files=50,
        )
        assert result["status"] == "success"
        assert result["results"]["files_discovered"] == 300
        assert result["results"]["files_capped_at"] == 50
        assert mock_extract.call_count == 50

    @patch("mulder.server.tools.extract.app_files.extract_and_index")
    @patch("mulder.server.tools.extract.app_files._extract_and_read_file")
    @patch("mulder.server.tools.extract.app_files._collect_fls_chunks")
    @patch("mulder.server.tools.extract.app_files.get_ctx")
    def test_binary_files_skipped(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_extract: MagicMock,
        mock_index: MagicMock,
    ) -> None:
        """Files that return None from extraction (binary) are skipped."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_chunks.return_value = [([_SAMPLE_FLS], 63)]
        mock_extract.return_value = None
        mock_index.return_value = {"windows_indexed": 1}

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            directory_pattern="Program Files/mIRC",
        )
        assert result["status"] == "success"
        assert result["results"]["files_extracted"] == 0
        assert result["results"]["files_skipped_binary"] > 0

    @patch("mulder.server.tools.extract.app_files.extract_and_index")
    @patch("mulder.server.tools.extract.app_files._extract_and_read_file")
    @patch("mulder.server.tools.extract.app_files._collect_fls_chunks")
    @patch("mulder.server.tools.extract.app_files.get_ctx")
    def test_successful_indexing(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_extract: MagicMock,
        mock_index: MagicMock,
    ) -> None:
        """Successfully discovered files are extracted and indexed."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_chunks.return_value = [([_SAMPLE_FLS], 63)]
        mock_extract.return_value = "[mIRC]\nnick=TestUser\nserver=irc.example.com\n"
        mock_index.return_value = {"windows_indexed": 2}

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            directory_pattern="Program Files/mIRC",
        )
        assert result["status"] == "success"
        assert result["results"]["files_indexed"] > 0
        assert result["results"]["source_prefix"] == "appfiles.program_files.mirc"
        assert len(result["results"]["sample_files"]) > 0

    @patch("mulder.server.tools.extract.app_files.extract_and_index")
    @patch("mulder.server.tools.extract.app_files._extract_and_read_file")
    @patch("mulder.server.tools.extract.app_files._collect_fls_chunks")
    @patch("mulder.server.tools.extract.app_files.get_ctx")
    def test_custom_extensions_passed_through(
        self,
        mock_ctx: MagicMock,
        mock_chunks: MagicMock,
        mock_extract: MagicMock,
        mock_index: MagicMock,
    ) -> None:
        """Custom extensions parameter filters to only specified extensions."""
        fn = self._get_sync_fn()
        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx

        fls = (
            "r/r 8001:\tAppDir/data.sqlite\n"
            "r/r 8002:\tAppDir/cache.db\n"
            "r/r 8003:\tAppDir/config.ini\n"
        )
        mock_chunks.return_value = [([fls], 63)]
        mock_extract.return_value = "some content"
        mock_index.return_value = {"windows_indexed": 1}

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            directory_pattern="AppDir",
            extensions=[".sqlite", ".db"],
        )
        assert result["status"] == "success"
        assert result["results"]["files_discovered"] == 2
        assert ".ini" not in str(result["results"]["sample_files"])


class TestSizeLimitIsEnforced:
    """`max_file_size_kb` is applied to the bytes icat returns.

    It used to be checked against a size field parsed out of the fls
    listing with a ``\\t(digits)\\t`` regex. ``fls -r -p`` prints one tab
    per line and no size column -- sizes need ``fls -l`` -- so that search
    never matched and the threshold never skipped anything.
    """

    @staticmethod
    def _read(payload: bytes, max_size_bytes: int | None):  # type: ignore[no-untyped-def]
        import subprocess
        from unittest.mock import patch

        from mulder.server.tools.extract import app_files as af

        proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=payload)
        with (
            patch.object(af.shutil, "which", return_value="/usr/bin/icat"),
            patch.object(af.subprocess, "run", return_value=proc),
        ):
            return af._extract_and_read_file("/img.raw", "710", 0, max_size_bytes=max_size_bytes)

    def test_a_file_over_the_threshold_is_skipped(self) -> None:
        assert self._read(b"x" * 2048, 1024) is None

    def test_a_file_under_the_threshold_is_read(self) -> None:
        assert self._read(b"hello world", 1024) == "hello world"

    def test_a_file_exactly_at_the_threshold_is_read(self) -> None:
        assert self._read(b"x" * 1024, 1024) is not None

    def test_no_threshold_reads_everything(self) -> None:
        assert self._read(b"x" * 100_000, None) is not None
