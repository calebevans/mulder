"""Tests for NTUSER.DAT and UsrClass.dat hive discovery and parsing.

Covers username extraction, hive discovery from fls output, plugin
selection, source naming, isolated error handling, and the
include_user_hives parameter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from mulder.server.tools.extract.registry import (
    _NTUSER_PLUGINS,
    _USRCLASS_PLUGINS,
    _discover_user_hives_via_tsk,
    _extract_username,
    _parse_all_user_hives,
)


class TestExtractUsername:
    """Tests for _extract_username."""

    def test_xp_style_path(self) -> None:
        """XP-style path extracts the correct username."""
        result = _extract_username("Documents and Settings/Administrator/NTUSER.DAT")
        assert result == "Administrator"

    def test_modern_style_path(self) -> None:
        """Vista+ style path extracts the correct username."""
        result = _extract_username("Users/jdoe/NTUSER.DAT")
        assert result == "jdoe"

    def test_case_insensitive(self) -> None:
        """Matching is case-insensitive for the directory prefix."""
        result = _extract_username("users/Alice/NTUSER.DAT")
        assert result == "Alice"

    def test_usrclass_xp_path(self) -> None:
        """XP-style UsrClass.dat path extracts the username."""
        result = _extract_username(
            "Documents and Settings/bob/Local Settings/"
            "Application Data/Microsoft/Windows/UsrClass.dat"
        )
        assert result == "bob"

    def test_usrclass_modern_path(self) -> None:
        """Modern UsrClass.dat path extracts the username."""
        result = _extract_username("Users/jdoe/AppData/Local/Microsoft/Windows/UsrClass.dat")
        assert result == "jdoe"

    def test_no_match_returns_none(self) -> None:
        """Paths not matching user profile patterns return None."""
        assert _extract_username("Windows/System32/config/SYSTEM") is None

    def test_nested_path(self) -> None:
        """Deeply nested user profile path still extracts username."""
        result = _extract_username("Users/testuser/AppData/Roaming/something/NTUSER.DAT")
        assert result == "testuser"


class TestDiscoverUserHivesViaTsk:
    """Tests for _discover_user_hives_via_tsk."""

    @staticmethod
    def _make_fls_line(inode: int, path: str) -> str:
        """Create a single fls output line."""
        return f"r/r {inode}:\t{path}"

    @patch("mulder.server.tools.extract.registry.subprocess.run")
    @patch("mulder.server.tools.extract.registry._collect_fls_chunks")
    def test_discovers_xp_ntuser(
        self,
        mock_chunks: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """Discovers NTUSER.DAT from XP-style Documents and Settings."""
        fls_output = "\n".join(
            [
                self._make_fls_line(1000, "Documents and Settings/Administrator/NTUSER.DAT"),
                self._make_fls_line(1001, "Documents and Settings/jdoe/NTUSER.DAT"),
                self._make_fls_line(500, "Windows/System32/config/SYSTEM"),
            ]
        )
        mock_chunks.return_value = [([fls_output], 0)]

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"fake hive data"
        mock_run.return_value = mock_proc

        hives, extract_dir = _discover_user_hives_via_tsk("/images/xp.dd")

        assert len(hives) == 2
        usernames = {h[2] for h in hives}
        assert "Administrator" in usernames
        assert "jdoe" in usernames
        assert all(h[1] == "ntuser" for h in hives)
        assert extract_dir is not None

    @patch("mulder.server.tools.extract.registry.subprocess.run")
    @patch("mulder.server.tools.extract.registry._collect_fls_chunks")
    def test_discovers_modern_ntuser(
        self,
        mock_chunks: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """Discovers NTUSER.DAT from modern Users directory."""
        fls_output = self._make_fls_line(2000, "Users/Alice/NTUSER.DAT")
        mock_chunks.return_value = [([fls_output], 128)]

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"fake hive data"
        mock_run.return_value = mock_proc

        hives, extract_dir = _discover_user_hives_via_tsk("/images/win10.dd")

        assert len(hives) == 1
        assert hives[0][1] == "ntuser"
        assert hives[0][2] == "Alice"

    @patch("mulder.server.tools.extract.registry.subprocess.run")
    @patch("mulder.server.tools.extract.registry._collect_fls_chunks")
    def test_discovers_usrclass(
        self,
        mock_chunks: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """Discovers UsrClass.dat files."""
        fls_output = self._make_fls_line(
            3000,
            "Users/jdoe/AppData/Local/Microsoft/Windows/UsrClass.dat",
        )
        mock_chunks.return_value = [([fls_output], 0)]

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"usrclass data"
        mock_run.return_value = mock_proc

        hives, _ = _discover_user_hives_via_tsk("/images/win10.dd")

        assert len(hives) == 1
        assert hives[0][1] == "usrclass"
        assert hives[0][2] == "jdoe"

    @patch("mulder.server.tools.extract.registry.subprocess.run")
    @patch("mulder.server.tools.extract.registry._collect_fls_chunks")
    def test_mixed_layout_discovery(
        self,
        mock_chunks: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """Both XP and modern user hive paths are discovered."""
        fls_output = "\n".join(
            [
                self._make_fls_line(1000, "Documents and Settings/olduser/NTUSER.DAT"),
                self._make_fls_line(2000, "Users/newuser/NTUSER.DAT"),
                self._make_fls_line(
                    3000,
                    "Users/newuser/AppData/Local/Microsoft/Windows/UsrClass.dat",
                ),
            ]
        )
        mock_chunks.return_value = [([fls_output], 0)]

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"data"
        mock_run.return_value = mock_proc

        hives, _ = _discover_user_hives_via_tsk("/images/dual.dd")

        assert len(hives) == 3
        types = {(h[1], h[2]) for h in hives}
        assert ("ntuser", "olduser") in types
        assert ("ntuser", "newuser") in types
        assert ("usrclass", "newuser") in types

    @patch("mulder.server.tools.extract.registry._collect_fls_chunks")
    def test_no_fls_data_returns_empty(self, mock_chunks: MagicMock) -> None:
        """Returns empty list when no fls data is available."""
        mock_chunks.return_value = []

        hives, extract_dir = _discover_user_hives_via_tsk("/images/empty.dd")

        assert hives == []
        assert extract_dir is None

    @patch("mulder.server.tools.extract.registry.subprocess.run")
    @patch("mulder.server.tools.extract.registry._collect_fls_chunks")
    def test_icat_failure_skips_hive(
        self,
        mock_chunks: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """If icat fails for a hive, it is skipped without crashing."""
        fls_output = "\n".join(
            [
                self._make_fls_line(1000, "Users/good/NTUSER.DAT"),
                self._make_fls_line(1001, "Users/bad/NTUSER.DAT"),
            ]
        )
        mock_chunks.return_value = [([fls_output], 0)]

        def side_effect(*args: Any, **kwargs: Any) -> MagicMock:
            cmd = args[0]
            if "1001" in cmd:
                result = MagicMock()
                result.returncode = 1
                result.stdout = b""
                return result
            result = MagicMock()
            result.returncode = 0
            result.stdout = b"good data"
            return result

        mock_run.side_effect = side_effect

        hives, _ = _discover_user_hives_via_tsk("/images/disk.dd")

        assert len(hives) == 1
        assert hives[0][2] == "good"


class TestParseAllUserHives:
    """Tests for _parse_all_user_hives and integration with run_registry_parser."""

    @patch("mulder.server.tools.extract.registry._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry._parse_single_hive")
    @patch("mulder.server.tools.extract.registry._discover_user_hives_via_tsk")
    def test_plugin_selection_ntuser(
        self,
        mock_discover: MagicMock,
        mock_parse: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """NTUSER.DAT hives are parsed with _NTUSER_PLUGINS."""
        hive_path = Path("/tmp/fake_ntuser")
        mock_discover.return_value = (
            [(hive_path, "ntuser", "jdoe")],
            "/tmp/extract",
        )
        mock_parse.return_value = {
            "source_name": "registry.ntuser.jdoe",
            "windows_indexed": 5,
        }

        results = _parse_all_user_hives("/images/disk.dd")

        assert len(results) == 1
        mock_parse.assert_called_once_with(
            hive_path, "registry.ntuser.jdoe", "/images/disk.dd", plugins=_NTUSER_PLUGINS
        )

    @patch("mulder.server.tools.extract.registry._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry._parse_single_hive")
    @patch("mulder.server.tools.extract.registry._discover_user_hives_via_tsk")
    def test_plugin_selection_usrclass(
        self,
        mock_discover: MagicMock,
        mock_parse: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """UsrClass.dat hives are parsed with _USRCLASS_PLUGINS."""
        hive_path = Path("/tmp/fake_usrclass")
        mock_discover.return_value = (
            [(hive_path, "usrclass", "alice")],
            "/tmp/extract",
        )
        mock_parse.return_value = {
            "source_name": "registry.usrclass.alice",
            "windows_indexed": 2,
        }

        results = _parse_all_user_hives("/images/disk.dd")

        assert len(results) == 1
        mock_parse.assert_called_once_with(
            hive_path, "registry.usrclass.alice", "/images/disk.dd", plugins=_USRCLASS_PLUGINS
        )

    @patch("mulder.server.tools.extract.registry._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry._parse_single_hive")
    @patch("mulder.server.tools.extract.registry._discover_user_hives_via_tsk")
    def test_source_naming(
        self,
        mock_discover: MagicMock,
        mock_parse: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """User hives are indexed with correct source naming pattern."""
        mock_discover.return_value = (
            [
                (Path("/tmp/ntuser"), "ntuser", "JDoe"),
                (Path("/tmp/usrclass"), "usrclass", "JDoe"),
            ],
            "/tmp/extract",
        )
        mock_parse.return_value = {"source_name": "test", "windows_indexed": 1}

        _parse_all_user_hives("/images/disk.dd")

        calls = mock_parse.call_args_list
        assert calls[0][0][1] == "registry.ntuser.jdoe"
        assert calls[1][0][1] == "registry.usrclass.jdoe"

    @patch("mulder.server.tools.extract.registry._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry._parse_single_hive")
    @patch("mulder.server.tools.extract.registry._discover_user_hives_via_tsk")
    def test_isolated_error_handling(
        self,
        mock_discover: MagicMock,
        mock_parse: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """A corrupted hive produces an error entry without stopping others."""
        mock_discover.return_value = (
            [
                (Path("/tmp/good"), "ntuser", "good_user"),
                (Path("/tmp/bad"), "ntuser", "bad_user"),
            ],
            "/tmp/extract",
        )

        def parse_side_effect(
            hive_path: Path, source_name: str, image_path: str, plugins: Any = None
        ) -> dict[str, Any]:
            if "bad_user" in source_name:
                raise RuntimeError("Corrupted hive")
            return {"source_name": source_name, "windows_indexed": 3}

        mock_parse.side_effect = parse_side_effect

        results = _parse_all_user_hives("/images/disk.dd")

        assert len(results) == 2
        good_result = next(r for r in results if "good_user" in r.get("source_name", ""))
        bad_result = next(r for r in results if "bad_user" in r.get("source_name", ""))
        assert good_result["windows_indexed"] == 3
        assert bad_result["status"] == "error"
        assert "bad_user" in bad_result["error"]

    @patch("mulder.server.tools.extract.registry._discover_user_hives_via_tsk")
    def test_no_user_hives_returns_empty(self, mock_discover: MagicMock) -> None:
        """Returns empty list when no user hives are found."""
        mock_discover.return_value = ([], None)

        results = _parse_all_user_hives("/images/disk.dd")

        assert results == []


class TestRunRegistryParserUserHives:
    """Tests for include_user_hives parameter on run_registry_parser."""

    @staticmethod
    def _get_sync_fn() -> Any:
        """Get the unwrapped sync function from the tool dispatch."""
        from mulder.server.app import _tool_dispatch_sync

        return _tool_dispatch_sync["run_registry_parser"]

    @patch("mulder.server.tools.extract.registry._parse_all_user_hives")
    @patch("mulder.server.tools.extract.registry._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry._parse_single_hive")
    @patch("mulder.server.tools.extract.registry._discover_hives_via_tsk")
    @patch("mulder.server.tools.extract.registry.sources_already_indexed")
    def test_include_user_hives_true_by_default(
        self,
        mock_indexed: MagicMock,
        mock_discover: MagicMock,
        mock_parse: MagicMock,
        mock_cleanup: MagicMock,
        mock_user_hives: MagicMock,
    ) -> None:
        """User hives are included by default."""
        fn = self._get_sync_fn()
        mock_indexed.return_value = []
        mock_discover.return_value = (
            [(Path("/tmp/system"), "system")],
            "/tmp/extract",
        )
        mock_parse.return_value = {"source_name": "registry.system", "windows_indexed": 10}
        mock_user_hives.return_value = [
            {"source_name": "registry.ntuser.admin", "windows_indexed": 5}
        ]

        fn(image_path="/images/disk.dd")

        mock_user_hives.assert_called_once_with("/images/disk.dd")

    @patch("mulder.server.tools.extract.registry._parse_all_user_hives")
    @patch("mulder.server.tools.extract.registry._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry._parse_single_hive")
    @patch("mulder.server.tools.extract.registry._discover_hives_via_tsk")
    @patch("mulder.server.tools.extract.registry.sources_already_indexed")
    def test_include_user_hives_false_skips_user_parsing(
        self,
        mock_indexed: MagicMock,
        mock_discover: MagicMock,
        mock_parse: MagicMock,
        mock_cleanup: MagicMock,
        mock_user_hives: MagicMock,
    ) -> None:
        """Setting include_user_hives=False skips user hive parsing."""
        fn = self._get_sync_fn()
        mock_indexed.return_value = []
        mock_discover.return_value = (
            [(Path("/tmp/system"), "system")],
            "/tmp/extract",
        )
        mock_parse.return_value = {"source_name": "registry.system", "windows_indexed": 10}

        fn(image_path="/images/disk.dd", include_user_hives=False)

        mock_user_hives.assert_not_called()

    @patch("mulder.server.tools.extract.registry._parse_all_user_hives")
    @patch("mulder.server.tools.extract.registry._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry._parse_single_hive")
    @patch("mulder.server.tools.extract.registry._discover_hives_via_tsk")
    @patch("mulder.server.tools.extract.registry.sources_already_indexed")
    def test_specific_hive_skips_user_hives(
        self,
        mock_indexed: MagicMock,
        mock_discover: MagicMock,
        mock_parse: MagicMock,
        mock_cleanup: MagicMock,
        mock_user_hives: MagicMock,
    ) -> None:
        """When a specific hive is requested, user hives are not parsed."""
        fn = self._get_sync_fn()
        mock_indexed.return_value = []
        mock_discover.return_value = (
            [(Path("/tmp/system"), "system")],
            "/tmp/extract",
        )
        mock_parse.return_value = {"source_name": "registry.system", "windows_indexed": 10}

        fn(image_path="/images/disk.dd", hive="system")

        mock_user_hives.assert_not_called()

    @patch("mulder.server.tools.extract.registry._parse_all_user_hives")
    @patch("mulder.server.tools.extract.registry._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry._parse_single_hive")
    @patch("mulder.server.tools.extract.registry._discover_hives_via_tsk")
    @patch("mulder.server.tools.extract.registry.sources_already_indexed")
    def test_skip_already_indexed(
        self,
        mock_indexed: MagicMock,
        mock_discover: MagicMock,
        mock_parse: MagicMock,
        mock_cleanup: MagicMock,
        mock_user_hives: MagicMock,
    ) -> None:
        """When registry sources are already indexed, skips everything."""
        fn = self._get_sync_fn()
        mock_indexed.return_value = ["registry.system", "registry.ntuser.jdoe"]

        result = fn(image_path="/images/disk.dd")

        assert result["status"] == "success"
        assert "skipped" in str(result.get("preview", ""))
        mock_discover.assert_not_called()
        mock_user_hives.assert_not_called()
