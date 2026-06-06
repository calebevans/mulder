"""Tests for mulder.server.tools.extract.registry_query.

Covers value decoding, FILETIME conversion, hive extraction logic,
key/value enumeration, and error handling paths.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from mulder.server.tools.extract.registry_query import (
    _decode_registry_value,
    _try_decode_filetime,
)


class TestTryDecodeFiletime:
    """Tests for FILETIME binary decoding."""

    def test_valid_filetime_returns_iso_timestamp(self) -> None:
        """Known FILETIME for 2023-06-15T12:00:00Z decodes correctly."""
        dt = datetime(2023, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        ticks = int((dt - epoch).total_seconds() * 10_000_000)
        raw = ticks.to_bytes(8, "little")
        result = _try_decode_filetime(raw)
        assert result is not None
        assert result.startswith("2023-06-15T12:00:00")

    def test_zero_value_returns_none(self) -> None:
        """All-zero bytes should not be treated as a valid timestamp."""
        raw = b"\x00" * 8
        assert _try_decode_filetime(raw) is None

    def test_out_of_range_value_returns_none(self) -> None:
        """Timestamps before 1980 should be rejected."""
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc)
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        ticks = int((dt - epoch).total_seconds() * 10_000_000)
        raw = ticks.to_bytes(8, "little")
        assert _try_decode_filetime(raw) is None

    def test_overflow_value_returns_none(self) -> None:
        """Extremely large tick values should not crash."""
        raw = b"\xff" * 8
        assert _try_decode_filetime(raw) is None


class TestDecodeRegistryValue:
    """Tests for _decode_registry_value with mock RegistryValue objects."""

    def _make_mock_value(self, name: str, vtype: int, value: Any) -> MagicMock:
        """Create a mock RegistryValue with the given type and data."""
        mock = MagicMock()
        mock.name.return_value = name
        mock.value_type.return_value = vtype
        mock.value.return_value = value
        return mock

    def test_reg_sz_returns_string(self) -> None:
        """REG_SZ values are returned as plain strings."""
        from Registry import Registry

        mock_val = self._make_mock_value("ProductName", Registry.RegSZ, "Windows 10 Pro")
        result = _decode_registry_value(mock_val)
        assert result["name"] == "ProductName"
        assert result["type"] == "REG_SZ"
        assert result["data"] == "Windows 10 Pro"
        assert "decoded" not in result

    def test_reg_expand_sz_returns_string(self) -> None:
        """REG_EXPAND_SZ values are returned as strings."""
        from Registry import Registry

        mock_val = self._make_mock_value(
            "SystemRoot", Registry.RegExpandSZ, "%SystemRoot%\\system32"
        )
        result = _decode_registry_value(mock_val)
        assert result["type"] == "REG_EXPAND_SZ"
        assert result["data"] == "%SystemRoot%\\system32"

    def test_reg_dword_returns_integer(self) -> None:
        """REG_DWORD values are returned as integers."""
        from Registry import Registry

        mock_val = self._make_mock_value("InstallDate", Registry.RegDWord, 1686830400)
        result = _decode_registry_value(mock_val)
        assert result["type"] == "REG_DWORD"
        assert result["data"] == 1686830400

    def test_reg_qword_returns_integer(self) -> None:
        """REG_QWORD values are returned as integers."""
        from Registry import Registry

        mock_val = self._make_mock_value("LargeValue", Registry.RegQWord, 9999999999999)
        result = _decode_registry_value(mock_val)
        assert result["type"] == "REG_QWORD"
        assert result["data"] == 9999999999999

    def test_reg_binary_8_bytes_filetime_decoded(self) -> None:
        """8-byte REG_BINARY matching FILETIME range includes decoded field."""
        from Registry import Registry

        dt = datetime(2023, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        ticks = int((dt - epoch).total_seconds() * 10_000_000)
        raw = ticks.to_bytes(8, "little")

        mock_val = self._make_mock_value("ShutdownTime", Registry.RegBin, raw)
        result = _decode_registry_value(mock_val)
        assert result["type"] == "REG_BINARY"
        assert result["data"] == raw.hex()
        assert "decoded" in result
        assert result["decoded"].startswith("2023-06-15T12:00:00")

    def test_reg_binary_16_bytes_no_filetime(self) -> None:
        """16-byte REG_BINARY does not attempt FILETIME decoding."""
        from Registry import Registry

        raw = b"\x01\x02\x03\x04" * 4
        mock_val = self._make_mock_value("BinaryData", Registry.RegBin, raw)
        result = _decode_registry_value(mock_val)
        assert result["type"] == "REG_BINARY"
        assert result["data"] == raw.hex()
        assert "decoded" not in result

    def test_reg_multi_sz_returns_list(self) -> None:
        """REG_MULTI_SZ values are returned as a list of strings."""
        from Registry import Registry

        mock_val = self._make_mock_value("DnsServers", Registry.RegMultiSZ, ["8.8.8.8", "8.8.4.4"])
        result = _decode_registry_value(mock_val)
        assert result["type"] == "REG_MULTI_SZ"
        assert result["data"] == ["8.8.8.8", "8.8.4.4"]

    def test_reg_none_bytes_returns_hex(self) -> None:
        """REG_NONE with bytes value returns hex string."""
        from Registry import Registry

        mock_val = self._make_mock_value("EmptyVal", Registry.RegNone, b"\xde\xad")
        result = _decode_registry_value(mock_val)
        assert result["type"] == "REG_NONE"
        assert result["data"] == "dead"


class TestQueryRegistryValueTool:
    """Integration tests for the query_registry_value MCP tool."""

    @staticmethod
    def _get_sync_fn() -> Any:
        """Get the unwrapped sync function from the tool dispatch."""
        from mulder.server.app import _tool_dispatch_sync

        return _tool_dispatch_sync["query_registry_value"]

    @patch("mulder.server.tools.extract.registry_query.extract_and_index")
    @patch("mulder.server.tools.extract.registry_query._extract_hive")
    @patch("mulder.server.tools.extract.registry_query.get_ctx")
    def test_ntuser_requires_username(
        self,
        mock_ctx: MagicMock,
        mock_extract: MagicMock,
        mock_index: MagicMock,
    ) -> None:
        """Querying ntuser hive without username returns an error."""
        fn = self._get_sync_fn()

        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            hive="ntuser",
            key_path="Software\\Microsoft\\Windows",
            value_name=None,
            username=None,
        )
        assert result["status"] == "error"
        assert "username" in result["error_message"]
        mock_extract.assert_not_called()

    @patch("mulder.server.tools.extract.registry_query.extract_and_index")
    @patch("mulder.server.tools.extract.registry_query._extract_hive")
    @patch("mulder.server.tools.extract.registry_query.get_ctx")
    def test_usrclass_requires_username(
        self,
        mock_ctx: MagicMock,
        mock_extract: MagicMock,
        mock_index: MagicMock,
    ) -> None:
        """Querying usrclass hive without username returns an error."""
        fn = self._get_sync_fn()

        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            hive="usrclass",
            key_path="Software\\Classes",
            value_name=None,
            username=None,
        )
        assert result["status"] == "error"
        assert "username" in result["error_message"]

    @patch("mulder.server.tools.extract.registry_query._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry_query.extract_and_index")
    @patch("mulder.server.tools.extract.registry_query._extract_hive")
    @patch("mulder.server.tools.extract.registry_query.get_ctx")
    def test_hive_not_found_returns_error(
        self,
        mock_ctx: MagicMock,
        mock_extract: MagicMock,
        mock_index: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """When TSK cannot locate the hive, returns a descriptive error."""
        fn = self._get_sync_fn()

        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_extract.return_value = (None, None)

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            hive="system",
            key_path="ControlSet001\\Control\\Windows",
            value_name=None,
            username=None,
        )
        assert result["status"] == "error"
        assert result["error_type"] == "hive_not_found"

    @patch("mulder.server.tools.extract.registry_query._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry_query.extract_and_index")
    @patch("mulder.server.tools.extract.registry_query.Registry.Registry")
    @patch("mulder.server.tools.extract.registry_query._extract_hive")
    @patch("mulder.server.tools.extract.registry_query.get_ctx")
    def test_key_not_found_returns_error(
        self,
        mock_ctx: MagicMock,
        mock_extract: MagicMock,
        mock_registry_cls: MagicMock,
        mock_index: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """Querying a non-existent key returns a descriptive error."""
        from Registry import Registry as Reg

        fn = self._get_sync_fn()

        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx

        hive_path = Path("/tmp/fake_hive")
        mock_extract.return_value = (hive_path, "/tmp")

        mock_reg = MagicMock()
        mock_reg.open.side_effect = Reg.RegistryKeyNotFoundException("Key not found")
        mock_registry_cls.return_value = mock_reg

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            hive="system",
            key_path="NonExistent\\Path",
            value_name=None,
            username=None,
        )
        assert result["status"] == "error"
        assert result["error_type"] == "key_not_found"
        assert "NonExistent\\Path" in result["error_message"]

    @patch("mulder.server.tools.extract.registry_query._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry_query.extract_and_index")
    @patch("mulder.server.tools.extract.registry_query.Registry.Registry")
    @patch("mulder.server.tools.extract.registry_query._extract_hive")
    @patch("mulder.server.tools.extract.registry_query.get_ctx")
    def test_value_not_found_returns_available_values(
        self,
        mock_ctx: MagicMock,
        mock_extract: MagicMock,
        mock_registry_cls: MagicMock,
        mock_index: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """Querying a non-existent value lists what is available."""
        from Registry import Registry as Reg

        fn = self._get_sync_fn()

        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx

        hive_path = Path("/tmp/fake_hive")
        mock_extract.return_value = (hive_path, "/tmp")

        mock_key = MagicMock()
        mock_key.value.side_effect = Reg.RegistryValueNotFoundException("Not found")
        mock_val1 = MagicMock()
        mock_val1.name.return_value = "ExistingValue1"
        mock_val2 = MagicMock()
        mock_val2.name.return_value = "ExistingValue2"
        mock_key.values.return_value = [mock_val1, mock_val2]

        mock_reg = MagicMock()
        mock_reg.open.return_value = mock_key
        mock_registry_cls.return_value = mock_reg

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            hive="system",
            key_path="ControlSet001\\Control\\Windows",
            value_name="BadName",
            username=None,
        )
        assert result["status"] == "error"
        assert result["error_type"] == "value_not_found"
        assert "ExistingValue1" in result["error_message"]
        assert "ExistingValue2" in result["error_message"]

    @patch("mulder.server.tools.extract.registry_query._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry_query.extract_and_index")
    @patch("mulder.server.tools.extract.registry_query.Registry.Registry")
    @patch("mulder.server.tools.extract.registry_query._extract_hive")
    @patch("mulder.server.tools.extract.registry_query.get_ctx")
    def test_key_enumeration_returns_values_and_subkeys(
        self,
        mock_ctx: MagicMock,
        mock_extract: MagicMock,
        mock_registry_cls: MagicMock,
        mock_index: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """Querying with no value_name returns all values and subkeys."""
        from Registry import Registry as Reg

        fn = self._get_sync_fn()

        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_index.return_value = {"source_name": "registry.query.system", "windows_indexed": 1}

        hive_path = Path("/tmp/fake_hive")
        mock_extract.return_value = (hive_path, "/tmp")

        mock_val1 = MagicMock()
        mock_val1.name.return_value = "Bias"
        mock_val1.value_type.return_value = Reg.RegDWord
        mock_val1.value.return_value = 480

        mock_val2 = MagicMock()
        mock_val2.name.return_value = "TimeZoneKeyName"
        mock_val2.value_type.return_value = Reg.RegSZ
        mock_val2.value.return_value = "Central Standard Time"

        mock_val3 = MagicMock()
        mock_val3.name.return_value = "DaylightBias"
        mock_val3.value_type.return_value = Reg.RegDWord
        mock_val3.value.return_value = -60

        mock_subkey = MagicMock()
        mock_subkey.name.return_value = "Subkey1"

        mock_key = MagicMock()
        mock_key.values.return_value = [mock_val1, mock_val2, mock_val3]
        mock_key.subkeys.return_value = [mock_subkey]
        mock_key.timestamp.return_value = datetime(2023, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        mock_reg = MagicMock()
        mock_reg.open.return_value = mock_key
        mock_registry_cls.return_value = mock_reg

        result = fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            hive="system",
            key_path="ControlSet001\\Control\\TimeZoneInformation",
            value_name=None,
            username=None,
        )
        assert result["status"] == "success"
        results_data = result["results"]
        assert results_data["key_path"] == "ControlSet001\\Control\\TimeZoneInformation"
        assert results_data["last_written"] == "2023-06-15T12:00:00+00:00"
        assert len(results_data["values"]) == 3
        assert results_data["subkeys"] == ["Subkey1"]

    @patch("mulder.server.tools.extract.registry_query._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry_query.extract_and_index")
    @patch("mulder.server.tools.extract.registry_query.Registry.Registry")
    @patch("mulder.server.tools.extract.registry_query._extract_hive")
    @patch("mulder.server.tools.extract.registry_query.get_ctx")
    def test_result_indexing_system_hive(
        self,
        mock_ctx: MagicMock,
        mock_extract: MagicMock,
        mock_registry_cls: MagicMock,
        mock_index: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """Results are indexed under registry.query.<hive> pattern."""
        from Registry import Registry as Reg

        fn = self._get_sync_fn()

        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_index.return_value = {"source_name": "registry.query.system", "windows_indexed": 1}

        hive_path = Path("/tmp/fake_hive")
        mock_extract.return_value = (hive_path, "/tmp")

        mock_val = MagicMock()
        mock_val.name.return_value = "ProductName"
        mock_val.value_type.return_value = Reg.RegSZ
        mock_val.value.return_value = "Windows 10"

        mock_key = MagicMock()
        mock_key.values.return_value = [mock_val]
        mock_key.subkeys.return_value = []
        mock_key.timestamp.return_value = datetime(2023, 1, 1, tzinfo=timezone.utc)
        mock_key.value.return_value = mock_val

        mock_reg = MagicMock()
        mock_reg.open.return_value = mock_key
        mock_registry_cls.return_value = mock_reg

        fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            hive="system",
            key_path="ControlSet001\\Control\\Windows",
            value_name="ProductName",
            username=None,
        )

        mock_index.assert_called_once()
        call_args = mock_index.call_args
        assert call_args[0][1] == "registry.query.system"

    @patch("mulder.server.tools.extract.registry_query._cleanup_tsk_extract_dir")
    @patch("mulder.server.tools.extract.registry_query.extract_and_index")
    @patch("mulder.server.tools.extract.registry_query.Registry.Registry")
    @patch("mulder.server.tools.extract.registry_query._extract_hive")
    @patch("mulder.server.tools.extract.registry_query.get_ctx")
    def test_result_indexing_ntuser_hive(
        self,
        mock_ctx: MagicMock,
        mock_extract: MagicMock,
        mock_registry_cls: MagicMock,
        mock_index: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """NTUSER results are indexed as registry.query.ntuser.<username>."""
        from Registry import Registry as Reg

        fn = self._get_sync_fn()

        ctx = MagicMock()
        ctx.case_id = "test-case"
        mock_ctx.return_value = ctx
        mock_index.return_value = {
            "source_name": "registry.query.ntuser.jdoe",
            "windows_indexed": 1,
        }

        hive_path = Path("/tmp/fake_hive")
        mock_extract.return_value = (hive_path, "/tmp")

        mock_val = MagicMock()
        mock_val.name.return_value = "url1"
        mock_val.value_type.return_value = Reg.RegSZ
        mock_val.value.return_value = "http://example.com"

        mock_key = MagicMock()
        mock_key.values.return_value = [mock_val]
        mock_key.subkeys.return_value = []
        mock_key.timestamp.return_value = datetime(2023, 1, 1, tzinfo=timezone.utc)

        mock_reg = MagicMock()
        mock_reg.open.return_value = mock_key
        mock_registry_cls.return_value = mock_reg

        fn(
            case_id="test-case",
            image_path="/images/disk.dd",
            hive="ntuser",
            key_path="Software\\Microsoft\\Internet Explorer\\TypedURLs",
            value_name=None,
            username="jdoe",
        )

        mock_index.assert_called_once()
        call_args = mock_index.call_args
        assert call_args[0][1] == "registry.query.ntuser.jdoe"
