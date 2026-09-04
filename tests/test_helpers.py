"""Tests for mulder.server.helpers -- pure utility functions."""

from __future__ import annotations

import hashlib
import json
import re

from mulder.models import WindowRow
from mulder.server.helpers import (
    extract_module_names,
    extract_pid,
    hash_output,
    make_tool_call_id,
    serialize_windows,
    slim_window,
)


class TestHashOutput:
    def test_small_dict_full_hash(self) -> None:
        data = {"key": "value"}
        result = hash_output(data)
        expected_json = json.dumps(data, sort_keys=True, default=str)
        expected = "blake2b:" + hashlib.blake2b(expected_json.encode(), digest_size=32).hexdigest()
        assert result == expected

    def test_small_list_full_hash(self) -> None:
        data = [1, 2, 3]
        result = hash_output(data)
        expected_json = json.dumps(data, sort_keys=True, default=str)
        expected = "blake2b:" + hashlib.blake2b(expected_json.encode(), digest_size=32).hexdigest()
        assert result == expected

    def test_large_dict_full_hash(self) -> None:
        data = {f"k{i}": "x" * 100 for i in range(150)}
        result = hash_output(data)
        full_json = json.dumps(data, sort_keys=True, default=str)
        full_hash = "blake2b:" + hashlib.blake2b(full_json.encode(), digest_size=32).hexdigest()
        assert result == full_hash

    def test_large_list_full_hash(self) -> None:
        data = ["x" * 50 for _ in range(250)]
        result = hash_output(data)
        full_json = json.dumps(data, sort_keys=True, default=str)
        full_hash = "blake2b:" + hashlib.blake2b(full_json.encode(), digest_size=32).hexdigest()
        assert result == full_hash

    def test_scalar_input(self) -> None:
        result = hash_output("hello world")
        assert result.startswith("blake2b:")

    def test_none_input(self) -> None:
        result = hash_output(None)
        assert result.startswith("blake2b:")


class TestSerializeWindows:
    def _windows(self, n: int) -> list[WindowRow]:
        return [
            WindowRow(
                source_id=1, line_start=i, line_end=i + 1, event_time=None, raw_text=f"line {i}"
            )
            for i in range(n)
        ]

    def test_under_cap_returns_all(self) -> None:
        ws = self._windows(5)
        result = serialize_windows(ws)
        assert len(result) == 5

    def test_over_default_cap(self) -> None:
        ws = self._windows(100)
        result = serialize_windows(ws)
        assert len(result) == 20

    def test_custom_cap(self) -> None:
        ws = self._windows(10)
        result = serialize_windows(ws, cap=3)
        assert len(result) == 3

    def test_returns_dicts(self) -> None:
        ws = self._windows(1)
        result = serialize_windows(ws)
        assert isinstance(result[0], dict)
        assert "raw_text" in result[0]

    def test_truncates_raw_text(self) -> None:
        w = WindowRow(
            source_id=1,
            line_start=0,
            line_end=1,
            event_time=None,
            raw_text="x" * 500,
        )
        result = serialize_windows([w], text_cap=100)
        assert result[0]["raw_text"] == "x" * 100 + "..."
        assert result[0]["full_text_available"] is True

    def test_short_text_not_truncated(self) -> None:
        w = WindowRow(
            source_id=1,
            line_start=0,
            line_end=1,
            event_time=None,
            raw_text="short",
        )
        result = serialize_windows([w], text_cap=100)
        assert result[0]["raw_text"] == "short"
        assert "full_text_available" not in result[0]


class TestSlimWindow:
    def test_removes_raw_text(self) -> None:
        w = WindowRow(
            source_id=1, line_start=0, line_end=10, event_time="2025-01-01", raw_text="data"
        )
        result = slim_window(w)
        assert "raw_text" not in result
        assert result["source_id"] == 1
        assert result["event_time"] == "2025-01-01"


class TestHashOutputHeuristic:
    """Large audit commitments must distinguish complete payload content."""

    def test_large_list_commits_values(self) -> None:
        data = list(range(250))
        h1 = hash_output(data)
        data_different_content = list(range(250, 500))
        h2 = hash_output(data_different_content)
        assert h1 != h2

    def test_large_dict_commits_values(self) -> None:
        data = {f"k{i}": "value_a" for i in range(150)}
        h1 = hash_output(data)
        data_different_values = {f"k{i}": "value_b" for i in range(150)}
        h2 = hash_output(data_different_values)
        assert h1 != h2


class TestExtractPid:
    def test_extracts_pid_from_volatility_output(self) -> None:
        text = "svchost.exe\t1234\t456\t..."
        result = extract_pid(text)
        assert result == 1234

    def test_returns_none_for_no_match(self) -> None:
        result = extract_pid("no numeric pid here")
        assert result is None

    def test_extracts_first_pid(self) -> None:
        text = "process\t999\t0"
        result = extract_pid(text)
        assert result == 999

    def test_returns_none_for_zero_pid(self) -> None:
        text = "idle\t0\t0"
        result = extract_pid(text)
        assert result is None


class TestExtractModuleNames:
    def _make_window(self, text: str) -> WindowRow:
        return WindowRow(source_id=1, line_start=0, line_end=1, event_time=None, raw_text=text)

    def test_extracts_sys_names(self) -> None:
        windows = [
            self._make_window("ntoskrnl.sys\t0x00\tkernel"),
            self._make_window("tcpip.sys\t0x01\tnetwork"),
        ]
        result = extract_module_names(windows)
        assert "ntoskrnl.sys" in result
        assert "tcpip.sys" in result

    def test_returns_empty_for_no_modules(self) -> None:
        windows = [self._make_window("no module names here")]
        result = extract_module_names(windows)
        assert result == {}


class TestMakeToolCallId:
    def test_format(self) -> None:
        tc_id = make_tool_call_id()
        assert re.match(r"^tc_[0-9a-f]{8}$", tc_id)
