"""Tests for mulder.server.helpers -- pure utility functions."""

from __future__ import annotations

import hashlib
import json
import re

from mulder.models import WindowRow
from mulder.server.helpers import hash_output, make_tool_call_id, serialize_windows, slim_window


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

    def test_large_dict_summary_hash(self) -> None:
        data = {f"k{i}": "x" * 1000 for i in range(20)}
        result = hash_output(data)
        full_json = json.dumps(data, sort_keys=True, default=str)
        full_hash = "blake2b:" + hashlib.blake2b(full_json.encode(), digest_size=32).hexdigest()
        assert result != full_hash
        assert result.startswith("blake2b:")

    def test_large_list_summary_hash(self) -> None:
        data = ["x" * 500 for _ in range(30)]
        result = hash_output(data)
        full_json = json.dumps(data, sort_keys=True, default=str)
        full_hash = "blake2b:" + hashlib.blake2b(full_json.encode(), digest_size=32).hexdigest()
        assert result != full_hash
        assert result.startswith("blake2b:")

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
        ws = self._windows(250)
        result = serialize_windows(ws)
        assert len(result) == 200

    def test_custom_cap(self) -> None:
        ws = self._windows(10)
        result = serialize_windows(ws, cap=3)
        assert len(result) == 3

    def test_returns_dicts(self) -> None:
        ws = self._windows(1)
        result = serialize_windows(ws)
        assert isinstance(result[0], dict)
        assert "raw_text" in result[0]


class TestSlimWindow:
    def test_removes_raw_text(self) -> None:
        w = WindowRow(
            source_id=1, line_start=0, line_end=10, event_time="2025-01-01", raw_text="data"
        )
        result = slim_window(w)
        assert "raw_text" not in result
        assert result["source_id"] == 1
        assert result["event_time"] == "2025-01-01"


class TestMakeToolCallId:
    def test_format(self) -> None:
        tc_id = make_tool_call_id()
        assert re.match(r"^tc_[0-9a-f]{8}$", tc_id)

    def test_unique(self) -> None:
        ids = {make_tool_call_id() for _ in range(100)}
        assert len(ids) == 100
