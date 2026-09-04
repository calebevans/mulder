"""Tests for mulder.audit -- AuditLog persistence, provenance, summary."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mulder.audit import AuditLog
from mulder.models import SourceRow


class TestToolCallPersistence:
    def test_log_and_has_tool_call(self, tmp_audit_log: AuditLog) -> None:
        tmp_audit_log.log_tool_call(
            tool_call_id="tc_001",
            tool_name="search",
            params={"query": "spinlock"},
            output_hash="sha256:abc",
            duration_ms=150.0,
        )
        assert tmp_audit_log.has_tool_call("tc_001")
        assert not tmp_audit_log.has_tool_call("tc_nonexistent")

    def test_tool_call_ids_returns_copy(self, tmp_audit_log: AuditLog) -> None:
        tmp_audit_log.log_tool_call("tc_a", "tool", {}, "sha256:x")
        ids = tmp_audit_log.tool_call_ids
        ids.add("tc_fake")
        assert "tc_fake" not in tmp_audit_log.tool_call_ids


class TestLoadExisting:
    def test_reload_from_disk(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log1 = AuditLog(log_path)
        log1.log_tool_call("tc_persist", "search", {}, "sha256:x")

        log2 = AuditLog(log_path)
        assert log2.has_tool_call("tc_persist")

    def test_corrupt_lines_skipped(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(
            '{"type":"tool_call","tool_call_id":"tc_ok","tool_name":"x","params":{}}\n'
            "not valid json\n"
            "\n"
            '{"type":"tool_call","tool_call_id":"tc_ok2","tool_name":"y","params":{}}\n'
        )
        log = AuditLog(log_path)
        assert log.has_tool_call("tc_ok")
        assert log.has_tool_call("tc_ok2")

    def test_corrupt_lines_logged_as_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Corrupt JSONL lines should be counted and logged as a warning."""
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(
            '{"type":"tool_call","tool_call_id":"tc_good","tool_name":"x","params":{}}\n'
            "this is not json\n"
            "also broken {{{{\n"
            '{"type":"tool_call","tool_call_id":"tc_good2","tool_name":"y","params":{}}\n'
        )
        with caplog.at_level(logging.WARNING):
            log = AuditLog(log_path)

        assert log.has_tool_call("tc_good")
        assert log.has_tool_call("tc_good2")
        assert any("2 lines failed to parse" in msg for msg in caplog.messages)


class TestIntegrityChain:
    @staticmethod
    def _write_lines(path: Path, entries: list[dict[str, object]]) -> None:
        path.write_text(
            "".join(json.dumps(entry, separators=(",", ":")) + "\n" for entry in entries),
            encoding="utf-8",
        )

    @staticmethod
    def _read_lines(path: Path) -> list[dict[str, object]]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    @staticmethod
    def _three_entry_log(path: Path) -> AuditLog:
        audit = AuditLog(path)
        audit.log_tool_call("tc_1", "search", {"query": "one"}, "blake2b:one")
        audit.log_tool_call("tc_2", "search", {"query": "two"}, "blake2b:two")
        audit.log_finding_submission("finding-1", ["tc_1", "tc_2"])
        return audit

    def test_new_events_are_canonical_and_verified(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path)
        audit.log_tool_call(
            "tc_1",
            "search",
            {"z": {"last": 2, "first": 1}, "a": "value"},
            "blake2b:output",
        )

        raw = log_path.read_text(encoding="utf-8").strip()
        entry = json.loads(raw)
        assert list(entry) == sorted(entry)
        assert list(entry["params"]) == ["a", "z"]
        assert list(entry["params"]["z"]) == ["first", "last"]
        assert entry["schema"] == "mulder.audit"
        assert entry["version"] == 1
        assert entry["sequence"] == 1
        assert entry["previous_hash"].startswith("sha256:")
        assert entry["entry_hash"].startswith("sha256:")

        result = audit.verify_integrity()
        assert result.ok
        assert result.cryptographically_verified
        assert result.status == "verified"
        assert result.entries_checked == 1
        assert result.head_hash == entry["entry_hash"]

    def test_key_reordering_does_not_break_canonical_hash(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path)
        audit.log_tool_call("tc_1", "search", {"b": 2, "a": 1}, "blake2b:output")
        entry = self._read_lines(log_path)[0]
        reversed_entry = dict(reversed(list(entry.items())))
        log_path.write_text(json.dumps(reversed_entry) + "\n", encoding="utf-8")

        result = audit.verify_integrity()
        assert result.ok
        assert result.status == "verified"

    def test_edit_reports_first_broken_entry(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = self._three_entry_log(log_path)
        entries = self._read_lines(log_path)
        entries[1]["tool_name"] = "edited"
        self._write_lines(log_path, entries)

        result = audit.verify_integrity()
        assert not result.ok
        assert result.first_error_line == 2
        assert result.first_error_sequence == 2
        assert result.error_code == "entry_hash_mismatch"

    def test_delete_reports_sequence_gap(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = self._three_entry_log(log_path)
        entries = self._read_lines(log_path)
        self._write_lines(log_path, [entries[0], entries[2]])

        result = audit.verify_integrity()
        assert not result.ok
        assert result.first_error_line == 2
        assert result.error_code == "sequence_mismatch"
        assert result.expected == 2
        assert result.actual == 3

    def test_insert_reports_duplicate_sequence(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = self._three_entry_log(log_path)
        entries = self._read_lines(log_path)
        self._write_lines(log_path, [entries[0], entries[0], entries[1], entries[2]])

        result = audit.verify_integrity()
        assert not result.ok
        assert result.first_error_line == 2
        assert result.error_code == "sequence_mismatch"

    def test_reorder_reports_first_out_of_order_entry(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = self._three_entry_log(log_path)
        entries = self._read_lines(log_path)
        self._write_lines(log_path, [entries[1], entries[0], entries[2]])

        result = audit.verify_integrity()
        assert not result.ok
        assert result.first_error_line == 1
        assert result.error_code == "sequence_mismatch"

    def test_truncated_final_json_is_invalid(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = self._three_entry_log(log_path)
        raw = log_path.read_bytes()
        log_path.write_bytes(raw[:-12])

        result = audit.verify_integrity()
        assert not result.ok
        assert result.first_error_line == 3
        assert result.error_code == "invalid_json"

    def test_bit_flip_is_detected(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = self._three_entry_log(log_path)
        raw = log_path.read_bytes()
        original = b"blake2b:two"
        replacement = b"blake2b:Two"
        assert original in raw
        log_path.write_bytes(raw.replace(original, replacement, 1))

        result = audit.verify_integrity()
        assert not result.ok
        assert result.first_error_line == 2
        assert result.error_code == "entry_hash_mismatch"

    def test_append_and_reload_continue_chain(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        AuditLog(log_path).log_tool_call("tc_1", "search", {}, "blake2b:one")
        reloaded = AuditLog(log_path)
        reloaded.log_tool_call("tc_2", "search", {}, "blake2b:two")

        entries = self._read_lines(log_path)
        assert [entry["sequence"] for entry in entries] == [1, 2]
        assert entries[1]["previous_hash"] == entries[0]["entry_hash"]
        result = AuditLog(log_path).verify_integrity()
        assert result.ok
        assert result.status == "verified"
        assert result.entries_checked == 2

    def test_concurrent_writers_serialize_under_file_lock(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        writers = [AuditLog(log_path) for _ in range(4)]

        def write(index: int) -> None:
            writers[index % len(writers)].log_tool_call(
                f"tc_{index}", "search", {"index": index}, f"blake2b:{index}"
            )

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(write, range(40)))

        result = AuditLog(log_path).verify_integrity()
        assert result.ok
        assert result.status == "verified"
        assert result.entries_checked == 40
        assert [entry["sequence"] for entry in self._read_lines(log_path)] == list(range(1, 41))

    def test_invalid_native_log_refuses_append(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = self._three_entry_log(log_path)
        entries = self._read_lines(log_path)
        entries[0]["tool_name"] = "tampered"
        self._write_lines(log_path, entries)

        with pytest.raises(RuntimeError, match="Refusing to append"):
            audit.log_tool_call("tc_4", "search", {}, "blake2b:four")

    def test_legacy_log_is_readable_but_explicitly_unverified(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        legacy = [
            {"type": "tool_call", "tool_call_id": "legacy-1", "tool_name": "x"},
            {"type": "finding", "finding_id": "legacy-f", "evidence_refs": ["legacy-1"]},
        ]
        self._write_lines(log_path, legacy)

        audit = AuditLog(log_path)
        assert audit.has_tool_call("legacy-1")
        result = audit.verify_integrity()
        assert result.ok
        assert not result.cryptographically_verified
        assert result.status == "legacy_unverified"
        assert result.legacy_entries == 2
        assert result.head_hash is None

    def test_first_new_entry_anchors_and_labels_legacy_prefix(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        legacy = [
            {"type": "tool_call", "tool_call_id": "legacy-1", "tool_name": "x"},
            {"type": "finding", "finding_id": "legacy-f", "evidence_refs": ["legacy-1"]},
        ]
        self._write_lines(log_path, legacy)
        audit = AuditLog(log_path)
        audit.log_tool_call("native-1", "search", {}, "blake2b:one")

        entries = self._read_lines(log_path)
        assert entries[2]["sequence"] == 3
        assert entries[2]["legacy_prefix_entries"] == 2
        result = audit.verify_integrity()
        assert result.ok
        assert result.cryptographically_verified
        assert result.status == "verified_with_legacy_anchor"
        assert result.legacy_entries == 2

        entries[0]["tool_name"] = "edited-legacy"
        self._write_lines(log_path, entries)
        tampered = audit.verify_integrity()
        assert not tampered.ok
        assert tampered.first_error_line == 3
        assert tampered.error_code == "previous_hash_mismatch"


class TestProvenance:
    def test_get_provenance_chain(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path)
        audit.log_tool_call(
            "tc_abc", "search", {"source": "volatility.pslist"}, "sha256:out", duration_ms=100
        )
        audit.log_finding_submission("f-1", ["tc_abc"])

        mock_db = MagicMock()
        mock_db.get_sources.return_value = [
            SourceRow(
                source_id=1,
                case_id="c",
                source_name="volatility.pslist",
                source_path="/ev/mem.mem",
                source_hash="hash",
                extractor="volatility",
                line_count=10,
            )
        ]
        chain = audit.get_provenance_chain("f-1", mock_db)
        assert chain.finding_id == "f-1"
        assert len(chain.tool_calls) == 1
        assert chain.tool_calls[0].tool_call_id == "tc_abc"
        assert len(chain.sources) == 1
        assert chain.sources[0].source_name == "volatility.pslist"

    def test_unknown_finding_raises(self, tmp_audit_log: AuditLog) -> None:
        mock_db = MagicMock()
        with pytest.raises(KeyError, match="No finding with id"):
            tmp_audit_log.get_provenance_chain("nonexistent", mock_db)


class TestExtractSourceNames:
    def test_source_key(self) -> None:
        names = AuditLog._extract_source_names({"source": "vol.pslist"})
        assert names == {"vol.pslist"}

    def test_source_name_key(self) -> None:
        names = AuditLog._extract_source_names({"source_name": "tsk.fls"})
        assert names == {"tsk.fls"}

    def test_channel_key(self) -> None:
        names = AuditLog._extract_source_names({"channel": "Security"})
        assert names == {"evtx.Security"}

    def test_sources_list(self) -> None:
        names = AuditLog._extract_source_names({"sources": ["a", "b", 42]})
        assert names == {"a", "b"}

    def test_empty_params(self) -> None:
        assert AuditLog._extract_source_names({}) == set()


class TestSummary:
    def test_empty_log(self, tmp_path: Path) -> None:
        audit = AuditLog(tmp_path / "empty.jsonl")
        s = audit.summary()
        assert s.total_tool_calls == 0
        assert s.total_findings == 0
        assert s.first_timestamp == ""

    def test_aggregates_counts_and_durations(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path)
        audit.log_tool_call("tc_1", "search", {"q": "x"}, "sha256:a", duration_ms=100)
        audit.log_tool_call("tc_2", "search", {"q": "y"}, "sha256:b", duration_ms=200)
        audit.log_tool_call("tc_3", "correlate", {}, "sha256:c", duration_ms=50)
        audit.log_finding_submission("f-1", ["tc_1"])

        s = audit.summary()
        assert s.total_tool_calls == 3
        assert s.total_findings == 1
        assert s.tool_call_counts["search"] == 2
        assert s.tool_call_counts["correlate"] == 1
        assert s.total_duration_ms == 350.0
        assert s.first_timestamp != ""
        assert s.estimated_cost_usd >= 0

    def test_skips_run_parallel(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        entry = json.dumps(
            {
                "type": "tool_call",
                "tool_call_id": "tc_rp",
                "tool_name": "run_parallel",
                "params": {},
                "output_hash": "sha256:x",
                "duration_ms": 500,
                "timestamp": "2025-01-01T00:00:00Z",
            }
        )
        log_path.write_text(entry + "\n")
        audit = AuditLog(log_path)
        s = audit.summary()
        assert s.total_tool_calls == 0


class TestIngestion:
    def test_log_ingestion_step(self, tmp_audit_log: AuditLog) -> None:
        tmp_audit_log.log_ingestion_step(
            source_name="vol.pslist",
            source_path="/ev/mem.mem",
            source_hash="abc",
            extractor="volatility",
            window_count=10,
            duration_ms=500,
        )
        s = tmp_audit_log.summary()
        assert s.first_timestamp != ""
