"""Tests for mulder.audit -- AuditLog persistence, provenance, summary."""

from __future__ import annotations

import json
import logging
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
