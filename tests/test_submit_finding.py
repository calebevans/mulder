"""Tests for submit_finding evidence validation and timestamp sanitization."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools.findings import _sanitize_event_time


@pytest.fixture()
def case_db(tmp_path: Path) -> CaseDB:
    """Create a CaseDB with a valid case_id for submit_finding tests."""
    db = CaseDB.create(case_id="test-case", evidence_root="/evidence", db_dir=tmp_path)
    return db


@pytest.fixture()
def audit_log(tmp_path: Path) -> AuditLog:
    """Create an AuditLog with some pre-recorded tool call IDs."""
    log = AuditLog(tmp_path / "test.audit.jsonl")
    log.log_tool_call(
        tool_call_id="tc_aabbccdd",
        tool_name="run_volatility",
        params={"plugin": "pslist"},
        output_hash="hash1",
        duration_ms=100.0,
    )
    log.log_tool_call(
        tool_call_id="tc_11223344",
        tool_name="search_windows",
        params={"query": "cmd.exe"},
        output_hash="hash2",
        duration_ms=50.0,
    )
    return log


def _call_submit_finding(
    case_db: CaseDB, audit_log: AuditLog, **kwargs: object
) -> dict[str, object]:
    """Invoke the sync submit_finding directly, bypassing the async MCP wrapper."""
    ctx = MagicMock()
    ctx.db = case_db
    ctx.audit = audit_log

    sync_fn = _tool_dispatch_sync["submit_finding"]
    with patch("mulder.server.tools.findings.get_ctx", return_value=ctx):
        return sync_fn(**kwargs)  # type: ignore[no-any-return]


class TestEvidenceValidation:
    """Tests for evidence_refs validation against the audit log."""

    def test_valid_finding_accepted(self, case_db: CaseDB, audit_log: AuditLog) -> None:
        """Finding with valid evidence_refs from audit passes validation."""
        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Suspicious process",
            description="cmd.exe spawned with network connection",
            severity="high",
            confidence="confirmed",
            evidence_refs=["tc_aabbccdd", "tc_11223344"],
            sources=["volatility.pslist"],
            mitre_attack_ids=["T1059.001"],
            event_time_start="2025-01-15T08:30:00Z",
            event_time_end="2025-01-15T09:00:00Z",
        )
        assert result["status"] == "accepted"
        assert "finding_id" in result

    def test_invalid_evidence_ref_rejected(self, case_db: CaseDB, audit_log: AuditLog) -> None:
        """Finding referencing non-existent audit entry is rejected."""
        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Bad finding",
            description="No real evidence",
            severity="medium",
            confidence="inference",
            evidence_refs=["tc_NONEXISTENT"],
            sources=["volatility.pslist"],
        )
        assert "error" in result or result.get("status") != "accepted"
        assert "valid_refs" in result


class TestTimestampSanitization:
    """Tests for _sanitize_event_time timestamp validation."""

    def test_midnight_timestamp_nullified(self) -> None:
        """Timestamps at T00:00:00Z are treated as placeholders and nullified."""
        value, warning = _sanitize_event_time("2025-01-15T00:00:00Z")
        assert value is None
        assert warning is not None
        assert "placeholder" in warning.lower()

    def test_midnight_with_offset_nullified(self) -> None:
        """Timestamps at T00:00:00+00:00 are also treated as placeholders."""
        value, warning = _sanitize_event_time("2025-01-15T00:00:00+00:00")
        assert value is None
        assert warning is not None

    def test_invalid_iso8601_nullified(self) -> None:
        """Malformed ISO-8601 timestamps are nullified."""
        value, warning = _sanitize_event_time("not-a-date")
        assert value is None
        assert warning is not None
        assert "not valid ISO-8601" in warning

    def test_valid_timestamp_passes(self) -> None:
        """A legitimate ISO-8601 timestamp passes through unchanged."""
        value, warning = _sanitize_event_time("2025-01-15T14:30:00Z")
        assert value == "2025-01-15T14:30:00Z"
        assert warning is None

    def test_none_timestamp_passes(self) -> None:
        """None input returns (None, None) without error."""
        value, warning = _sanitize_event_time(None)
        assert value is None
        assert warning is None


class TestSeverityConfidenceValidation:
    """Tests for invalid severity/confidence rejection."""

    def test_invalid_severity_rejected(self, case_db: CaseDB, audit_log: AuditLog) -> None:
        """Invalid severity value is rejected."""
        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Bad severity",
            description="Testing invalid severity",
            severity="catastrophic",
            confidence="inference",
            evidence_refs=["tc_aabbccdd"],
            sources=["volatility.pslist"],
        )
        assert result.get("status") != "accepted"

    def test_invalid_confidence_rejected(self, case_db: CaseDB, audit_log: AuditLog) -> None:
        """Invalid confidence value is rejected."""
        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Bad confidence",
            description="Testing invalid confidence",
            severity="high",
            confidence="maybe",
            evidence_refs=["tc_aabbccdd"],
            sources=["volatility.pslist"],
        )
        assert result.get("status") != "accepted"
