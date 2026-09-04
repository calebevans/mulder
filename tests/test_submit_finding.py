"""Tests for submit_finding evidence validation and timestamp sanitization."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.models import WindowRow
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
        params={"plugin": "pslist", "returned_window_ids": [1]},
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


def _call_update_finding(
    case_db: CaseDB, audit_log: AuditLog, **kwargs: object
) -> dict[str, object]:
    ctx = MagicMock()
    ctx.db = case_db
    ctx.audit = audit_log

    sync_fn = _tool_dispatch_sync["update_finding"]
    with patch("mulder.server.tools.findings.get_ctx", return_value=ctx):
        return sync_fn(**kwargs)  # type: ignore[no-any-return]


class TestEvidenceValidation:
    """Tests for evidence_refs validation against the audit log."""

    def test_claimless_confirmed_finding_is_rejected(
        self, case_db: CaseDB, audit_log: AuditLog
    ) -> None:
        """Audit-call existence alone cannot promote legacy prose to confirmed."""
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
        assert result["status"] == "error"
        assert result["error_type"] == "confirmation_policy"
        assert case_db.get_findings() == []

    def test_claimless_finding_cannot_be_promoted_to_confirmed_by_update(
        self, case_db: CaseDB, audit_log: AuditLog
    ) -> None:
        submitted = _call_submit_finding(
            case_db,
            audit_log,
            title="Legacy inference",
            description="prose-only",
            severity="medium",
            confidence="inference",
            evidence_refs=["tc_aabbccdd"],
            sources=["volatility.pslist"],
        )
        assert submitted["status"] == "accepted"

        updated = _call_update_finding(
            case_db,
            audit_log,
            finding_id=submitted["finding_id"],
            confidence="confirmed",
        )

        assert updated["status"] == "error"
        assert updated["error_type"] == "confirmation_policy"
        persisted = case_db.get_finding(str(submitted["finding_id"]))
        assert persisted is not None
        assert persisted.confidence == "inference"
        assert persisted.claim_state == "legacy_unverified"

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

    def test_atomic_claim_is_resolved_and_persisted(
        self, case_db: CaseDB, audit_log: AuditLog
    ) -> None:
        sid = case_db.register_source(
            "volatility.pslist", "/evidence/memory.raw", "memory-hash", "volatility", 1
        )
        case_db.insert_windows(
            sid,
            [
                WindowRow(
                    source_id=sid,
                    line_start=1,
                    line_end=1,
                    event_time=None,
                    raw_text="PID 1234 cmd.exe",
                )
            ],
        )
        window = case_db.get_windows_by_source("volatility.pslist")[0]
        assert window.window_id is not None

        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Suspicious process",
            description="PID 1234 is cmd.exe",
            severity="high",
            confidence="inference",
            evidence_refs=["tc_aabbccdd"],
            sources=["caller-controlled-name"],
            claims=[
                {
                    "statement": "PID 1234 is cmd.exe",
                    "subject": "process:1234",
                    "predicate": "image_name",
                    "object_value": "cmd.exe",
                    "anchors": [
                        {
                            "tool_call_id": "tc_aabbccdd",
                            "window_id": window.window_id,
                            "char_start": 9,
                            "char_end": 16,
                            "expected_text": "cmd.exe",
                        }
                    ],
                }
            ],
        )

        assert result["status"] == "accepted"
        assert result["claim_mode"] == "atomic_checked"
        assert result["claim_verifications"][0]["result"] == "verified"
        finding_id = str(result["finding_id"])
        persisted = case_db.get_finding(finding_id)
        assert persisted.sources == ["volatility.pslist"]
        assert persisted.claim_state == "atomic"
        claim = case_db.get_claims(finding_id)[0]
        assert claim.anchors[0].exact_text == "cmd.exe"
        assert claim.epistemic_state == "verified"
        revisions = case_db.get_finding_revisions(finding_id)
        assert len(revisions) == 1
        assert revisions[0].reason_code == "finding_submitted"

    def test_claim_refs_must_exactly_match_finding_refs(
        self, case_db: CaseDB, audit_log: AuditLog
    ) -> None:
        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Mismatched refs",
            description="desc",
            severity="medium",
            confidence="inference",
            evidence_refs=["tc_aabbccdd", "tc_11223344"],
            sources=["src"],
            claims=[
                {
                    "statement": "statement",
                    "subject": "subject",
                    "predicate": "equals",
                    "object_value": "value",
                    "anchors": [
                        {
                            "tool_call_id": "tc_aabbccdd",
                            "window_id": 1,
                            "char_start": 0,
                            "char_end": 1,
                            "expected_text": "x",
                        }
                    ],
                }
            ],
        )
        assert result.get("error_type") == "validation"
        assert "exactly match" in str(result.get("error_message"))

    def test_irrelevant_audited_call_cannot_anchor_an_unrelated_window(
        self, case_db: CaseDB, audit_log: AuditLog
    ) -> None:
        sid = case_db.register_source(
            "volatility.pslist", "/evidence/memory.raw", "memory-hash", "volatility", 1
        )
        case_db.insert_windows(
            sid,
            [
                WindowRow(
                    source_id=sid,
                    line_start=1,
                    line_end=1,
                    event_time=None,
                    raw_text="cmd.exe",
                )
            ],
        )
        window = case_db.get_windows_by_source("volatility.pslist")[0]

        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Unrelated call",
            description="must fail",
            severity="medium",
            confidence="inference",
            evidence_refs=["tc_11223344"],
            sources=["volatility.pslist"],
            claims=[
                {
                    "statement": "Image is cmd.exe",
                    "subject": "process:1",
                    "predicate": "image_name",
                    "object_value": "cmd.exe",
                    "anchors": [
                        {
                            "tool_call_id": "tc_11223344",
                            "window_id": window.window_id,
                            "char_start": 0,
                            "char_end": 7,
                            "expected_text": "cmd.exe",
                        }
                    ],
                }
            ],
        )

        assert result["status"] == "error"
        assert result["error_type"] == "provenance"
        assert case_db.get_findings() == []

    def test_call_for_same_source_cannot_anchor_a_window_it_did_not_return(
        self, case_db: CaseDB, audit_log: AuditLog
    ) -> None:
        sid = case_db.register_source(
            "volatility.pslist", "/evidence/memory.raw", "memory-hash", "volatility", 1
        )
        case_db.insert_windows(
            sid,
            [
                WindowRow(
                    source_id=sid,
                    line_start=1,
                    line_end=1,
                    event_time=None,
                    raw_text="cmd.exe",
                )
            ],
        )
        window = case_db.get_windows_by_source("volatility.pslist")[0]
        assert window.window_id is not None
        audit_log.log_tool_call(
            tool_call_id="tc_source_only",
            tool_name="search",
            params={"source": "volatility.pslist", "returned_window_ids": []},
            output_hash="hash3",
        )

        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Unreturned window",
            description="must fail",
            severity="medium",
            confidence="inference",
            evidence_refs=["tc_source_only"],
            sources=["volatility.pslist"],
            claims=[
                {
                    "statement": "Image is cmd.exe",
                    "subject": "process:1",
                    "predicate": "image_name",
                    "object_value": "cmd.exe",
                    "anchors": [
                        {
                            "tool_call_id": "tc_source_only",
                            "window_id": window.window_id,
                            "char_start": 0,
                            "char_end": 7,
                            "expected_text": "cmd.exe",
                        }
                    ],
                }
            ],
        )

        assert result["status"] == "error"
        assert result["error_type"] == "provenance"
        assert case_db.get_findings() == []

    def test_confirmed_atomic_claim_requires_independent_root_sources(
        self, case_db: CaseDB, audit_log: AuditLog
    ) -> None:
        sid = case_db.register_source("volatility.pslist", "/evidence/a", "one-root", "text", 1)
        case_db.insert_windows(
            sid,
            [
                WindowRow(
                    source_id=sid,
                    line_start=1,
                    line_end=1,
                    event_time=None,
                    raw_text="cmd.exe",
                )
            ],
        )
        window = case_db.get_windows_by_source("volatility.pslist")[0]
        assert window.window_id is not None

        result = _call_submit_finding(
            case_db,
            audit_log,
            title="Single-source execution claim",
            description="cmd.exe executed",
            severity="high",
            confidence="confirmed",
            evidence_refs=["tc_aabbccdd"],
            sources=["volatility.pslist"],
            claims=[
                {
                    "statement": "Image is cmd.exe",
                    "subject": "process:1",
                    "predicate": "image_name",
                    "object_value": "cmd.exe",
                    "anchors": [
                        {
                            "tool_call_id": "tc_aabbccdd",
                            "window_id": window.window_id,
                            "char_start": 0,
                            "char_end": 7,
                            "expected_text": "cmd.exe",
                        }
                    ],
                }
            ],
        )

        assert result["status"] == "error"
        assert result["error_type"] == "confirmation_policy"
        assert result["confirmation_assessment"]["claims"][0]["independent_sources"] == 1
        assert case_db.get_findings() == []


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
