"""Tests for finalize_report hard gates, check_finalize_readiness, track_progress.

Tests the pure gate evaluation logic directly via _evaluate_finalize_gates,
and verifies tool-level behavior by calling the underlying sync functions
via ``_tool_dispatch_sync`` (bypassing the async MCP wrapper).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import mulder.server.tools.findings  # noqa: F401 ensure tools are registered
import mulder.server.tools.review  # noqa: F401
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.models import (
    AuditSummary,
    CaseMetadataRow,
    ClaimConfirmation,
    ConfirmationAssessment,
    Finding,
    SourceRow,
)
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools.findings import _evaluate_finalize_gates


def _make_finding(
    finding_id: str = "f_001",
    title: str = "Suspicious process",
    severity: str = "high",
    event_time_start: str | None = "2025-01-15T08:00:00Z",
    sources: list[str] | None = None,
) -> Finding:
    """Build a minimal Finding for gate tests."""
    return Finding(
        finding_id=finding_id,
        case_id="test-case",
        title=title,
        description="test description",
        severity=severity,  # type: ignore[arg-type]
        confidence="confirmed",
        evidence_refs=["tc_aabbccdd"],
        sources=sources or ["volatility.pslist"],
        event_time_start=event_time_start,
        submitted_at="2025-01-15T12:00:00Z",
    )


def _make_metadata(narrative: str | None = "Full investigation report.") -> CaseMetadataRow:
    """Build a CaseMetadataRow with optional narrative."""
    return CaseMetadataRow(
        case_id="test-case",
        ingested_at="2025-01-15T00:00:00Z",
        evidence_root="/evidence",
        extractor_versions={},
        narrative=narrative,
    )


def _make_source(name: str = "volatility.pslist", line_count: int = 42) -> SourceRow:
    """Build a SourceRow for gate tests."""
    return SourceRow(
        source_id=1,
        case_id="test-case",
        source_name=name,
        source_path="/evidence/mem.mem",
        source_hash="abc123",
        extractor="volatility",
        line_count=line_count,
    )


def _make_audit_summary(
    tool_call_counts: dict[str, int] | None = None,
) -> AuditSummary:
    """Build an AuditSummary with specified tool call counts."""
    counts = tool_call_counts or {
        "audit_evidence_coverage": 1,
        "audit_tool_coverage": 1,
    }
    return AuditSummary(
        total_tool_calls=sum(counts.values()),
        total_findings=0,
        tool_call_counts=counts,
        total_duration_ms=0.0,
        first_timestamp="",
        last_timestamp="",
    )


def _passing_gate_inputs() -> tuple[list[Finding], CaseMetadataRow, list[SourceRow], AuditSummary]:
    """Return inputs where all gates pass."""
    findings = [
        _make_finding("f_001", "Proc A", sources=["volatility.pslist"]),
        _make_finding("f_002", "Proc B", sources=["volatility.netscan"]),
        _make_finding("f_003", "Proc C", sources=["tsk.fls"]),
    ]
    metadata = _make_metadata("Full report narrative.")
    sources = [
        _make_source("volatility.pslist", 10),
        _make_source("volatility.netscan", 20),
        _make_source("tsk.fls", 30),
    ]
    audit = _make_audit_summary()
    return findings, metadata, sources, audit


class TestAtomicConfirmationGate:
    def test_fails_when_persisted_atomic_policy_no_longer_passes(self) -> None:
        findings, metadata, sources, audit = _passing_gate_inputs()
        assessment = ConfirmationAssessment(
            accepted=False,
            claims=[
                ClaimConfirmation(
                    claim_id="c_1",
                    accepted=False,
                    reason_code="insufficient_independent_sources",
                    independent_sources=1,
                    required_sources=2,
                )
            ],
        )
        gates = _evaluate_finalize_gates(
            findings,
            metadata,
            sources,
            audit,
            {"f_001": assessment},
        )
        gate = next(item for item in gates if item["name"] == "atomic_confirmation")
        assert gate["passed"] is False
        assert "f_001" in str(gate["detail"])


class TestGateMinimumFindings:
    """Gate 2: At least 3 non-negative findings required."""

    def test_passes_with_three_findings(self) -> None:
        findings, metadata, sources, audit = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "minimum_findings")
        assert gate["passed"] is True

    def test_fails_with_fewer_than_three(self) -> None:
        findings = [_make_finding("f_001"), _make_finding("f_002")]
        gates = _evaluate_finalize_gates(
            findings, _make_metadata(), [_make_source()], _make_audit_summary()
        )
        gate = next(g for g in gates if g["name"] == "minimum_findings")
        assert gate["passed"] is False
        assert "2 non-negative" in str(gate["detail"])

    def test_negative_findings_excluded(self) -> None:
        """Negative findings should not count toward the minimum."""
        findings = [
            _make_finding("f_001"),
            _make_finding("f_002"),
            _make_finding("f_003", title="[NEGATIVE] No malware found"),
        ]
        gates = _evaluate_finalize_gates(
            findings, _make_metadata(), [_make_source()], _make_audit_summary()
        )
        gate = next(g for g in gates if g["name"] == "minimum_findings")
        assert gate["passed"] is False

    def test_passes_with_mix_of_negative_and_positive(self) -> None:
        findings = [
            _make_finding("f_001"),
            _make_finding("f_002"),
            _make_finding("f_003"),
            _make_finding("f_004", title="[NEGATIVE] Clean system"),
        ]
        gates = _evaluate_finalize_gates(
            findings, _make_metadata(), [_make_source()], _make_audit_summary()
        )
        gate = next(g for g in gates if g["name"] == "minimum_findings")
        assert gate["passed"] is True


class TestGateTimestampCoverage:
    """Gate 3: All non-negative findings must have event_time_start."""

    def test_passes_when_all_have_timestamps(self) -> None:
        findings, metadata, sources, audit = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "timestamp_coverage")
        assert gate["passed"] is True

    def test_fails_when_missing_timestamps(self) -> None:
        findings = [
            _make_finding("f_001", event_time_start="2025-01-15T08:00:00Z"),
            _make_finding("f_002", event_time_start=None),
            _make_finding("f_003"),
        ]
        gates = _evaluate_finalize_gates(
            findings, _make_metadata(), [_make_source()], _make_audit_summary()
        )
        gate = next(g for g in gates if g["name"] == "timestamp_coverage")
        assert gate["passed"] is False
        assert "1 non-negative finding(s)" in str(gate["detail"])

    def test_negative_findings_not_checked(self) -> None:
        """Negative findings without timestamps should not fail this gate."""
        findings = [
            _make_finding("f_001"),
            _make_finding("f_002"),
            _make_finding("f_003"),
            _make_finding("f_004", title="[NEGATIVE] Clean", event_time_start=None),
        ]
        gates = _evaluate_finalize_gates(
            findings, _make_metadata(), [_make_source()], _make_audit_summary()
        )
        gate = next(g for g in gates if g["name"] == "timestamp_coverage")
        assert gate["passed"] is True


class TestGateNarrativeSubmitted:
    """Gate 4: case_metadata must have a narrative."""

    def test_passes_with_narrative(self) -> None:
        findings, metadata, sources, audit = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "narrative_submitted")
        assert gate["passed"] is True

    def test_fails_without_narrative(self) -> None:
        metadata = _make_metadata(narrative=None)
        findings, _, sources, audit = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "narrative_submitted")
        assert gate["passed"] is False

    def test_fails_with_whitespace_only_narrative(self) -> None:
        metadata = _make_metadata(narrative="   ")
        findings, _, sources, audit = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "narrative_submitted")
        assert gate["passed"] is False


class TestGateAuditToolsCalled:
    """Gate 5: Both audit tools must appear in the audit log."""

    def test_passes_when_both_called(self) -> None:
        findings, metadata, sources, audit = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "audit_tools_called")
        assert gate["passed"] is True

    def test_fails_when_evidence_audit_missing(self) -> None:
        audit = _make_audit_summary({"audit_tool_coverage": 1})
        findings, metadata, sources, _ = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "audit_tools_called")
        assert gate["passed"] is False
        assert "audit_evidence_coverage" in str(gate["detail"])

    def test_fails_when_tool_audit_missing(self) -> None:
        audit = _make_audit_summary({"audit_evidence_coverage": 1})
        findings, metadata, sources, _ = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "audit_tools_called")
        assert gate["passed"] is False
        assert "audit_tool_coverage" in str(gate["detail"])

    def test_fails_when_neither_called(self) -> None:
        audit = _make_audit_summary({"search": 5})
        findings, metadata, sources, _ = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "audit_tools_called")
        assert gate["passed"] is False


class TestGateEvidenceCitationCoverage:
    """Gate 6: At least 50% of non-empty sources must be cited in findings."""

    def test_passes_when_all_cited(self) -> None:
        findings, metadata, sources, audit = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "evidence_citation_coverage")
        assert gate["passed"] is True

    def test_fails_below_threshold(self) -> None:
        findings = [_make_finding("f_001", sources=["src_a"])] * 3
        sources = [
            _make_source("src_a", 10),
            _make_source("src_b", 20),
            _make_source("src_c", 30),
            _make_source("src_d", 40),
            _make_source("src_e", 50),
        ]
        gates = _evaluate_finalize_gates(
            findings, _make_metadata(), sources, _make_audit_summary()
        )
        gate = next(g for g in gates if g["name"] == "evidence_citation_coverage")
        assert gate["passed"] is False

    def test_empty_sources_skipped(self) -> None:
        """Sources with line_count=0 should not count toward coverage."""
        findings = [
            _make_finding("f_001", sources=["src_a"]),
            _make_finding("f_002", sources=["src_a"]),
            _make_finding("f_003", sources=["src_a"]),
        ]
        sources = [
            _make_source("src_a", 10),
            _make_source("src_empty", 0),
        ]
        gates = _evaluate_finalize_gates(
            findings, _make_metadata(), sources, _make_audit_summary()
        )
        gate = next(g for g in gates if g["name"] == "evidence_citation_coverage")
        assert gate["passed"] is True

    def test_passes_with_no_non_empty_sources(self) -> None:
        """When all sources are empty, the gate should pass."""
        findings, metadata, _, audit = _passing_gate_inputs()
        sources = [_make_source("empty", 0)]
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        gate = next(g for g in gates if g["name"] == "evidence_citation_coverage")
        assert gate["passed"] is True


class TestAllGatesPass:
    """Integration: verify that a well-formed investigation passes all gates."""

    def test_all_gates_pass(self) -> None:
        findings, metadata, sources, audit = _passing_gate_inputs()
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
        assert len(gates) == 6
        for gate in gates:
            assert gate["passed"] is True, f"Gate '{gate['name']}' unexpectedly failed"


def _mock_ctx(
    tmp_path: Path,
    findings: list[Finding] | None = None,
    narrative: str | None = "Full report.",
    sources: list[SourceRow] | None = None,
    audit_tool_calls: list[tuple[str, str]] | None = None,
) -> Any:
    """Build a mock ServerContext backed by a real CaseDB and AuditLog."""
    db = CaseDB.create(case_id="test-case", evidence_root="/evidence", db_dir=tmp_path)

    if narrative:
        db.set_narrative(narrative)

    if findings:
        for f in findings:
            db.insert_finding(f)

    if sources:
        for src in sources:
            db.register_source(
                source_name=src.source_name,
                source_path=src.source_path,
                source_hash=src.source_hash,
                extractor=src.extractor,
                line_count=src.line_count,
            )

    audit = AuditLog(tmp_path / "test.audit.jsonl")
    if audit_tool_calls:
        for tc_id, tool_name in audit_tool_calls:
            audit.log_tool_call(tc_id, tool_name, {}, "sha256:x", duration_ms=10)

    ctx = MagicMock()
    ctx.db = db
    ctx.audit = audit
    return ctx, db


class TestCheckFinalizeReadiness:
    """Tool-level tests for check_finalize_readiness."""

    def test_reports_ready_when_all_pass(self, tmp_path: Path) -> None:
        findings = [
            _make_finding("f_001", sources=["src_a"]),
            _make_finding("f_002", sources=["src_a"]),
            _make_finding("f_003", sources=["src_a"]),
        ]
        sources = [_make_source("src_a", 10)]
        ctx, db = _mock_ctx(
            tmp_path,
            findings=findings,
            narrative="Report.",
            sources=sources,
            audit_tool_calls=[
                ("tc_ev", "audit_evidence_coverage"),
                ("tc_tc", "audit_tool_coverage"),
            ],
        )
        fn = _tool_dispatch_sync["check_finalize_readiness"]
        try:
            with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
                result = fn()
            assert result["ready_to_finalize"] is True
            assert result["status"] == "success"
        finally:
            db.close()

    def test_reports_not_ready_when_gates_fail(self, tmp_path: Path) -> None:
        ctx, db = _mock_ctx(tmp_path, findings=[], narrative=None, sources=[], audit_tool_calls=[])
        fn = _tool_dispatch_sync["check_finalize_readiness"]
        try:
            with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
                result = fn()
            assert result["ready_to_finalize"] is False
            gates = result["gates"]
            assert isinstance(gates, list)
            failing = [g for g in gates if not g["passed"]]
            assert len(failing) > 0
        finally:
            db.close()


class TestTrackProgress:
    """Tool-level tests for track_progress."""

    def test_stores_and_returns_summary(self, tmp_path: Path) -> None:
        ctx, db = _mock_ctx(tmp_path)
        fn = _tool_dispatch_sync["track_progress"]
        try:
            with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
                result = fn(
                    system_name="memory",
                    tools_completed=["run_volatility"],
                    questions_addressed=["Q1"],
                    notes="done",
                )
            assert result["status"] == "accepted"
            assert result["system_name"] == "memory"
            summary = result["progress_summary"]
            assert isinstance(summary, dict)
            systems = summary["systems_analyzed"]
            assert isinstance(systems, list)
            assert "memory" in systems

            records = db.get_all_progress()
            assert len(records) == 1
            assert records[0]["system_name"] == "memory"
        finally:
            db.close()

    def test_multiple_progress_records(self, tmp_path: Path) -> None:
        ctx, db = _mock_ctx(tmp_path)
        fn = _tool_dispatch_sync["track_progress"]
        try:
            with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
                fn("memory", ["run_volatility"], ["Q1"])
                result = fn("disk", ["run_fls"], ["Q2", "Q3"])

            summary = result["progress_summary"]
            assert summary["total_progress_records"] == 2
            assert summary["systems_analyzed"] == ["disk", "memory"]
        finally:
            db.close()


class TestGetInvestigationSummaryEnrichment:
    """Test the new remaining_work, ready_to_finalize, finalize_blockers fields."""

    def test_includes_blockers_when_incomplete(self, tmp_path: Path) -> None:
        ctx, db = _mock_ctx(tmp_path, findings=[], narrative=None, sources=[], audit_tool_calls=[])
        fn = _tool_dispatch_sync["get_investigation_summary"]
        try:
            with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
                result = fn()
            assert result["ready_to_finalize"] is False
            assert isinstance(result["finalize_blockers"], list)
            assert len(result["finalize_blockers"]) > 0
        finally:
            db.close()

    def test_shows_ready_when_complete(self, tmp_path: Path) -> None:
        findings = [
            _make_finding("f_001", sources=["src_a"]),
            _make_finding("f_002", sources=["src_a"]),
            _make_finding("f_003", sources=["src_a"]),
        ]
        sources = [_make_source("src_a", 10)]
        ctx, db = _mock_ctx(
            tmp_path,
            findings=findings,
            narrative="Report.",
            sources=sources,
            audit_tool_calls=[
                ("tc_ev", "audit_evidence_coverage"),
                ("tc_tc", "audit_tool_coverage"),
            ],
        )
        fn = _tool_dispatch_sync["get_investigation_summary"]
        try:
            with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
                result = fn()
            assert result["ready_to_finalize"] is True
            assert result["finalize_blockers"] == "none"
        finally:
            db.close()

    def test_remaining_work_lists_missing_narrative(self, tmp_path: Path) -> None:
        findings = [_make_finding("f_001"), _make_finding("f_002"), _make_finding("f_003")]
        ctx, db = _mock_ctx(
            tmp_path,
            findings=findings,
            narrative=None,
            audit_tool_calls=[
                ("tc_ev", "audit_evidence_coverage"),
                ("tc_tc", "audit_tool_coverage"),
            ],
        )
        fn = _tool_dispatch_sync["get_investigation_summary"]
        try:
            with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
                result = fn()
            remaining = result["remaining_work"]
            assert isinstance(remaining, list)
            assert any("narrative" in str(item).lower() for item in remaining)
        finally:
            db.close()

    def test_remaining_work_lists_missing_audit_tools(self, tmp_path: Path) -> None:
        findings = [_make_finding("f_001"), _make_finding("f_002"), _make_finding("f_003")]
        ctx, db = _mock_ctx(tmp_path, findings=findings, narrative="Report.", audit_tool_calls=[])
        fn = _tool_dispatch_sync["get_investigation_summary"]
        try:
            with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
                result = fn()
            remaining = result["remaining_work"]
            assert isinstance(remaining, list)
            assert any("audit_evidence_coverage" in str(item) for item in remaining)
            assert any("audit_tool_coverage" in str(item) for item in remaining)
        finally:
            db.close()


class TestFinalizeReportGateBlocking:
    """Verify finalize_report returns blocked status for each failing gate."""

    def test_blocks_on_minimum_findings(self, tmp_path: Path) -> None:
        findings = [_make_finding("f_001")]
        ctx, db = _mock_ctx(
            tmp_path,
            findings=findings,
            narrative="Report.",
            audit_tool_calls=[
                ("tc_ev", "audit_evidence_coverage"),
                ("tc_tc", "audit_tool_coverage"),
            ],
        )
        fn = _tool_dispatch_sync["finalize_report"]
        try:
            with (
                patch("mulder.server.tools.findings.get_ctx", return_value=ctx),
                patch("mulder.server.tools.findings.get_job_store", side_effect=RuntimeError),
            ):
                result = fn()
            assert result["status"] == "blocked"
            assert "minimum_findings" in str(result["error_message"])
        finally:
            db.close()

    def test_blocks_on_missing_narrative(self, tmp_path: Path) -> None:
        findings = [
            _make_finding("f_001", sources=["src_a"]),
            _make_finding("f_002", sources=["src_a"]),
            _make_finding("f_003", sources=["src_a"]),
        ]
        sources = [_make_source("src_a", 10)]
        ctx, db = _mock_ctx(
            tmp_path,
            findings=findings,
            narrative=None,
            sources=sources,
            audit_tool_calls=[
                ("tc_ev", "audit_evidence_coverage"),
                ("tc_tc", "audit_tool_coverage"),
            ],
        )
        fn = _tool_dispatch_sync["finalize_report"]
        try:
            with (
                patch("mulder.server.tools.findings.get_ctx", return_value=ctx),
                patch("mulder.server.tools.findings.get_job_store", side_effect=RuntimeError),
            ):
                result = fn()
            assert result["status"] == "blocked"
            assert "narrative_submitted" in str(result["error_message"])
        finally:
            db.close()

    def test_blocks_on_missing_audit_tools(self, tmp_path: Path) -> None:
        findings = [
            _make_finding("f_001", sources=["src_a"]),
            _make_finding("f_002", sources=["src_a"]),
            _make_finding("f_003", sources=["src_a"]),
        ]
        sources = [_make_source("src_a", 10)]
        ctx, db = _mock_ctx(
            tmp_path,
            findings=findings,
            narrative="Report.",
            sources=sources,
            audit_tool_calls=[],
        )
        fn = _tool_dispatch_sync["finalize_report"]
        try:
            with (
                patch("mulder.server.tools.findings.get_ctx", return_value=ctx),
                patch("mulder.server.tools.findings.get_job_store", side_effect=RuntimeError),
            ):
                result = fn()
            assert result["status"] == "blocked"
            assert "audit_tools_called" in str(result["error_message"])
        finally:
            db.close()

    def test_blocks_on_missing_timestamps(self, tmp_path: Path) -> None:
        findings = [
            _make_finding("f_001", event_time_start="2025-01-15T08:00:00Z", sources=["src_a"]),
            _make_finding("f_002", event_time_start=None, sources=["src_a"]),
            _make_finding("f_003", sources=["src_a"]),
        ]
        sources = [_make_source("src_a", 10)]
        ctx, db = _mock_ctx(
            tmp_path,
            findings=findings,
            narrative="Report.",
            sources=sources,
            audit_tool_calls=[
                ("tc_ev", "audit_evidence_coverage"),
                ("tc_tc", "audit_tool_coverage"),
            ],
        )
        fn = _tool_dispatch_sync["finalize_report"]
        try:
            with (
                patch("mulder.server.tools.findings.get_ctx", return_value=ctx),
                patch("mulder.server.tools.findings.get_job_store", side_effect=RuntimeError),
            ):
                result = fn()
            assert result["status"] == "blocked"
            assert "timestamp_coverage" in str(result["error_message"])
        finally:
            db.close()
