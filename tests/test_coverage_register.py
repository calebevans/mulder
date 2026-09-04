"""Persistence, finalization, and rendering tests for the coverage register."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from mulder.db import CaseDB
from mulder.models import (
    AuditSummary,
    CaseMetadataRow,
    CoverageKey,
    CoverageMetadata,
    CoverageRecord,
    CoverageRequirement,
    FallbackAttempt,
    Finding,
    ScopedNegativeVerdict,
    ToolExecutionMetadata,
    ToolOutcome,
    ToolOutcomeStatus,
)
from mulder.report.renderer import ReportRenderer
from mulder.server.tools.findings import _evaluate_finalize_gates


def _key(system: str = "host-a", domain: str = "processes", check: str = "pslist") -> CoverageKey:
    return CoverageKey(system_name=system, evidence_domain=domain, check_name=check)


def _outcome(status: ToolOutcomeStatus, **coverage: object) -> ToolOutcome:
    if status is ToolOutcomeStatus.SAMPLED and "sample_reason" not in coverage:
        coverage["sample_reason"] = "bounded test"
    return ToolOutcome(status=status, coverage=CoverageMetadata(**coverage))


def _record(key: CoverageKey, status: ToolOutcomeStatus) -> CoverageRecord:
    return CoverageRecord(
        case_id="test-case",
        key=key,
        outcome=_outcome(status),
        recorded_at="2025-01-15T12:00:00Z",
    )


def _requirement(key: CoverageKey | None = None) -> CoverageRequirement:
    return CoverageRequirement(
        case_id="test-case",
        key=key or _key(),
        required_tool="run_check",
        rationale="test mandatory domain",
        declared_at="2025-01-15T11:00:00Z",
    )


def _negative(*, scoped: bool = False) -> Finding:
    verdict = ScopedNegativeVerdict(scope=[_key()]) if scoped else None
    return Finding(
        finding_id="f_negative",
        case_id="test-case",
        title="No suspicious processes" if scoped else "[NEGATIVE] No suspicious processes",
        description="No matching observations were returned.",
        severity="info",
        confidence="inference",
        evidence_refs=["tc_check"],
        sources=["volatility.pslist"],
        negative_verdict=verdict,
        submitted_at="2025-01-15T12:00:00Z",
    )


def _finalize_gates(
    records: list[CoverageRecord],
    finding: Finding | None = None,
    *,
    requirements: list[CoverageRequirement] | None = None,
) -> list[dict[str, object]]:
    metadata = CaseMetadataRow(
        case_id="test-case",
        ingested_at="2025-01-15T00:00:00Z",
        evidence_root="/evidence",
        extractor_versions={},
        narrative="Report.",
    )
    audit = AuditSummary(
        total_tool_calls=2,
        total_findings=1,
        tool_call_counts={"audit_evidence_coverage": 1, "audit_tool_coverage": 1},
        total_duration_ms=1.0,
        first_timestamp="",
        last_timestamp="",
    )
    return _evaluate_finalize_gates(
        [finding or _negative()],
        metadata,
        [],
        audit,
        records,
        coverage_requirements=(requirements if requirements is not None else [_requirement()]),
    )


def _coverage_gate(
    records: list[CoverageRecord], finding: Finding | None = None
) -> dict[str, object]:
    gates = _finalize_gates(records, finding)
    return next(gate for gate in gates if gate["name"] == "negative_coverage_scope")


class TestCoverageRegisterPersistence:
    def test_mandatory_domain_exists_before_any_result(self, tmp_case_db: CaseDB) -> None:
        declared = tmp_case_db.declare_coverage_requirement(
            _key(domain="authentication", check="logons"),
            required_tool="query_logons",
            rationale="authentication is mandatory for this case",
        )

        assert tmp_case_db.get_coverage() == []
        assert tmp_case_db.get_coverage_requirements() == [declared]

    def test_parser_failure_and_successful_empty_remain_distinct(
        self, tmp_case_db: CaseDB
    ) -> None:
        tmp_case_db.record_coverage(
            _key(check="broken-parser"),
            ToolOutcome(
                status=ToolOutcomeStatus.FAILED,
                reason="malformed record",
                coverage=CoverageMetadata(bytes_examined=42, bytes_total=100),
            ),
        )
        tmp_case_db.record_coverage(
            _key(check="empty-parser"),
            _outcome(
                ToolOutcomeStatus.SUCCESS_EMPTY,
                bytes_examined=100,
                bytes_total=100,
                rows_examined=0,
                rows_total=0,
            ),
        )

        records = {record.key.check_name: record for record in tmp_case_db.get_coverage()}
        assert records["broken-parser"].outcome.status is ToolOutcomeStatus.FAILED
        assert records["broken-parser"].outcome.reason == "malformed record"
        assert records["empty-parser"].outcome.status is ToolOutcomeStatus.SUCCESS_EMPTY

    def test_execution_and_legacy_mapping_round_trip_durably(self, tmp_path: Path) -> None:
        db = CaseDB.create("outcomes", "/evidence", tmp_path)
        executed = ToolOutcome(
            status=ToolOutcomeStatus.SUCCESS_EMPTY,
            execution=ToolExecutionMetadata(
                source_ids=["source-1"],
                started_at="2026-01-01T00:00:00Z",
                ended_at="2026-01-01T00:00:01Z",
                output_digest="sha256:" + "a" * 64,
            ),
            legacy_mapping=None,
        )
        db.record_coverage(_key(check="executed"), executed)
        db.record_coverage(_key(check="legacy"), _outcome(ToolOutcomeStatus.SUCCESS_EMPTY))
        db.close()

        reopened = CaseDB.open("outcomes", tmp_path)
        try:
            records = {record.key.check_name: record for record in reopened.get_coverage()}
            assert records["executed"].outcome.execution == executed.execution
            assert records["executed"].outcome.legacy_mapping is None
            assert records["legacy"].outcome.execution is None
            assert records["legacy"].outcome.legacy_mapping == "LEGACY_UNCLASSIFIED"
            with reopened.engine.connect() as connection:
                stored = connection.exec_driver_sql(
                    "SELECT legacy_mapping FROM coverage_register WHERE check_name = 'legacy'"
                ).scalar_one()
            assert stored == "LEGACY_UNCLASSIFIED"
        finally:
            reopened.close()

    def test_successful_fallback_replaces_current_state_and_retains_lineage(
        self, tmp_case_db: CaseDB
    ) -> None:
        key = _key(check="evtx")
        tmp_case_db.record_coverage(key, _outcome(ToolOutcomeStatus.UNSUPPORTED_VERSION))
        recovered = ToolOutcome(
            status=ToolOutcomeStatus.SUCCESS_EMPTY,
            coverage=CoverageMetadata(
                rows_examined=500,
                rows_total=500,
                fallback_lineage=[
                    FallbackAttempt(
                        adapter="primary",
                        status=ToolOutcomeStatus.UNSUPPORTED_VERSION,
                        reason="unknown chunk version",
                    )
                ],
            ),
        )
        tmp_case_db.record_coverage(key, recovered, tool_call_id="tc_fallback")

        records = tmp_case_db.get_coverage(evidence_domain="processes", check_name="evtx")
        assert len(records) == 1
        assert records[0].outcome.status is ToolOutcomeStatus.SUCCESS_EMPTY
        assert records[0].outcome.coverage.fallback_lineage[0].status is (
            ToolOutcomeStatus.UNSUPPORTED_VERSION
        )
        assert records[0].tool_call_id == "tc_fallback"

    def test_open_migrates_a_legacy_database_without_coverage_table(self, tmp_path: Path) -> None:
        db = CaseDB.create("legacy", "/evidence", tmp_path)
        db_path = Path(db.db_path)
        db.close()
        with sqlite3.connect(db_path) as conn:
            conn.execute("DROP TABLE coverage_register")

        reopened = CaseDB.open("legacy", tmp_path)
        try:
            assert reopened.get_coverage() == []
            reopened.record_coverage(_key(), _outcome(ToolOutcomeStatus.NOT_APPLICABLE))
            assert len(reopened.get_coverage()) == 1
        finally:
            reopened.close()

    def test_scoped_negative_verdict_round_trips_with_finding(self, tmp_case_db: CaseDB) -> None:
        finding = _negative(scoped=True)
        tmp_case_db.insert_finding(finding)

        restored = tmp_case_db.get_finding(finding.finding_id)
        assert restored is not None
        assert restored.negative_verdict is not None
        assert restored.negative_verdict.verdict == "NO_EVIL_WITHIN_COVERAGE"
        assert restored.negative_verdict.scope == [_key()]


class TestNegativeCoverageGate:
    def test_omitted_declared_domain_blocks_mandatory_coverage_gate(self) -> None:
        requirements = [
            _requirement(),
            _requirement(_key(domain="network", check="netscan")),
        ]
        gates = _finalize_gates(
            [_record(_key(), ToolOutcomeStatus.SUCCESS_EMPTY)],
            requirements=requirements,
        )
        gate = next(item for item in gates if item["name"] == "mandatory_coverage")

        assert gate["passed"] is False
        assert "host-a/network/netscan=MISSING" in str(gate["detail"])

    @pytest.mark.parametrize(
        "status",
        [
            ToolOutcomeStatus.FAILED,
            ToolOutcomeStatus.PARTIAL,
            ToolOutcomeStatus.SAMPLED,
            ToolOutcomeStatus.UNAVAILABLE,
            ToolOutcomeStatus.UNSUPPORTED_VERSION,
            ToolOutcomeStatus.TIMED_OUT,
            ToolOutcomeStatus.NOT_RUN,
        ],
    )
    def test_incomplete_or_failed_check_cannot_support_unscoped_negative(
        self, status: ToolOutcomeStatus
    ) -> None:
        gate = _coverage_gate([_record(_key(), status)])
        assert gate["passed"] is False
        assert status.value in str(gate["detail"])

    def test_not_applicable_is_not_misreported_as_successful_empty(self) -> None:
        gate = _coverage_gate([_record(_key(), ToolOutcomeStatus.NOT_APPLICABLE)])
        assert gate["passed"] is False
        assert "no applicable completed coverage" in str(gate["detail"])

    def test_successful_empty_supports_scoped_negative(self) -> None:
        gate = _coverage_gate(
            [_record(_key(), ToolOutcomeStatus.SUCCESS_EMPTY)], _negative(scoped=True)
        )
        assert gate["passed"] is True
        assert "successful-empty" in str(gate["detail"])

    def test_scoped_negative_does_not_claim_failed_domain_outside_its_scope(self) -> None:
        records = [
            _record(_key(), ToolOutcomeStatus.SUCCESS_EMPTY),
            _record(_key(domain="network", check="netscan"), ToolOutcomeStatus.FAILED),
        ]
        assert _coverage_gate(records, _negative(scoped=True))["passed"] is True

    def test_scoped_negative_rejects_sampled_named_scope(self) -> None:
        gate = _coverage_gate([_record(_key(), ToolOutcomeStatus.SAMPLED)], _negative(scoped=True))
        assert gate["passed"] is False
        assert "SAMPLED" in str(gate["detail"])

    def test_scoped_negative_rejects_unknown_coverage_key(self) -> None:
        gate = _coverage_gate(
            [_record(_key(domain="network", check="netscan"), ToolOutcomeStatus.SUCCESS_EMPTY)],
            _negative(scoped=True),
        )
        assert gate["passed"] is False
        assert "missing host-a/processes/pslist" in str(gate["detail"])

    def test_legacy_case_without_register_cannot_support_a_negative(self) -> None:
        gate = _coverage_gate([])
        assert gate["passed"] is False
        assert "completed coverage records" in str(gate["detail"])

    def test_complete_fallback_supports_negative_after_failed_primary(self) -> None:
        recovered = CoverageRecord(
            case_id="test-case",
            key=_key(),
            outcome=ToolOutcome(
                status=ToolOutcomeStatus.SUCCESS_EMPTY,
                coverage=CoverageMetadata(
                    fallback_lineage=[
                        FallbackAttempt(adapter="primary", status=ToolOutcomeStatus.FAILED)
                    ]
                ),
            ),
            recorded_at="2025-01-15T12:00:00Z",
        )
        assert _coverage_gate([recovered], _negative(scoped=True))["passed"] is True


def test_scoped_negative_verdict_requires_nonempty_scope() -> None:
    with pytest.raises(ValidationError, match="scope"):
        ScopedNegativeVerdict(scope=[])


def test_report_context_and_markdown_render_coverage_boundary() -> None:
    metadata = CaseMetadataRow(
        case_id="test-case",
        ingested_at="2025-01-15T00:00:00Z",
        evidence_root="/evidence",
        extractor_versions={},
        narrative="Report.",
    )
    audit = AuditSummary(
        total_tool_calls=0,
        total_findings=1,
        tool_call_counts={},
        total_duration_ms=0.0,
        first_timestamp="",
        last_timestamp="",
    )
    record = CoverageRecord(
        case_id="test-case",
        key=_key(),
        outcome=ToolOutcome(
            status=ToolOutcomeStatus.PARTIAL,
            reason="corrupt record",
            coverage=CoverageMetadata(
                rows_examined=20, rows_total=100, truncation_reason="parser stopped"
            ),
        ),
        recorded_at="2025-01-15T12:00:00Z",
    )

    rendered = ReportRenderer().render(
        metadata,
        [_negative(scoped=True)],
        audit,
        "/nonexistent/audit.jsonl",
        coverage_records=[record],
    )
    assert "Coverage and Boundary Register" in rendered
    assert "`PARTIAL`" in rendered
    assert "20/100 rows" in rendered
    assert "NO_EVIL_WITHIN_COVERAGE" in rendered
