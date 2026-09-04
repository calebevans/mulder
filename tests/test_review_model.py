"""Read-only case-review projection tests at the module interface."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest
from click.testing import CliRunner

from mulder.audit import AuditLog
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.models import (
    AtomicClaimInput,
    CaseMetadataRow,
    CoverageKey,
    CoverageMetadata,
    EvidenceAnchorInput,
    Finding,
    ScopedNegativeVerdict,
    ToolOutcome,
    ToolOutcomeStatus,
    WindowRow,
)
from mulder.receipt import seal_case
from mulder.report.renderer import ReportRenderer
from mulder.review.model import CaseReviewError, ReviewQuery, query_case_review


@dataclass(frozen=True)
class ReviewFixture:
    case_dir: Path
    database: Path
    audit: Path


def _finding(
    finding_id: str,
    *,
    submitted_at: str,
    negative: ScopedNegativeVerdict | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        case_id="review-case",
        title=f"Finding {finding_id}",
        description=f"Observed statement for {finding_id}",
        severity="high" if negative is None else "info",
        confidence="inference",
        evidence_refs=[f"tc-{finding_id}"],
        sources=["host.processes"],
        negative_verdict=negative,
        submitted_at=submitted_at,
    )


def _build_case(tmp_path: Path) -> ReviewFixture:
    case_dir = tmp_path / "cases"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence = evidence_dir / "host.log"
    evidence.write_text("cmd.exe connected to 203.0.113.8", encoding="utf-8")

    db = CaseDB.create("review-case", str(evidence_dir), case_dir)
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    db.register_evidence_file(str(evidence), digest, evidence.stat().st_size)
    source_id = db.register_source(
        "host.processes", str(evidence), f"sha256:{digest}", "fixture", 1
    )
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=1,
                line_end=1,
                event_time="2026-01-01T00:00:00Z",
                raw_text="cmd.exe connected to 203.0.113.8",
            )
        ],
    )
    window = db.get_windows_by_source("host.processes")[0]
    assert window.window_id is not None
    active = _finding("active", submitted_at="2026-01-01T00:00:00Z")
    db.insert_finding(
        active,
        [
            AtomicClaimInput(
                statement="cmd.exe was observed",
                subject="process:cmd.exe",
                predicate="image_name",
                object_value="cmd.exe",
                anchors=[
                    EvidenceAnchorInput(
                        tool_call_id="tc-active",
                        window_id=window.window_id,
                        char_start=0,
                        char_end=7,
                        expected_text="cmd.exe",
                        normalized_value="cmd.exe",
                    )
                ],
            )
        ],
    )
    db.verify_finding_claims("active")

    key = CoverageKey(system_name="host-a", evidence_domain="process", check_name="scan")
    negative = _finding(
        "negative",
        submitted_at="2026-01-01T00:00:01Z",
        negative=ScopedNegativeVerdict(scope=[key]),
    )
    db.insert_finding(negative)
    db.record_coverage(
        key,
        ToolOutcome(
            status=ToolOutcomeStatus.SUCCESS_EMPTY,
            coverage=CoverageMetadata(
                rows_examined=1,
                rows_total=1,
                tool_version="1.0",
                parser_version="2.0",
            ),
        ),
        source_name="host.processes",
        tool_call_id="tc-negative",
    )

    withdrawn = _finding("withdrawn", submitted_at="2026-01-01T00:00:02Z")
    db.insert_finding(withdrawn)
    assert db.delete_finding("withdrawn", actor_kind="human", actor_id="reviewer")
    db.record_progress("host-a", ["scan"], ["Q1"], "Observed activity only")
    db.set_narrative("Preserve inference wording.")
    db.close()

    audit_path = case_dir / "review-case.audit.jsonl"
    audit = AuditLog(audit_path)
    audit.log_tool_call("tc-active", "search", {"source": "host.processes"}, "sha256:x")
    audit.log_finding_submission("active", ["tc-active"])
    (case_dir / "review-case.model_usage.json").write_text(
        json.dumps([{"model": "model-b", "input_tokens": 20, "output_tokens": 4},
                    {"model": "model-a", "input_tokens": 10, "output_tokens": 2}]),
        encoding="utf-8",
    )
    return ReviewFixture(case_dir, case_dir / "review-case.db", audit_path)


def _schema(path: Path) -> list[tuple[str, str]]:
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        return connection.execute(
            "SELECT type, name FROM sqlite_schema ORDER BY type, name"
        ).fetchall()
    finally:
        connection.close()


def test_fixture_projects_authoritative_state_without_strengthening(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)

    review = query_case_review(
        ReviewQuery(
            "review-case",
            fixture.case_dir,
            evidence_limit=1,
            revision_limit=10,
        )
    )

    assert review.model_dump(by_alias=True)["schema"] == "mulder.case-review"
    assert review.case.state == "native"
    assert [item.finding.finding_id for item in review.findings.active] == [
        "active",
        "negative",
    ]
    assert [item.finding.finding_id for item in review.findings.withdrawn] == ["withdrawn"]
    assert review.findings.withdrawn[0].lifecycle_state == "withdrawn"
    claim = review.findings.active[0].claims[0]
    assert claim.epistemic_state == "verified"
    assert claim.anchors[0].exact_text == "cmd.exe"
    assert claim.verifications[0].result == "verified"
    assert review.findings.active[0].confirmation.assessment is not None
    assert not review.findings.active[0].confirmation.assessment.accepted
    assert review.findings.active[0].finding.confidence == "inference"
    assert review.coverage.matrix[0].record.outcome.status is ToolOutcomeStatus.SUCCESS_EMPTY
    assert review.coverage.matrix[0].scoped_negative_finding_ids == ("negative",)
    assert review.receipt.status == "not_sealed"
    assert review.audit.integrity_status == "verified"
    assert [item.model for item in review.costs.recorded_model_usage] == ["model-a", "model-b"]
    assert review.follow_ups.status == "not_implemented"
    assert review.contradictions.status == "not_implemented"
    assert review.graph.status == "not_implemented"
    assert all(not phase.completion_claimed for phase in review.phases)


def test_pages_are_bounded_and_stably_ordered(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)

    first = query_case_review(
        ReviewQuery(
            "review-case",
            fixture.case_dir,
            finding_limit=2,
            evidence_limit=1,
            revision_limit=1,
        )
    )
    second = query_case_review(
        ReviewQuery(
            "review-case",
            fixture.case_dir,
            finding_offset=2,
            finding_limit=1,
            evidence_limit=1,
            revision_limit=1,
        )
    )

    assert first.findings.page.total == 3
    assert first.findings.page.returned == 2
    assert first.findings.page.truncated
    assert [item.finding.finding_id for item in first.findings.active] == ["active", "negative"]
    assert [item.finding.finding_id for item in second.findings.withdrawn] == ["withdrawn"]
    assert first.findings.revision_page.returned == 1
    assert first.findings.revision_page.truncated
    with pytest.raises(CaseReviewError, match="evidence_limit"):
        ReviewQuery("review-case", fixture.case_dir, evidence_limit=1001)


def test_receipt_signature_and_replay_states_are_projected(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)
    seal_case("review-case", fixture.case_dir)

    review = query_case_review(ReviewQuery("review-case", fixture.case_dir))

    assert review.receipt.presence == "present"
    assert review.receipt.status == "verified"
    assert review.receipt.signature_status == "unsigned"
    assert review.receipt.replay_status == "NON_DETERMINISTIC"
    assert review.receipt.manifest_hash is not None
    assert review.phases[-1].state == "receipt_present"


def test_cross_case_rows_and_wrong_database_are_isolated(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)
    connection = sqlite3.connect(fixture.database)
    try:
        connection.execute(
            "INSERT INTO findings (finding_id, case_id, title, description, severity, confidence, "
            "evidence_refs, sources, mitre_attack_ids, event_time_start, event_time_end, "
            "negative_verdict, is_deleted, submitted_at) VALUES "
            "('rogue', 'other-case', 'Secret other case', 'do not expose', 'high', 'inference', "
            "'[\"tc-other\"]', '[\"other.source\"]', '[]', NULL, NULL, NULL, 0, "
            "'2026-01-01T00:00:03Z')"
        )
        connection.commit()
    finally:
        connection.close()

    review = query_case_review(ReviewQuery("review-case", fixture.case_dir))
    encoded = review.model_dump_json()

    assert "rogue" not in encoded
    assert "Secret other case" not in encoded
    with pytest.raises(CaseReviewError, match="case database not found"):
        query_case_review(ReviewQuery("other-case", fixture.case_dir))


def test_query_is_physically_read_only(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)
    before_bytes = fixture.database.read_bytes()
    before_stat = fixture.database.stat()
    before_schema = _schema(fixture.database)
    wal = Path(str(fixture.database) + "-wal")
    wal_before = wal.read_bytes() if wal.exists() else None
    fixture.database.chmod(0o444)

    query_case_review(ReviewQuery("review-case", fixture.case_dir))

    after_stat = fixture.database.stat()
    assert fixture.database.read_bytes() == before_bytes
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert _schema(fixture.database) == before_schema
    assert (wal.read_bytes() if wal.exists() else None) == wal_before


def test_query_rejects_non_quiescent_database_instead_of_ignoring_wal(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)
    wal = Path(str(fixture.database) + "-wal")
    wal.write_bytes(b"uncheckpointed")

    with pytest.raises(CaseReviewError, match="not a quiescent read-only snapshot"):
        query_case_review(ReviewQuery("review-case", fixture.case_dir))


def test_legacy_case_is_explicit_and_never_migrated(tmp_path: Path) -> None:
    case_dir = tmp_path / "legacy"
    case_dir.mkdir()
    database = case_dir / "legacy.db"
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            """
            CREATE TABLE case_metadata (
              case_id TEXT PRIMARY KEY, ingested_at TEXT NOT NULL,
              evidence_root TEXT NOT NULL, extractor_versions TEXT NOT NULL
            );
            CREATE TABLE findings (
              finding_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, title TEXT NOT NULL,
              description TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL,
              evidence_refs TEXT NOT NULL, sources TEXT NOT NULL,
              event_time_start TEXT, event_time_end TEXT, submitted_at TEXT NOT NULL
            );
            INSERT INTO case_metadata VALUES ('legacy', '2020-01-01Z', '/old', '{}');
            INSERT INTO findings VALUES (
              'f-old', 'legacy', 'Legacy inference', 'Historical wording', 'low', 'inference',
              '["tc-old"]', '["old.source"]', NULL, NULL, '2020-01-02Z'
            );
            """
        )
        connection.commit()
    finally:
        connection.close()
    before = _schema(database)

    review = query_case_review(ReviewQuery("legacy", case_dir))

    assert review.findings.active[0].lifecycle_state == "legacy_unversioned"
    assert review.case.state == "legacy_compatible"
    assert review.findings.active[0].claim_state == "legacy_unavailable"
    assert review.coverage.status == "legacy_unavailable"
    assert "claims_absent" in review.case.legacy_states
    assert "finding_revisions_absent" in review.case.legacy_states
    assert review.audit.presence == "absent"
    assert _schema(database) == before


def test_cli_json_text_and_static_report_share_review_calculation(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)
    runner = CliRunner()

    json_result = runner.invoke(
        cli,
        ["review", "review-case", "--db-dir", str(fixture.case_dir), "--json"],
    )
    text_result = runner.invoke(
        cli,
        ["review", "review-case", "--db-dir", str(fixture.case_dir)],
    )

    assert json_result.exit_code == 0, json_result.output
    payload = json.loads(json_result.output)
    assert payload["schema"] == "mulder.case-review"
    assert payload["findings"]["active"][0]["claims"][0]["statement"] == (
        "cmd.exe was observed"
    )
    assert text_result.exit_code == 0, text_result.output
    assert "Phases (observations, not completion claims)" in text_result.output

    review = query_case_review(ReviewQuery("review-case", fixture.case_dir))
    metadata = CaseMetadataRow(
        case_id=review.case.case_id,
        ingested_at=review.case.ingested_at,
        evidence_root=review.case.evidence_root,
        extractor_versions=review.case.extractor_versions,
        narrative=review.case.narrative,
    )
    markdown = ReportRenderer().render(
        metadata,
        [item.finding for item in review.findings.active],
        review.audit.summary,
        fixture.audit,
        proof_cards=review.proof_cards(),
        case_review=review.model_dump(mode="json", by_alias=True),
    )
    assert "Case Review Snapshot" in markdown
    assert "mulder.case-review" in markdown
    assert "cmd.exe was observed" in markdown
    assert "not_implemented" in markdown

    report_result = runner.invoke(
        cli,
        ["report", "review-case", "--db-dir", str(fixture.case_dir)],
    )
    assert report_result.exit_code == 0, report_result.output
    generated = (fixture.case_dir / "review-case.report.md").read_text(encoding="utf-8")
    assert "Case Review Snapshot" in generated
    assert "cmd.exe was observed" in generated
