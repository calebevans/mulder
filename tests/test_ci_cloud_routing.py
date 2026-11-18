"""Cloud and CI evidence reaches its tools, and missing evidence is reported.

Three links that were absent: the classifier did not see repositories or CI
run logs, the planner was never told where any of this evidence was, and
nothing could say "this evidence exists but was not provided".
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import mulder.server.tools.review  # noqa: F401 ensure tools are registered
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.extractors.classifier import EvidenceClassifier
from mulder.models import AuditSummary, CaseMetadataRow, Finding
from mulder.orchestrator.evidence import EvidenceContext
from mulder.orchestrator.types import PhaseResult
from mulder.report.ioc_export import export_iocs
from mulder.report.renderer import ReportRenderer
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools.findings import _evaluate_finalize_gates, _timestamp_gap
from mulder.server.tools.review import _EVIDENCE_INPUT_PARAMS, _EVIDENCE_TOOL_MAP

_FALLBACK = "No pre-populated paths available"
_RUN_LOG = "2026-11-10T12:00:01.1234567Z ##[group]Run actions/checkout@v4\n"
_AUDIT_EVENT = {"@timestamp": 1731800000000, "action": "org.create_actions_secret", "actor": "m"}


def _evidence(root: Path) -> Path:
    """Cloud logs, a repository and CI run logs, each in its own directory."""
    (root / "acme-org-audit").mkdir(parents=True)
    (root / "acme-org-audit" / "github.jsonl").write_text(json.dumps(_AUDIT_EVENT))
    (root / "acme-org-audit" / "more.json").write_text(json.dumps([_AUDIT_EVENT]))
    workflows = root / "acme-app" / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text("on: push\njobs: {}\n")
    (root / "acme-app" / "README.md").write_text("# app\n")
    run = root / "run-12345"
    (run / "build").mkdir(parents=True)
    (run / "1_build.txt").write_text(_RUN_LOG)
    (run / "build" / "2_Run tests.txt").write_text(_RUN_LOG)
    return root


def _types(root: Path) -> dict[str, str]:
    return {
        str(c.path.relative_to(root.resolve())): c.artifact_type
        for c in EvidenceClassifier().classify(root)
    }


def test_repositories_and_ci_run_logs_are_classified(tmp_path: Path) -> None:
    root = _evidence(tmp_path / "evidence")

    assert _types(root) == {
        "acme-app": "repository",
        "acme-org-audit/github.jsonl": "cloud_audit_log",
        "acme-org-audit/more.json": "cloud_audit_log",
        # One item for the run, not one per log file; the nested job
        # directory is its own run-log directory.
        "run-12345": "ci_run_logs",
        "run-12345/build": "ci_run_logs",
    }


def test_ordinary_text_files_are_not_ci_run_logs(tmp_path: Path) -> None:
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "1_summary.txt").write_text("Meeting notes, 2026-11-10\n")
    (notes / "readme.txt").write_text(_RUN_LOG)  # right content, not a run-log name

    assert set(_types(tmp_path).values()) == {"log_file"}


def test_a_dot_directory_above_the_evidence_does_not_hide_it(tmp_path: Path) -> None:
    """Only components below the evidence root say whether an item is hidden."""
    root = _evidence(tmp_path / ".cache" / "case-1" / "evidence")

    assert "acme-app" in _types(root)
    assert not any(".github" in path for path in _types(root))


def _context(root: Path, name: str, evidence: list[str], extracted: Path | None = None) -> str:
    ctx = EvidenceContext(str(root), extracted_dir=extracted)
    systems = [{"name": name, "type": "Cloud", "evidence": evidence}]
    systems.append({"name": "ws-01", "type": "Windows", "evidence": ["disk_image"]})
    ctx.identify_systems(
        PhaseResult(phase_name="catalog", messages=[]), cached_catalog_data={"systems": systems}
    )
    return ctx.build_evidence_context(name)


def test_the_planner_is_given_the_type_the_path_and_the_tool(tmp_path: Path) -> None:
    root = _evidence(tmp_path / "evidence")

    cloud = _context(root, "acme-org-audit", ["cloud_audit_log"])
    repo = _context(root, "acme-app", ["repository"])
    logs = _context(root, "run-12345", ["ci_run_logs"])

    assert 'Cloud audit logs (type "cloud_audit_log"):' in cloud
    assert f"  {root / 'acme-org-audit'}  (2 files)" in cloud
    assert "run_cloud_audit_logs(evidence_path=<path>)" in cloud
    assert "Repository checkouts" not in cloud

    assert f"  {root / 'acme-app'}" in repo
    assert "run_workflow_audit(evidence_path=<directory>)" in repo
    assert "run_secret_scan(evidence_path=<directory>)" in repo

    assert f"  {root / 'run-12345'}" in logs
    assert "run_secret_scan(evidence_path=<directory>)" in logs
    for text in (cloud, repo, logs):
        assert _FALLBACK not in text


def test_a_system_named_for_the_organization_still_gets_its_logs(tmp_path: Path) -> None:
    """The catalog may name a cloud system after the org, which is in no path.

    The type it assigned is then enough, as long as no other system's name
    claims the directory.
    """
    root = _evidence(tmp_path / "evidence")

    text = _context(root, "Acme Corp", ["cloud_audit_log"])

    assert f"  {root / 'acme-org-audit'}  (2 files)" in text
    assert "Repository checkouts" not in text  # not a type the catalog gave it

    host = _context(root, "db-server", ["disk_image"])
    assert "Cloud audit logs" not in host


def test_evidence_delivered_in_an_archive_is_listed_where_it_was_unpacked(
    tmp_path: Path,
) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "cloud-export.zip").write_bytes(b"PK\x03\x04")
    extracted = tmp_path / "extracted"
    _evidence(extracted / "cloud-export-abc123")

    text = _context(root, "acme-org-audit", ["cloud_audit_log"], extracted)

    assert f"  {extracted / 'cloud-export-abc123' / 'acme-org-audit'}  (2 files)" in text


def test_the_coverage_audit_knows_which_tools_these_types_need() -> None:
    assert _EVIDENCE_TOOL_MAP["repository"] == ["run_workflow_audit", "run_secret_scan"]
    assert _EVIDENCE_TOOL_MAP["ci_run_logs"] == ["run_secret_scan"]
    assert _EVIDENCE_TOOL_MAP["cloud_audit_log"] == ["run_cloud_audit_logs"]
    # All three name their input the way start_extraction_batch scopes its
    # already-indexed check; any other name skips a second target in a case.
    for tool in ("run_cloud_audit_logs", "run_secret_scan", "run_workflow_audit"):
        assert _EVIDENCE_INPUT_PARAMS[tool] == ("evidence_path",)


def _finding(title: str, severity: str = "info", when: str | None = None) -> Finding:
    return Finding(
        finding_id=f"f_{abs(hash(title)) % 10**8}",
        case_id="test-case",
        title=title,
        description="gcloud credentials for project acme-prod at 203.0.113.9 in ~/.config/gcloud",
        severity=severity,  # type: ignore[arg-type]
        confidence="confirmed",
        evidence_refs=["tc_aabbccdd"],
        sources=["tsk.filelist"],
        event_time_start=when,
        submitted_at="2026-11-17T12:00:00Z",
    )


_COLLECT = "[COLLECT] Cloud audit log of project acme-prod"
_META = CaseMetadataRow(
    case_id="test-case",
    ingested_at="2026-11-17T00:00:00Z",
    evidence_root="/evidence",
    extractor_versions={},
    narrative="Narrative.",
)


def _summary(findings: int) -> AuditSummary:
    return AuditSummary(
        total_tool_calls=1,
        tool_call_counts={},
        total_findings=findings,
        total_duration_ms=1.0,
        first_timestamp="2026-11-17T00:00:00Z",
        last_timestamp="2026-11-17T01:00:00Z",
    )


def test_a_collection_lead_is_not_a_finding_for_the_gates() -> None:
    """It needs no timestamp, and cannot be used to reach the finding minimum."""
    assert _timestamp_gap(_COLLECT, "high", None) is None

    leads = [_finding(f"{_COLLECT} {i}") for i in range(5)]
    summary = _summary(5)
    gates = {g["name"]: g for g in _evaluate_finalize_gates(leads, _META, [], summary)}

    assert gates["minimum_findings"]["passed"] is False


def test_collection_leads_get_their_own_report_section(tmp_path: Path) -> None:
    findings = [
        _finding(_COLLECT),
        _finding("Credential file read by web shell", "high", "2026-11-10T12:00:00Z"),
    ]
    summary = _summary(2)
    audit = tmp_path / "audit.jsonl"
    audit.write_text("")

    report = ReportRenderer().render(_META, findings, summary, audit)

    section = report.split("## Evidence To Collect", 1)[1].split("\n## ", 1)[0]
    assert "**Cloud audit log of project acme-prod**" in section
    assert "nothing in them has been ruled in or out" in section
    # Listed once, in its section, and not among the findings proper.
    assert report.count("Cloud audit log of project acme-prod") == 1


def test_collection_leads_yield_no_iocs(tmp_path: Path) -> None:
    export_iocs("case", [_finding(_COLLECT)], tmp_path)

    assert "203.0.113.9" not in (tmp_path / "case.iocs.csv").read_text()


def test_the_coverage_audit_flags_unrun_tools_including_in_unpacked_archives(
    tmp_path: Path,
) -> None:
    """A repository used to classify to nothing, so nothing was ever flagged;
    evidence unpacked from an archive was never looked at."""
    root = tmp_path / "evidence"
    workflows = root / "acme-app" / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text("on: push\njobs: {}\n")
    db_dir = tmp_path / "db"
    unpacked = _evidence(db_dir / "extracted" / "cov" / "export-abc123")

    db = CaseDB.create(case_id="cov", evidence_root=str(root), db_dir=db_dir)
    audit = AuditLog(db_dir / "cov.audit.jsonl")
    audit.log_tool_call(
        "tc_0", "run_workflow_audit", {"evidence_path": str(root / "acme-app")}, "sha256:x"
    )
    ctx = MagicMock(db=db, audit=audit, case_id="cov")
    try:
        with (
            patch("mulder.server.tools.review.get_ctx", return_value=ctx),
            patch("mulder.server.tools.review.get_cfg", return_value=MagicMock(db_dir=db_dir)),
        ):
            result = _tool_dispatch_sync["audit_tool_coverage"]()
    finally:
        db.close()

    gaps = {str(item["path"]): item["tools_not_run"] for item in result["coverage"]}
    assert gaps[str(root / "acme-app")] == ["run_secret_scan"]
    assert gaps[str(unpacked / "acme-app")] == ["run_workflow_audit", "run_secret_scan"]
    assert gaps[str(unpacked / "run-12345")] == ["run_secret_scan"]
    assert gaps[str(unpacked / "acme-org-audit" / "more.json")] == ["run_cloud_audit_logs"]


def test_dedup_never_merges_across_kinds_of_statement() -> None:
    """A lead cites the same call as the finding it came from, and scored as
    its duplicate: the lead was deleted, or a negative absorbed a finding."""
    from mulder.server.tools.findings import _group_duplicates

    trace = _finding("gcloud credentials for project acme-prod found on host", "medium")
    lead = _finding(_COLLECT)
    negative = _finding("[NEGATIVE] gcloud credentials for project acme-prod were used")
    twin = _finding("gcloud credentials for project acme-prod found on host (copy)", "medium")

    groups = _group_duplicates([trace, lead, negative, twin], threshold=0.4)

    merged = sorted(sorted(f.title for f in g) for g in groups)
    assert merged == sorted(
        [
            sorted([trace.title, twin.title]),  # same kind, same evidence: still merged
            [lead.title],
            [negative.title],
        ]
    )


def test_an_audit_log_at_the_top_of_the_evidence_is_planned_by_itself(tmp_path: Path) -> None:
    """Its directory is the evidence root; planning that would index every
    JSON file in the case, once per system that owns a log."""
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "github-audit.json").write_text(json.dumps([_AUDIT_EVENT]))
    (root / "gcp-audit.json").write_text(json.dumps([{"protoPayload": {}, "timestamp": "t"}]))

    text = _context(root, "github-audit", ["cloud_audit_log"])

    assert f"  {root / 'github-audit.json'}\n" in text
    assert "gcp-audit" not in text
    assert f"  {root}  (" not in text
