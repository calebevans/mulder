"""Publication state, audience rendering, and output-QA tests."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from mulder.audit import AuditLog
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.models import AtomicClaimInput, EvidenceAnchorInput, Finding, WindowRow
from mulder.receipt import seal_case, verify_case
from mulder.review.decisions import ReviewWorkflow
from mulder.review.publication import PublicationError, PublicationManager


def _case(tmp_path: Path, case_id: str = "publication") -> Path:
    evidence = tmp_path / "evidence.log"
    content = b"host-a executed evil.exe\n"
    evidence.write_bytes(content)
    db = CaseDB.create(case_id, str(tmp_path), tmp_path)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    db.register_evidence_file(str(evidence), digest, len(content))
    source_id = db.register_source("host.processes", str(evidence), digest, "fixture", 1)
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=1,
                line_end=1,
                event_time="2026-01-01T00:00:00Z",
                raw_text=content.decode().strip(),
            )
        ],
    )
    window = db.get_windows_by_source("host.processes")[0]
    assert window.window_id is not None
    db.insert_finding(
        Finding(
            finding_id="finding-1",
            case_id=case_id,
            title="Execution <script>alert(1)</script>",
            description="evil.exe executed",
            severity="high",
            confidence="inference",
            evidence_refs=["tc-1"],
            sources=["host.processes"],
            submitted_at="2026-01-01T00:00:01Z",
        ),
        [
            AtomicClaimInput(
                statement="host-a executed evil.exe <script>alert(2)</script>",
                subject="host-a",
                predicate="executed",
                object_value="evil.exe",
                anchors=[
                    EvidenceAnchorInput(
                        tool_call_id="tc-1",
                        window_id=window.window_id,
                        char_start=16,
                        char_end=24,
                        expected_text="evil.exe",
                    )
                ],
            )
        ],
    )
    db.close()
    audit = AuditLog(tmp_path / f"{case_id}.audit.jsonl")
    audit.log_tool_call("tc-1", "search", {"query": "evil.exe"}, "sha256:one")
    audit.log_finding_submission("finding-1", ["tc-1"])
    return tmp_path / f"{case_id}.db"


def _analyst_approve(case_id: str, case_dir: Path) -> None:
    workflow = ReviewWorkflow(case_id, case_dir)
    request = workflow.request_approval(requested_by="publication-tests")
    workflow.decide(request.request_id, "approve", reviewer="examiner-a")


def test_one_fact_snapshot_renders_escaped_resolvable_audience_views(tmp_path: Path) -> None:
    _case(tmp_path)
    manager = PublicationManager("publication", tmp_path)

    path = manager.create_draft(generate_pdf=False)
    manifest = manager.read()

    assert path == tmp_path / "publication.publication.json"
    assert manifest["state"] == "DRAFT"
    assert manifest["audiences"] == ["executive", "technical", "examiner"]
    assert manifest["qa"]["passed"] is True
    artifacts = manifest["artifacts"]
    assert len(artifacts) == 6
    fact_digest = manifest["fact_model"]["digest"]
    for audience in manifest["audiences"]:
        html_text = (tmp_path / f"publication.publication.{audience}.html").read_text(
            encoding="utf-8"
        )
        assert fact_digest in html_text
        assert "<script>alert" not in html_text
        assert "&lt;script&gt;alert" in html_text
        assert 'data-epistemic-state="unverified"' in html_text
    assert all(
        check["status"] == "pass" for check in manifest["qa"]["checks"] if check["blocking"]
    )


def test_publication_requires_current_analyst_approval_and_prevents_downgrade(
    tmp_path: Path,
) -> None:
    _case(tmp_path)
    manager = PublicationManager("publication", tmp_path)
    manager.create_draft(generate_pdf=False)

    with pytest.raises(PublicationError, match="requires analyst approval"):
        manager.approve()

    # The approval event changes the review fact model, so the pre-approval
    # draft cannot be promoted under a different state.
    _analyst_approve("publication", tmp_path)
    with pytest.raises(PublicationError, match="fact model is stale"):
        manager.approve()

    manager.create_draft(generate_pdf=False)
    manager.approve()
    assert manager.read()["state"] == "APPROVED"
    with pytest.raises(PublicationError, match="refusing to downgrade"):
        manager.create_draft(generate_pdf=False)


def test_changed_artifact_or_case_state_cannot_be_approved(tmp_path: Path) -> None:
    db_path = _case(tmp_path)
    _analyst_approve("publication", tmp_path)
    manager = PublicationManager("publication", tmp_path)
    manager.create_draft(generate_pdf=False)
    html_path = tmp_path / "publication.publication.executive.html"
    html_path.write_text(html_path.read_text(encoding="utf-8") + "changed", encoding="utf-8")

    with pytest.raises(PublicationError, match="changed after QA"):
        manager.approve()

    manager.create_draft(generate_pdf=False)
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE claims SET statement='different state'")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    with pytest.raises(PublicationError, match="fact model is stale"):
        manager.approve()


def test_broken_proof_link_is_recorded_and_blocks_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _case(tmp_path)
    _analyst_approve("publication", tmp_path)
    from mulder.review import publication

    original = publication._render_html

    def broken_html(review: object, audience: object, fact_digest: str) -> str:
        rendered = original(review, audience, fact_digest)  # type: ignore[arg-type]
        return rendered.replace("</body>", '<a href="#missing-proof">broken</a></body>')

    monkeypatch.setattr(publication, "_render_html", broken_html)
    manager = PublicationManager("publication", tmp_path)
    manager.create_draft(generate_pdf=False)
    manifest = manager.read()

    assert manifest["qa"]["passed"] is False
    assert {check["name"] for check in manifest["qa"]["checks"] if check["status"] == "fail"} == {
        "executive_proof_links",
        "technical_proof_links",
        "examiner_proof_links",
    }
    with pytest.raises(PublicationError, match="publication QA failed"):
        manager.approve()


def test_sidecar_and_every_audience_artifact_are_sealed(tmp_path: Path) -> None:
    _case(tmp_path)
    _analyst_approve("publication", tmp_path)
    manager = PublicationManager("publication", tmp_path)
    manager.create_draft(generate_pdf=False)
    manager.approve()

    case_manifest = seal_case("publication", tmp_path)
    raw = json.loads(case_manifest.read_text(encoding="utf-8"))
    names = {artifact["name"] for artifact in raw["reports"]}

    assert "publication.publication.json" in names
    assert {
        f"publication.publication.{audience}.{extension}"
        for audience in ("executive", "technical", "examiner")
        for extension in ("md", "html")
    } <= names
    assert verify_case(case_manifest).ok


def test_cli_publish_and_sidecar_integrity(tmp_path: Path) -> None:
    _case(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["publish", "publication", "--db-dir", str(tmp_path), "--no-pdf"],
    )
    assert result.exit_code == 0, result.output
    assert "Publication DRAFT" in result.output

    path = tmp_path / "publication.publication.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["state"] = "APPROVED"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    status = runner.invoke(cli, ["publication-status", "publication", "--db-dir", str(tmp_path)])
    assert status.exit_code != 0
    assert "integrity check failed" in status.output
