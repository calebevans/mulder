"""MCP tools for submitting findings, retrieving them, and generating reports.

submit_finding enforces evidence-backed findings at the API boundary:
every evidence_ref must correspond to a real tool_call_id recorded in
the session's audit log.  This is the architectural guardrail that
replaces prompt-based hallucination prevention.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from killjoy.models import Finding
from killjoy.report.redactor import Redactor
from killjoy.report.renderer import ReportRenderer
from killjoy.server.app import get_ctx, mcp

logger = logging.getLogger(__name__)


def _make_tool_call_id() -> str:
    return f"tc_{uuid4().hex[:8]}"


def _hash_output(output: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(output, sort_keys=True, default=str).encode()).hexdigest()
    )


# ------------------------------------------------------------------
# Tool: submit_finding
# ------------------------------------------------------------------


@mcp.tool()
def submit_finding(
    title: str,
    description: str,
    severity: str,
    confidence: str,
    evidence_refs: list[str],
    sources: list[str],
    event_time_start: str | None = None,
    event_time_end: str | None = None,
) -> dict:
    """Submit a validated forensic finding backed by evidence references.

    Every value in *evidence_refs* must be a ``tool_call_id`` returned by
    a previous tool invocation in this session.  The server validates
    each reference against the audit log and rejects the finding if any
    are invalid.  *severity* must be one of critical/high/medium/low/info.
    *confidence* must be "confirmed" (corroborated by 2+ sources) or
    "inference".

    Returns an acceptance confirmation on success, or an error dict with
    guidance on how to fix the submission.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    invalid_refs = [ref for ref in evidence_refs if not ctx.audit.has_tool_call(ref)]
    if invalid_refs:
        recent_ids = sorted(ctx.audit.tool_call_ids)[-10:]
        error = {
            "tool_call_id": tc_id,
            "error": (
                f"Invalid evidence_ref(s): {', '.join(invalid_refs)} not found in the audit log"
            ),
            "valid_refs": recent_ids,
        }
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="submit_finding",
            params={"title": title, "evidence_refs": evidence_refs},
            output_hash=_hash_output(error),
            duration_ms=elapsed,
        )
        return error

    case_metadata = ctx.db.get_case_metadata()
    finding_id = f"f_{uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    try:
        finding = Finding(
            finding_id=finding_id,
            case_id=case_metadata.case_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            evidence_refs=evidence_refs,
            sources=sources,
            event_time_start=event_time_start,
            event_time_end=event_time_end,
            submitted_at=now,
        )
    except Exception as exc:
        error = {
            "tool_call_id": tc_id,
            "error": f"Validation error: {exc}",
        }
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="submit_finding",
            params={"title": title, "evidence_refs": evidence_refs},
            output_hash=_hash_output(error),
            duration_ms=elapsed,
        )
        return error

    ctx.db.insert_finding(finding)
    ctx.audit.log_finding_submission(finding_id, evidence_refs)

    result = {
        "tool_call_id": tc_id,
        "finding_id": finding_id,
        "status": "accepted",
        "confidence": finding.confidence,
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="submit_finding",
        params={
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "evidence_refs": evidence_refs,
            "sources": sources,
        },
        output_hash=_hash_output(result),
        duration_ms=elapsed,
    )
    return result


# ------------------------------------------------------------------
# Tool: get_findings
# ------------------------------------------------------------------


@mcp.tool()
def get_findings() -> list[dict]:
    """Retrieve all findings submitted so far in this case.

    Returns each finding's id, title, severity, confidence, evidence
    references, sources, and time range.  Read-only.
    """
    ctx = get_ctx()
    findings = ctx.db.get_findings()
    return [f.model_dump() for f in findings]


# ------------------------------------------------------------------
# Tool: finalize_report
# ------------------------------------------------------------------


@mcp.tool()
def finalize_report() -> dict:
    """Generate the final investigation report from all submitted findings.

    Retrieves all findings, redacts potential secrets from descriptions,
    renders a markdown report via the Jinja2 template, and writes it to
    disk alongside the case database.  Returns the report path and
    finding counts.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    findings = ctx.db.get_findings()
    case_metadata = ctx.db.get_case_metadata()
    audit_summary = ctx.audit.summary()

    redactor = Redactor()
    redacted_findings: list[Finding] = []
    for f in findings:
        redacted = f.model_copy(update={"description": redactor.redact(f.description)})
        redacted_findings.append(redacted)

    db_path = Path(ctx.db.db_path)
    report_dir = db_path.parent
    report_path = report_dir / f"{case_metadata.case_id}.report.md"
    audit_log_path = report_dir / f"{case_metadata.case_id}.audit.jsonl"

    renderer = ReportRenderer()
    report_text = renderer.render(
        case_metadata=case_metadata,
        findings=redacted_findings,
        audit_summary=audit_summary,
        audit_log_path=audit_log_path,
    )

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")

    result = {
        "tool_call_id": tc_id,
        "report_path": str(report_path),
        "finding_count": len(findings),
        "confirmed_count": sum(1 for f in findings if f.confidence == "confirmed"),
        "inference_count": sum(1 for f in findings if f.confidence == "inference"),
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="finalize_report",
        params={},
        output_hash=_hash_output(result),
        duration_ms=elapsed,
    )
    return result
