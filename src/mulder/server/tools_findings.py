"""MCP tools for submitting findings, retrieving them, and generating reports.

submit_finding enforces evidence-backed findings at the API boundary:
every evidence_ref must correspond to a real tool_call_id recorded in
the session's audit log.  This is the architectural guardrail that
replaces prompt-based hallucination prevention.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

from mulder.models import Finding
from mulder.report.renderer import ReportRenderer
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import hash_output, make_tool_call_id

logger = logging.getLogger(__name__)

_MIDNIGHT_RE = re.compile(r"T00:00:00(?:Z|[+-]00:?00)?$")


def _sanitize_event_time(ts: str | None) -> tuple[str | None, str | None]:
    """Validate an event timestamp and nullify day-precision placeholders.

    Returns ``(cleaned_value, warning_message)``.  If the timestamp ends
    in ``T00:00:00Z`` it is almost certainly a fabricated day-level
    placeholder and is replaced with ``None``.
    """
    if not ts:
        return None, None
    if _MIDNIGHT_RE.search(ts):
        return None, (
            f"Timestamp '{ts}' looks like a day-precision placeholder "
            f"(T00:00:00). Nullified -- omit timestamps you don't have "
            f"precise values for."
        )
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None, f"Timestamp '{ts}' is not valid ISO-8601. Nullified."
    return ts, None


@mcp.tool()
def submit_finding(
    title: str,
    description: str,
    severity: str,
    confidence: str,
    evidence_refs: list[str],
    sources: list[str],
    mitre_attack_ids: list[str] | None = None,
    event_time_start: str | None = None,
    event_time_end: str | None = None,
) -> dict[str, object]:
    """Submit a validated forensic finding backed by evidence references.

    Every value in *evidence_refs* must be a ``tool_call_id`` returned by
    a previous tool invocation in this session.  The server validates
    each reference against the audit log and rejects the finding if any
    are invalid.  *severity* must be one of critical/high/medium/low/info.
    *confidence* must be "confirmed" (corroborated by 2+ sources) or
    "inference".  *mitre_attack_ids* is an optional list of MITRE ATT&CK
    technique IDs (e.g. ``["T1059.001", "T1570"]``).

    **Timestamps:** ``event_time_start`` and ``event_time_end`` must be
    precise ISO-8601 values copied from tool output.  If you do not have
    a precise timestamp, pass ``null`` rather than fabricating one.
    Day-precision placeholders (e.g. ``2018-08-01T00:00:00Z``) are
    automatically nullified.

    Returns an acceptance confirmation on success, or an error dict with
    guidance on how to fix the submission.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    invalid_refs = [ref for ref in evidence_refs if not ctx.audit.has_tool_call(ref)]
    if invalid_refs:
        recent_ids = sorted(ctx.audit.tool_call_ids)[-10:]
        error: dict[str, object] = {
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
            output_hash=hash_output(error),
            duration_ms=elapsed,
        )
        return error

    case_metadata = ctx.db.get_case_metadata()
    finding_id = f"f_{uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    ts_warnings: list[str] = []
    event_time_start, w = _sanitize_event_time(event_time_start)
    if w:
        ts_warnings.append(w)
    event_time_end, w = _sanitize_event_time(event_time_end)
    if w:
        ts_warnings.append(w)

    try:
        finding = Finding(
            finding_id=finding_id,
            case_id=case_metadata.case_id,
            title=title,
            description=description,
            severity=cast(Literal["critical", "high", "medium", "low", "info"], severity),
            confidence=cast(Literal["confirmed", "inference"], confidence),
            evidence_refs=evidence_refs,
            sources=sources,
            mitre_attack_ids=mitre_attack_ids or [],
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
            output_hash=hash_output(error),
            duration_ms=elapsed,
        )
        return error

    ctx.db.insert_finding(finding)
    ctx.audit.log_finding_submission(finding_id, evidence_refs)

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "finding_id": finding_id,
        "status": "accepted",
        "confidence": finding.confidence,
    }
    if ts_warnings:
        result["timestamp_warnings"] = ts_warnings

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
            "mitre_attack_ids": mitre_attack_ids or [],
        },
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


@mcp.tool()
def submit_narrative(narrative: str) -> dict[str, object]:
    """Submit the long-form investigation narrative report.

    Write this as an official incident report in markdown with these
    sections: Background, Incident Timeline, Key Findings, Impact
    Assessment, Recommendations, and Conclusion.  Use full paragraphs,
    not bullet points.  This becomes the "Report" page in the final
    output.

    Can be called multiple times -- each call replaces the previous
    narrative.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    ctx.db.set_narrative(narrative)

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "accepted",
        "length": len(narrative),
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="submit_narrative",
        params={"length": len(narrative)},
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


@mcp.tool()
def get_findings(limit: int = 20, offset: int = 0) -> dict[str, object]:
    """Retrieve findings submitted so far in this case.

    Returns paginated findings with id, title, severity, confidence,
    evidence references, sources, and time range.  Read-only.

    Args:
        limit: Maximum findings to return (default 20).
        offset: Number of findings to skip (default 0, most recent first).
    """
    ctx = get_ctx()
    all_findings = ctx.db.get_findings()
    total = len(all_findings)
    page = all_findings[offset : offset + limit]
    results = [f.model_dump() for f in page]
    resp: dict[str, object] = {
        "status": "success",
        "results": results,
        "result_count": len(results),
        "total_findings": total,
    }
    if total > offset + limit:
        resp["has_more"] = True
        resp["hint"] = (
            f"Showing {len(results)} of {total} findings. Use offset={offset + limit} to see more."
        )
    return resp


@mcp.tool()
def finalize_report() -> dict[str, object]:
    """Generate the final investigation report from all submitted findings.

    PREREQUISITES (do NOT call until all are met):
    - All extraction batches report all_done via check_extraction_status
    - audit_tool_coverage shows adequate tool invocation per evidence type
    - submit_narrative has been called with the investigation narrative
    - All 8 investigation questions (Q1-Q8) answered or documented as gaps
    - get_investigation_summary confirms adequate progress

    A PreToolUse hook will BLOCK this call if tool coverage is too low.
    Run audit_tool_coverage() first to check.

    Renders markdown and HTML reports via Jinja2 templates and writes them
    to disk alongside the case database.  Returns the report path and
    finding counts.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    findings = ctx.db.get_findings()
    case_metadata = ctx.db.get_case_metadata()
    audit_summary = ctx.audit.summary()
    sources_list = ctx.db.get_sources()
    evidence_integrity = ctx.db.get_evidence_registry()

    db_path = Path(ctx.db.db_path)
    report_dir = db_path.parent
    report_path = report_dir / f"{case_metadata.case_id}.report.md"
    audit_log_path = report_dir / f"{case_metadata.case_id}.audit.jsonl"

    renderer = ReportRenderer()
    report_text = renderer.render(
        case_metadata=case_metadata,
        findings=findings,
        audit_summary=audit_summary,
        audit_log_path=audit_log_path,
        sources_list=sources_list,
        evidence_integrity=evidence_integrity,
    )

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")

    _MAX_WINDOWS_PER_SOURCE = 50
    source_windows: dict[str, list[dict[str, object]]] = {}
    for src in sources_list:
        windows = ctx.db.get_windows_by_source(src.source_name)
        total = len(windows)
        capped = windows[:_MAX_WINDOWS_PER_SOURCE]
        source_windows[src.source_name] = [
            {
                "line_start": w.line_start,
                "line_end": w.line_end,
                "event_time": w.event_time,
                "raw_text": w.raw_text,
                "total": total,
                "truncated": total > _MAX_WINDOWS_PER_SOURCE,
            }
            for w in capped
        ]

    html_path: Path | None = report_dir / f"{case_metadata.case_id}.report.html"
    try:
        html_text = renderer.render_html(
            case_metadata=case_metadata,
            findings=findings,
            audit_summary=audit_summary,
            audit_log_path=audit_log_path,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
            source_windows=source_windows,
        )
        if html_path is not None:
            html_path.write_text(html_text, encoding="utf-8")
    except Exception:
        logger.warning("HTML report generation failed, markdown report still saved", exc_info=True)
        html_path = None

    log_src = report_dir / "mulder.log"
    log_dest = report_dir / f"{case_metadata.case_id}.mulder.log"
    if log_src.exists() and log_src != log_dest:
        try:
            import shutil

            shutil.copy2(str(log_src), str(log_dest))
        except OSError:
            pass

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "report_path": str(report_path),
        "html_report_path": str(html_path) if html_path else None,
        "log_path": str(log_dest) if log_dest.exists() else str(log_src),
        "finding_count": len(findings),
        "confirmed_count": sum(1 for f in findings if f.confidence == "confirmed"),
        "inference_count": sum(1 for f in findings if f.confidence == "inference"),
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="finalize_report",
        params={},
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result
