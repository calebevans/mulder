"""MCP tools for submitting findings, retrieving them, and generating reports.

submit_finding enforces evidence-backed findings at the API boundary:
every evidence_ref must correspond to a real tool_call_id recorded in
the session's audit log.  This is the architectural guardrail that
replaces prompt-driven hallucination prevention.

finalize_report enforces structural hard gates that reject incomplete
investigations.  The gates verify minimum finding counts, timestamp
coverage, narrative presence, audit tool invocation, and evidence
citation coverage before allowing report generation.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

from mulder.models import AuditSummary, CaseMetadataRow, Finding, SourceRow
from mulder.patterns import source_is_cited
from mulder.report.renderer import ReportRenderer
from mulder.server.app import get_ctx, get_job_store, mcp
from mulder.server.helpers import error_response, hash_output, make_tool_call_id

logger = logging.getLogger(__name__)

_MIDNIGHT_RE = re.compile(r"T00:00:00(?:Z|[+-]00:?00)?$")

_MIN_NON_NEGATIVE_FINDINGS = 3
_MIN_EVIDENCE_CITATION_PCT = 50.0


def _evaluate_finalize_gates(
    findings: list[Finding],
    case_metadata: CaseMetadataRow,
    sources: list[SourceRow],
    audit_summary: AuditSummary,
) -> list[dict[str, object]]:
    """Evaluate all finalize_report hard gates and return per-gate results.

    Each entry contains ``name``, ``passed`` (bool), and ``detail``
    describing the gate status.  Called by both ``finalize_report``
    (which blocks on the first failure) and ``check_finalize_readiness``
    (which reports all gates).
    """
    gates: list[dict[str, object]] = []
    non_negative = [f for f in findings if not f.title.startswith("[NEGATIVE]")]

    # Gate 1: Minimum non-negative finding count
    count = len(non_negative)
    passed = count >= _MIN_NON_NEGATIVE_FINDINGS
    detail: str
    if passed:
        detail = f"{count} non-negative findings submitted (minimum {_MIN_NON_NEGATIVE_FINDINGS})"
    else:
        detail = (
            f"Only {count} non-negative findings submitted, "
            f"need at least {_MIN_NON_NEGATIVE_FINDINGS}. "
            f"Submit more findings with submit_finding before finalizing."
        )
    gates.append({"name": "minimum_findings", "passed": passed, "detail": detail})

    # Gate 2: Timestamp coverage on non-negative findings
    missing_ts = [f for f in non_negative if not f.event_time_start]
    passed = len(missing_ts) == 0
    if passed:
        detail = "All non-negative findings have event_time_start"
    else:
        titles = [f.title for f in missing_ts[:5]]
        detail = (
            f"{len(missing_ts)} non-negative finding(s) missing event_time_start: "
            f"{titles}. Use update_finding to add precise timestamps from evidence."
        )
    gates.append({"name": "timestamp_coverage", "passed": passed, "detail": detail})

    # Gate 3: Narrative submitted
    passed = bool(case_metadata.narrative and case_metadata.narrative.strip())
    if passed:
        detail = "Narrative is present"
    else:
        detail = (
            "No narrative submitted. Call submit_narrative with a complete "
            "investigation report before finalizing."
        )
    gates.append({"name": "narrative_submitted", "passed": passed, "detail": detail})

    # Gate 4: Audit tools called
    tool_counts = audit_summary.tool_call_counts
    has_evidence_audit = "audit_evidence_coverage" in tool_counts
    has_tool_audit = "audit_tool_coverage" in tool_counts
    passed = has_evidence_audit and has_tool_audit
    if passed:
        detail = "Both audit_evidence_coverage and audit_tool_coverage have been called"
    else:
        missing_tools: list[str] = []
        if not has_evidence_audit:
            missing_tools.append("audit_evidence_coverage")
        if not has_tool_audit:
            missing_tools.append("audit_tool_coverage")
        detail = (
            f"Required audit tool(s) not yet called: {missing_tools}. "
            f"Run these tools to verify investigation completeness before finalizing."
        )
    gates.append({"name": "audit_tools_called", "passed": passed, "detail": detail})

    # Gate 5: Evidence citation coverage
    finding_source_names: set[str] = set()
    for f in findings:
        finding_source_names.update(f.sources)

    non_empty_sources = [s for s in sources if s.line_count > 0]
    total_non_empty = len(non_empty_sources)
    if total_non_empty > 0:
        cited_count = sum(
            1 for s in non_empty_sources if source_is_cited(s.source_name, finding_source_names)
        )
        coverage_pct = round(cited_count / total_non_empty * 100, 1)
        passed = coverage_pct >= _MIN_EVIDENCE_CITATION_PCT
        if passed:
            detail = (
                f"{coverage_pct}% of non-empty sources cited in findings "
                f"({cited_count}/{total_non_empty})"
            )
        else:
            detail = (
                f"Only {coverage_pct}% of non-empty sources are cited "
                f"({cited_count}/{total_non_empty}), need at least "
                f"{_MIN_EVIDENCE_CITATION_PCT}%. Run audit_evidence_coverage "
                f"to identify uncited sources, then review and submit findings "
                f"or document why they are not relevant."
            )
    else:
        passed = True
        detail = "No non-empty sources to check"
    gates.append({"name": "evidence_citation_coverage", "passed": passed, "detail": detail})

    return gates


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
            f"(T00:00:00). Nullified; omit timestamps you don't have "
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
        resp = error_response(
            tc_id,
            "submit_finding",
            {"title": title, "evidence_refs": evidence_refs},
            f"Invalid evidence_ref(s): {', '.join(invalid_refs)} not found in the audit log",
            (time.monotonic() - t0) * 1000,
        )
        resp["valid_refs"] = recent_ids
        return resp

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
        return error_response(
            tc_id,
            "submit_finding",
            {"title": title, "evidence_refs": evidence_refs},
            f"Validation error: {exc}",
            (time.monotonic() - t0) * 1000,
            error_type="validation",
        )

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
def update_finding(
    finding_id: str,
    title: str | None = None,
    description: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    evidence_refs: list[str] | None = None,
    sources: list[str] | None = None,
    mitre_attack_ids: list[str] | None = None,
    event_time_start: str | None = None,
    event_time_end: str | None = None,
) -> dict[str, object]:
    """Update or correct an existing finding.

    Use this to correct a finding when new evidence changes your
    assessment.  For example, downgrade severity when a suspicious
    process turns out to be legitimate, or update the description
    with additional context.

    Only provided fields are updated.  Omitted fields remain unchanged.

    Args:
        finding_id: The finding ID to update (from get_findings).
        title: New title (optional).
        description: New/appended description (optional).
        severity: New severity level (optional).
        confidence: New confidence level (optional).
        evidence_refs: New evidence refs list (optional).
        sources: New sources list (optional).
        mitre_attack_ids: New ATT&CK IDs (optional).
        event_time_start: New start time (optional).
        event_time_end: New end time (optional).
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if not ctx.db._finding_exists(finding_id):
        return error_response(
            tc_id,
            "update_finding",
            {"finding_id": finding_id},
            f"Finding '{finding_id}' not found.",
            (time.monotonic() - t0) * 1000,
            error_type="not_found",
        )

    if evidence_refs is not None:
        invalid_refs = [ref for ref in evidence_refs if not ctx.audit.has_tool_call(ref)]
        if invalid_refs:
            recent_ids = sorted(ctx.audit.tool_call_ids)[-10:]
            resp = error_response(
                tc_id,
                "update_finding",
                {"finding_id": finding_id, "evidence_refs": evidence_refs},
                f"Invalid evidence_ref(s): {', '.join(invalid_refs)} not found in the audit log",
                (time.monotonic() - t0) * 1000,
            )
            resp["valid_refs"] = recent_ids
            return resp

    ts_warnings: list[str] = []
    if event_time_start is not None:
        event_time_start, w = _sanitize_event_time(event_time_start)
        if w:
            ts_warnings.append(w)
    if event_time_end is not None:
        event_time_end, w = _sanitize_event_time(event_time_end)
        if w:
            ts_warnings.append(w)

    update_kwargs: dict[str, object] = {}
    for field, value in [
        ("title", title),
        ("description", description),
        ("severity", severity),
        ("confidence", confidence),
        ("evidence_refs", evidence_refs),
        ("sources", sources),
        ("mitre_attack_ids", mitre_attack_ids),
        ("event_time_start", event_time_start),
        ("event_time_end", event_time_end),
    ]:
        if value is not None:
            update_kwargs[field] = value

    ctx.db.update_finding(finding_id, **update_kwargs)

    updated = ctx.db.get_finding(finding_id)
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="update_finding",
        params={"finding_id": finding_id, **update_kwargs},
        output_hash=hash_output(update_kwargs),
        duration_ms=(time.monotonic() - t0) * 1000,
    )

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "finding_id": finding_id,
        "status": "updated",
        "updated_fields": list(update_kwargs.keys()),
    }
    if updated is not None:
        result["finding"] = updated.model_dump()
    if ts_warnings:
        result["timestamp_warnings"] = ts_warnings
    return result


@mcp.tool()
def delete_finding(finding_id: str) -> dict[str, object]:
    """Delete a finding that was submitted in error.

    Use this when a finding turns out to be completely wrong (e.g.,
    a legitimate tool misidentified as malware). The finding is
    permanently removed from the case database and will not appear
    in the final report.

    Args:
        finding_id: The finding ID to delete.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    deleted = ctx.db.delete_finding(finding_id)

    if not deleted:
        return error_response(
            tc_id,
            "delete_finding",
            {"finding_id": finding_id},
            f"Finding '{finding_id}' not found.",
            (time.monotonic() - t0) * 1000,
            error_type="not_found",
        )

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "finding_id": finding_id,
        "status": "deleted",
    }
    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="delete_finding",
        params={"finding_id": finding_id},
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

    Can be called multiple times; each call replaces the previous
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
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    all_findings = ctx.db.get_findings()
    total = len(all_findings)
    page = all_findings[offset : offset + limit]
    results = [f.model_dump() for f in page]
    resp: dict[str, object] = {
        "tool_call_id": tc_id,
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

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_findings",
        params={"limit": limit, "offset": offset},
        output_hash=hash_output(resp),
        duration_ms=elapsed,
    )
    return resp


@mcp.tool()
def finalize_report() -> dict[str, object]:
    """Generate the final investigation report from all submitted findings.

    Before calling, ensure:
    - All extraction batches report all_done via check_extraction_status
    - All applicable tools have been run (check with audit_tool_coverage)
    - submit_narrative has been called with the investigation narrative
    - All 8 investigation questions (Q1-Q8) answered or documented as gaps

    Renders markdown and HTML reports via Jinja2 templates and writes them
    to disk alongside the case database.  Returns the report path and
    finding counts.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    try:
        store = get_job_store()
        for batch_id in store.batch_ids():
            status = store.get_batch_status(batch_id)
            if status and not status.get("all_done", False):
                running = status.get("running", 0)
                pending = status.get("pending", 0)
                return {
                    "tool_call_id": tc_id,
                    "status": "blocked",
                    "error_message": (
                        f"Cannot finalize: batch {batch_id} still has "
                        f"{running} running and {pending} pending jobs. "
                        f"Call check_extraction_status('{batch_id}') and "
                        f"get_completed_results('{batch_id}') first."
                    ),
                }
    except RuntimeError:
        pass

    findings = ctx.db.get_findings()
    case_metadata = ctx.db.get_case_metadata()
    audit_summary = ctx.audit.summary()
    sources_list = ctx.db.get_sources()

    gate_results = _evaluate_finalize_gates(findings, case_metadata, sources_list, audit_summary)
    for gate in gate_results:
        if not gate["passed"]:
            return {
                "tool_call_id": tc_id,
                "status": "blocked",
                "error_message": f"Gate '{gate['name']}' failed: {gate['detail']}",
            }

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
    source_names = [s.source_name for s in sources_list]
    bulk_windows = ctx.db.get_capped_windows_by_sources(source_names, _MAX_WINDOWS_PER_SOURCE)
    source_windows: dict[str, list[dict[str, object]]] = {}
    for sname, (windows, total) in bulk_windows.items():
        source_windows[sname] = [
            {
                "line_start": w.line_start,
                "line_end": w.line_end,
                "event_time": w.event_time,
                "raw_text": w.raw_text,
                "total": total,
                "truncated": total > _MAX_WINDOWS_PER_SOURCE,
            }
            for w in windows
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
    except Exception as exc:
        logger.warning("HTML report generation failed, markdown report still saved", exc_info=True)
        html_warning: str | None = f"HTML report generation failed: {exc}"
        html_path = None
    else:
        html_warning = None

    log_src = report_dir / "mulder.log"
    log_dest = report_dir / f"{case_metadata.case_id}.mulder.log"
    if log_src.exists() and log_src != log_dest:
        try:
            import shutil

            shutil.copy2(str(log_src), str(log_dest))
        except OSError as exc:
            logger.debug("Failed to copy audit log: %s", exc)

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "report_path": str(report_path),
        "html_report_path": str(html_path) if html_path else None,
        "log_path": str(log_dest) if log_dest.exists() else str(log_src),
        "finding_count": len(findings),
        "confirmed_count": sum(1 for f in findings if f.confidence == "confirmed"),
        "inference_count": sum(1 for f in findings if f.confidence == "inference"),
    }
    if html_warning:
        result["html_warning"] = html_warning

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="finalize_report",
        params={},
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result
