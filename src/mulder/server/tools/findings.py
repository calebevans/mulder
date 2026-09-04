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

import hashlib
import json
import logging
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

from mulder.models import (
    AtomicClaimInput,
    AuditSummary,
    CaseMetadataRow,
    ConfirmationAssessment,
    CoverageRecord,
    Finding,
    ScopedNegativeVerdict,
    SourceRow,
    ToolOutcomeStatus,
)
from mulder.patterns import SEVERITY_ORDER, source_is_cited
from mulder.report.renderer import ReportRenderer
from mulder.review.model import ReviewQuery, query_case_review
from mulder.server.app import get_ctx, get_job_store, mcp
from mulder.server.helpers import error_response, hash_output, make_tool_call_id
from mulder.server.tool_access import ANALYSTS, Role, tool_access
from mulder.verification.policy import assess_confirmation

logger = logging.getLogger(__name__)

_MIDNIGHT_RE = re.compile(r"T00:00:00(?:Z|[+-]00:?00)?$")

_MIN_NON_NEGATIVE_FINDINGS = 3
_MIN_EVIDENCE_CITATION_PCT = 50.0

_COVERAGE_BLOCKING_STATUSES = frozenset(
    {
        ToolOutcomeStatus.UNAVAILABLE,
        ToolOutcomeStatus.UNSUPPORTED_VERSION,
        ToolOutcomeStatus.FAILED,
        ToolOutcomeStatus.TIMED_OUT,
        ToolOutcomeStatus.PARTIAL,
        ToolOutcomeStatus.SAMPLED,
        ToolOutcomeStatus.NOT_RUN,
    }
)
_COVERAGE_SUPPORTING_STATUSES = frozenset(
    {ToolOutcomeStatus.SUCCESS_EMPTY, ToolOutcomeStatus.SUCCESS_NONEMPTY}
)


def _coverage_tuple(record: CoverageRecord) -> tuple[str, str, str]:
    """Return the stable lookup key for a coverage record."""
    return (
        record.key.system_name,
        record.key.evidence_domain,
        record.key.check_name,
    )


def _evaluate_negative_coverage(
    findings: list[Finding], coverage_records: list[CoverageRecord]
) -> tuple[bool, str]:
    """Decide whether negative findings stay within successfully examined scope.

    Legacy investigations with no coverage register remain renderable. Once a
    register exists, an unscoped negative conclusion is allowed only when at
    least one applicable check completed and no applicable check has an
    incomplete/error state. New scoped verdicts are stricter: every named key
    must exist and have a successful outcome.
    """
    negative_findings = [
        finding
        for finding in findings
        if finding.title.startswith("[NEGATIVE]") or finding.negative_verdict is not None
    ]
    if not negative_findings:
        return True, "No clean or absence conclusion requires coverage validation"
    if not coverage_records:
        return True, (
            "Legacy case has no coverage register; negative findings remain unverified "
            "and are not promoted to NO_EVIL_WITHIN_COVERAGE"
        )

    coverage_by_key = {_coverage_tuple(record): record for record in coverage_records}
    failures: list[str] = []
    for finding in negative_findings:
        if finding.negative_verdict is not None:
            for key in finding.negative_verdict.scope:
                tuple_key = (key.system_name, key.evidence_domain, key.check_name)
                record = coverage_by_key.get(tuple_key)
                label = "/".join(tuple_key)
                if record is None:
                    failures.append(f"{finding.finding_id}: missing {label}")
                elif record.outcome.status not in _COVERAGE_SUPPORTING_STATUSES:
                    failures.append(
                        f"{finding.finding_id}: {label} is {record.outcome.status.value}"
                    )
            continue

        applicable = [
            record
            for record in coverage_records
            if record.outcome.status is not ToolOutcomeStatus.NOT_APPLICABLE
        ]
        blocking = [
            record for record in applicable if record.outcome.status in _COVERAGE_BLOCKING_STATUSES
        ]
        successful = [
            record
            for record in applicable
            if record.outcome.status in _COVERAGE_SUPPORTING_STATUSES
        ]
        if blocking:
            labels = [
                f"{'/'.join(_coverage_tuple(record))}={record.outcome.status.value}"
                for record in blocking[:5]
            ]
            failures.append(f"{finding.finding_id}: unscoped negative crosses {labels}")
        elif not successful:
            failures.append(f"{finding.finding_id}: no applicable completed coverage")

    if failures:
        return False, (
            "Negative conclusions require successful, explicit coverage. "
            + "; ".join(failures)
            + ". Narrow the verdict to completed checks or finish the missing analysis."
        )
    scoped = sum(finding.negative_verdict is not None for finding in negative_findings)
    empty = sum(
        record.outcome.status is ToolOutcomeStatus.SUCCESS_EMPTY for record in coverage_records
    )
    return True, (
        f"{len(negative_findings)} negative conclusion(s) supported by completed coverage "
        f"({scoped} explicitly scoped; {empty} successful-empty check(s))"
    )


def _evaluate_finalize_gates(
    findings: list[Finding],
    case_metadata: CaseMetadataRow,
    sources: list[SourceRow],
    audit_summary: AuditSummary,
    coverage_records: list[CoverageRecord] | None = None,
    confirmation_assessments: dict[str, ConfirmationAssessment] | None = None,
) -> list[dict[str, object]]:
    """Evaluate all finalize_report hard gates and return per-gate results.

    Each entry contains ``name``, ``passed`` (bool), and ``detail``
    describing the gate status.  Called by both ``finalize_report``
    (which blocks on the first failure) and ``check_finalize_readiness``
    (which reports all gates).
    """
    gates: list[dict[str, object]] = []
    non_negative = [
        f for f in findings if not f.title.startswith("[NEGATIVE]") and f.negative_verdict is None
    ]

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
    # Configuration and informational findings may not have meaningful
    # timestamps (e.g., "BitLocker keys stored insecurely" is a state,
    # not a timed event). Exempt them to avoid incentivizing fabricated dates.
    _TS_EXEMPT_SEVERITIES = ("info", "informational")
    ts_required = [f for f in non_negative if f.severity not in _TS_EXEMPT_SEVERITIES]
    missing_ts = [f for f in ts_required if not f.event_time_start]
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

    # Gate 5: Evidence citation coverage (advisory, not blocking)
    # A low citation percentage is a signal to investigate more sources,
    # NOT an instruction to manufacture findings. Only submit findings
    # when the evidence genuinely warrants it. This gate passes at 25%
    # to catch cases where major evidence categories were overlooked,
    # without pressuring the analyst to cite every source.
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
        passed = coverage_pct >= 25.0
        if passed:
            detail = (
                f"{coverage_pct}% of non-empty sources cited in findings "
                f"({cited_count}/{total_non_empty})"
            )
        else:
            detail = (
                f"Only {coverage_pct}% of non-empty sources are cited "
                f"({cited_count}/{total_non_empty}). Review uncited sources "
                f"to verify nothing was missed, but do NOT create findings "
                f"just to increase this percentage."
            )
    else:
        passed = True
        detail = "No non-empty sources to check"
    gates.append({"name": "evidence_citation_coverage", "passed": passed, "detail": detail})

    # Gate 6: clean/absence conclusions cannot outrun actual analysis scope.
    passed, detail = _evaluate_negative_coverage(findings, coverage_records or [])
    gates.append({"name": "negative_coverage_scope", "passed": passed, "detail": detail})

    # Gate 7: Atomic confirmed findings still satisfy deterministic policy.
    # Legacy findings have no assessment and remain explicitly outside this
    # additive gate until migrated; new atomic findings cannot bypass it.
    assessments = confirmation_assessments or {}
    failed_confirmations = [
        finding_id for finding_id, item in assessments.items() if not item.accepted
    ]
    passed = not failed_confirmations
    if passed:
        detail = (
            f"{len(assessments)} atomic confirmed finding(s) satisfy "
            "verification and independence policy"
        )
    else:
        detail = (
            "Atomic confirmed findings no longer satisfy verification/independence "
            f"policy: {failed_confirmations}"
        )
    gates.append({"name": "atomic_confirmation", "passed": passed, "detail": detail})

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
@tool_access(ANALYSTS)
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
    claims: list[dict[str, Any]] | None = None,
    negative_verdict: dict[str, Any] | None = None,
) -> dict[str, object]:
    """Record a forensic finding with validated evidence references and metadata.

    Call after discovering evidence worth reporting. Every evidence_ref
    must be a tool_call_id from a prior tool invocation (validated against
    the audit log). The evidence_ref must be from a tool call whose output
    you directly examined and that specifically supports this finding's
    claims. Citing a tool_call_id from a search you did not review is
    insufficient.

    Timestamps must be precise ISO-8601 values copied from tool output;
    pass null rather than fabricating. Day-precision placeholders are
    auto-nullified.

    New callers should also submit atomic ``claims``. Each claim points to an
    exact character range in an indexed evidence window and repeats the text
    expected at that immutable location. The server resolves source identity,
    hashes, extractor family, and independence key rather than trusting those
    values from the caller. Omitting ``claims`` remains supported for legacy
    clients; such prose is not promoted to a verified atomic claim.

    A clean or absence conclusion can carry ``negative_verdict`` with verdict
    ``NO_EVIL_WITHIN_COVERAGE`` and an explicit list of coverage-register
    keys. Finalization verifies that every named check completed successfully.

    Returns finding_id on acceptance. Severity must be
    critical/high/medium/low/info. Confidence must be "confirmed"
    (corroborated by 2+ sources) or "inference".
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    try:
        claim_inputs = [AtomicClaimInput.model_validate(raw) for raw in claims or []]
        scoped_negative = (
            ScopedNegativeVerdict.model_validate(negative_verdict)
            if negative_verdict is not None
            else None
        )
    except Exception as exc:
        return error_response(
            tc_id,
            "submit_finding",
            {"title": title, "evidence_refs": evidence_refs},
            f"Finding input validation error: {exc}",
            (time.monotonic() - t0) * 1000,
            error_type="validation",
        )

    claim_refs = {anchor.tool_call_id for claim in claim_inputs for anchor in claim.anchors}
    invalid_refs = [
        ref for ref in sorted(set(evidence_refs) | claim_refs) if not ctx.audit.has_tool_call(ref)
    ]
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

    if claim_inputs and claim_refs != set(evidence_refs):
        return error_response(
            tc_id,
            "submit_finding",
            {"title": title, "evidence_refs": evidence_refs},
            "Atomic claim tool_call_ids must exactly match evidence_refs; "
            "uncited or unanchored references are not accepted",
            (time.monotonic() - t0) * 1000,
            error_type="validation",
        )

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
            negative_verdict=scoped_negative,
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

    thin_evidence_warning: str | None = None
    if finding.confidence == "confirmed" and len(finding.evidence_refs) < 2:
        thin_evidence_warning = (
            "Note: this finding is marked 'confirmed' but cites only "
            f"{len(finding.evidence_refs)} evidence source(s). Best practice "
            "requires 2+ independent sources for 'confirmed' confidence. "
            "Consider whether 'inference' is more appropriate."
        )

    try:
        stored_claims = ctx.db.insert_finding(finding, claim_inputs)
        verifications = ctx.db.verify_finding_claims(finding_id) if stored_claims else []
        persisted_claims = ctx.db.get_claims(finding_id)
        confirmation = assess_confirmation(persisted_claims) if persisted_claims else None
        if (
            finding.confidence == "confirmed"
            and confirmation is not None
            and not confirmation.accepted
        ):
            ctx.db.delete_finding(
                finding_id,
                actor_kind="deterministic_rule",
                reason_code="confirmation_policy_rejected",
            )
            response = error_response(
                tc_id,
                "submit_finding",
                {"title": title, "evidence_refs": evidence_refs},
                "Confirmed atomic finding failed deterministic verification or "
                "independent-source policy",
                (time.monotonic() - t0) * 1000,
                error_type="confirmation_policy",
            )
            response["confirmation_assessment"] = confirmation.model_dump()
            return response
    except Exception as exc:
        # Claim persistence and verification are separate database operations;
        # compensate before the finding becomes visible if verification cannot
        # complete. Exact anchor validation itself is transactional in CaseDB.
        if ctx.db._finding_exists(finding_id):
            ctx.db.delete_finding(
                finding_id,
                actor_kind="deterministic_rule",
                reason_code="verification_failed",
            )
        return error_response(
            tc_id,
            "submit_finding",
            {"title": title, "evidence_refs": evidence_refs},
            f"Evidence anchor validation error: {exc}",
            (time.monotonic() - t0) * 1000,
            error_type="validation",
        )
    ctx.audit.log_finding_submission(finding_id, evidence_refs)

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "finding_id": finding_id,
        "status": "accepted",
        "confidence": finding.confidence,
        "atomic_claims": [claim.model_dump() for claim in ctx.db.get_claims(finding_id)],
        "claim_verifications": [item.model_dump() for item in verifications],
        "confirmation_assessment": confirmation.model_dump() if confirmation else None,
        "claim_mode": "atomic_checked" if stored_claims else "legacy_unverified",
        "negative_verdict": (
            finding.negative_verdict.model_dump(mode="json")
            if finding.negative_verdict is not None
            else None
        ),
    }
    if thin_evidence_warning:
        result["hint"] = thin_evidence_warning
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
            "claim_count": len(stored_claims),
            "negative_verdict": (
                finding.negative_verdict.model_dump(mode="json")
                if finding.negative_verdict is not None
                else None
            ),
        },
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


@mcp.tool()
@tool_access(ANALYSTS | Role.NARRATIVE_EXECUTOR | Role.REPORT)
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
    revision_state: str | None = None,
    reason_code: str = "analyst_correction",
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
        revision_state: Explicit lifecycle state for this revision (optional).
        reason_code: Stable explanation recorded in immutable history.
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

    try:
        ctx.db.update_finding(
            finding_id,
            actor_kind="investigator",
            reason_code=reason_code,
            revision_state=revision_state,
            **cast(dict[str, Any], update_kwargs),
        )
    except Exception as exc:
        return error_response(
            tc_id,
            "update_finding",
            {"finding_id": finding_id},
            f"Finding revision validation error: {exc}",
            (time.monotonic() - t0) * 1000,
            error_type="validation",
        )

    updated = ctx.db.get_finding(finding_id)
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="update_finding",
        params={
            "finding_id": finding_id,
            "revision_state": revision_state,
            "reason_code": reason_code,
            **update_kwargs,
        },
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
@tool_access(Role.CROSS_ANALYST | Role.NARRATIVE_ANALYST)
def delete_finding(
    finding_id: str,
    reason_code: str = "analyst_withdrawal",
) -> dict[str, object]:
    """Withdraw a finding while preserving immutable correction history.

    Use this when a finding turns out to be completely wrong (e.g.,
    a legitimate tool misidentified as malware). The finding is
    hidden from the current report but retained as a tombstoned revision.

    Args:
        finding_id: The finding ID to delete.
        reason_code: Stable explanation for the withdrawal.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    deleted = ctx.db.delete_finding(
        finding_id,
        actor_kind="investigator",
        reason_code=reason_code,
    )

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
        params={"finding_id": finding_id, "reason_code": reason_code},
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


@mcp.tool()
@tool_access(Role.REPORT)
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
@tool_access(
    ANALYSTS | Role.CROSS_PLANNER | Role.NARRATIVE_PLANNER | Role.NARRATIVE_EXECUTOR | Role.REPORT
)
def get_findings(limit: int = 20, offset: int = 0) -> dict[str, object]:
    """Retrieve paginated findings submitted in this case.

    Call at any point to review current findings. Useful before
    submitting new findings (to check for duplicates) and during
    analysis to track investigation progress.

    Returns finding metadata: id, title, severity, confidence,
    evidence_refs, sources, MITRE IDs, and time range.

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
    results: list[dict[str, object]] = []
    for finding in page:
        item = finding.model_dump()
        item["atomic_claims"] = [
            claim.model_dump() for claim in ctx.db.get_claims(finding.finding_id)
        ]
        item["claim_verifications"] = [
            verification.model_dump()
            for verification in ctx.db.get_claim_verifications(finding.finding_id)
        ]
        item["revisions"] = [
            revision.model_dump() for revision in ctx.db.get_finding_revisions(finding.finding_id)
        ]
        results.append(item)
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
@tool_access(Role.REPORT)
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
    coverage_records = ctx.db.get_coverage()

    confirmation_assessments: dict[str, ConfirmationAssessment] = {}
    for finding in findings:
        if finding.confidence != "confirmed":
            continue
        atomic_claims = ctx.db.get_claims(finding.finding_id)
        if not atomic_claims:
            continue
        ctx.db.verify_finding_claims(finding.finding_id)
        confirmation_assessments[finding.finding_id] = assess_confirmation(
            ctx.db.get_claims(finding.finding_id)
        )
    gate_results = _evaluate_finalize_gates(
        findings,
        case_metadata,
        sources_list,
        audit_summary,
        coverage_records=coverage_records,
        confirmation_assessments=confirmation_assessments,
    )
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

    review = query_case_review(
        ReviewQuery(
            case_id=case_metadata.case_id,
            db_dir=report_dir,
            finding_limit=500,
            evidence_limit=1000,
            revision_limit=1000,
        )
    )
    proof_cards = review.proof_cards()
    review_data = review.model_dump(mode="json", by_alias=True)
    reasoning_review = ctx.db.get_reasoning_review()
    run_id = os.environ.get("MULDER_RUN_ID") or None
    if run_id is not None and (not run_id or Path(run_id).name != run_id):
        return {
            "tool_call_id": tc_id,
            "status": "blocked",
            "error_message": "Cannot finalize: durable run ID is invalid.",
        }
    renderer = ReportRenderer(run_id=run_id)
    run_scope = renderer._load_run_summary(report_dir, case_metadata.case_id, run_id)
    if run_id is not None and (run_scope is None or run_scope.get("error")):
        return {
            "tool_call_id": tc_id,
            "status": "blocked",
            "error_message": (
                "Cannot finalize: durable report/run scope is invalid: "
                f"{run_scope.get('error') if run_scope else 'missing scope'}"
            ),
        }

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

    enrichment_rows = ctx.db.get_windows_by_source("enrichment.iocs")
    enrichment_windows: list[dict[str, Any]] = [{"raw_text": w.raw_text} for w in enrichment_rows]

    html_path: Path | None = report_dir / f"{case_metadata.case_id}.report.html"
    try:
        report_text, html_text, _ = renderer.render_all(
            case_metadata=case_metadata,
            findings=findings,
            audit_summary=audit_summary,
            audit_log_path=audit_log_path,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
            source_windows=source_windows,
            generate_pdf=False,
            enrichment_windows=enrichment_windows,
            coverage_records=coverage_records,
            proof_cards=proof_cards,
            case_review=review_data,
            reasoning_review=reasoning_review,
        )
    except Exception as exc:
        logger.warning(
            "HTML report generation failed, falling back to markdown only", exc_info=True
        )
        report_text = renderer.render(
            case_metadata=case_metadata,
            findings=findings,
            audit_summary=audit_summary,
            audit_log_path=audit_log_path,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
            enrichment_windows=enrichment_windows,
            coverage_records=coverage_records,
            proof_cards=proof_cards,
            case_review=review_data,
            reasoning_review=reasoning_review,
        )
        html_text = ""
        html_warning: str | None = f"HTML report generation failed: {exc}"
        html_path = None
    else:
        html_warning = None

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")
    if html_path is not None and html_text:
        html_path.write_text(html_text, encoding="utf-8")
    binding_path: Path | None = None
    binding_hash: str | None = None
    if run_id is not None:
        report_hashes = {
            report_path.name: "sha256:" + hashlib.sha256(report_path.read_bytes()).hexdigest()
        }
        if html_path is not None and html_path.is_file():
            report_hashes[html_path.name] = (
                "sha256:" + hashlib.sha256(html_path.read_bytes()).hexdigest()
            )
        binding = {
            "schema": "mulder.report-run-binding",
            "version": 1,
            "case_id": case_metadata.case_id,
            "run_id": run_id,
            "reports": report_hashes,
        }
        binding_path = report_dir / f"{case_metadata.case_id}.report-run.json"
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=report_dir,
            prefix=f".{binding_path.name}.",
            delete=False,
        ) as handle:
            temporary_binding = Path(handle.name)
            json.dump(binding, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_binding, binding_path)
        binding_hash = "sha256:" + hashlib.sha256(binding_path.read_bytes()).hexdigest()

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
    if run_id is not None and binding_path is not None:
        result.update(
            {
                "run_id": run_id,
                "report_run_binding": str(binding_path),
                "report_run_binding_sha256": binding_hash,
            }
        )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="finalize_report",
        params={},
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


_IOC_PATTERN = re.compile(
    r"\b(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|[a-fA-F0-9]{32,64}"
    r"|(?:[a-z0-9-]+\.)+[a-z]{2,}"
    r")\b"
)

_SEVERITY_RANK = SEVERITY_ORDER


def _jaccard(a: set[str], b: set[str]) -> float:
    """Compute the Jaccard similarity coefficient of two sets.

    Args:
        a: First set.
        b: Second set.

    Returns:
        Jaccard coefficient between 0.0 and 1.0.
    """
    if not a and not b:
        return 0.0
    intersection = a & b
    union = a | b
    return len(intersection) / len(union)


def _tokenize(text: str) -> set[str]:
    """Split text into lowercase word tokens, stripping punctuation.

    Args:
        text: Input text to tokenize.

    Returns:
        Set of lowercase word tokens longer than 2 characters.
    """
    return {w.lower().strip(".,;:!?()[]") for w in text.split() if len(w) > 2}


def _extract_ioc_tokens(description: str) -> set[str]:
    """Extract IOC-like tokens (IPs, hashes, domains) from text.

    Args:
        description: Finding description text.

    Returns:
        Set of IOC strings found in the text.
    """
    return set(_IOC_PATTERN.findall(description.lower()))


def _time_windows_overlap(a: Finding, b: Finding) -> float:
    """Compute overlap between two findings' time windows.

    Returns 1.0 if both findings share any part of the same time window,
    0.0 otherwise. Findings without timestamps return 0.0.

    Args:
        a: First finding.
        b: Second finding.

    Returns:
        1.0 if time windows overlap, 0.0 otherwise.
    """
    if not a.event_time_start or not b.event_time_start:
        return 0.0
    a_start = a.event_time_start
    a_end = a.event_time_end or a.event_time_start
    b_start = b.event_time_start
    b_end = b.event_time_end or b.event_time_start
    if a_start <= b_end and b_start <= a_end:
        return 1.0
    return 0.0


def _compute_similarity(a: Finding, b: Finding) -> float:
    """Compute a weighted similarity score between two findings.

    Combines six signals to detect findings describing the same event
    even when title wording differs significantly:
    - Title word overlap (Jaccard coefficient), weight 0.2
    - MITRE technique ID overlap (Jaccard), weight 0.15
    - IOC overlap in descriptions, weight 0.15
    - Evidence ref overlap (Jaccard), weight 0.25
    - Source overlap (Jaccard), weight 0.15
    - Time window overlap (binary), weight 0.1

    Args:
        a: First finding.
        b: Second finding.

    Returns:
        Similarity score between 0.0 and 1.0.
    """
    title_sim = _jaccard(_tokenize(a.title), _tokenize(b.title))
    mitre_sim = _jaccard(set(a.mitre_attack_ids), set(b.mitre_attack_ids))
    ioc_sim = _jaccard(
        _extract_ioc_tokens(a.description),
        _extract_ioc_tokens(b.description),
    )
    evidence_sim = _jaccard(set(a.evidence_refs), set(b.evidence_refs))
    source_sim = _jaccard(set(a.sources), set(b.sources))
    time_sim = _time_windows_overlap(a, b)

    return (
        0.20 * title_sim
        + 0.15 * mitre_sim
        + 0.15 * ioc_sim
        + 0.25 * evidence_sim
        + 0.15 * source_sim
        + 0.10 * time_sim
    )


def _group_duplicates(
    findings: list[Finding],
    threshold: float,
) -> list[list[Finding]]:
    """Group findings into clusters of likely duplicates.

    Uses single-linkage clustering: two findings in the same group
    if either is similar enough to any existing group member.

    Args:
        findings: All findings for the case.
        threshold: Minimum similarity to join a group.

    Returns:
        List of groups, where each group is a list of similar findings.
        Single-member groups (unique findings) are included.
    """
    groups: list[list[Finding]] = []
    assigned: set[str] = set()

    for finding in findings:
        if finding.finding_id in assigned:
            continue
        group = [finding]
        assigned.add(finding.finding_id)

        for candidate in findings:
            if candidate.finding_id in assigned:
                continue
            for member in group:
                if _compute_similarity(member, candidate) >= threshold:
                    group.append(candidate)
                    assigned.add(candidate.finding_id)
                    break

        groups.append(group)

    return groups


def _consolidate_group(
    group: list[Finding],
) -> tuple[Finding, list[str]]:
    """Select the representative finding and merge metadata from duplicates.

    Keeps the finding with the longest description. Merges unique
    evidence_refs, sources, and MITRE IDs from all group members.
    Elevates severity to the highest in the group.

    Args:
        group: List of similar findings to consolidate.

    Returns:
        Tuple of (representative finding to keep, finding_ids to delete).
    """
    best = max(group, key=lambda f: len(f.description))
    to_delete: list[str] = []

    all_sources: set[str] = set()
    all_refs: set[str] = set()
    all_mitre: set[str] = set()
    highest_severity = best.severity

    for f in group:
        all_sources.update(f.sources)
        all_refs.update(f.evidence_refs)
        all_mitre.update(f.mitre_attack_ids)
        if _SEVERITY_RANK.get(f.severity, 99) < _SEVERITY_RANK.get(highest_severity, 99):
            highest_severity = f.severity
        if f.finding_id != best.finding_id:
            to_delete.append(f.finding_id)

    best.sources = sorted(all_sources)
    best.evidence_refs = sorted(all_refs)
    best.mitre_attack_ids = sorted(all_mitre)
    best.severity = highest_severity

    return best, to_delete


@mcp.tool()
@tool_access(Role.NARRATIVE_EXECUTOR | Role.NARRATIVE_ANALYST | Role.REPORT)
def deduplicate_findings(
    case_id: str,
    similarity_threshold: float = 0.4,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Identify and consolidate duplicate findings across systems.

    Groups findings by evidence overlap, source overlap, time window
    overlap, MITRE technique overlap, title similarity, and IOC overlap.
    For each duplicate group, keeps the most detailed finding and merges
    system-specific metadata from the others.

    Args:
        case_id: Active case identifier.
        similarity_threshold: Minimum combined similarity score (0.0 to
            1.0) to consider two findings as duplicates. Default 0.4.
        dry_run: If True, return the proposed groups without modifying
            findings.

    Returns:
        Dict with ``groups`` (proposed or applied merge groups),
        ``merged_count`` (findings removed), and ``kept_count``
        (findings retained).
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    findings = ctx.db.get_findings()
    groups = _group_duplicates(findings, similarity_threshold)

    multi_groups = [g for g in groups if len(g) > 1]
    merged_count = 0
    kept_count = len(findings)
    group_summaries: list[dict[str, Any]] = []

    for group in multi_groups:
        representative, delete_ids = _consolidate_group(group)
        affected_systems = sorted({s for f in group for s in f.sources})
        suffix = f"\n\n**Affected Systems:** {', '.join(affected_systems)}"

        group_summary: dict[str, Any] = {
            "representative_id": representative.finding_id,
            "representative_title": representative.title,
            "merged_ids": delete_ids,
            "affected_systems": affected_systems,
            "group_size": len(group),
        }
        group_summaries.append(group_summary)

        if not dry_run:
            if suffix not in representative.description:
                representative.description += suffix
            ctx.db.update_finding(
                representative.finding_id,
                actor_kind="system",
                reason_code="deduplicated_findings",
                description=representative.description,
                severity=representative.severity,
                sources=representative.sources,
                evidence_refs=representative.evidence_refs,
                mitre_attack_ids=representative.mitre_attack_ids,
            )
            for fid in delete_ids:
                ctx.db.delete_finding(
                    fid,
                    actor_kind="system",
                    reason_code="merged_as_duplicate",
                )
            merged_count += len(delete_ids)

    if not dry_run:
        kept_count = len(findings) - merged_count

    result: dict[str, Any] = {
        "tool_call_id": tc_id,
        "status": "success",
        "dry_run": dry_run,
        "groups": group_summaries,
        "merged_count": merged_count if not dry_run else 0,
        "would_merge_count": sum(len(g["merged_ids"]) for g in group_summaries),
        "kept_count": kept_count,
        "total_groups": len(multi_groups),
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="deduplicate_findings",
        params={
            "case_id": case_id,
            "similarity_threshold": similarity_threshold,
            "dry_run": dry_run,
        },
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result
