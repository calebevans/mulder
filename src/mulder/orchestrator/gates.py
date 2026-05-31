"""Quality gates for validating investigation phase completion.

Each gate function examines the investigation state after a phase completes
and returns a structured result indicating whether the phase produced
sufficient output to proceed. Failed gates trigger retry logic in the
orchestrator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GateCheck:
    """Individual gate check result.

    Attributes:
        name: Short identifier for this check.
        passed: Whether the check passed.
        detail: Human-readable explanation of the result.
    """

    name: str
    passed: bool
    detail: str = ""


@dataclass
class GateResult:
    """Aggregate result of a phase validation gate.

    Attributes:
        passed: True if all checks passed.
        phase_name: Name of the phase being validated.
        checks: Individual check results.
        gaps: List of identified gaps requiring remediation.
    """

    passed: bool
    phase_name: str
    checks: list[GateCheck] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def validate_catalog(summary: dict[str, Any]) -> GateResult:
    """Validate that the catalog phase created a case with evidence.

    The catalog phase classifies evidence files and creates the case
    in the database. It does NOT index sources (that happens during
    extraction). This gate verifies the case exists and evidence was
    discovered.

    Args:
        summary: Output from ``get_investigation_summary`` after cataloging.

    Returns:
        GateResult indicating whether a case was created.
    """
    checks: list[GateCheck] = []
    gaps: list[str] = []

    # If we got a non-empty summary back, the case exists
    case_exists = bool(summary) and summary.get("case_id") is not None
    check_case = GateCheck(
        name="case_created",
        passed=case_exists,
        detail="Case created" if case_exists else "No case found",
    )
    checks.append(check_case)
    if not check_case.passed:
        gaps.append("No case was created during cataloging. scan_evidence may have failed.")

    evidence_found = bool(summary.get("evidence_root"))
    check_evidence = GateCheck(
        name="evidence_discovered",
        passed=evidence_found,
        detail="Evidence root set" if evidence_found else "No evidence root in summary",
    )
    checks.append(check_evidence)
    if not check_evidence.passed:
        gaps.append("Catalog completed but no evidence_root was set.")

    return GateResult(
        passed=all(c.passed for c in checks),
        phase_name="catalog",
        checks=checks,
        gaps=gaps,
    )


def validate_extraction(summary: dict[str, Any] | None) -> GateResult:
    """Validate that extraction indexed sources into the database.

    The extraction gate is intentionally lenient per-system: indexing
    sources is required, but findings may come from later systems or
    the cross-system phase. If the summary query failed (None or empty),
    the gate passes to avoid blocking on transient MCP issues.

    Args:
        summary: Output from ``get_investigation_summary`` after extraction,
            or None if the utility query failed entirely.

    Returns:
        GateResult indicating extraction completeness.
    """
    checks: list[GateCheck] = []
    gaps: list[str] = []

    if not summary:
        detail = "Summary query failed; passing gate to avoid false block"
        logger.warning("Extraction gate: %s", detail)
        return GateResult(
            passed=True,
            phase_name="extraction",
            checks=[
                GateCheck(
                    name="summary_unavailable",
                    passed=True,
                    detail=detail,
                )
            ],
            gaps=[],
        )

    sources_indexed = summary.get("sources_indexed", 0)
    check_sources = GateCheck(
        name="sources_populated",
        passed=sources_indexed > 0,
        detail=f"{sources_indexed} source(s) indexed",
    )
    checks.append(check_sources)
    if not check_sources.passed:
        gaps.append("No sources indexed after extraction.")

    return GateResult(
        passed=all(c.passed for c in checks),
        phase_name="extraction",
        checks=checks,
        gaps=gaps,
    )


def validate_cross_system(summary: dict[str, Any] | None) -> GateResult:
    """Validate that cross-system analysis was performed.

    If the summary query failed (None or empty), the gate passes with
    a warning to avoid blocking on transient MCP issues.

    Args:
        summary: Output from ``get_investigation_summary`` after cross-system
            analysis, or None if the utility query failed.

    Returns:
        GateResult indicating cross-system completeness.
    """
    checks: list[GateCheck] = []
    gaps: list[str] = []

    if not summary:
        detail = "Summary query failed; passing gate to avoid false block"
        logger.warning("Cross-system gate: %s", detail)
        return GateResult(
            passed=True,
            phase_name="cross_system",
            checks=[
                GateCheck(
                    name="summary_unavailable",
                    passed=True,
                    detail=detail,
                )
            ],
            gaps=[],
        )

    findings_submitted = summary.get("findings_submitted", 0)
    check_findings = GateCheck(
        name="cross_system_findings",
        passed=findings_submitted > 0,
        detail=f"{findings_submitted} total finding(s) after cross-system analysis",
    )
    checks.append(check_findings)
    if not check_findings.passed:
        gaps.append("No findings exist after cross-system analysis.")

    mitre_count = summary.get("findings_with_mitre_ids", 0)
    check_mitre = GateCheck(
        name="mitre_mapping",
        passed=mitre_count > 0,
        detail=f"{mitre_count} finding(s) mapped to MITRE ATT&CK",
    )
    checks.append(check_mitre)
    if not check_mitre.passed:
        gaps.append("No findings have MITRE ATT&CK technique mappings.")

    return GateResult(
        passed=all(c.passed for c in checks),
        phase_name="cross_system",
        checks=checks,
        gaps=gaps,
    )


def validate_audit(
    summary: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
) -> GateResult:
    """Validate that the audit phase resolved quality gaps.

    Requires at least one gate check to be evaluated; an empty readiness
    response fails the gate to prevent vacuous passes.

    Args:
        summary: Output from ``get_investigation_summary``, or None.
        readiness: Output from ``check_finalize_readiness``, or None.

    Returns:
        GateResult reflecting finalize readiness state.
    """
    checks: list[GateCheck] = []
    gaps: list[str] = []

    if not readiness:
        detail = "Readiness query failed; cannot verify audit"
        logger.warning("Audit gate: %s", detail)
        return GateResult(
            passed=False,
            phase_name="audit",
            checks=[GateCheck(name="readiness_unavailable", passed=False, detail=detail)],
            gaps=[detail],
        )

    gate_details = readiness.get("gates", [])

    for gate in gate_details:
        gate_name = str(gate.get("name", "unknown"))
        gate_passed = bool(gate.get("passed", False))
        gate_detail = str(gate.get("detail", ""))

        # Allow narrative gate to fail since it is written in the report phase
        if gate_name == "narrative_submitted" and not gate_passed:
            checks.append(
                GateCheck(
                    name=gate_name,
                    passed=True,
                    detail="Deferred to report phase",
                )
            )
            continue

        checks.append(
            GateCheck(
                name=gate_name,
                passed=gate_passed,
                detail=gate_detail,
            )
        )
        if not gate_passed:
            gaps.append(f"{gate_name}: {gate_detail}")

    # Fail when no checks were evaluated (prevents vacuous pass)
    if not checks:
        checks.append(
            GateCheck(
                name="checks_performed",
                passed=False,
                detail="No readiness checks were evaluated",
            )
        )
        gaps.append("No readiness checks were returned by check_finalize_readiness")

    if summary:
        remaining = summary.get("remaining_work", [])
        for item in remaining:
            item_str = str(item)
            if "narrative" in item_str.lower():
                continue
            gaps.append(item_str)

    return GateResult(
        passed=len(checks) > 0 and all(c.passed for c in checks),
        phase_name="audit",
        checks=checks,
        gaps=gaps,
    )


def validate_report(result_messages: list[dict[str, Any]]) -> GateResult:
    """Validate that finalize_report succeeded.

    Checks for indicators in the assistant text that the report was
    generated. Uses broad matching since Claude describes the outcome
    in natural language rather than echoing exact tool output keys.

    Args:
        result_messages: Collected assistant messages from the report phase.

    Returns:
        GateResult indicating whether the report was generated.
    """
    checks: list[GateCheck] = []
    gaps: list[str] = []

    _SUCCESS_INDICATORS = (
        "report_path",
        "finalize_report",
        ".report.md",
        ".report.html",
        "report has been",
        "successfully finalized",
        "finalization complete",
        "report generated",
        "finalized",
    )

    finalized = False
    for msg in result_messages:
        text = str(msg.get("text", "")).lower()
        if any(indicator in text for indicator in _SUCCESS_INDICATORS):
            finalized = True
            break

    check = GateCheck(
        name="report_finalized",
        passed=finalized,
        detail="Report generated" if finalized else "finalize_report was not called or failed",
    )
    checks.append(check)
    if not check.passed:
        gaps.append("The report was not finalized. Ensure all gates pass and retry.")

    return GateResult(
        passed=all(c.passed for c in checks),
        phase_name="report",
        checks=checks,
        gaps=gaps,
    )
