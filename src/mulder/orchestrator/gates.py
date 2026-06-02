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

_consecutive_extraction_failures: int = 0
_consecutive_cross_system_failures: int = 0


def reset_gate_failure_counters() -> None:
    """Reset consecutive failure counters for extraction and cross-system gates.

    Call between investigations or in test fixtures to ensure gate state
    does not leak across runs.
    """
    global _consecutive_extraction_failures, _consecutive_cross_system_failures  # noqa: PLW0603
    _consecutive_extraction_failures = 0
    _consecutive_cross_system_failures = 0


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


def validate_catalog(catalog_json: dict[str, Any]) -> GateResult:
    """Validate that the catalog phase produced structured JSON output.

    The catalog agent must emit a final JSON message containing
    ``case_id``, ``evidence_root``, and a non-empty ``systems`` array.
    This gate validates that structure directly rather than scanning
    assistant text for keywords.

    Args:
        catalog_json: Parsed JSON from the catalog agent's final message,
            or an empty dict if parsing failed.

    Returns:
        GateResult indicating whether the catalog output is valid.
    """
    checks: list[GateCheck] = []
    gaps: list[str] = []

    case_exists = bool(catalog_json) and catalog_json.get("case_id") is not None
    check_case = GateCheck(
        name="case_created",
        passed=case_exists,
        detail="Case created" if case_exists else "No case_id in catalog JSON",
    )
    checks.append(check_case)
    if not check_case.passed:
        gaps.append(
            "Catalog did not output valid JSON with a case_id. "
            "Ensure the final message is raw JSON matching the required schema."
        )

    evidence_found = bool(catalog_json.get("evidence_root"))
    check_evidence = GateCheck(
        name="evidence_discovered",
        passed=evidence_found,
        detail="Evidence root set" if evidence_found else "No evidence_root in catalog JSON",
    )
    checks.append(check_evidence)
    if not check_evidence.passed:
        gaps.append("Catalog JSON is missing the evidence_root field.")

    systems = catalog_json.get("systems", [])
    has_systems = isinstance(systems, list) and len(systems) > 0
    system_count = len(systems) if has_systems else 0
    check_systems = GateCheck(
        name="systems_identified",
        passed=has_systems,
        detail=(
            f"{system_count} system(s) identified" if has_systems else "No systems in catalog JSON"
        ),
    )
    checks.append(check_systems)
    if not check_systems.passed:
        gaps.append(
            "Catalog JSON must include a non-empty 'systems' array. "
            "Each entry needs at minimum a 'name' field."
        )

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
    the cross-system phase. If the summary query fails on the first
    attempt, the gate passes with an advisory warning. On consecutive
    failures, the gate fails to prevent indefinite silent auto-passes.

    Args:
        summary: Output from ``get_investigation_summary`` after extraction,
            or None if the utility query failed entirely.

    Returns:
        GateResult indicating extraction completeness.
    """
    global _consecutive_extraction_failures  # noqa: PLW0603

    checks: list[GateCheck] = []
    gaps: list[str] = []

    if not summary:
        if _consecutive_extraction_failures >= 1:
            detail = "Summary query failed on retry; cannot validate extraction"
            logger.error("Extraction gate: %s", detail)
            _consecutive_extraction_failures += 1
            return GateResult(
                passed=False,
                phase_name="extraction",
                checks=[
                    GateCheck(
                        name="summary_unavailable",
                        passed=False,
                        detail=detail,
                    )
                ],
                gaps=["Summary query failed on retry; cannot validate phase"],
            )
        _consecutive_extraction_failures += 1
        detail = "Summary query failed; passing gate with advisory warning"
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
            gaps=["ADVISORY: summary check skipped due to query failure"],
        )

    _consecutive_extraction_failures = 0

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

    If the summary query fails on the first attempt, the gate passes with
    an advisory warning. On consecutive failures, the gate fails to prevent
    indefinite silent auto-passes.

    Args:
        summary: Output from ``get_investigation_summary`` after cross-system
            analysis, or None if the utility query failed.

    Returns:
        GateResult indicating cross-system completeness.
    """
    global _consecutive_cross_system_failures  # noqa: PLW0603

    checks: list[GateCheck] = []
    gaps: list[str] = []

    if not summary:
        if _consecutive_cross_system_failures >= 1:
            detail = "Summary query failed on retry; cannot validate cross-system"
            logger.error("Cross-system gate: %s", detail)
            _consecutive_cross_system_failures += 1
            return GateResult(
                passed=False,
                phase_name="cross_system",
                checks=[
                    GateCheck(
                        name="summary_unavailable",
                        passed=False,
                        detail=detail,
                    )
                ],
                gaps=["Summary query failed on retry; cannot validate phase"],
            )
        _consecutive_cross_system_failures += 1
        detail = "Summary query failed; passing gate with advisory warning"
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
            gaps=["ADVISORY: summary check skipped due to query failure"],
        )

    _consecutive_cross_system_failures = 0

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


def validate_narrative(
    summary: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
) -> GateResult:
    """Validate that the narrative phase resolved quality gaps.

    The alternative narrative phase now includes audit responsibilities.
    This gate checks finalize readiness to confirm the investigation is
    ready for the report phase. Requires at least one gate check to be
    evaluated; an empty readiness response fails the gate to prevent
    vacuous passes.

    Args:
        summary: Output from ``get_investigation_summary``, or None.
        readiness: Output from ``check_finalize_readiness``, or None.

    Returns:
        GateResult reflecting finalize readiness state.
    """
    checks: list[GateCheck] = []
    gaps: list[str] = []

    if not readiness:
        detail = "Readiness query failed; cannot verify narrative phase"
        logger.warning("Narrative gate: %s", detail)
        return GateResult(
            passed=False,
            phase_name="alternative_narrative",
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
        phase_name="alternative_narrative",
        checks=checks,
        gaps=gaps,
    )


def validate_report(tool_names: list[str]) -> GateResult:
    """Validate that finalize_report was invoked during the report phase.

    Checks the structured tool call log for a ``finalize_report``
    invocation rather than scanning assistant prose for text indicators.

    Args:
        tool_names: List of MCP tool short names invoked during the
            report phase (captured from ToolUseBlock events).

    Returns:
        GateResult indicating whether the report was generated.
    """
    checks: list[GateCheck] = []
    gaps: list[str] = []

    finalized = "finalize_report" in tool_names

    check = GateCheck(
        name="report_finalized",
        passed=finalized,
        detail=(
            "finalize_report was called" if finalized else "finalize_report was never invoked"
        ),
    )
    checks.append(check)
    if not check.passed:
        gaps.append("The report was not finalized. Call finalize_report to generate it.")

    return GateResult(
        passed=all(c.passed for c in checks),
        phase_name="report",
        checks=checks,
        gaps=gaps,
    )
