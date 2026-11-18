"""Quality gates for validating investigation phase completion.

Each gate function examines the investigation state after a phase completes
and returns a structured result indicating whether the phase produced
sufficient output to proceed. Failed gates trigger retry logic in the
orchestrator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mulder.extractors.classifier import EvidenceClassifier

logger = logging.getLogger(__name__)

_consecutive_extraction_failures: int = 0
_consecutive_cross_system_failures: int = 0
_catalog_coverage_reprompts: int = 0


def reset_gate_failure_counters() -> None:
    """Reset gate retry counters.

    Call between investigations or in test fixtures to ensure gate state
    does not leak across runs.
    """
    global _consecutive_extraction_failures, _consecutive_cross_system_failures  # noqa: PLW0603
    global _catalog_coverage_reprompts  # noqa: PLW0603
    _consecutive_extraction_failures = 0
    _consecutive_cross_system_failures = 0
    _catalog_coverage_reprompts = 0


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


def validate_catalog(
    catalog_json: dict[str, Any],
    evidence_path: str | None = None,
) -> GateResult:
    """Validate that the catalog phase produced structured JSON output.

    The catalog agent must emit a final JSON message containing
    ``case_id``, ``evidence_root``, and a non-empty ``systems`` array.
    This gate validates that structure directly rather than scanning
    assistant text for keywords.

    Fewer systems than disk images prompts one coverage check (#237), then
    becomes advisory: one host can have multiple disks or image formats.
    The classifier recognises several disk-image extensions; EWF segments
    after ``.E01`` are ignored. Ambiguous ``.img`` memory dumps are excluded,
    as are the classifier's memory dumps and split archive parts.

    Args:
        catalog_json: Parsed JSON from the catalog agent's final message,
            or an empty dict if parsing failed.
        evidence_path: Evidence directory to count disk images in. When
            omitted, or when it cannot be classified, the image-count
            check is skipped with a warning rather than failing.

    Returns:
        GateResult indicating whether the catalog output is valid.
    """
    global _catalog_coverage_reprompts  # noqa: PLW0603

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

    if check_systems.passed and evidence_path:
        root = Path(evidence_path)
        try:
            images = sorted(
                str(e.path.relative_to(root.resolve()))
                for e in EvidenceClassifier().classify(root)
                if e.artifact_type == "disk_image" and e.path.suffix.lower() != ".img"
            )
        except Exception:
            logger.warning("Catalog gate: cannot classify %s", evidence_path, exc_info=True)
            images = None
        if images is None:
            detail = "Evidence could not be classified; disk image count not verified"
            logger.warning("Catalog gate: %s", detail)
            checks.append(GateCheck(name="images_covered", passed=True, detail=detail))
        else:
            covered = system_count >= len(images)
            advisory = not covered and _catalog_coverage_reprompts >= 1
            checks.append(
                GateCheck(
                    name="images_covered",
                    passed=covered or advisory,
                    detail=f"{system_count} system(s) for {len(images)} disk image(s)",
                )
            )
            if not covered:
                _catalog_coverage_reprompts += 1
                gaps.append(
                    ("ADVISORY: " if advisory else "")
                    + (
                        f"Catalog registered {system_count} system(s) but the evidence "
                        f"contains {len(images)} disk image(s). Confirm every listed image "
                        "is accounted for by a system. Keep multiple disks, segments, or "
                        "formats belonging to the same host under one system. Images: "
                    )
                    + ", ".join(images)
                )
            else:
                _catalog_coverage_reprompts = 0

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

    Needs a finding and a MITRE-mapped finding, or, for a case where the
    evidence shows no incident, every recorded investigation question
    resolved and no finding of activity at medium severity or above. A
    summary without recorded questions is judged on the first pair only.

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

    # The second way to pass both checks: a case where the evidence shows no
    # incident has nothing to map to ATT&CK. It needs every recorded question
    # resolved and no finding of activity at medium severity or above. The
    # coverage audits the finalize gate also asks for are not required here:
    # no cross-system role can run them, they belong to the next phase.
    questions = summary.get("questions") or {}
    recorded = questions.get("recorded", 0)
    still_open = questions.get("open", 0)
    quiet = recorded > 0 and summary.get("significant_findings", 1) == 0
    by_questions = quiet and still_open == 0
    via = (
        f"; passed on resolved questions: all {recorded} recorded question(s) resolved "
        "and no finding of medium severity or above"
    )
    hint = (
        f" If the evidence examined shows no incident, resolve the {still_open} open "
        "investigation question(s) with resolve_question instead of adding a finding or "
        "a mapping the evidence does not support."
        if quiet
        else ""
    )

    findings_submitted = summary.get("findings_submitted", 0)
    check_findings = GateCheck(
        name="cross_system_findings",
        passed=findings_submitted > 0 or by_questions,
        detail=f"{findings_submitted} total finding(s) after cross-system analysis"
        + (via if findings_submitted == 0 and by_questions else ""),
    )
    checks.append(check_findings)
    if not check_findings.passed:
        gaps.append("No findings exist after cross-system analysis." + hint)

    mitre_count = summary.get("findings_with_mitre_ids", 0)
    check_mitre = GateCheck(
        name="mitre_mapping",
        passed=mitre_count > 0 or by_questions,
        detail=f"{mitre_count} finding(s) mapped to MITRE ATT&CK"
        + (via if mitre_count == 0 and by_questions else ""),
    )
    checks.append(check_mitre)
    if not check_mitre.passed:
        gaps.append("No findings have MITRE ATT&CK technique mappings." + hint)

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
        elif gate.get("advisory"):
            # Passed with a warning: surfaced in the log, never a gap, so
            # it cannot trigger a retry or fail the run.
            logger.warning("Narrative gate: %s: %s", gate_name, gate_detail)

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


def report_written(report_path: Path, since: float) -> bool:
    """Return True when the Markdown report was written at or after *since*.

    ``finalize_report`` writes it only after every readiness gate passes, so
    a report this fresh is a finalized one.

    Args:
        report_path: ``<db_dir>/<case_id>.report.md``.
        since: A ``time.time()`` value; an older report is a leftover.

    Returns:
        True if the file exists and is not older than *since*.
    """
    # 1s slack for filesystems with whole-second mtimes.
    return report_path.is_file() and report_path.stat().st_mtime >= since - 1.0


def validate_report(
    tool_names: list[str],
    report_path: Path,
    readiness: dict[str, Any] | None = None,
    started_at: float = 0.0,
) -> GateResult:
    """Validate that the report phase actually produced a report.

    ``finalize_report`` refuses (``status: blocked``) when its readiness
    gates fail and writes nothing, so having been *called* proves nothing.
    The Markdown report is written only after every readiness gate passes,
    which makes its presence the exact success signal.

    Args:
        tool_names: MCP tool short names invoked during the report phase.
        report_path: Where ``finalize_report`` writes the Markdown report
            (``<db_dir>/<case_id>.report.md``).
        readiness: Output of ``check_finalize_readiness``; its failing
            gates are surfaced in the gap so a retry knows what to fix.
        started_at: Phase start (``time.time()``); a report older than
            this is a leftover from an earlier run, not this phase's.

    Returns:
        GateResult indicating whether the report exists.
    """
    written = report_written(report_path, started_at)
    invoked = "finalize_report" in tool_names

    if written:
        detail = f"report written to {report_path}"
    elif invoked:
        detail = f"finalize_report was called but no report exists at {report_path}"
    else:
        detail = "finalize_report was never invoked"
    checks = [GateCheck(name="report_written", passed=written, detail=detail)]

    gaps: list[str] = []
    if not written and not invoked:
        gaps.append("The report was not finalized. Call finalize_report to generate it.")
    elif not written:
        failing = [
            f"{g.get('name', 'unknown')}: {g.get('detail', '')}"
            for g in (readiness or {}).get("gates", [])
            if not g.get("passed", False)
        ]
        fix = (
            "Fix these readiness gates, then call finalize_report again: " + "; ".join(failing)
            if failing
            else "Call check_finalize_readiness, fix what it reports, "
            "then call finalize_report again."
        )
        gaps.append(f"finalize_report was called but refused, so no report was written. {fix}")

    return GateResult(passed=written, phase_name="report", checks=checks, gaps=gaps)
