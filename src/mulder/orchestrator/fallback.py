"""Partial report for an investigation that ended without a finalized one.

``finalize_report`` is the only thing that writes a report during a run, and
it refuses until every readiness gate passes. A run that dies first (out of
credit, bad credentials, a failed gate, Ctrl-C, a crash) would otherwise leave
its findings in the case database and nothing to read. This renders what the
database holds, marked INCOMPLETE, through the same code as ``mulder report``.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from mulder.db import CaseDB
from mulder.orchestrator.budget import TokenBudgetReached
from mulder.orchestrator.errors import (
    AuthenticationError,
    ModelNotAvailableError,
    OutOfCreditError,
)
from mulder.orchestrator.gates import report_written
from mulder.orchestrator.phases import (
    ALTERNATIVE_NARRATIVE,
    CATALOG,
    CROSS_SYSTEM,
    EXTRACTION,
    REPORT,
)
from mulder.report.case_report import WrittenReport, write_case_report

if TYPE_CHECKING:
    from mulder.orchestrator.runner import Orchestrator

logger = logging.getLogger(__name__)

_PHASE_ORDER: tuple[str, ...] = tuple(
    phase.name for phase in (CATALOG, EXTRACTION, CROSS_SYSTEM, ALTERNATIVE_NARRATIVE, REPORT)
)

#: How a partial report's Markdown opens (``report/templates/report.md.j2``).
#: A finalized report has its ``**Case:**`` line there instead.
_PARTIAL_HEAD = "# Mulder Investigation Report\n\n> **INCOMPLETE INVESTIGATION"

#: Unfinished systems the banner names; the rest are counted.
_MAX_SYSTEMS = 10

_REASONS: dict[type[BaseException], str] = {
    OutOfCreditError: "the API account is out of credit or over its quota",
    AuthenticationError: "authentication failed",
    ModelNotAvailableError: "the configured model is not available",
    TokenBudgetReached: "token budget reached",
}


def _one_line(text: str, limit: int = 300) -> str:
    """Flatten untrusted text to one bounded, printable line.

    Error bodies, gate gaps and system names (which come from evidence file
    names) end up in the report banner and on the terminal; none of them may
    add lines or control characters there.
    """
    flat = " ".join("".join(c if c.isprintable() else " " for c in text).split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _is_partial(report: Path) -> bool:
    """Return True when *report* is a partial report an earlier run left.

    The banner sits at a fixed place above all case content, so nothing a
    finding or source says can make a finalized report look partial.
    """
    with report.open(encoding="utf-8", errors="replace") as handle:
        return handle.read(len(_PARTIAL_HEAD)) == _PARTIAL_HEAD


def not_completed(orchestrator: Orchestrator) -> list[str]:
    """Name the phases that have not passed, and the systems extraction left.

    Args:
        orchestrator: The orchestrator, during or after its run.

    Returns:
        One bounded, printable entry per phase, in pipeline order.
    """
    phases = orchestrator.result.phases
    pending = [name for name, done in orchestrator.systems_done.items() if not done]
    left: list[str] = []
    for name in _PHASE_ORDER:
        results = [p for p in phases if p.phase_name == name]
        if name == EXTRACTION.name and pending:
            # Bounded on its own, so a many-host case cannot push the phases
            # after it out of the line.
            shown = ", ".join(_one_line(system, 40) for system in pending[:_MAX_SYSTEMS])
            more = len(pending) - _MAX_SYSTEMS
            left.append(
                f"{name} ({len(pending)} of {len(orchestrator.systems_done)} systems: {shown}"
                + (f", +{more} more)" if more > 0 else ")")
            )
        elif not results:
            left.append(name)
        elif not all(p.success for p in results):
            left.append(f"{name} (failed)")
    return left


def incomplete_notice(orchestrator: Orchestrator, error: BaseException | None) -> list[str]:
    """Say where the run stopped, why, and what it did not complete.

    Args:
        orchestrator: The orchestrator whose run just ended.
        error: What ended it, or None when the pipeline returned on its own
            (a phase failed its gate after every retry).

    Returns:
        Three plain-text lines for the INCOMPLETE banner.
    """
    phases = orchestrator.result.phases
    stopped = orchestrator.current_phase or _PHASE_ORDER[0]

    if error is None:
        gaps = [
            gap
            for p in phases
            if p.phase_name == stopped and not p.success and p.gate_result
            for gap in p.gate_result.gaps
        ]
        why = (
            "its gate failed after every retry: " + "; ".join(gaps)
            if gaps
            else "the pipeline ended without finalizing a report"
        )
    elif isinstance(error, KeyboardInterrupt | asyncio.CancelledError):
        why = "interrupted (Ctrl-C or SIGTERM)"
    else:
        label = _REASONS.get(type(error), f"unexpected {type(error).__name__}")
        why = f"{label}: {error}"
    reason = _one_line(why)
    # A gate names the symptom. When the last session ended on a provider
    # error (an ordinary 429, an overload), that is the likelier cause.
    if error is None and (session_error := orchestrator._session.last_query_error):
        reason += f"; last session error: {_one_line(session_error, 200)}"

    left = not_completed(orchestrator)
    return [
        f"Stopped in phase: {stopped}",
        f"Reason: {reason}",
        f"Not completed: {_one_line('; '.join(left), 600) or 'none recorded'}",
    ]


def write_fallback_report(
    orchestrator: Orchestrator,
    case_id: str,
    db_dir: Path,
    started_at: float,
    error: BaseException | None,
) -> WrittenReport | None:
    """Render a partial report unless this run already finalized one.

    Args:
        orchestrator: The orchestrator whose run just ended.
        case_id: Case identifier.
        db_dir: Directory holding the case database.
        started_at: ``time.time()`` taken before the run started.
        error: What ended the run, or None for a gate failure.

    Returns:
        What was written, or None when nothing was: the report was finalized
        during this run (it is never overwritten), there is no case
        database, or it holds no source and no finding yet. When an earlier
        run left a report that is not itself a partial one, that report is
        kept and this one is written as ``<case_id>.partial.report.*``.
    """
    report = db_dir / f"{case_id}.report.md"
    if report_written(report, started_at):
        return None
    db_path = db_dir / f"{case_id}.db"
    if not db_path.is_file():
        logger.info("No partial report: no case database at %s", db_path)
        return None
    with CaseDB(db_path) as case_db:
        if not case_db.get_source_count() and not case_db.get_findings():
            logger.info("No partial report: the case has no sources or findings yet")
            return None

    # The report's token table reads this sidecar, which a completed run
    # writes just before its report phase.
    orchestrator._write_model_usage()
    notice = incomplete_notice(orchestrator, error)
    stem = case_id
    if report.is_file() and not _is_partial(report):
        # An earlier run's report: that run's deliverable, which cannot be
        # rendered again from here (``finalize_report`` adds IOC enrichment)
        # and for which this run's banner would be false. Write beside it.
        stem = f"{case_id}.partial"
        notice.append(
            f"Earlier report: {_one_line(report.name)} is from an earlier run of this case "
            "and was kept unchanged"
        )
    written = write_case_report(case_id, db_dir, notice, stem)
    logger.warning("Investigation incomplete; partial report written to %s", written.markdown)
    return written
