"""Render a case's Markdown and HTML reports straight from its database.

Shared by ``mulder report`` and by the partial report ``mulder investigate``
leaves behind when a run ends without a finalized one. No gates and no MCP
server: it reads the case database and audit log and writes next to them.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.report.renderer import ReportRenderer

_MAX_WINDOWS = 50


class WrittenReport(NamedTuple):
    """What :func:`write_case_report` wrote, and from how much."""

    markdown: Path
    html: Path | None
    html_error: str
    findings: int
    sources: int


def write_case_report(
    case_id: str, db_dir: Path, incomplete: Sequence[str] = (), stem: str = ""
) -> WrittenReport:
    """Write ``<case_id>.report.md`` and ``.report.html`` beside the case database.

    Args:
        case_id: Case identifier; the database is ``<db_dir>/<case_id>.db``
            and must exist.
        db_dir: Directory holding the case database and audit log.
        incomplete: Lines saying where and why the investigation stopped.
            When non-empty both reports open with an INCOMPLETE banner.
        stem: Name the two files ``<stem>.report.md`` and ``.report.html``
            instead of after the case, to leave an existing report alone.

    Returns:
        The paths written and the counts rendered. ``html`` is None, with
        the reason in ``html_error``, when only the Markdown could be
        rendered.
    """
    audit_path = db_dir / f"{case_id}.audit.jsonl"
    stem = stem or case_id

    with CaseDB(db_dir / f"{case_id}.db") as case_db:
        case_metadata = case_db.get_case_metadata()
        findings = case_db.get_findings()
        sources_list = case_db.get_sources()
        evidence_integrity = case_db.get_evidence_registry()
        questions = case_db.get_questions()
        cut_short = case_db.get_cut_short()
        unanalysed = case_db.get_unanalysed()
        audit_summary = AuditLog(audit_path).summary()

        renderer = ReportRenderer()

        md_path = db_dir / f"{stem}.report.md"
        md_text = renderer.render(
            case_metadata=case_metadata,
            findings=findings,
            audit_summary=audit_summary,
            audit_log_path=audit_path,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
            incomplete=incomplete,
            questions=questions,
            cut_short=cut_short,
            unanalysed=unanalysed,
        )
        md_path.write_text(md_text, encoding="utf-8")

        source_names = [s.source_name for s in sources_list]
        bulk_windows = case_db.get_capped_windows_by_sources(source_names, _MAX_WINDOWS)
        source_windows: dict[str, list[dict[str, object]]] = {}
        for sname, (windows, total) in bulk_windows.items():
            source_windows[sname] = [
                {
                    "line_start": w.line_start,
                    "line_end": w.line_end,
                    "event_time": w.event_time,
                    "raw_text": w.raw_text,
                    "total": total,
                    "truncated": total > _MAX_WINDOWS,
                }
                for w in windows
            ]

        html_path = db_dir / f"{stem}.report.html"
        html_error = ""
        try:
            html_text = renderer.render_html(
                case_metadata=case_metadata,
                findings=findings,
                audit_summary=audit_summary,
                audit_log_path=audit_path,
                sources_list=sources_list,
                evidence_integrity=evidence_integrity,
                source_windows=source_windows,
                incomplete=incomplete,
                questions=questions,
                cut_short=cut_short,
                unanalysed=unanalysed,
            )
            html_path.write_text(html_text, encoding="utf-8")
        except Exception as exc:
            html_error = str(exc) or type(exc).__name__

    return WrittenReport(
        md_path, None if html_error else html_path, html_error, len(findings), len(sources_list)
    )
