"""Jinja2 report renderer for Mulder investigation reports."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import jinja2

from mulder.models import AuditSummary, CaseMetadataRow, Finding

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportRenderer:
    """Renders validated findings into a markdown investigation report."""

    def __init__(self) -> None:
        self._env = jinja2.Environment(
            loader=jinja2.PackageLoader("mulder", "report/templates"),
            autoescape=False,
            keep_trailing_newline=True,
        )

    def render(
        self,
        case_metadata: CaseMetadataRow,
        findings: list[Finding],
        audit_summary: AuditSummary,
        audit_log_path: Path | str,
    ) -> str:
        sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

        confirmed = sum(1 for f in findings if f.confidence == "confirmed")
        inference = sum(1 for f in findings if f.confidence == "inference")

        template = self._env.get_template("report.md.j2")
        return template.render(
            case_id=case_metadata.case_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence_root=case_metadata.evidence_root,
            finding_count=len(findings),
            confirmed_count=confirmed,
            inference_count=inference,
            findings=sorted_findings,
            total_tool_calls=audit_summary.total_tool_calls,
            audit_log_path=str(audit_log_path),
        )
