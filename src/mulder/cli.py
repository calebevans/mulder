"""Click CLI entry point for Mulder."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from mulder import __version__


@click.group()
@click.version_option(version=__version__, prog_name="mulder")
def cli() -> None:
    """Mulder -- forensic MCP server for the SANS SIFT Workstation."""


@cli.command()
@click.option("--case-id", default=None, help="Pre-load this case on startup.")
@click.option(
    "--db-dir",
    default="~/.mulder/cases",
    show_default=True,
    help="Directory containing per-case databases.",
)
@click.option(
    "--transport",
    default="stdio",
    show_default=True,
    type=click.Choice(["stdio", "streamable-http"]),
    help="MCP transport to use.",
)
@click.option(
    "--workers",
    default=8,
    show_default=True,
    help="Number of parallel extraction workers for ingestion.",
)
@click.option(
    "--mem-limit",
    default=90.0,
    show_default=True,
    help="Memory usage %% threshold; tools wait when exceeded (0 to disable).",
)
@click.option(
    "--cpu-limit",
    default=90.0,
    show_default=True,
    help="CPU usage %% threshold; tools wait when exceeded (0 to disable).",
)
def serve(
    case_id: str | None,
    db_dir: str,
    transport: str,
    workers: int,
    mem_limit: float,
    cpu_limit: float,
) -> None:
    """Start the Mulder MCP server.

    Without --case-id, starts in ready state. The agent can then call
    scan_evidence() to create a new case, or open_case() to load an
    existing one.  The agent drives extraction by calling Tier 2 tools
    (run_volatility, run_fls, run_plaso, etc.) on demand.

    With --case-id, pre-loads that case so analysis tools work immediately.
    """
    from mulder.server.app import init_server
    from mulder.server.app import mcp as mcp_server

    db_dir_path = Path(db_dir).expanduser()
    db_dir_path.mkdir(parents=True, exist_ok=True)

    log_file = db_dir_path / "mulder.log"
    file_handler = logging.FileHandler(str(log_file), mode="a")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(threadName)s] %(levelname)s %(name)s: %(message)s")
    )
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)

    if case_id:
        click.echo(f"Initialising MCP server for case '{case_id}' ...", err=True)
    else:
        click.echo("Initialising MCP server (no case pre-loaded) ...", err=True)
    click.echo(f"Logging to {log_file}", err=True)

    init_server(
        db_dir=db_dir_path,
        case_id=case_id,
        max_workers=workers,
        mem_percent_limit=mem_limit,
        cpu_percent_limit=cpu_limit,
    )

    click.echo(f"Starting MCP server (transport={transport}) ...", err=True)
    mcp_server.run(transport=transport)  # type: ignore[arg-type]


@cli.command()
@click.argument("case_id")
@click.option(
    "--db-dir",
    default="~/.mulder/cases",
    show_default=True,
    help="Directory containing per-case databases.",
)
def report(case_id: str, db_dir: str) -> None:
    """Generate HTML + Markdown reports from an existing case database.

    Reads the case DB and audit log from DB_DIR, renders both report
    formats, and writes them alongside the database.  Does not require
    the MCP server to be running.
    """
    from mulder.audit import AuditLog
    from mulder.db import CaseDB
    from mulder.report.renderer import ReportRenderer

    db_dir_path = Path(db_dir).expanduser()
    db_path = db_dir_path / f"{case_id}.db"
    audit_path = db_dir_path / f"{case_id}.audit.jsonl"

    if not db_path.exists():
        raise click.ClickException(f"Case database not found: {db_path}")

    click.echo(f"Loading case '{case_id}' from {db_path} ...")

    with CaseDB(db_path) as case_db:
        case_metadata = case_db.get_case_metadata()
        findings = case_db.get_findings()
        sources_list = case_db.get_sources()
        evidence_integrity = case_db.get_evidence_registry()

        audit = AuditLog(audit_path)
        audit_summary = audit.summary()

        click.echo(f"  {len(findings)} findings, {len(sources_list)} sources")

        renderer = ReportRenderer()

        md_path = db_dir_path / f"{case_id}.report.md"
        md_text = renderer.render(
            case_metadata=case_metadata,
            findings=findings,
            audit_summary=audit_summary,
            audit_log_path=audit_path,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
        )
        md_path.write_text(md_text, encoding="utf-8")
        click.echo(f"  Markdown: {md_path}")

        _MAX_WINDOWS = 50
        source_windows: dict[str, list[dict[str, object]]] = {}
        for src in sources_list:
            windows = case_db.get_windows_by_source(src.source_name)
            total = len(windows)
            capped = windows[:_MAX_WINDOWS]
            source_windows[src.source_name] = [
                {
                    "line_start": w.line_start,
                    "line_end": w.line_end,
                    "event_time": w.event_time,
                    "raw_text": w.raw_text,
                    "total": total,
                    "truncated": total > _MAX_WINDOWS,
                }
                for w in capped
            ]

        html_path = db_dir_path / f"{case_id}.report.html"
        html_text = renderer.render_html(
            case_metadata=case_metadata,
            findings=findings,
            audit_summary=audit_summary,
            audit_log_path=audit_path,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
            source_windows=source_windows,
        )
        html_path.write_text(html_text, encoding="utf-8")
        click.echo(f"  HTML:     {html_path}")

    click.echo("Done.")


@cli.command("validate-pre-finalize")
@click.option(
    "--db-dir",
    default="~/.mulder/cases",
    show_default=True,
    help="Directory containing per-case databases.",
)
@click.option(
    "--min-coverage",
    default=0.7,
    show_default=True,
    type=float,
    help="Minimum fraction of sources that must be cited by findings.",
)
def validate_pre_finalize(db_dir: str, min_coverage: float) -> None:
    """Validate prerequisites before finalizing a report.

    Used as a Claude Code PreToolUse hook to block premature finalization.
    Outputs JSON compatible with the hookSpecificOutput schema.
    """
    import json

    from mulder.db import CaseDB

    db_dir_path = Path(db_dir).expanduser()

    db_files = sorted(
        db_dir_path.glob("*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not db_files:
        click.echo(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "permissionDecisionReason": "No case DB found",
                    }
                }
            )
        )
        return

    db_path = db_files[0]

    with CaseDB(db_path) as case_db:
        findings = case_db.get_findings()
        sources = case_db.get_sources()

        if not findings:
            click.echo(
                json.dumps(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": (
                                "No findings submitted yet. You must submit findings "
                                "before finalizing the report."
                            ),
                        }
                    }
                )
            )
            return

        cited_sources: set[str] = set()
        for finding in findings:
            cited_sources.update(finding.sources)

        total = len(sources)
        cited = len(cited_sources)
        coverage = cited / total if total > 0 else 0.0

        if coverage < min_coverage:
            click.echo(
                json.dumps(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": (
                                f"Evidence coverage too low: {cited}/{total} sources "
                                f"cited ({coverage:.0%}). Must exceed {min_coverage:.0%}. "
                                f"Run audit_evidence_coverage() to identify uncited "
                                f"sources, then analyze them and submit findings."
                            ),
                        }
                    }
                )
            )
            return

        click.echo(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "permissionDecisionReason": (
                            f"Coverage {cited}/{total} ({coverage:.0%}) meets threshold."
                        ),
                    }
                }
            )
        )


if __name__ == "__main__":
    cli()
