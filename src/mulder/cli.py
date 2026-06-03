"""Click CLI entry point for Mulder."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from mulder import __version__
from mulder.patterns import DEFAULT_DB_DIR


@click.group()
@click.version_option(version=__version__, prog_name="mulder")
def cli() -> None:
    """Mulder: forensic MCP server for the SANS SIFT Workstation."""


@cli.command()
@click.option("--case-id", default=None, help="Pre-load this case on startup.")
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
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
    default=DEFAULT_DB_DIR,
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

        html_path = db_dir_path / f"{case_id}.report.html"
        try:
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
        except Exception as exc:
            click.echo(f"  HTML generation failed: {exc}", err=True)

    click.echo("Done.")


@cli.command()
@click.argument("evidence_path")
@click.argument("case_id")
@click.option(
    "--model",
    default=None,
    help="Fallback model for all roles.",
)
@click.option(
    "--planner-model",
    default=None,
    help="Model for planner agents (decides what to do).",
)
@click.option(
    "--executor-model",
    default=None,
    help="Model for executor agents (calls tools).",
)
@click.option(
    "--analyst-model",
    default=None,
    help="Model for analyst agents (interprets results).",
)
@click.option(
    "--config",
    "config_path",
    default=None,
    type=click.Path(),
    help="YAML config file for models and settings.",
)
@click.option(
    "--effort",
    default="max",
    type=click.Choice(["max", "xhigh", "high"]),
    show_default=True,
    help="Effort level.",
)
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    show_default=True,
    help="Case database directory.",
)
@click.option(
    "--cwd",
    default="/mulder-investigation",
    show_default=True,
    help="Working directory for sessions.",
)
@click.option(
    "--workers",
    default=3,
    show_default=True,
    help="Max parallel extraction sessions.",
)
@click.option(
    "--proxy-config",
    default=None,
    type=click.Path(exists=True),
    help="LiteLLM config YAML for custom model routing.",
)
def investigate(
    evidence_path: str,
    case_id: str,
    model: str | None,
    planner_model: str | None,
    executor_model: str | None,
    analyst_model: str | None,
    config_path: str | None,
    effort: str,
    db_dir: str,
    cwd: str,
    workers: int,
    proxy_config: str | None,
) -> None:
    """Run a full multi-pass forensic investigation.

    Uses a planner/executor/analyst pipeline for each phase. Configure
    models per role via CLI flags or a YAML config file.

    EVIDENCE_PATH is the filesystem path to the evidence directory.
    CASE_ID is the unique identifier for this investigation (used as the
    database filename and referenced by all phases).

    \b
      mulder investigate /evidence Rocba \\
        --planner-model claude-sonnet-4-6 \\
        --executor-model claude-haiku-4-5 \\
        --analyst-model claude-sonnet-4-6

    Non-Claude models are supported via LiteLLM proxy (auto-started when
    a model ID uses a provider prefix like bedrock/ or openai/).
    """
    import asyncio

    from mulder.orchestrator.models import ModelConfig
    from mulder.orchestrator.runner import Orchestrator

    mcp_config_file = Path(cwd) / ".mcp.json"
    if not mcp_config_file.exists():
        raise click.ClickException(
            f"MCP configuration not found at {mcp_config_file}. "
            f"Ensure {cwd}/.mcp.json exists with the mulder MCP server config."
        )

    log_dir = Path(db_dir).expanduser()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "orchestrator.log"
    file_handler = logging.FileHandler(str(log_file), mode="a")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)

    model_config = ModelConfig.from_args(
        model=model,
        planner_model=planner_model,
        executor_model=executor_model,
        analyst_model=analyst_model,
        config_path=config_path,
    )

    click.echo(
        f"Mulder v{__version__} \u2014 The truth is in the data.",
        err=True,
    )
    click.echo(f"Starting multi-pass investigation of {evidence_path}", err=True)
    click.echo("Models:", err=True)
    click.echo(f"  Planner:  {model_config.planner}", err=True)
    click.echo(f"  Executor: {model_config.executor}", err=True)
    click.echo(f"  Analyst:  {model_config.analyst}", err=True)
    click.echo(f"Effort: {effort}, Workers: {workers}", err=True)
    click.echo(f"Logging to {log_file}", err=True)

    orchestrator = Orchestrator(
        evidence_path=evidence_path,
        cwd=cwd,
        model_config=model_config,
        effort=effort,
        env={},
        parallel_extractions=workers,
        proxy_config=proxy_config,
        case_id=case_id,
    )

    result = asyncio.run(orchestrator.run())

    orchestrator.dashboard.print_summary(result)

    if not result.success:
        raise SystemExit(1)


@cli.command("export-iocs")
@click.argument("case_id")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["stix", "csv", "all"]),
    default="all",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output-dir",
    default=None,
    help="Directory for output files. Defaults to the case report directory.",
)
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    show_default=True,
    help="Directory containing per-case databases.",
)
def export_iocs_cmd(case_id: str, fmt: str, output_dir: str | None, db_dir: str) -> None:
    """Export IOCs from a completed investigation as STIX 2.1 or CSV."""
    from mulder.db import CaseDB
    from mulder.report.ioc_export import export_iocs

    db_dir_path = Path(db_dir).expanduser()
    db_path = db_dir_path / f"{case_id}.db"

    if not db_path.exists():
        raise click.ClickException(f"Case database not found: {db_path}")

    out_dir = Path(output_dir) if output_dir else db_dir_path

    with CaseDB(db_path) as case_db:
        findings = case_db.get_findings()
        click.echo(f"Exporting IOCs from {len(findings)} findings ...")
        result = export_iocs(case_id, findings, out_dir, fmt=fmt)

    if result.get("csv_path"):
        click.echo(f"  CSV:  {result['csv_path']}")
    if result.get("stix_path"):
        click.echo(f"  STIX: {result['stix_path']}")
    click.echo("Done.")


@cli.command("export-navigator")
@click.argument("case_id")
@click.option(
    "--output-dir",
    default=None,
    help="Directory for the output file. Defaults to the case report directory.",
)
@click.option(
    "--domain",
    type=click.Choice(["enterprise-attack", "ics-attack"]),
    default="enterprise-attack",
    show_default=True,
    help="ATT&CK domain for the layer.",
)
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    show_default=True,
    help="Directory containing per-case databases.",
)
def export_navigator_cmd(case_id: str, output_dir: str | None, domain: str, db_dir: str) -> None:
    """Export a MITRE ATT&CK Navigator layer from investigation findings."""
    from mulder.db import CaseDB
    from mulder.report.navigator import export_navigator_layer

    db_dir_path = Path(db_dir).expanduser()
    db_path = db_dir_path / f"{case_id}.db"

    if not db_path.exists():
        raise click.ClickException(f"Case database not found: {db_path}")

    out_dir = Path(output_dir) if output_dir else db_dir_path

    with CaseDB(db_path) as case_db:
        findings = case_db.get_findings()
        click.echo(f"Building Navigator layer from {len(findings)} findings ...")
        layer_path = export_navigator_layer(case_id, findings, out_dir, domain=domain)

    if layer_path:
        click.echo(f"  Layer: {layer_path}")
    else:
        click.echo("  No MITRE technique IDs found; no layer generated.")
    click.echo("Done.")


if __name__ == "__main__":
    cli()
