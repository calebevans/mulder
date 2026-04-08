"""Click CLI entry point for Killjoy."""

from __future__ import annotations

import click

from killjoy import __version__


@click.group()
@click.version_option(version=__version__, prog_name="killjoy")
def cli() -> None:
    """Killjoy -- forensic MCP server for the SANS SIFT Workstation."""


@cli.command()
@click.argument("evidence_path")
@click.option("--case-id", required=True, help="Unique identifier for this case.")
@click.option(
    "--db-dir",
    default="~/.killjoy/cases",
    show_default=True,
    help="Directory to store per-case databases.",
)
def ingest(evidence_path: str, case_id: str, db_dir: str) -> None:
    """Ingest evidence into a per-case semantic index.

    EVIDENCE_PATH is the root directory (or file) containing forensic artifacts.
    """
    click.echo("Not yet implemented -- see Piece 2")


@cli.command()
@click.option("--case-id", required=True, help="Case to serve.")
@click.option(
    "--db-dir",
    default="~/.killjoy/cases",
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
def serve(case_id: str, db_dir: str, transport: str) -> None:
    """Start the Killjoy MCP server for a case."""
    click.echo("Not yet implemented -- see Piece 7")


@cli.command()
@click.option("--case-id", required=True, help="Case to investigate.")
@click.option(
    "--db-dir",
    default="~/.killjoy/cases",
    show_default=True,
    help="Directory containing per-case databases.",
)
@click.option(
    "--model",
    default="claude-sonnet-4-20250514",
    show_default=True,
    help="LLM model for the investigation agent.",
)
@click.option(
    "--max-iterations",
    default=20,
    show_default=True,
    help="Maximum agent iterations.",
)
def investigate(case_id: str, db_dir: str, model: str, max_iterations: int) -> None:
    """Run an autonomous IR investigation against a case."""
    click.echo("Not yet implemented -- see Piece 9")
