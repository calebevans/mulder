"""Click CLI entry point for Mulder."""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path

import click

from mulder import __version__
from mulder.db import CaseDB
from mulder.extractors import EvidenceClassifier, default_registry
from mulder.extractors.classifier import ClassifierConfig
from mulder.index import Embedder
from mulder.models import EmbeddingConfig, WindowRow

logger = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    """Return ``sha256:<hex>`` digest of *path*, reading in 8 MB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def run_ingestion(
    evidence_path: Path,
    case_id: str,
    db_dir: Path,
    embedding_config: EmbeddingConfig | None = None,
    api_key: str | None = None,
    exclude_patterns: tuple[str, ...] = (),
) -> None:
    """Full ingestion pipeline: classify -> extract -> window -> embed -> store."""
    t_start = time.monotonic()

    click.echo("Loading embedding model ...")
    embedder = Embedder(config=embedding_config, api_key=api_key)

    emb_cfg = embedding_config or EmbeddingConfig()
    emb_cfg.embedding_dim = embedder.embedding_dim
    click.echo(
        f"  Backend: {emb_cfg.backend}, model: {emb_cfg.model_name}, dim: {emb_cfg.embedding_dim}"
    )

    click.echo(f"Creating case database for '{case_id}' ...")
    db = CaseDB.create(case_id, str(evidence_path), db_dir, embedding_config=emb_cfg)

    clf_config = ClassifierConfig(exclude_patterns=list(exclude_patterns))
    classifier = EvidenceClassifier(clf_config)
    registry = default_registry()

    click.echo(f"Scanning evidence at {evidence_path} ...")
    classified = classifier.classify(evidence_path)
    click.echo(f"  Found {len(classified)} evidence item(s)")

    extractor_versions: dict[str, str] = {}
    total_sources = 0
    total_windows = 0

    for item in classified:
        extractors = registry.get_all_extractors_for(item.path)
        if not extractors:
            click.echo(f"  [skip] No extractor for {item.path} ({item.artifact_type})")
            continue

        source_hash = _sha256_file(item.path) if item.path.is_file() else "sha256:directory"

        for extractor in extractors:
            click.echo(f"  [extract] {extractor.name}: {item.path}")

            results = extractor.extract(item.path, case_id)
            if extractor.name not in extractor_versions:
                extractor_versions[extractor.name] = extractor.version()

            for result in results:
                source_id = db.register_source(
                    source_name=result.source_name,
                    source_path=result.source_path,
                    source_hash=source_hash,
                    extractor=result.extractor,
                    line_count=result.line_count,
                )

                windows_data = embedder.window_and_embed(result.text_output)
                if not windows_data:
                    click.echo(f"    {result.source_name}: 0 windows (empty output)")
                    total_sources += 1
                    continue

                base_id = db.get_max_window_id() + 1
                window_rows = [
                    WindowRow(
                        window_id=base_id + i,
                        source_id=source_id,
                        line_start=line_start,
                        line_end=line_end,
                        event_time=event_time,
                        raw_text=raw_text,
                    )
                    for i, (raw_text, line_start, line_end, _emb, event_time) in enumerate(
                        windows_data
                    )
                ]
                vec_rows = [
                    (base_id + i, emb) for i, (_raw, _ls, _le, emb, _et) in enumerate(windows_data)
                ]

                db.insert_windows(source_id, window_rows)
                db.insert_vec_windows(vec_rows)

                total_sources += 1
                total_windows += len(window_rows)
                click.echo(f"    {result.source_name}: {len(window_rows)} windows")

    db.update_extractor_versions(extractor_versions)
    db.close()

    elapsed = time.monotonic() - t_start
    click.echo(
        f"\nIngestion complete: {total_sources} source(s), "
        f"{total_windows} window(s) in {elapsed:.1f}s"
    )


@click.group()
@click.version_option(version=__version__, prog_name="mulder")
def cli() -> None:
    """Mulder -- forensic MCP server for the SANS SIFT Workstation."""


@cli.command()
@click.argument("evidence_path")
@click.option("--case-id", required=True, help="Unique identifier for this case.")
@click.option(
    "--db-dir",
    default="~/.mulder/cases",
    show_default=True,
    help="Directory to store per-case databases.",
)
@click.option(
    "--embedding-backend",
    default="sentence-transformers",
    show_default=True,
    type=click.Choice(["sentence-transformers", "remote"]),
    help="Embedding backend. Use 'remote' for API-based models (Gemini, OpenAI, etc.).",
)
@click.option(
    "--embedding-model",
    default="all-MiniLM-L6-v2",
    show_default=True,
    help="Embedding model name. For remote: use litellm format (e.g. gemini/text-embedding-004).",
)
@click.option(
    "--batch-size",
    default=100,
    show_default=True,
    help="Embedding batch size (windows per API call). Larger = faster for remote backends.",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Glob pattern(s) to exclude. Repeatable. Example: --exclude 'results/*'",
)
@click.option(
    "--api-key",
    default=None,
    envvar="MULDER_API_KEY",
    help="API key for remote embeddings. Falls back to provider env vars (GEMINI_API_KEY, etc.).",
)
def ingest(
    evidence_path: str,
    case_id: str,
    db_dir: str,
    embedding_backend: str,
    embedding_model: str,
    batch_size: int,
    exclude: tuple[str, ...],
    api_key: str | None,
) -> None:
    """Ingest evidence into a per-case semantic index.

    EVIDENCE_PATH is the root directory (or file) containing forensic artifacts.
    """
    emb_cfg = EmbeddingConfig(
        backend=embedding_backend, model_name=embedding_model, batch_size=batch_size
    )
    run_ingestion(
        evidence_path=Path(evidence_path).expanduser().resolve(),
        case_id=case_id,
        db_dir=Path(db_dir).expanduser(),
        embedding_config=emb_cfg,
        api_key=api_key,
        exclude_patterns=exclude,
    )


@cli.command()
@click.option("--case-id", required=True, help="Case to serve.")
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
    "--api-key",
    default=None,
    envvar="MULDER_API_KEY",
    help="API key for remote embeddings (if case was ingested with --embedding-backend remote).",
)
def serve(case_id: str, db_dir: str, transport: str, api_key: str | None) -> None:
    """Start the Mulder MCP server for a case."""
    from mulder.server.app import init_server
    from mulder.server.app import mcp as mcp_server

    db_dir_path = Path(db_dir).expanduser()
    audit_path = db_dir_path / f"{case_id}.audit.jsonl"

    click.echo(f"Initialising MCP server for case '{case_id}' ...", err=True)
    init_server(case_id, db_dir_path, audit_path, api_key=api_key)

    click.echo(f"Starting MCP server (transport={transport}) ...", err=True)
    mcp_server.run(transport=transport)


@cli.command()
@click.option("--case-id", required=True, help="Case to investigate.")
@click.option(
    "--db-dir",
    default="~/.mulder/cases",
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
@click.option(
    "--api-key",
    default=None,
    envvar="MULDER_API_KEY",
    help="API key for remote embeddings (if case was ingested with --embedding-backend remote).",
)
def investigate(
    case_id: str, db_dir: str, model: str, max_iterations: int, api_key: str | None
) -> None:
    """Run an autonomous IR investigation against a case."""
    import asyncio
    import sys

    from mcp.client.stdio import StdioServerParameters

    from mulder.agent import Investigator

    db_dir_path = Path(db_dir).expanduser()

    serve_args = [
        "-m",
        "mulder.cli",
        "serve",
        "--case-id",
        case_id,
        "--db-dir",
        str(db_dir_path),
    ]
    if api_key:
        serve_args.extend(["--api-key", api_key])

    server_params = StdioServerParameters(
        command=sys.executable,
        args=serve_args,
    )

    investigator = Investigator(
        model=model,
        max_iterations=max_iterations,
        case_id=case_id,
    )

    click.echo(f"Starting investigation for case '{case_id}' (model={model}) ...")
    result = asyncio.run(investigator.run(server_params))
    click.echo(f"Investigation complete: {result.findings_submitted} finding(s) submitted.")


if __name__ == "__main__":
    cli()
