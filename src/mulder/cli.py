"""Click CLI entry point for Mulder."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click

from mulder import __version__
from mulder.patterns import DEFAULT_DB_DIR, DEFAULT_WORKSPACE_DIR

if TYPE_CHECKING:  # heavy imports stay inside the command bodies
    from rich.console import Console

    from mulder.assets.fetch import Fetcher
    from mulder.assets.install import Plan, Result, SetupOptions
    from mulder.plugin_packs import PluginDiscoveryRequest

#: The default ``.mcp.json`` shipped as package data, copied into a fresh
#: workspace on first run so a ``pipx``/``uv tool`` install works out of the box.
DEFAULT_MCP_CONFIG = Path(__file__).resolve().parent / "data" / "mcp.json"


def _is_interactive() -> bool:
    """Check if stderr is connected to an interactive terminal.

    Returns:
        True if stderr is a TTY (interactive session), False if piped or in CI.
    """
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


@click.group()
@click.version_option(version=__version__, prog_name="mulder")
def cli() -> None:
    """Mulder: forensic MCP server for the SANS SIFT Workstation."""


def _read_json_object(path: Path | None, label: str) -> dict[str, object]:
    """Read one optional local JSON object for an offline CLI command."""
    if path is None:
        return {}
    import json

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise click.ClickException(f"Cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise click.ClickException(f"{label} must contain a JSON object")
    return value


def _plugin_request(
    roots: tuple[Path, ...],
    manifests: tuple[Path, ...],
    approval_path: Path | None,
    inventory_path: Path | None,
) -> PluginDiscoveryRequest:
    """Build the typed discovery request without importing plugins at CLI import."""
    from pydantic import ValidationError

    from mulder.plugin_packs import (
        CapabilityApproval,
        ComponentInventory,
        PluginDiscoveryRequest,
    )

    try:
        approval = CapabilityApproval.model_validate(
            _read_json_object(approval_path, "capability approval")
        )
        inventory = ComponentInventory.model_validate(
            _read_json_object(inventory_path, "component inventory")
        )
        return PluginDiscoveryRequest(
            approved_roots=roots,
            approved_manifests=manifests,
            capability_approval=approval,
            inventory=inventory,
        )
    except ValidationError as exc:
        raise click.ClickException(f"Invalid plugin discovery input: {exc}") from exc


@cli.group("plugins")
def plugins_cmd() -> None:
    """Discover and activate examiner-approved declarative plugin packs."""


@plugins_cmd.command("discover")
@click.option(
    "--root",
    "roots",
    multiple=True,
    type=click.Path(path_type=Path, file_okay=False),
    help="Examiner-approved discovery root; repeat as needed.",
)
@click.option(
    "--manifest",
    "manifests",
    multiple=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Examiner-approved exact manifest; repeat as needed.",
)
@click.option(
    "--approval",
    "approval_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="JSON capability ceiling. Defaults to no tools, writes, paths, or network.",
)
@click.option(
    "--inventory",
    "inventory_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Offline JSON inventory of tool, parser, and binary versions/digests.",
)
@click.option("--json", "json_output", is_flag=True, help="Emit the versioned catalog as JSON.")
def discover_plugins_cmd(
    roots: tuple[Path, ...],
    manifests: tuple[Path, ...],
    approval_path: Path | None,
    inventory_path: Path | None,
    json_output: bool,
) -> None:
    """Validate metadata and digests without importing or activating code."""
    import json

    from mulder.plugin_packs import PluginPackError, discover_plugin_packs

    request = _plugin_request(roots, manifests, approval_path, inventory_path)
    try:
        catalog = discover_plugin_packs(request)
    except PluginPackError as exc:
        raise click.ClickException(str(exc)) from exc
    if json_output:
        click.echo(
            json.dumps(
                catalog.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True
            )
        )
        return
    if not catalog.packs:
        click.echo("No plugin packs selected for discovery.")
        return
    for pack in catalog.packs:
        identity = pack.manifest.plugin
        click.echo(
            f"{identity.plugin_id}@{identity.version}: {pack.status} "
            f"({pack.plugin_digest})"
        )
        for check in pack.compatibility:
            click.echo(
                f"  {check.requirement.kind}:{check.requirement.name} "
                f"{check.status} — {check.reason}"
            )


@plugins_cmd.command("activate")
@click.argument("case_id")
@click.option("--db-dir", default=DEFAULT_DB_DIR, show_default=True)
@click.option(
    "--plugin",
    "plugin_ids",
    multiple=True,
    required=True,
    help="Exact plugin ID to activate; repeat as needed.",
)
@click.option("--root", "roots", multiple=True, type=click.Path(path_type=Path, file_okay=False))
@click.option(
    "--manifest", "manifests", multiple=True, type=click.Path(path_type=Path, dir_okay=False)
)
@click.option(
    "--approval", "approval_path", type=click.Path(path_type=Path, dir_okay=False)
)
@click.option(
    "--inventory", "inventory_path", type=click.Path(path_type=Path, dir_okay=False)
)
@click.option("--json", "json_output", is_flag=True)
def activate_plugins_cmd(
    case_id: str,
    db_dir: str,
    plugin_ids: tuple[str, ...],
    roots: tuple[Path, ...],
    manifests: tuple[Path, ...],
    approval_path: Path | None,
    inventory_path: Path | None,
    json_output: bool,
) -> None:
    """Bind selected, compatible pack identities to a case receipt."""
    import json

    from pydantic import ValidationError

    from mulder.db import CaseDB
    from mulder.plugin_packs import (
        PluginActivationRequest,
        PluginPackError,
    )

    discovery = _plugin_request(roots, manifests, approval_path, inventory_path)
    try:
        request = PluginActivationRequest(discovery=discovery, plugin_ids=plugin_ids)
        with CaseDB.open(case_id, Path(db_dir)) as db:
            activations = db.activate_plugin_packs(request)
    except (FileNotFoundError, PluginPackError, ValidationError) as exc:
        raise click.ClickException(str(exc)) from exc
    if json_output:
        click.echo(
            json.dumps(
                [activation.model_dump(mode="json") for activation in activations],
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for activation in activations:
            click.echo(
                f"Activated {activation.plugin.plugin_id}@{activation.plugin.version} "
                f"for {case_id}: {activation.plugin_digest}"
            )


@cli.group("release-metadata")
def release_metadata_cmd() -> None:
    """Generate or verify an offline release SBOM and build provenance."""


@release_metadata_cmd.command("generate")
@click.option(
    "--project-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("."),
)
@click.option("--artifact", "artifacts", multiple=True, type=click.Path(path_type=Path))
@click.option(
    "--artifact-dir",
    type=click.Path(path_type=Path, file_okay=False),
    help="Include wheel and source-distribution files directly under this directory.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("dist/release-supply-chain.json"),
    show_default=True,
)
@click.option("--project-name", default="mulder-dfir", show_default=True)
@click.option("--project-version", default=__version__, show_default=True)
@click.option("--source-revision", required=True)
@click.option("--source-date-epoch", type=int, required=True, envvar="SOURCE_DATE_EPOCH")
@click.option("--builder-id", required=True)
@click.option(
    "--dependency-lock",
    "dependency_lock_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("uv.lock"),
    show_default=True,
)
def generate_release_metadata_cmd(
    project_root: Path,
    artifacts: tuple[Path, ...],
    artifact_dir: Path | None,
    output_path: Path,
    project_name: str,
    project_version: str,
    source_revision: str,
    source_date_epoch: int,
    builder_id: str,
    dependency_lock_path: Path,
) -> None:
    """Create deterministic metadata without querying a registry or build service."""
    from mulder.supply_chain import (
        ReleaseMetadataRequest,
        SupplyChainError,
        generate_release_metadata,
    )

    root = project_root.expanduser().absolute()
    selected = list(artifacts)
    if artifact_dir is not None:
        selected_dir = artifact_dir if artifact_dir.is_absolute() else root / artifact_dir
        try:
            selected.extend(
                path
                for path in sorted(selected_dir.iterdir())
                if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
            )
        except OSError as exc:
            raise click.ClickException(f"Cannot read artifact directory: {exc}") from exc
    if not selected:
        raise click.UsageError("provide --artifact or --artifact-dir")
    output = output_path if output_path.is_absolute() else root / output_path
    lock = (
        dependency_lock_path
        if dependency_lock_path.is_absolute()
        else root / dependency_lock_path
    )
    try:
        result = generate_release_metadata(
            ReleaseMetadataRequest(
                project_root=root,
                artifact_paths=tuple(selected),
                output_path=output,
                project_name=project_name,
                project_version=project_version,
                source_revision=source_revision,
                source_date_epoch=source_date_epoch,
                builder_id=builder_id,
                invocation={"frontend": "mulder release-metadata generate"},
                dependency_lock_path=lock,
            )
        )
    except (OSError, SupplyChainError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Release metadata: {output}")
    click.echo(f"Digest: {result.document_digest}")


@release_metadata_cmd.command("verify")
@click.argument("metadata_path", type=click.Path(path_type=Path, dir_okay=False))
@click.option(
    "--release-root", type=click.Path(path_type=Path, file_okay=False), default=Path(".")
)
@click.option("--json", "json_output", is_flag=True)
def verify_release_metadata_cmd(
    metadata_path: Path,
    release_root: Path,
    json_output: bool,
) -> None:
    """Verify the document, dependency lock, and release artifacts offline."""
    import json

    from mulder.supply_chain import verify_release_metadata

    result = verify_release_metadata(metadata_path, release_root)
    if json_output:
        click.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        click.echo(f"Release metadata: {result.status}")
        click.echo(f"Artifacts checked: {result.artifacts_checked}")
        for diagnostic in result.diagnostics:
            click.echo(f"- {diagnostic}")
    if not result.ok:
        raise click.exceptions.Exit(1)


@cli.command()
@click.option("--case-id", default=None, help="Pre-load this case on startup.")
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    envvar="MULDER_DB_DIR",
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
@click.option(
    "--airgap",
    is_flag=True,
    help="Disable external threat intelligence and telemetry-capable egress paths.",
)
def serve(
    case_id: str | None,
    db_dir: str,
    transport: str,
    workers: int,
    mem_limit: float,
    cpu_limit: float,
    airgap: bool,
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

    if airgap:
        import os

        from mulder.security.provider_policy import zero_egress_environment

        os.environ.update(zero_egress_environment())

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
    # ``MCPServer.run`` is overloaded per transport, so the literal has to
    # reach it directly rather than through the click-supplied ``str``.
    if transport == "streamable-http":
        mcp_server.run(transport="streamable-http")
    else:
        mcp_server.run(transport="stdio")


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
    from mulder.models import CaseMetadataRow
    from mulder.report.renderer import ReportRenderer
    from mulder.review.model import CaseReviewError, ReviewQuery, query_case_review

    db_dir_path = Path(db_dir).expanduser()
    db_path = db_dir_path / f"{case_id}.db"
    audit_path = db_dir_path / f"{case_id}.audit.jsonl"

    if not db_path.exists():
        raise click.ClickException(f"Case database not found: {db_path}")
    run_ledger_path = db_dir_path / f"{case_id}.runs.db"
    report_binding_path = db_dir_path / f"{case_id}.report-run.json"
    if run_ledger_path.exists() or report_binding_path.exists():
        raise click.ClickException(
            "Durable run state exists; regenerate reports through the investigation "
            "finalize step so report/run commitments remain exact"
        )

    click.echo(f"Loading case '{case_id}' from {db_path} ...")

    try:
        review = query_case_review(
            ReviewQuery(
                case_id=case_id,
                db_dir=db_dir_path,
                finding_limit=500,
                evidence_limit=1000,
                revision_limit=1000,
            )
        )
    except CaseReviewError as exc:
        raise click.ClickException(str(exc)) from exc

    with CaseDB(db_path) as case_db:
        case_metadata = CaseMetadataRow(
            case_id=review.case.case_id,
            ingested_at=review.case.ingested_at,
            evidence_root=review.case.evidence_root,
            extractor_versions=review.case.extractor_versions,
            narrative=review.case.narrative,
        )
        findings = [item.finding for item in review.findings.active]
        sources_list = case_db.get_sources()
        evidence_integrity = case_db.get_evidence_registry()
        coverage_records = [cell.record for cell in review.coverage.matrix]
        proof_cards = review.proof_cards()
        review_data = review.model_dump(mode="json", by_alias=True)
        reasoning_review = case_db.get_reasoning_review()

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
            coverage_records=coverage_records,
            proof_cards=proof_cards,
            case_review=review_data,
            reasoning_review=reasoning_review,
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
                coverage_records=coverage_records,
                proof_cards=proof_cards,
                case_review=review_data,
                reasoning_review=reasoning_review,
            )
            html_path.write_text(html_text, encoding="utf-8")
            click.echo(f"  HTML:     {html_path}")
        except Exception as exc:
            click.echo(f"  HTML generation failed: {exc}", err=True)

    click.echo("Done.")


@cli.command("publish")
@click.argument("case_id")
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    show_default=True,
    help="Directory containing the authoritative case artifacts.",
)
@click.option(
    "--pdf/--no-pdf",
    default=True,
    show_default=True,
    help="Render PDFs when the optional WeasyPrint dependency is available.",
)
@click.option(
    "--approve",
    "approve_publication",
    is_flag=True,
    help="Promote the new draft after QA and state-bound analyst approval checks.",
)
def publish_cmd(
    case_id: str,
    db_dir: str,
    pdf: bool,
    approve_publication: bool,
) -> None:
    """Render one fact snapshot for executive, technical, and examiner audiences."""
    from mulder.review.model import CaseReviewError
    from mulder.review.publication import PublicationError, PublicationManager

    manager = PublicationManager(case_id, Path(db_dir))
    try:
        path = manager.create_draft(generate_pdf=pdf)
        if approve_publication:
            path = manager.approve()
        manifest = manager.read()
    except (OSError, CaseReviewError, PublicationError) as exc:
        raise click.ClickException(str(exc)) from exc
    qa = manifest.get("qa")
    qa_passed = isinstance(qa, dict) and qa.get("passed") is True
    click.echo(
        f"Publication {manifest['state']}: {path} "
        f"(QA {'passed' if qa_passed else 'failed'})"
    )


@cli.command("publication-status")
@click.argument("case_id")
@click.option("--db-dir", default=DEFAULT_DB_DIR, show_default=True)
def publication_status_cmd(case_id: str, db_dir: str) -> None:
    """Verify and print the current publication sidecar."""
    from mulder.review.publication import PublicationError, PublicationManager

    try:
        manifest = PublicationManager(case_id, Path(db_dir)).read()
    except PublicationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(manifest, sort_keys=True))


@cli.command("review")
@click.argument("case_id")
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    show_default=True,
    help="Directory containing the authoritative case artifacts.",
)
@click.option("--finding-offset", default=0, type=click.IntRange(min=0), show_default=True)
@click.option(
    "--finding-limit", default=100, type=click.IntRange(min=1, max=500), show_default=True
)
@click.option("--evidence-offset", default=0, type=click.IntRange(min=0), show_default=True)
@click.option(
    "--evidence-limit", default=200, type=click.IntRange(min=1, max=1000), show_default=True
)
@click.option("--revision-offset", default=0, type=click.IntRange(min=0), show_default=True)
@click.option(
    "--revision-limit", default=200, type=click.IntRange(min=1, max=1000), show_default=True
)
@click.option(
    "--manifest",
    "manifest_path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help="Explicit case manifest; defaults to DB_DIR/CASE_ID.manifest.json.",
)
@click.option(
    "--public-key",
    "public_key_path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help="Independent Ed25519 public key for receipt verification.",
)
@click.option(
    "--replay-inventory",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help="JSON inventory for replay classification.",
)
@click.option("--json", "json_output", is_flag=True, help="Emit the versioned review JSON.")
def review_case_cmd(
    case_id: str,
    db_dir: str,
    finding_offset: int,
    finding_limit: int,
    evidence_offset: int,
    evidence_limit: int,
    revision_offset: int,
    revision_limit: int,
    manifest_path: Path | None,
    public_key_path: Path | None,
    replay_inventory: Path | None,
    json_output: bool,
) -> None:
    """Read one bounded, transport-neutral case-review projection."""
    import json

    from mulder.review.model import (
        CaseReviewError,
        ReviewQuery,
        format_case_review,
        query_case_review,
    )

    inventory: dict[str, object] | None = None
    if replay_inventory is not None:
        try:
            loaded = json.loads(replay_inventory.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise click.ClickException(f"Cannot read replay inventory: {exc}") from exc
        if not isinstance(loaded, dict):
            raise click.ClickException("Replay inventory must be a JSON object")
        inventory = loaded
    try:
        review = query_case_review(
            ReviewQuery(
                case_id=case_id,
                db_dir=Path(db_dir),
                finding_offset=finding_offset,
                finding_limit=finding_limit,
                evidence_offset=evidence_offset,
                evidence_limit=evidence_limit,
                revision_offset=revision_offset,
                revision_limit=revision_limit,
                manifest_path=manifest_path,
                public_key_path=public_key_path,
                replay_inventory=inventory,
            )
        )
    except CaseReviewError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        review.model_dump_json(indent=2, by_alias=True)
        if json_output
        else format_case_review(review)
    )


@cli.command("review-action")
@click.argument("case_id")
@click.argument("kind", type=click.Choice(["accept", "reject", "comment", "follow_up"]))
@click.option("--subject-type", required=True)
@click.option("--subject-id", required=True)
@click.option("--reviewer", required=True)
@click.option("--comment", default="")
@click.option("--db-dir", default=DEFAULT_DB_DIR, show_default=True)
def review_action_cmd(
    case_id: str,
    kind: str,
    subject_type: str,
    subject_id: str,
    reviewer: str,
    comment: str,
    db_dir: str,
) -> None:
    """Append an immutable analyst review action for CASE_ID."""
    from dataclasses import asdict
    from typing import cast

    from mulder.review.decisions import ReviewEventKind, ReviewWorkflow, ReviewWorkflowError

    try:
        event = ReviewWorkflow(case_id, Path(db_dir)).append_event(
            cast("ReviewEventKind", kind),
            subject_type=subject_type,
            subject_id=subject_id,
            reviewer=reviewer,
            comment=comment,
        )
    except ReviewWorkflowError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(asdict(event), sort_keys=True))


@cli.command("request-approval")
@click.argument("case_id")
@click.option("--requested-by", required=True)
@click.option("--db-dir", default=DEFAULT_DB_DIR, show_default=True)
def request_approval_cmd(case_id: str, requested_by: str, db_dir: str) -> None:
    """Create an approval request bound to the current claims and audit head."""
    from dataclasses import asdict

    from mulder.review.decisions import ReviewWorkflow, ReviewWorkflowError

    try:
        request = ReviewWorkflow(case_id, Path(db_dir)).request_approval(
            requested_by=requested_by
        )
    except ReviewWorkflowError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(asdict(request), sort_keys=True))


@cli.command("approve")
@click.argument("case_id")
@click.option("--request-id", default=None, help="Defaults to the current pending request.")
@click.option("--decision", type=click.Choice(["approve", "reject"]), required=True)
@click.option("--reviewer", required=True)
@click.option("--comment", default="")
@click.option("--db-dir", default=DEFAULT_DB_DIR, show_default=True)
def approve_cmd(
    case_id: str,
    request_id: str | None,
    decision: str,
    reviewer: str,
    comment: str,
    db_dir: str,
) -> None:
    """Approve or reject exactly the CASE_ID state that was requested."""
    from dataclasses import asdict
    from typing import cast

    from mulder.review.decisions import (
        ApprovalDecisionKind,
        ReviewWorkflow,
        ReviewWorkflowError,
    )

    workflow = ReviewWorkflow(case_id, Path(db_dir))
    try:
        if request_id is None:
            status = workflow.status()
            if status.state != "awaiting_review" or status.request is None:
                raise ReviewWorkflowError("Case has no current pending approval request")
            request_id = status.request.request_id
        result = workflow.decide(
            request_id,
            cast("ApprovalDecisionKind", decision),
            reviewer=reviewer,
            comment=comment,
        )
    except ReviewWorkflowError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(asdict(result), sort_keys=True))


@cli.command("approval-status")
@click.argument("case_id")
@click.option("--db-dir", default=DEFAULT_DB_DIR, show_default=True)
def approval_status_cmd(case_id: str, db_dir: str) -> None:
    """Show the conservative approval state for CASE_ID."""
    from mulder.review.decisions import ReviewWorkflow, ReviewWorkflowError

    try:
        status = ReviewWorkflow(case_id, Path(db_dir)).status()
    except ReviewWorkflowError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(status.as_mapping(), sort_keys=True))


@cli.command("review-console")
@click.argument("case_id")
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    show_default=True,
    help="Directory containing the authoritative case artifacts.",
)
@click.option("--host", default="127.0.0.1", show_default=True, help="Address to bind.")
@click.option(
    "--port",
    default=8765,
    type=click.IntRange(min=1, max=65535),
    show_default=True,
)
@click.option(
    "--auth-token",
    envvar="MULDER_REVIEW_TOKEN",
    help="Examiner-supplied bearer/basic token; required for non-loopback binding.",
)
def review_console_cmd(
    case_id: str,
    db_dir: str,
    host: str,
    port: int,
    auth_token: str | None,
) -> None:
    """Serve one case through the optional, read-only local review console.

    Install ``mulder-dfir[web]`` first. The default address is loopback-only.
    Non-loopback binding is rejected unless the examiner explicitly supplies
    an authentication token.
    """
    try:
        from mulder.review.web import (
            ReviewConsoleConfig,
            ReviewConsoleError,
            run_review_console,
        )
    except ImportError as exc:
        raise click.ClickException(
            "The review console requires the optional 'web' extra: "
            "install mulder-dfir[web]"
        ) from exc

    try:
        config = ReviewConsoleConfig(
            case_id=case_id,
            db_dir=Path(db_dir).expanduser(),
            host=host,
            port=port,
            auth_token=auth_token,
        )
    except ReviewConsoleError as exc:
        raise click.UsageError(str(exc)) from exc
    if not (config.db_dir / f"{config.case_id}.db").is_file():
        raise click.ClickException(
            f"Case database not found: {config.db_dir / f'{config.case_id}.db'}"
        )
    click.echo(
        f"Serving read-only case review at http://{config.host}:{config.port}/"
    )
    click.echo(
        "Authentication: examiner token required"
        if config.auth_token is not None
        else "Authentication: loopback-only, no token"
    )
    run_review_console(config)


@cli.command("seal-case")
@click.argument("case_id")
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    show_default=True,
    help="Directory containing the case database, audit log, and standard reports.",
)
@click.option(
    "--manifest",
    "manifest_path",
    default=None,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Output path. Defaults to DB_DIR/CASE_ID.manifest.json.",
)
@click.option(
    "--artifact",
    "artifacts",
    multiple=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Additional generated report/export artifact to bind; repeat as needed.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Replace an existing manifest after re-verifying every current artifact.",
)
@click.option(
    "--signing-key",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help="Existing examiner-owned Ed25519 PEM private key; no key is generated implicitly.",
)
@click.option("--examiner", help="Optional caller-asserted examiner label stored as metadata.")
@click.option("--key-id", help="Optional caller-selected key identifier; defaults to fingerprint.")
@click.option(
    "--require-approval",
    is_flag=True,
    help="Seal only an approval bound to the current claims and an audit-chain ancestor.",
)
@click.option(
    "--require-resolved-contradictions",
    is_flag=True,
    help="Refuse sealing while any material contradiction remains unresolved.",
)
def seal_case_cmd(
    case_id: str,
    db_dir: str,
    manifest_path: Path | None,
    artifacts: tuple[Path, ...],
    force: bool,
    signing_key: Path | None,
    examiner: str | None,
    key_id: str | None,
    require_approval: bool,
    require_resolved_contradictions: bool,
) -> None:
    """Seal CASE_ID into a relocatable, optionally signed case manifest.

    This is a local operation. It reads the case database, audit log, original
    evidence, and generated reports without starting MCP or calling a model.
    """
    from mulder.case_signing import Ed25519PEMKeyProvider, SigningKeyError
    from mulder.receipt import SealError, seal_case

    if signing_key is None and (examiner is not None or key_id is not None):
        raise click.UsageError("--examiner and --key-id require --signing-key")
    try:
        provider = (
            Ed25519PEMKeyProvider.from_file(signing_key, examiner=examiner, key_id=key_id)
            if signing_key is not None
            else None
        )
    except SigningKeyError as exc:
        raise click.ClickException(str(exc)) from exc

    try:
        path = seal_case(
            case_id,
            Path(db_dir),
            manifest_path=manifest_path,
            report_artifacts=artifacts,
            overwrite=force,
            key_provider=provider,
            require_approval=require_approval,
            require_resolved_contradictions=require_resolved_contradictions,
        )
    except (OSError, SealError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Sealed case manifest: {path}")
    if provider is None:
        click.echo("Signature: unsigned (no examiner key supplied)")
    else:
        click.echo(f"Signature: Ed25519 ({provider.public_metadata.fingerprint})")


@cli.command("verify-case")
@click.argument(
    "manifest_path",
    type=click.Path(path_type=Path, dir_okay=False),
)
@click.option(
    "--evidence-root",
    default=None,
    type=click.Path(path_type=Path),
    help="Relocated evidence root; otherwise the manifest's relative locator is used.",
)
@click.option(
    "--public-key",
    "public_key_path",
    default=None,
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help="Examiner-selected Ed25519 PEM/OpenSSH public key (embedded key is used otherwise).",
)
@click.option(
    "--replay-inventory",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help="JSON inventory used only for EXACT/DRIFTED/UNSUPPORTED replay classification.",
)
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON.")
def verify_case_cmd(
    manifest_path: Path,
    evidence_root: Path | None,
    public_key_path: Path | None,
    replay_inventory: Path | None,
    json_output: bool,
) -> None:
    """Verify MANIFEST_PATH entirely offline.

    Exit status is 0 for a fully verified native case, 2 for intact but
    cryptographically unverified legacy material, 3 for an unsupported
    manifest schema, and 1 for corruption, mutation, or missing artifacts.
    """
    import json

    from mulder.receipt import format_verification_result, verify_case

    inventory: dict[str, object] | None = None
    if replay_inventory is not None:
        try:
            inventory = json.loads(replay_inventory.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise click.ClickException(f"Cannot read replay inventory: {exc}") from exc
        if not isinstance(inventory, dict):
            raise click.ClickException("Replay inventory must be a JSON object")
    result = verify_case(
        manifest_path,
        evidence_root=evidence_root,
        public_key_path=public_key_path,
        replay_inventory=inventory,
    )
    if json_output:
        click.echo(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    else:
        click.echo(format_verification_result(result))

    exit_code = {
        "verified": 0,
        "legacy_unverified": 2,
        "unsupported_manifest": 3,
        "invalid": 1,
    }[result.status]
    if exit_code:
        raise click.exceptions.Exit(exit_code)


@cli.command("verify-linux-live")
@click.argument(
    "bundle_path",
    type=click.Path(path_type=Path, dir_okay=False),
)
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON.")
def verify_linux_live_cmd(bundle_path: Path, json_output: bool) -> None:
    """Verify a sealed Linux live-state BUNDLE_PATH entirely offline."""
    import json

    from mulder.linux_live import verify_linux_live_bundle

    result = verify_linux_live_bundle(bundle_path)
    payload = result.model_dump(mode="json")
    if json_output:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        click.echo(f"Linux live bundle: {result.status}")
        click.echo(f"Host: {result.host_id or 'unknown'}")
        click.echo(f"Artifacts checked: {result.artifacts_checked}")
        for diagnostic in result.diagnostics:
            click.echo(f"- {diagnostic.code} [{diagnostic.subject}]: {diagnostic.message}")
    exit_code = {"valid": 0, "invalid": 1, "unsupported": 3}[result.status]
    if exit_code:
        raise click.exceptions.Exit(exit_code)


@cli.command("intake-collection")
@click.argument("source", type=click.Path(path_type=Path, exists=True))
@click.argument("case_id")
@click.option(
    "--format",
    "collection_format",
    type=click.Choice(["auto", "kape", "velociraptor"]),
    default="auto",
    show_default=True,
)
@click.option("--collector-version", help="Examiner-asserted collector version.")
@click.option("--collection-id", help="Examiner-asserted collector run/flow identifier.")
@click.option("--host", help="Examiner-asserted collected host identifier.")
@click.option("--db-dir", default=DEFAULT_DB_DIR, show_default=True)
def intake_collection_cmd(
    source: Path,
    case_id: str,
    collection_format: str,
    collector_version: str | None,
    collection_id: str | None,
    host: str | None,
    db_dir: str,
) -> None:
    """Immutably inventory and register a KAPE or Velociraptor export."""
    from typing import Literal, cast

    from mulder.adapters import IntakeError, ingest_collection

    try:
        result = ingest_collection(
            source,
            case_id,
            Path(db_dir),
            collection_format=cast(
                "Literal['auto', 'kape', 'velociraptor']", collection_format
            ),
            collector_version=collector_version,
            collection_id=collection_id,
            host=host,
        )
    except (IntakeError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(result.model_dump_json(indent=2))


@cli.command("run-status")
@click.argument("case_id")
@click.argument("run_id")
@click.option("--db-dir", default=DEFAULT_DB_DIR, show_default=True)
def run_status_cmd(case_id: str, run_id: str, db_dir: str) -> None:
    """Show a durable investigation run handle and completed checkpoints."""
    from mulder.run_state import RunLedger, RunStateError

    root = Path(db_dir).expanduser()
    ledger_path = root / f"{case_id}.runs.db"
    if not ledger_path.is_file():
        raise click.ClickException(f"Run ledger not found: {ledger_path}")
    try:
        handle = RunLedger(
            case_id,
            ledger_path,
            root / f"{case_id}.audit.jsonl",
        ).status(run_id)
    except (RunStateError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(handle.model_dump_json(indent=2))


@cli.command("cancel-run")
@click.argument("case_id")
@click.argument("run_id")
@click.option("--requested-by", required=True, help="Examiner requesting cancellation.")
@click.option("--db-dir", default=DEFAULT_DB_DIR, show_default=True)
def cancel_run_cmd(case_id: str, run_id: str, requested_by: str, db_dir: str) -> None:
    """Request cooperative cancellation at the next safe phase boundary."""
    from mulder.run_state import RunLedger, RunStateError

    root = Path(db_dir).expanduser()
    ledger_path = root / f"{case_id}.runs.db"
    if not ledger_path.is_file():
        raise click.ClickException(f"Run ledger not found: {ledger_path}")
    try:
        handle = RunLedger(
            case_id,
            ledger_path,
            root / f"{case_id}.audit.jsonl",
        ).request_cancel(run_id, requested_by=requested_by)
    except (RunStateError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(handle.model_dump_json(indent=2))


@cli.command("forecast-run")
@click.argument("evidence_path", type=click.Path(path_type=Path, exists=True))
@click.option(
    "--profile",
    type=click.Choice(["quick", "full"]),
    default="full",
    show_default=True,
)
@click.option(
    "--db-dir",
    default=DEFAULT_DB_DIR,
    show_default=True,
    type=click.Path(path_type=Path, file_okay=False),
    help="Planned case-database output directory whose filesystem is measured.",
)
@click.option(
    "--cwd",
    default=DEFAULT_WORKSPACE_DIR,
    show_default=True,
    type=click.Path(path_type=Path, file_okay=False),
    help="Planned workspace output directory whose filesystem is measured.",
)
def forecast_run_cmd(
    evidence_path: Path,
    profile: str,
    db_dir: Path,
    cwd: Path,
) -> None:
    """Print a conservative local capacity forecast without starting a model."""
    from typing import cast

    from mulder.run_state import RunProfile, forecast_health

    forecast = forecast_health(
        evidence_path,
        cast("RunProfile", profile),
        working_paths=(db_dir, cwd),
    )
    click.echo(forecast.model_dump_json(indent=2))


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
    default=DEFAULT_WORKSPACE_DIR,
    envvar="MULDER_CWD",
    show_default=True,
    help="Working directory for agent sessions (env: MULDER_CWD).",
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
@click.option(
    "--data-policy",
    type=click.Choice(["local-only", "metadata-only", "sensitive-approved"]),
    default=None,
    help="Case policy for provider-bound data (default: sensitive-approved).",
)
@click.option(
    "--airgap",
    "zero_egress",
    is_flag=True,
    default=None,
    help="Require zero egress; only verified local model routes are allowed.",
)
@click.option(
    "--approval-before-report",
    is_flag=True,
    help="Stop after counter-analysis and persist an exact-state approval request.",
)
@click.option(
    "--resume-after-approval",
    is_flag=True,
    help="Validate a persisted approval and run only the report phase.",
)
@click.option(
    "--profile",
    type=click.Choice(["quick", "full"]),
    default=None,
    help="Run profile (new runs default to full; resumes inherit their profile).",
)
@click.option("--run-id", default=None, help="Caller-selected handle for a new run.")
@click.option(
    "--resume-run",
    "resume_run_id",
    default=None,
    help="Resume this durable run handle after validating its input and profile.",
)
@click.option(
    "--require-healthy",
    is_flag=True,
    help="Refuse to start when the conservative capacity forecast is not ready.",
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
    data_policy: str | None,
    zero_egress: bool | None,
    approval_before_report: bool,
    resume_after_approval: bool,
    profile: str | None,
    run_id: str | None,
    resume_run_id: str | None,
    require_healthy: bool,
) -> None:
    """Run a full multi-pass forensic investigation.

    Uses a planner/executor/analyst pipeline for each phase. Configure
    models per role via CLI flags or a YAML config file.

    EVIDENCE_PATH is the filesystem path to the evidence directory.
    CASE_ID is the unique identifier for this investigation (used as the
    database filename and referenced by all phases).

    \b
      mulder investigate /evidence Rocba \\
        --planner-model claude-opus-4-6 \\
        --executor-model claude-haiku-4-5 \\
        --analyst-model claude-opus-4-6

    Non-Claude models are supported via LiteLLM proxy (auto-started when
    a model ID uses a provider prefix like bedrock/ or openai/).
    """
    import asyncio
    from typing import cast

    from mulder.orchestrator.models import ModelConfig
    from mulder.orchestrator.runner import Orchestrator
    from mulder.orchestrator.types import EffortLevel
    from mulder.run_state import (
        RunCancelled,
        RunHandle,
        RunLedger,
        RunProfile,
        RunStateError,
        forecast_health,
    )

    if approval_before_report and resume_after_approval:
        raise click.UsageError(
            "--approval-before-report and --resume-after-approval are mutually exclusive"
        )
    if resume_after_approval and resume_run_id is None:
        raise click.UsageError("--resume-after-approval requires --resume-run RUN_ID")
    if run_id is not None and resume_run_id is not None:
        raise click.UsageError("--run-id and --resume-run are mutually exclusive")

    model_config = ModelConfig.from_args(
        model=model,
        planner_model=planner_model,
        executor_model=executor_model,
        analyst_model=analyst_model,
        config_path=config_path,
        data_policy=data_policy,
        zero_egress=zero_egress,
    )

    if model_config.zero_egress:
        import os

        from mulder.security.provider_policy import preflight_zero_egress

        violations = preflight_zero_egress(
            models=model_config.all_models,
            env=os.environ,
            proxy_config=proxy_config,
        )
        if violations:
            raise click.ClickException("zero-egress preflight failed: " + "; ".join(violations))

    cwd_path = Path(cwd).expanduser()
    try:
        cwd_path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise click.ClickException(f"Cannot create working directory {cwd_path}: {exc}") from exc
    # The *expanded* path is what must reach Orchestrator(cwd=...) below, or the
    # agent sessions are handed a literal "~/.mulder/workspace" string.
    cwd = str(cwd_path)

    mcp_config_file = cwd_path / ".mcp.json"
    if not mcp_config_file.exists():
        try:
            mcp_config_file.write_text(
                DEFAULT_MCP_CONFIG.read_text(encoding="utf-8"), encoding="utf-8"
            )
        except OSError as exc:
            raise click.ClickException(
                f"Cannot write MCP configuration to {mcp_config_file}: {exc}"
            ) from exc
        click.echo(f"Created default MCP configuration at {mcp_config_file}", err=True)

    log_dir = Path(db_dir).expanduser()
    log_dir.mkdir(parents=True, exist_ok=True)
    selected_profile = cast("RunProfile", profile or "full")
    if resume_run_id is not None:
        ledger_path = log_dir / f"{case_id}.runs.db"
        if not ledger_path.is_file():
            raise click.ClickException(f"Run ledger not found: {ledger_path}")
        try:
            persisted = RunLedger(
                case_id,
                ledger_path,
                log_dir / f"{case_id}.audit.jsonl",
            ).status(resume_run_id)
        except (RunStateError, OSError) as exc:
            raise click.ClickException(str(exc)) from exc
        if profile is not None and profile != persisted.profile:
            raise click.UsageError(
                f"--profile {profile} does not match resumed profile {persisted.profile}"
            )
        selected_profile = persisted.profile

    evidence = Path(evidence_path).expanduser()
    if evidence.is_file() or evidence.is_dir():
        try:
            health = forecast_health(
                evidence,
                selected_profile,
                working_paths=(log_dir, cwd_path),
            )
        except (OSError, RunStateError) as exc:
            raise click.ClickException(f"Health forecast failed: {exc}") from exc
        click.echo(
            "Health forecast: "
            f"{'ready' if health.ready else 'not ready'}, "
            f"{health.evidence_files} files, "
            f"{health.estimated_minutes_low}-{health.estimated_minutes_high} min",
            err=True,
        )
        for warning in health.warnings:
            click.echo(f"  Warning: {warning}", err=True)
        if require_healthy and not health.ready:
            raise click.ClickException("Capacity forecast is not ready")
    elif require_healthy:
        raise click.ClickException(f"Evidence path is unavailable: {evidence}")
    else:
        click.echo(
            f"Health forecast unavailable: evidence path does not exist: {evidence}",
            err=True,
        )
    log_file = log_dir / "orchestrator.log"
    file_handler = logging.FileHandler(str(log_file), mode="a")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)

    click.echo(
        f"Mulder v{__version__} \u2014 The truth is in the data.",
        err=True,
    )
    click.echo(f"Starting multi-pass investigation of {evidence_path}", err=True)
    click.echo("Models:", err=True)
    click.echo(f"  Planner:  {model_config.planner}", err=True)
    click.echo(f"  Executor: {model_config.executor}", err=True)
    click.echo(f"  Analyst:  {model_config.analyst}", err=True)
    click.echo(
        f"Effort: {effort}, Workers: {workers}, Profile: {selected_profile}",
        err=True,
    )
    click.echo(
        f"Data policy: {model_config.data_policy.value}, "
        f"Zero egress: {'enabled' if model_config.zero_egress else 'disabled'}",
        err=True,
    )
    click.echo(
        f"Outbound manifest: {log_dir / f'{case_id}.outbound.jsonl'}",
        err=True,
    )
    click.echo(f"Logging to {log_file}", err=True)

    try:
        orchestrator = Orchestrator(
            evidence_path=evidence_path,
            cwd=cwd,
            model_config=model_config,
            # click.Choice above is the validation boundary for this value.
            effort=cast("EffortLevel", effort),
            env={},
            parallel_extractions=workers,
            proxy_config=proxy_config,
            case_id=case_id,
            db_dir=log_dir,
            approval_before_report=approval_before_report,
            resume_after_approval=resume_after_approval,
            run_event_path=log_dir / f"{case_id}.audit.jsonl",
            run_profile=selected_profile,
            run_id=resume_run_id or run_id,
            resume_run=resume_run_id is not None,
            run_state_path=log_dir / f"{case_id}.runs.db",
        )
    except (OSError, RunStateError) as exc:
        raise click.ClickException(str(exc)) from exc

    durable_handle = orchestrator.run_handle
    if isinstance(durable_handle, RunHandle):
        click.echo(f"Run handle: {durable_handle.run_id}", err=True)

    from mulder.orchestrator.errors import (
        AuthenticationError,
        ModelNotAvailableError,
    )
    from mulder.review.decisions import ReviewWorkflowError
    from mulder.security.provider_policy import ProviderPolicyError

    try:
        result = asyncio.run(orchestrator.run())
    except AuthenticationError as exc:
        orchestrator.dashboard.stop()
        click.echo(f"\nError: {exc}", err=True)
        if exc.suggestion:
            click.echo(f"\n{exc.suggestion}", err=True)
        raise SystemExit(2) from None
    except ModelNotAvailableError as exc:
        orchestrator.dashboard.stop()
        click.echo(f"\nError: {exc}", err=True)
        if exc.alternative:
            if _is_interactive():
                if click.confirm(
                    f"Would you like to try {exc.alternative} instead?",
                    default=True,
                ):
                    click.echo(
                        f"\nRe-run with: mulder investigate ... --model {exc.alternative}",
                        err=True,
                    )
            else:
                click.echo(
                    f"\nTry: mulder investigate ... --model {exc.alternative}",
                    err=True,
                )
        else:
            click.echo(
                "\nSpecify a different model with --model <model-id>",
                err=True,
            )
        raise SystemExit(2) from None
    except ProviderPolicyError as exc:
        orchestrator.dashboard.stop()
        click.echo(f"\nError: {exc}", err=True)
        raise SystemExit(2) from None
    except ReviewWorkflowError as exc:
        orchestrator.dashboard.stop()
        click.echo(f"\nError: {exc}", err=True)
        raise SystemExit(2) from None
    except RunCancelled as exc:
        orchestrator.dashboard.stop()
        click.echo(f"\nCancelled: {exc}", err=True)
        raise SystemExit(1) from None
    except RunStateError as exc:
        orchestrator.dashboard.stop()
        click.echo(f"\nRun state error: {exc}", err=True)
        raise SystemExit(2) from None

    orchestrator.dashboard.print_summary(result)

    if result.review_state in {"awaiting_review", "rejected"}:
        if result.approval_request_id is not None:
            click.echo(
                f"Approval required: mulder approve {case_id} --request-id "
                f"{result.approval_request_id} --decision approve --reviewer NAME",
                err=True,
            )
        click.echo(
            f"After approval, resume with: mulder investigate {evidence_path} {case_id} "
            f"--resume-run {result.run_id} --resume-after-approval",
            err=True,
        )

    if not result.success:
        raise SystemExit(1)


@cli.command()
@click.option(
    "--asset-root",
    default=None,
    type=click.Path(),
    help="Override the asset root (env: MULDER_ASSET_ROOT). Exclusive: setting it "
    "disables the /opt search entirely.",
)
@click.option("--dry-run", is_flag=True, help="Print the plan and exit. Issues no requests.")
@click.option(
    "--verify",
    is_flag=True,
    help="Validate what is installed; fetch nothing. Exits 4 if anything is missing, "
    "invalid, or shadowed by a copy mulder does not manage.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the result document on stdout.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt for large plans.")
def setup(
    asset_root: str | None,
    dry_run: bool,
    verify: bool,
    as_json: bool,
    yes: bool,
) -> None:
    """Download the forensic data, rule sets and helper tools pip cannot ship.

    Installs everything mulder owns.  Never installs OS packages, and never
    needs sudo -- it refuses to run as root, because root-owned clones make git
    refuse to update the YARA rules afterwards.

    \b
      mulder setup                 # install everything (~2.2 GB)
      mulder setup --dry-run       # print the plan, download nothing
      mulder setup --verify        # check an existing install, touch no network

    Assets are written to $MULDER_ASSET_ROOT if set, else /opt when it is
    writable, else ~/.local/share/mulder/assets.  Mulder *reads* /opt first, so
    an existing SIFT layout keeps working untouched.
    """
    import os

    from rich.console import Console

    from mulder.assets import install as install_mod
    from mulder.assets.fetch import HttpFetcher, OfflineFetcher
    from mulder.assets.paths import asset_write_root, reset_asset_caches
    from mulder.assets.paths import bin_dir as resolve_bin_dir

    console = Console(stderr=True, no_color=bool(os.environ.get("NO_COLOR")))

    if asset_root:
        # Set the variable rather than threading a second value around, so the
        # flag and the environment can never disagree.
        os.environ["MULDER_ASSET_ROOT"] = str(Path(asset_root).expanduser())
        reset_asset_caches()

    options = install_mod.SetupOptions(verify=verify, dry_run=dry_run)

    write_root = asset_write_root()
    try:
        plan = install_mod.build_plan(options, write_root, resolve_bin_dir())
        install_mod.preflight(plan, options)
    except install_mod.PlanError as exc:
        console.print(f"[red]{exc}[/red]", highlight=False)
        raise SystemExit(exc.exit_code) from None

    console.print(
        f"Asset root: {write_root}  |  shims: {plan.bin_dir}  |  arch: {plan.arch}",
        highlight=False,
    )

    fetcher = OfflineFetcher() if verify else HttpFetcher(timeout=120.0)

    if verify:
        console.print(f"Verifying {len(plan.selected)} assets; no network.", highlight=False)
    elif dry_run:
        # Manifest estimates only: --dry-run issues no requests of any kind.
        console.print(
            f"Plan: {len(plan.selected)} assets, about "
            f"{_human_bytes(plan.total_bytes)} to download.",
            highlight=False,
        )
    else:
        _confirm_size(console, plan, fetcher, yes)

    def _on_event(_key: str, message: str) -> None:
        console.print(f"  {message}", highlight=False)

    try:
        result = install_mod.provision(plan, options, fetch=fetcher, on_event=_on_event)
    except install_mod.PlanError as exc:
        console.print(f"[red]{exc}[/red]", highlight=False)
        raise SystemExit(exc.exit_code) from None
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted; nothing was left half-written.[/yellow]")
        raise SystemExit(3) from None

    _print_summary(console, result, plan, options)

    if as_json:
        click.echo(_setup_json(result, plan))

    raise SystemExit(result.exit_code)


def _confirm_size(console: Console, plan: Plan, fetcher: Fetcher, yes: bool) -> None:
    """Refine the plan total from Content-Length, then prompt above 1 GB."""
    total = plan.total_bytes
    head = getattr(fetcher, "head", None)
    if head is not None:
        refined = 0
        for asset in plan.selected:
            if asset.kind not in ("file", "archive"):
                refined += asset.size_estimate
                continue
            measured = head(asset.url_for(plan.arch))
            refined += measured if measured else asset.size_estimate
        total = refined

    console.print(
        f"Plan: {len(plan.selected)} assets, about {_human_bytes(total)} to download.",
        highlight=False,
    )
    if total <= 1024**3 or yes:
        return
    if not _is_interactive():
        console.print(
            "[red]This plan downloads more than 1 GB and stdin is not a terminal. "
            "Re-run with --yes to proceed.[/red]"
        )
        raise SystemExit(2)
    if not click.confirm(f"Download about {_human_bytes(total)}?", default=True):
        raise SystemExit(2)


def _print_summary(console: Console, result: Result, plan: Plan, options: SetupOptions) -> None:
    """One row per manifest asset, selected or not.

    Nothing is ever omitted, so a silent partial install is not expressible.
    """
    from rich.table import Table

    from mulder.assets.install import capability_gaps

    table = Table(title="Summary", title_justify="left")
    table.add_column("asset")
    table.add_column("status")
    table.add_column("detail")
    installed = shadowed = failed = missing = 0
    for outcome in result.outcomes:
        status = outcome.status
        colour = "green"
        if outcome.shadowed_by:
            status = f"{status}, shadowed by {outcome.shadowed_by}"
            colour = "yellow"
            shadowed += 1
        elif outcome.failed:
            colour = "red"
            failed += 1
        elif not outcome.selected:
            colour = "dim"
        elif outcome.status in ("missing", "invalid"):
            colour = "yellow"
            missing += 1
        else:
            installed += 1
        table.add_row(outcome.key, f"[{colour}]{status}[/{colour}]", outcome.detail)
    console.print(table)

    gaps = [] if options.dry_run else capability_gaps(result.outcomes)
    if gaps:
        console.print("\n[bold]Consequences[/bold]")
        for gap in gaps:
            console.print(f"  {gap}", highlight=False)

    for remedy in result.remedies:
        console.print(f"\n[yellow]{remedy}[/yellow]", highlight=False)

    selected = len(plan.selected)
    if options.dry_run:
        console.print(
            f"\nDry run: {selected} assets would be provisioned; nothing was downloaded."
        )
    elif failed:
        console.print(
            f"\n{installed} installed, {failed} failed - re-run 'mulder setup' to retry; "
            "see the errors above."
        )
    elif missing:
        # Never fall through to "All ... present" here: the table two lines up
        # says otherwise, and the last line is the one a human actually reads.
        console.print(
            f"\n{installed} present, {missing} missing - run 'mulder setup' to install them."
        )
    elif shadowed:
        console.print(
            f"\n{installed} installed, {shadowed} shadowed - mulder is still reading "
            "the older copies."
        )
    else:
        console.print(f"\nAll {selected} selected assets present.")


def _setup_json(result: Result, plan: Plan) -> str:
    import json

    return json.dumps(
        {
            "schema": 1,
            "root": str(plan.write_root),
            "arch": plan.arch,
            "assets": [
                {
                    "key": outcome.key,
                    "status": outcome.status,
                    "selected": outcome.selected,
                    "detail": outcome.detail,
                    "bytes": outcome.size,
                    "shadowed_by": outcome.shadowed_by,
                }
                for outcome in result.outcomes
            ],
            "exit": result.exit_code,
        },
        indent=2,
    )


def _human_bytes(count: int) -> str:
    """Render a byte count the way the docs quote sizes."""
    if count >= 1024**3:
        return f"{count / 1024**3:.1f} GB"
    return f"{count / 1024**2:.0f} MB"


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


@cli.command("benchmark")
@click.argument(
    "manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument(
    "results",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--output",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the versioned JSON score document to this path.",
)
def benchmark_cmd(manifest: Path, results: tuple[Path, ...], output_path: Path) -> None:
    """Score committed JSON/YAML RESULTS against a MANIFEST, entirely offline."""
    from mulder.benchmark.io import (
        BenchmarkInputError,
        load_manifest,
        load_result,
        render_comparison_table,
        write_score,
    )
    from mulder.benchmark.scorer import score_benchmark

    try:
        benchmark_manifest = load_manifest(manifest)
        benchmark_results = [load_result(path) for path in results]
        score = score_benchmark(
            benchmark_manifest, benchmark_results, evidence_root=manifest.parent
        )
        write_score(output_path, score)
    except (BenchmarkInputError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(render_comparison_table(score))
    click.echo(f"\nJSON score: {output_path}")


@cli.command("benchmark-ablate")
@click.argument(
    "result_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--ablation",
    "ablations",
    multiple=True,
    required=True,
    type=click.Choice(
        [
            "without-candidate-filters",
            "without-verifier",
            "without-independence-gate",
        ]
    ),
    help="Actually skip this component while replaying the committed workflow trace.",
)
@click.option("--run-id", required=True)
@click.option("--matrix-cell", required=True)
@click.option(
    "--output",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
)
def benchmark_ablate_cmd(
    result_path: Path,
    ablations: tuple[str, ...],
    run_id: str,
    matrix_cell: str,
    output_path: Path,
) -> None:
    """Replay a normalized benchmark RESULT with typed components disabled."""
    from pydantic import ValidationError

    from mulder.benchmark.ablations import execute_ablations
    from mulder.benchmark.io import BenchmarkInputError, load_result, write_result

    try:
        if output_path.resolve() == result_path.resolve():
            raise ValueError("--output must not overwrite the base benchmark result")
        result = execute_ablations(
            load_result(result_path),
            ablations,
            run_id=run_id,
            matrix_cell=matrix_cell,
        )
        write_result(output_path, result)
    except (BenchmarkInputError, OSError, ValidationError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Executable ablation result: {output_path}")


def _benchmark_assignments(values: tuple[str, ...], option: str) -> dict[str, str]:
    """Parse repeatable ``NAME=VALUE`` CLI options without silent replacement."""
    assignments: dict[str, str] = {}
    for value in values:
        name, separator, assigned = value.partition("=")
        if not separator or not name.strip() or not assigned.strip():
            raise click.ClickException(f"{option} must use non-empty NAME=VALUE entries")
        name = name.strip()
        if name in assignments:
            raise click.ClickException(f"duplicate {option} name: {name}")
        assignments[name] = assigned.strip()
    return assignments


@cli.command("benchmark-export")
@click.argument(
    "manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--case-db",
    "case_db_values",
    multiple=True,
    metavar="CASE_ID=PATH",
    help="Read a completed manifest case from this Mulder database.",
)
@click.option(
    "--failed-case",
    "failed_case_values",
    multiple=True,
    metavar="CASE_ID=REASON",
    help="Record an explicit failed/no-verdict matrix cell instead of hiding it.",
)
@click.option("--run-id", required=True)
@click.option("--system-name", default="mulder", show_default=True)
@click.option("--system-version", required=True)
@click.option("--matrix-cell", required=True)
@click.option(
    "--model",
    "model_values",
    multiple=True,
    required=True,
    metavar="ROLE=MODEL",
    help="Stamp each model role and exact model identifier.",
)
@click.option(
    "--prompt-set-sha256",
    required=True,
    help="SHA-256 of the exact prompt set used by this run.",
)
@click.option(
    "--toolset-sha256",
    required=True,
    help="SHA-256 of the exact tool configuration used by this run.",
)
@click.option("--orchestrator-version", required=True)
@click.option(
    "--methodology-version",
    default=None,
    help="Methodology version; defaults to the manifest and must match it when supplied.",
)
@click.option("--repeat-index", type=click.IntRange(min=0), default=0, show_default=True)
@click.option("--seed", type=int, default=None)
@click.option("--ablation", "ablations", multiple=True)
@click.option("--runtime-ms", type=click.IntRange(min=0), default=None)
@click.option("--input-tokens", type=click.IntRange(min=0), default=0, show_default=True)
@click.option("--output-tokens", type=click.IntRange(min=0), default=0, show_default=True)
@click.option("--unattributed-tokens", type=click.IntRange(min=0), default=0, show_default=True)
@click.option("--cost-usd", type=click.FloatRange(min=0), default=None)
@click.option(
    "--output",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
)
def benchmark_export_cmd(
    manifest: Path,
    case_db_values: tuple[str, ...],
    failed_case_values: tuple[str, ...],
    run_id: str,
    system_name: str,
    system_version: str,
    matrix_cell: str,
    model_values: tuple[str, ...],
    prompt_set_sha256: str | None,
    toolset_sha256: str | None,
    orchestrator_version: str,
    methodology_version: str | None,
    repeat_index: int,
    seed: int | None,
    ablations: tuple[str, ...],
    runtime_ms: int | None,
    input_tokens: int,
    output_tokens: int,
    unattributed_tokens: int,
    cost_usd: float | None,
    output_path: Path,
) -> None:
    """Export normalized benchmark JSON from read-only case databases."""
    from pydantic import ValidationError

    from mulder.benchmark.extractor import extract_run_result
    from mulder.benchmark.io import BenchmarkInputError, load_manifest, write_result
    from mulder.benchmark.models import ResourceUsage, RunIdentity

    try:
        from mulder.benchmark.models import RESERVED_ABLATION_LABELS

        executable_labels = sorted(set(ablations) & RESERVED_ABLATION_LABELS)
        if executable_labels:
            raise ValueError(
                "executable ablations cannot be stamped during export; export an unablated "
                "trace and use benchmark-ablate: " + ", ".join(executable_labels)
            )
        case_db_assignments = _benchmark_assignments(case_db_values, "--case-db")
        failed_cases = _benchmark_assignments(failed_case_values, "--failed-case")
        models = _benchmark_assignments(model_values, "--model")
        case_databases = {
            case_id: Path(path).expanduser() for case_id, path in case_db_assignments.items()
        }
        protected_inputs = {
            manifest.resolve(),
            *(path.resolve() for path in case_databases.values()),
        }
        if output_path.resolve() in protected_inputs:
            raise ValueError("--output must not overwrite the manifest or a case database")
        benchmark_manifest = load_manifest(manifest)
        if (
            methodology_version is not None
            and methodology_version != benchmark_manifest.methodology_version
        ):
            raise ValueError(
                f"methodology version {methodology_version!r} does not match manifest "
                f"{benchmark_manifest.methodology_version!r}"
            )
        effective_methodology = methodology_version or benchmark_manifest.methodology_version
        identity = RunIdentity(
            matrix_cell=matrix_cell,
            models=models,
            prompt_set_sha256=prompt_set_sha256,
            toolset_sha256=toolset_sha256,
            orchestrator_version=orchestrator_version,
            methodology_version=effective_methodology,
            repeat_index=repeat_index,
            seed=seed,
            ablations=list(ablations),
        )
        resources = ResourceUsage(
            runtime_ms=runtime_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            unattributed_tokens=unattributed_tokens,
            cost_usd=cost_usd,
        )
        result = extract_run_result(
            benchmark_manifest,
            case_databases=case_databases,
            failed_cases=failed_cases,
            run_id=run_id,
            system_name=system_name,
            system_version=system_version,
            identity=identity,
            resources=resources,
            evidence_root=manifest.parent,
        )
        write_result(output_path, result)
    except (BenchmarkInputError, OSError, ValidationError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Normalized benchmark result: {output_path}")


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
