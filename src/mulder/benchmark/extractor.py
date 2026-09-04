"""Read-only normalization of Mulder case databases into benchmark results."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote

from mulder.benchmark.ablations import execute_workflow_base
from mulder.benchmark.anchors import canonical_anchor_id as canonical_anchor_id
from mulder.benchmark.io import BenchmarkInputError, read_text_selector_snapshot
from mulder.benchmark.models import (
    BenchmarkCase,
    BenchmarkManifest,
    BenchmarkRunResult,
    CaseRunResult,
    CaseWorkflowTrace,
    EvidenceArtifact,
    ObservedCoverage,
    ResourceUsage,
    RunIdentity,
    WorkflowCandidate,
    WorkflowEvidenceBinding,
)
from mulder.db import CaseDB
from mulder.models import ClaimVerification, FindingRevision


def canonical_coverage_domain(system: str, domain: str, check: str) -> str:
    """Encode a coverage-register key into an unambiguous manifest domain."""
    return "/".join(quote(part, safe="") for part in (system, domain, check))


_DATABASE_METADATA_PRAGMAS = (
    "application_id",
    "auto_vacuum",
    "encoding",
    "freelist_count",
    "journal_mode",
    "page_count",
    "page_size",
    "schema_version",
    "user_version",
)


def _database_commitment(connection: sqlite3.Connection) -> str:
    """Commit to the complete logical SQLite state visible to this transaction."""
    digest = hashlib.sha256()
    for pragma in _DATABASE_METADATA_PRAGMAS:
        row = connection.execute(f"PRAGMA {pragma}").fetchone()
        digest.update(pragma.encode("ascii"))
        digest.update(b"=")
        digest.update(repr(row).encode("utf-8"))
        digest.update(b"\0")
    for statement in connection.iterdump():
        digest.update(statement.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _database_path_identity(db_path: Path) -> tuple[int, int]:
    try:
        status = db_path.stat()
    except OSError as exc:
        raise ValueError(
            f"case database path became unavailable during benchmark export: {db_path}"
        ) from exc
    return status.st_dev, status.st_ino


def _open_read_snapshot(db_path: Path) -> sqlite3.Connection:
    source_uri = f"file:{quote(str(db_path.resolve()), safe='/')}?mode=ro"
    connection = sqlite3.connect(source_uri, uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
    except sqlite3.Error:
        connection.close()
        raise
    return connection


@contextmanager
def _stable_case_snapshot(db_path: Path) -> Iterator[Path]:
    """Yield one materialized read snapshot and reject concurrent mutations."""
    initial_identity = _database_path_identity(db_path)
    source = _open_read_snapshot(db_path)
    try:
        initial_commitment = _database_commitment(source)
        if _database_path_identity(db_path) != initial_identity:
            raise ValueError("case database path was replaced during benchmark export")
        with TemporaryDirectory(prefix="mulder-benchmark-snapshot-") as temp_dir:
            snapshot_path = Path(temp_dir) / "case.db"
            with sqlite3.connect(snapshot_path) as snapshot:
                source.backup(snapshot)
            try:
                yield snapshot_path
            finally:
                source.rollback()
                final_identity = _database_path_identity(db_path)
                if final_identity != initial_identity:
                    raise ValueError(
                        "case database path was replaced during benchmark export"
                    )
                final_source = _open_read_snapshot(db_path)
                try:
                    final_commitment = _database_commitment(final_source)
                    if _database_path_identity(db_path) != final_identity:
                        raise ValueError(
                            "case database path was replaced during benchmark export"
                        )
                finally:
                    final_source.rollback()
                    final_source.close()
            if final_commitment != initial_commitment:
                raise ValueError("case database changed during benchmark export")
    finally:
        source.close()


def _extract_case_workflow(
    case_id: str,
    db_path: Path,
    *,
    manifest_case: BenchmarkCase | None = None,
    evidence_root: Path | None = None,
) -> tuple[CaseRunResult, CaseWorkflowTrace]:
    if not db_path.is_file():
        raise ValueError(f"case database does not exist: {db_path}")
    with _stable_case_snapshot(db_path) as snapshot_path, CaseDB(snapshot_path) as db:
        metadata = db.get_case_metadata()
        if metadata.case_id != case_id:
            raise ValueError(
                f"database case_id {metadata.case_id!r} does not match manifest case "
                f"{case_id!r}"
            )
        active = {finding.finding_id: finding for finding in db.get_findings()}
        histories: dict[str, list[FindingRevision]] = {}
        for revision in db.get_all_finding_revisions():
            histories.setdefault(revision.finding_id, []).append(revision)
        candidates: list[WorkflowCandidate] = []
        for finding_id in sorted(set(active) | set(histories)):
            revisions = histories.get(finding_id, [])
            finding = revisions[0].snapshot if revisions else active[finding_id]
            current = active.get(finding_id) or next(
                revision.snapshot for revision in reversed(revisions) if not revision.tombstone
            )
            withdrawal = next(
                (revision for revision in reversed(revisions) if revision.tombstone),
                None,
            )
            verifications = db.get_claim_verifications(finding_id)
            current_verifications = db.evaluate_finding_claims(finding_id)
            by_claim: dict[str, list[ClaimVerification]] = {}
            for verification in verifications:
                by_claim.setdefault(verification.claim_id, []).append(verification)
            for claim in db.get_claims(finding_id):
                candidates.append(
                    WorkflowCandidate(
                        finding=finding,
                        claim=claim.model_copy(update={"epistemic_state": "unverified"}),
                        confidence_probability=(
                            0.95 if current.confidence == "confirmed" else 0.5
                        ),
                        source_verifications=by_claim.get(claim.claim_id, []),
                        current_verification=current_verifications[claim.claim_id],
                        finding_revisions=revisions,
                        withdrawal_revision=withdrawal,
                    )
                )

        coverage = [
            ObservedCoverage(
                domain=canonical_coverage_domain(
                    record.key.system_name,
                    record.key.evidence_domain,
                    record.key.check_name,
                ),
                status=record.outcome.status,
            )
            for record in db.get_coverage()
        ]
        bindings = _evidence_bindings(db, candidates, manifest_case, evidence_root)

        trace = CaseWorkflowTrace(
            case_id=case_id,
            trace_version=2,
            candidates=candidates,
            coverage=sorted(coverage, key=lambda item: item.domain),
            evidence_bindings=bindings,
        )
        result = execute_workflow_base(trace)
        if _evidence_bindings(
            db, candidates, manifest_case, evidence_root
        ) != bindings:
            raise ValueError("evidence bindings changed during benchmark export")
    return result, trace


def extract_case_result(case_id: str, db_path: Path) -> CaseRunResult:
    """Execute the real bounded benchmark workflow over one read-only case DB."""
    result, _ = _extract_case_workflow(case_id, db_path)
    return result


def extract_run_result(
    manifest: BenchmarkManifest,
    *,
    case_databases: Mapping[str, Path],
    failed_cases: Mapping[str, str],
    run_id: str,
    system_name: str,
    system_version: str,
    identity: RunIdentity,
    resources: ResourceUsage,
    evidence_root: Path | None = None,
) -> BenchmarkRunResult:
    """Normalize a complete benchmark run from DB cells and explicit failures."""
    overlap = set(case_databases) & set(failed_cases)
    if overlap:
        raise ValueError(f"cases cannot be both databases and failures: {sorted(overlap)!r}")
    manifest_cases = {case.case_id: case for case in manifest.cases}
    expected = set(manifest_cases)
    supplied = set(case_databases) | set(failed_cases)
    if supplied != expected:
        raise ValueError(
            "case inputs must exactly match the manifest; "
            f"missing={sorted(expected - supplied)!r}, unexpected={sorted(supplied - expected)!r}"
        )
    cases: list[CaseRunResult] = []
    workflow_traces: list[CaseWorkflowTrace] = []
    for case_id in sorted(expected):
        if case_id in failed_cases:
            cases.append(
                CaseRunResult(
                    case_id=case_id,
                    verdict="no_verdict",
                    cell_status="failed",
                    failure_reason=failed_cases[case_id],
                )
            )
            workflow_traces.append(
                CaseWorkflowTrace(
                    case_id=case_id,
                    trace_version=2,
                    failure_reason=failed_cases[case_id],
                )
            )
        else:
            case, trace = _extract_case_workflow(
                case_id,
                case_databases[case_id],
                manifest_case=manifest_cases[case_id],
                evidence_root=evidence_root,
            )
            cases.append(case)
            workflow_traces.append(trace)
    return BenchmarkRunResult(
        benchmark_id=manifest.benchmark_id,
        run_id=run_id,
        system_name=system_name,
        system_version=system_version,
        identity=identity,
        cases=cases,
        resources=resources,
        workflow_traces=workflow_traces,
    )


def _evidence_bindings(
    db: CaseDB,
    candidates: list[WorkflowCandidate],
    manifest_case: BenchmarkCase | None,
    evidence_root: Path | None,
) -> list[WorkflowEvidenceBinding]:
    if manifest_case is None:
        return []
    if evidence_root is None:
        raise ValueError("manifest evidence root is required for case database export")
    sources = {source.source_id: source for source in db.get_sources()}
    artifacts_by_digest: dict[str, list[EvidenceArtifact]] = {}
    for artifact in manifest_case.evidence:
        artifacts_by_digest.setdefault(artifact.sha256, []).append(artifact)
    expected_anchors = {anchor.anchor_id: anchor for anchor in manifest_case.anchors}
    bindings: dict[str, WorkflowEvidenceBinding] = {}
    for candidate in candidates:
        for anchor in candidate.claim.anchors:
            digest = anchor.source_hash.removeprefix("sha256:")
            matches = artifacts_by_digest.get(digest, [])
            if len(matches) != 1:
                raise ValueError(
                    f"anchor {anchor.anchor_id!r} does not bind one manifest artifact"
                )
            artifact = matches[0]
            source = sources.get(anchor.source_id)
            if source is None:
                raise ValueError(f"anchor {anchor.anchor_id!r} source is missing")
            artifact_path = (evidence_root / artifact.path).resolve()
            if Path(source.source_path).resolve() != artifact_path:
                raise ValueError(
                    f"anchor {anchor.anchor_id!r} source path does not match manifest artifact"
                )
            canonical_id = canonical_anchor_id(anchor)
            expected = expected_anchors.get(canonical_id)
            if expected is None:
                raise ValueError(f"anchor {canonical_id!r} has no answer-key selector")
            if expected.artifact_id != artifact.artifact_id:
                raise ValueError(
                    f"anchor {canonical_id!r} answer-key artifact does not match source"
                )
            try:
                artifact_snapshot = read_text_selector_snapshot(
                    artifact_path, expected.selector
                )
            except BenchmarkInputError as exc:
                raise ValueError(str(exc)) from exc
            if artifact_snapshot.artifact_sha256 != artifact.sha256:
                raise ValueError(
                    f"anchor {anchor.anchor_id!r} artifact bytes no longer match manifest"
                )
            resolved_text = artifact_snapshot.exact_text
            resolved_hash = hashlib.sha256(resolved_text.encode("utf-8")).hexdigest()
            if resolved_text != anchor.exact_text:
                raise ValueError(
                    f"anchor {canonical_id!r} selector does not resolve its exact text"
                )
            if resolved_hash != expected.exact_text_sha256:
                raise ValueError(
                    f"anchor {canonical_id!r} selector does not match answer-key exact text"
                )
            root_id = artifact.root_acquisition_id
            if root_id is None:
                raise ValueError(
                    f"artifact {artifact.artifact_id!r} lacks root acquisition identity"
                )
            binding = WorkflowEvidenceBinding(
                anchor_id=canonical_id,
                artifact_id=artifact.artifact_id,
                artifact_sha256=artifact.sha256,
                selector=expected.selector,
                exact_text_sha256=resolved_hash,
                root_acquisition_id=root_id,
            )
            earlier = bindings.setdefault(canonical_id, binding)
            if earlier != binding:
                raise ValueError(f"anchor {canonical_id!r} has conflicting artifact bindings")
    return sorted(bindings.values(), key=lambda item: item.anchor_id)
