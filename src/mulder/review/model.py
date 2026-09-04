"""One read-only query interface over authoritative Mulder case artifacts.

SQLite, audit JSONL, receipts, and usage sidecars remain the stores of record.
This module only projects their current state into a bounded, immutable review
model suitable for a CLI, static report, or a future transport adapter.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from mulder.audit import AuditLog
from mulder.models import (
    AuditSummary,
    ClaimConfirmation,
    ClaimVerification,
    ConfirmationAssessment,
    CoverageKey,
    CoverageRecord,
    EvidenceAnchor,
    Finding,
    FindingRevision,
    ToolOutcome,
    ToolOutcomeStatus,
)
from mulder.receipt import ReplayInventory, verify_case
from mulder.review.decisions import ReviewWorkflow, ReviewWorkflowError

REVIEW_SCHEMA = "mulder.case-review"
REVIEW_VERSION = 1
DEFAULT_FINDING_LIMIT = 100
DEFAULT_EVIDENCE_LIMIT = 200
DEFAULT_REVISION_LIMIT = 200
MAX_FINDING_LIMIT = 500
MAX_EVIDENCE_LIMIT = 1000
MAX_REVISION_LIMIT = 1000
EpistemicState = Literal[
    "legacy_unverified", "unverified", "verified", "contradicted", "inconclusive"
]

_REPORT_SUFFIXES = (".report.md", ".report.html", ".report.pdf")
_PHASE_ORDER = (
    "catalog",
    "extraction",
    "cross_system",
    "alternative_narrative",
    "report",
    "seal",
)


class CaseReviewError(ValueError):
    """Raised when a case cannot be projected without guessing."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)


class PageState(_FrozenModel):
    """Stable offset pagination metadata."""

    offset: int = Field(ge=0)
    limit: int = Field(gt=0)
    returned: int = Field(ge=0)
    total: int = Field(ge=0)

    @property
    def truncated(self) -> bool:
        return self.offset > 0 or self.offset + self.returned < self.total


class ProgressState(_FrozenModel):
    system_name: str
    tools_completed: tuple[str, ...]
    questions_addressed: tuple[str, ...]
    notes: str | None
    recorded_at: str


class CaseState(_FrozenModel):
    state: Literal["native", "legacy_compatible"]
    case_id: str
    database_path: str
    ingested_at: str
    evidence_root: str
    extractor_versions: dict[str, str]
    narrative: str | None
    source_count: int = Field(ge=0)
    evidence_registry_count: int = Field(ge=0)
    progress: tuple[ProgressState, ...]
    legacy_states: tuple[str, ...]


class PhaseState(_FrozenModel):
    """Observed phase evidence; never a strengthened completion claim."""

    name: str
    state: Literal[
        "metadata_present",
        "activity_observed",
        "artifact_present",
        "receipt_present",
        "not_recorded",
    ]
    basis: tuple[str, ...]
    completion_claimed: Literal[False] = False


class ClaimFact(_FrozenModel):
    claim_id: str
    finding_id: str
    ordinal: int = Field(ge=0)
    statement: str
    subject: str
    predicate: str
    object_value: object
    qualifiers: dict[str, object]
    epistemic_state: EpistemicState
    anchor_count: int = Field(ge=0)
    anchors: tuple[EvidenceAnchor, ...]
    verifications: tuple[ClaimVerification, ...]


class ConfirmationState(_FrozenModel):
    status: Literal["evaluated", "not_asserted", "legacy_unavailable"]
    assessment: ConfirmationAssessment | None = None


class FindingState(_FrozenModel):
    finding: Finding
    active: bool
    lifecycle_state: str
    revision_count: int = Field(ge=0)
    revisions: tuple[FindingRevision, ...]
    claim_state: Literal["available", "not_asserted", "legacy_unavailable"]
    claims: tuple[ClaimFact, ...]
    confirmation: ConfirmationState
    coverage: tuple[CoverageRecord, ...]


class FindingsState(_FrozenModel):
    page: PageState
    active_total: int = Field(ge=0)
    withdrawn_total: int = Field(ge=0)
    active: tuple[FindingState, ...]
    withdrawn: tuple[FindingState, ...]
    revision_page: PageState
    evidence_page: PageState


class CoverageCell(_FrozenModel):
    record: CoverageRecord
    scoped_negative_finding_ids: tuple[str, ...]


class CoverageState(_FrozenModel):
    status: Literal["available", "legacy_unavailable"]
    matrix: tuple[CoverageCell, ...]
    scoped_negative_finding_ids: tuple[str, ...]


class AuditState(_FrozenModel):
    presence: Literal["present", "absent"]
    path: str
    integrity_status: str
    integrity_ok: bool
    entry_count: int = Field(ge=0)
    legacy_entries: int = Field(ge=0)
    head_hash: str | None
    error_code: str | None
    message: str
    summary: AuditSummary


class ReceiptState(_FrozenModel):
    presence: Literal["present", "absent"]
    path: str
    status: str
    manifest_hash: str | None
    signature_status: str
    public_key: dict[str, str] | None
    replay_status: str
    replay_reasons: tuple[str, ...]
    diagnostics: tuple[dict[str, object], ...]


class ModelUsageState(_FrozenModel):
    model: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class CostsState(_FrozenModel):
    basis: Literal["audit_estimate"] = "audit_estimate"
    estimated_cost_usd: float = Field(ge=0)
    estimated_input_tokens: int = Field(ge=0)
    estimated_output_tokens: int = Field(ge=0)
    recorded_model_usage: tuple[ModelUsageState, ...]
    recorded_input_tokens: int = Field(ge=0)
    recorded_output_tokens: int = Field(ge=0)


class ProjectionPlaceholder(_FrozenModel):
    status: Literal["not_implemented", "available"] = "not_implemented"
    items: tuple[object, ...] = ()
    note: str


class ReviewActionState(_FrozenModel):
    sequence: int = Field(ge=1)
    event_id: str
    kind: str
    subject_type: str
    subject_id: str
    reviewer: str
    comment: str
    created_at: str


class ApprovalReviewState(_FrozenModel):
    state: Literal[
        "unavailable", "not_requested", "awaiting_review", "approved", "rejected", "stale"
    ]
    claim_set_digest: str | None = None
    audit_head_digest: str | None = None
    request_id: str | None = None
    decision_id: str | None = None
    reviewer: str | None = None
    reason: str = ""


class CaseReviewModel(_FrozenModel):
    """Immutable result returned by the review module's sole query interface."""

    review_schema: Literal["mulder.case-review"] = Field(
        default="mulder.case-review", alias="schema"
    )
    version: Literal[1] = 1
    case: CaseState
    phases: tuple[PhaseState, ...]
    findings: FindingsState
    coverage: CoverageState
    audit: AuditState
    receipt: ReceiptState
    costs: CostsState
    review_actions: tuple[ReviewActionState, ...]
    approval: ApprovalReviewState
    contradictions: ProjectionPlaceholder
    follow_ups: ProjectionPlaceholder
    graph: ProjectionPlaceholder

    def proof_cards(self) -> list[dict[str, object]]:
        """Adapt the same bounded finding facts to the static-report interface."""
        cards: list[dict[str, object]] = []
        for item in (*self.findings.active, *self.findings.withdrawn):
            claims: list[dict[str, object]] = []
            for claim in item.claims:
                claim_data = claim.model_dump(mode="json")
                claim_data["verifications"] = [
                    verification.model_dump(mode="json")
                    for verification in claim.verifications
                ]
                claims.append(claim_data)
            cards.append(
                {
                    "schema": "mulder.finding-proof-card",
                    "version": 1,
                    "finding": {
                        "finding_id": item.finding.finding_id,
                        "title": item.finding.title,
                        "severity": item.finding.severity,
                        "confidence": item.finding.confidence,
                        "evidence_refs": list(item.finding.evidence_refs),
                        "sources": list(item.finding.sources),
                    },
                    "claims": claims,
                    "revisions": [revision.model_dump(mode="json") for revision in item.revisions],
                    "coverage": [record.model_dump(mode="json") for record in item.coverage],
                    "receipt": {
                        "status": self.receipt.status,
                        "signature_status": self.receipt.signature_status,
                        "manifest_hash": self.receipt.manifest_hash,
                        "audit_head": self.audit.head_hash,
                        "public_key_fingerprint": (
                            self.receipt.public_key.get("fingerprint")
                            if self.receipt.public_key is not None
                            else None
                        ),
                    },
                }
            )
        return cards


class EvidenceCitation(_FrozenModel):
    """Exact selector used by every evidence-detail adapter."""

    anchor_id: str
    claim_id: str
    finding_id: str
    source_name: str
    window_id: int = Field(gt=0)
    line_start: int
    line_end: int
    char_start: int = Field(ge=0)
    char_end: int = Field(gt=0)
    exact_text: str


class EvidenceWindowDetail(_FrozenModel):
    """Authoritative source window with a validated exact-anchor selection."""

    source_id: int = Field(gt=0)
    source_name: str
    source_path: str
    source_hash: str
    extractor: str
    window_id: int = Field(gt=0)
    line_start: int
    line_end: int
    event_time: str | None
    raw_text: str
    text_before: str
    selected_text: str
    text_after: str


class EvidenceDetail(_FrozenModel):
    """Typed, read-only drill-down for one exact claim anchor."""

    detail_schema: Literal["mulder.evidence-detail"] = Field(
        default="mulder.evidence-detail", alias="schema"
    )
    version: Literal[1] = 1
    case_id: str
    finding_title: str
    finding_confidence: str
    finding_active: bool
    claim_statement: str
    claim_epistemic_state: EpistemicState
    anchor: EvidenceAnchor
    citation: EvidenceCitation
    window: EvidenceWindowDetail


@dataclass(frozen=True)
class ReviewQuery:
    """Bounded parameters for :func:`query_case_review`.

    The query reads one case snapshot. Finding rows, exact anchors, and full
    revision snapshots have independent offset pages so large evidence sets
    cannot accidentally become unbounded transport responses.
    """

    case_id: str
    db_dir: Path
    finding_offset: int = 0
    finding_limit: int = DEFAULT_FINDING_LIMIT
    evidence_offset: int = 0
    evidence_limit: int = DEFAULT_EVIDENCE_LIMIT
    revision_offset: int = 0
    revision_limit: int = DEFAULT_REVISION_LIMIT
    manifest_path: Path | None = None
    evidence_root: Path | None = None
    public_key_path: Path | None = None
    replay_inventory: ReplayInventory | Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if not self.case_id or Path(self.case_id).name != self.case_id:
            raise CaseReviewError("case_id must be one non-empty path segment")
        for name in ("finding_offset", "evidence_offset", "revision_offset"):
            if cast(int, getattr(self, name)) < 0:
                raise CaseReviewError(f"{name} must be non-negative")
        for name, maximum in (
            ("finding_limit", MAX_FINDING_LIMIT),
            ("evidence_limit", MAX_EVIDENCE_LIMIT),
            ("revision_limit", MAX_REVISION_LIMIT),
        ):
            value = cast(int, getattr(self, name))
            if value < 1 or value > maximum:
                raise CaseReviewError(f"{name} must be between 1 and {maximum}")


@dataclass(frozen=True)
class EvidenceReviewQuery:
    """Locator for one case-scoped exact citation drill-down."""

    case_id: str
    anchor_id: str
    db_dir: Path

    def __post_init__(self) -> None:
        for name, value in (("case_id", self.case_id), ("anchor_id", self.anchor_id)):
            if not value or len(value) > 256 or Path(value).name != value or value in {".", ".."}:
                raise CaseReviewError(f"{name} must be one safe path segment")


def _read_manifest_hash(path: Path) -> str | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("integrity"), dict):
        return None
    value = cast(dict[str, object], raw["integrity"]).get("manifest_hash")
    return value if isinstance(value, str) else None


def _read_json(value: object, subject: str, expected: type[Any]) -> Any:
    if not isinstance(value, str):
        raise CaseReviewError(f"{subject} is not stored as JSON text")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise CaseReviewError(f"{subject} contains invalid JSON: {exc}") from exc
    if not isinstance(parsed, expected):
        raise CaseReviewError(f"{subject} has the wrong JSON shape")
    return parsed


def _open_read_only(path: Path) -> sqlite3.Connection:
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(path) + suffix)
        try:
            size = sidecar.stat().st_size
        except FileNotFoundError:
            continue
        if size:
            raise CaseReviewError(
                f"case database is not a quiescent read-only snapshot: {sidecar.name} is non-empty"
            )
    try:
        connection = sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True
        )
    except sqlite3.Error as exc:
        raise CaseReviewError(f"cannot open case database read-only: {path}: {exc}") from exc
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        cast(str, row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        ).fetchall()
    }


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    escaped = table.replace('"', '""')
    return {
        cast(str, row[1])
        for row in connection.execute(f'PRAGMA table_xinfo("{escaped}")').fetchall()
    }


def _optional_column(columns: set[str], name: str, fallback: str) -> str:
    return f'"{name}"' if name in columns else fallback


def _finding_from_row(row: sqlite3.Row) -> Finding:
    negative = (
        _read_json(row["negative_verdict"], "finding negative verdict", dict)
        if row["negative_verdict"]
        else None
    )
    return Finding(
        finding_id=row["finding_id"],
        case_id=row["case_id"],
        title=row["title"],
        description=row["description"],
        severity=row["severity"],
        confidence=row["confidence"],
        evidence_refs=_read_json(row["evidence_refs"], "finding evidence refs", list),
        sources=_read_json(row["sources"], "finding sources", list),
        mitre_attack_ids=_read_json(row["mitre_attack_ids"], "finding ATT&CK IDs", list),
        event_time_start=row["event_time_start"],
        event_time_end=row["event_time_end"],
        negative_verdict=negative,
        submitted_at=row["submitted_at"],
    )


def _load_model_usage(path: Path, legacy: list[str]) -> tuple[ModelUsageState, ...]:
    if not path.is_file():
        return ()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        legacy.append("model_usage_invalid")
        return ()
    if not isinstance(raw, list):
        legacy.append("model_usage_invalid")
        return ()
    usage: list[ModelUsageState] = []
    for item in raw:
        if not isinstance(item, dict):
            legacy.append("model_usage_invalid")
            continue
        model = item.get("model")
        input_tokens = item.get("input_tokens", 0)
        output_tokens = item.get("output_tokens", 0)
        if (
            not isinstance(model, str)
            or not isinstance(input_tokens, int)
            or not isinstance(output_tokens, int)
            or input_tokens < 0
            or output_tokens < 0
        ):
            legacy.append("model_usage_invalid")
            continue
        usage.append(
            ModelUsageState(
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
        )
    return tuple(sorted(usage, key=lambda item: item.model))


def _receipt_state(query: ReviewQuery, case_dir: Path) -> ReceiptState:
    manifest = (
        query.manifest_path.expanduser().resolve(strict=False)
        if query.manifest_path is not None
        else case_dir / f"{query.case_id}.manifest.json"
    )
    if not manifest.is_file():
        return ReceiptState(
            presence="absent",
            path=str(manifest),
            status="not_sealed",
            manifest_hash=None,
            signature_status="unknown",
            public_key=None,
            replay_status="UNSUPPORTED",
            replay_reasons=("case manifest is absent",),
            diagnostics=(),
        )
    result = verify_case(
        manifest,
        evidence_root=query.evidence_root,
        public_key_path=query.public_key_path,
        replay_inventory=query.replay_inventory,
    )
    diagnostics = [diagnostic.as_dict() for diagnostic in result.diagnostics]
    status: str = result.status
    if result.case_id != query.case_id:
        status = "case_mismatch"
        diagnostics.append(
            {
                "code": "review.receipt_case_mismatch",
                "severity": "error",
                "subject": "manifest",
                "message": "Receipt belongs to a different case.",
                "expected": query.case_id,
                "actual": result.case_id,
            }
        )
    return ReceiptState(
        presence="present",
        path=str(manifest),
        status=status,
        manifest_hash=_read_manifest_hash(manifest),
        signature_status=result.signature_status,
        public_key=dict(result.public_key) if result.public_key is not None else None,
        replay_status=result.replay.status,
        replay_reasons=result.replay.reasons,
        diagnostics=tuple(diagnostics),
    )


def _audit_state(case_id: str, case_dir: Path) -> AuditState:
    path = case_dir / f"{case_id}.audit.jsonl"
    log = AuditLog(path)
    summary = log.summary()
    if not path.is_file():
        return AuditState(
            presence="absent",
            path=str(path),
            integrity_status="absent",
            integrity_ok=False,
            entry_count=0,
            legacy_entries=0,
            head_hash=None,
            error_code="audit_missing",
            message="Audit log is absent.",
            summary=summary,
        )
    integrity = log.verify_integrity()
    return AuditState(
        presence="present",
        path=str(path),
        integrity_status=integrity.status,
        integrity_ok=integrity.ok,
        entry_count=integrity.entries_checked,
        legacy_entries=integrity.legacy_entries,
        head_hash=integrity.head_hash,
        error_code=integrity.error_code,
        message=integrity.message,
        summary=summary,
    )


def _phase_states(
    *,
    source_count: int,
    progress: tuple[ProgressState, ...],
    report_names: tuple[str, ...],
    receipt: ReceiptState,
) -> tuple[PhaseState, ...]:
    states: dict[str, PhaseState] = {
        name: PhaseState(name=name, state="not_recorded", basis=()) for name in _PHASE_ORDER
    }
    states["catalog"] = PhaseState(
        name="catalog",
        state="metadata_present",
        basis=("case_metadata row exists",),
    )
    if source_count or progress:
        basis = []
        if source_count:
            basis.append(f"{source_count} normalized source(s) present")
        if progress:
            basis.append(f"{len(progress)} progress record(s) present")
        states["extraction"] = PhaseState(
            name="extraction", state="activity_observed", basis=tuple(basis)
        )
    if report_names:
        states["report"] = PhaseState(
            name="report",
            state="artifact_present",
            basis=tuple(f"artifact present: {name}" for name in report_names),
        )
    if receipt.presence == "present":
        states["seal"] = PhaseState(
            name="seal",
            state="receipt_present",
            basis=(f"receipt verification status: {receipt.status}",),
        )
    return tuple(states[name] for name in _PHASE_ORDER)


def query_case_review(query: ReviewQuery) -> CaseReviewModel:
    """Project one bounded case review without mutating any authoritative store."""
    case_dir = Path(query.db_dir).expanduser().resolve(strict=False)
    db_path = (case_dir / f"{query.case_id}.db").resolve(strict=False)
    if db_path.parent != case_dir:
        raise CaseReviewError("case database path escapes db_dir")
    if not db_path.is_file():
        raise CaseReviewError(f"case database not found: {db_path}")

    legacy: list[str] = []
    connection = _open_read_only(db_path)
    try:
        connection.execute("BEGIN")
        tables = _tables(connection)
        if "case_metadata" not in tables or "findings" not in tables:
            raise CaseReviewError("database is not a readable Mulder case")
        metadata_columns = _columns(connection, "case_metadata")
        if "narrative" not in metadata_columns:
            legacy.append("narrative_column_absent")
        metadata = connection.execute(
            "SELECT case_id, ingested_at, evidence_root, extractor_versions, "
            f"{_optional_column(metadata_columns, 'narrative', 'NULL')} AS narrative "
            "FROM case_metadata WHERE case_id = ?",
            (query.case_id,),
        ).fetchone()
        if metadata is None:
            actual = connection.execute("SELECT case_id FROM case_metadata LIMIT 1").fetchone()
            actual_id = actual[0] if actual is not None else None
            raise CaseReviewError(
                f"case ID mismatch: requested {query.case_id!r}, database contains {actual_id!r}"
            )
        extractor_versions = _read_json(
            metadata["extractor_versions"], "case extractor versions", dict
        )

        source_count = (
            cast(
                int,
                connection.execute(
                    "SELECT COUNT(*) FROM sources WHERE case_id = ?", (query.case_id,)
                ).fetchone()[0],
            )
            if "sources" in tables
            else 0
        )
        if "sources" not in tables:
            legacy.append("sources_absent")
        evidence_registry_count = (
            cast(int, connection.execute("SELECT COUNT(*) FROM evidence_registry").fetchone()[0])
            if "evidence_registry" in tables
            else 0
        )
        if "evidence_registry" not in tables:
            legacy.append("evidence_registry_absent")

        progress: list[ProgressState] = []
        if "progress" in tables:
            for row in connection.execute(
                "SELECT system_name, tools_completed, questions_addressed, notes, recorded_at "
                "FROM progress ORDER BY id"
            ).fetchall():
                progress.append(
                    ProgressState(
                        system_name=row["system_name"],
                        tools_completed=tuple(
                            _read_json(row["tools_completed"], "progress tools", list)
                        ),
                        questions_addressed=tuple(
                            _read_json(row["questions_addressed"], "progress questions", list)
                        ),
                        notes=row["notes"],
                        recorded_at=row["recorded_at"],
                    )
                )
        else:
            legacy.append("progress_absent")

        finding_columns = _columns(connection, "findings")
        for column in (
            "mitre_attack_ids",
            "negative_verdict",
            "is_deleted",
            "event_time_start",
            "event_time_end",
        ):
            if column not in finding_columns:
                legacy.append(f"finding_{column}_absent")
        mitre = _optional_column(finding_columns, "mitre_attack_ids", "'[]'")
        negative = _optional_column(finding_columns, "negative_verdict", "NULL")
        deleted = _optional_column(finding_columns, "is_deleted", "0")
        event_start = _optional_column(finding_columns, "event_time_start", "NULL")
        event_end = _optional_column(finding_columns, "event_time_end", "NULL")
        finding_select = (
            "SELECT finding_id, case_id, title, description, severity, confidence, "
            f"evidence_refs, sources, {mitre} AS mitre_attack_ids, "
            f"{event_start} AS event_time_start, {event_end} AS event_time_end, "
            f"{negative} AS negative_verdict, {deleted} AS is_deleted, "
            "submitted_at FROM findings WHERE case_id = ? "
            "ORDER BY submitted_at, finding_id LIMIT ? OFFSET ?"
        )
        total_findings = cast(
            int,
            connection.execute(
                "SELECT COUNT(*) FROM findings WHERE case_id = ?", (query.case_id,)
            ).fetchone()[0],
        )
        active_total = cast(
            int,
            connection.execute(
                "SELECT COUNT(*) FROM findings WHERE case_id = ? AND "
                f"{deleted} = 0",
                (query.case_id,),
            ).fetchone()[0],
        )
        selected_rows = connection.execute(
            finding_select, (query.case_id, query.finding_limit, query.finding_offset)
        ).fetchall()
        selected: list[tuple[Finding, bool]] = [
            (_finding_from_row(row), not bool(row["is_deleted"])) for row in selected_rows
        ]
        selected_ids = [finding.finding_id for finding, _active in selected]

        placeholders = ",".join("?" for _ in selected_ids) or "NULL"
        claim_rows: list[sqlite3.Row] = []
        claims_available = "claims" in tables
        if claims_available and selected_ids:
            claim_rows = connection.execute(
                "SELECT claim_id, finding_id, ordinal, statement, subject, predicate, "
                "object_value, qualifiers, epistemic_state FROM claims "
                f"WHERE finding_id IN ({placeholders}) ORDER BY finding_id, ordinal, claim_id",
                selected_ids,
            ).fetchall()
        elif not claims_available:
            legacy.append("claims_absent")
        claim_ids = [cast(str, row["claim_id"]) for row in claim_rows]
        claim_placeholders = ",".join("?" for _ in claim_ids) or "NULL"

        anchor_counts: dict[str, int] = defaultdict(int)
        independence: dict[str, set[str]] = defaultdict(set)
        anchors_by_claim: dict[str, list[EvidenceAnchor]] = defaultdict(list)
        evidence_total = 0
        if "evidence_anchors" in tables and claim_ids:
            for row in connection.execute(
                "SELECT claim_id, COUNT(*) AS total FROM evidence_anchors "
                f"WHERE claim_id IN ({claim_placeholders}) GROUP BY claim_id",
                claim_ids,
            ).fetchall():
                anchor_counts[row["claim_id"]] = row["total"]
            for row in connection.execute(
                "SELECT claim_id, independence_key, role FROM evidence_anchors "
                f"WHERE claim_id IN ({claim_placeholders}) ORDER BY claim_id, anchor_id",
                claim_ids,
            ).fetchall():
                if row["role"] == "supports":
                    independence[row["claim_id"]].add(row["independence_key"])
            evidence_total = sum(anchor_counts.values())
            anchor_rows = connection.execute(
                "SELECT anchor_id, claim_id, tool_call_id, source_id, source_name, source_hash, "
                "window_id, line_start, line_end, char_start, char_end, exact_text, "
                "artifact_family, extractor_family, independence_key, value_type, "
                "normalized_value, role FROM evidence_anchors "
                f"WHERE claim_id IN ({claim_placeholders}) ORDER BY claim_id, anchor_id "
                "LIMIT ? OFFSET ?",
                [*claim_ids, query.evidence_limit, query.evidence_offset],
            ).fetchall()
            for row in anchor_rows:
                anchors_by_claim[row["claim_id"]].append(
                    EvidenceAnchor(
                        anchor_id=row["anchor_id"],
                        claim_id=row["claim_id"],
                        tool_call_id=row["tool_call_id"],
                        source_id=row["source_id"],
                        source_name=row["source_name"],
                        source_hash=row["source_hash"],
                        window_id=row["window_id"],
                        line_start=row["line_start"],
                        line_end=row["line_end"],
                        char_start=row["char_start"],
                        char_end=row["char_end"],
                        exact_text=row["exact_text"],
                        artifact_family=row["artifact_family"],
                        extractor_family=row["extractor_family"],
                        independence_key=row["independence_key"],
                        value_type=row["value_type"],
                        normalized_value=_read_json(
                            row["normalized_value"], "anchor normalized value", object
                        ),
                        role=row["role"],
                    )
                )
        elif claims_available and "evidence_anchors" not in tables:
            legacy.append("evidence_anchors_absent")

        verifications_by_claim: dict[str, list[ClaimVerification]] = defaultdict(list)
        if "claim_verifications" in tables and claim_ids:
            rows = connection.execute(
                "SELECT verification_id, claim_id, verifier_name, verifier_version, result, "
                "reason_code, details, verified_at FROM claim_verifications "
                f"WHERE claim_id IN ({claim_placeholders}) "
                "ORDER BY claim_id, verified_at, verification_id",
                claim_ids,
            ).fetchall()
            for row in rows:
                verifications_by_claim[row["claim_id"]].append(
                    ClaimVerification(
                        verification_id=row["verification_id"],
                        claim_id=row["claim_id"],
                        verifier_name=row["verifier_name"],
                        verifier_version=row["verifier_version"],
                        result=row["result"],
                        reason_code=row["reason_code"],
                        details=_read_json(row["details"], "verification details", dict),
                        verified_at=row["verified_at"],
                    )
                )
        elif claims_available and "claim_verifications" not in tables:
            legacy.append("claim_verifications_absent")

        claims_by_finding: dict[str, list[ClaimFact]] = defaultdict(list)
        confirmations_by_finding: dict[str, list[ClaimConfirmation]] = defaultdict(list)
        for row in claim_rows:
            claim_id = cast(str, row["claim_id"])
            state = cast(EpistemicState, row["epistemic_state"])
            claims_by_finding[row["finding_id"]].append(
                ClaimFact(
                    claim_id=claim_id,
                    finding_id=row["finding_id"],
                    ordinal=row["ordinal"],
                    statement=row["statement"],
                    subject=row["subject"],
                    predicate=row["predicate"],
                    object_value=_read_json(row["object_value"], "claim object", object),
                    qualifiers=_read_json(row["qualifiers"], "claim qualifiers", dict),
                    epistemic_state=state,
                    anchor_count=anchor_counts[claim_id],
                    anchors=tuple(anchors_by_claim[claim_id]),
                    verifications=tuple(verifications_by_claim[claim_id]),
                )
            )
            independent_count = len(independence[claim_id])
            accepted = state == "verified" and independent_count >= 2
            confirmations_by_finding[row["finding_id"]].append(
                ClaimConfirmation(
                    claim_id=claim_id,
                    accepted=accepted,
                    reason_code=(
                        "verified_and_independently_corroborated"
                        if accepted
                        else f"claim_{state}"
                        if state != "verified"
                        else "insufficient_independent_sources"
                    ),
                    independent_sources=independent_count,
                    required_sources=2,
                )
            )

        revision_count: dict[str, int] = defaultdict(int)
        latest_state: dict[str, str] = {}
        revisions_by_finding: dict[str, list[FindingRevision]] = defaultdict(list)
        revision_total = 0
        revisions_available = "finding_revisions" in tables
        if revisions_available and selected_ids:
            all_revision_rows = connection.execute(
                "SELECT finding_id, revision_number, state FROM finding_revisions "
                f"WHERE finding_id IN ({placeholders}) "
                "ORDER BY finding_id, revision_number, revision_id",
                selected_ids,
            ).fetchall()
            for row in all_revision_rows:
                revision_count[row["finding_id"]] += 1
                latest_state[row["finding_id"]] = row["state"]
            revision_total = len(all_revision_rows)
            rows = connection.execute(
                "SELECT revision_id, finding_id, revision_number, parent_revision_id, state, "
                "snapshot, actor_kind, actor_id, reason_code, changed_fields, evidence_added, "
                "evidence_removed, tombstone, created_at FROM finding_revisions "
                f"WHERE finding_id IN ({placeholders}) "
                "ORDER BY finding_id, revision_number, revision_id LIMIT ? OFFSET ?",
                [*selected_ids, query.revision_limit, query.revision_offset],
            ).fetchall()
            for row in rows:
                revisions_by_finding[row["finding_id"]].append(
                    FindingRevision(
                        revision_id=row["revision_id"],
                        finding_id=row["finding_id"],
                        revision_number=row["revision_number"],
                        parent_revision_id=row["parent_revision_id"],
                        state=row["state"],
                        snapshot=Finding.model_validate_json(row["snapshot"]),
                        actor_kind=row["actor_kind"],
                        actor_id=row["actor_id"],
                        reason_code=row["reason_code"],
                        changed_fields=_read_json(
                            row["changed_fields"], "revision changed fields", list
                        ),
                        evidence_added=_read_json(
                            row["evidence_added"], "revision evidence added", list
                        ),
                        evidence_removed=_read_json(
                            row["evidence_removed"], "revision evidence removed", list
                        ),
                        tombstone=bool(row["tombstone"]),
                        created_at=row["created_at"],
                    )
                )
        elif not revisions_available:
            legacy.append("finding_revisions_absent")

        coverage_records: list[CoverageRecord] = []
        coverage_available = "coverage_register" in tables
        if coverage_available:
            rows = connection.execute(
                "SELECT system_name, evidence_domain, check_name, status, coverage, reason, "
                "source_name, tool_call_id, recorded_at FROM coverage_register "
                "WHERE case_id = ? ORDER BY system_name, evidence_domain, check_name",
                (query.case_id,),
            ).fetchall()
            for row in rows:
                coverage_records.append(
                    CoverageRecord(
                        case_id=query.case_id,
                        key=CoverageKey(
                            system_name=row["system_name"],
                            evidence_domain=row["evidence_domain"],
                            check_name=row["check_name"],
                        ),
                        outcome=ToolOutcome(
                            status=ToolOutcomeStatus(row["status"]),
                            coverage=_read_json(row["coverage"], "coverage metadata", dict),
                            reason=row["reason"],
                        ),
                        source_name=row["source_name"],
                        tool_call_id=row["tool_call_id"],
                        recorded_at=row["recorded_at"],
                    )
                )
        else:
            legacy.append("coverage_register_absent")

        scoped_negative_ids = tuple(
            sorted(
                finding.finding_id
                for finding, _active in selected
                if finding.negative_verdict is not None
            )
        )
        negative_by_key: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        for finding, _active in selected:
            if finding.negative_verdict is None:
                continue
            for key in finding.negative_verdict.scope:
                negative_by_key[(key.system_name, key.evidence_domain, key.check_name)].append(
                    finding.finding_id
                )

        review_findings: list[FindingState] = []
        for finding, active in selected:
            finding_claims = tuple(claims_by_finding[finding.finding_id])
            decisions = tuple(confirmations_by_finding[finding.finding_id])
            if not claims_available:
                claim_state: Literal["available", "not_asserted", "legacy_unavailable"] = (
                    "legacy_unavailable"
                )
                confirmation = ConfirmationState(status="legacy_unavailable")
            elif not finding_claims:
                claim_state = "not_asserted"
                confirmation = ConfirmationState(status="not_asserted")
            else:
                claim_state = "available"
                confirmation = ConfirmationState(
                    status="evaluated",
                    assessment=ConfirmationAssessment(
                        accepted=all(decision.accepted for decision in decisions),
                        claims=list(decisions),
                    ),
                )
            relevant_coverage = tuple(
                record
                for record in coverage_records
                if record.source_name in finding.sources
                or record.tool_call_id in finding.evidence_refs
                or (
                    finding.negative_verdict is not None
                    and record.key in finding.negative_verdict.scope
                )
            )
            lifecycle = latest_state.get(finding.finding_id)
            if lifecycle is None:
                lifecycle = "withdrawn" if not active else "legacy_unversioned"
            review_findings.append(
                FindingState(
                    finding=finding,
                    active=active,
                    lifecycle_state=lifecycle,
                    revision_count=revision_count[finding.finding_id],
                    revisions=tuple(revisions_by_finding[finding.finding_id]),
                    claim_state=claim_state,
                    claims=finding_claims,
                    confirmation=confirmation,
                    coverage=relevant_coverage,
                )
            )
        connection.rollback()
    except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, CaseReviewError):
            raise
        raise CaseReviewError(f"cannot read case review from {db_path}: {exc}") from exc
    finally:
        connection.close()

    audit = _audit_state(query.case_id, case_dir)
    receipt = _receipt_state(query, case_dir)
    try:
        workflow = ReviewWorkflow(query.case_id, case_dir)
        review_events = workflow.events(limit=1000)
        approval_status = workflow.status()
        review_actions = tuple(
            ReviewActionState(
                sequence=event.sequence,
                event_id=event.event_id,
                kind=event.kind,
                subject_type=event.subject_type,
                subject_id=event.subject_id,
                reviewer=event.reviewer,
                comment=event.comment,
                created_at=event.created_at,
            )
            for event in review_events
        )
        approval = ApprovalReviewState(
            state=approval_status.state,
            claim_set_digest=approval_status.claim_set_digest,
            audit_head_digest=approval_status.audit_head_digest,
            request_id=(
                approval_status.request.request_id
                if approval_status.request is not None
                else None
            ),
            decision_id=(
                approval_status.decision.decision_id
                if approval_status.decision is not None
                else None
            ),
            reviewer=(
                approval_status.decision.reviewer
                if approval_status.decision is not None
                else None
            ),
            reason=approval_status.reason,
        )
    except ReviewWorkflowError:
        review_actions = ()
        approval = ApprovalReviewState(
            state="unavailable",
            reason="approval requires native atomic claims and a verified audit chain",
        )
    usage = _load_model_usage(case_dir / f"{query.case_id}.model_usage.json", legacy)
    report_names = tuple(
        f"{query.case_id}{suffix}"
        for suffix in _REPORT_SUFFIXES
        if (case_dir / f"{query.case_id}{suffix}").is_file()
    )
    case = CaseState(
        state="legacy_compatible" if legacy else "native",
        case_id=query.case_id,
        database_path=str(db_path),
        ingested_at=metadata["ingested_at"],
        evidence_root=metadata["evidence_root"],
        extractor_versions=cast(dict[str, str], extractor_versions),
        narrative=metadata["narrative"],
        source_count=source_count,
        evidence_registry_count=evidence_registry_count,
        progress=tuple(progress),
        legacy_states=tuple(sorted(set(legacy))),
    )
    active_findings = tuple(item for item in review_findings if item.active)
    withdrawn_findings = tuple(item for item in review_findings if not item.active)
    finding_state = FindingsState(
        page=PageState(
            offset=query.finding_offset,
            limit=query.finding_limit,
            returned=len(review_findings),
            total=total_findings,
        ),
        active_total=active_total,
        withdrawn_total=total_findings - active_total,
        active=active_findings,
        withdrawn=withdrawn_findings,
        revision_page=PageState(
            offset=query.revision_offset,
            limit=query.revision_limit,
            returned=sum(len(item.revisions) for item in review_findings),
            total=revision_total,
        ),
        evidence_page=PageState(
            offset=query.evidence_offset,
            limit=query.evidence_limit,
            returned=sum(
                len(claim.anchors) for item in review_findings for claim in item.claims
            ),
            total=evidence_total,
        ),
    )
    matrix = tuple(
        CoverageCell(
            record=record,
            scoped_negative_finding_ids=tuple(
                sorted(
                    negative_by_key[
                        (
                            record.key.system_name,
                            record.key.evidence_domain,
                            record.key.check_name,
                        )
                    ]
                )
            ),
        )
        for record in coverage_records
    )
    return CaseReviewModel(
        case=case,
        phases=_phase_states(
            source_count=source_count,
            progress=tuple(progress),
            report_names=report_names,
            receipt=receipt,
        ),
        findings=finding_state,
        coverage=CoverageState(
            status="available" if coverage_available else "legacy_unavailable",
            matrix=matrix,
            scoped_negative_finding_ids=scoped_negative_ids,
        ),
        audit=audit,
        receipt=receipt,
        costs=CostsState(
            estimated_cost_usd=audit.summary.estimated_cost_usd,
            estimated_input_tokens=audit.summary.estimated_input_tokens,
            estimated_output_tokens=audit.summary.estimated_output_tokens,
            recorded_model_usage=usage,
            recorded_input_tokens=sum(item.input_tokens for item in usage),
            recorded_output_tokens=sum(item.output_tokens for item in usage),
        ),
        review_actions=review_actions,
        approval=approval,
        contradictions=ProjectionPlaceholder(
            note=(
                "No first-class contradiction table exists yet; claim epistemic states, "
                "contradicting anchor roles, and verification results are preserved verbatim."
            )
        ),
        follow_ups=ProjectionPlaceholder(
            status="available" if "review_events" in tables else "not_implemented",
            items=tuple(
                action.model_dump(mode="json")
                for action in review_actions
                if action.kind == "follow_up"
            ),
            note=(
                "Durable append-only follow-up review events."
                if "review_events" in tables
                else "No durable follow-up store exists yet; absence is not completion."
            ),
        ),
        graph=ProjectionPlaceholder(
            note="No authoritative graph projection exists yet; no entities or edges are inferred."
        ),
    )


def query_evidence_detail(query: EvidenceReviewQuery) -> EvidenceDetail:
    """Resolve one exact anchor through its case, claim, source, and window.

    The join is case-scoped at both the finding and source rows.  Stored anchor
    coordinates must still select the stored exact text from the authoritative
    window; a mismatch is diagnosed instead of rendered as a citation.
    """
    db_path = Path(query.db_dir).expanduser() / f"{query.case_id}.db"
    if not db_path.is_file():
        raise CaseReviewError(f"case database not found: {db_path}")
    connection = _open_read_only(db_path)
    try:
        connection.execute("BEGIN")
        tables = _tables(connection)
        required = {
            "case_metadata",
            "findings",
            "claims",
            "evidence_anchors",
            "sources",
            "windows",
        }
        missing = sorted(required.difference(tables))
        if missing:
            raise CaseReviewError(
                "exact evidence drill-down is unavailable for this legacy case: "
                + ", ".join(missing)
            )
        source_columns = _columns(connection, "sources")
        finding_columns = _columns(connection, "findings")
        if "case_id" not in source_columns:
            raise CaseReviewError(
                "exact evidence drill-down is unavailable: source case ownership is not recorded"
            )
        deleted = "f.is_deleted" if "is_deleted" in finding_columns else "0"
        row = connection.execute(
            "SELECT f.case_id, f.title AS finding_title, f.confidence, "
            f"{deleted} AS is_deleted, "
            "c.finding_id, c.statement, c.epistemic_state, "
            "a.anchor_id, a.claim_id, a.tool_call_id, a.source_id, a.source_name, "
            "a.source_hash, a.window_id, a.line_start AS anchor_line_start, "
            "a.line_end AS anchor_line_end, a.char_start, a.char_end, a.exact_text, "
            "a.artifact_family, a.extractor_family, a.independence_key, a.value_type, "
            "a.normalized_value, a.role, s.source_path, s.source_hash AS current_source_hash, "
            "s.extractor, w.line_start AS window_line_start, w.line_end AS window_line_end, "
            "w.event_time, w.raw_text "
            "FROM evidence_anchors a "
            "JOIN claims c ON c.claim_id = a.claim_id "
            "JOIN findings f ON f.finding_id = c.finding_id "
            "JOIN sources s ON s.source_id = a.source_id "
            "JOIN windows w ON w.window_id = a.window_id AND w.source_id = s.source_id "
            "WHERE a.anchor_id = ? AND f.case_id = ? AND s.case_id = ?",
            (query.anchor_id, query.case_id, query.case_id),
        ).fetchone()
        if row is None:
            raise CaseReviewError(
                f"evidence anchor not found in case {query.case_id}: {query.anchor_id}"
            )
        raw_text = cast(str, row["raw_text"])
        char_start = cast(int, row["char_start"])
        char_end = cast(int, row["char_end"])
        exact_text = cast(str, row["exact_text"])
        if char_start < 0 or char_end <= char_start or char_end > len(raw_text):
            raise CaseReviewError("evidence anchor has invalid character coordinates")
        selected_text = raw_text[char_start:char_end]
        if selected_text != exact_text:
            raise CaseReviewError(
                "evidence anchor text no longer matches its authoritative source window"
            )
        if row["source_hash"] != row["current_source_hash"]:
            raise CaseReviewError("evidence anchor source hash does not match its source row")
        anchor = EvidenceAnchor(
            anchor_id=row["anchor_id"],
            claim_id=row["claim_id"],
            tool_call_id=row["tool_call_id"],
            source_id=row["source_id"],
            source_name=row["source_name"],
            source_hash=row["source_hash"],
            window_id=row["window_id"],
            line_start=row["anchor_line_start"],
            line_end=row["anchor_line_end"],
            char_start=char_start,
            char_end=char_end,
            exact_text=exact_text,
            artifact_family=row["artifact_family"],
            extractor_family=row["extractor_family"],
            independence_key=row["independence_key"],
            value_type=row["value_type"],
            normalized_value=_read_json(
                row["normalized_value"], "anchor normalized value", object
            ),
            role=row["role"],
        )
        citation = EvidenceCitation(
            anchor_id=anchor.anchor_id,
            claim_id=anchor.claim_id,
            finding_id=row["finding_id"],
            source_name=anchor.source_name,
            window_id=anchor.window_id,
            line_start=anchor.line_start,
            line_end=anchor.line_end,
            char_start=anchor.char_start,
            char_end=anchor.char_end,
            exact_text=anchor.exact_text,
        )
        return EvidenceDetail(
            case_id=query.case_id,
            finding_title=row["finding_title"],
            finding_confidence=row["confidence"],
            finding_active=not bool(row["is_deleted"]),
            claim_statement=row["statement"],
            claim_epistemic_state=row["epistemic_state"],
            anchor=anchor,
            citation=citation,
            window=EvidenceWindowDetail(
                source_id=anchor.source_id,
                source_name=anchor.source_name,
                source_path=row["source_path"],
                source_hash=row["current_source_hash"],
                extractor=row["extractor"],
                window_id=anchor.window_id,
                line_start=row["window_line_start"],
                line_end=row["window_line_end"],
                event_time=row["event_time"],
                raw_text=raw_text,
                text_before=raw_text[:char_start],
                selected_text=selected_text,
                text_after=raw_text[char_end:],
            ),
        )
    except sqlite3.Error as exc:
        raise CaseReviewError(f"cannot read exact evidence citation: {exc}") from exc
    finally:
        connection.rollback()
        connection.close()


def format_case_review(review: CaseReviewModel) -> str:
    """Render a bounded human-readable adapter over :class:`CaseReviewModel`."""
    lines = [
        f"Case {review.case.case_id}",
        (
            f"Findings: {review.findings.active_total} active, "
            f"{review.findings.withdrawn_total} withdrawn "
            f"(showing {review.findings.page.returned}/{review.findings.page.total})"
        ),
        (
            f"Audit: {review.audit.integrity_status}; receipt: {review.receipt.status}; "
            f"signature: {review.receipt.signature_status}; replay: {review.receipt.replay_status}"
        ),
        f"Review approval: {review.approval.state}",
        (
            f"Cost: ${review.costs.estimated_cost_usd:.4f} estimated from audit; "
            f"recorded model tokens: {review.costs.recorded_input_tokens} in / "
            f"{review.costs.recorded_output_tokens} out"
        ),
        "Phases (observations, not completion claims):",
    ]
    for phase in review.phases:
        basis = "; ".join(phase.basis) or "no durable state"
        lines.append(f"  {phase.name}: {phase.state} — {basis}")
    for label, findings in (
        ("Active", review.findings.active),
        ("Withdrawn", review.findings.withdrawn),
    ):
        if not findings:
            continue
        lines.append(f"{label} findings:")
        for item in findings:
            lines.append(
                f"  [{item.finding.severity.upper()}] {item.finding.finding_id}: "
                f"{item.finding.title!r} ({item.finding.confidence}; {item.lifecycle_state})"
            )
            for claim in item.claims:
                lines.append(
                    f"    claim {claim.ordinal}: {claim.epistemic_state} — {claim.statement!r} "
                    f"[{len(claim.anchors)}/{claim.anchor_count} anchors shown]"
                )
    if review.case.legacy_states:
        lines.append("Legacy/unavailable: " + ", ".join(review.case.legacy_states))
    lines.extend(
        (
            f"Contradictions: {review.contradictions.status}",
            f"Follow-ups: {review.follow_ups.status}",
            f"Graph: {review.graph.status}",
        )
    )
    return "\n".join(lines)
