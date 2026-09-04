"""Per-case SQLite database lifecycle and queries using SQLAlchemy Core."""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import re
import threading
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict, TypeVar, cast
from uuid import uuid4

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    delete,
    event,
    func,
    insert,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DatabaseError, OperationalError
from sqlalchemy.pool import NullPool

from mulder.graph import _define_graph_tables
from mulder.models import (
    AtomicClaim,
    AtomicClaimInput,
    CaseMetadataRow,
    ClaimVerification,
    CoverageKey,
    CoverageRecord,
    EvidenceAnchor,
    Finding,
    FindingRevision,
    SourceRow,
    ToolOutcome,
    ToolOutcomeStatus,
    WindowRow,
)
from mulder.reasoning import _define_reasoning_tables

if TYPE_CHECKING:
    from mulder.graph import EdgeProvenance, GraphBuildResult, GraphSnapshot
    from mulder.graph_query import GraphQueryRequest, GraphQueryResult
    from mulder.reasoning import (
        ReasoningCommand,
        ReasoningReviewProjection,
        ReasoningWriteResult,
    )

_T = TypeVar("_T")

logger = logging.getLogger(__name__)

metadata = MetaData()

case_metadata_t = Table(
    "case_metadata",
    metadata,
    Column("case_id", Text, primary_key=True),
    Column("ingested_at", Text, nullable=False),
    Column("evidence_root", Text, nullable=False),
    Column("extractor_versions", Text, nullable=False),
    Column("narrative", Text, nullable=True),
)

sources_t = Table(
    "sources",
    metadata,
    Column("source_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False),
    Column("source_name", Text, nullable=False, index=True),
    Column("source_path", Text, nullable=False),
    Column("source_hash", Text, nullable=False),
    Column("extractor", Text, nullable=False),
    Column("line_count", Integer, nullable=False),
    Column("ingested_at", Text, nullable=False),
    Column("windows_hash", Text, nullable=True),
)

windows_t = Table(
    "windows",
    metadata,
    Column("window_id", Integer, primary_key=True, autoincrement=True),
    Column("source_id", Integer, ForeignKey("sources.source_id"), nullable=False, index=True),
    Column("line_start", Integer, nullable=False),
    Column("line_end", Integer, nullable=False),
    Column("event_time", Text, index=True),
    Column("raw_text", Text, nullable=False),
)

findings_t = Table(
    "findings",
    metadata,
    Column("finding_id", Text, primary_key=True),
    Column("case_id", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("description", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("confidence", Text, nullable=False),
    Column("evidence_refs", Text, nullable=False),
    Column("sources", Text, nullable=False),
    Column("mitre_attack_ids", Text),
    Column("event_time_start", Text),
    Column("event_time_end", Text),
    Column("negative_verdict", Text),
    Column("is_deleted", Integer, nullable=False, default=0, server_default="0"),
    Column("submitted_at", Text, nullable=False),
)

finding_revisions_t = Table(
    "finding_revisions",
    metadata,
    Column("revision_id", Text, primary_key=True),
    Column("finding_id", Text, ForeignKey("findings.finding_id"), nullable=False, index=True),
    Column("revision_number", Integer, nullable=False),
    Column("parent_revision_id", Text, nullable=True),
    Column("state", Text, nullable=False),
    Column("snapshot", Text, nullable=False),
    Column("actor_kind", Text, nullable=False),
    Column("actor_id", Text, nullable=True),
    Column("reason_code", Text, nullable=False),
    Column("changed_fields", Text, nullable=False),
    Column("evidence_added", Text, nullable=False),
    Column("evidence_removed", Text, nullable=False),
    Column("tombstone", Integer, nullable=False),
    Column("created_at", Text, nullable=False),
    UniqueConstraint("finding_id", "revision_number", name="uq_finding_revision_number"),
)

coverage_register_t = Table(
    "coverage_register",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False),
    Column("system_name", Text, nullable=False),
    Column("evidence_domain", Text, nullable=False),
    Column("check_name", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("coverage", Text, nullable=False),
    Column("reason", Text),
    Column("source_name", Text),
    Column("tool_call_id", Text),
    Column("recorded_at", Text, nullable=False),
    UniqueConstraint(
        "case_id",
        "system_name",
        "evidence_domain",
        "check_name",
        name="uq_coverage_register_key",
    ),
)

claims_t = Table(
    "claims",
    metadata,
    Column("claim_id", Text, primary_key=True),
    Column(
        "finding_id",
        Text,
        ForeignKey("findings.finding_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    ),
    Column("ordinal", Integer, nullable=False),
    Column("statement", Text, nullable=False),
    Column("subject", Text, nullable=False),
    Column("predicate", Text, nullable=False),
    Column("object_value", Text, nullable=False),
    Column("qualifiers", Text, nullable=False),
    Column("epistemic_state", Text, nullable=False),
)

evidence_anchors_t = Table(
    "evidence_anchors",
    metadata,
    Column("anchor_id", Text, primary_key=True),
    Column(
        "claim_id",
        Text,
        ForeignKey("claims.claim_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    ),
    Column("tool_call_id", Text, nullable=False, index=True),
    Column("source_id", Integer, ForeignKey("sources.source_id"), nullable=False, index=True),
    Column("source_name", Text, nullable=False),
    Column("source_hash", Text, nullable=False),
    Column("window_id", Integer, ForeignKey("windows.window_id"), nullable=False, index=True),
    Column("line_start", Integer, nullable=False),
    Column("line_end", Integer, nullable=False),
    Column("char_start", Integer, nullable=False),
    Column("char_end", Integer, nullable=False),
    Column("exact_text", Text, nullable=False),
    Column("artifact_family", Text, nullable=False),
    Column("extractor_family", Text, nullable=False),
    Column("independence_key", Text, nullable=False, index=True),
    Column("value_type", Text, nullable=False),
    Column("normalized_value", Text, nullable=False),
    Column("role", Text, nullable=False),
)

claim_verifications_t = Table(
    "claim_verifications",
    metadata,
    Column("verification_id", Text, primary_key=True),
    Column(
        "claim_id",
        Text,
        ForeignKey("claims.claim_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    ),
    Column("verifier_name", Text, nullable=False),
    Column("verifier_version", Text, nullable=False),
    Column("result", Text, nullable=False),
    Column("reason_code", Text, nullable=False),
    Column("details", Text, nullable=False),
    Column("verified_at", Text, nullable=False),
)

_graph_tables = _define_graph_tables(metadata)
graph_projections_t = _graph_tables.projections
graph_entities_t = _graph_tables.entities
graph_aliases_t = _graph_tables.aliases
graph_relations_t = _graph_tables.relations
graph_events_t = _graph_tables.events
graph_edge_anchors_t = _graph_tables.edge_anchors

_reasoning_tables = _define_reasoning_tables(metadata)
hypotheses_t = _reasoning_tables.hypotheses
hypothesis_discriminators_t = _reasoning_tables.discriminators
hypothesis_test_results_t = _reasoning_tables.test_results
hypothesis_contradictions_t = _reasoning_tables.contradictions
contradiction_resolutions_t = _reasoning_tables.contradiction_resolutions
review_verdicts_t = _reasoning_tables.review_verdicts

evidence_registry_t = Table(
    "evidence_registry",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("file_path", Text, nullable=False),
    Column("sha256", Text, nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("registered_at", Text, nullable=False),
)

bookmarks_t = Table(
    "bookmarks",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("window_id", Integer, ForeignKey("windows.window_id"), nullable=False),
    Column("source_name", Text, nullable=False),
    Column("note", Text, nullable=False),
    Column("created_at", Text, nullable=False),
)

progress_t = Table(
    "progress",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("system_name", Text, nullable=False),
    Column("tools_completed", Text, nullable=False),
    Column("questions_addressed", Text, nullable=False),
    Column("notes", Text),
    Column("recorded_at", Text, nullable=False),
)

kv_store_t = Table(
    "kv_store",
    metadata,
    Column("key", Text, primary_key=True),
    Column("value", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)

_FTS_CREATE = (
    "CREATE VIRTUAL TABLE IF NOT EXISTS windows_fts USING fts5("
    "    raw_text, content=windows, content_rowid=window_id"
    ")"
)

_IX_WINDOWS_SOURCE_LINE = (
    "CREATE INDEX IF NOT EXISTS ix_windows_source_line ON windows (source_id, line_start)"
)

_FTS5_OPERATORS = frozenset({"AND", "OR", "NOT", "NEAR"})
_FTS5_SPECIAL = re.compile(r'["./$:^{}()*+\-~]')
_FTS5_TOKEN_RE = re.compile(r'"[^"]*"|\S+')


def _sanitize_fts5_query(query: str) -> str:
    """Quote tokens that contain FTS5 special characters.

    Preserves FTS5 boolean operators (AND, OR, NOT, NEAR) and
    already-quoted phrases.  Converts pipe characters to OR operators
    (common mistake by LLMs using regex-style syntax).  All other
    tokens containing special characters are wrapped in double quotes
    so FTS5 treats them as literals.
    """
    # Convert pipe-separated queries to FTS5 OR syntax before tokenizing.
    # e.g., "subject_srv|powershell|cmd" -> "subject_srv OR powershell OR cmd"
    if "|" in query:
        segments = query.replace("\\|", "|").split("|")
        query = " OR ".join(part.strip() for part in segments if part.strip())

    parts = _FTS5_TOKEN_RE.findall(query)
    tokens: list[str] = []
    for token in parts:
        if token in _FTS5_OPERATORS or token.startswith('"') and token.endswith('"'):
            tokens.append(token)
        elif _FTS5_SPECIAL.search(token):
            safe = token.replace('"', '""')
            tokens.append(f'"{safe}"')
        else:
            tokens.append(token)
    return " ".join(tokens)


def _make_engine(db_path: Path) -> Engine:
    """Create a SQLAlchemy engine with WAL mode and foreign keys enabled.

    Uses ``NullPool`` so each ``engine.begin()`` / ``engine.connect()`` gets
    a fresh SQLite connection.  A ``connect`` event listener sets PRAGMAs on
    every new connection (NullPool discards connections after use, so the
    initial connection's PRAGMAs would not persist to later calls).

    ``busy_timeout=30000`` (30 s) tells SQLite to wait up to 30 seconds for
    the write lock instead of immediately returning SQLITE_BUSY when another
    thread holds it.  This is critical for ``run_parallel`` concurrency.
    """
    engine = create_engine(f"sqlite:///{db_path}", echo=False, poolclass=NullPool)

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn: Any, connection_record: Any) -> None:
        """Set WAL mode, foreign keys, and busy timeout on each new connection."""
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    return engine


def _migrate_add_mitre_attack_ids(conn: Connection) -> None:
    """Add the mitre_attack_ids column if it doesn't exist yet."""
    try:
        conn.execute(text("ALTER TABLE findings ADD COLUMN mitre_attack_ids TEXT"))
    except Exception as exc:
        if "duplicate column" in str(exc).lower() or "already exists" in str(exc).lower():
            pass
        else:
            raise


def _migrate_add_narrative(conn: Connection) -> None:
    """Add the narrative column to case_metadata if it doesn't exist yet."""
    try:
        conn.execute(text("ALTER TABLE case_metadata ADD COLUMN narrative TEXT"))
    except Exception as exc:
        if "duplicate column" in str(exc).lower() or "already exists" in str(exc).lower():
            pass
        else:
            raise


def _migrate_add_evidence_registry(conn: Connection) -> None:
    """Create the evidence_registry table if it doesn't exist yet."""
    conn.execute(
        text(
            "CREATE TABLE IF NOT EXISTS evidence_registry ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  file_path TEXT NOT NULL,"
            "  sha256 TEXT NOT NULL,"
            "  size_bytes INTEGER NOT NULL,"
            "  registered_at TEXT NOT NULL"
            ")"
        )
    )


def _migrate_add_windows_hash(conn: Connection) -> None:
    """Add the windows_hash column to sources if it doesn't exist."""
    try:
        conn.execute(text("ALTER TABLE sources ADD COLUMN windows_hash TEXT"))
    except Exception as exc:
        if "duplicate column" not in str(exc).lower():
            raise


def _migrate_add_bookmarks(conn: Connection) -> None:
    """Create the bookmarks table if it doesn't exist yet."""
    conn.execute(
        text(
            "CREATE TABLE IF NOT EXISTS bookmarks ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  window_id INTEGER NOT NULL,"
            "  source_name TEXT NOT NULL,"
            "  note TEXT NOT NULL,"
            "  created_at TEXT NOT NULL,"
            "  FOREIGN KEY (window_id) REFERENCES windows(window_id)"
            ")"
        )
    )


def _migrate_add_progress(conn: Connection) -> None:
    """Create the progress table if it doesn't exist yet."""
    conn.execute(
        text(
            "CREATE TABLE IF NOT EXISTS progress ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  system_name TEXT NOT NULL,"
            "  tools_completed TEXT NOT NULL,"
            "  questions_addressed TEXT NOT NULL,"
            "  notes TEXT,"
            "  recorded_at TEXT NOT NULL"
            ")"
        )
    )


def _migrate_add_kv_store(conn: Connection) -> None:
    """Create the kv_store table if it doesn't exist yet."""
    conn.execute(
        text(
            "CREATE TABLE IF NOT EXISTS kv_store ("
            "  key TEXT PRIMARY KEY,"
            "  value TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL"
            ")"
        )
    )


def _migrate_add_claim_tables(conn: Connection) -> None:
    """Create additive atomic-claim tables for databases from older releases."""
    claims_t.create(conn, checkfirst=True)
    evidence_anchors_t.create(conn, checkfirst=True)
    claim_verifications_t.create(conn, checkfirst=True)


def _migrate_add_entity_graph(conn: Connection) -> None:
    """Create the additive verified-claim graph projection tables."""
    graph_projections_t.create(conn, checkfirst=True)
    graph_entities_t.create(conn, checkfirst=True)
    graph_aliases_t.create(conn, checkfirst=True)
    graph_relations_t.create(conn, checkfirst=True)
    graph_events_t.create(conn, checkfirst=True)
    graph_edge_anchors_t.create(conn, checkfirst=True)


def _migrate_add_reasoning_review(conn: Connection) -> None:
    """Create additive competing-hypothesis and reviewer tables."""
    hypotheses_t.create(conn, checkfirst=True)
    hypothesis_discriminators_t.create(conn, checkfirst=True)
    hypothesis_test_results_t.create(conn, checkfirst=True)
    hypothesis_contradictions_t.create(conn, checkfirst=True)
    contradiction_resolutions_t.create(conn, checkfirst=True)
    review_verdicts_t.create(conn, checkfirst=True)


def _migrate_add_coverage_register(conn: Connection) -> None:
    """Create the additive coverage register for databases from older releases."""
    coverage_register_t.create(conn, checkfirst=True)


def _migrate_add_negative_verdict(conn: Connection) -> None:
    """Add scoped negative verdict storage to databases from older releases."""
    try:
        conn.execute(text("ALTER TABLE findings ADD COLUMN negative_verdict TEXT"))
    except Exception as exc:
        if "duplicate column" not in str(exc).lower():
            raise


def _migrate_add_finding_revisions(conn: Connection) -> None:
    """Add tombstone state and backfill immutable history for legacy findings."""
    try:
        conn.execute(text("ALTER TABLE findings ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0"))
    except Exception as exc:
        if "duplicate column" not in str(exc).lower():
            raise
    finding_revisions_t.create(conn, checkfirst=True)
    legacy_rows = conn.execute(
        select(findings_t).where(
            ~findings_t.c.finding_id.in_(select(finding_revisions_t.c.finding_id))
        )
    ).fetchall()
    for row in legacy_rows:
        finding = _finding_from_row(row)
        _append_finding_revision(
            conn,
            finding,
            state=_state_for_finding(finding),
            actor_kind="system",
            actor_id=None,
            reason_code="legacy_import",
            changed_fields=list(type(finding).model_fields),
            previous=None,
        )


def _finding_from_row(row: Any) -> Finding:
    """Build the current finding read model from one SQLAlchemy row."""
    return Finding(
        finding_id=row.finding_id,
        case_id=row.case_id,
        title=row.title,
        description=row.description,
        severity=row.severity,
        confidence=row.confidence,
        evidence_refs=json.loads(row.evidence_refs),
        sources=json.loads(row.sources),
        mitre_attack_ids=json.loads(row.mitre_attack_ids) if row.mitre_attack_ids else [],
        event_time_start=row.event_time_start,
        event_time_end=row.event_time_end,
        negative_verdict=(
            json.loads(row.negative_verdict) if getattr(row, "negative_verdict", None) else None
        ),
        submitted_at=row.submitted_at,
    )


def _state_for_finding(finding: Finding) -> str:
    """Map the compatibility confidence field to revision lifecycle state."""
    return "confirmed" if finding.confidence == "confirmed" else "indicated"


def _append_finding_revision(
    conn: Connection,
    finding: Finding,
    *,
    state: str,
    actor_kind: str,
    actor_id: str | None,
    reason_code: str,
    changed_fields: list[str],
    previous: Finding | None,
    tombstone: bool = False,
) -> FindingRevision:
    """Append one immutable snapshot inside the caller's transaction."""
    latest = conn.execute(
        select(
            finding_revisions_t.c.revision_id,
            finding_revisions_t.c.revision_number,
        )
        .where(finding_revisions_t.c.finding_id == finding.finding_id)
        .order_by(finding_revisions_t.c.revision_number.desc())
        .limit(1)
    ).fetchone()
    revision_number = int(latest.revision_number) + 1 if latest is not None else 1
    previous_refs = set(previous.evidence_refs) if previous is not None else set()
    current_refs = set(finding.evidence_refs)
    revision = FindingRevision(
        revision_id=f"fr_{uuid4().hex[:12]}",
        finding_id=finding.finding_id,
        revision_number=revision_number,
        parent_revision_id=str(latest.revision_id) if latest is not None else None,
        state=cast(Any, state),
        snapshot=finding,
        actor_kind=cast(Any, actor_kind),
        actor_id=actor_id,
        reason_code=reason_code,
        changed_fields=sorted(changed_fields),
        evidence_added=sorted(current_refs - previous_refs),
        evidence_removed=sorted(previous_refs - current_refs),
        tombstone=tombstone,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    conn.execute(
        insert(finding_revisions_t).values(
            revision_id=revision.revision_id,
            finding_id=revision.finding_id,
            revision_number=revision.revision_number,
            parent_revision_id=revision.parent_revision_id,
            state=revision.state,
            snapshot=revision.snapshot.model_dump_json(),
            actor_kind=revision.actor_kind,
            actor_id=revision.actor_id,
            reason_code=revision.reason_code,
            changed_fields=json.dumps(revision.changed_fields),
            evidence_added=json.dumps(revision.evidence_added),
            evidence_removed=json.dumps(revision.evidence_removed),
            tombstone=int(revision.tombstone),
            created_at=revision.created_at,
        )
    )
    return revision


_SENTINEL = object()


@dataclass
class _QueueResult:
    """Holds the return value or exception from a queued writer operation."""

    value: object = None
    error: BaseException | None = None


class ProgressRecord(TypedDict):
    """Typed representation of a single progress table row."""

    id: int
    system_name: str
    tools_completed: list[str]
    questions_addressed: list[str]
    notes: str | None
    recorded_at: str


class ProgressSummary(TypedDict):
    """Aggregated progress across all recorded entries."""

    systems_analyzed: list[str]
    questions_covered: list[str]
    tools_used: list[str]
    total_progress_records: int


_QueueItem = tuple[
    Callable[..., object], tuple[object, ...], dict[str, object], _QueueResult, threading.Event
]


class _WriteQueue:
    """Single-writer thread that serialises all DB write operations.

    Worker threads submit callables via ``submit`` and block until the
    writer thread executes them.  This eliminates SQLite ``BUSY`` errors
    entirely; only one thread ever holds the write lock.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[_QueueItem | object] = queue.Queue()
        self._thread = threading.Thread(target=self._writer_loop, name="db-writer", daemon=True)
        self._thread.start()

    def _writer_loop(self) -> None:
        """Drain the queue, executing submitted callables until sentinel."""
        while True:
            item = self._queue.get()
            if item is _SENTINEL:
                self._queue.task_done()
                return
            qi = cast(_QueueItem, item)
            fn, args, kwargs, result_holder, done_event = qi
            try:
                result_holder.value = fn(*args, **kwargs)
            except Exception as exc:
                result_holder.error = exc
            finally:
                done_event.set()
                self._queue.task_done()

    def submit(self, fn: Callable[..., _T], *args: object, **kwargs: object) -> _T:
        """Submit *fn* to the writer thread and block until it completes.

        Returns the result of ``fn(*args, **kwargs)`` or re-raises its
        exception in the calling thread with the original traceback.
        """
        result_holder = _QueueResult()
        done_event = threading.Event()
        self._queue.put((fn, args, kwargs, result_holder, done_event))
        done_event.wait()
        if result_holder.error is not None:
            raise result_holder.error.with_traceback(result_holder.error.__traceback__)
        return cast(_T, result_holder.value)

    def shutdown(self) -> None:
        """Signal the writer thread to exit and wait for it."""
        self._queue.put(_SENTINEL)
        self._thread.join(timeout=10.0)
        if self._thread.is_alive():
            remaining = self._queue.qsize()
            logger.warning(
                "DB writer thread did not finish within timeout; %d queued items may be lost",
                remaining,
            )


class CaseDB:
    """Manages a per-case SQLite database file."""

    def __init__(self, db_path: Path) -> None:
        """Open an existing case database at the given path."""
        self._db_path = db_path
        self._engine = _make_engine(db_path)
        self._wq = _WriteQueue()
        self._case_id_cache: str | None = None

    @classmethod
    def create(
        cls,
        case_id: str,
        evidence_root: str,
        db_dir: Path,
        **_kwargs: object,
    ) -> CaseDB:
        """Create a new case database with metadata."""
        db_dir = Path(db_dir).expanduser()
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = db_dir / f"{case_id}.db"

        db = cls(db_path)
        metadata.create_all(db._engine)

        with db._engine.begin() as conn:
            conn.execute(text(_FTS_CREATE))
            conn.execute(text(_IX_WINDOWS_SOURCE_LINE))
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                insert(case_metadata_t).values(
                    case_id=case_id,
                    ingested_at=now,
                    evidence_root=evidence_root,
                    extractor_versions=json.dumps({}),
                )
            )
        return db

    @classmethod
    def open(cls, case_id: str, db_dir: Path) -> CaseDB:
        """Open an existing case database by case_id."""
        db_dir = Path(db_dir).expanduser()
        db_path = db_dir / f"{case_id}.db"
        if not db_path.exists():
            raise FileNotFoundError(f"Case database not found: {db_path}")
        db = cls(db_path)
        with db._engine.begin() as conn:
            conn.execute(text(_FTS_CREATE))
            conn.execute(text(_IX_WINDOWS_SOURCE_LINE))
            _migrate_add_mitre_attack_ids(conn)
            _migrate_add_narrative(conn)
            _migrate_add_evidence_registry(conn)
            _migrate_add_windows_hash(conn)
            _migrate_add_bookmarks(conn)
            _migrate_add_progress(conn)
            _migrate_add_kv_store(conn)
            _migrate_add_claim_tables(conn)
            _migrate_add_coverage_register(conn)
            _migrate_add_negative_verdict(conn)
            _migrate_add_finding_revisions(conn)
            _migrate_add_entity_graph(conn)
            _migrate_add_reasoning_review(conn)
        return db

    def close(self) -> None:
        """Shut down the write queue and dispose the engine."""
        self._wq.shutdown()
        self._engine.dispose()

    def __enter__(self) -> CaseDB:
        """Return self for use as a context manager."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close the database when exiting the context."""
        self.close()

    def register_source(
        self,
        source_name: str,
        source_path: str,
        source_hash: str,
        extractor: str,
        line_count: int,
    ) -> int:
        """Register a new evidence source; return its source_id."""

        def _do_register() -> int:
            """Insert source row and return its auto-generated ID."""
            now = datetime.now(timezone.utc).isoformat()
            case_id = self._get_case_id()
            with self._engine.begin() as conn:
                result = conn.execute(
                    insert(sources_t).values(
                        case_id=case_id,
                        source_name=source_name,
                        source_path=source_path,
                        source_hash=source_hash,
                        extractor=extractor,
                        line_count=line_count,
                        ingested_at=now,
                    )
                )
                if result.inserted_primary_key is None:
                    raise RuntimeError(
                        "INSERT did not return a primary key for source registration"
                    )
                return int(result.inserted_primary_key[0])

        return int(self._wq.submit(_do_register))

    def insert_windows(self, source_id: int, windows: list[WindowRow]) -> None:
        """Bulk-insert window rows and populate the FTS index."""
        if not windows:
            return
        rows = [
            {
                "source_id": source_id,
                "line_start": w.line_start,
                "line_end": w.line_end,
                "event_time": w.event_time,
                "raw_text": w.raw_text,
            }
            for w in windows
        ]

        def _do_insert() -> None:
            """Bulk-insert window rows, sync the FTS index, and update windows_hash."""
            with self._engine.begin() as conn:
                last_id_row = conn.execute(
                    text("SELECT COALESCE(MAX(window_id), 0) FROM windows WHERE source_id = :sid"),
                    {"sid": source_id},
                ).fetchone()
                last_id = last_id_row[0] if last_id_row else 0
                conn.execute(insert(windows_t), rows)
                conn.execute(
                    text(
                        "INSERT INTO windows_fts(rowid, raw_text) "
                        "SELECT window_id, raw_text FROM windows "
                        "WHERE source_id = :sid AND window_id > :last_id"
                    ),
                    {"sid": source_id, "last_id": last_id},
                )

                h = hashlib.blake2b(digest_size=32)
                if last_id > 0:
                    prior = conn.execute(
                        text(
                            "SELECT raw_text FROM windows "
                            "WHERE source_id = :sid AND window_id <= :last_id "
                            "ORDER BY window_id"
                        ),
                        {"sid": source_id, "last_id": last_id},
                    )
                    for prior_row in prior:
                        h.update(prior_row[0].encode())
                for w in windows:
                    h.update(w.raw_text.encode())
                conn.execute(
                    text("UPDATE sources SET windows_hash = :wh WHERE source_id = :sid"),
                    {"wh": "blake2b:" + h.hexdigest(), "sid": source_id},
                )

        self._wq.submit(_do_insert)

    def search_windows(
        self,
        query: str,
        source_name: str | None = None,
        max_results: int = 100,
        time_start: str | None = None,
        time_end: str | None = None,
        exclude_source_names: list[str] | None = None,
    ) -> list[tuple[WindowRow, str]]:
        """Full-text keyword search over raw_text using FTS5.

        Supports terms (``spinlock.exe``), phrases (``"brute force"``),
        and boolean (``4624 AND logon``).

        Args:
            query: FTS5 query string.
            source_name: Optional source name or prefix to scope search.
            max_results: Maximum number of results to return.
            time_start: Optional ISO 8601 lower bound for event_time.
            time_end: Optional ISO 8601 upper bound for event_time.
            exclude_source_names: Optional source name prefixes to exclude.
        """
        j = windows_t.join(sources_t, windows_t.c.source_id == sources_t.c.source_id)
        stmt = (
            select(windows_t, sources_t.c.source_name)
            .select_from(j)
            .where(
                windows_t.c.window_id.in_(
                    select(text("rowid"))
                    .select_from(text("windows_fts"))
                    .where(text("windows_fts MATCH :q"))
                )
            )
        )

        if source_name is not None:
            stmt = stmt.where(
                or_(
                    sources_t.c.source_name == source_name,
                    sources_t.c.source_name.like(source_name + ".%"),
                )
            )

        if time_start is not None:
            stmt = stmt.where(windows_t.c.event_time >= time_start)
        if time_end is not None:
            stmt = stmt.where(windows_t.c.event_time <= time_end)

        if exclude_source_names:
            for prefix in exclude_source_names:
                stmt = stmt.where(
                    ~or_(
                        sources_t.c.source_name == prefix,
                        sources_t.c.source_name.like(prefix + ".%"),
                    )
                )

        stmt = stmt.order_by(
            windows_t.c.event_time.asc().nullslast(),
        ).limit(max_results)

        safe_query = _sanitize_fts5_query(query)

        with self._engine.connect() as conn:
            try:
                rows = conn.execute(stmt, {"q": safe_query}).fetchall()
            except (OperationalError, DatabaseError):
                logger.warning(
                    "FTS5 MATCH failed for query %r, returning empty",
                    query,
                    exc_info=True,
                )
                rows = []

        return [
            (
                WindowRow(
                    window_id=row.window_id,
                    source_id=row.source_id,
                    line_start=row.line_start,
                    line_end=row.line_end,
                    event_time=row.event_time,
                    raw_text=row.raw_text,
                ),
                row.source_name,
            )
            for row in rows
        ]

    def count_search_windows(
        self,
        query: str,
        source_name: str | None = None,
        time_start: str | None = None,
        time_end: str | None = None,
        exclude_source_names: list[str] | None = None,
    ) -> int:
        """Return the total number of FTS5 matches without fetching rows.

        Uses the same filtering logic as ``search_windows`` but runs
        ``SELECT COUNT(*)`` instead of materializing results, making it
        efficient for pagination metadata.

        Args:
            query: FTS5 query string.
            source_name: Optional source name or prefix to scope search.
            time_start: Optional ISO 8601 lower bound for event_time.
            time_end: Optional ISO 8601 upper bound for event_time.
            exclude_source_names: Optional source name prefixes to exclude.
        """
        j = windows_t.join(sources_t, windows_t.c.source_id == sources_t.c.source_id)
        stmt = (
            select(func.count())
            .select_from(j)
            .where(
                windows_t.c.window_id.in_(
                    select(text("rowid"))
                    .select_from(text("windows_fts"))
                    .where(text("windows_fts MATCH :q"))
                )
            )
        )

        if source_name is not None:
            stmt = stmt.where(
                or_(
                    sources_t.c.source_name == source_name,
                    sources_t.c.source_name.like(source_name + ".%"),
                )
            )

        if time_start is not None:
            stmt = stmt.where(windows_t.c.event_time >= time_start)
        if time_end is not None:
            stmt = stmt.where(windows_t.c.event_time <= time_end)

        if exclude_source_names:
            for prefix in exclude_source_names:
                stmt = stmt.where(
                    ~or_(
                        sources_t.c.source_name == prefix,
                        sources_t.c.source_name.like(prefix + ".%"),
                    )
                )

        safe_query = _sanitize_fts5_query(query)

        with self._engine.connect() as conn:
            try:
                result = conn.execute(stmt, {"q": safe_query}).scalar()
            except (OperationalError, DatabaseError):
                logger.warning(
                    "FTS5 COUNT failed for query %r, returning 0",
                    query,
                    exc_info=True,
                )
                return 0

        return result or 0

    def get_windows_by_source(
        self,
        source_name: str,
        time_start: str | None = None,
        time_end: str | None = None,
    ) -> list[WindowRow]:
        """Fetch windows for a source name, optionally filtered by time range."""
        j = windows_t.join(sources_t, windows_t.c.source_id == sources_t.c.source_id)
        stmt = select(windows_t).select_from(j).where(sources_t.c.source_name == source_name)

        if time_start is not None:
            stmt = stmt.where(windows_t.c.event_time >= time_start)
        if time_end is not None:
            stmt = stmt.where(windows_t.c.event_time <= time_end)

        stmt = stmt.order_by(windows_t.c.line_start)

        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()

        return [
            WindowRow(
                window_id=row.window_id,
                source_id=row.source_id,
                line_start=row.line_start,
                line_end=row.line_end,
                event_time=row.event_time,
                raw_text=row.raw_text,
            )
            for row in rows
        ]

    def get_capped_windows_by_sources(
        self,
        source_names: list[str],
        max_per_source: int = 50,
    ) -> dict[str, tuple[list[WindowRow], int]]:
        """Fetch capped windows for multiple sources in a single query.

        Uses a SQL window function to limit rows per source, avoiding the
        N+1 query pattern where each source requires a separate round-trip.

        Args:
            source_names: Source names to retrieve windows for.
            max_per_source: Maximum windows to return per source.

        Returns:
            Dict mapping each source_name to a tuple of
            (capped window list, total window count for that source).
        """
        if not source_names:
            return {}

        placeholders = ", ".join(f":sn{i}" for i in range(len(source_names)))
        params: dict[str, object] = {f"sn{i}": name for i, name in enumerate(source_names)}
        params["cap"] = max_per_source

        # ROW_NUMBER partitions by source to cap per-source rows;
        # COUNT gives the untruncated total for each source.
        query = text(
            "WITH ranked AS ("
            "  SELECT w.*, s.source_name,"
            "    ROW_NUMBER() OVER (PARTITION BY s.source_id ORDER BY w.window_id) AS rn,"
            "    COUNT(*) OVER (PARTITION BY s.source_id) AS total_count"
            "  FROM windows w"
            "  JOIN sources s ON w.source_id = s.source_id"
            f"  WHERE s.source_name IN ({placeholders})"
            ") SELECT * FROM ranked WHERE rn <= :cap"
            " ORDER BY source_name, window_id"
        )

        result: dict[str, tuple[list[WindowRow], int]] = {}
        with self._engine.connect() as conn:
            rows = conn.execute(query, params).fetchall()

        for row in rows:
            sname: str = row.source_name
            total: int = row.total_count
            w = WindowRow(
                window_id=row.window_id,
                source_id=row.source_id,
                line_start=row.line_start,
                line_end=row.line_end,
                event_time=row.event_time,
                raw_text=row.raw_text,
            )
            if sname not in result:
                result[sname] = ([], total)
            result[sname][0].append(w)

        # Include sources that had zero windows
        for name in source_names:
            if name not in result:
                result[name] = ([], 0)

        return result

    def get_windows_by_source_prefix(
        self,
        source_prefix: str,
        time_start: str | None = None,
        time_end: str | None = None,
    ) -> list[WindowRow]:
        """Fetch windows from all sources whose name starts with *source_prefix*."""
        j = windows_t.join(sources_t, windows_t.c.source_id == sources_t.c.source_id)
        stmt = (
            select(windows_t)
            .select_from(j)
            .where(
                or_(
                    sources_t.c.source_name == source_prefix,
                    sources_t.c.source_name.like(source_prefix + ".%"),
                )
            )
        )

        if time_start is not None:
            stmt = stmt.where(windows_t.c.event_time >= time_start)
        if time_end is not None:
            stmt = stmt.where(windows_t.c.event_time <= time_end)

        stmt = stmt.order_by(windows_t.c.line_start)

        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()

        return [
            WindowRow(
                window_id=row.window_id,
                source_id=row.source_id,
                line_start=row.line_start,
                line_end=row.line_end,
                event_time=row.event_time,
                raw_text=row.raw_text,
            )
            for row in rows
        ]

    def get_windows_page(
        self,
        source_prefix: str,
        after_id: int = 0,
        limit: int = 500,
    ) -> tuple[list[WindowRow], int]:
        """Fetch a page of windows using keyset pagination.

        Uses ``window_id > after_id`` instead of SQL OFFSET, so seeking
        to any position is O(log n) via the primary key index regardless
        of how deep into the source you are.

        Pass ``after_id=0`` for the first page, then pass the last
        ``window_id`` from the previous page to get the next one.

        Returns ``(windows, total_count)``.
        """
        source_where = or_(
            sources_t.c.source_name == source_prefix,
            sources_t.c.source_name.like(source_prefix + ".%"),
        )

        count_stmt = (
            select(func.count())
            .select_from(windows_t.join(sources_t, windows_t.c.source_id == sources_t.c.source_id))
            .where(source_where)
        )

        j = windows_t.join(sources_t, windows_t.c.source_id == sources_t.c.source_id)
        page_stmt = (
            select(windows_t)
            .select_from(j)
            .where(source_where)
            .where(windows_t.c.window_id > after_id)
            .order_by(windows_t.c.window_id)
            .limit(limit)
        )

        with self._engine.connect() as conn:
            total = conn.execute(count_stmt).scalar() or 0
            rows = conn.execute(page_stmt).fetchall()

        windows = [
            WindowRow(
                window_id=row.window_id,
                source_id=row.source_id,
                line_start=row.line_start,
                line_end=row.line_end,
                event_time=row.event_time,
                raw_text=row.raw_text,
            )
            for row in rows
        ]
        return windows, total

    def get_sources(self) -> list[SourceRow]:
        """Return all registered sources ordered by source_id."""
        stmt = select(sources_t).order_by(sources_t.c.source_id)
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [
            SourceRow(
                source_id=row.source_id,
                case_id=row.case_id,
                source_name=row.source_name,
                source_path=row.source_path,
                source_hash=row.source_hash,
                extractor=row.extractor,
                line_count=row.line_count,
                windows_hash=getattr(row, "windows_hash", None),
            )
            for row in rows
        ]

    def get_source_count(self) -> int:
        """Return the number of registered sources."""
        stmt = select(func.count()).select_from(sources_t)
        with self._engine.connect() as conn:
            result = conn.execute(stmt).scalar()
        return result or 0

    def get_case_metadata(self) -> CaseMetadataRow:
        """Return the case metadata row."""
        stmt = select(case_metadata_t).limit(1)
        with self._engine.connect() as conn:
            row = conn.execute(stmt).fetchone()

        if row is None:
            raise RuntimeError("No case metadata found in database")

        narrative = getattr(row, "narrative", None)
        return CaseMetadataRow(
            case_id=row.case_id,
            ingested_at=row.ingested_at,
            evidence_root=row.evidence_root,
            extractor_versions=json.loads(row.extractor_versions),
            narrative=narrative,
        )

    def set_narrative(self, narrative: str) -> None:
        """Store or replace the investigation narrative in case metadata."""
        case_id = self._get_case_id()

        def _do_update() -> None:
            with self._engine.begin() as conn:
                conn.execute(
                    update(case_metadata_t)
                    .where(case_metadata_t.c.case_id == case_id)
                    .values(narrative=narrative)
                )

        self._wq.submit(_do_update)

    def insert_finding(
        self,
        finding: Finding,
        claims: list[AtomicClaimInput] | None = None,
    ) -> list[AtomicClaim]:
        """Persist a finding and optional atomic claims in one transaction.

        Exact evidence text and provenance are resolved from the case database;
        callers cannot inject source hashes or independence keys.  If an anchor
        is stale, out of bounds, or does not match its expected text, the whole
        write is rejected and no finding row is committed.
        """

        def _do_insert() -> list[AtomicClaim]:
            """Persist a finding and its claim graph atomically."""
            with self._engine.begin() as conn:
                conn.execute(
                    insert(findings_t).values(
                        finding_id=finding.finding_id,
                        case_id=finding.case_id,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity,
                        confidence=finding.confidence,
                        evidence_refs=json.dumps(finding.evidence_refs),
                        sources=json.dumps(finding.sources),
                        mitre_attack_ids=json.dumps(finding.mitre_attack_ids),
                        event_time_start=finding.event_time_start,
                        event_time_end=finding.event_time_end,
                        negative_verdict=(
                            finding.negative_verdict.model_dump_json()
                            if finding.negative_verdict is not None
                            else None
                        ),
                        is_deleted=0,
                        submitted_at=finding.submitted_at,
                    )
                )

                stored: list[AtomicClaim] = []
                resolved_source_names: set[str] = set()
                for ordinal, claim_input in enumerate(claims or []):
                    claim_id = f"c_{uuid4().hex[:12]}"
                    claim = AtomicClaim(
                        claim_id=claim_id,
                        finding_id=finding.finding_id,
                        ordinal=ordinal,
                        statement=claim_input.statement,
                        subject=claim_input.subject,
                        predicate=claim_input.predicate,
                        object_value=claim_input.object_value,
                        qualifiers=claim_input.qualifiers,
                        epistemic_state="unverified",
                        anchors=[],
                    )
                    conn.execute(
                        insert(claims_t).values(
                            claim_id=claim.claim_id,
                            finding_id=claim.finding_id,
                            ordinal=claim.ordinal,
                            statement=claim.statement,
                            subject=claim.subject,
                            predicate=claim.predicate,
                            object_value=json.dumps(claim.object_value),
                            qualifiers=json.dumps(claim.qualifiers),
                            epistemic_state=claim.epistemic_state,
                        )
                    )

                    resolved_anchors: list[EvidenceAnchor] = []
                    for anchor_input in claim_input.anchors:
                        row = conn.execute(
                            select(
                                windows_t.c.window_id,
                                windows_t.c.source_id,
                                windows_t.c.line_start,
                                windows_t.c.line_end,
                                windows_t.c.raw_text,
                                sources_t.c.source_name,
                                sources_t.c.source_hash,
                                sources_t.c.extractor,
                            )
                            .select_from(
                                windows_t.join(
                                    sources_t,
                                    windows_t.c.source_id == sources_t.c.source_id,
                                )
                            )
                            .where(windows_t.c.window_id == anchor_input.window_id)
                        ).fetchone()
                        if row is None:
                            raise ValueError(
                                "Evidence anchor window_id "
                                f"{anchor_input.window_id} does not exist"
                            )
                        raw_text = str(row.raw_text)
                        if anchor_input.char_end > len(raw_text):
                            raise ValueError(
                                "Evidence anchor character range is outside window "
                                f"{anchor_input.window_id} (length {len(raw_text)})"
                            )
                        exact_text = raw_text[anchor_input.char_start : anchor_input.char_end]
                        if exact_text != anchor_input.expected_text:
                            raise ValueError(
                                "Evidence anchor text does not match the immutable window at "
                                f"{anchor_input.window_id}:{anchor_input.char_start}-"
                                f"{anchor_input.char_end}"
                            )

                        extractor = str(row.extractor)
                        source_hash = str(row.source_hash)
                        anchor = EvidenceAnchor(
                            anchor_id=f"a_{uuid4().hex[:12]}",
                            claim_id=claim_id,
                            tool_call_id=anchor_input.tool_call_id,
                            source_id=int(row.source_id),
                            source_name=str(row.source_name),
                            source_hash=source_hash,
                            window_id=int(row.window_id),
                            line_start=int(row.line_start),
                            line_end=int(row.line_end),
                            char_start=anchor_input.char_start,
                            char_end=anchor_input.char_end,
                            exact_text=exact_text,
                            artifact_family=anchor_input.artifact_family or extractor,
                            extractor_family=extractor,
                            independence_key=f"source:{source_hash}",
                            value_type=anchor_input.value_type,
                            normalized_value=anchor_input.normalized_value,
                            role=anchor_input.role,
                        )
                        resolved_source_names.add(anchor.source_name)
                        conn.execute(
                            insert(evidence_anchors_t).values(
                                anchor_id=anchor.anchor_id,
                                claim_id=anchor.claim_id,
                                tool_call_id=anchor.tool_call_id,
                                source_id=anchor.source_id,
                                source_name=anchor.source_name,
                                source_hash=anchor.source_hash,
                                window_id=anchor.window_id,
                                line_start=anchor.line_start,
                                line_end=anchor.line_end,
                                char_start=anchor.char_start,
                                char_end=anchor.char_end,
                                exact_text=anchor.exact_text,
                                artifact_family=anchor.artifact_family,
                                extractor_family=anchor.extractor_family,
                                independence_key=anchor.independence_key,
                                value_type=anchor.value_type,
                                normalized_value=json.dumps(anchor.normalized_value),
                                role=anchor.role,
                            )
                        )
                        resolved_anchors.append(anchor)
                    stored.append(claim.model_copy(update={"anchors": resolved_anchors}))
                if stored:
                    conn.execute(
                        update(findings_t)
                        .where(findings_t.c.finding_id == finding.finding_id)
                        .values(sources=json.dumps(sorted(resolved_source_names)))
                    )
                revision_finding = finding.model_copy(
                    update={
                        "sources": (sorted(resolved_source_names) if stored else finding.sources)
                    }
                )
                _append_finding_revision(
                    conn,
                    revision_finding,
                    state=_state_for_finding(revision_finding),
                    actor_kind="investigator",
                    actor_id=None,
                    reason_code="finding_submitted",
                    changed_fields=list(type(finding).model_fields),
                    previous=None,
                )
                return stored

        return self._wq.submit(_do_insert)

    def get_claims(self, finding_id: str) -> list[AtomicClaim]:
        """Return a finding's atomic claims with exact anchors, in stable order."""
        with self._engine.connect() as conn:
            claim_rows = conn.execute(
                select(claims_t)
                .where(claims_t.c.finding_id == finding_id)
                .order_by(claims_t.c.ordinal, claims_t.c.claim_id)
            ).fetchall()
            anchor_rows = conn.execute(
                select(evidence_anchors_t)
                .select_from(
                    evidence_anchors_t.join(
                        claims_t, evidence_anchors_t.c.claim_id == claims_t.c.claim_id
                    )
                )
                .where(claims_t.c.finding_id == finding_id)
                .order_by(evidence_anchors_t.c.anchor_id)
            ).fetchall()

        by_claim: dict[str, list[EvidenceAnchor]] = defaultdict(list)
        for row in anchor_rows:
            by_claim[row.claim_id].append(
                EvidenceAnchor(
                    anchor_id=row.anchor_id,
                    claim_id=row.claim_id,
                    tool_call_id=row.tool_call_id,
                    source_id=row.source_id,
                    source_name=row.source_name,
                    source_hash=row.source_hash,
                    window_id=row.window_id,
                    line_start=row.line_start,
                    line_end=row.line_end,
                    char_start=row.char_start,
                    char_end=row.char_end,
                    exact_text=row.exact_text,
                    artifact_family=row.artifact_family,
                    extractor_family=row.extractor_family,
                    independence_key=row.independence_key,
                    value_type=row.value_type,
                    normalized_value=json.loads(row.normalized_value),
                    role=row.role,
                )
            )

        return [
            AtomicClaim(
                claim_id=row.claim_id,
                finding_id=row.finding_id,
                ordinal=row.ordinal,
                statement=row.statement,
                subject=row.subject,
                predicate=row.predicate,
                object_value=json.loads(row.object_value),
                qualifiers=json.loads(row.qualifiers),
                epistemic_state=row.epistemic_state,
                anchors=by_claim[row.claim_id],
            )
            for row in claim_rows
        ]

    def verify_finding_claims(self, finding_id: str) -> list[ClaimVerification]:
        """Reopen evidence anchors and deterministically verify all finding claims.

        The current source/window identity and exact character slice are checked
        before semantic verification. Results are append-only; the claim row
        stores only the latest state for efficient gates and presentation.
        """
        from mulder.models import VerificationDecision
        from mulder.verification.claims import (
            VERIFIER_NAME,
            VERIFIER_VERSION,
            verify_claim,
        )

        claims = self.get_claims(finding_id)
        if not claims:
            return []

        def _do_verify() -> list[ClaimVerification]:
            verified_at = datetime.now(timezone.utc).isoformat()
            results: list[ClaimVerification] = []
            with self._engine.begin() as conn:
                for claim in claims:
                    evidence_problem: str | None = None
                    for anchor in claim.anchors:
                        row = conn.execute(
                            select(
                                windows_t.c.source_id,
                                windows_t.c.raw_text,
                                sources_t.c.source_name,
                                sources_t.c.source_hash,
                            )
                            .select_from(
                                windows_t.join(
                                    sources_t,
                                    windows_t.c.source_id == sources_t.c.source_id,
                                )
                            )
                            .where(windows_t.c.window_id == anchor.window_id)
                        ).fetchone()
                        if row is None:
                            evidence_problem = "anchor_window_missing"
                            break
                        if (
                            int(row.source_id) != anchor.source_id
                            or str(row.source_name) != anchor.source_name
                            or str(row.source_hash) != anchor.source_hash
                        ):
                            evidence_problem = "anchor_provenance_changed"
                            break
                        raw_text = str(row.raw_text)
                        if anchor.char_end > len(raw_text):
                            evidence_problem = "anchor_range_invalid"
                            break
                        if raw_text[anchor.char_start : anchor.char_end] != anchor.exact_text:
                            evidence_problem = "anchor_text_changed"
                            break

                    decision = (
                        VerificationDecision(
                            result="inconclusive",
                            reason_code=evidence_problem,
                            details={},
                        )
                        if evidence_problem is not None
                        else verify_claim(claim)
                    )
                    result = ClaimVerification(
                        verification_id=f"v_{uuid4().hex[:12]}",
                        claim_id=claim.claim_id,
                        verifier_name=VERIFIER_NAME,
                        verifier_version=VERIFIER_VERSION,
                        result=decision.result,
                        reason_code=decision.reason_code,
                        details=decision.details,
                        verified_at=verified_at,
                    )
                    conn.execute(
                        insert(claim_verifications_t).values(
                            verification_id=result.verification_id,
                            claim_id=result.claim_id,
                            verifier_name=result.verifier_name,
                            verifier_version=result.verifier_version,
                            result=result.result,
                            reason_code=result.reason_code,
                            details=json.dumps(result.details, sort_keys=True),
                            verified_at=result.verified_at,
                        )
                    )
                    conn.execute(
                        update(claims_t)
                        .where(claims_t.c.claim_id == claim.claim_id)
                        .values(epistemic_state=result.result)
                    )
                    results.append(result)
            return results

        return self._wq.submit(_do_verify)

    def get_claim_verifications(self, finding_id: str) -> list[ClaimVerification]:
        """Return append-only verification history for a finding's claims."""
        stmt = (
            select(claim_verifications_t)
            .select_from(
                claim_verifications_t.join(
                    claims_t, claim_verifications_t.c.claim_id == claims_t.c.claim_id
                )
            )
            .where(claims_t.c.finding_id == finding_id)
            .order_by(claim_verifications_t.c.verified_at, claim_verifications_t.c.verification_id)
        )
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [
            ClaimVerification(
                verification_id=row.verification_id,
                claim_id=row.claim_id,
                verifier_name=row.verifier_name,
                verifier_version=row.verifier_version,
                result=row.result,
                reason_code=row.reason_code,
                details=json.loads(row.details),
                verified_at=row.verified_at,
            )
            for row in rows
        ]

    def rebuild_entity_graph(self) -> GraphBuildResult:
        """Rebuild the versioned graph projection from currently verified claims."""
        from mulder.graph import _rebuild_projection

        case_id = self._get_case_id()

        def _do_rebuild() -> GraphBuildResult:
            with self._engine.begin() as conn:
                return _rebuild_projection(conn, case_id)

        return self._wq.submit(_do_rebuild)

    def get_entity_graph(self, *, include_superseded: bool = False) -> GraphSnapshot:
        """Return the typed graph snapshot without exposing a SQL query surface."""
        from mulder.graph import _read_snapshot

        with self._engine.connect() as conn:
            return _read_snapshot(
                conn,
                self._get_case_id(),
                include_superseded=include_superseded,
            )

    def get_graph_edge_provenance(self, edge_id: str) -> EdgeProvenance | None:
        """Resolve one projected edge through its claim and exact source anchors."""
        from mulder.graph import _read_edge_provenance

        with self._engine.connect() as conn:
            return _read_edge_provenance(conn, self._get_case_id(), edge_id)

    def query_entity_graph(self, request: GraphQueryRequest) -> GraphQueryResult:
        """Run one typed, bounded graph operation for this case.

        The projection is refreshed before reading so an analyst never sees a
        stale edge after a claim is contradicted or withdrawn.  The request
        type owns every supported selector and hard limit; callers cannot pass
        SQL, Cypher, table names, or query fragments.
        """
        from mulder.graph import _rebuild_projection
        from mulder.graph_query import _query_graph

        case_id = self._get_case_id()

        def _do_query() -> GraphQueryResult:
            with self._engine.begin() as conn:
                _rebuild_projection(conn, case_id)
                return _query_graph(conn, case_id, request)

        return self._wq.submit(_do_query)

    def record_reasoning(self, command: ReasoningCommand) -> ReasoningWriteResult:
        """Apply one typed append-only hypothesis or specialist-review command."""
        from mulder.reasoning import _record_command

        case_id = self._get_case_id()

        def _do_record() -> ReasoningWriteResult:
            with self._engine.begin() as conn:
                return _record_command(conn, case_id, command)

        return self._wq.submit(_do_record)

    def get_reasoning_review(self) -> ReasoningReviewProjection:
        """Return the case-local reasoning projection with reviewer seats separate."""
        from mulder.reasoning import _read_review_projection

        with self._engine.connect() as conn:
            return _read_review_projection(conn, self._get_case_id())

    def update_finding(
        self,
        finding_id: str,
        *,
        actor_kind: str = "system",
        actor_id: str | None = None,
        reason_code: str = "finding_updated",
        revision_state: str | None = None,
        **kwargs: object,
    ) -> bool:
        """Update the current read model and append an immutable revision.

        Only the provided keyword arguments are written; omitted fields
        remain unchanged.  List-valued columns (``evidence_refs``,
        ``sources``, ``mitre_attack_ids``) are JSON-serialised before
        storage.

        Args:
            finding_id: Primary key of the finding to update.
            actor_kind: Origin of the change recorded in immutable history.
            actor_id: Optional stable actor identity.
            reason_code: Machine-readable explanation for the transition.
            revision_state: Explicit lifecycle state, or derive it from confidence.
            **kwargs: Finding fields mapped to their new values.

        Returns:
            True if a row was matched and updated, False otherwise.
        """
        json_columns = frozenset({"evidence_refs", "sources", "mitre_attack_ids"})
        allowed_columns = frozenset(
            {
                "title",
                "description",
                "severity",
                "confidence",
                "evidence_refs",
                "sources",
                "mitre_attack_ids",
                "event_time_start",
                "event_time_end",
                "negative_verdict",
            }
        )
        values: dict[str, object] = {}
        for key, val in kwargs.items():
            if val is None:
                continue
            if key not in allowed_columns:
                raise ValueError(f"Unsupported finding field: {key}")
            if key in json_columns:
                values[key] = json.dumps(val)
            elif key == "negative_verdict":
                values[key] = (
                    val.model_dump_json() if hasattr(val, "model_dump_json") else json.dumps(val)
                )
            else:
                values[key] = val

        if not values:
            return self._finding_exists(finding_id)

        def _do_update() -> bool:
            """Execute the projection update and revision append atomically."""
            with self._engine.begin() as conn:
                before_row = conn.execute(
                    select(findings_t).where(
                        (findings_t.c.finding_id == finding_id) & (findings_t.c.is_deleted == 0)
                    )
                ).fetchone()
                if before_row is None:
                    return False
                before = _finding_from_row(before_row)
                result = conn.execute(
                    update(findings_t)
                    .where(
                        (findings_t.c.finding_id == finding_id) & (findings_t.c.is_deleted == 0)
                    )
                    .values(**values)
                )
                after_row = conn.execute(
                    select(findings_t).where(findings_t.c.finding_id == finding_id)
                ).fetchone()
                if result.rowcount <= 0 or after_row is None:
                    return False
                after = _finding_from_row(after_row)
                _append_finding_revision(
                    conn,
                    after,
                    state=revision_state or _state_for_finding(after),
                    actor_kind=actor_kind,
                    actor_id=actor_id,
                    reason_code=reason_code,
                    changed_fields=list(values),
                    previous=before,
                )
                return True

        return bool(self._wq.submit(_do_update))

    def delete_finding(
        self,
        finding_id: str,
        *,
        actor_kind: str = "system",
        actor_id: str | None = None,
        reason_code: str = "finding_withdrawn",
    ) -> bool:
        """Tombstone a finding while preserving its claims and full history.

        Args:
            finding_id: Primary key of the finding to remove.

        Returns:
            True if the finding existed and was deleted, False otherwise.
        """

        def _do_delete() -> bool:
            """Append a withdrawal and hide the current read projection."""
            with self._engine.begin() as conn:
                row = conn.execute(
                    select(findings_t).where(
                        (findings_t.c.finding_id == finding_id) & (findings_t.c.is_deleted == 0)
                    )
                ).fetchone()
                if row is None:
                    return False
                finding = _finding_from_row(row)
                result = conn.execute(
                    update(findings_t)
                    .where(
                        (findings_t.c.finding_id == finding_id) & (findings_t.c.is_deleted == 0)
                    )
                    .values(is_deleted=1)
                )
                _append_finding_revision(
                    conn,
                    finding,
                    state="withdrawn",
                    actor_kind=actor_kind,
                    actor_id=actor_id,
                    reason_code=reason_code,
                    changed_fields=["is_deleted"],
                    previous=finding,
                    tombstone=True,
                )
                return result.rowcount > 0

        return bool(self._wq.submit(_do_delete))

    def _finding_exists(self, finding_id: str) -> bool:
        """Return True if a finding with the given ID exists."""
        stmt = select(findings_t.c.finding_id).where(
            (findings_t.c.finding_id == finding_id) & (findings_t.c.is_deleted == 0)
        )
        with self._engine.connect() as conn:
            return conn.execute(stmt).fetchone() is not None

    def get_finding(self, finding_id: str) -> Finding | None:
        """Return a single finding by ID, or None if not found."""
        stmt = select(findings_t).where(
            (findings_t.c.finding_id == finding_id) & (findings_t.c.is_deleted == 0)
        )
        with self._engine.connect() as conn:
            row = conn.execute(stmt).fetchone()
        if row is None:
            return None
        return _finding_from_row(row)

    def get_findings(self) -> list[Finding]:
        """Return all findings ordered by submission time."""
        stmt = (
            select(findings_t)
            .where(findings_t.c.is_deleted == 0)
            .order_by(findings_t.c.submitted_at)
        )
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [_finding_from_row(row) for row in rows]

    def get_finding_revisions(self, finding_id: str) -> list[FindingRevision]:
        """Return complete immutable history, including withdrawn findings."""
        stmt = (
            select(finding_revisions_t)
            .where(finding_revisions_t.c.finding_id == finding_id)
            .order_by(finding_revisions_t.c.revision_number)
        )
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [
            FindingRevision(
                revision_id=row.revision_id,
                finding_id=row.finding_id,
                revision_number=row.revision_number,
                parent_revision_id=row.parent_revision_id,
                state=row.state,
                snapshot=Finding.model_validate_json(row.snapshot),
                actor_kind=row.actor_kind,
                actor_id=row.actor_id,
                reason_code=row.reason_code,
                changed_fields=json.loads(row.changed_fields),
                evidence_added=json.loads(row.evidence_added),
                evidence_removed=json.loads(row.evidence_removed),
                tombstone=bool(row.tombstone),
                created_at=row.created_at,
            )
            for row in rows
        ]

    def record_coverage(
        self,
        key: CoverageKey,
        outcome: ToolOutcome,
        *,
        source_name: str | None = None,
        tool_call_id: str | None = None,
    ) -> CoverageRecord:
        """Upsert one coverage assertion and return its canonical stored form.

        The tuple ``(case, system, evidence domain, check)`` is the stable
        identity. A later complete fallback therefore replaces the current
        state while its earlier failures remain in ``fallback_lineage``.
        """
        case_id = self._get_case_id()
        recorded_at = datetime.now(timezone.utc).isoformat()
        record = CoverageRecord(
            case_id=case_id,
            key=key,
            outcome=outcome,
            source_name=source_name,
            tool_call_id=tool_call_id,
            recorded_at=recorded_at,
        )

        def _do_upsert() -> None:
            with self._engine.begin() as conn:
                selector = (
                    (coverage_register_t.c.case_id == case_id)
                    & (coverage_register_t.c.system_name == key.system_name)
                    & (coverage_register_t.c.evidence_domain == key.evidence_domain)
                    & (coverage_register_t.c.check_name == key.check_name)
                )
                conn.execute(delete(coverage_register_t).where(selector))
                conn.execute(
                    insert(coverage_register_t).values(
                        case_id=case_id,
                        system_name=key.system_name,
                        evidence_domain=key.evidence_domain,
                        check_name=key.check_name,
                        status=outcome.status.value,
                        coverage=outcome.coverage.model_dump_json(),
                        reason=outcome.reason,
                        source_name=source_name,
                        tool_call_id=tool_call_id,
                        recorded_at=recorded_at,
                    )
                )

        self._wq.submit(_do_upsert)
        return record

    def get_coverage(
        self,
        *,
        system_name: str | None = None,
        evidence_domain: str | None = None,
        check_name: str | None = None,
    ) -> list[CoverageRecord]:
        """Return coverage records, optionally filtered at the stable key seam."""
        stmt = select(coverage_register_t).order_by(
            coverage_register_t.c.system_name,
            coverage_register_t.c.evidence_domain,
            coverage_register_t.c.check_name,
        )
        if system_name is not None:
            stmt = stmt.where(coverage_register_t.c.system_name == system_name)
        if evidence_domain is not None:
            stmt = stmt.where(coverage_register_t.c.evidence_domain == evidence_domain)
        if check_name is not None:
            stmt = stmt.where(coverage_register_t.c.check_name == check_name)
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [
            CoverageRecord(
                case_id=row.case_id,
                key=CoverageKey(
                    system_name=row.system_name,
                    evidence_domain=row.evidence_domain,
                    check_name=row.check_name,
                ),
                outcome=ToolOutcome(
                    status=ToolOutcomeStatus(row.status),
                    coverage=json.loads(row.coverage),
                    reason=row.reason,
                ),
                source_name=row.source_name,
                tool_call_id=row.tool_call_id,
                recorded_at=row.recorded_at,
            )
            for row in rows
        ]

    def update_extractor_versions(self, versions: dict[str, str]) -> None:
        """Update the stored extractor version map."""

        def _do_update() -> None:
            """Overwrite the extractor_versions JSON column."""
            case_id = self._get_case_id()
            with self._engine.begin() as conn:
                conn.execute(
                    update(case_metadata_t)
                    .where(case_metadata_t.c.case_id == case_id)
                    .values(extractor_versions=json.dumps(versions))
                )

        self._wq.submit(_do_update)

    def register_evidence_file(
        self,
        file_path: str,
        sha256: str,
        size_bytes: int,
    ) -> None:
        """Record an evidence file's SHA-256 hash for chain of custody."""

        def _do_register() -> None:
            """Insert a row into the evidence_registry table."""
            now = datetime.now(timezone.utc).isoformat()
            with self._engine.begin() as conn:
                conn.execute(
                    insert(evidence_registry_t).values(
                        file_path=file_path,
                        sha256=sha256,
                        size_bytes=size_bytes,
                        registered_at=now,
                    )
                )

        self._wq.submit(_do_register)

    def get_evidence_registry(self) -> list[dict[str, object]]:
        """Return all registered evidence files."""
        stmt = select(evidence_registry_t).order_by(evidence_registry_t.c.id)
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [
            {
                "file_path": row.file_path,
                "sha256": row.sha256,
                "size_bytes": row.size_bytes,
                "registered_at": row.registered_at,
            }
            for row in rows
        ]

    def add_bookmark(self, window_id: int, source_name: str, note: str) -> int:
        """Add a bookmark for a window and return its ID."""

        def _do_insert() -> int:
            """Insert a bookmark row and return its auto-generated ID."""
            now = datetime.now(timezone.utc).isoformat()
            with self._engine.begin() as conn:
                result = conn.execute(
                    insert(bookmarks_t).values(
                        window_id=window_id,
                        source_name=source_name,
                        note=note,
                        created_at=now,
                    )
                )
                if result.inserted_primary_key is None:
                    raise RuntimeError("INSERT did not return a primary key for bookmark")
                return int(result.inserted_primary_key[0])

        return int(self._wq.submit(_do_insert))

    def get_bookmarks(self) -> list[dict[str, object]]:
        """Return all bookmarks ordered by creation time."""
        stmt = select(bookmarks_t).order_by(bookmarks_t.c.created_at)
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [
            {
                "id": row.id,
                "window_id": row.window_id,
                "source_name": row.source_name,
                "note": row.note,
                "created_at": row.created_at,
            }
            for row in rows
        ]

    def remove_bookmark(self, bookmark_id: int) -> bool:
        """Remove a bookmark by ID. Returns True if a row was deleted."""

        def _do_delete() -> bool:
            """Delete the bookmark row and return whether it existed."""
            with self._engine.begin() as conn:
                result = conn.execute(
                    text("DELETE FROM bookmarks WHERE id = :bid"),
                    {"bid": bookmark_id},
                )
                return result.rowcount > 0

        return bool(self._wq.submit(_do_delete))

    def verify_evidence_integrity(self) -> list[dict[str, object]]:
        """Verify indexed source data against stored window hashes.

        Recomputes BLAKE2b from stored windows in a single streaming query
        ordered by source_id, comparing each hash to the windows_hash
        recorded at ingestion. Sources without a stored hash are reported
        as ``no_hash_recorded``.
        """
        sources = self.get_sources()
        no_hash_ids = {s.source_id for s in sources if not s.windows_hash}

        computed: dict[int, tuple[Any, int]] = {}

        with self._engine.connect() as conn:
            stream = conn.execute(
                text("SELECT source_id, raw_text FROM windows ORDER BY source_id, window_id")
            )
            for row in stream:
                sid: int = row[0]
                if sid in no_hash_ids:
                    continue
                if sid not in computed:
                    computed[sid] = (hashlib.blake2b(digest_size=32), 0)
                h, count = computed[sid]
                h.update(row[1].encode())
                computed[sid] = (h, count + 1)

        results: list[dict[str, object]] = []
        for src in sources:
            if src.source_id in no_hash_ids:
                results.append(
                    {
                        "source_name": src.source_name,
                        "expected_hash": None,
                        "actual_hash": None,
                        "window_count": 0,
                        "status": "no_hash_recorded",
                    }
                )
                continue
            entry = computed.get(src.source_id)
            if entry is None:
                actual = "blake2b:" + hashlib.blake2b(digest_size=32).hexdigest()
                window_count = 0
            else:
                h, window_count = entry
                actual = "blake2b:" + h.hexdigest()
            results.append(
                {
                    "source_name": src.source_name,
                    "expected_hash": src.windows_hash,
                    "actual_hash": actual,
                    "window_count": window_count,
                    "status": "verified" if actual == src.windows_hash else "modified",
                }
            )
        return results

    def record_progress(
        self,
        system_name: str,
        tools_completed: list[str],
        questions_addressed: list[str],
        notes: str = "",
    ) -> None:
        """Insert a progress record for a system analysis step."""

        def _do_insert() -> None:
            """Persist a single progress row."""
            now = datetime.now(timezone.utc).isoformat()
            with self._engine.begin() as conn:
                conn.execute(
                    insert(progress_t).values(
                        system_name=system_name,
                        tools_completed=json.dumps(tools_completed),
                        questions_addressed=json.dumps(questions_addressed),
                        notes=notes,
                        recorded_at=now,
                    )
                )

        self._wq.submit(_do_insert)

    def get_all_progress(self) -> list[ProgressRecord]:
        """Return all progress records ordered by insertion."""
        stmt = select(progress_t).order_by(progress_t.c.id)
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [
            ProgressRecord(
                id=row.id,
                system_name=row.system_name,
                tools_completed=json.loads(row.tools_completed),
                questions_addressed=json.loads(row.questions_addressed),
                notes=row.notes,
                recorded_at=row.recorded_at,
            )
            for row in rows
        ]

    def get_progress_summary(self) -> ProgressSummary:
        """Return aggregated progress across all recorded entries.

        Collects unique systems analyzed, questions addressed, and tools
        used from all progress records.
        """
        records = self.get_all_progress()
        systems: set[str] = set()
        questions_covered: set[str] = set()
        all_tools: set[str] = set()
        for r in records:
            systems.add(r["system_name"])
            for q in r["questions_addressed"]:
                questions_covered.add(q)
            for t in r["tools_completed"]:
                all_tools.add(t)
        return ProgressSummary(
            systems_analyzed=sorted(systems),
            questions_covered=sorted(questions_covered),
            tools_used=sorted(all_tools),
            total_progress_records=len(records),
        )

    def set_kv(self, key: str, value: str) -> None:
        """Store a key-value pair, replacing any existing value for the key.

        Args:
            key: Unique string identifier.
            value: String value to persist.
        """

        def _do_upsert() -> None:
            now = datetime.now(timezone.utc).isoformat()
            with self._engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO kv_store (key, value, updated_at) "
                        "VALUES (:key, :value, :updated_at) "
                        "ON CONFLICT(key) DO UPDATE SET value=:value, updated_at=:updated_at"
                    ),
                    {"key": key, "value": value, "updated_at": now},
                )

        self._wq.submit(_do_upsert)

    def get_kv(self, key: str) -> str | None:
        """Retrieve a value by key, or None if not stored.

        Args:
            key: The key to look up.

        Returns:
            The stored value string, or None if the key does not exist.
        """
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT value FROM kv_store WHERE key = :key"),
                {"key": key},
            ).fetchone()
        return row[0] if row else None

    def _get_case_id(self) -> str:
        """Read case_id from the case_metadata table (cached after first call)."""
        if self._case_id_cache is not None:
            return self._case_id_cache
        stmt = select(case_metadata_t.c.case_id).limit(1)
        with self._engine.connect() as conn:
            row = conn.execute(stmt).fetchone()
        if row is None:
            raise RuntimeError("No case metadata found in database")
        self._case_id_cache = str(row[0])
        return self._case_id_cache

    def get_windows_by_time_range(
        self,
        time_start: str,
        time_end: str,
    ) -> dict[str, list[WindowRow]]:
        """Fetch all windows in a time range, grouped by source_name."""
        j = windows_t.join(sources_t, windows_t.c.source_id == sources_t.c.source_id)
        stmt = (
            select(windows_t, sources_t.c.source_name)
            .select_from(j)
            .where(
                windows_t.c.event_time.isnot(None),
                windows_t.c.event_time >= time_start,
                windows_t.c.event_time <= time_end,
            )
            .order_by(windows_t.c.event_time)
        )
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()

        result: dict[str, list[WindowRow]] = {}
        for row in rows:
            sname = row.source_name
            w = WindowRow(
                window_id=row.window_id,
                source_id=row.source_id,
                line_start=row.line_start,
                line_end=row.line_end,
                event_time=row.event_time,
                raw_text=row.raw_text,
            )
            result.setdefault(sname, []).append(w)
        return result

    def get_source_stats(self) -> list[dict[str, object]]:
        """Return per-source window counts and time ranges via a single query."""
        stmt = text(
            "SELECT s.source_name, s.extractor, "
            "       COUNT(w.window_id) AS window_count, "
            "       MIN(w.event_time) AS earliest, "
            "       MAX(w.event_time) AS latest "
            "FROM sources s "
            "LEFT JOIN windows w ON s.source_id = w.source_id "
            "GROUP BY s.source_id "
            "ORDER BY s.source_id"
        )
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [
            {
                "source_name": row[0],
                "extractor": row[1],
                "window_count": row[2],
                "earliest": row[3],
                "latest": row[4],
            }
            for row in rows
        ]

    @property
    def db_path(self) -> Path:
        """Return the database file path."""
        return self._db_path

    @property
    def engine(self) -> Engine:
        """Return the SQLAlchemy engine."""
        return self._engine
