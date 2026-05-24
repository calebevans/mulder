"""Per-case SQLite database lifecycle and queries using SQLAlchemy Core."""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import re
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar, cast

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Text,
    create_engine,
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

from mulder.models import CaseMetadataRow, Finding, SourceRow, WindowRow

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
    Column("submitted_at", Text, nullable=False),
)

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
    already-quoted phrases.  All other tokens containing special
    characters are wrapped in double quotes so FTS5 treats them
    as literals.
    """
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


_SENTINEL = object()

_QueueItem = tuple[
    Callable[..., object], tuple[object, ...], dict[str, object], list[object], threading.Event
]


class _WriteQueue:
    """Single-writer thread that serialises all DB write operations.

    Worker threads submit callables via ``submit`` and block until the
    writer thread executes them.  This eliminates SQLite ``BUSY`` errors
    entirely -- only one thread ever holds the write lock.
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
                result_holder[0] = fn(*args, **kwargs)
            except Exception as exc:
                result_holder[1] = exc
            finally:
                done_event.set()
                self._queue.task_done()

    def submit(self, fn: Callable[..., _T], *args: object, **kwargs: object) -> _T:
        """Submit *fn* to the writer thread and block until it completes.

        Returns the result of ``fn(*args, **kwargs)`` or re-raises its
        exception in the calling thread.
        """
        result_holder: list[object] = [None, None]
        done_event = threading.Event()
        self._queue.put((fn, args, kwargs, result_holder, done_event))
        done_event.wait()
        if result_holder[1] is not None:
            raise result_holder[1]  # type: ignore[misc]
        return result_holder[0]  # type: ignore[return-value]

    def shutdown(self) -> None:
        """Signal the writer thread to exit and wait for it."""
        self._queue.put(_SENTINEL)
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            logger.warning(
                "DB writer thread did not exit within timeout; remaining queue items may be lost"
            )


class CaseDB:
    """Manages a per-case SQLite database file."""

    def __init__(self, db_path: Path) -> None:
        """Open an existing case database at the given path."""
        self._db_path = db_path
        self._engine = _make_engine(db_path)
        self._wq = _WriteQueue()

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
                assert result.inserted_primary_key is not None
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

                all_wins = conn.execute(
                    text("SELECT raw_text FROM windows WHERE source_id = :sid ORDER BY window_id"),
                    {"sid": source_id},
                ).fetchall()
                h = hashlib.blake2b(digest_size=32)
                for row in all_wins:
                    h.update(row[0].encode())
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

        stmt = stmt.order_by(windows_t.c.line_start).limit(max_results)

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

    def insert_finding(self, finding: Finding) -> None:
        """Persist a Finding to the database."""

        def _do_insert() -> None:
            """Persist a single finding row."""
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
                        submitted_at=finding.submitted_at,
                    )
                )

        self._wq.submit(_do_insert)

    def get_findings(self) -> list[Finding]:
        """Return all findings ordered by submission time."""
        stmt = select(findings_t).order_by(findings_t.c.submitted_at)
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return [
            Finding(
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
                submitted_at=row.submitted_at,
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
                assert result.inserted_primary_key is not None
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

        For each source, recomputes BLAKE2b from stored windows and compares
        to the windows_hash recorded at ingestion. This is a fast DB-only
        operation that verifies the indexed data has not been tampered with.
        """
        sources = self.get_sources()
        results: list[dict[str, object]] = []
        for src in sources:
            if not src.windows_hash:
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
            windows = self.get_windows_by_source(src.source_name)
            h = hashlib.blake2b(digest_size=32)
            for w in windows:
                h.update(w.raw_text.encode())
            actual = "blake2b:" + h.hexdigest()
            results.append(
                {
                    "source_name": src.source_name,
                    "expected_hash": src.windows_hash,
                    "actual_hash": actual,
                    "window_count": len(windows),
                    "status": "verified" if actual == src.windows_hash else "modified",
                }
            )
        return results

    def _get_case_id(self) -> str:
        """Read case_id from the case_metadata table (cached after first call)."""
        if hasattr(self, "_case_id_cache"):
            return self._case_id_cache
        stmt = select(case_metadata_t.c.case_id).limit(1)
        with self._engine.connect() as conn:
            row = conn.execute(stmt).fetchone()
        if row is None:
            raise RuntimeError("No case metadata found in database")
        self._case_id_cache: str = str(row[0])
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
