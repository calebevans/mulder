"""Per-case SQLite database lifecycle and queries using SQLAlchemy Core."""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict, TypeVar, cast

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Text,
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

    def update_finding(self, finding_id: str, **kwargs: object) -> bool:
        """Update fields on an existing finding. Returns True if found.

        Only the provided keyword arguments are written; omitted fields
        remain unchanged.  List-valued columns (``evidence_refs``,
        ``sources``, ``mitre_attack_ids``) are JSON-serialised before
        storage.

        Args:
            finding_id: Primary key of the finding to update.
            **kwargs: Column names mapped to their new values.

        Returns:
            True if a row was matched and updated, False otherwise.
        """
        json_columns = frozenset({"evidence_refs", "sources", "mitre_attack_ids"})
        values: dict[str, object] = {}
        for key, val in kwargs.items():
            if val is None:
                continue
            if key in json_columns:
                values[key] = json.dumps(val)
            else:
                values[key] = val

        if not values:
            return self._finding_exists(finding_id)

        def _do_update() -> bool:
            """Execute the UPDATE and return whether a row was matched."""
            with self._engine.begin() as conn:
                result = conn.execute(
                    update(findings_t)
                    .where(findings_t.c.finding_id == finding_id)
                    .values(**values)
                )
                return result.rowcount > 0

        return bool(self._wq.submit(_do_update))

    def delete_finding(self, finding_id: str) -> bool:
        """Delete a finding by ID. Returns True if a row was deleted.

        Args:
            finding_id: Primary key of the finding to remove.

        Returns:
            True if the finding existed and was deleted, False otherwise.
        """

        def _do_delete() -> bool:
            """Execute the DELETE and return whether a row was matched."""
            with self._engine.begin() as conn:
                result = conn.execute(
                    delete(findings_t).where(findings_t.c.finding_id == finding_id)
                )
                return result.rowcount > 0

        return bool(self._wq.submit(_do_delete))

    def _finding_exists(self, finding_id: str) -> bool:
        """Return True if a finding with the given ID exists."""
        stmt = select(findings_t.c.finding_id).where(findings_t.c.finding_id == finding_id)
        with self._engine.connect() as conn:
            return conn.execute(stmt).fetchone() is not None

    def get_finding(self, finding_id: str) -> Finding | None:
        """Return a single finding by ID, or None if not found."""
        stmt = select(findings_t).where(findings_t.c.finding_id == finding_id)
        with self._engine.connect() as conn:
            row = conn.execute(stmt).fetchone()
        if row is None:
            return None
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
            submitted_at=row.submitted_at,
        )

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
