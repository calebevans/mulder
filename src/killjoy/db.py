"""Per-case sqlite-vec database lifecycle and queries."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import sqlite_vec

from killjoy.models import CaseMetadataRow, Finding, SourceRow, WindowRow

_SCHEMA_DDL = """\
CREATE TABLE IF NOT EXISTS case_metadata (
    case_id            TEXT PRIMARY KEY,
    ingested_at        TEXT NOT NULL,
    evidence_root      TEXT NOT NULL,
    extractor_versions TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    source_id          INTEGER PRIMARY KEY,
    case_id            TEXT NOT NULL REFERENCES case_metadata(case_id),
    source_name        TEXT NOT NULL,
    source_path        TEXT NOT NULL,
    source_hash        TEXT NOT NULL,
    extractor          TEXT NOT NULL,
    line_count         INTEGER NOT NULL,
    ingested_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS windows (
    window_id          INTEGER PRIMARY KEY,
    source_id          INTEGER NOT NULL REFERENCES sources(source_id),
    line_start         INTEGER NOT NULL,
    line_end           INTEGER NOT NULL,
    event_time         TEXT,
    raw_text           TEXT NOT NULL,
    embedding          BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id         TEXT PRIMARY KEY,
    case_id            TEXT NOT NULL,
    title              TEXT NOT NULL,
    description        TEXT NOT NULL,
    severity           TEXT NOT NULL,
    confidence         TEXT NOT NULL,
    evidence_refs      TEXT NOT NULL,
    sources            TEXT NOT NULL,
    event_time_start   TEXT,
    event_time_end     TEXT,
    submitted_at       TEXT NOT NULL
);
"""

_VEC_TABLE_DDL = """\
CREATE VIRTUAL TABLE IF NOT EXISTS vec_windows USING vec0 (
    window_id   INTEGER PRIMARY KEY,
    embedding   float[384]
);
"""


class CaseDB:
    """Manages a per-case sqlite-vec database file."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.enable_load_extension(True)
        sqlite_vec.load(self._conn)
        self._conn.enable_load_extension(False)

    @classmethod
    def create(
        cls,
        case_id: str,
        evidence_root: str,
        db_dir: Path,
    ) -> CaseDB:
        db_dir = Path(db_dir).expanduser()
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = db_dir / f"{case_id}.db"

        db = cls(db_path)
        db._conn.executescript(_SCHEMA_DDL)
        db._conn.execute(_VEC_TABLE_DDL)
        db._conn.commit()

        now = datetime.now(timezone.utc).isoformat()
        db._conn.execute(
            "INSERT INTO case_metadata (case_id, ingested_at, evidence_root, extractor_versions)"
            " VALUES (?, ?, ?, ?)",
            (case_id, now, evidence_root, json.dumps({})),
        )
        db._conn.commit()
        return db

    @classmethod
    def open(cls, case_id: str, db_dir: Path) -> CaseDB:
        db_dir = Path(db_dir).expanduser()
        db_path = db_dir / f"{case_id}.db"
        if not db_path.exists():
            raise FileNotFoundError(f"Case database not found: {db_path}")
        return cls(db_path)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> CaseDB:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Source registration (Piece 2)
    # ------------------------------------------------------------------

    def register_source(
        self,
        source_name: str,
        source_path: str,
        source_hash: str,
        extractor: str,
        line_count: int,
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        case_id = self._get_case_id()
        cur = self._conn.execute(
            "INSERT INTO sources"
            " (case_id, source_name, source_path, source_hash, extractor, line_count, ingested_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case_id, source_name, source_path, source_hash, extractor, line_count, now),
        )
        self._conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid

    # ------------------------------------------------------------------
    # Window insertion (Piece 2/5)
    # ------------------------------------------------------------------

    def insert_windows(self, source_id: int, windows: list[WindowRow]) -> None:
        rows = [
            (
                w.window_id,
                source_id,
                w.line_start,
                w.line_end,
                w.event_time,
                w.raw_text,
                b"",  # embedding placeholder; real blob goes to vec_windows
            )
            for w in windows
        ]
        self._conn.executemany(
            "INSERT INTO windows"
            " (window_id, source_id, line_start, line_end, event_time, raw_text, embedding)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()

    def insert_vec_windows(self, rows: list[tuple[int, bytes]]) -> None:
        self._conn.executemany(
            "INSERT INTO vec_windows (window_id, embedding) VALUES (?, ?)",
            rows,
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Query methods (Piece 5)
    # ------------------------------------------------------------------

    def knn_query(
        self,
        query_embedding: bytes,
        k: int,
        source_name: str | None = None,
        time_start: str | None = None,
        time_end: str | None = None,
    ) -> list[WindowRow]:
        sql = (
            "WITH knn AS ("
            "  SELECT window_id, distance"
            "  FROM vec_windows"
            "  WHERE embedding MATCH ? AND k = ?"
            ")"
            " SELECT w.window_id, w.source_id, w.line_start, w.line_end,"
            "        w.event_time, w.raw_text"
            " FROM knn"
            " JOIN windows w ON w.window_id = knn.window_id"
            " JOIN sources s ON s.source_id = w.source_id"
        )
        params: list[object] = [query_embedding, k]
        clauses: list[str] = []

        if source_name is not None:
            clauses.append("s.source_name = ?")
            params.append(source_name)
        if time_start is not None:
            clauses.append("w.event_time >= ?")
            params.append(time_start)
        if time_end is not None:
            clauses.append("w.event_time <= ?")
            params.append(time_end)

        if clauses:
            sql += " WHERE " + " AND ".join(clauses)

        sql += " ORDER BY knn.distance"

        return [
            WindowRow(
                window_id=row["window_id"],
                source_id=row["source_id"],
                line_start=row["line_start"],
                line_end=row["line_end"],
                event_time=row["event_time"],
                raw_text=row["raw_text"],
            )
            for row in self._conn.execute(sql, params)
        ]

    def get_windows_by_source(
        self,
        source_name: str,
        time_start: str | None = None,
        time_end: str | None = None,
    ) -> list[WindowRow]:
        sql = (
            "SELECT w.window_id, w.source_id, w.line_start, w.line_end,"
            "       w.event_time, w.raw_text"
            " FROM windows w"
            " JOIN sources s ON s.source_id = w.source_id"
            " WHERE s.source_name = ?"
        )
        params: list[object] = [source_name]

        if time_start is not None:
            sql += " AND w.event_time >= ?"
            params.append(time_start)
        if time_end is not None:
            sql += " AND w.event_time <= ?"
            params.append(time_end)

        sql += " ORDER BY w.line_start"

        return [
            WindowRow(
                window_id=row["window_id"],
                source_id=row["source_id"],
                line_start=row["line_start"],
                line_end=row["line_end"],
                event_time=row["event_time"],
                raw_text=row["raw_text"],
            )
            for row in self._conn.execute(sql, params)
        ]

    def get_sources(self) -> list[SourceRow]:
        rows = self._conn.execute(
            "SELECT source_id, case_id, source_name, source_path,"
            "       source_hash, extractor, line_count"
            " FROM sources"
            " ORDER BY source_id"
        ).fetchall()
        return [
            SourceRow(
                source_id=row["source_id"],
                case_id=row["case_id"],
                source_name=row["source_name"],
                source_path=row["source_path"],
                source_hash=row["source_hash"],
                extractor=row["extractor"],
                line_count=row["line_count"],
            )
            for row in rows
        ]

    def get_case_metadata(self) -> CaseMetadataRow:
        row = self._conn.execute("SELECT * FROM case_metadata LIMIT 1").fetchone()
        if row is None:
            raise RuntimeError("No case metadata found in database")
        return CaseMetadataRow(
            case_id=row["case_id"],
            ingested_at=row["ingested_at"],
            evidence_root=row["evidence_root"],
            extractor_versions=json.loads(row["extractor_versions"]),
        )

    # ------------------------------------------------------------------
    # Findings (Piece 10)
    # ------------------------------------------------------------------

    def insert_finding(self, finding: Finding) -> None:
        self._conn.execute(
            "INSERT INTO findings"
            " (finding_id, case_id, title, description, severity, confidence,"
            "  evidence_refs, sources, event_time_start, event_time_end, submitted_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.finding_id,
                finding.case_id,
                finding.title,
                finding.description,
                finding.severity,
                finding.confidence,
                json.dumps(finding.evidence_refs),
                json.dumps(finding.sources),
                finding.event_time_start,
                finding.event_time_end,
                finding.submitted_at,
            ),
        )
        self._conn.commit()

    def get_findings(self) -> list[Finding]:
        rows = self._conn.execute("SELECT * FROM findings ORDER BY submitted_at").fetchall()
        return [
            Finding(
                finding_id=row["finding_id"],
                case_id=row["case_id"],
                title=row["title"],
                description=row["description"],
                severity=row["severity"],
                confidence=row["confidence"],
                evidence_refs=json.loads(row["evidence_refs"]),
                sources=json.loads(row["sources"]),
                event_time_start=row["event_time_start"],
                event_time_end=row["event_time_end"],
                submitted_at=row["submitted_at"],
            )
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Extractor metadata (Piece 2)
    # ------------------------------------------------------------------

    def update_extractor_versions(self, versions: dict[str, str]) -> None:
        case_id = self._get_case_id()
        self._conn.execute(
            "UPDATE case_metadata SET extractor_versions = ? WHERE case_id = ?",
            (json.dumps(versions), case_id),
        )
        self._conn.commit()

    def get_max_window_id(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(window_id), 0) AS max_id FROM windows"
        ).fetchone()
        return row["max_id"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_case_id(self) -> str:
        row = self._conn.execute("SELECT case_id FROM case_metadata LIMIT 1").fetchone()
        if row is None:
            raise RuntimeError("No case metadata found in database")
        return row["case_id"]

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn
