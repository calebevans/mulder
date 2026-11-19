"""Log tables: one normalised row per log event in the case database, and bounded
counting queries over them.

An extractor that has indexed a log as text calls :func:`ingest` with the same events as
rows; the tools in ``mulder.server.tools.logtables`` call :func:`tables`, :func:`top`,
:func:`histogram` and :func:`rows`.

Every statement is assembled from constants in this module. A field name is looked up
(a fixed column, or a key the table's own ingest recorded) and never interpolated; every
value, limit and JSON path is a bound parameter.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection

from mulder.db import CaseDB

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows; mulder is Linux-first
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "BUCKETS",
    "COLUMNS",
    "HISTOGRAM_ORDERS",
    "MAX_VALUE_CHARS",
    "OPERATORS",
    "TOP_ORDERS",
    "LogTableError",
    "histogram",
    "ingest",
    "normalise_time",
    "rows",
    "tables",
    "top",
]

#: The text columns almost every log has. ``bytes`` (an integer) and ``event_time`` sit
#: beside them; anything else an extractor selects goes in ``extra``.
COLUMNS = ("actor", "src_ip", "action", "target", "status", "user_agent", "session_id")
MAX_VALUE_CHARS = 512
OPERATORS = ("eq", "ne", "in", "contains", "prefix", "exists", "missing", "gt", "ge", "lt", "le")
BUCKETS = {"minute": 16, "hour": 13, "day": 10}  # characters of event_time that name a bucket
TOP_ORDERS = ("count", "rare", "bytes", "first_seen", "last_seen")
HISTOGRAM_ORDERS = ("time", "count")

_ROW_KEYS = frozenset({*COLUMNS, "event_time", "bytes", "line", "extra"})
# Names a result row uses for something else; an ``extra`` key may not take them.
_RESERVED = _ROW_KEYS | {"time", "source", "source_path", "count", "first_seen", "last_seen"}
_COLUMN_SQL = {name: name for name in (*COLUMNS, "bytes")}
_TABLE_RE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_COMPARE = {"eq": "IS", "ne": "IS NOT", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}
_BATCH = 5000
_SCAN_CHARS = 4 * MAX_VALUE_CHARS
_MAX_FILTERS = 10
_MAX_IN_VALUES = 50
_SPLIT_VALUES = 5
_MIN_TIME = datetime(1990, 1, 1, tzinfo=UTC)
_MAX_TIME = datetime(2100, 1, 1, tzinfo=UTC)
# ponytail: one ingest of a case at a time, so an ingest cannot replace one that is still
# loading (two overlapping paths planned in one batch, or by two sessions). This lock
# covers the batch's threads and, in :func:`ingest`, a ``flock`` beside the database
# covers the other sessions' server processes, as for archive extraction. Writes are
# serialised anyway; a lock per table if ingests of different tables must interleave.
_INGEST_LOCK = threading.Lock()

_INSERT = text(
    "INSERT INTO log_events (log_table, source_id, line, event_time, actor, src_ip, action,"
    " target, status, user_agent, session_id, bytes, extra) VALUES (:log_table, :source_id,"
    " :line, :event_time, :actor, :src_ip, :action, :target, :status, :user_agent,"
    " :session_id, :bytes, :extra)"
)
_UPDATE = text(
    "UPDATE log_tables SET complete = :complete, row_count = :rows, rows_no_time = :no_time,"
    " rows_unparsed = :unparsed, first_time = :first, last_time = :last,"
    " field_counts = :fields WHERE source_id = :sid AND log_table = :t"
)
# The ingests of one table from a source of the same name as this one, itself included,
# with their evidence paths: the ones this ingest may replace or be covered by.
_EARLIER = text(
    "SELECT t.source_id, t.complete, t.nested, old.source_path AS path,"
    " new.source_path AS mine"
    " FROM log_tables t JOIN sources old ON old.source_id = t.source_id"
    " JOIN sources new ON new.source_id = :sid AND old.source_name = new.source_name"
    " WHERE t.log_table = :t"
)


class LogTableError(ValueError):
    """A query argument that cannot be answered; the message says what would be."""


def _show(value: object) -> str:
    """A bounded repr for an error message."""
    return repr(value)[:80]


def normalise_time(value: object) -> str | None:
    """Return *value* as ``YYYY-MM-DDTHH:MM:SSZ``, or None when it is not a usable time.

    Reads ISO 8601 text (an offset is converted to UTC; none is taken as UTC), epoch
    seconds or milliseconds, and datetimes. A time outside 1990..2100 is refused: one
    forged far-future event would otherwise become every "last seen", and a zeroed time
    or a compact date read as an epoch ("20240501" is a day in 1970) every "first seen".
    """
    if isinstance(value, str):
        value = value.strip()
        if value.isascii() and value.isdigit():
            value = int(value) if len(value) < 16 else None
        elif len(value) <= 40:
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return None
    try:
        if isinstance(value, int | float) and not isinstance(value, bool):
            # Epoch milliseconds are past year 5000 when read as seconds.
            value = datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=UTC)
        if not isinstance(value, datetime):
            return None
        when = value if value.tzinfo else value.replace(tzinfo=UTC)
        if not _MIN_TIME <= when < _MAX_TIME:
            return None
        return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _text(value: object) -> str | None:
    """One bounded printable line, or None when empty.

    ``str.split`` breaks on every Unicode line separator, so a stored value cannot
    start a second line where a result is indexed. A value cut short ends in "…".
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    line = " ".join(str(value)[:_SCAN_CHARS].split())
    if not line.isprintable():
        line = "".join(ch for ch in line if ch.isprintable())
    if len(line) > MAX_VALUE_CHARS:
        line = line[: MAX_VALUE_CHARS - 1] + "…"
    return line or None


def _inside(path: str, root: str) -> bool:
    """Whether evidence path *path* is *root* or lies under it, however each is spelled."""
    return Path(os.path.realpath(path)).is_relative_to(os.path.realpath(root))


def _int(value: object) -> int | None:
    """A non-negative integer that fits an SQLite INTEGER, or None."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError, OverflowError):
        return None
    return number if 0 <= number < 2**63 else None


def _record(
    table: str, source_id: int, row: Mapping[str, object], counts: dict[str, int]
) -> dict[str, object]:
    """Normalise one row for ``_INSERT`` and count its non-empty fields into *counts*."""
    unknown = row.keys() - _ROW_KEYS
    if unknown:
        raise ValueError(f"unknown log row keys {sorted(unknown)}; allowed: {sorted(_ROW_KEYS)}")
    record: dict[str, object] = {
        "log_table": table,
        "source_id": source_id,
        "line": _int(row.get("line")),
        "event_time": normalise_time(row.get("event_time")),
        "bytes": _int(row.get("bytes")),
    }
    for name in COLUMNS:
        record[name] = _text(row.get(name))
    extra: dict[str, str] = {}
    given = row.get("extra") or {}
    if not isinstance(given, Mapping):
        raise ValueError("a log row's 'extra' must be a mapping")
    for key, value in given.items():
        # Keys are constants chosen by the extractor, never names read from evidence.
        if not isinstance(key, str) or not _KEY_RE.fullmatch(key) or key in _RESERVED:
            raise ValueError(
                f"extra key {key!r} must match [a-z][a-z0-9_]* and not be one of "
                f"{sorted(_RESERVED)}"
            )
        cleaned = _text(value)
        if cleaned is not None:
            extra[key] = cleaned
    record["extra"] = json.dumps(extra, sort_keys=True) if extra else None
    for name in _COLUMN_SQL:
        if record[name] is not None:
            counts[name] = counts.get(name, 0) + 1
    for key in extra:
        counts[key] = counts.get(key, 0) + 1
    return record


def ingest(
    db: CaseDB,
    table: str,
    source_id: int,
    rows: Iterable[Mapping[str, object] | None],
    *,
    nested: bool = False,
) -> dict[str, Any]:
    """Load *rows* into log table *table* and return how many were stored and how many not.

    Call it after indexing the same events as text, with the ``source_id`` that
    ``extract_and_index`` returned: once per source and table, with every row in the one
    iterable (a second call replaces the first). Each row is a mapping with any of
    ``event_time``, ``actor``, ``src_ip``, ``action``, ``target``, ``status``,
    ``user_agent``, ``session_id``, ``bytes``, ``line`` (the event's 1-based line in the
    indexed text) and ``extra`` (a mapping of further fields worth counting on, keyed by
    constants matching ``[a-z][a-z0-9_]*``). Yield ``None`` for a record that could not
    be parsed, or for a damaged stretch of the input: it is counted, and every query
    result reports the count.

    *rows* may be a generator; it is consumed in batches, so memory stays flat, and a
    run that dies part-way leaves the table marked incomplete with what it stored. Values
    are reduced to one printable line of at most ``MAX_VALUE_CHARS`` characters. A time
    that :func:`normalise_time` refuses is stored as no time and counted. An earlier
    ingest of *table* from a source of the same name and evidence path (a forced
    re-run, or the same path spelled differently) is replaced.

    Pass ``nested=True`` when the extractor reads a directory recursively, so that one
    evidence path can contain another and then holds the same events. An earlier ingest
    from a path inside this source's is replaced as well; and when a completed earlier
    ingest's path contains this source's, nothing is loaded, *rows* is not read and the
    result names that path as ``covered_by``.
    Both rules hold only between ingests that passed ``nested=True``: pass False for a
    path that the recursive read of a directory above it would skip, so that it is
    neither taken as loaded by that directory nor replaced by it.

    Returns:
        ``{"rows", "rows_no_time", "rows_unparsed"}``, and ``covered_by`` when nothing
        was loaded because the events are already in the table.

    Raises:
        ValueError: A malformed table name, row key or ``extra`` key. These are
            mistakes in the extractor, not in the evidence.
    """
    if not _TABLE_RE.fullmatch(table):
        raise ValueError(f"log table name {table!r} must match [a-z][a-z0-9_.-]*")
    scope = {"t": table, "sid": source_id}

    def _start(conn: Connection) -> str | None:
        replaced = []
        for old in conn.execute(_EARLIER, scope).fetchall():
            both = nested and old.nested
            # The same path, however it is spelled; or, between recursive reads, one inside.
            if _inside(old.path, old.mine) and (both or _inside(old.mine, old.path)):
                replaced.append(old.source_id)
            elif both and old.complete and _inside(old.mine, old.path):
                return str(old.path)
        for old_id in replaced:
            gone = {"t": table, "old": old_id}
            for name in ("log_events", "log_tables"):
                conn.execute(
                    text(f"DELETE FROM {name} WHERE log_table = :t AND source_id = :old"), gone
                )
        conn.execute(
            text(
                "INSERT INTO log_tables (source_id, log_table, complete, nested, row_count,"
                " rows_no_time, rows_unparsed, field_counts)"
                " VALUES (:sid, :t, 0, :nested, 0, 0, 0, '{}')"
            ),
            {**scope, "nested": int(nested)},
        )
        return None

    lock_path = db.db_path.with_name(f".mulder-logtable-{db.db_path.stem}.lock")
    with _INGEST_LOCK, open(lock_path, "a") as lock:
        if fcntl is not None:
            fcntl.flock(lock, fcntl.LOCK_EX)  # released when the file is closed
        covered_by = db.write(_start)
        if covered_by is not None:
            return {"rows": 0, "rows_no_time": 0, "rows_unparsed": 0, "covered_by": covered_by}
        return _load(db, table, source_id, rows)


def _load(
    db: CaseDB, table: str, source_id: int, rows: Iterable[Mapping[str, object] | None]
) -> dict[str, Any]:
    """Store *rows* for the ingest that :func:`ingest` has just registered."""
    scope = {"t": table, "sid": source_id}
    counts: dict[str, int] = {}
    stored = no_time = unparsed = 0
    first = last = None
    batch: list[dict[str, object]] = []

    def _flush(conn: Connection, complete: int = 0) -> None:
        # The rows and the counts that describe them are committed together, so an
        # ingest that dies part-way leaves a table whose stated size is what it holds.
        if batch:
            conn.execute(_INSERT, batch)
        conn.execute(
            _UPDATE,
            {
                "complete": complete,
                "rows": stored,
                "no_time": no_time,
                "unparsed": unparsed,
                "first": first,
                "last": last,
                "fields": json.dumps(counts, sort_keys=True),
                **scope,
            },
        )

    for row in rows:
        if not isinstance(row, Mapping):
            unparsed += 1
            continue
        record = _record(table, source_id, row, counts)
        when = record["event_time"]
        if isinstance(when, str):
            first = when if first is None or when < first else first
            last = when if last is None or when > last else last
        else:
            no_time += 1
        stored += 1
        batch.append(record)
        if len(batch) >= _BATCH:
            db.write(_flush)
            batch = []
    db.write(lambda conn: _flush(conn, complete=1))
    return {"rows": stored, "rows_no_time": no_time, "rows_unparsed": unparsed}


def tables(db: CaseDB) -> list[dict[str, Any]]:
    """Every log table of the case: rows, time range, fields and where it was loaded from."""
    with db.engine.connect() as conn:
        found = conn.execute(
            text(
                "SELECT t.log_table, t.source_id, t.complete, t.row_count, t.rows_no_time,"
                " t.rows_unparsed, t.first_time, t.last_time, t.field_counts, s.source_path"
                " FROM log_tables t LEFT JOIN sources s ON s.source_id = t.source_id"
                " ORDER BY t.log_table, t.source_id"
            )
        ).fetchall()
    merged: dict[str, dict[str, Any]] = {}
    for row in found:
        entry = merged.setdefault(
            row.log_table,
            {
                "table": row.log_table,
                "rows": 0,
                "rows_without_time": 0,
                "rows_not_parsed": 0,
                "first_time": None,
                "last_time": None,
                "fields": {},
                "ingests": [],
                "loaded_from": [],
            },
        )
        entry["rows"] += row.row_count
        entry["rows_without_time"] += row.rows_no_time
        entry["rows_not_parsed"] += row.rows_unparsed
        times = [t for t in (entry["first_time"], row.first_time) if t]
        entry["first_time"] = min(times, default=None)
        times = [t for t in (entry["last_time"], row.last_time) if t]
        entry["last_time"] = max(times, default=None)
        for name, count in json.loads(row.field_counts).items():
            entry["fields"][name] = entry["fields"].get(name, 0) + count
        entry["ingests"].append(row.source_id)
        entry["loaded_from"].append({"source_path": row.source_path, "rows": row.row_count})
        if not row.complete:
            # The extractor stopped part-way: what is stored is counted, the rest is not.
            entry["ingest_incomplete"] = True
    return list(merged.values())


class _Query:
    """One validated query: the table's state, its WHERE clause and bound parameters."""

    def __init__(
        self,
        db: CaseDB,
        table: str,
        filters: Sequence[Mapping[str, object]] | None,
        t_start: str | None,
        t_end: str | None,
    ) -> None:
        state = next((t for t in tables(db) if t["table"] == table), None)
        if state is None:
            known = sorted(t["table"] for t in tables(db))
            raise LogTableError(
                f"no log table {_show(table)}; tables in this case: {known or 'none'}"
            )
        self.db = db
        self.state = state
        self.params: dict[str, object] = {"t": table}
        clauses = ["log_table = :t"]
        applied: list[dict[str, object]] = []
        if filters is not None and not isinstance(filters, list | tuple):
            raise LogTableError("filters must be a list of {field, op, value} objects")
        if len(filters or ()) > _MAX_FILTERS:
            raise LogTableError(f"at most {_MAX_FILTERS} filters")
        for item in filters or ():
            clause, echo = self._filter(item)
            clauses.append(clause)
            applied.append(echo)
        window: dict[str, str | None] = {"t_start": None, "t_end": None}
        for name, given, op in (("t_start", t_start, ">="), ("t_end", t_end, "<=")):
            if given is None or given == "":
                continue
            when = normalise_time(given)
            if when is None:
                raise LogTableError(
                    f"{name} {_show(given)} is not a UTC time like 2026-01-31T13:00:00Z"
                )
            window[name] = when
            clauses.append(f"event_time {op} {self.bind(when)}")
        self.where = " AND ".join(clauses)
        self.base: dict[str, Any] = {
            "table": table,
            "filter_applied": {"filters": applied, **window},
            "rows_in_table": state["rows"],
            "rows_not_parsed": state["rows_not_parsed"],
            "rows_without_time": state["rows_without_time"],
            # The table's ingests (source ids): what a result is a result *of*.
            "ingests": state["ingests"],
        }
        if state.get("ingest_incomplete"):
            self.base["ingest_incomplete"] = True

    def bind(self, value: object) -> str:
        """Bind *value* and return its placeholder."""
        key = f"p{len(self.params)}"
        self.params[key] = value
        return f":{key}"

    def field(self, name: object) -> str:
        """The SQL expression for field *name*: a fixed column, or a recorded ``extra`` key."""
        fields = self.state["fields"]
        if not isinstance(name, str) or name not in fields:
            cut = " (loading it was cut short)" if self.state.get("ingest_incomplete") else ""
            raise LogTableError(
                f"unknown field {_show(name)} for {self.state['table']}{cut}; "
                f"fields: {sorted(fields)}"
            )
        if name in _COLUMN_SQL:
            return _COLUMN_SQL[name]
        # *name* is a key this table's ingest validated and recorded; even so the JSON
        # path is bound, not interpolated.
        return f"json_extract(extra, {self.bind('$.' + name)})"

    def _filter(self, item: object) -> tuple[str, dict[str, object]]:
        if not isinstance(item, Mapping) or not {"field", "op"} <= item.keys():
            raise LogTableError(
                'each filter is {"field": ..., "op": ..., "value": ...}; ops: '
                + ", ".join(OPERATORS)
            )
        name, op, value = item["field"], item["op"], item.get("value")
        if not isinstance(op, str) or op not in OPERATORS:
            raise LogTableError(f"unknown op {_show(op)}; ops: {', '.join(OPERATORS)}")
        expr = self.field(name)
        text_only, bytes_only = op in ("contains", "prefix"), op in ("gt", "ge", "lt", "le")
        if (text_only and name == "bytes") or (bytes_only and name != "bytes"):
            raise LogTableError(
                "contains and prefix apply to text fields; gt, ge, lt and le to bytes only "
                "(use t_start/t_end for times)"
            )
        if op in ("exists", "missing"):
            return f"{expr} IS {'NOT ' if op == 'exists' else ''}NULL", {"field": name, "op": op}
        if op == "in":
            if not isinstance(value, list | tuple) or not 0 < len(value) <= _MAX_IN_VALUES:
                raise LogTableError(f"op 'in' takes a list of 1 to {_MAX_IN_VALUES} values")
            values = [self._value(name, v) for v in value]
            marks = ", ".join(self.bind(v) for v in values)
            return f"{expr} IN ({marks})", {"field": name, "op": op, "value": values}
        cleaned = self._value(name, value)
        echo = {"field": name, "op": op, "value": cleaned}
        if op in _COMPARE:
            return f"{expr} {_COMPARE[op]} {self.bind(cleaned)}", echo
        # Case-insensitive (ASCII); instr and substr take no wildcards, so "%" and "_" in
        # the value are ordinary characters.
        mark = self.bind(cleaned)
        if op == "contains":
            return f"instr(lower({expr}), lower({mark})) > 0", echo
        return f"substr(lower({expr}), 1, length({mark})) = lower({mark})", echo

    def _value(self, name: object, value: object) -> str | int:
        """A filter value normalised the way stored values were."""
        cleaned = None
        if not isinstance(value, list | tuple | Mapping):
            cleaned = _int(value) if name == "bytes" else _text(value)
        if cleaned is None:
            raise LogTableError(
                f"filter on {name} needs "
                + ("a non-negative integer" if name == "bytes" else "a non-empty value")
                + "; use op 'missing' for rows without the field"
            )
        return cleaned

    def run(self, sql: str, **more: object) -> list[Any]:
        """Execute *sql* with the bound parameters."""
        with self.db.engine.connect() as conn:
            return list(conn.execute(text(sql), {**self.params, **more}).fetchall())


def top(
    db: CaseDB,
    table: str,
    fields: Sequence[str],
    *,
    filters: Sequence[Mapping[str, object]] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    n: int = 25,
    order: str = "count",
) -> dict[str, Any]:
    """The *n* leading value combinations of one to three *fields*, with counts.

    Each row carries the values, ``count``, ``first_seen``, ``last_seen`` and, where the
    table has byte counts, ``bytes``. Rows without a value form a group of their own
    (value None), so the counts add up to ``rows_matched``.
    """
    query = _Query(db, table, filters, t_start, t_end)
    if not isinstance(fields, list | tuple) or not 1 <= len(fields) <= 3:
        raise LogTableError("fields must name one to three fields")
    if order not in TOP_ORDERS:
        raise LogTableError(f"order must be one of {', '.join(TOP_ORDERS)}")
    keys = [query.field(name) for name in fields]
    if "bytes" in fields or len(set(fields)) != len(fields):
        raise LogTableError("fields must be distinct, and bytes is summed, not grouped")
    k = len(keys)
    ordinals = ", ".join(str(i) for i in range(1, k + 1))
    # Positions, not aliases: an alias that is also a column name would resolve to the column.
    by = {
        "count": f"{k + 1} DESC",
        "rare": f"{k + 1} ASC",
        "first_seen": f"{k + 2} ASC NULLS LAST",
        "last_seen": f"{k + 3} DESC",
        "bytes": f"{k + 4} DESC",
    }[order]
    # TOTAL sums as a float: SUM raises "integer overflow" once forged byte counts pass
    # 2**63. A sum above 2**53 bytes (8 PiB) is therefore approximate.
    found = query.run(
        f"SELECT {', '.join(keys)}, COUNT(*), MIN(event_time), MAX(event_time), TOTAL(bytes),"
        f" COUNT(*) OVER (), SUM(COUNT(*)) OVER () FROM log_events WHERE {query.where}"
        f" GROUP BY {ordinals} ORDER BY {by}, {ordinals} LIMIT :n",
        n=n,
    )
    has_bytes = "bytes" in query.state["fields"]
    out: list[dict[str, Any]] = []
    for row in found:
        entry = dict(zip(fields, row[:k], strict=True))
        entry.update(count=row[k], first_seen=row[k + 1], last_seen=row[k + 2])
        if has_bytes:
            entry["bytes"] = int(row[k + 3])
        out.append(entry)
    groups = found[0][k + 4] if found else 0
    return {
        **query.base,
        "rows_matched": found[0][k + 5] if found else 0,
        "groups_total": groups,
        "truncated": groups > len(out),
        "rows": out,
    }


def histogram(
    db: CaseDB,
    table: str,
    bucket: str = "hour",
    *,
    split_by: str | None = None,
    filters: Sequence[Mapping[str, object]] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    n: int = 100,
    order: str = "time",
) -> dict[str, Any]:
    """Events per minute, hour or day, optionally split by the leading values of a field.

    Buckets without events are not returned. With *split_by*, each bucket lists the
    count of the field's five most frequent values (over the whole match) and the rest
    as ``other``, so the output is bounded whatever the field holds.
    """
    query = _Query(db, table, filters, t_start, t_end)
    if not isinstance(bucket, str) or bucket not in BUCKETS:
        raise LogTableError(f"bucket must be one of {', '.join(BUCKETS)}")
    if order not in HISTOGRAM_ORDERS:
        raise LogTableError(f"order must be one of {', '.join(HISTOGRAM_ORDERS)}")
    timed = f"{query.where} AND event_time IS NOT NULL"
    leading: list[object] = []
    sums = ""
    if split_by is not None:
        if split_by == "bytes":
            raise LogTableError("split_by takes a text field, not bytes")
        key = query.field(split_by)
        leading = [
            row[0]
            for row in query.run(
                f"SELECT {key}, COUNT(*) FROM log_events WHERE {timed}"
                " GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT :n",
                n=_SPLIT_VALUES,
            )
        ]
        # IS compares NULL as a value, so "no value" can be one of the leading groups.
        sums = "".join(f", SUM({key} IS {query.bind(value)})" for value in leading)
    width = query.bind(BUCKETS[bucket])
    found = query.run(
        f"SELECT substr(event_time, 1, {width}), COUNT(*), COUNT(*) OVER (),"
        f" SUM(COUNT(*)) OVER (){sums} FROM log_events WHERE {timed}"
        f" GROUP BY 1 ORDER BY {'2 DESC, 1' if order == 'count' else '1'} LIMIT :n",
        n=n,
    )
    untimed = query.run(
        f"SELECT COUNT(*) FROM log_events WHERE {query.where} AND event_time IS NULL"
    )[0][0]
    out: list[dict[str, Any]] = []
    for row in found:
        entry: dict[str, Any] = {"bucket": row[0], "count": row[1]}
        if split_by is not None:
            parts = [
                {"value": value, "count": count}
                for value, count in zip(leading, row[4:], strict=True)
                if count
            ]
            entry["by"] = parts
            entry["other"] = row[1] - sum(part["count"] for part in parts)
        out.append(entry)
    buckets = found[0][2] if found else 0
    return {
        **query.base,
        "rows_matched": (found[0][3] if found else 0) + untimed,
        "matched_without_time": untimed,
        "bucket": bucket,
        "split_by": split_by,
        "buckets_total": buckets,
        "truncated": buckets > len(out),
        "rows": out,
    }


def rows(
    db: CaseDB,
    table: str,
    *,
    filters: Sequence[Mapping[str, object]] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    limit: int = 50,
    offset: int = 0,
    newest_first: bool = False,
) -> dict[str, Any]:
    """One page of the matching events in time order; events without a time come last.

    Each row carries its non-empty fields, plus ``source`` and ``line``: where the whole
    event is in the indexed text. When the table was loaded from more than one evidence
    path those sources share a name, so each row also carries its ``source_path``.
    """
    query = _Query(db, table, filters, t_start, t_end)
    matched = query.run(f"SELECT COUNT(*) FROM log_events WHERE {query.where}")[0][0]
    # ponytail: OFFSET paging reads the rows it skips; keyset paging if deep pages get slow.
    found = query.run(
        "SELECT source_id, line, event_time, actor, src_ip, action, target, status, user_agent,"
        f" session_id, bytes, extra FROM log_events WHERE {query.where}"
        f" ORDER BY event_time {'DESC' if newest_first else 'ASC'} NULLS LAST, event_id"
        " LIMIT :n OFFSET :skip",
        n=limit,
        skip=offset,
    )
    sources = {s.source_id: s for s in db.get_sources()}
    several = len(query.state["ingests"]) > 1
    out: list[dict[str, Any]] = []
    for row in found:
        entry: dict[str, Any] = {"time": row.event_time}
        entry.update({name: getattr(row, name) for name in _COLUMN_SQL})
        entry.update(json.loads(row.extra) if row.extra else {})
        source = sources.get(row.source_id)
        entry.update(
            source=getattr(source, "source_name", None),
            source_path=getattr(source, "source_path", None) if several else None,
            line=row.line,
        )
        out.append({key: value for key, value in entry.items() if value is not None})
    return {
        **query.base,
        "rows_matched": matched,
        "offset": offset,
        "truncated": offset + len(out) < matched,
        "rows": out,
    }
