"""Log table MCP tools: counting questions over logs that were loaded as rows.

``search`` finds text; it cannot say how often, from how many addresses, or when first
and last. These tools answer that from the log tables an extractor filled
(``mulder.logtable.ingest``): ``list_log_tables`` names them, ``log_top`` ranks values,
``log_histogram`` counts per time bucket and ``log_rows`` pages through events. The
model never writes SQL: it names fields and gives values, and ``mulder.logtable`` binds
them. Every result is bounded, says what it left out, and is indexed as its own
``logtable.<kind>.<id>`` source whose first line carries the ``tool_call_id``.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from mulder import logtable
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    audited_tool,
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.netflow.core import NetflowArgError, clamp, source_hid

__all__ = ["list_log_tables", "log_histogram", "log_rows", "log_top"]

# The roles the NetFlow pivots have: the analyst who has read the indexed log, and the
# cross-system executor running a plan.
_ROLES = Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR
_MAX_ROWS = 200
_MAX_OFFSET = 100_000
_MAX_PATHS = 20  # evidence paths list_log_tables names per table
_INLINE_CHARS = 12_000  # about 3,000 tokens of rows in one response
# ponytail: one lock for every log-table query, so identical concurrent calls cannot both
# register the same source name; per-name locks if the queries ever get slow.
_LOCK = threading.Lock()


def _when(row: dict[str, Any]) -> str:
    """The time a result row is indexed under: its own, its first, or its bucket's start."""
    bucket = row.get("bucket")
    if bucket:
        return str(bucket) + "T00:00:00"[len(bucket) - 10 :]
    return str(row.get("time") or row.get("first_seen") or "-")


def _answer(
    tool: str,
    params: dict[str, object],
    force: bool,
    query: Callable[[], tuple[dict[str, object], dict[str, Any]]],
) -> dict[str, object]:
    """Run *query*, index its rows as their own source and return the bounded envelope.

    *query* returns the effective parameters that shape the rows, and the result of a
    ``mulder.logtable`` query. An identical query over an unchanged table is not indexed
    twice: the answer is returned again with ``status: "skipped"`` and the existing source.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    kind = tool.removeprefix("log_")
    try:
        shape, result = query()
    except (logtable.LogTableError, NetflowArgError) as exc:
        return error_response(
            tc_id,
            tool,
            params,
            str(exc),
            (time.monotonic() - t0) * 1000,
            error_type="invalid_argument",
            suggestion="list_log_tables shows each table's fields and time range",
        )
    except SQLAlchemyError as exc:
        # Reported, and so audited, like any other failed call. The driver's own message
        # is given, not SQLAlchemy's, which appends the statement and its parameters.
        return error_response(
            tc_id,
            tool,
            params,
            f"the case database could not answer this query: {getattr(exc, 'orig', exc)}"[:300],
            (time.monotonic() - t0) * 1000,
            error_type="tool_failed",
        )
    rows: list[dict[str, Any]] = result.pop("rows")
    table = str(result["table"])
    # The table's ingests are part of the identity: a table that has since been loaded
    # again or added to is queried afresh, not answered from an older source.
    identity = {**shape, "filter": result["filter_applied"], "ingests": result.pop("ingests")}
    base = f"logtable.{kind}.{source_hid(tool, table, identity)}"
    notes: list[str] = []
    with _LOCK:
        existing = sources_already_indexed([base], evidence_path=table)
        if existing and not force:
            name, status = existing[-1], "skipped"
            notes.append(
                f"identical query already indexed as '{name}': nothing new was indexed "
                "(force=True indexes it again)"
            )
        else:
            name, status = (f"{base}-r{len(existing)}" if existing else base), "success"
            header = {"tool": tool, "tool_call_id": tc_id, **shape, **result, "rows": len(rows)}
            if existing:
                header["supersedes"] = existing[-1]
            # json.dumps escapes every control and non-ASCII character, so a value read
            # from evidence cannot end its line and start a forged one.
            lines = [f"- logtable header {json.dumps(header, default=str)}"]
            lines += [f"{_when(row)} logtable {kind} {json.dumps(row)}" for row in rows]
            extract_and_index("\n".join(lines), name, table, "logtable")

    shown: list[dict[str, Any]] = []
    used = 0
    for row in rows:
        used += len(json.dumps(row))
        if shown and used > _INLINE_CHARS:
            break
        shown.append(row)
    if len(shown) < len(rows):
        notes.append(
            f"{len(rows) - len(shown)} more rows are in source '{name}' (get_raw_output), "
            "left out here to keep the response small"
        )
    if result["truncated"]:
        following = result.get("offset", 0) + len(rows)
        if kind != "rows":
            notes.append(
                "truncated: more matched than was returned; narrow the filter or the time "
                "window, or raise the row limit"
            )
        elif following <= _MAX_OFFSET:
            notes.append(f"truncated: more rows matched; next page: offset={following}")
        else:
            notes.append(
                f"truncated: more rows matched, but offset is capped at {_MAX_OFFSET} (this "
                f"page starts at offset {result['offset']}); narrow the filter or the time "
                "window to read further"
            )
    if result["rows_not_parsed"]:
        notes.append(
            f"at least {result['rows_not_parsed']} records of this log could not be parsed "
            "(damaged, truncated or malformed input) and are in no count: the table is "
            "incomplete"
        )
    if result.get("ingest_incomplete"):
        notes.append("loading this table was cut short: the counts cover only what was stored")
    body: dict[str, object] = {
        "status": status,
        "source": name,
        **result,
        "row_count": len(rows),
        "rows": shown,
        "notes": notes,
        "hint": (
            f"To cite: evidence_refs = this tool_call_id ({tc_id}), sources = '{name}'. "
            "Counts are of log records loaded into this table, not of everything that "
            "happened: no rows for a value means no such record here."
        ),
    }
    # tool_response writes the audit entry; the envelope itself is flat, as the NetFlow
    # tools' is, so the rows are not nested under "results".
    tool_response(tc_id, tool, params, body, None, (time.monotonic() - t0) * 1000)
    return {"tool_call_id": tc_id, **body}


@mcp.tool()
@tool_access(_ROLES)
@audited_tool("list_log_tables")
def list_log_tables() -> dict[str, object]:
    """List the log tables of this case: logs loaded as rows that can be counted.

    Call before log_top, log_histogram or log_rows to learn the table names, their time
    range and which fields each has. A log that is not listed was indexed as text only:
    use search for it.

    Returns per table: rows, rows_without_time, rows_not_parsed (records the parser could
    not read: they are in no count), first_time and last_time (UTC), fields (field name
    to the number of rows that have a value) and loaded_from (evidence path and rows;
    the 20 largest when there are more, with loaded_from_note saying so).
    """
    found = logtable.tables(get_ctx().db)
    for entry in found:
        del entry["ingests"]
        paths = entry["loaded_from"]
        if len(paths) > _MAX_PATHS:
            entry["loaded_from"] = sorted(paths, key=lambda part: -part["rows"])[:_MAX_PATHS]
            entry["loaded_from_note"] = (
                f"the {_MAX_PATHS} largest of {len(paths)} evidence paths this table was "
                "loaded from"
            )
    result: dict[str, object] = {"status": "success", "tables": found}
    if not found:
        result["message"] = (
            "No log tables in this case: no extractor that fills one has run on its "
            "evidence. Use search on the indexed sources instead."
        )
    return result


@mcp.tool()
@tool_access(_ROLES)
def log_top(
    table: str,
    fields: str | list[str],
    filters: list[dict[str, Any]] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    n: int = 20,
    order: str = "count",
    force: bool = False,
) -> dict[str, object]:
    """Count log events by the values of one to three fields, with first and last seen.

    Call for counting questions instead of paging through search: which source IPs an
    actor used and how often, which actions a key performed, the first and last time a
    user agent appeared. Rows without a value form their own group (null), so the
    counts add up to rows_matched.

    Returns up to n groups (the field values, count, first_seen, last_seen, and bytes
    where the table has byte counts) with groups_total (distinct combinations),
    rows_matched, rows_in_table, rows_not_parsed, filter_applied and truncated; indexed
    as source logtable.top.<id>. Times are UTC. A count is of records in this table: it
    says nothing about periods or systems the log does not cover.

    Args:
        table: A table name from list_log_tables, e.g. "cloudlog.aws".
        fields: One to three field names of that table to group by.
        filters: Conditions that must all hold, each
            {"field": "actor", "op": "eq", "value": "alice"}. ops: eq, ne, in (value is
            a list), contains and prefix (ignore case), exists and missing (no value),
            and gt, ge, lt, le on bytes.
        t_start: Only events at or after this UTC time, e.g. "2026-01-31T13:00:00Z".
        t_end: Only events at or before this UTC time.
        n: Groups to return (1..200).
        order: count (most frequent first), rare (least frequent first), bytes,
            first_seen (earliest first) or last_seen (latest first).
        force: Index the result again even if this exact query was already indexed.
    """
    names = [fields] if isinstance(fields, str) else fields
    params: dict[str, object] = {
        "table": table, "fields": fields, "filters": filters, "t_start": t_start,
        "t_end": t_end, "n": n, "order": order, "force": force,
    }  # fmt: skip

    def query() -> tuple[dict[str, object], dict[str, Any]]:
        limit = clamp(n, 1, _MAX_ROWS)
        result = logtable.top(
            get_ctx().db, table, names,
            filters=filters, t_start=t_start, t_end=t_end, n=limit, order=order,
        )  # fmt: skip
        return {"fields": list(names), "n": limit, "order": order}, result

    return _answer("log_top", params, force, query)


@mcp.tool()
@tool_access(_ROLES)
def log_histogram(
    table: str,
    bucket: str = "hour",
    split_by: str | None = None,
    filters: list[dict[str, Any]] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    n: int = 100,
    order: str = "time",
    force: bool = False,
) -> dict[str, object]:
    """Count log events per minute, hour or day, optionally split by one field.

    Call to see when activity happened: events per hour for an actor, the day a source
    IP first became busy, the busiest minutes (order="count"). Buckets with no events
    are not listed, and events without a time are in no bucket (matched_without_time).

    Returns up to n buckets (bucket, count; with split_by also by: the count of each of
    the field's five most frequent values, and other) with buckets_total, rows_matched,
    rows_in_table, rows_not_parsed, filter_applied and truncated; indexed as source
    logtable.histogram.<id>. Bucket names are UTC: "2026-01-31T13" is the hour from
    13:00. A quiet bucket shows no records in this table, not that nothing happened.

    Args:
        table: A table name from list_log_tables, e.g. "cloudlog.aws".
        bucket: minute, hour or day.
        split_by: A field of the table to break each bucket down by.
        filters: Conditions that must all hold, each
            {"field": "actor", "op": "eq", "value": "alice"}. ops: eq, ne, in (value is
            a list), contains and prefix (ignore case), exists and missing (no value),
            and gt, ge, lt, le on bytes.
        t_start: Only events at or after this UTC time, e.g. "2026-01-31T13:00:00Z".
        t_end: Only events at or before this UTC time.
        n: Buckets to return (1..200).
        order: time (earliest bucket first) or count (busiest bucket first).
        force: Index the result again even if this exact query was already indexed.
    """
    params: dict[str, object] = {
        "table": table, "bucket": bucket, "split_by": split_by, "filters": filters,
        "t_start": t_start, "t_end": t_end, "n": n, "order": order, "force": force,
    }  # fmt: skip

    def query() -> tuple[dict[str, object], dict[str, Any]]:
        limit = clamp(n, 1, _MAX_ROWS)
        result = logtable.histogram(
            get_ctx().db, table, bucket, split_by=split_by,
            filters=filters, t_start=t_start, t_end=t_end, n=limit, order=order,
        )  # fmt: skip
        return {"bucket": bucket, "split_by": split_by, "n": limit, "order": order}, result

    return _answer("log_histogram", params, force, query)


@mcp.tool()
@tool_access(_ROLES)
def log_rows(
    table: str,
    filters: list[dict[str, Any]] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    limit: int = 25,
    offset: int = 0,
    newest_first: bool = False,
    force: bool = False,
) -> dict[str, object]:
    """Read log events that match a filter, one page at a time, in time order.

    Call after log_top or log_histogram has shown what to look at: the events of one
    actor in one hour, everything from one address. Events without a time come last.
    Use a filter or a time window: paging through a whole table is what log_top is for.

    Returns up to limit rows (time, the fields that have a value, and source and line:
    where the whole event is in the indexed text, with source_path when the table was
    loaded from several evidence paths) with rows_matched, rows_in_table,
    rows_not_parsed, filter_applied and truncated; indexed as source
    logtable.rows.<id>. When truncated, notes names the next page's offset. Values
    longer than 512 characters end in "…"; search the source for the whole event.

    Args:
        table: A table name from list_log_tables, e.g. "cloudlog.aws".
        filters: Conditions that must all hold, each
            {"field": "actor", "op": "eq", "value": "alice"}. ops: eq, ne, in (value is
            a list), contains and prefix (ignore case), exists and missing (no value),
            and gt, ge, lt, le on bytes.
        t_start: Only events at or after this UTC time, e.g. "2026-01-31T13:00:00Z".
        t_end: Only events at or before this UTC time.
        limit: Rows to return (1..200).
        offset: Rows to skip, for the next page (0..100000; a larger one is read as
            100000, so narrow the filter or the time window to read further).
        newest_first: Latest events first instead of earliest first.
        force: Index the result again even if this exact page was already indexed.
    """
    params: dict[str, object] = {
        "table": table, "filters": filters, "t_start": t_start, "t_end": t_end,
        "limit": limit, "offset": offset, "newest_first": newest_first, "force": force,
    }  # fmt: skip

    def query() -> tuple[dict[str, object], dict[str, Any]]:
        page, skip = clamp(limit, 1, _MAX_ROWS), clamp(offset, 0, _MAX_OFFSET)
        result = logtable.rows(
            get_ctx().db, table, filters=filters, t_start=t_start, t_end=t_end,
            limit=page, offset=skip, newest_first=bool(newest_first),
        )  # fmt: skip
        return {"limit": page, "offset": skip, "newest_first": bool(newest_first)}, result

    return _answer("log_rows", params, force, query)
