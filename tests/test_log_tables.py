"""Log tables: events loaded as rows, and the bounded counting tools over them."""

from __future__ import annotations

import inspect
import json
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from mulder import logtable
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.orchestrator import prompts
from mulder.server import app
from mulder.server.tool_access import Role, get_tools_for_role
from mulder.server.tools import cloudlogs, logtables
from mulder.server.tools.cloudlogs import run_cloud_audit_logs
from mulder.server.tools.findings import _uncitable_refs
from mulder.server.tools.logtables import list_log_tables, log_histogram, log_rows, log_top

_TABLE = "weblog.access"
_ROWS: list[dict[str, object]] = [
    {
        "event_time": "2026-03-01T10:00:05Z",
        "actor": "alice",
        "src_ip": "203.0.113.9",
        "action": "login",
        "status": "ok",
        "user_agent": "Mozilla/5.0",
        "bytes": 100,
        "line": 1,
        "extra": {"country": "NL"},
    },
    {
        "event_time": "2026-03-01T10:20:00Z",
        "actor": "alice",
        "src_ip": "203.0.113.9",
        "action": "download",
        "status": "ok",
        "user_agent": "Mozilla/5.0",
        "bytes": 5000,
        "line": 2,
        "extra": {"country": "NL"},
    },
    {
        "event_time": "2026-03-01T11:05:00Z",
        "actor": "alice",
        "src_ip": "198.51.100.7",
        "action": "login",
        "status": "denied",
        "user_agent": "curl/8.4",
        "line": 3,
        "extra": {"country": "RO"},
    },
    {
        "event_time": "2026-03-02T09:00:00Z",
        "actor": "bob",
        "src_ip": "198.51.100.7",
        "action": "login",
        "status": "ok",
        "user_agent": "curl/8.4",
        "bytes": 40,
        "line": 4,
    },
    {"actor": "bob", "action": "logout", "line": 5},
]


@pytest.fixture
def case(tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    """A real case database and audit log behind the server context."""
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    return tmp_case_db


def _load(
    db: CaseDB,
    rows: Any = _ROWS,
    table: str = _TABLE,
    path: str = "/evidence/access.log",
    nested: bool = False,
) -> dict[str, Any]:
    source_id = db.register_source(table, path, "blake2b:test", "test", 5)
    return logtable.ingest(db, table, source_id, rows, nested=nested)


def _call(tool: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
    result: dict[str, Any] = tool.__wrapped__(*args, **kwargs)
    return result


def _counts(result: dict[str, Any], field: str) -> dict[Any, int]:
    return {row[field]: row["count"] for row in result["rows"]}


def _source_lines(db: CaseDB, source: str) -> list[str]:
    return "".join(w.raw_text for w in db.get_windows_by_source(source)).splitlines()


# --- ingest ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "stored"),
    [
        ("2026-03-01T10:00:05Z", "2026-03-01T10:00:05Z"),
        ("2026-03-01T10:00:05.987654321Z", "2026-03-01T10:00:05Z"),
        ("2026-03-01 10:00:05", "2026-03-01T10:00:05Z"),
        ("2026-03-01T12:00:05+02:00", "2026-03-01T10:00:05Z"),
        (1772359205, "2026-03-01T10:00:05Z"),
        ("1772359205000", "2026-03-01T10:00:05Z"),
        (1772359205.5, "2026-03-01T10:00:05Z"),
        ("yesterday", None),
        ("", None),
        (None, None),
        (True, None),
        ("9999-12-31T23:59:59Z", None),
        ("0001-01-01T00:00:00+14:00", None),
        (-5, None),
        # A zeroed time, and a compact date read as epoch seconds, land in 1970.
        (0, None),
        ("0", None),
        ("20240501", None),
        ("1970-01-01T00:00:00Z", None),
        (float("nan"), None),
        (float("inf"), None),
        ("2" * 5000, None),
        ({"when": "now"}, None),
    ],
)
def test_times_are_stored_as_fixed_width_utc_or_not_at_all(given: object, stored: object) -> None:
    assert logtable.normalise_time(given) == stored


def test_ingest_counts_what_it_stored_and_what_it_could_not_use(case: CaseDB) -> None:
    rows = [*_ROWS, None, {"event_time": "not a time", "actor": "carol"}, None]

    loaded = _load(case, iter(rows))

    assert loaded == {"rows": 6, "rows_no_time": 2, "rows_unparsed": 2}
    (table,) = _call(list_log_tables)["tables"]
    assert table == {
        "table": _TABLE,
        "rows": 6,
        "rows_without_time": 2,
        "rows_not_parsed": 2,
        "first_time": "2026-03-01T10:00:05Z",
        "last_time": "2026-03-02T09:00:00Z",
        "fields": {
            "action": 5,
            "actor": 6,
            "bytes": 3,
            "country": 3,
            "src_ip": 4,
            "status": 4,
            "user_agent": 4,
        },
        "loaded_from": [{"source_path": "/evidence/access.log", "rows": 6}],
    }


def test_hostile_values_are_stored_as_one_bounded_printable_line(case: CaseDB) -> None:
    forged = "evil\n2026-01-01T00:00:00Z logtable rows {} second\x00\x1b[31m\tend"
    _load(case, [{"actor": forged, "target": "A" * 100_000, "extra": {"note": "B" * 100_000}}])

    with case.engine.connect() as conn:
        actor, target, extra = conn.execute(
            text("SELECT actor, target, extra FROM log_events")
        ).one()

    assert actor == "evil 2026-01-01T00:00:00Z logtable rows {} second[31m end"
    assert len(target) == logtable.MAX_VALUE_CHARS and target.endswith("A…")
    assert len(json.loads(extra)["note"]) == logtable.MAX_VALUE_CHARS


@pytest.mark.parametrize(
    "row",
    [
        {"source_ip": "203.0.113.9"},
        {"extra": {"Bad-Key": 1}},
        {"extra": {"x'); DROP TABLE log_events; --": 1}},
        {"extra": {"actor": "shadows a column"}},
        {"extra": {"count": "shadows a result key"}},
        {"extra": "not a mapping"},
    ],
)
def test_a_row_shape_only_an_extractor_bug_produces_is_refused(
    case: CaseDB, row: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        _load(case, [row])


def test_a_bad_table_name_is_refused_before_anything_is_written(case: CaseDB) -> None:
    with pytest.raises(ValueError):
        _load(case, table="log'; DROP TABLE log_events; --")

    assert _call(list_log_tables)["tables"] == []


def test_a_forced_rerun_replaces_its_rows_and_other_evidence_adds_to_them(case: CaseDB) -> None:
    _load(case)
    _load(case)  # the same source name and path again: a forced re-run
    assert _call(list_log_tables)["tables"][0]["rows"] == 5

    _load(case, path="/evidence/other/access.log")
    (table,) = _call(list_log_tables)["tables"]
    assert table["rows"] == 10
    assert [part["source_path"] for part in table["loaded_from"]] == [
        "/evidence/access.log",
        "/evidence/other/access.log",
    ]
    assert _counts(_call(log_top, _TABLE, "actor"), "actor") == {"alice": 6, "bob": 4}
    # Two text sources now share the name: a row says which one its line is in.
    assert {(row["source_path"], row["line"]) for row in _call(log_rows, _TABLE)["rows"]} == {
        (path, line)
        for path in ("/evidence/access.log", "/evidence/other/access.log")
        for line in range(1, 6)
    }


def test_a_recursive_extractor_does_not_load_a_path_twice(case: CaseDB) -> None:
    """``nested=True``: one evidence path can contain another, and holds the same events."""
    whole = {"alice": 3, "bob": 2}
    _load(case, path="/evidence/logs/2024", nested=True)
    assert _load(case, path="/evidence/logs/2025", nested=True)["rows"] == 5  # beside, not inside

    # The directory above both replaces them, however it is spelled.
    assert _load(case, path="/evidence/logs/2024/..", nested=True)["rows"] == 5
    assert _counts(_call(log_top, _TABLE, "actor"), "actor") == whole

    # A path inside it adds nothing; the same path spelled differently replaces it.
    inside = _load(case, [*_ROWS, None], path="/evidence/logs/2024/a.log", nested=True)
    assert inside == {
        "rows": 0,
        "rows_no_time": 0,
        "rows_unparsed": 0,
        "covered_by": "/evidence/logs/2024/..",
    }
    assert _load(case, path="/evidence/logs/", nested=True)["rows"] == 5
    (table,) = _call(list_log_tables)["tables"]
    assert table["loaded_from"] == [{"source_path": "/evidence/logs/", "rows": 5}]
    assert (table["rows"], table["rows_not_parsed"]) == (5, 0)

    # An extractor that does not recurse keeps both: the inner path holds other events.
    assert _load(case, path="/evidence/logs/2024")["rows"] == 5
    assert _call(log_top, _TABLE, "actor")["rows_in_table"] == 10
    # And a recursive read of the directory above it does not replace what it did not read.
    assert _load(case, path="/evidence/logs", nested=True)["rows"] == 5
    assert _call(log_top, _TABLE, "actor")["rows_in_table"] == 10


def test_overlapping_paths_loaded_at_the_same_time_are_still_counted_once(case: CaseDB) -> None:
    """The planner lists a directory and one inside it; a batch runs both at once."""
    started, release = threading.Event(), threading.Event()

    def slow() -> Iterator[dict[str, object]]:
        yield from _ROWS[:2]
        started.set()
        release.wait(10)
        yield from _ROWS[2:]

    inner = threading.Thread(
        target=_load, args=(case, slow(), _TABLE, "/evidence/logs/2024", True)
    )
    outer = threading.Thread(target=_load, args=(case, _ROWS, _TABLE, "/evidence/logs", True))
    inner.start()
    assert started.wait(10)
    outer.start()
    outer.join(0.3)  # it must wait: replacing an ingest that is still loading orphans its rows
    release.set()
    inner.join()
    outer.join()

    result = _call(log_top, _TABLE, "actor")
    assert (result["rows_matched"], result["rows_in_table"]) == (5, 5)
    assert "ingest_incomplete" not in result


# Another server process part-way through loading a directory into the case: it has
# registered its ingest and waits for a line on stdin before it yields the rest.
_OTHER_SERVER = """
import sys
from pathlib import Path
from mulder import logtable
from mulder.db import CaseDB

def rows():
    yield {"actor": "alice", "line": 1}
    print("loading", flush=True)
    sys.stdin.readline()
    yield {"actor": "bob", "line": 2}

db = CaseDB.open("test-case", Path(sys.argv[1]))
source_id = db.register_source("weblog.access", "/evidence/logs/2024", "blake2b:test", "test", 2)
logtable.ingest(db, "weblog.access", source_id, rows(), nested=True)
db.close()
"""


def test_overlapping_paths_loaded_by_two_server_processes_are_still_counted_once(
    case: CaseDB,
) -> None:
    """Each agent session has its own ``mulder serve``, and they share the case database."""
    other = subprocess.Popen(
        [sys.executable, "-c", _OTHER_SERVER, str(case.db_path.parent)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert other.stdout is not None and other.stdout.readline() == "loading\n"
    outer = threading.Thread(target=_load, args=(case, _ROWS, _TABLE, "/evidence/logs", True))
    outer.start()
    outer.join(0.3)  # it must wait for the other process, as it would for another thread
    other.communicate("\n", timeout=30)
    outer.join(30)

    assert other.returncode == 0
    result = _call(log_top, _TABLE, "actor")
    assert (result["rows_matched"], result["rows_in_table"]) == (5, 5)
    assert "ingest_incomplete" not in result


def test_one_source_can_feed_two_tables(case: CaseDB) -> None:
    source_id = case.register_source("weblog", "/evidence/web.log", "blake2b:test", "test", 5)

    logtable.ingest(case, "weblog.access", source_id, _ROWS[:3])
    logtable.ingest(case, "weblog.error", source_id, _ROWS[3:])

    listed = {t["table"]: t["rows"] for t in _call(list_log_tables)["tables"]}
    assert listed == {"weblog.access": 3, "weblog.error": 2}
    assert _call(log_top, "weblog.error", "actor")["rows_matched"] == 2


def test_the_table_listing_stays_small_however_many_paths_fed_a_table(case: CaseDB) -> None:
    for day in range(25):
        _load(case, _ROWS[: 1 + day % 3], path=f"/evidence/day-{day:02d}/access.log")

    (table,) = _call(list_log_tables)["tables"]

    assert table["rows"] == 49
    assert len(table["loaded_from"]) == 20 and table["loaded_from"][0]["rows"] == 3
    assert "20 largest of 25" in table["loaded_from_note"]


def test_an_ingest_that_was_cut_short_is_reported_not_passed_off_as_whole(
    case: CaseDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    def rows() -> Iterator[dict[str, object]]:
        yield from _ROWS[:3]
        raise OSError("disk went away")

    monkeypatch.setattr(logtable, "_BATCH", 2)
    with pytest.raises(OSError):
        _load(case, rows())

    # The two rows of the batch that was committed, and counts that describe exactly them.
    (table,) = _call(list_log_tables)["tables"]
    assert (table["rows"], table["ingest_incomplete"]) == (2, True)
    result = _call(log_top, _TABLE, "actor")
    assert (result["rows_matched"], result["ingest_incomplete"]) == (2, True)
    assert any("cut short" in note for note in result["notes"])


def test_a_case_database_from_before_log_tables_gains_them_on_open(tmp_path: Path) -> None:
    CaseDB.create(case_id="old", evidence_root="/evidence", db_dir=tmp_path).close()
    old = CaseDB.open("old", tmp_path)
    old.write(lambda conn: conn.execute(text("DROP TABLE log_events")))
    old.write(lambda conn: conn.execute(text("DROP TABLE log_tables")))
    old.close()

    with CaseDB.open("old", tmp_path) as db:
        assert _load(db)["rows"] == 5
        assert logtable.top(db, _TABLE, ["actor"])["rows_matched"] == 5


# --- queries --------------------------------------------------------------------------


def test_top_counts_values_with_first_and_last_seen_and_a_byte_sum(case: CaseDB) -> None:
    _load(case)

    result = _call(log_top, _TABLE, ["actor", "src_ip"])

    assert result["rows"] == [
        {
            "actor": "alice",
            "src_ip": "203.0.113.9",
            "count": 2,
            "first_seen": "2026-03-01T10:00:05Z",
            "last_seen": "2026-03-01T10:20:00Z",
            "bytes": 5100,
        },
        {
            "actor": "alice",
            "src_ip": "198.51.100.7",
            "count": 1,
            "first_seen": "2026-03-01T11:05:00Z",
            "last_seen": "2026-03-01T11:05:00Z",
            "bytes": 0,
        },
        {
            # No source IP and no time: its own group, so the counts still add up.
            "actor": "bob",
            "src_ip": None,
            "count": 1,
            "first_seen": None,
            "last_seen": None,
            "bytes": 0,
        },
        {
            "actor": "bob",
            "src_ip": "198.51.100.7",
            "count": 1,
            "first_seen": "2026-03-02T09:00:00Z",
            "last_seen": "2026-03-02T09:00:00Z",
            "bytes": 40,
        },
    ]
    assert result["groups_total"] == 4
    assert sum(row["count"] for row in result["rows"]) == result["rows_matched"] == 5


def test_top_orders_and_says_when_groups_were_left_out(case: CaseDB) -> None:
    _load(case)

    def first(order: str) -> object:
        return _call(log_top, _TABLE, "action", order=order, n=1)["rows"][0]["action"]

    assert first("count") == "login"
    assert first("rare") == "download"
    assert first("bytes") == "download"
    assert first("first_seen") == "login"
    assert first("last_seen") == "login"
    one = _call(log_top, _TABLE, "action", n=1)
    assert one["truncated"] is True and one["groups_total"] == 3 and one["row_count"] == 1
    assert any("truncated" in note for note in one["notes"])
    assert _call(log_top, _TABLE, "action")["truncated"] is False


def test_a_field_kept_as_json_is_counted_like_a_column(case: CaseDB) -> None:
    _load(case)

    result = _call(log_top, _TABLE, "country")

    assert _counts(result, "country") == {"NL": 2, None: 2, "RO": 1}


@pytest.mark.parametrize(
    ("filters", "matched"),
    [
        ([{"field": "actor", "op": "eq", "value": "alice"}], 3),
        ([{"field": "actor", "op": "eq", "value": "ALICE"}], 0),
        ([{"field": "actor", "op": "ne", "value": "alice"}], 2),
        # ne keeps rows that have no value at all.
        ([{"field": "src_ip", "op": "ne", "value": "203.0.113.9"}], 3),
        ([{"field": "action", "op": "in", "value": ["download", "logout"]}], 2),
        ([{"field": "user_agent", "op": "contains", "value": "MOZILLA"}], 2),
        ([{"field": "src_ip", "op": "prefix", "value": "198.51.100."}], 2),
        ([{"field": "status", "op": "exists"}], 4),
        ([{"field": "status", "op": "missing"}], 1),
        ([{"field": "bytes", "op": "gt", "value": 100}], 1),
        ([{"field": "bytes", "op": "ge", "value": "100"}], 2),
        ([{"field": "bytes", "op": "lt", "value": 100}], 1),
        ([{"field": "bytes", "op": "le", "value": 100}], 2),
        ([{"field": "bytes", "op": "eq", "value": 40}], 1),
        ([{"field": "country", "op": "eq", "value": "RO"}], 1),
        ([{"field": "country", "op": "missing"}], 2),
        (
            [
                {"field": "actor", "op": "eq", "value": "alice"},
                {"field": "status", "op": "eq", "value": "ok"},
            ],
            2,
        ),
        # LIKE wildcards are ordinary characters.
        ([{"field": "actor", "op": "contains", "value": "%"}], 0),
        ([{"field": "actor", "op": "prefix", "value": "_"}], 0),
    ],
)
def test_filters_select_rows(case: CaseDB, filters: list[dict[str, Any]], matched: int) -> None:
    _load(case)

    result = _call(log_rows, _TABLE, filters)

    assert result["rows_matched"] == matched == len(result["rows"])
    assert result["filter_applied"]["filters"][0]["field"] == filters[0]["field"]


def test_a_time_window_is_inclusive_and_read_in_any_utc_spelling(case: CaseDB) -> None:
    _load(case)

    result = _call(log_top, _TABLE, "actor", t_start="2026-03-01 10:20:00", t_end="2026-03-01")
    assert result["rows_matched"] == 0
    result = _call(
        log_top, _TABLE, "actor", t_start="2026-03-01T12:20:00+02:00", t_end="2026-03-01T11:05:00"
    )

    assert result["rows_matched"] == 2
    assert result["filter_applied"] == {
        "filters": [],
        "t_start": "2026-03-01T10:20:00Z",
        "t_end": "2026-03-01T11:05:00Z",
    }


def test_histogram_counts_per_bucket_and_leaves_untimed_events_out(case: CaseDB) -> None:
    _load(case)

    hours = _call(log_histogram, _TABLE)
    assert hours["rows"] == [
        {"bucket": "2026-03-01T10", "count": 2},
        {"bucket": "2026-03-01T11", "count": 1},
        {"bucket": "2026-03-02T09", "count": 1},
    ]
    assert (hours["rows_matched"], hours["matched_without_time"], hours["buckets_total"]) == (
        5,
        1,
        3,
    )
    days = _call(log_histogram, _TABLE, "day")
    assert _counts(days, "bucket") == {"2026-03-01": 3, "2026-03-02": 1}
    minutes = _call(log_histogram, _TABLE, "minute", order="count", n=2)
    assert minutes["rows"][0] == {"bucket": "2026-03-01T10:00", "count": 1}
    assert minutes["truncated"] is True and minutes["buckets_total"] == 4


def test_histogram_split_is_bounded_to_the_leading_values_plus_other(
    case: CaseDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    _load(case)

    by_ip = _call(log_histogram, _TABLE, "day", "src_ip")
    assert by_ip["rows"] == [
        {
            "bucket": "2026-03-01",
            "count": 3,
            "by": [{"value": "198.51.100.7", "count": 1}, {"value": "203.0.113.9", "count": 2}],
            "other": 0,
        },
        {
            "bucket": "2026-03-02",
            "count": 1,
            "by": [{"value": "198.51.100.7", "count": 1}],
            "other": 0,
        },
    ]

    monkeypatch.setattr(logtable, "_SPLIT_VALUES", 1)
    by_action = _call(log_histogram, _TABLE, "day", "action")
    assert by_action["rows"][0] == {
        "bucket": "2026-03-01",
        "count": 3,
        "by": [{"value": "login", "count": 2}],
        "other": 1,
    }


def test_rows_page_in_time_order_and_point_back_at_the_indexed_text(case: CaseDB) -> None:
    _load(case)

    first = _call(log_rows, _TABLE, limit=2)
    assert first["rows"][0] == {
        "time": "2026-03-01T10:00:05Z",
        "actor": "alice",
        "src_ip": "203.0.113.9",
        "action": "login",
        "status": "ok",
        "user_agent": "Mozilla/5.0",
        "bytes": 100,
        "country": "NL",
        "source": _TABLE,
        "line": 1,
    }
    assert [row["line"] for row in first["rows"]] == [1, 2]
    assert first["truncated"] is True and first["rows_matched"] == 5

    rest = _call(log_rows, _TABLE, limit=10, offset=first["offset"] + first["row_count"])
    # The event without a time comes last, and absent fields are left out.
    assert [row["line"] for row in rest["rows"]] == [3, 4, 5]
    assert rest["rows"][-1] == {"actor": "bob", "action": "logout", "source": _TABLE, "line": 5}
    assert rest["truncated"] is False

    newest = _call(log_rows, _TABLE, newest_first=True, limit=1)
    assert newest["rows"][0]["line"] == 4


# --- the envelope, indexing and citation ----------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args"),
    [(log_top, (_TABLE, "actor")), (log_histogram, (_TABLE,)), (log_rows, (_TABLE,))],
)
def test_every_result_states_its_filter_its_counts_and_whether_it_was_cut(
    case: CaseDB, tool: Any, args: tuple[Any, ...]
) -> None:
    _load(case, [*_ROWS, None])
    filters = [{"field": "actor", "op": "eq", "value": "alice"}]

    result = _call(tool, *args, filters=filters, t_start="2026-03-01T00:00:00Z")

    assert result["status"] == "success"
    assert result["table"] == _TABLE
    assert result["filter_applied"] == {
        "filters": filters,
        "t_start": "2026-03-01T00:00:00Z",
        "t_end": None,
    }
    assert (result["rows_matched"], result["rows_in_table"]) == (3, 5)
    assert (result["rows_not_parsed"], result["rows_without_time"]) == (1, 1)
    assert result["truncated"] is False
    assert any("could not be parsed" in note for note in result["notes"])
    assert "ingests" not in result


def test_a_result_is_indexed_with_its_tool_call_id_and_can_be_cited(
    case: CaseDB, tmp_audit_log: AuditLog
) -> None:
    _load(case)

    result = _call(log_top, _TABLE, "actor")

    assert result["source"].startswith("logtable.top.")
    header, *rows = _source_lines(case, result["source"])
    assert header.startswith("- logtable header ")
    recorded = json.loads(header.removeprefix("- logtable header "))
    assert recorded["tool_call_id"] == result["tool_call_id"]
    assert (recorded["tool"], recorded["table"], recorded["rows_matched"]) == (
        "log_top",
        _TABLE,
        5,
    )
    assert rows[0].startswith("2026-03-01T10:00:05Z logtable top ")
    assert json.loads(rows[0].split(" logtable top ", 1)[1]) == result["rows"][0]
    assert _uncitable_refs(tmp_audit_log, [result["tool_call_id"]]) == []
    assert "not of everything that happened" in result["hint"]
    assert case.search_windows("alice", source_name="logtable")
    # A query that matches nothing is on record too.
    nothing = _call(log_top, _TABLE, "actor", [{"field": "actor", "op": "eq", "value": "zed"}])
    assert nothing["rows"] == [] and len(_source_lines(case, nothing["source"])) == 1


def test_an_identical_query_is_indexed_once_unless_forced_or_the_table_changed(
    case: CaseDB,
) -> None:
    _load(case)
    first = _call(log_top, _TABLE, "actor", t_start="2026-03-01T00:00:00Z")

    again = _call(log_top, _TABLE, ["actor"], t_start="2026-03-01 00:00:00", n="20")
    assert again["status"] == "skipped" and again["source"] == first["source"]
    # The answer is still given: a small model should not need a second call to read it.
    assert again["rows"] == first["rows"]
    assert any("already indexed" in note for note in again["notes"])

    forced = _call(log_top, _TABLE, "actor", t_start="2026-03-01T00:00:00Z", force=True)
    assert forced["status"] == "success" and forced["source"] == first["source"] + "-r1"
    assert first["source"] in _source_lines(case, forced["source"])[0]

    other = _call(log_top, _TABLE, "actor")
    assert other["source"] not in (first["source"], forced["source"])

    _load(case, path="/evidence/other/access.log")
    grown = _call(log_top, _TABLE, "actor", t_start="2026-03-01T00:00:00Z")
    assert grown["status"] == "success" and not grown["source"].startswith(first["source"])
    assert grown["rows_in_table"] == 10

    names = [s.source_name for s in case.get_sources() if s.source_name.startswith("logtable.")]
    assert len(names) == len(set(names)) == 4


def test_paging_names_the_next_offset_and_says_when_the_offset_is_capped(
    case: CaseDB, monkeypatch: pytest.MonkeyPatch
) -> None:
    _load(case)

    first = _call(log_rows, _TABLE, limit=2)
    assert any("next page: offset=2" in note for note in first["notes"])

    monkeypatch.setattr(logtables, "_MAX_OFFSET", 3)
    capped = _call(log_rows, _TABLE, limit=1, offset=50)
    assert (capped["offset"], capped["truncated"]) == (3, True)
    assert any("capped at 3" in note for note in capped["notes"])
    assert not any("next page" in note for note in capped["notes"])


def test_a_database_error_is_an_audited_error_response(
    case: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object, **__: object) -> dict[str, Any]:
        raise OperationalError("SELECT 1", {}, sqlite3.OperationalError("disk I/O error"))

    _load(case)
    monkeypatch.setattr(logtable, "top", broken)

    result = _call(log_top, _TABLE, "actor")

    assert (result["status"], result["error_type"]) == ("error", "tool_failed")
    assert "disk I/O error" in result["error_message"] and "SELECT" not in result["error_message"]
    assert tmp_audit_log.has_tool_call(result["tool_call_id"])


# --- hostile input --------------------------------------------------------------------

_INJECTIONS = [
    "' OR '1'='1",
    "x'; DROP TABLE log_events; --",
    '" OR 1=1 --',
    "alice' UNION SELECT raw_text FROM windows --",
    ":t",
    "$.actor",
    "%",
]


@pytest.mark.parametrize("payload", _INJECTIONS)
def test_sql_in_a_filter_value_is_compared_as_text(case: CaseDB, payload: str) -> None:
    _load(case)

    for op in ("eq", "contains", "prefix"):
        filters = [{"field": "actor", "op": op, "value": payload}]
        assert _call(log_rows, _TABLE, filters)["rows_matched"] == 0
    listed = [{"field": "country", "op": "in", "value": [payload, "RO"]}]
    assert _call(log_top, _TABLE, "actor", listed)["rows_matched"] == 1

    assert _call(log_top, _TABLE, "actor")["rows_in_table"] == 5
    with case.engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM log_events")).scalar() == 5


@pytest.mark.parametrize("payload", [*_INJECTIONS, "extra", "event_time", "", None, 7, ["actor"]])
def test_sql_cannot_arrive_as_a_field_table_operator_or_option(
    case: CaseDB, payload: object
) -> None:
    _load(case)
    calls: list[Callable[[], dict[str, Any]]] = [
        lambda: _call(log_top, _TABLE, [payload]),
        lambda: _call(log_top, payload, "actor"),
        lambda: _call(log_top, _TABLE, "actor", order=payload),
        lambda: _call(log_top, _TABLE, "actor", [{"field": payload, "op": "eq", "value": "x"}]),
        lambda: _call(log_top, _TABLE, "actor", [{"field": "actor", "op": payload, "value": "x"}]),
        lambda: _call(log_histogram, _TABLE, payload),
        lambda: _call(log_histogram, _TABLE, "hour", payload or "nope"),
        lambda: _call(log_histogram, _TABLE, order=payload),
    ]

    for call in calls:
        result = call()
        assert (result["status"], result["error_type"]) == ("error", "invalid_argument"), result

    with case.engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM log_events")).scalar() == 5
    assert not [s for s in case.get_sources() if s.source_name.startswith("logtable.")]


def test_invalid_arguments_say_what_would_be_valid(case: CaseDB) -> None:
    _load(case)

    unknown = _call(log_top, "cloudlog.aws", "actor")
    assert _TABLE in unknown["error_message"] and "list_log_tables" in unknown["suggestion"]
    field = _call(log_top, _TABLE, "username")
    assert "'actor'" in field["error_message"] and "'country'" in field["error_message"]
    # A column no row of this table has a value for is not offered either.
    assert "unknown field 'target'" in _call(log_top, _TABLE, "target")["error_message"]
    cases: list[dict[str, Any]] = [
        {"t_start": "last tuesday"},
        {"t_start": "20240101"},
        {"n": "many"},
        {"fields": ["actor", "actor"]},
        {"fields": ["bytes"]},
        {"fields": []},
        {"fields": ["actor", "src_ip", "action", "status"]},
        {"filters": "actor = alice"},
        {"filters": [{"field": "actor"}]},
        {"filters": [{"field": "actor", "op": "eq"}]},
        {"filters": [{"field": "actor", "op": "eq", "value": {"$ne": 1}}]},
        {"filters": [{"field": "actor", "op": "gt", "value": "a"}]},
        {"filters": [{"field": "bytes", "op": "contains", "value": "1"}]},
        {"filters": [{"field": "bytes", "op": "gt", "value": "lots"}]},
        {"filters": [{"field": "actor", "op": "in", "value": "alice"}]},
        {"filters": [{"field": "actor", "op": "in", "value": ["a"] * 51}]},
        {"filters": [{"field": "actor", "op": "exists"}] * 11},
    ]
    for bad in cases:
        result = _call(log_top, **{"table": _TABLE, "fields": "actor", **bad})
        assert result.get("error_type") == "invalid_argument", bad


def test_values_read_from_evidence_cannot_forge_a_row_in_the_indexed_result(
    case: CaseDB,
) -> None:
    forged = 'mallory"}\n2026-03-01T00:00:00Z logtable top {"actor": "nobody", "count": 999}'
    _load(case, [{"event_time": "2026-03-01T10:00:00Z", "actor": forged + " " + forged}])

    result = _call(log_top, _TABLE, "actor")

    lines = _source_lines(case, result["source"])
    assert len(lines) == 2  # the header and the one real group
    assert json.loads(lines[1].split(" logtable top ", 1)[1])["count"] == 1


def test_byte_counts_at_the_integer_limit_are_summed_not_an_error(case: CaseDB) -> None:
    """Two forged byte counts whose sum does not fit SQLite's 64-bit integer."""
    huge = 2**63 - 1
    _load(
        case,
        [{"actor": "a", "bytes": huge}, {"actor": "a", "bytes": huge}, {"actor": "b", "bytes": 7}],
    )

    result = _call(log_top, _TABLE, "actor", order="bytes")

    assert result["status"] == "success"
    assert [row["actor"] for row in result["rows"]] == ["a", "b"]
    assert result["rows"][0]["bytes"] == pytest.approx(2 * huge)
    assert result["rows"][1]["bytes"] == 7 and isinstance(result["rows"][0]["bytes"], int)


def test_long_values_cannot_make_a_response_large(case: CaseDB) -> None:
    rows = [
        {"event_time": 1772359205 + i, "actor": f"{i:03d}" + "A" * 100_000} for i in range(200)
    ]
    _load(case, rows)

    for result in (_call(log_top, _TABLE, "actor", n=200), _call(log_rows, _TABLE, limit=200)):
        assert result["row_count"] == 200
        assert 0 < len(result["rows"]) < 200
        assert len(json.dumps(result)) < 2 * logtables._INLINE_CHARS
        assert any("more rows are in source" in note for note in result["notes"])
        # Everything that was left out of the response is in the indexed source.
        assert len(_source_lines(case, result["source"])) == 201


# --- fed by run_cloud_audit_logs ------------------------------------------------------

_CLOUDTRAIL = {
    "Records": [
        {
            "eventTime": "2026-11-10T13:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.9",
            "userAgent": "aws-cli/2.15",
            "eventID": "11111111-aaaa",
            "readOnly": False,
            "recipientAccountId": "123456789012",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::1:user/mallory",
                "accessKeyId": "AKIAEXAMPLE",
            },
        },
        {
            "eventTime": "2026-11-10T12:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.9",
            "userAgent": "aws-cli/2.15",
            "eventID": "22222222-bbbb",
            "readOnly": True,
            "errorCode": "AccessDenied",
            "additionalEventData": {"bytesTransferredOut": 2048},
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/mallory"},
        },
        {
            "eventTime": "2026-11-10T12:30:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "198.51.100.7",
            "eventID": "33333333-cccc",
            "errorMessage": "Failed authentication",
            "responseElements": {"ConsoleLogin": "Failure"},
            "userIdentity": {"type": "Root"},
        },
    ]
}
_GITHUB = {
    "@timestamp": 1731800000000,
    "action": "org.create_actions_secret",
    "actor": "mallory",
    "actor_ip": "203.0.113.9",
    "org": "acme",
    "user_agent": "GitHub CLI 2.40",
    "_document_id": "doc-1",
    "actor_location": {"country_code": "NL"},
}
_GCP = {
    "protoPayload": {
        "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
        "authenticationInfo": {"principalEmail": "mallory@example.com"},
        "requestMetadata": {"callerIp": "203.0.113.9", "callerSuppliedUserAgent": "gcloud/460"},
        "resourceName": "projects/-/serviceAccounts/ci@acme.iam.gserviceaccount.com",
        "status": {"code": 7, "message": "denied"},
    },
    "timestamp": "2026-11-10T12:01:00.5Z",
    "insertId": "ins-1",
}


@pytest.fixture
def cloud(case: CaseDB, tmp_path: Path) -> Path:
    root = tmp_path / "cloud"
    root.mkdir()
    (root / "cloudtrail.json").write_text(json.dumps(_CLOUDTRAIL))
    (root / "github.json").write_text(json.dumps([_GITHUB]))
    (root / "gcp.json").write_text(json.dumps([_GCP]))
    (root / "other.json").write_text(json.dumps({"timestamp": "2026-11-10T12:00:00Z", "x": 1}))
    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        result = _call(run_cloud_audit_logs, str(root))
    assert result["results"]["log_types"]["aws"]["log_table"] == "cloudlog.aws"
    assert "log_table" not in result["results"]["log_types"]["generic"]
    return root


def test_cloud_audit_events_are_loaded_as_rows_beside_the_text(case: CaseDB, cloud: Path) -> None:
    listed = {t["table"]: t for t in _call(list_log_tables)["tables"]}

    # A generic JSON log has a time and nothing to count on: text only.
    assert sorted(listed) == ["cloudlog.aws", "cloudlog.gcp", "cloudlog.github"]
    assert listed["cloudlog.aws"]["rows"] == 3
    assert listed["cloudlog.aws"]["loaded_from"] == [{"source_path": str(cloud), "rows": 3}]

    aws = _call(log_rows, "cloudlog.aws")["rows"]
    assert aws[0] == {
        "time": "2026-11-10T12:00:00Z",
        "actor": "arn:aws:iam::1:user/mallory",
        "src_ip": "203.0.113.9",
        "action": "s3.amazonaws.com:GetObject",
        "target": "us-east-1",
        "status": "AccessDenied",
        "user_agent": "aws-cli/2.15",
        "bytes": 2048,
        "event_id": "22222222-bbbb",
        "identity_type": "IAMUser",
        "read_only": "true",
        "source": "cloudlog.aws",
        "line": 1,
    }
    # A failed console login has an errorMessage and no errorCode.
    assert [row["status"] for row in aws] == ["AccessDenied", "Failure", "Success"]
    assert aws[2]["session_id"] == "AKIAEXAMPLE" and aws[2]["account"] == "123456789012"
    # Each row's line is its event's line in the indexed text.
    text_lines = _source_lines(case, "cloudlog.aws")
    for row in aws:
        assert row["event_id"] in text_lines[row["line"] - 1]

    (github,) = _call(log_rows, "cloudlog.github")["rows"]
    assert (github["user_agent"], github["country"], github["event_id"]) == (
        "GitHub CLI 2.40",
        "NL",
        "doc-1",
    )
    (gcp,) = _call(log_rows, "cloudlog.gcp")["rows"]
    assert (gcp["time"], gcp["status"], gcp["user_agent"], gcp["event_id"]) == (
        "2026-11-10T12:01:00Z",
        "7",
        "gcloud/460",
        "ins-1",
    )


def test_a_forced_cloud_log_rerun_does_not_double_the_counts(case: CaseDB, cloud: Path) -> None:
    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        _call(run_cloud_audit_logs, str(cloud), force=True)

    result = _call(log_top, "cloudlog.aws", "src_ip")

    assert result["rows_in_table"] == 3
    assert _counts(result, "src_ip") == {"203.0.113.9": 2, "198.51.100.7": 1}


def _run(path: Path | str) -> dict[str, Any]:
    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        found: dict[str, Any] = _call(run_cloud_audit_logs, str(path))["results"]["log_types"]
    return found


@pytest.mark.parametrize(
    ("first", "second", "second_is_covered"),
    [
        ("aws", "aws/2024-05", True),  # what the planner lists: a directory and one inside it
        ("aws/2024-05", "aws", False),
        ("aws", "aws/2024-05/trail-b.json", True),
        ("aws/2024-05/trail-b.json", "aws", False),
        ("aws", "aws/", False),
        ("aws", "aws/2024-05/..", False),
    ],
)
def test_cloud_logs_reached_through_overlapping_paths_are_counted_once(
    case: CaseDB, tmp_path: Path, first: str, second: str, second_is_covered: bool
) -> None:
    records = _CLOUDTRAIL["Records"]
    inner = tmp_path / "aws" / "2024-05"
    inner.mkdir(parents=True)
    (tmp_path / "aws" / "trail-a.json").write_text(json.dumps({"Records": records[:2]}))
    (inner / "trail-b.json").write_text(json.dumps({"Records": records[2:]}))

    _run(f"{tmp_path}/{first}")
    again = _run(f"{tmp_path}/{second}")["aws"]

    assert again["log_table"] == "cloudlog.aws"
    assert ("log_table_note" in again) is second_is_covered
    if second_is_covered:
        assert f"{tmp_path}/{first}" in again["log_table_note"]
    result = _call(log_top, "cloudlog.aws", "src_ip")
    assert (result["rows_in_table"], result["rows_matched"]) == (3, 3)
    assert _counts(result, "src_ip") == {"203.0.113.9": 2, "198.51.100.7": 1}
    (table,) = _call(list_log_tables)["tables"]
    assert len(table["loaded_from"]) == 1


@pytest.mark.parametrize("file_first", [False, True])
def test_a_file_the_directory_read_skips_is_neither_covered_nor_replaced_by_it(
    case: CaseDB, tmp_path: Path, file_first: bool
) -> None:
    """A directory is searched for JSON suffixes; a file named itself is read whatever its own."""
    records = _CLOUDTRAIL["Records"]
    logs = tmp_path / "aws"
    logs.mkdir()
    (logs / "trail.json").write_text(json.dumps({"Records": records[:2]}))
    (logs / "trail.log").write_text(json.dumps({"Records": records[2:]}))

    for path in (logs / "trail.log", logs) if file_first else (logs, logs / "trail.log"):
        assert "log_table_note" not in _run(path)["aws"]
    _run(f"{logs}/../aws/trail.log")  # the same file again: its rows are replaced

    result = _call(log_top, "cloudlog.aws", "src_ip")
    assert (result["rows_in_table"], result["rows_matched"]) == (3, 3)


def test_json_that_is_no_log_is_named_and_counts_against_no_table(
    case: CaseDB, tmp_path: Path
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "trail.json").write_text(json.dumps(_CLOUDTRAIL))
    (logs / "tags.json").write_text(json.dumps(["prod", "eu", "tier-1"]))
    (logs / "count.json").write_text("42")

    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        problems = _call(run_cloud_audit_logs, str(logs))["results"]["files_with_problems"]

    assert problems == {
        str(logs / "count.json"): "JSON values that are not objects: 1; events read: 0",
        str(logs / "tags.json"): "JSON values that are not objects: 3; events read: 0",
    }
    result = _call(log_top, "cloudlog.aws", "actor")
    assert (result["rows_in_table"], result["rows_not_parsed"], result["notes"]) == (3, 0, [])


def test_damaged_cloud_log_files_and_records_that_are_no_event_count_as_not_parsed(
    case: CaseDB, tmp_path: Path
) -> None:
    one, two, three = _CLOUDTRAIL["Records"]
    (tmp_path / "odd.json").write_text(json.dumps({"Records": [one, "not an event", 7, None]}))
    (tmp_path / "cut.json").write_text(json.dumps([two, three])[:-40])
    # Nothing of this one can be read, so its log type is unknown: every table says so.
    (tmp_path / "gone.json").write_text(json.dumps(_CLOUDTRAIL)[:-40])
    (tmp_path / "github.json").write_text(json.dumps([_GITHUB]))

    _run(tmp_path)

    listed = {t["table"]: t for t in _call(list_log_tables)["tables"]}
    assert (listed["cloudlog.aws"]["rows"], listed["cloudlog.aws"]["rows_not_parsed"]) == (2, 5)
    assert listed["cloudlog.github"]["rows_not_parsed"] == 1
    result = _call(log_top, "cloudlog.aws", "actor")
    assert result["rows_not_parsed"] == 5
    assert any("at least 5 records" in note for note in result["notes"])


# --- registration and guidance --------------------------------------------------------

_TOOLS = ("list_log_tables", "log_top", "log_histogram", "log_rows")


def _can_call(role: Role) -> set[str]:
    return {name.removeprefix("mcp__mulder__") for name in get_tools_for_role(role)}


def test_the_tools_go_to_the_roles_the_netflow_pivots_have() -> None:
    for role in Role:
        expected = role in (Role.EXTRACT_ANALYST, Role.CROSS_EXECUTOR)
        assert (set(_TOOLS) <= _can_call(role)) is expected, role
        assert expected or not set(_TOOLS) & _can_call(role), role


def test_guidance_names_the_tools_to_roles_that_can_reach_them() -> None:
    prompt_dir = Path(prompts.__file__).parent
    analyst = (prompt_dir / "extract_analyst.md").read_text(encoding="utf-8")
    planner = (prompt_dir / "cross_system_planner.md").read_text(encoding="utf-8")

    for tool in _TOOLS:
        assert tool in analyst, tool
    for tool in ("log_top", "log_histogram", "log_rows"):
        assert tool in planner, tool
    # The cross-system planner cannot list log tables itself; it reads source names.
    assert "list_log_tables" not in _can_call(Role.CROSS_PLANNER)
    assert "list_sources" in _can_call(Role.CROSS_PLANNER)
    assert "list_log_tables" not in planner and "list_sources" in planner
    # What a count does not establish is said where the model reads it.
    for fn in (log_top, log_histogram):
        assert "this table" in (inspect.getdoc(fn) or "")


def test_queries_run_on_the_container_sqlite() -> None:
    """Ubuntu 22.04 ships SQLite 3.37: no ``->`` or ``->>``, which arrived in 3.38."""
    assert "->" not in inspect.getsource(logtable).replace(") -> ", "")
