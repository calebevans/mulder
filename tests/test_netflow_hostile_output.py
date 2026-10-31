"""Hostile nfdump output: flow timestamps out of range.

Flow timestamps come from evidence, so a crafted capture can carry any value; the parsers drop
such records (with a warning) before any datetime conversion.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from mulder.server.tools.netflow import core
from tests.conftest import Env, fixture_text

_RAW_HEADER = "firstSeen,lastSeen,proto,srcAddr,srcPort,dstAddr,dstPort,flags,packets,bytes"
_RAW_GOOD = "981210127.000,981210127.000,6,10.0.3.44,40100,10.0.8.21,445,......S.,1,52"
_STAT_HEADER = "ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,ipps,ibps,ibpp"
_STAT_GOOD = (
    "2001-02-03 14:22:07,2001-02-03 14:22:29,22.570,any,10.0.3.44,"
    "74,37.6,130,0.4,13334,0.1,5,4726,102"
)


def _single(nf_env: Env) -> Path:
    return nf_env.tree(days=range(63, 64), strays=False)


# ---------------------------------------------------------------------------
# timestamp bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("first", ["1e20", "-5", "nan", "inf", "4102444801"])
def test_flow_csv_drops_out_of_range_timestamps(first: str) -> None:
    bad = f"{first},981210127.000,6,10.0.3.44,40100,10.0.8.21,445,......S.,1,52"
    parsed = core.parse_flow_csv("\n".join([_RAW_HEADER, _RAW_GOOD, bad]))
    assert len(parsed.rows) == 1 and parsed.dropped == 1
    assert parsed.warnings == ["1 rows with out-of-range timestamps dropped"]


@pytest.mark.parametrize(
    "ts", ["2200-01-01 00:00:00", "1969-12-31 23:59:59", "2001-13-40 00:00:00", "garbage"]
)
def test_stat_csv_drops_out_of_range_timestamps(ts: str) -> None:
    bad = _STAT_GOOD.replace("2001-02-03 14:22:07", ts, 1)
    parsed = core.parse_stat_csv("\n".join([_STAT_HEADER, _STAT_GOOD, bad]), [True])
    assert len(parsed.tables[0].rows) == 1 and parsed.dropped == 1


def test_dash_i_out_of_range_first_last_read_as_unknown() -> None:
    text = fixture_text("dash_I.txt").replace("First: 981160567", "First: 99999999999999")
    info = core.parse_dash_i(text.replace("Last: 981254910", "Last: -1"))
    assert info["First"] == 0 and info["Last"] == 0 and info["Flows"] == 197


@pytest.mark.parametrize("epoch", [1e300, -1e300, float("nan"), float("inf")])
def test_converters_never_raise(epoch: float) -> None:
    assert len(core.iso_s(epoch)) == 19
    assert len(core.iso_ms(epoch)) == 23


def _rec(first: float, last: float) -> core.FlowRec:
    return core.FlowRec(first=first, last=last)


def test_active_days_merges_overlapping_spans() -> None:
    day = 86400.0
    rows = [
        _rec(0, 0),  # day 0
        _rec(day * 2 + 5, day * 4),  # days 2..4
        _rec(day * 3, day * 3 + 1),  # inside 2..4
        _rec(day * 10, day * 9),  # last before first: no active day
    ]
    assert core._active_days(rows) == 4


def test_active_days_is_not_linear_in_span_length() -> None:
    rows = [_rec(core.EPOCH_MIN, core.EPOCH_MAX)] * 1000
    t0 = time.monotonic()
    assert core._active_days(rows) == int(core.EPOCH_MAX // 86400) + 1
    assert time.monotonic() - t0 < 1.0


def test_query_drops_a_hostile_row_and_reports_it(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    bad = _RAW_GOOD.replace("981210127.000,981210127.000", "1e20,1e20", 1)
    nf_env.fake.stdout = "\n".join([_RAW_HEADER, _RAW_GOOD, bad]) + "\n"
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir))
    assert resp["status"] == "success"
    assert resp["rows_dropped"] == 1
    assert "1 rows with out-of-range timestamps dropped" in resp["warnings"]
