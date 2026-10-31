"""Hostile or unexpected nfdump output: out-of-range timestamps, unrecognised stdout, versions.

Flow timestamps come from evidence, so a crafted capture can carry any value; the parsers drop
such records (with a warning) before any datetime conversion. An rc-0 run whose stdout carries
neither a table header nor the no-match sentinel fails instead of indexing nothing as a success.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from mulder.server.tools.netflow import core, tools
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


# ---------------------------------------------------------------------------
# unrecognised output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stdout", "fmt", "ok"),
    [
        (f"{_RAW_HEADER}\n{_RAW_GOOD}\n", core.RAW_FMT, True),
        (f"{_RAW_HEADER}\n{core.NO_MATCH}\n", core.RAW_FMT, True),
        (f"{core.NO_MATCH}\n", core.RAW_FMT, True),
        (f"{core.NO_MATCH}\n", core.STAT_FMT, True),
        (f"{_STAT_HEADER}\n{_STAT_GOOD}\n", core.STAT_FMT, True),
        ("", core.RAW_FMT, False),
        ("", core.STAT_FMT, False),
        (f"{_STAT_HEADER}\n{_STAT_GOOD}\n", core.RAW_FMT, False),  # wrong table for the mode
        ("Date first seen,Duration,Proto\n2001-02-03,0.0,TCP\n", core.RAW_FMT, False),
        (fixture_text("dash_I.txt"), None, True),
        ("", None, False),
    ],
)
def test_recognised_output(stdout: str, fmt: str | None, ok: bool) -> None:
    assert core.recognised_output(stdout, fmt) is ok


@pytest.mark.parametrize("stdout", ["", "Date first seen,Duration,Proto\n"])
@pytest.mark.parametrize("tool", ["run_netflow_top", "run_netflow_query"])
def test_unrecognised_stdout_at_rc0_fails_and_indexes_nothing(
    nf_env: Env, tool: str, stdout: str
) -> None:
    day_dir = _single(nf_env)
    nf_env.fake.responder = lambda argv: None if "-I" in argv else stdout
    resp = nf_env.call(tool, evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "tool_failed"
    assert "without a recognised table header" in resp["error_message"]
    assert core.NFDUMP_VERIFIED_VERSION in resp["suggestion"]
    assert [
        s for s in nf_env.db.get_sources() if not s.source_name.startswith("netflow.progress.")
    ] == []


def test_analysis_with_unrecognised_stdout_writes_no_completion_marker(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.fake.responder = lambda argv: None if "-I" in argv else ""
    resp = nf_env.call("run_netflow_analysis", evidence_path=str(day_dir))
    assert resp["status"] != "success"
    names = [s.source_name for s in nf_env.db.get_sources()]
    assert not any(n.startswith("netflow.complete.") for n in names)
    assert not any(n.startswith("netflow.analysis.") for n in names)


# ---------------------------------------------------------------------------
# nfdump version
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("banner", "error"),
    [
        ("nfdump: Version: 1.6.23\n", "nfdump 1.6.23 at /opt/nfdump/bin/nfdump is too old"),
        ("nfdump 1.7\n", "could not read the nfdump version"),
    ],
)
def test_old_or_unreadable_version_is_refused(nf_env: Env, banner: str, error: str) -> None:
    day_dir = _single(nf_env)
    nf_env.monkeypatch.setattr(tools, "_NFDUMP_VERSIONS", {})
    nf_env.fake.responder = lambda argv: banner if argv[1:] == ["-V"] else None
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "binary_missing"
    assert error in resp["error_message"]
    assert all(c.cmd[1:] == ["-V"] for c in nf_env.fake.calls)


def test_version_is_probed_once_per_binary(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.monkeypatch.setattr(tools, "_NFDUMP_VERSIONS", {})
    nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    nf_env.call("run_netflow_top", evidence_path=str(day_dir), n=5)
    probes = [c for c in nf_env.fake.calls if c.cmd[1:] == ["-V"]]
    assert len(probes) == 1
    assert tools._NFDUMP_VERSIONS[core.NFDUMP_BINARY] == (1, 7, 10)
