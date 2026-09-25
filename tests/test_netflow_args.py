"""Window parsing, file discovery / selection / staging, argv snapshots and the heavy-query guard.

What: ``parse_iso``/``parse_window`` accept the documented UTC forms only; ``select`` applies the
1-day lookbehind / 8-day lookahead with open ends and never overflows; ``discover`` admits files by
magic (rotation-named text file excluded, renamed file with magic kept, strays reported with the
right reason, non-candidates ignored silently); ``stage`` yields ``-r <file>`` or ``-R <nfsel_*>``
of zero-padded symlinks and removes the directory even on failure; every tool's argv matches the
documented snapshot (``prlimit`` prefix, ``-N -6 -q -o``, ``--`` then the filter last);
``subprocess`` is invoked with a list, ``TZ=UTC`` and no shell; the ``run_netflow_query`` memory
guard refuses
``-s record/<volume>`` and high-cardinality ``-A`` (including ``srcip4/32``-style masks) over > 3
files without a filter; digit-only strings are accepted for int parameters (the batch path skips
pydantic coercion); a plain and a masked key on one side of an aggregate are refused.
When: hermetic (fake subprocess, tmp trees).
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import os
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mulder.server.tools.netflow import core
from mulder.server.tools.netflow.core import NetflowArgError, NfFile
from tests.netflow_harness import PRLIMIT_PREFIX, Env, FakeCall, make_tree, nfcapd, yday

NFDUMP = core.NFDUMP_BINARY
_RFC1918_SRC = "(src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16)"
_RFC1918_DST = "(dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16)"
_ONE_DAY = {"t_start": "2001-03-04T00:00:00", "t_end": "2001-03-04T23:59:59"}
_ONE_DAY_CLAUSE = "first seen <= 2001-03-04T23:59:59 and last seen >= 2001-03-04T00:00:00"


# ---------------------------------------------------------------------------
# parse_iso / parse_window / window_clause
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ("2001-03-04T12:38:00", datetime(2001, 3, 4, 12, 38, 0)),
        ("2001-03-04T12:38:00Z", datetime(2001, 3, 4, 12, 38, 0)),
        ("2001-03-04T12:38:00+00:00", datetime(2001, 3, 4, 12, 38, 0)),
        ("2001-03-04T12:38:00+0000", datetime(2001, 3, 4, 12, 38, 0)),
        ("2001-03-04T12:38:00-00:00", datetime(2001, 3, 4, 12, 38, 0)),
        ("2001-03-04 12:38:00", datetime(2001, 3, 4, 12, 38, 0)),
        ("2001-03-04T12:38:00.123", datetime(2001, 3, 4, 12, 38, 0, 123000)),
        ("2001-03-04T12:38:00.123456Z", datetime(2001, 3, 4, 12, 38, 0, 123456)),
        ("  2001-03-04T12:38:00  ", datetime(2001, 3, 4, 12, 38, 0)),
    ],
)
def test_parse_iso_accepts_utc_forms(text: str, expected: datetime) -> None:
    got = core.parse_iso(text)
    assert got == expected
    assert got.tzinfo is None


@pytest.mark.parametrize(
    "text",
    [
        "2001-03-04T12:38:00+05:00",
        "2001-03-04T12:38:00-01:00",
        "2001-03-04T12:38:00+0530",
        "2001-03-04",
        "2001-03-04T12:38",
        "yesterday",
        "2001-13-01T00:00:00",
        "2001-03-32T00:00:00",
        "983709482",
        "",
        "\u0662\u0660\u0660\u0661-03-04T12:38:00",  # Arabic-Indic year: ASCII only
        "2001-03-04T12:38:00\x00",
    ],
)
def test_parse_iso_rejects(text: str) -> None:
    with pytest.raises(NetflowArgError) as ei:
        core.parse_iso(text, "t_start")
    assert "t_start" in str(ei.value)
    assert ei.value.suggestion is not None and "UTC" in ei.value.suggestion


def test_parse_window_open_ends_and_order() -> None:
    assert core.parse_window(None, None) == (None, None)
    assert core.parse_window("", "") == (None, None)
    ts, te = core.parse_window("2001-03-04T12:38:00", None)
    assert ts == datetime(2001, 3, 4, 12, 38) and te is None
    ts, te = core.parse_window(None, "2001-03-04T12:38:20")
    assert ts is None and te == datetime(2001, 3, 4, 12, 38, 20)
    assert core.parse_window("2001-03-04T12:38:00", "2001-03-04T12:38:00") == (
        datetime(2001, 3, 4, 12, 38),
        datetime(2001, 3, 4, 12, 38),
    )
    with pytest.raises(NetflowArgError) as ei:
        core.parse_window("2001-03-05T00:00:00", "2001-03-04T00:00:00")
    assert "t_start is after t_end" in str(ei.value)


def test_window_clause_is_active_in_window_and_t_separated() -> None:
    ts, te = core.parse_window("2001-03-04T12:38:00", "2001-03-04T12:38:20")
    assert core.window_clause(ts, te) == (
        "first seen <= 2001-03-04T12:38:20 and last seen >= 2001-03-04T12:38:00"
    )
    assert core.window_clause(ts, None) == "last seen >= 2001-03-04T12:38:00"
    assert core.window_clause(None, te) == "first seen <= 2001-03-04T12:38:20"
    assert core.window_clause(None, None) == ""
    assert core.window_label(ts, te) == "2001-03-04T12:38:00..2001-03-04T12:38:20"
    assert core.window_label(ts, None) == "2001-03-04T12:38:00..*"
    assert core.window_label(None, te) == "*..2001-03-04T12:38:20"
    assert core.window_label(None, None) == "none"


def test_tool_rejects_bad_windows_before_any_subprocess(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    for kwargs in (
        {"t_start": "2001-03-05T00:00:00", "t_end": "2001-03-04T00:00:00"},
        {"t_start": "2001-03-04T12:38:00+05:00"},
        {"t_end": "2001-03-04 12:38:00 UTC"},
        {"t_start": "2001-03-04"},
    ):
        resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir), **kwargs)
        assert resp["status"] == "error", kwargs
        assert resp["error_type"] == "invalid_argument", kwargs
        assert "nfdump_argv" not in resp
    assert nf_env.fake.calls == []


# ---------------------------------------------------------------------------
# select
# ---------------------------------------------------------------------------


def _files(
    days: range, undated: tuple[str, ...] = ("renamed", "nfcapd.current.99")
) -> list[NfFile]:
    files = [
        NfFile(
            path=Path(f"/e/nfcapd.{yday(d)}0000"),
            day=date(2001, 1, 1) + timedelta(days=d - 1),
            size=64,
        )
        for d in days
    ]
    files += [NfFile(path=Path(f"/e/{n}"), day=None, size=64) for n in undated]
    return files


def _dated(selected: list[NfFile]) -> list[int]:
    return [f.day.timetuple().tm_yday for f in selected if f.day]


def test_select_lookbehind_1_lookahead_8() -> None:
    # A record is written when it expires; LOOKAHEAD_DAYS = 8 covers exporters whose active
    # timeout is up to 7 days, plus one rotation day.
    assert core.LOOKAHEAD_DAYS == 8 and core.LOOKBEHIND_DAYS == 1
    files = _files(range(48, 76))
    ts, te = core.parse_window(_ONE_DAY["t_start"], _ONE_DAY["t_end"])
    sel = core.select(files, ts, te)
    assert _dated(sel) == list(range(62, 72))
    assert len(sel) == 10 + 2  # undated files always kept
    # a one-hour pivot reads the same 10 files
    ts, te = core.parse_window("2001-03-04T12:37:00", "2001-03-04T13:37:00")
    assert _dated(core.select(files, ts, te)) == list(range(62, 72))
    # a record still active at the end of the window and expired by a 7-day active timeout
    # can land in the file dated 8 days later (one rotation day on top)
    ts, te = core.parse_window("2001-03-04T23:51:00", "2001-03-04T23:59:59")
    assert 71 in _dated(core.select(files, ts, te))


def test_select_single_bounds_and_none() -> None:
    files = _files(range(48, 76))
    assert _dated(core.select(files, core.parse_iso("2001-03-15T00:00:00"), None)) == [73, 74, 75]
    assert _dated(core.select(files, None, core.parse_iso("2001-02-17T00:00:00"))) == list(
        range(48, 57)
    )
    assert core.select(files, None, None) == files
    assert (
        len(core.select(files, core.parse_iso("2001-03-28T00:00:00"), None)) == 2
    )  # undated only


def test_select_extreme_dates_never_overflow() -> None:
    files = _files(range(48, 76))
    assert core.select(files, core.parse_iso("0001-01-01T00:00:00"), None) == files
    assert core.select(files, None, core.parse_iso("9999-12-31T23:59:59")) == files
    assert (
        core.select(
            files, core.parse_iso("0001-01-01T00:00:00"), core.parse_iso("9999-12-31T23:59:59")
        )
        == files
    )


def test_window_selecting_no_file_is_indexed_empty_without_nfdump(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), t_start="2001-03-28T00:00:00"
    )
    assert resp["status"] == "indexed_empty"
    assert resp["files_scanned"] == 0 and resp["file_range"] == []
    assert any("nothing was read" in w for w in resp["warnings"])
    assert nf_env.fake.calls == []


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


def _messy_tree(root: Path) -> Path:
    day_dir = make_tree(root, days=range(62, 65), strays=True)
    nfcapd(day_dir, "nfcapd.txt")  # non-digit suffix: not a candidate, never sniffed
    (day_dir / "README.md").write_text("hi\n")
    nfcapd(day_dir, "renamed")
    nfcapd(day_dir, "nfcapd.current.99")
    nfcapd(day_dir, "nfcapd.200103040000.bak")
    os.symlink(day_dir / "nfcapd.200103040000", day_dir / "link")
    return day_dir


def test_discover_admits_by_magic_and_reports_strays(tmp_path: Path) -> None:
    day_dir = _messy_tree(tmp_path)
    files, excluded = core.discover(day_dir.parent.parent.parent)  # edge-router/
    kept = [f.path.name for f in files]
    assert kept == [
        "nfcapd.200103030000",
        "nfcapd.200103040000",
        "nfcapd.200103050000",
        "nfcapd.current.99",
        "renamed",
    ]
    assert {Path(e.path).name: e.reason for e in excluded} == {
        "zero-length": "empty",
        "nfcapd.200103035555": "no nfdump magic",
        "link": "symlink",
    }
    assert [f.day for f in files][:3] == [date(2001, 3, 3), date(2001, 3, 4), date(2001, 3, 5)]
    assert all(f.day is None for f in files[3:])
    assert all(f.size == 64 for f in files)


def test_discover_single_file_and_empty_dir(tmp_path: Path) -> None:
    f = nfcapd(tmp_path / "d", day="20010304")
    files, excluded = core.discover(f)
    assert [x.path for x in files] == [f] and excluded == []
    (tmp_path / "empty").mkdir()
    assert core.discover(tmp_path / "empty") == ([], [])
    text = tmp_path / "d" / "nfcapd.200103045555"
    text.write_text("not a netflow file\n")
    files, excluded = core.discover(text)
    assert files == [] and [e.reason for e in excluded] == ["no nfdump magic"]


def test_tool_reports_files_excluded_and_scans_only_admitted(nf_env: Env) -> None:
    day_dir = _messy_tree(nf_env.evidence_root)
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir.parent.parent.parent))
    assert resp["status"] == "success", resp
    assert resp["files_scanned"] == 5
    assert resp["file_range"] == ["nfcapd.200103030000", "renamed"]
    assert {Path(e["path"]).name: e["reason"] for e in resp["files_excluded"]} == {
        "zero-length": "empty",
        "nfcapd.200103035555": "no nfdump magic",
        "link": "symlink",
    }
    assert resp["note"] is None


def test_more_than_400_files_is_invalid_argument(nf_env: Env) -> None:
    d = nf_env.evidence_root / "many"
    for i in range(core.MAX_FILES + 1):
        nfcapd(d, f"nfcapd.20010217{i:04d}")
    resp = nf_env.call("run_netflow_top", evidence_path=str(d))
    assert resp["status"] == "error" and resp["error_type"] == "invalid_argument"
    assert "401" in resp["error_message"] and "subdirectory" in resp["suggestion"]
    assert nf_env.fake.calls == []


def test_exactly_400_files_runs(nf_env: Env) -> None:
    d = nf_env.evidence_root / "many"
    for i in range(core.MAX_FILES):
        nfcapd(d, f"nfcapd.20010217{i:04d}")
    resp = nf_env.call("run_netflow_top", evidence_path=str(d))
    assert resp["status"] == "success" and resp["files_scanned"] == 400


def test_more_than_20_exclusions_are_capped_with_note(nf_env: Env) -> None:
    d = nf_env.evidence_root / "strays"
    nfcapd(d, day="20010304")
    for i in range(25):
        (d / f"nfcapd.2001030455{i:02d}").write_text("x\n")
    resp = nf_env.call("run_netflow_top", evidence_path=str(d))
    assert resp["status"] == "success"
    assert len(resp["files_excluded"]) == 20
    assert resp["note"] == "25 entries excluded; first 20 listed"


# ---------------------------------------------------------------------------
# stage / timeout_for / file_range
# ---------------------------------------------------------------------------


def test_stage_single_file_uses_dash_r(tmp_path: Path) -> None:
    f = nfcapd(tmp_path, day="20010304")
    files, _ = core.discover(f)
    with core.stage(files) as read:
        assert read == ["-r", str(f)]


def test_stage_many_files_symlink_dir_removed_after(tmp_path: Path) -> None:
    day_dir = make_tree(tmp_path, days=range(62, 65), strays=False)
    files, _ = core.discover(day_dir)
    with core.stage(files) as read:
        assert read[0] == "-R"
        tmp = Path(read[1])
        assert tmp.name.startswith("nfsel_") and tmp.is_dir()
        assert not tmp.is_relative_to(day_dir)
        assert ":" not in read[1]
        assert sorted(os.listdir(tmp)) == ["000000", "000001", "000002"]
        assert [os.readlink(tmp / n) for n in sorted(os.listdir(tmp))] == [
            str(f.path) for f in files
        ]
        assert all((tmp / n).is_symlink() for n in os.listdir(tmp))
    assert not tmp.exists()


def test_stage_removes_dir_when_body_raises(tmp_path: Path) -> None:
    day_dir = make_tree(tmp_path, days=range(62, 65), strays=False)
    files, _ = core.discover(day_dir)
    with pytest.raises(RuntimeError), core.stage(files) as read:
        tmp = Path(read[1])
        raise RuntimeError("boom")
    assert not tmp.exists()


def test_timeout_for_and_file_range() -> None:
    assert core.timeout_for(_files(range(48, 49), ())) == 150
    assert core.timeout_for(_files(range(48, 76), ())) == 960
    assert core.timeout_for(_files(range(48, 76)) * 4) == 1800
    assert core.file_range([]) == []
    assert core.file_range(_files(range(48, 76))) == ["nfcapd.200102170000", "nfcapd.current.99"]


# ---------------------------------------------------------------------------
# argv snapshots (all six tools)
# ---------------------------------------------------------------------------


def _single(nf_env: Env) -> tuple[Path, Path]:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    return day_dir, day_dir / "nfcapd.200103040000"


def _read_R(call: FakeCall) -> list[str]:
    read = call.read_args
    assert read[0] == "-R" and Path(read[1]).name.startswith("nfsel_")
    return read


def test_argv_top_single_file(nf_env: Env) -> None:
    day_dir, f = _single(nf_env)
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    assert resp["status"] == "success"
    call = nf_env.fake.last
    assert call.cmd[: len(PRLIMIT_PREFIX)] == PRLIMIT_PREFIX
    assert call.nfdump_argv == [
        NFDUMP, "-r", str(f), "-s", "dstip/flows", "-n", "25", "-N", "-6", "-q", "-o", "csv",
        "--", "any",
    ]  # fmt: skip
    assert resp["nfdump_argv"] == call.cmd
    assert resp["filter_applied"] == "any"


def test_argv_top_split_egress_window_clamped_n(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    resp = nf_env.call(
        "run_netflow_top", evidence_path=str(day_dir), stat="dstport", order="bytes", n=999,
        direction="egress", protocol_split=True, **_ONE_DAY,
    )  # fmt: skip
    assert resp["status"] == "success"
    call = nf_env.fake.last
    read = _read_R(call)
    expected_filter = f"({_RFC1918_SRC} and not {_RFC1918_DST}) and {_ONE_DAY_CLAUSE}"
    assert call.nfdump_argv == [
        NFDUMP, *read, "-s", "dstport:p/bytes", "-n", "200", "-N", "-6", "-q", "-o", "csv", "--",
        expected_filter,
    ]  # fmt: skip
    assert resp["params_effective"]["n"] == 200
    assert resp["files_scanned"] == 10
    assert resp["file_range"] == ["nfcapd.200103030000", "nfcapd.200103120000"]
    assert resp["window"] == {"t_start": _ONE_DAY["t_start"], "t_end": _ONE_DAY["t_end"]}


def test_argv_top_or_filter_is_parenthesised_before_the_window(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    resp = nf_env.call(
        "run_netflow_top", evidence_path=str(day_dir), stat="srcip",
        filter="dst port 443 or dst port 80", **_ONE_DAY,
    )  # fmt: skip
    assert resp["status"] == "success"
    assert nf_env.fake.last.cmd[-1] == f"(dst port 443 or dst port 80) and {_ONE_DAY_CLAUSE}"


def test_argv_host_profile_two_passes(nf_env: Env) -> None:
    day_dir, f = _single(nf_env)
    resp = nf_env.call("run_netflow_host_profile", evidence_path=str(day_dir), host="10.0.2.37")
    assert resp["status"] == "success"
    out, inn = nf_env.fake.calls
    # table 0 (`<host>/flows`, exactly one row) carries the exact direction totals
    assert out.nfdump_argv == [
        NFDUMP, "-r", str(f), "-s", "srcip/flows", "-s", "dstport:p/flows", "-s", "dstip/flows",
        "-s", "dstip/bytes", "-n", "20", "-N", "-6", "-q", "-o", "csv", "--",
        "src ip 10.0.2.37",
    ]  # fmt: skip
    assert inn.nfdump_argv == [
        NFDUMP, "-r", str(f), "-s", "dstip/flows", "-s", "dstport:p/flows", "-s", "srcip/flows",
        "-s", "srcip/bytes", "-n", "20", "-N", "-6", "-q", "-o", "csv", "--",
        "dst ip 10.0.2.37",
    ]  # fmt: skip
    assert resp["nfdump_argv_passes"] == {"out": out.cmd, "in": inn.cmd}
    assert set(resp["passes"]) == {"out", "in"}
    assert resp["filter_applied"] == "src ip 10.0.2.37 | dst ip 10.0.2.37"


def test_argv_host_profile_window_and_n_clamped(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    resp = nf_env.call(
        "run_netflow_host_profile", evidence_path=str(day_dir), host="10.0.2.37", n=1,
        t_start="2001-03-14T00:00:00", t_end="2001-03-17T00:00:00",
    )  # fmt: skip
    assert resp["status"] == "success"
    out = nf_env.fake.calls[0].nfdump_argv
    assert out[out.index("-n") + 1] == "5"
    assert out[-1] == (
        "src ip 10.0.2.37 and first seen <= 2001-03-17T00:00:00 and "
        "last seen >= 2001-03-14T00:00:00"
    )
    assert resp["files_scanned"] == 4  # 03-13 .. 03-16


def test_argv_sweep(nf_env: Env) -> None:
    day_dir, f = _single(nf_env)
    resp = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    assert resp["status"] == "success"
    call = nf_env.fake.last
    assert call.nfdump_argv == [
        NFDUMP, "-r", str(f), "-A", "srcip,dstip,dstport,flags", "-s", "record/flows",
        "-n", "50000", "-N", "-6", "-q", "-o", "csv:%tsr,%ter,%sa,%da,%dp,%flg,%pkt,%byt,%fl",
        "--", f"proto tcp and flags S and dst port in [ 445 3389 ] and {_RFC1918_SRC} and "
        f"{_RFC1918_DST}",
    ]  # fmt: skip
    assert resp["params_effective"]["ports"] == [445, 3389]


def test_argv_sweep_defaults_syn_only_window(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    resp = nf_env.call(
        "run_netflow_sweep", evidence_path=str(day_dir), syn_only=True,
        internal_nets=["10.0.0.0/16"], **_ONE_DAY,
    )  # fmt: skip
    assert resp["status"] == "success"
    assert nf_env.fake.last.cmd[-1] == (
        "proto tcp and flags S and not flags A and dst port in [ 22 135 139 445 3389 5985 5986 ]"
        f" and (src net 10.0.0.0/16) and (dst net 10.0.0.0/16) and {_ONE_DAY_CLAUSE}"
    )
    assert resp["files_scanned"] == 10


def test_argv_pair_timeline(nf_env: Env) -> None:
    day_dir, f = _single(nf_env)
    resp = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="10.0.2.37",
        dst="203.0.113.77", dport=40519,
    )  # fmt: skip
    assert resp["status"] == "success"
    assert nf_env.fake.last.nfdump_argv == [
        NFDUMP, "-r", str(f), "-c", "20001", "-N", "-6", "-q", "-o", core.RAW_FMT, "--",
        "src ip 10.0.2.37 and dst ip 203.0.113.77 and dst port 40519",
    ]  # fmt: skip


def test_argv_pair_both_directions_proto_and_caps(nf_env: Env) -> None:
    day_dir, _ = _single(nf_env)
    resp = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="10.0.2.37",
        dst="203.0.113.77", both_directions=True, proto="tcp", max_records=10, **_ONE_DAY,
    )  # fmt: skip
    assert resp["status"] == "success"
    argv = nf_env.fake.last.nfdump_argv
    assert argv[argv.index("-c") + 1] == "101"  # max_records clamped to 100, +1 for truncation
    assert argv[-1] == (
        "((src ip 10.0.2.37 and dst ip 203.0.113.77) or "
        "(src ip 203.0.113.77 and dst ip 10.0.2.37)) and proto tcp and "
        f"{_ONE_DAY_CLAUSE}"
    )
    assert resp["params_effective"]["max_records"] == 100


def test_argv_pair_both_directions_puts_the_port_on_each_leg(nf_env: Env) -> None:
    """The reply leg carries dport as its source port, so the port clause goes on each leg."""
    day_dir, _ = _single(nf_env)
    resp = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="10.0.2.37",
        dst="203.0.113.77", dport=40519, both_directions=True, proto="tcp",
    )  # fmt: skip
    assert resp["status"] == "success"
    assert nf_env.fake.last.nfdump_argv[-1] == (
        "((src ip 10.0.2.37 and dst ip 203.0.113.77 and dst port 40519) or "
        "(src ip 203.0.113.77 and dst ip 10.0.2.37 and src port 40519)) and proto tcp"
    )
    assert resp["filter_applied"] == nf_env.fake.last.nfdump_argv[-1]
    assert core.validate_filter(resp["filter_applied"]) == resp["filter_applied"]
    # without both_directions the port stays a plain `dst port` clause on the one leg
    one_way = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="10.0.2.37",
        dst="203.0.113.77", dport=40519,
    )  # fmt: skip
    assert one_way["filter_applied"] == (
        "src ip 10.0.2.37 and dst ip 203.0.113.77 and dst port 40519"
    )


def test_argv_query_raw_orders(nf_env: Env) -> None:
    day_dir, f = _single(nf_env)
    nf_env.call("run_netflow_query", evidence_path=str(day_dir))
    assert nf_env.fake.last.nfdump_argv == [
        NFDUMP, "-r", str(f), "-O", "tstart", "-c", "101", "-N", "-6", "-q", "-o", core.RAW_FMT,
        "--", "any",
    ]  # fmt: skip
    nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="duration", limit=7)
    argv = nf_env.fake.last.nfdump_argv
    assert argv[argv.index("-O") : argv.index("-O") + 4] == ["-O", "duration", "-c", "8"]
    nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="bytes", limit=7)
    argv = nf_env.fake.last.nfdump_argv
    assert "-O" not in argv and "-c" not in argv
    assert argv[argv.index("-s") : argv.index("-s") + 4] == ["-s", "record/bytes", "-n", "8"]
    assert argv[argv.index("-o") + 1] == core.RAW_FMT


def test_argv_query_aggregated(nf_env: Env) -> None:
    day_dir, f = _single(nf_env)
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["srcip", "dstip", "dstport"],
        filter="src net 10.0.3.0/24 and dst net 10.0.8.0/24 and proto tcp and dst port 445",
    )  # fmt: skip
    assert resp["status"] == "success"
    assert nf_env.fake.last.nfdump_argv == [
        NFDUMP, "-r", str(f), "-A", "srcip,dstip,dstport", "-s", "record/flows", "-n", "101",
        "-N", "-6", "-q", "-o", "csv:%tsr,%ter,%sa,%da,%dp,%pkt,%byt,%bps,%bpp,%fl", "--",
        "src net 10.0.3.0/24 and dst net 10.0.8.0/24 and proto tcp and dst port 445",
    ]  # fmt: skip
    assert resp["params_effective"]["order"] == "flows"  # left-over tstart becomes flows

    nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["proto", "flags"],
        order="bytes", limit=500,
    )  # fmt: skip
    argv = nf_env.fake.last.nfdump_argv
    assert argv[argv.index("-A") : argv.index("-A") + 6] == [
        "-A", "proto,flags", "-s", "record/bytes", "-n", "501",
    ]  # fmt: skip
    assert argv[argv.index("-o") + 1] == "csv:%tsr,%ter,%pr,%flg,%pkt,%byt,%bps,%bpp,%fl"

    nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["srcip4/24", "dstip4/24"]
    )
    argv = nf_env.fake.last.nfdump_argv
    assert argv[argv.index("-A") + 1] == "srcip4/24,dstip4/24"
    assert argv[argv.index("-s") + 1] == "record/flows"
    assert argv[argv.index("-o") + 1] == "csv:%tsr,%ter,%sa,%da,%pkt,%byt,%bps,%bpp,%fl"
    assert "%flg" not in argv[argv.index("-o") + 1]


def test_argv_query_direction_and_window(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), filter="dst port 3128",
        direction="internal", **_ONE_DAY,
    )  # fmt: skip
    assert resp["status"] == "success"
    assert nf_env.fake.last.cmd[-1] == (
        f"dst port 3128 and ({_RFC1918_SRC} and {_RFC1918_DST}) and {_ONE_DAY_CLAUSE}"
    )
    assert resp["filter_applied"] == nf_env.fake.last.cmd[-1]


def test_argv_inventory_three_passes(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 65), strays=False)
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "success", resp
    calls = nf_env.fake.calls
    assert len(calls) == 4
    for c, name in zip(calls[:2], ["nfcapd.200103040000", "nfcapd.200103050000"], strict=True):
        assert c.nfdump_argv == [NFDUMP, "-I", "-r", str(day_dir / name)]
    read = _read_R(calls[2])
    assert calls[2].nfdump_argv == [
        NFDUMP, *read, "-s", "ip/flows", "-s", "dstport:p/flows", "-s", "srcip/bytes", "-s",
        "dstip/bytes", "-n", "50", "-N", "-6", "-q", "-o", "csv", "--", "any",
    ]  # fmt: skip
    assert calls[3].nfdump_argv == [
        NFDUMP, *read, "-A", "srcip4/24,dstip4/24", "-s", "record/flows", "-n", "50", "-N", "-6",
        "-q", "-o", core.SEG_FMT, "--", "any",
    ]  # fmt: skip
    assert calls[3].read_args == read  # both passes share one staging directory
    assert set(resp["passes"]) == {"I", "stat", "segment"}
    assert resp["nfdump_argv_passes"]["I"] == calls[0].cmd
    assert resp["nfdump_argv_passes"]["stat"] == calls[2].cmd
    assert resp["nfdump_argv_passes"]["segment"] == calls[3].cmd
    assert resp["nfdump_argv"] == calls[3].cmd


def test_argv_inventory_top_n_clamped(nf_env: Env) -> None:
    day_dir, _ = _single(nf_env)
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir), top_n=1)
    assert resp["params_effective"]["top_n"] == 5
    argv = nf_env.fake.calls[1].nfdump_argv
    assert argv[argv.index("-n") + 1] == "5"


# ---------------------------------------------------------------------------
# subprocess contract (every call, every tool)
# ---------------------------------------------------------------------------


def _all_tools_once(nf_env: Env, day_dir: Path, **window: str) -> list[dict[str, Any]]:
    calls: list[tuple[str, dict[str, Any]]] = [
        ("run_netflow_inventory", {}),
        ("run_netflow_top", {"stat": "srcip", "order": "flows"}),
        ("run_netflow_host_profile", {"host": "10.0.2.37"}),
        ("run_netflow_sweep", {"ports": [445, 3389]}),
        ("run_netflow_pair_timeline", {"src": "10.0.2.37", "dst": "203.0.113.77"}),
        (
            "run_netflow_query",
            {"aggregate": ["srcip", "dstip", "dstport"], "filter": "src net 10.0.3.0/24"},
        ),  # fmt: skip
    ]
    out = []
    for tool, kw in calls:
        kw2 = dict(kw)
        if tool != "run_netflow_inventory":
            kw2.update(window)
        resp = nf_env.call(tool, evidence_path=str(day_dir), **kw2)
        assert resp["status"] == "success", (tool, resp)
        out.append(resp)
    return out


def test_subprocess_is_argv_list_tz_utc_no_shell_no_preexec(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    _all_tools_once(nf_env, day_dir, **_ONE_DAY)
    assert len(nf_env.fake.calls) >= 6
    selected_10 = core.timeout_for(_files(range(62, 72), ()))  # windowed tools: 10 files -> 420 s
    all_files = core.timeout_for(_files(range(48, 76), ()))  # inventory ignores the window: 960 s
    for call in nf_env.fake.calls:
        assert isinstance(call.cmd, list) and all(isinstance(a, str) for a in call.cmd)
        assert call.cmd[: len(PRLIMIT_PREFIX)] == PRLIMIT_PREFIX
        assert call.kwargs["errors"] == "replace"  # no nfdump byte can raise UnicodeDecodeError
        assert "shell" not in call.kwargs
        assert "preexec_fn" not in call.kwargs
        assert call.kwargs["capture_output"] is True
        assert call.kwargs["text"] is True
        assert call.kwargs["check"] is False
        assert call.env["TZ"] == "UTC"
        assert isinstance(call.kwargs["timeout"], float) and call.timeout >= 1.0
        read = call.read_args
        if read[0] == "-R":
            assert Path(read[1]).name.startswith("nfsel_")
            assert not Path(read[1]).is_relative_to(nf_env.evidence_root)
            assert ":" not in read[1]
            budget = (
                all_files
                if "ip/flows" in call.cmd or "srcip4/24,dstip4/24" in call.cmd
                else (selected_10)
            )
            assert budget - 2 < call.timeout <= budget
        else:
            assert Path(read[1]).parent == day_dir and Path(read[1]).name.startswith("nfcapd.")
        argv = call.nfdump_argv
        if "-I" in argv:
            assert argv == [NFDUMP, "-I", "-r", read[1]]
            continue
        assert argv[-7:] == ["-N", "-6", "-q", "-o", argv[-3], "--", argv[-1]]
        assert argv[-3] in {"csv", core.RAW_FMT, core.SEG_FMT} or argv[-3].startswith("csv:%tsr")
        assert argv.index("-N") == len(argv) - 7
        assert str(day_dir) not in argv[-1]
        assert core.validate_filter(argv[-1]) == argv[-1]


def test_no_evidence_directory_reaches_nfdump(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    _all_tools_once(nf_env, day_dir)
    for call in nf_env.fake.calls:
        read = call.read_args
        for arg in call.cmd:
            assert arg != str(day_dir) and arg != str(nf_env.evidence_root)
            assert not arg.startswith(f"{day_dir}:")  # no dir/first:last range form
            if arg.startswith(f"{day_dir}/"):
                # only a single validated file after -r (the inventory's per-file -I pass)
                assert read == ["-r", arg] and call.nfdump_argv[1] == "-I"
        # 28 files are staged: every multi-file read goes through the private symlink dir
        assert read[0] == "-R" or call.nfdump_argv[1] == "-I"


def test_staging_dir_is_removed_after_every_call(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    seen: list[Path] = []
    nf_env.fake.hook = lambda argv: (
        seen.append(Path(argv[argv.index("-R") + 1])) if "-R" in argv else None
    )
    _all_tools_once(nf_env, day_dir)
    assert len(seen) >= 6
    for tmp in seen:
        assert not tmp.exists()


# ---------------------------------------------------------------------------
# heavy-query guard (run_netflow_query only)
# ---------------------------------------------------------------------------


def _assert_guard(resp: dict[str, Any], what: str, n: int) -> None:
    assert resp["status"] == "error" and resp["error_type"] == "invalid_argument", resp
    assert resp["error_message"].startswith(f"{what} over {n} files needs a filter")
    assert "<= 3 files" in resp["error_message"]
    assert "nfdump keeps every distinct key in memory" in resp["error_message"]
    assert "src net 192.0.2.0/24" in resp["suggestion"]
    assert "nfdump_argv" not in resp
    assert resp["files_scanned"] == n


def test_heavy_guard_volume_order_over_9_files(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="bytes", **_ONE_DAY)
    _assert_guard(resp, "order=bytes", 10)
    assert nf_env.fake.calls == []
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="pps")
    _assert_guard(resp, "order=pps", 28)
    assert nf_env.fake.calls == []


def test_heavy_guard_lifted_by_filter_or_small_window(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), order="bytes",
        filter="src net 10.0.3.0/24", **_ONE_DAY,
    )  # fmt: skip
    assert resp["status"] == "success" and resp["files_scanned"] == 10
    assert "record/bytes" in nf_env.fake.last.nfdump_argv
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), order="bytes",
        t_start="2001-03-15T00:00:00", t_end="2001-03-15T01:00:00",
    )  # fmt: skip
    assert resp["status"] == "success" and resp["files_scanned"] == 3
    assert "record/bytes" in nf_env.fake.last.nfdump_argv


@pytest.mark.parametrize(
    "filt", ["ipv4", "IPV6", "ipv4 or ipv6", "( ipv4 )", "any", "  ANY  and ipv4"]
)
def test_heavy_guard_treats_address_family_only_filters_as_any(nf_env: Env, filt: str) -> None:
    """``filter='ipv4'`` selects every IPv4 flow: over many files nfdump can die at the 4 GiB
    cap (SIGABRT) exactly as with ``any``, so the guard refuses it up front."""
    day_dir = nf_env.tree()
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), order="bytes", filter=filt, **_ONE_DAY
    )
    _assert_guard(resp, "order=bytes", 10)
    assert "any/ipv4/ipv6 alone" in resp["error_message"]
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["srcip", "dstip"],
        filter=filt, **_ONE_DAY,
    )  # fmt: skip
    _assert_guard(resp, "aggregate=srcip,dstip", 10)
    assert nf_env.fake.calls == []


@pytest.mark.parametrize(
    "filt", ["proto icmp", "not ipv4", "ipv4 and dst port 22", "flags S", "bytes > 1M"]
)
def test_heavy_guard_runs_with_any_narrowing_primitive(nf_env: Env, filt: str) -> None:
    """A protocol, port, flag, volume or negated primitive may narrow the key space; those
    queries run and a real out-of-memory abort is classified by the runner instead."""
    day_dir = nf_env.tree()
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), order="bytes", filter=filt, **_ONE_DAY
    )
    assert resp["status"] == "success", resp
    assert nf_env.fake.last.nfdump_argv[-1].startswith(f"{filt} and first seen <= ")
    assert core.is_unrestrictive_filter("ipv4 or ipv6")
    assert not core.is_unrestrictive_filter(filt)


def test_heavy_guard_high_cardinality_aggregates(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["srcip", "dstip"], **_ONE_DAY
    )
    _assert_guard(resp, "aggregate=srcip,dstip", 10)
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["srcport"], **_ONE_DAY
    )
    _assert_guard(resp, "aggregate=srcport", 10)
    # a /32 (or any mask >= /25) has per-host cardinality: it must not bypass the guard;
    # the error echoes the keys as written
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["srcip4/32", "dstip4/32"],
        **_ONE_DAY,
    )  # fmt: skip
    _assert_guard(resp, "aggregate=srcip4/32,dstip4/32", 10)
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["srcip", "dstip4/32"],
        **_ONE_DAY,
    )  # fmt: skip
    _assert_guard(resp, "aggregate=srcip,dstip4/32", 10)
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["srcip4/25", "dstip4/31"],
        **_ONE_DAY,
    )  # fmt: skip
    _assert_guard(resp, "aggregate=srcip4/25,dstip4/31", 10)
    assert nf_env.fake.calls == []
    for keys in (["srcip4/24", "dstip4/24"], ["dstport"], ["srcip", "dstport"], ["proto"],
                 ["srcip4/24", "dstip4/32"], ["srcip", "dstip4/24"]):  # fmt: skip
        resp = nf_env.call(
            "run_netflow_query", evidence_path=str(day_dir), aggregate=keys, **_ONE_DAY
        )
        assert resp["status"] == "success", keys
    assert not core.is_heavy_query(None, "tstart")
    assert not core.is_heavy_query(None, "duration")
    assert core.is_heavy_query(None, "bpp")
    assert core.is_heavy_query(["dstip", "srcip", "flags"], "flows")
    assert core.is_heavy_query(["srcip4/32", "dstip4/32"], "flows")
    assert core.is_heavy_query(["srcip4/25", "dstip"], "flows")
    assert not core.is_heavy_query(["srcip4/24", "dstip4/24"], "flows")
    assert not core.is_heavy_query(["srcip4/24", "dstip4/32"], "flows")


def test_query_argument_validation(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    bad: list[dict[str, Any]] = [
        {"aggregate": ["srcip; rm -rf /"]},
        {"aggregate": ["srcip4/33"]},
        {"aggregate": ["srcip", "srcip"]},
        {"aggregate": []},
        {"aggregate": ["proto"] * 6},
        {"order": "flows"},  # raw mode has no flows order
        {"aggregate": ["dstport"], "order": "tstart"},  # becomes flows: allowed
        {"direction": "sideways"},
        {"internal_nets": ["not-a-net"]},
        {"limit": "10"},  # a digit-only string is accepted (batch path)
        {"limit": "ten"},
        {"limit": "1e3"},
        {"limit": True},
        {"filter": "src ipp 1"},
        {"filter": "dst port \u0664\u0664\u0665"},  # Arabic-Indic digits
        {"filter": "dst port\u00a0445"},  # non-ASCII whitespace inside the text
    ]
    for kwargs in bad:
        resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), **kwargs)
        if kwargs in ({"aggregate": ["dstport"], "order": "tstart"}, {"limit": "10"}):
            assert resp["status"] == "success", kwargs
            if kwargs == {"limit": "10"}:
                assert resp["params_effective"]["limit"] == 10
            continue
        assert resp["status"] == "error", kwargs
        assert resp["error_type"] == "invalid_argument", kwargs
        assert "nfdump_argv" not in resp
    assert len(nf_env.fake.calls) == 2


@pytest.mark.parametrize(
    "keys",
    [
        ["srcip", "srcip4/24"],
        ["srcip4/24", "srcip"],
        ["dstip", "dstip4/16"],
        ["srcip4/24", "srcip4/16"],
        ["dstip4/8", "dstip4/24"],
        ["srcip4/32", "srcip"],
    ],
)
def test_aggregate_rejects_two_keys_on_one_address_side(nf_env: Env, keys: list[str]) -> None:
    """nfdump has ONE srcAddr/dstAddr column: `srcip` beside `srcip4/N` prints the masked network
    under a per-host row (or ignores the host key) and two masks exit 1."""
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), aggregate=keys)
    assert resp["status"] == "error" and resp["error_type"] == "invalid_argument", keys
    assert "conflicts with another" in resp["error_message"]
    assert "per host" in resp["suggestion"] and "per network" in resp["suggestion"]
    assert "nfdump_argv" not in resp and nf_env.fake.calls == []
    with pytest.raises(NetflowArgError):
        core.validate_agg_keys(keys)
    # one key per side is still fine in any combination
    assert core.validate_agg_keys(["srcip", "dstip4/24"]) == ["srcip", "dstip4/24"]
    assert core.validate_agg_keys(["srcip4/24", "dstip4/24"]) == ["srcip4/24", "dstip4/24"]
    assert core.validate_agg_keys(["dstip4/16", "proto", "srcip"]) == ["dstip4/16", "proto",
                                                                        "srcip"]  # fmt: skip


def test_other_tools_argument_validation(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    cases: list[tuple[str, dict[str, Any]]] = [
        ("run_netflow_top", {"stat": "record"}),
        ("run_netflow_top", {"order": "tstart"}),
        ("run_netflow_top", {"filter": "$(id)"}),
        ("run_netflow_host_profile", {"host": "not-an-address"}),
        ("run_netflow_host_profile", {"host": "10.0.2.37; ls"}),
        ("run_netflow_sweep", {"ports": [0]}),
        ("run_netflow_sweep", {"ports": [70000]}),
        ("run_netflow_sweep", {"ports": list(range(1, 18))}),
        ("run_netflow_sweep", {"ports": ["445a"]}),
        ("run_netflow_sweep", {"ports": ["-1"]}),
        ("run_netflow_sweep", {"ports": [True]}),
        ("run_netflow_sweep", {"ports": ["\u00b2"]}),  # superscript two: not an ASCII digit
        ("run_netflow_pair_timeline", {"src": "a", "dst": "10.0.2.37"}),
        ("run_netflow_pair_timeline", {"src": "10.0.2.37", "dst": "203.0.113.77", "dport": 0}),
        (
            "run_netflow_pair_timeline",
            {"src": "10.0.2.37", "dst": "203.0.113.77", "dport": "abc"},
        ),  # fmt: skip
        ("run_netflow_pair_timeline", {"src": "10.0.2.37", "dst": "192.0.2.99", "proto": "sctp"}),
        ("run_netflow_inventory", {"top_n": "fifty"}),
    ]
    for tool, kwargs in cases:
        resp = nf_env.call(tool, evidence_path=str(day_dir), **kwargs)
        assert resp["status"] == "error" and resp["error_type"] == "invalid_argument", (
            tool, kwargs, resp,
        )  # fmt: skip
        assert "nfdump_argv" not in resp
        assert resp["tool"] == tool
    assert nf_env.fake.calls == []


def test_int_parameters_are_clamped_and_echoed(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call(
        "run_netflow_sweep", evidence_path=str(day_dir), min_targets=1, n=500,
        burst_window_s=0, max_inline_rows=999,
    )  # fmt: skip
    assert resp["status"] == "success"
    assert resp["params_effective"] == {
        "ports": [22, 135, 139, 445, 3389, 5985, 5986], "min_targets": 2, "n": 100,
        "syn_only": False, "burst_window_s": 1, "internal_nets": list(core.DEFAULT_INTERNAL_NETS),
        "t_start": None, "t_end": None, "max_inline_rows": 100,
    }  # fmt: skip
    resp = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="10.0.2.37",
        dst="203.0.113.77", max_records=99_999, index_records=-5,
    )  # fmt: skip
    assert resp["params_effective"]["max_records"] == 50_000
    assert resp["params_effective"]["index_records"] == 0


def test_digit_strings_are_accepted_for_int_parameters(nf_env: Env) -> None:
    """run_parallel / start_extraction_batch call tools with the planner's JSON as-is (no pydantic
    coercion), so dport="445" or limit="100" must behave like the direct MCP path."""
    assert core.validate_port("445", "dport") == 445
    assert core.validate_port(" 22 ", "dport") == 22
    assert core.clamp("100", 1, 500) == 100
    assert core.clamp("999", 1, 500) == 500
    for bad in ("abc", "-1", "1.5", "", "\u00b2", "\u0664\u0664\u0665"):
        with pytest.raises(NetflowArgError):
            core.validate_port(bad, "dport")
        with pytest.raises(NetflowArgError):
            core.clamp(bad, 1, 500)
    with pytest.raises(NetflowArgError):
        core.validate_port(True, "dport")
    with pytest.raises(NetflowArgError):
        core.clamp(True, 1, 500)
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="10.0.2.37",
        dst="203.0.113.77", dport="40519", max_records="200", index_records="5",
    )  # fmt: skip
    assert resp["status"] == "success", resp
    assert resp["params_effective"]["dport"] == 40519
    assert resp["params_effective"]["max_records"] == 200
    assert nf_env.fake.last.nfdump_argv[-1].endswith("dst port 40519")
    resp = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=["445", "3389"],
                       n="10")  # fmt: skip
    assert resp["status"] == "success" and resp["params_effective"]["ports"] == [445, 3389]
    assert resp["params_effective"]["n"] == 10
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir), top_n="50")
    assert resp["status"] == "success" and resp["params_effective"]["top_n"] == 50
