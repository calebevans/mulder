"""Branches that are easy to leave untested.

What: zero-match runs in the aggregation modes, where nfdump 1.7.10 prints only the sentinel and
no header; the inventory's pass-I budget exhaustion and its binary-missing / OSError exits; a
second-pass failure in the inventory and in the host profile (the staging directory is removed on
the way out); the ``srcport`` aggregation key's row text; malformed numeric / address csv lines and
a stat row before any header; a FIFO, an invalid-date name and an unreadable entry in discover().
When: hermetic (fake subprocess, tmp trees).
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from mulder.server.tools.netflow import core, tools
from mulder.server.tools.netflow.core import FlowRec
from tests.netflow_harness import Env, fake_which, fixture_text, nfcapd

# ---------------------------------------------------------------------------
# zero-match aggregation modes: sentinel only, no header (tests/fixtures/netflow/README.md)
# ---------------------------------------------------------------------------


def test_zero_match_aggregate_and_volume_modes_are_indexed_empty(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    calls: list[tuple[str, dict[str, Any]]] = [
        ("run_netflow_query", {"filter": "src ip 192.0.2.99", "aggregate": ["srcip", "dstport"]}),
        ("run_netflow_query", {"filter": "src ip 192.0.2.99", "order": "bytes"}),
        ("run_netflow_sweep", {"internal_nets": ["192.0.2.99/32"]}),
        ("run_netflow_top", {"filter": "src ip 192.0.2.99", "stat": "dstport"}),
    ]
    for tool, kw in calls:
        resp = nf_env.call(tool, evidence_path=str(day_dir), **kw)
        assert resp["status"] == "indexed_empty", (tool, resp)
        assert resp["row_count"] == 0 and resp["rows_dropped"] == 0 and resp["warnings"] == []
        assert resp["line_count"] == 0
    assert nf_env.fake.calls[0].cmd[-1].startswith("src ip 192.0.2.99")
    assert "-A" in nf_env.fake.calls[0].cmd and "record/bytes" in nf_env.fake.calls[1].cmd
    # the fake served the header-less sentinel for the -A and -s record/* runs
    assert core.parse_flow_csv(fixture_text("no_match_agg.txt")).saw_header is False


# ---------------------------------------------------------------------------
# inventory pass I: budget, binary, OSError; second-pass failures clean up
# ---------------------------------------------------------------------------


def test_inventory_pass_i_budget_exhausted_is_timeout(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(62, 65), strays=False)
    nf_env.monkeypatch.setattr(core, "timeout_for", lambda selected: 0)
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "timeout"
    assert resp["error_message"].startswith("pass I exceeded 0s over 3 files")
    assert "page cache" in resp["suggestion"]
    assert resp["nfdump_argv"] == [] and resp["files_scanned"] == 3
    assert nf_env.fake.calls == [] and nf_env.db.get_sources() == []


def test_inventory_binary_missing_and_os_error_on_dash_i(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    nf_env.monkeypatch.setattr(tools, "require_binary", lambda name: None)
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "binary_missing"
    assert nf_env.fake.calls == []
    nf_env.monkeypatch.setattr(tools, "require_binary", fake_which)
    nf_env.fake.raise_exc = PermissionError(13, "Permission denied")
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "os_error"
    assert "Permission denied" in resp["error_message"]
    assert resp["nfdump_argv"][-3:-1] == ["-I", "-r"]
    assert nf_env.db.get_sources() == []


def _fail_pass(nf_env: Env, marker: str) -> list[Path]:
    """Raise OSError on the pass whose argv contains ``marker``; record staging dirs seen."""
    seen: list[Path] = []
    real_call = nf_env.fake.__call__

    def run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "-R" in cmd:
            seen.append(Path(cmd[cmd.index("-R") + 1]))
        if marker in cmd:
            raise OSError("exec failed on the second pass")
        return real_call(cmd, **kwargs)

    nf_env.monkeypatch.setattr(subprocess, "run", run)
    return seen


def test_inventory_second_and_third_pass_failures_remove_staging(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(62, 65), strays=False)
    seen = _fail_pass(nf_env, "ip/flows")  # the stat pass
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "os_error"
    assert len(seen) == 1 and not seen[0].exists()
    assert nf_env.db.get_sources() == []
    nf_env.monkeypatch.setattr(subprocess, "run", nf_env.fake)
    seen = _fail_pass(nf_env, "srcip4/24,dstip4/24")  # the segment pass
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "os_error"
    assert len(seen) == 2 and not any(p.exists() for p in seen)
    assert nf_env.db.get_sources() == []


def test_profile_out_and_in_pass_failures_remove_staging(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(62, 65), strays=False)
    seen = _fail_pass(nf_env, "dstip/bytes")  # the out pass (its 4th table)
    resp = nf_env.call("run_netflow_host_profile", evidence_path=str(day_dir), host="10.0.2.37")
    assert resp["status"] == "error" and resp["error_type"] == "os_error"
    assert len(seen) == 1 and not seen[0].exists()
    nf_env.monkeypatch.setattr(subprocess, "run", nf_env.fake)
    seen = _fail_pass(nf_env, "srcip/bytes")  # the in pass
    resp = nf_env.call("run_netflow_host_profile", evidence_path=str(day_dir), host="10.0.2.37")
    assert resp["status"] == "error" and resp["error_type"] == "os_error"
    assert len(seen) == 2 and not any(p.exists() for p in seen)
    assert resp["nfdump_argv"][-1] == "dst ip 10.0.2.37"
    assert nf_env.db.get_sources() == []


# ---------------------------------------------------------------------------
# parsers and row grammar
# ---------------------------------------------------------------------------


def test_agg_row_renders_the_srcport_key() -> None:
    r = FlowRec(first=981210127.675, last=981210128.0, sp=50123, dp=445, pkt=3, byt=132, fl=2)
    assert core.agg_row(r, ["srcport", "dstport"]).text() == (
        "2001-02-03T14:22:07 netflow agg sport=50123 dport=445 flows=2 packets=3 bytes=132 bps=0 "
        "bpp=0 first=2001-02-03T14:22:07.675 last=2001-02-03T14:22:08.000"
    )


def test_agg_row_srcport_through_the_tool(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), aggregate=["srcport"])
    assert resp["status"] == "success"  # one file: the srcport key is not heavy here
    assert "sport" in resp["rows"][0] and "%sp" in nf_env.fake.last.cmd[-3]


def test_parse_flow_csv_malformed_numbers_and_addresses() -> None:
    header = "firstSeen,lastSeen,proto,srcAddr,srcPort,dstAddr,dstPort,flags,packets,bytes\n"
    text = (
        header
        + "\n".join(
            [
                "1.0,2.0,6,10.0.3.44,1,10.0.1.5,80,......S.,1,44",  # good
                "1.0,2.0,six,10.0.3.44,1,10.0.1.5,80,......S.,1,44",  # bad proto
                "1.0,2.0,6,10.0.3.44,1,10.0.1.999,80,......S.,1,44",  # bad dstAddr
                "1.0,2.0,6,10.0.3.999,1,10.0.1.5,80,......S.,1,44",  # bad srcAddr
                "nope,2.0,6,10.0.3.44,1,10.0.1.5,80,......S.,1,44",  # bad first
                "1.0,2.0,6,10.0.3.44,1,10.0.1.5,80,......S.,1",  # short line
            ]
        )
        + "\n"
    )
    p = core.parse_flow_csv(text)
    assert len(p.rows) == 1 and p.dropped == 5
    assert p.warnings == [
        "2 rows with unparseable addresses dropped", "3 malformed csv lines dropped",
    ]  # fmt: skip


def test_parse_stat_csv_rows_before_a_header_and_malformed_numbers() -> None:
    text = (
        "2001-02-03 08:10:10,2001-02-03 17:45:31,1,any,10.0.1.5,5,1.0,1,1,1,1,1,1,1\n"
        "ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,ipps,ibps,ibpp\n"
        "2001-02-03 08:10:10,2001-02-03 17:45:31,1,any,10.0.1.5,five,1.0,1,1,1,1,1,1,1\n"
        "2001-02-03 08:10:10,2001-02-03 17:45:31,1,any,10.0.1.5,5,1.0,1,1,1,1,1,1,1\n"
    )
    p = core.parse_stat_csv(text, [True])
    assert len(p.tables) == 1 and [r.val for r in p.tables[0].rows] == ["10.0.1.5"]
    assert p.dropped == 1 and p.tables[0].dropped == 1
    assert p.warnings == ["1 malformed csv lines dropped"]


# ---------------------------------------------------------------------------
# discover(): FIFO, invalid-date name, unreadable entry
# ---------------------------------------------------------------------------


def test_discover_fifo_invalid_date_and_unreadable_entries(
    tmp_path: Path, monkeypatch: Any
) -> None:
    d = tmp_path / "flows"
    nfcapd(d, day="20010304")
    weird = nfcapd(d, "nfcapd.200113990000")  # rotation-style name, impossible date
    os.mkfifo(d / "nfcapd.200103050000")
    files, excluded = core.discover(d)
    assert [f.path.name for f in files] == ["nfcapd.200103040000", "nfcapd.200113990000"]
    assert [f.day for f in files][1] is None and files[1].path == weird  # kept, undated
    assert {Path(e.path).name: e.reason for e in excluded} == {
        "nfcapd.200103050000": "not a regular file",
    }
    real_inspect = core._inspect

    def flaky(path: Path) -> core.NfFile | core.Excluded | None:
        if path.name == "nfcapd.200103040000":
            raise OSError(5, "Input/output error")
        return real_inspect(path)

    monkeypatch.setattr(core, "_inspect", flaky)
    files, excluded = core.discover(d)
    assert [f.path.name for f in files] == ["nfcapd.200113990000"]
    reasons = {Path(e.path).name: e.reason for e in excluded}
    assert reasons["nfcapd.200103040000"] == "unreadable: Input/output error"
    # selection keeps the undated file for any window
    ts, te = core.parse_window("2001-03-01T00:00:00", "2001-03-02T00:00:00")
    assert [f.path.name for f in core.select(files, ts, te)] == ["nfcapd.200113990000"]
