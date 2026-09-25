"""Parsers and statistics on captured nfdump stdout (``tests/fixtures/netflow/nfdump_stdout``).

What: STAT tables (single, ``:p`` split, two back-to-back, ``i``-column normalisation, ``pr``
strip), RAW/AGG/SEG flow tables, ``-I`` output, the ``No matching flows`` sentinels (including the
header-less one of the aggregation modes), exit-254 text, the hand-written IPv6 (condensed row
dropped with ``rows_dropped``) and ``flP == 0`` fixtures; epoch to ISO conversion; the SYN-only
predicate; sweep grouping on the captured sweep aggregate of the synthetic corpus (``sweep.txt``:
10.0.3.44 -> 13 targets on two /24s on 445 and on 3389 within ~22 s); pair statistics on the
captured SYN-only retry pair (``pair_retries.txt``: 294 SYN-only records 53 s apart, 240
distinct after collapsing the 54 exporter near-copies), on the long session's both-directions
capture (``pair_session_both.txt``: one 17 h session at 143 B/s plus its reply leg, which must
not double the session count) and on constructed series (periodic, long-lived, nightly,
truncated -> ``hints_partial``, copies with differing counters); host-profile totals come from
the exact ``<host>/flows`` table (``profile_out.txt`` / ``profile_in.txt``).
When: pure ``core`` plus a few tool-level checks with the fake subprocess.
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import re
from pathlib import Path

from mulder.server.tools.netflow import core
from mulder.server.tools.netflow.core import FlowRec
from tests.netflow_harness import Env, fixture_text

_EVENT_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
_BASE = 981_158_400.0  # 2001-02-03T00:00:00Z, a midnight


def _rec(
    first: float,
    dur: float = 15.0,
    byt: int = 300,
    flg: str = "......S.",
    pkt: int = 5,
    sp: int = 50000,
) -> FlowRec:
    return FlowRec(
        first=first, last=first + dur, proto=6, sa="10.0.0.1", sp=sp, da="10.0.0.2", dp=443,
        flg=flg, pkt=pkt, byt=byt,
    )  # fmt: skip


# ---------------------------------------------------------------------------
# time / number helpers
# ---------------------------------------------------------------------------


def test_epoch_to_iso() -> None:
    assert core.iso_s(981210127.675) == "2001-02-03T14:22:07"
    assert core.iso_ms(981210127.675) == "2001-02-03T14:22:07.675"
    assert core.iso_ms(981210127.634) == "2001-02-03T14:22:07.634"
    assert core.iso_ms(981210127.0) == "2001-02-03T14:22:07.000"
    assert core.iso_ms(981210127.9996) == "2001-02-03T14:22:08.000"
    assert core.stat_ts_to_iso("2001-02-03 08:10:10") == "2001-02-03T08:10:10"
    assert _EVENT_TIME.match(core.iso_s(0))


def test_num_and_proto_name() -> None:
    assert core.num(53.0) == "53"
    assert core.num(0.972) == "0.972"
    assert core.num(61200.125) == "61200.125"
    assert core.num(0.26999998) == "0.27"
    assert core.num(True) == "true" and core.num(False) == "false"
    assert core.num(7) == "7"
    assert core.proto_name("6    ") == "tcp"
    assert core.proto_name("17   ") == "udp"
    assert core.proto_name("1") == "icmp"
    assert core.proto_name("any") == "any"
    assert core.proto_name("") == "any"
    assert core.proto_name("99") == "99"
    assert core.proto_name("TCP") == "tcp"


def test_row_grammar_values_never_contain_spaces() -> None:
    row = core.Row("x", "2001-02-03T14:22:07", [("a", "with space"), ("b", None), ("c", (1, 2)),
                                                ("d", 1.5), ("e", True)])  # fmt: skip
    assert row.text() == "2001-02-03T14:22:07 netflow x a=with_space b=null c=1,2 d=1.5 e=true"
    assert core.Row("h", None, [("k", "v")]).text() == "- netflow h k=v"
    assert row.as_dict()["c"] == [1, 2] and row.as_dict()["kind"] == "x"


# ---------------------------------------------------------------------------
# STAT tables
# ---------------------------------------------------------------------------


def test_stat_ip_flows_uses_i_columns_normalised() -> None:
    p = core.parse_stat_csv(fixture_text("stat_ip.txt"), [True])
    assert len(p.tables) == 1 and p.dropped == 0 and p.warnings == []
    rows = p.tables[0].rows
    assert len(rows) == 5
    r = rows[0]
    assert (r.val, r.fl, r.flP, r.pkt, r.pktP, r.byt, r.bytP, r.pps, r.bps, r.bpp) == (
        "10.0.3.44",
        74,
        37.6,
        130,
        0.4,
        13334,
        0.1,
        5,
        4726,
        102,
    )
    assert r.proto == "any"
    assert r.ts == "2001-02-03T14:22:07" and r.te == "2001-02-03T14:22:29"
    assert r.td == 22.57


def test_stat_port_protocol_split() -> None:
    p = core.parse_stat_csv(fixture_text("stat_port_p.txt"), [False])
    rows = p.tables[0].rows
    assert [(r.val, r.proto, r.fl) for r in rows] == [
        ("445", "tcp", 41), ("53", "udp", 36), ("3389", "tcp", 33), ("3128", "tcp", 30),
        ("443", "tcp", 22),
    ]  # fmt: skip
    assert core.stat_ip_valued("dstport:p") is False
    assert (
        core.stat_ip_valued("ip")
        and core.stat_ip_valued("srcip")
        and core.stat_ip_valued("dstip:p")
    )
    assert not core.stat_ip_valued("port")


def test_stat_multi_two_tables_plain_and_i_columns() -> None:
    p = core.parse_stat_csv(fixture_text("stat_multi.txt"), [True, False])
    assert len(p.tables) == 2
    first, second = p.tables
    assert [(r.val, r.pkt, r.byt, r.bytP) for r in first.rows] == [
        ("10.0.2.37", 30600, 8751600, 70.8),
        ("10.0.2.90", 1650, 2350000, 19.0),
        ("10.0.1.5", 1071, 771841, 6.2),
        ("10.0.2.117", 59, 51566, 0.4),
        ("10.0.2.108", 52, 37475, 0.3),
    ]
    assert (first.rows[0].bps, first.rows[0].bpp) == (1144, 286)  # plain columns: 17 h at 143 B/s
    assert [(r.val, r.proto, r.fl) for r in second.rows] == [
        ("445", "tcp", 41), ("53", "udp", 36), ("3389", "tcp", 33), ("3128", "tcp", 30),
        ("443", "tcp", 22),
    ]  # fmt: skip
    assert second.rows[0].bps == 2932  # ibps -> bps


def test_stat_flp_zero_rows_parse() -> None:
    """A table whose shares all round to 0.0 % parses."""
    p = core.parse_stat_csv(fixture_text("stat_flp_zero.txt"), [False])
    assert len(p.tables[0].rows) == 5 and all(r.flP == 0.0 for r in p.tables[0].rows)


def test_profile_captures_exact_host_table_first() -> None:
    """The 4-table captures: table 0 is the host itself, one row, flP == 100.0."""
    out = core.parse_stat_csv(fixture_text("profile_out.txt"), [True, False, True, True])
    inn = core.parse_stat_csv(fixture_text("profile_in.txt"), [True, False, True, True])
    assert len(out.tables) == 4 and len(inn.tables) == 4
    (o,) = out.tables[0].rows
    (i,) = inn.tables[0].rows
    assert (o.val, o.fl, o.flP, o.byt, o.ts, o.te) == (
        "10.0.2.37",
        1,
        100.0,
        8751600,
        "2001-02-03T09:48:30",
        "2001-02-04T02:48:30",
    )
    assert (i.val, i.fl, i.flP, i.byt) == ("10.0.2.37", 9, 100.0, 21844)  # 4 ssh + 5 snmp records
    assert [r.val for r in out.tables[2].rows] == ["203.0.113.77"]
    assert [r.val for r in inn.tables[2].rows] == ["10.0.4.12"]
    assert out.tables[1].rows[0].val == "40519" and out.tables[1].rows[0].proto == "tcp"
    assert [(r.val, r.proto, r.fl) for r in inn.tables[1].rows] == [
        ("161", "udp", 5), ("22", "tcp", 4),
    ]  # fmt: skip


def test_stat_ip_valued_unparseable_address_drops_row() -> None:
    text = (
        "ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,ipps,ibps,ibpp\n"
        "2001-02-03 08:10:10,2001-02-03 17:45:31,1,any,2001:db..e0:fed5,5,1.0,1,1,1,1,1,1,1\n"
        "2001-02-03 08:10:10,2001-02-03 17:45:31,1,any,2001:db8:1000:cafe:20e:35ff:fec0:fed5,"
        "5,1.0,1,1,1,1,1,1,1\n"
        "garbage,line\n"
    )
    p = core.parse_stat_csv(text, [True])
    assert [r.val for r in p.tables[0].rows] == ["2001:db8:1000:cafe:20e:35ff:fec0:fed5"]
    assert p.dropped == 2 and p.tables[0].dropped == 2
    assert p.warnings == [
        "1 rows with unparseable addresses dropped", "1 malformed csv lines dropped",
    ]  # fmt: skip


def test_no_match_stat_prints_sentinel_then_header() -> None:
    p = core.parse_stat_csv(fixture_text("no_match_stat.txt"), [True])
    assert len(p.tables) == 1 and p.tables[0].rows == [] and p.dropped == 0


# ---------------------------------------------------------------------------
# flow tables
# ---------------------------------------------------------------------------


def test_raw_records() -> None:
    p = core.parse_flow_csv(fixture_text("raw.txt"))
    assert p.saw_header and len(p.rows) == 20 and p.dropped == 0
    r = p.rows[0]
    assert (r.proto, r.sa, r.sp, r.da, r.dp, r.flg, r.pkt, r.byt) == (
        6,
        "10.0.3.44",
        40100,
        "10.0.8.21",
        445,
        "......S.",
        1,
        52,
    )
    assert r.first == 981210127.0 and r.last == 981210127.0
    assert r.fl is None and r.bps is None
    assert r.duration_s == 0.0
    done = p.rows[4]
    assert (done.flg, done.pkt, done.byt) == ("...AP.SF", 8, 1236)
    assert abs(done.duration_s - 0.24) < 1e-6
    assert core.flow_row(done).text() == (
        "2001-02-03T14:22:07 netflow flow src=10.0.3.44 sport=40102 dst=10.0.8.21 dport=445 "
        "proto=tcp flags=...AP.SF packets=8 bytes=1236 duration_s=0.24 "
        "first=2001-02-03T14:22:07.150 last=2001-02-03T14:22:07.390"
    )
    # the synthetic exporter copies differ from their originals in bytes (52 vs 53), so none of
    # them is an exact duplicate; exact copies are removed
    deduped, removed = core.dedupe_flows(p.rows)
    assert len(deduped) == 20 and removed == 0
    deduped, removed = core.dedupe_flows(p.rows + p.rows[:6])
    assert len(deduped) == 20 and removed == 6
    assert [x.first for x in deduped] == sorted(x.first for x in deduped)


def test_agg_plain_rows() -> None:
    p = core.parse_flow_csv(fixture_text("agg_plain.txt"))
    assert len(p.rows) == 5
    r = p.rows[0]
    assert (r.sa, r.da, r.pkt, r.byt, r.bps, r.bpp, r.fl) == (
        "10.0.2.37",
        "203.0.113.77",
        30600,
        8751600,
        1144,
        286,
        1,
    )
    assert r.proto is None and r.sp is None and r.dp is None and r.flg is None
    assert core.agg_row(r, ["srcip", "dstip"]).text() == (
        "2001-02-03T09:48:30 netflow agg src=10.0.2.37 dst=203.0.113.77 flows=1 "
        "packets=30600 bytes=8751600 bps=1144 bpp=286 first=2001-02-03T09:48:30.000 "
        "last=2001-02-04T02:48:30.000"
    )
    by_dst = {r.da: r.fl for r in p.rows}
    assert by_dst == {
        "203.0.113.77": 1, "198.51.100.23": 1, "203.0.113.140": 8, "192.0.2.45": 6,
        "198.51.100.61": 8,
    }  # fmt: skip


def test_agg_flags_rows_and_masked_keys() -> None:
    p = core.parse_flow_csv(fixture_text("agg_flags.txt"))
    assert len(p.rows) == 5 and p.rows[0].flg == "...AP.SF"
    text = core.agg_row(p.rows[1], ["srcip", "dstip", "dstport", "flags"]).text()
    assert text.startswith(
        "2001-02-03T11:35:09 netflow agg src=10.0.1.5 dst=203.0.113.140 dport=443 "
        "flags=...AP.SF flows=8"
    )
    seg = core.parse_flow_csv(fixture_text("seg24.txt"))
    assert len(seg.rows) == 5 and seg.rows[0].sa == "10.0.2.0" and seg.rows[0].fl == 52
    assert (
        core.agg_row(seg.rows[0], ["srcip4/24", "dstip4/24"])
        .text()
        .startswith(
            "2001-02-03T00:36:07 netflow agg src_net=10.0.2.0/24 dst_net=10.0.1.0/24 flows=52"
        )
    )
    assert [(r.sa, r.da, r.fl) for r in seg.rows[1:3]] == [
        ("10.0.3.0", "10.0.8.0", 46), ("10.0.3.0", "10.0.9.0", 28),
    ]  # fmt: skip
    assert core.agg_row(p.rows[0], ["proto"]).text().split(" ")[3] == "proto=any"


def test_ipv6_full_parses_condensed_row_dropped() -> None:
    p = core.parse_flow_csv(fixture_text("raw_ipv6.txt"))
    assert len(p.rows) == 1 and p.dropped == 1
    assert p.rows[0].sa == "2001:db8:1000:cafe:20e:35ff:fec0:fed5"
    assert p.rows[0].da == "2001:db8:1000:cafe::1"
    assert p.warnings == ["1 rows with unparseable addresses dropped"]


def test_no_match_and_sentinel_lines_ignored() -> None:
    p = core.parse_flow_csv(fixture_text("no_match.txt"))
    assert p.rows == [] and p.saw_header and p.dropped == 0
    assert core.parse_flow_csv("").rows == []
    assert core.parse_flow_csv(fixture_text("exit254.txt")).rows == []
    # -A ... -s record/* and -s record/<order> print ONLY the sentinel: no header at all
    assert fixture_text("no_match_agg.txt") == "No matching flows\n"
    agg = core.parse_flow_csv(fixture_text("no_match_agg.txt"))
    assert agg.rows == [] and not agg.saw_header and agg.dropped == 0 and agg.warnings == []
    assert core.parse_stat_csv(fixture_text("no_match_agg.txt")).tables == []
    # data before any header is ignored, a short line is counted as malformed
    p = core.parse_flow_csv("1,2,3\nfirstSeen,lastSeen,packets,bytes\n1,2,3\n1.0,2.0,3,4\n")
    assert len(p.rows) == 1 and p.dropped == 1 and p.rows[0].pkt == 3


def test_dash_i() -> None:
    d = core.parse_dash_i(fixture_text("dash_I.txt"))
    assert d["Ident"] == "edge-router" and d["Flows"] == 197
    assert d["Flows_tcp"] == 132 and d["Flows_udp"] == 41 and d["Flows_icmp"] == 24
    assert d["Packets"] == 34703 and d["Bytes"] == 12362331
    assert d["First"] == 981160567 and d["Last"] == 981254910
    assert d["msec_first"] == 0 and d["msec_last"] == 0
    assert d["Sequence failures"] == 0
    assert core.parse_dash_i("") == {}


def test_syn_only_predicate() -> None:
    assert core.is_syn_only("......S.")
    assert core.is_syn_only("....RS..")
    assert not core.is_syn_only("...A..SF")
    assert not core.is_syn_only("...AP.SF")
    assert not core.is_syn_only("........")
    assert not core.is_syn_only(None)


def test_sort_flows_orders() -> None:
    rows = core.parse_flow_csv(fixture_text("raw.txt")).rows
    assert [r.first for r in core.sort_flows(rows, "tstart")] == sorted(r.first for r in rows)
    assert [r.last for r in core.sort_flows(rows, "tend")] == sorted(r.last for r in rows)
    by_bytes = core.sort_flows(rows, "bytes")
    assert by_bytes[0].byt == max(r.byt for r in rows)
    assert core.sort_flows(rows, "duration")[0].duration_s == max(r.duration_s for r in rows)
    assert core.sort_flows(rows, "packets")[0].pkt == 8
    assert core.sort_flows(rows, "bps")[0] is max(rows, key=core.flow_bps)
    assert core.sort_flows(rows, "bpp")[0] is max(rows, key=core.flow_bpp)
    assert core.sort_flows(rows, "pps")[0] is max(rows, key=core.flow_pps)
    assert core.sort_flows(rows, "other") == rows


# ---------------------------------------------------------------------------
# sweep grouping
# ---------------------------------------------------------------------------


def test_sweep_grouping_on_captured_sweep_aggregate() -> None:
    p = core.parse_flow_csv(fixture_text("sweep.txt"))
    assert len(p.rows) == 34 and p.dropped == 0
    groups = core.sweep_groups(p.rows, 3, 60)
    assert [(g.src, g.dport) for g in groups] == [("10.0.3.44", 445), ("10.0.3.44", 3389)]
    g445, g3389 = groups
    assert (g445.targets, g445.flows, g445.syn_only_flows, g445.burst_targets) == (13, 41, 36, 13)
    assert core.iso_ms(g445.burst_start) == "2001-02-03T14:22:07.000"
    assert core.iso_ms(g445.first) == "2001-02-03T14:22:07.000"
    assert 21 < g445.burst_span_s < 22
    assert g445.targets_list == [f"10.0.8.{i}" for i in (21, 23, 27, 30, 34, 38, 41, 45)] + [
        f"10.0.9.{i}" for i in (12, 15, 19, 60, 66)
    ]  # fmt: skip
    assert (g3389.targets, g3389.flows, g3389.syn_only_flows, g3389.burst_targets) == (
        13,
        33,
        30,
        13,
    )
    assert core.iso_ms(g3389.burst_start) == "2001-02-03T14:22:07.900"
    assert g3389.targets_list == g445.targets_list
    assert g445.syn_only_flows + g3389.syn_only_flows == 66
    # no other source touches even two targets on these ports
    assert [(g.src, g.dport) for g in core.sweep_groups(p.rows, 2, 60)] == [
        ("10.0.3.44", 445), ("10.0.3.44", 3389),
    ]  # fmt: skip
    assert core.sweep_groups(p.rows, 14, 60) == []
    row = g445.row(60)
    assert row.event_time == "2001-02-03T14:22:07"
    assert row.text().startswith(
        "2001-02-03T14:22:07 netflow sweep src=10.0.3.44 dport=445 proto=tcp targets=13 "
        "burst_targets=13 burst_window_s=60 burst_start=2001-02-03T14:22:07.000 "
    )
    assert " flows=41 syn_only_flows=36 " in row.text()
    assert " " not in row.text().split("targets_list=")[1]


def test_sweep_grouping_on_agg_flags_capture() -> None:
    p = core.parse_flow_csv(fixture_text("agg_flags.txt"))
    groups = core.sweep_groups(p.rows, 3, 60)
    assert [(g.src, g.dport, g.targets, g.flows) for g in groups] == [("10.0.1.5", 443, 3, 22)]
    assert core.sweep_groups(p.rows, 4, 60) == []


def test_sweep_synthetic_burst_and_ranking() -> None:
    rows: list[FlowRec] = []
    for i, tgt in enumerate((21, 23, 27, 30, 34)):
        rows.append(FlowRec(
            first=_BASE + (i * 10 if i < 4 else 500), last=_BASE + 600, sa="10.0.3.44",
            da=f"10.0.8.{tgt}", dp=445, flg="...A..SF", pkt=3, byt=132, fl=2,
        ))  # fmt: skip
    rows.append(FlowRec(first=_BASE, last=_BASE + 1, sa="10.0.3.44", da="10.0.8.21", dp=445,
                        flg="......S.", pkt=1, byt=44, fl=3))  # fmt: skip
    rows.append(FlowRec(first=_BASE, last=_BASE + 1, sa="10.0.3.51", da="10.0.8.21", dp=22,
                        flg="......S.", pkt=1, byt=44, fl=1))  # fmt: skip
    rows.append(FlowRec(first=_BASE, last=_BASE + 1, sa="10.0.3.51", da="10.0.8.23", dp=22,
                        flg="......S.", pkt=1, byt=44, fl=1))  # fmt: skip
    rows.append(FlowRec(first=_BASE, last=_BASE + 1, sa="10.0.3.51", da="10.0.8.27", dp=22,
                        flg="......S.", pkt=1, byt=44, fl=1))  # fmt: skip
    groups = core.sweep_groups(rows, 3, 60)
    assert [(g.src, g.dport, g.targets) for g in groups] == [
        ("10.0.3.44", 445, 5), ("10.0.3.51", 22, 3),
    ]  # fmt: skip
    g = groups[0]
    assert g.flows == 13 and g.syn_only_flows == 3
    assert g.burst_targets == 4 and g.burst_start == _BASE and g.burst_span_s == 30.0
    assert groups[1].syn_only_flows == 3 and groups[1].burst_targets == 3
    assert core.sweep_groups(rows, 6, 60) == []
    assert core.sweep_groups([], 3, 60) == []


# ---------------------------------------------------------------------------
# pair statistics
# ---------------------------------------------------------------------------


def test_pair_stats_on_captured_retry_records() -> None:
    p = core.parse_flow_csv(fixture_text("pair_retries.txt"))
    assert len(p.rows) == 294
    st = core.pair_stats(p.rows, truncated=False)
    assert (st.records_raw, st.records, st.duplicates_removed) == (294, 294, 0)
    # the 54 exporter copies (same 5-tuple and first/last, +1 byte) are near-copies: collapsed
    # for the *_distinct figures, the larger counters kept
    assert (st.records_distinct, st.near_copies_collapsed) == (240, 54)
    assert st.bytes == 240 * 60 + 54 * 61
    assert st.bytes_distinct == 54 * 61 + 186 * 60
    assert st.packets == 294 and st.packets_distinct == 240
    assert st.syn_only_records == 294 and st.syn_only_records_distinct == 240
    assert st.sessions_over_1h == 0 and st.sessions == []
    assert st.records_out == 294 and st.records_in == 0 and st.bytes_in == 0
    assert st.bytes_out == st.bytes and st.packets_out == st.packets
    assert st.longest_session is not None and st.longest_session["duration_s"] == 0.0
    assert st.interval is not None and st.interval.median_s == 53.0 == 53
    assert st.interval.share_within_5pct == 1.0
    assert st.interval.n == 239  # over the collapsed set: 240 distinct start times
    assert st.syn_interval is not None and st.syn_interval.median_s == 53.0
    assert st.bytes_mode == 60 and st.bytes_mode_share < 0.8  # 60/61-byte copies: not fixed-size
    assert st.hints == ["periodic", "syn_only_retries"]
    assert st.hints_partial is False
    assert core.iso_ms(st.first or 0) == "2001-02-04T11:07:26.000"
    assert core.iso_ms(st.last or 0) == "2001-02-04T14:38:33.000"  # the 240th retry
    assert st.distinct_days == 1 and st.active_days == 1 and st.distinct_sports == 240
    assert st.flags_hist == {"......S.": 294}
    d = st.as_dict()
    assert (
        d["median_interval_s"] == 53 and d["interval_share_5pct"] == st.interval.share_within_5pct
    )
    assert d["records_distinct"] == 240 and d["active_days"] == 1 and d["sessions"] == []
    row = core.pair_summary_row(st, "10.0.5.83", "192.0.2.150", 993)
    assert row.event_time == "2001-02-04T11:07:26"
    assert row.text().startswith(
        "2001-02-04T11:07:26 netflow pair src=10.0.5.83 dst=192.0.2.150 dport=993 "
        "records=294 records_distinct=240 duplicates_removed=0 near_copies_collapsed=54 "
        "first=2001-02-04T11:07:26.000 last=2001-02-04T14:38:33.000 "
    )
    assert " sessions_over_1h=0 longest_session_s=0 longest_session_bps=0 " in row.text()
    assert (
        " syn_only_records=294 syn_only_records_distinct=240 median_interval_s=53 " in row.text()
    )
    assert " distinct_days=1 active_days=1 both_directions=false " in row.text()
    assert "records_out=" not in row.text()
    assert row.text().endswith(
        "truncated=false hints_partial=false hints=periodic,syn_only_retries"
    )


def test_pair_stats_both_directions_computes_sessions_on_the_client_leg() -> None:
    """The both-directions capture of the long session (its forward record + the reply leg and
    the reply's exporter copy): without a ``src`` the server-side record doubles the session
    count."""
    p = core.parse_flow_csv(fixture_text("pair_session_both.txt"))
    assert len(p.rows) == 3
    naive = core.pair_stats(p.rows, truncated=False)
    assert naive.sessions_over_1h == 2  # without src the reply leg counts as a second session
    assert naive.longest_session is not None and naive.longest_session["sport"] == 40519
    st = core.pair_stats(p.rows, truncated=False, src="10.0.2.37")
    assert (st.records_raw, st.records, st.duplicates_removed) == (3, 3, 0)
    assert (st.records_distinct, st.near_copies_collapsed) == (2, 1)  # the reply's copy
    assert st.records_out == 1 and st.records_in == 2
    assert st.bytes == st.bytes_out + st.bytes_in and st.packets == st.packets_out + st.packets_in
    assert st.bytes_out == 8751600 and st.packets_out == 30600
    assert st.bytes_in == 4590000 + 4681800 and st.packets_in == 30600 + 30600
    assert st.sessions_over_1h == 1
    assert st.longest_session is not None
    assert st.longest_session["sport"] == 49731 and st.longest_session["src"] == "10.0.2.37"
    assert st.longest_session["duration_s"] == 61200.0 and st.longest_session["bps"] == 1144
    assert all(s["src"] == "10.0.2.37" and s["dst"] == "203.0.113.77" for s in st.sessions)
    assert naive.distinct_sports == 2 and st.distinct_sports == 1  # 40519 is not a client port
    assert st.syn_only_records == 0 and st.hints == naive.hints == ["long_lived_low_rate"]
    assert st.distinct_days == 1 and st.active_days == 2  # 09:48:30 on day 1 .. 02:48:30 on day 2
    row = core.pair_summary_row(st, "10.0.2.37", "203.0.113.77", 40519, both_directions=True)
    assert row.event_time == "2001-02-03T09:48:30"
    assert " sessions_over_1h=1 longest_session_s=61200 longest_session_bps=1144 " in row.text()
    assert " both_directions=true records_out=1 records_in=2 bytes_out=8751600 " in row.text()
    assert f" bytes_in={st.bytes_in} truncated=false" in row.text()


def test_collapse_exporter_copies_near_copies_and_counters() -> None:
    """Copies with the same first/last but different counters, and copies within the 2 ms
    tolerance, collapse to one flow each, keeping the larger counters; unrelated records stay
    apart."""
    a1 = _rec(_BASE, dur=9.5, byt=120_000_000, pkt=90_000, flg="...AP.SF", sp=50001)
    a2 = _rec(_BASE, dur=9.5, byt=125_000_000, pkt=98_000, flg="...AP.SF", sp=50001)
    b1 = _rec(_BASE + 100.25, sp=50002)
    b2 = _rec(_BASE + 100.251, sp=50002)
    c = _rec(_BASE + 100.254, sp=50002)  # 4 ms from b1: a separate record
    d = _rec(_BASE + 100.25, sp=50003)  # another source port: a separate flow
    collapsed, n = core.collapse_exporter_copies([b2, a2, c, d, a1, b1])
    assert n == 2 and len(collapsed) == 4
    assert [(r.first, r.sp) for r in collapsed] == sorted((r.first, r.sp) for r in collapsed)
    kept_a = [r for r in collapsed if r.sp == 50001]
    assert len(kept_a) == 1 and (kept_a[0].byt, kept_a[0].pkt) == (125_000_000, 98_000)
    assert core.collapse_exporter_copies([]) == ([], 0)
    st = core.pair_stats([a1, a2, b1, b2, c, d], truncated=False)
    assert (st.records, st.duplicates_removed, st.records_distinct, st.near_copies_collapsed) == (
        6,
        0,
        4,
        2,
    )
    assert st.bytes == a1.byt + a2.byt + 4 * 300
    assert st.bytes_distinct == a2.byt + 3 * 300
    assert st.packets_distinct == a2.pkt + 3 * 5
    assert st.syn_only_records == 4 and st.syn_only_records_distinct == 3
    # a .5 s boundary between two copies does not split them (tolerance, not rounding)
    e1 = _rec(_BASE + 0.4995, sp=1)
    e2 = _rec(_BASE + 0.5005, sp=1)
    assert core.collapse_exporter_copies([e1, e2])[1] == 1


def test_active_days_spans_every_day_a_record_was_active() -> None:
    long = _rec(_BASE + 43_200, dur=3 * 86_400, byt=1000, flg="...AP.SF")  # noon, 3 days
    st = core.pair_stats([long], truncated=False)
    assert st.distinct_days == 1 and st.active_days == 4
    same_day = [_rec(_BASE + i * 53.0, sp=50000 + i) for i in range(5)]
    st = core.pair_stats(same_day, truncated=False)
    assert st.distinct_days == 1 and st.active_days == 1


def test_pair_stats_synthetic_periodic_syn_series() -> None:
    syn = [_rec(_BASE + i * 53.0 + 0.01 * (i % 3), sp=50000 + i) for i in range(50)]
    st = core.pair_stats(syn + syn[:5], truncated=False)
    assert st.records == 50 and st.duplicates_removed == 5 and st.records_raw == 55
    assert st.interval is not None and st.interval.median_s == 53.0 and st.interval.n == 49
    assert st.interval.share_within_5pct >= 0.5
    assert st.syn_only_records == 50 and st.syn_interval is not None
    assert {"periodic", "syn_only_retries", "fixed_size"} <= set(st.hints)
    assert "long_lived_low_rate" not in st.hints and "nightly" not in st.hints
    assert st.distinct_sports == 50 and st.flags_hist == {"......S.": 50}
    assert st.bytes_mode == 300 and st.bytes_mode_share == 1.0
    assert st.sessions_over_1h == 0 and st.sessions == []


def test_pair_stats_long_lived_low_rate_single_record() -> None:
    long = _rec(_BASE, dur=61200.0, byt=8751600, flg="...APRSF", pkt=30600)
    st = core.pair_stats([long], truncated=False)
    assert st.hints == ["long_lived_low_rate"]
    assert st.sessions_over_1h == 1 and st.sessions[0]["bps"] == 1144  # 143 B/s
    assert st.sessions[0]["duration_s"] == 61200.0
    assert st.interval is None
    assert st.as_dict()["median_interval_s"] is None
    fast = _rec(_BASE, dur=3600.0, byt=50_000_000, flg="...AP.SF", pkt=40000)
    assert core.pair_stats([fast], truncated=False).hints == []  # 111 kbps is not low-rate
    short = _rec(_BASE, dur=3599.0, byt=100, flg="...AP.SF")
    assert core.pair_stats([short], truncated=False).hints == []


def test_pair_stats_nightly_series_with_gaps() -> None:
    noon = _BASE + 43_200  # _BASE is a midnight; keep the +-30 s jitter inside one day
    nightly = [_rec(noon + i * 86400.0 + (30 if i % 2 else -30), byt=1000 + i, flg="...AP.SF",
                    sp=40000 + i) for i in range(12)]  # fmt: skip
    nightly.pop(4)
    nightly.pop(7)  # two 172 800 s gaps
    st = core.pair_stats(nightly, truncated=False)
    assert "nightly" in st.hints and "fixed_size" not in st.hints
    assert st.interval is not None and abs(st.interval.median_s - 86400) <= 60
    assert st.distinct_days == 10


def test_pair_stats_truncated_omits_periodicity_hints() -> None:
    syn = [_rec(_BASE + i * 53.0, sp=50000 + i) for i in range(50)]
    long = _rec(_BASE, dur=61200.0, byt=8751600, flg="...APRSF", pkt=30600)
    st = core.pair_stats([long, *syn], truncated=True)
    assert st.truncated and st.hints_partial
    assert st.hints == ["long_lived_low_rate"]
    for h in ("periodic", "syn_only_retries", "fixed_size", "nightly"):
        assert h not in st.hints
    assert st.interval is not None  # statistics are still reported, only hints are withheld


def test_pair_stats_empty() -> None:
    st = core.pair_stats([], truncated=False, src="192.0.2.99")
    assert st.records == 0 and st.first is None and st.hints == [] and not st.hints_partial
    assert st.records_distinct == 0 and st.active_days == 0 and st.records_out == 0
    assert st.as_dict()["longest_session"] is None
    # the tool never indexes this row (no records -> indexed_empty, see test_netflow_index)
    row = core.pair_summary_row(st, "192.0.2.99", "192.0.2.98", None)
    assert row.event_time is None
    assert " dport=any records=0 " in row.text() and "hints=none" in row.text()


def test_interval_stats_edge_cases() -> None:
    assert core.interval_stats([]) is None
    assert core.interval_stats([1.0]) is None
    assert core.interval_stats([1.0, 1.0, 1.0]) is None  # duplicates: no positive gap
    st = core.interval_stats([0.0, 53.02, 106.05, 159.07, 212.1])
    assert st is not None and st.n == 4 and st.median_s == 53.0 and st.share_within_5pct == 1.0
    assert st.p10_s == 53.0 and st.p90_s == 53.0


# ---------------------------------------------------------------------------
# tool-level parse effects
# ---------------------------------------------------------------------------


def test_pair_tool_reports_captured_values_and_indexes_flows(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(34, 36), strays=False)
    resp = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="10.0.5.83",
        dst="192.0.2.150", dport=993,
    )  # fmt: skip
    assert resp["status"] == "success"
    assert (resp["records_raw"], resp["records"]) == (294, 294)
    s = resp["summary"]
    assert s["syn_only_records"] == 294 and s["sessions_over_1h"] == 0
    assert s["records_distinct"] == 240 and s["near_copies_collapsed"] == 54
    assert s["median_interval_s"] == 53 and s["hints_partial"] is False
    assert set(resp["hints"]) == {"periodic", "syn_only_retries"}
    assert resp["row_count"] == 1 + 200 and resp["windows_indexed"] == 202
    assert resp["rows"][0]["kind"] == "pair" and resp["rows"][0]["line"] == 2
    flows = [r for r in resp["rows"][1:]]
    assert all(r["kind"] == "flow" for r in flows)
    times = [r["first"] for r in flows]
    assert times == sorted(times)
    assert any("294 unique records; 200 flow rows indexed" in w for w in resp["warnings"])
    assert resp["truncated"] is False
    # the long session's pair is a capture of its own: one record, no retries
    session = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="10.0.2.37",
        dst="203.0.113.77", dport=40519,
    )  # fmt: skip
    assert session["status"] == "success" and session["records"] == 1
    assert session["hints"] == ["long_lived_low_rate"]
    assert session["summary"]["longest_session"]["duration_s"] == 61200


def test_pair_tool_truncation_honesty(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(75, 76), strays=False)
    resp = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="10.0.5.83",
        dst="192.0.2.150", dport=993, max_records=100, index_records=500,
    )  # fmt: skip
    assert resp["status"] == "success"
    assert resp["truncated"] is True and resp["hints_partial"] is True
    assert resp["records_raw"] == 100
    assert resp["hints"] == []  # periodic / syn_only_retries need the whole series
    assert "narrow t_start/t_end" in resp["hint"]
    assert resp["rows"][0]["hints_partial"] is True and resp["rows"][0]["truncated"] is True
    assert resp["windows_indexed"] <= 501


def test_sweep_tool_on_captured_aggregate(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(34, 35), strays=False)
    resp = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    assert resp["status"] == "success" and resp["row_count"] == 2
    r1, r2 = resp["rows"]
    assert (r1["src"], r1["dport"], r1["targets"], r1["flows"], r1["burst_targets"]) == (
        "10.0.3.44",
        445,
        13,
        41,
        13,
    )
    assert r1["burst_start"] == "2001-02-03T14:22:07.000" and r1["syn_only_flows"] == 36
    assert r1["event_time"] == "2001-02-03T14:22:07" and len(r1["targets_list"]) == 13
    assert (r2["dport"], r2["targets"], r2["flows"], r2["burst_targets"]) == (3389, 13, 33, 13)
    assert resp["summary"]["top"]["targets"] == 13 and resp["summary"]["groups_total"] == 2
    empty = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389],
                        min_targets=14)  # fmt: skip
    assert empty["status"] == "indexed_empty" and empty["row_count"] == 0


def test_host_profile_totals_are_exact_from_the_host_table(nf_env: Env) -> None:
    """Totals come from the single ``<host>/flows`` row (flP == 100.0), never back-computed from
    a one-decimal share of the top dstport row."""
    day_dir = nf_env.tree(days=range(34, 35), strays=False)
    resp = nf_env.call(
        "run_netflow_host_profile", evidence_path=str(day_dir), host="10.0.2.37",
        internal_nets=["10.0.2.0/24", "10.0.4.0/24"], max_inline_rows=100,
    )  # fmt: skip
    assert resp["status"] == "success"
    assert resp["row_count"] == 1 + 1 + 1 + 1 + 2 + 1 + 1 == len(resp["rows"])
    kinds = [r["kind"] for r in resp["rows"]]
    assert kinds[0] == "summary"
    assert set(kinds) == {"summary", "out_service", "out_peer_flows", "out_peer_bytes",
                          "in_service", "in_peer_flows", "in_peer_bytes"}  # fmt: skip
    s = resp["summary"]
    assert (s["out_flows"], s["out_bytes"], s["in_flows"], s["in_bytes"]) == (1, 8751600, 9, 21844)
    assert all(isinstance(s[k], int) for k in ("out_flows", "out_bytes", "in_flows", "in_bytes"))
    assert s["first"] == "2001-02-03T06:05:00" and s["last"] == "2001-02-04T02:48:30"
    assert s["out_services"] == 1 and s["in_services"] == 2
    assert s["external_peer_ips"] == ["203.0.113.77"] and s["external_peers"] == 1
    assert s["external_peers_scope"] == "top20_peer_tables"
    assert "10.0.4.12" not in s["external_peer_ips"]  # the admin host is inside internal_nets
    assert resp["warnings"] == []
    summary = resp["rows"][0]
    assert summary["kind"] == "summary" and summary["out_flows"] == 1
    assert summary["external_peers_scope"] == "top20_peer_tables"
    assert summary["event_time"] == "2001-02-03T06:05:00"
    svc = [r for r in resp["rows"] if r["kind"] == "out_service"][0]
    assert (svc["proto"], svc["port"], svc["rank"], svc["flows"]) == ("tcp", "40519", 1, 1)
    peer = [r for r in resp["rows"] if r["kind"] == "out_peer_flows"][0]
    assert (peer["ip"], peer["rank"], peer["flows"]) == ("203.0.113.77", 1, 1)
    inbound = [(r["port"], r["flows"]) for r in resp["rows"] if r["kind"] == "in_service"]
    assert inbound == [("161", 5), ("22", 4)]
    text = nf_env.db.get_windows_page(resp["source_name"])[0][1].raw_text
    assert " out_flows=1 out_bytes=8751600 in_flows=9 in_bytes=21844 " in text
    assert " external_peers=1 external_peers_scope=top20_peer_tables " in text
    assert "top-n peer rows only" in resp["hint"]
    # the host itself never appears as its own peer
    assert not any(r.get("ip") == "10.0.2.37" for r in resp["rows"][1:])


def test_query_tool_ipv6_row_dropped_with_warning(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    nf_env.fake.stdout = fixture_text("raw_ipv6.txt")
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir))
    assert resp["status"] == "success"
    assert resp["row_count"] == 1 and resp["rows_dropped"] == 1
    assert "1 rows with unparseable addresses dropped" in resp["warnings"]
    assert resp["rows"][0]["src"] == "2001:db8:1000:cafe:20e:35ff:fec0:fed5"
    assert (
        " src=2001:db8:1000:cafe:20e:35ff:fec0:fed5 "
        in nf_env.db.get_windows_page(resp["source_name"])[0][1].raw_text
    )


def test_inventory_tool_rows_from_captures(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(34, 36), strays=False)
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir), max_inline_rows=100)
    assert resp["status"] == "success"
    kinds = [r["kind"] for r in resp["rows"]]
    assert kinds[0] == "summary"
    assert kinds.count("talker") == 5 and kinds.count("service") == 5
    assert kinds.count("src_bytes") == 5 and kinds.count("dst_bytes") == 5
    assert kinds.count("segment") == 5 and resp["row_count"] == 26
    s = resp["rows"][0]
    assert (s["exporter"], s["files"], s["flows"], s["tcp_flows"]) == ("edge-router", 2, 394, 264)
    assert s["first"] == "2001-02-03T00:36:07.000" and s["last"] == "2001-02-04T02:48:30.000"
    assert s["event_time"] == "2001-02-03T00:36:07" and s["dir"] == str(day_dir)
    talker = resp["rows"][1]
    assert (talker["rank"], talker["ip"], talker["flows"], talker["flows_pct"]) == (
        1,
        "10.0.3.44",
        74,
        37.6,
    )
    service = [r for r in resp["rows"] if r["kind"] == "service"][0]
    assert (service["proto"], service["port"], service["flows"]) == ("tcp", "445", 41)
    seg = [r for r in resp["rows"] if r["kind"] == "segment"][0]
    assert (seg["src_net"], seg["dst_net"], seg["flows"]) == ("10.0.2.0/24", "10.0.1.0/24", 52)
    assert resp["summary"]["flows"] == 394 and resp["summary"]["talkers"] == 5
    manifest = nf_env.db.get_windows_page(resp["manifest_source"])[0]
    assert [w.event_time for w in manifest] == [None, None, None]
    assert manifest[1].raw_text == (
        "- netflow file name=nfcapd.200102030000 size=64 flows=197 first=2001-02-03T00:36:07 "
        "last=2001-02-04T02:48:30 ident=edge-router seq_failures=0"
    )


def test_inventory_marks_live_collector_file(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    Path(day_dir / "nfcapd.current.4242").write_bytes(
        (day_dir / "nfcapd.200103040000").read_bytes()
    )
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "success" and resp["files_scanned"] == 2
    manifest = nf_env.db.get_windows_page(resp["manifest_source"])[0]
    current = [w.raw_text for w in manifest if "name=nfcapd.current.4242" in w.raw_text]
    assert len(current) == 1 and current[0].endswith(
        " note=live-collector-temp-file-read-via-staging"
    )
    assert " " not in current[0].split("note=")[1]
