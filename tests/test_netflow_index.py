"""Indexing: one WindowRow per line, event_time per row, FTS/timeline hits, naming and caps.

What: every non-empty source has line 1 = header (``event_time`` None, carries the originating
``tool_call_id``) and one data row per line with ``YYYY-MM-DDTHH:MM:SS`` ``event_time``; manifest
rows have no ``event_time``; ``get_windows_by_time_range`` returns sweep/agg rows and never a
header or manifest row; FTS phrase searches for an IP and for ``dport=445`` hit; the skip path
carries ``source_name``/``line_count``; ``force=True`` registers ``<name>-r1`` whose header says
``supersedes=<name>`` while ``get_windows_page(<name>)`` still returns only the first run; two
inventories on two directories get two ids; no match -> ``indexed_empty`` with ``line_count 0``
for every tool (a pair or profile with zero records never indexes a data row without an
``event_time``); the id is a deterministic 16-hex digest that changes with ``limit`` but not with
the spelling of the window (``T``/space/``Z``/``.000``) or of filter keywords (``SRC IP``); at most
501 windows per source; ``max_inline_rows`` default 20, 0 -> no rows, 500 -> 100.
When: hermetic (fake subprocess, real CaseDB on tmp_path).
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import re
from pathlib import Path

from mulder.server.tools.netflow import core
from tests.netflow_harness import Env, make_tree

_EVENT_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
_NAME = re.compile(r"^netflow\.(inventory|top|profile|sweep|pair|query)\.[0-9a-f]{16}$")
_AGG_FILTER = "src net 10.0.3.0/24 and dst net 10.0.8.0/24 and proto tcp and dst port 445"


def _raw_rows(n: int) -> str:
    header = "firstSeen,lastSeen,proto,srcAddr,srcPort,dstAddr,dstPort,flags,packets,bytes\n"
    lines = [
        f"{981210127.150 + i:.3f},{981210127.390 + i:.3f},6,10.0.3.44,{50000 + i},"
        f"10.0.1.5,3128,...AP.SF,8,{1236 + i}"
        for i in range(n)
    ]
    return header + "\n".join(lines) + "\n"


def _windows(nf_env: Env, name: str) -> list[object]:
    rows, total = nf_env.db.get_windows_page(name, limit=1000)
    assert total == len(rows)
    return list(rows)


def test_one_window_per_line_with_header_and_event_times(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    assert resp["status"] == "success"
    name = resp["source_name"]
    assert _NAME.match(name) and resp["source"] == name
    assert resp["windows_indexed"] == resp["line_count"] == 3 == resp["row_count"] + 1
    windows = _windows(nf_env, name)
    assert [(w.line_start, w.line_end) for w in windows] == [(1, 1), (2, 2), (3, 3)]  # type: ignore[attr-defined]
    header = windows[0]
    assert header.event_time is None  # type: ignore[attr-defined]
    assert header.raw_text.startswith("- netflow header tool=run_netflow_sweep ")  # type: ignore[attr-defined]
    assert f" tool_call_id={resp['tool_call_id']} " in header.raw_text  # type: ignore[attr-defined]
    assert (
        f" evidence_path={day_dir} files=1 "
        "file_range=nfcapd.200103040000..nfcapd.200103040000 window=none " in header.raw_text
    )  # type: ignore[attr-defined]
    assert ' filter="proto tcp and flags S and dst port in [ 445 3389 ]' in header.raw_text  # type: ignore[attr-defined]
    assert (
        " ports=445,3389 min_targets=3 n=25 syn_only=false burst_window_s=60 "
        "rows=2 truncated=false" in header.raw_text
    )  # type: ignore[attr-defined]
    assert "supersedes=" not in header.raw_text  # type: ignore[attr-defined]
    for w, inline in zip(windows[1:], resp["rows"], strict=True):
        assert _EVENT_TIME.match(w.event_time)  # type: ignore[attr-defined]
        assert w.raw_text.startswith(f"{w.event_time} netflow sweep src=")  # type: ignore[attr-defined]
        assert inline["line"] == w.line_start  # type: ignore[attr-defined]
        assert inline["event_time"] == w.event_time  # type: ignore[attr-defined]
    src = nf_env.db.get_sources()[0]
    assert (src.source_name, src.source_path, src.extractor, src.line_count) == (
        name,
        str(day_dir),
        "nfdump",
        3,
    )
    assert src.source_hash.startswith("blake2b:")
    assert resp["source_id"] == src.source_id


def test_timeline_and_fts_hits(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(34, 35), strays=False)
    sweep = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    agg = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), filter=_AGG_FILTER,
        aggregate=["srcip", "dstip", "dstport"],
    )  # fmt: skip
    raw = nf_env.call("run_netflow_query", evidence_path=str(day_dir), filter="src ip 10.0.3.44")
    inv = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert {r["status"] for r in (sweep, agg, raw, inv)} == {"success"}

    by_source = nf_env.db.get_windows_by_time_range("2001-02-03T14:22:07", "2001-02-03T14:22:30")
    assert {sweep["source_name"], raw["source_name"]} <= set(by_source)
    assert agg["source_name"] not in by_source  # its rows are 04:37:00 .. 11:35:09
    assert len(by_source[sweep["source_name"]]) == 2
    assert len(by_source[raw["source_name"]]) == 20
    for ws in by_source.values():
        for w in ws:
            assert w.event_time and "netflow header" not in w.raw_text
            assert "netflow file " not in w.raw_text
            assert "2001-02-03T14:22:07" <= w.event_time <= "2001-02-03T14:22:30"
    assert inv["manifest_source"] not in by_source
    inv_rows = by_source.get(inv["source_name"], [])  # inventory rows carry their own first-seen
    assert inv_rows and all(" netflow summary " not in w.raw_text for w in inv_rows)
    wide = nf_env.db.get_windows_by_time_range("2001-01-01T00:00:00", "2001-12-31T23:59:59")
    assert agg["source_name"] in wide and len(wide[agg["source_name"]]) == 5
    assert inv["manifest_source"] not in wide
    assert all("netflow header" not in w.raw_text for ws in wide.values() for w in ws)

    hits = nf_env.db.search_windows('"10.0.3.44"', max_results=500)
    assert {s for _, s in hits} >= {sweep["source_name"], raw["source_name"], inv["source_name"]}
    hits = nf_env.db.search_windows('"dport=445"', max_results=500)
    assert len(hits) == 13 + 1 and all("dport=445" in w.raw_text for w, _ in hits)  # raw + sweep
    assert not any("bytes=445" in w.raw_text and "dport=445" not in w.raw_text for w, _ in hits)
    hits = nf_env.db.search_windows('"10.0.8.27"', source_name="netflow")
    assert hits and all(w.event_time.startswith("2001-02-03T14:22") for w, _ in hits)  # type: ignore[union-attr]
    hits = nf_env.db.search_windows(
        '"dport=445"', source_name="netflow", time_start="2001-02-03T14:22:07",
        time_end="2001-02-03T14:22:30",
    )  # fmt: skip
    assert hits and all(w.event_time for w, _ in hits)
    everything = nf_env.db.search_windows("netflow", max_results=1000)
    assert any(w.raw_text.startswith("- netflow header") for w, _ in everything)
    bounded = nf_env.db.search_windows(
        "netflow", max_results=1000, time_start="2001-01-01T00:00:00"
    )
    assert bounded and not any(w.raw_text.startswith("- netflow") for w, _ in bounded)
    assert nf_env.db.search_windows("netflow", source_name="netflow.query", max_results=1000)
    assert not nf_env.db.search_windows("netflow", source_name="netflow.top", max_results=1000)


def test_skip_then_force_registers_r1_and_keeps_runs_apart(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    first = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    base = first["source_name"]
    again = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[3389, 445])
    assert again["status"] == "skipped"
    assert again["source"] == again["source_name"] == base
    assert again["line_count"] == 3 and again["windows_indexed"] == 0
    assert again["existing_sources"] == [base]
    assert again["tool"] == "run_netflow_sweep" and again["evidence_path"] == str(day_dir)
    assert f"get_raw_output('{base}')" in again["hint"] and "force=True" in again["hint"]
    assert len(nf_env.fake.calls) == 1
    assert nf_env.audit_entry(again["tool_call_id"])["params"]["source"] == base

    forced = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389],
                         force=True)  # fmt: skip
    assert forced["status"] == "success" and forced["source_name"] == f"{base}-r1"
    header = _windows(nf_env, f"{base}-r1")[0]
    assert header.raw_text.endswith(f" supersedes={base}")  # type: ignore[attr-defined]
    assert f" tool_call_id={forced['tool_call_id']} " in header.raw_text  # type: ignore[attr-defined]
    first_run = _windows(nf_env, base)
    assert len(first_run) == 3 and {w.source_id for w in first_run} == {first["source_id"]}  # type: ignore[attr-defined]
    assert len(_windows(nf_env, f"{base}-r1")) == 3
    assert (
        len(nf_env.db.search_windows("netflow", source_name="netflow.sweep", max_results=100)) == 6
    )

    skipped2 = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    assert skipped2["status"] == "skipped" and skipped2["source_name"] == f"{base}-r1"
    assert skipped2["existing_sources"] == [base, f"{base}-r1"]
    forced2 = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389],
                          force=True)  # fmt: skip
    assert forced2["source_name"] == f"{base}-r2"
    assert _windows(nf_env, f"{base}-r2")[0].raw_text.endswith(f" supersedes={base}-r1")  # type: ignore[attr-defined]
    names = [s.source_name for s in nf_env.db.get_sources()]
    assert names == [base, f"{base}-r1", f"{base}-r2"]


def test_same_params_other_directory_is_not_skipped(nf_env: Env) -> None:
    day_a = nf_env.tree(days=range(63, 64), strays=False)
    day_b = make_tree(nf_env.evidence_root / "other", days=range(63, 64), strays=False)
    a = nf_env.call("run_netflow_sweep", evidence_path=str(day_a))
    b = nf_env.call("run_netflow_sweep", evidence_path=str(day_b))
    assert a["status"] == b["status"] == "success"
    assert a["source_name"] != b["source_name"]


def test_two_inventories_two_ids_and_manifests(nf_env: Env) -> None:
    day_a = nf_env.tree(days=range(63, 65), strays=False)
    day_b = make_tree(nf_env.evidence_root / "branch-probe", days=range(48, 50), strays=False)
    a = nf_env.call("run_netflow_inventory", evidence_path=str(day_a))
    b = nf_env.call("run_netflow_inventory", evidence_path=str(day_b))
    assert a["status"] == b["status"] == "success"
    assert a["source_name"] != b["source_name"]
    assert all(_NAME.match(r["source_name"]) for r in (a, b))
    assert a["manifest_source"] == a["source_name"] + ".manifest"
    assert a["manifest_line_count"] == 3  # header + 2 files
    names = [s.source_name for s in nf_env.db.get_sources()]
    assert names == [
        a["source_name"],
        a["manifest_source"],
        b["source_name"],
        b["manifest_source"],
    ]
    for w in _windows(nf_env, a["manifest_source"]):
        assert w.event_time is None  # type: ignore[attr-defined]
    manifest = _windows(nf_env, a["manifest_source"])
    assert manifest[0].raw_text.startswith("- netflow header tool=run_netflow_inventory ")  # type: ignore[attr-defined]
    assert manifest[1].raw_text.startswith("- netflow file name=nfcapd.200103040000 size=64 ")  # type: ignore[attr-defined]
    assert manifest[2].raw_text.startswith("- netflow file name=nfcapd.200103050000 ")  # type: ignore[attr-defined]
    # get_raw_output(<inventory name>) also spans its .manifest (prefix + '.'); the main rows
    # come first
    both, total = nf_env.db.get_windows_page(a["source_name"], limit=1000)
    assert total == a["line_count"] + a["manifest_line_count"]
    skipped = nf_env.call("run_netflow_inventory", evidence_path=str(day_a))
    assert skipped["status"] == "skipped" and skipped["source_name"] == a["source_name"]
    assert skipped["existing_sources"] == [a["source_name"], a["manifest_source"]]
    forced = nf_env.call("run_netflow_inventory", evidence_path=str(day_a), force=True)
    assert forced["source_name"] == a["source_name"] + "-r1"
    assert forced["manifest_source"] == a["source_name"] + "-r1.manifest"


def test_no_match_is_indexed_empty(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), filter="src ip 192.0.2.99")
    assert resp["status"] == "indexed_empty"
    assert resp["row_count"] == 0 and resp["rows"] == []
    assert resp["line_count"] == 0 and resp["windows_indexed"] == 0
    assert _NAME.match(resp["source_name"]) and resp["source"] == resp["source_name"]
    assert "No rows matched" in resp["hint"] and "force=True" in resp["hint"]
    src = nf_env.db.get_sources()[0]
    assert src.source_name == resp["source_name"] and src.line_count == 0
    assert src.source_id == resp["source_id"]
    assert _windows(nf_env, resp["source_name"]) == []
    assert nf_env.audit_entry(resp["tool_call_id"])["params"]["source"] == resp["source_name"]
    again = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), filter="src ip 192.0.2.99"
    )
    assert again["status"] == "skipped" and again["line_count"] == 0


def test_no_match_pair_and_profile_are_indexed_empty(nf_env: Env) -> None:
    """A pair/host absent from the data registers an empty source (``indexed_empty``), never a
    summary row with records=0 and a NULL event_time that would inflate the citation
    denominator."""
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    pair = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="192.0.2.99", dst="192.0.2.98"
    )
    profile = nf_env.call(
        "run_netflow_host_profile", evidence_path=str(day_dir), host="192.0.2.99"
    )
    for resp in (pair, profile):
        assert resp["status"] == "indexed_empty", resp
        assert resp["row_count"] == 0 and resp["rows"] == []
        assert resp["line_count"] == 0 and resp["windows_indexed"] == 0
        assert _windows(nf_env, resp["source_name"]) == []
        assert "No rows matched" in resp["hint"]
    assert pair["records_raw"] == 0 and pair["records"] == 0 and pair["hints"] == []
    assert pair["summary"]["records"] == 0 and pair["summary"]["first"] is None
    assert profile["summary"]["out_flows"] == 0 and profile["summary"]["external_peers"] == 0
    assert [s.line_count for s in nf_env.db.get_sources()] == [0, 0]
    wide = nf_env.db.get_windows_by_time_range("2001-01-01T00:00:00", "2001-12-31T23:59:59")
    assert wide == {}
    again = nf_env.call(
        "run_netflow_pair_timeline", evidence_path=str(day_dir), src="192.0.2.99", dst="192.0.2.98"
    )
    assert again["status"] == "skipped" and again["line_count"] == 0


def test_hid_is_deterministic_16_hex_and_parameter_sensitive(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    a = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=100)
    b = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=100, force=True)
    c = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=101)
    d = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=100,
                    max_inline_rows=5)  # fmt: skip
    f = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=500)
    e = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=9999, force=True)
    base = a["source_name"]
    assert re.fullmatch(r"netflow\.query\.[0-9a-f]{16}", base)
    assert b["source_name"] == f"{base}-r1"  # identical params -> same id, forced re-run
    assert c["source_name"] != base and re.fullmatch(
        r"netflow\.query\.[0-9a-f]{16}", c["source_name"]
    )
    assert (
        d["status"] == "skipped" and d["source_name"] == f"{base}-r1"
    )  # inline count is not hashed
    assert e["source_name"] == f["source_name"] + "-r1"  # clamped 9999 == 500: same id
    assert f["source_name"] not in (base, c["source_name"])
    assert core.source_hid("run_netflow_query", str(day_dir), {"limit": 100}) == core.source_hid(
        "run_netflow_query", str(day_dir), {"limit": 100}
    )
    assert core.source_hid("t", "/x", {"a": 1}) != core.source_hid("t", "/y", {"a": 1})
    assert core.source_hid("t", "/x", {"a": 1}) != core.source_hid("u", "/x", {"a": 1})


def test_hid_ignores_window_spelling(nf_env: Env) -> None:
    """The parsed window (seconds, ``T`` form: what ``window_clause`` sends to nfdump) is hashed,
    not the caller's string, so one window is one source."""
    day_dir = nf_env.tree()
    spellings = [
        ("2001-03-04T12:37:00", "2001-03-04T13:37:00"),
        ("2001-03-04 12:37:00", "2001-03-04T13:37:00"),
        ("2001-03-04T12:37:00Z", "2001-03-04T13:37:00+00:00"),
        ("2001-03-04T12:37:00.000", "  2001-03-04T13:37:00  "),
        ("2001-03-04T12:37:00.000000Z", "2001-03-04 13:37:00Z"),
    ]
    for tool, kw in (
        ("run_netflow_query", {"filter": "dst port 445"}),
        ("run_netflow_top", {"stat": "srcip"}),
        ("run_netflow_host_profile", {"host": "10.0.2.37"}),
        ("run_netflow_sweep", {}),
        ("run_netflow_pair_timeline", {"src": "10.0.2.37", "dst": "203.0.113.77"}),
    ):
        first = nf_env.call(tool, evidence_path=str(day_dir), t_start=spellings[0][0],
                            t_end=spellings[0][1], **kw)  # fmt: skip
        assert first["status"] == "success", (tool, first)
        assert first["params_effective"]["t_start"] == "2001-03-04T12:37:00"
        assert first["params_effective"]["t_end"] == "2001-03-04T13:37:00"
        for ts, te in spellings[1:]:
            again = nf_env.call(tool, evidence_path=str(day_dir), t_start=ts, t_end=te, **kw)
            assert again["status"] == "skipped", (tool, ts, te, again)
            assert again["source_name"] == first["source_name"]
        # a different window is still a different source
        other = nf_env.call(tool, evidence_path=str(day_dir), t_start="2001-03-04T12:37:01",
                            t_end=spellings[0][1], **kw)  # fmt: skip
        assert other["status"] == "success" and other["source_name"] != first["source_name"]
    names = [
        s.source_name for s in nf_env.db.get_sources() if not s.source_name.endswith(".manifest")
    ]
    assert len(names) == len(set(names)) == 10


def test_hid_ignores_filter_keyword_case_and_spacing(nf_env: Env) -> None:
    """Keyword case and whitespace do not change the nfdump predicate, so they do not change the
    source id; the validated original is still what reaches nfdump."""
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    first = nf_env.call("run_netflow_query", evidence_path=str(day_dir),
                        filter="src ip 10.0.3.44 and dst port 445")  # fmt: skip
    assert first["status"] == "success"
    assert first["params_effective"]["filter"] == "src ip 10.0.3.44 and dst port 445"
    for spelling in (
        "SRC IP 10.0.3.44 AND DST PORT 445",
        "src  ip\t10.0.3.44 and dst port 445",
        "  src ip 10.0.3.44 and dst port 445  ",
        "(src ip 10.0.3.44) and (dst port 445)",
    ):
        again = nf_env.call("run_netflow_query", evidence_path=str(day_dir), filter=spelling)
        if spelling.startswith("("):
            # parentheses change the token stream: a different (if equivalent) predicate
            assert again["status"] == "success" and again["source_name"] != first["source_name"]
            continue
        assert again["status"] == "skipped", spelling
        assert again["source_name"] == first["source_name"]
    assert len(nf_env.fake.calls) == 2
    assert nf_env.fake.calls[0].cmd[-1] == "src ip 10.0.3.44 and dst port 445"
    # flag letters are case-sensitive in nfdump and are never folded
    a = nf_env.call("run_netflow_query", evidence_path=str(day_dir), filter="flags S")
    b = nf_env.call("run_netflow_query", evidence_path=str(day_dir), filter="FLAGS S")
    assert a["status"] == "success" and b["status"] == "skipped"
    assert nf_env.fake.calls[-1].cmd[-1] == "flags S"


def test_caps_501_windows_and_inline_rows(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    nf_env.fake.stdout = _raw_rows(600)
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=500)
    assert resp["status"] == "success"
    assert resp["row_count"] == 500 and resp["windows_indexed"] == 501
    assert resp["truncated"] is True and "truncated=true" in resp["hint"]
    assert len(resp["rows"]) == 20  # default max_inline_rows
    assert resp["rows"][0]["line"] == 2 and resp["rows"][-1]["line"] == 21
    assert len(_windows(nf_env, resp["source_name"])) == 501
    assert _windows(nf_env, resp["source_name"])[0].raw_text.endswith(  # type: ignore[attr-defined]
        " aggregate=none order=tstart limit=500 direction=any rows=500 truncated=true"
    )

    zero = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=500,
                       max_inline_rows=0, force=True)  # fmt: skip
    assert zero["rows"] == [] and zero["row_count"] == 500
    hundred = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=500,
                          max_inline_rows=500, force=True)  # fmt: skip
    assert len(hundred["rows"]) == 100 and hundred["params_effective"]["max_inline_rows"] == 100
    small = nf_env.call("run_netflow_query", evidence_path=str(day_dir), limit=3, force=True)
    assert small["row_count"] == 3 and small["windows_indexed"] == 4 and small["truncated"]
    assert len(small["rows"]) == 3


def test_query_limit_and_ordering_of_raw_rows(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="bytes", limit=10)
    assert resp["status"] == "success" and resp["row_count"] == 10 and resp["truncated"]
    sizes = [r["bytes"] for r in resp["rows"]]
    assert sizes == sorted(sizes, reverse=True)
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="tstart", limit=100)
    times = [r["first"] for r in resp["rows"]]
    assert times == sorted(times) and resp["row_count"] == 20 and not resp["truncated"]


def test_every_indexed_data_row_has_seconds_event_time(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    calls = [
        ("run_netflow_inventory", {}),
        ("run_netflow_top", {"stat": "srcip"}),
        ("run_netflow_host_profile", {"host": "10.0.2.37"}),
        ("run_netflow_sweep", {}),
        ("run_netflow_pair_timeline", {"src": "10.0.2.37", "dst": "203.0.113.77"}),
        (
            "run_netflow_pair_timeline",
            {"src": "10.0.2.37", "dst": "203.0.113.77", "dport": 40519, "both_directions": True},
        ),  # fmt: skip
        ("run_netflow_query", {"aggregate": ["srcip", "dstip", "dstport"]}),
        # no-match calls register an empty source and never a NULL-time data row
        ("run_netflow_pair_timeline", {"src": "192.0.2.99", "dst": "192.0.2.98"}),
        ("run_netflow_host_profile", {"host": "192.0.2.99"}),
        ("run_netflow_query", {"filter": "src ip 192.0.2.99"}),
        ("run_netflow_top", {"filter": "src ip 192.0.2.99"}),
        ("run_netflow_sweep", {"min_targets": 1000}),
    ]
    for tool, kw in calls:
        resp = nf_env.call(tool, evidence_path=str(day_dir), **kw)
        assert resp["status"] in ("success", "indexed_empty"), (tool, resp)
        assert (resp["status"] == "indexed_empty") == (resp["row_count"] == 0), (tool, resp)
        if resp["status"] == "indexed_empty":
            assert _windows(nf_env, resp["source_name"]) == []
            continue
        assert resp["windows_indexed"] <= 501
        assert len(resp["rows"]) <= 20
        windows = _windows(nf_env, resp["source_name"])  # inventory: main rows + .manifest rows
        assert windows[0].event_time is None and windows[0].raw_text.startswith("- netflow header")  # type: ignore[attr-defined]
        for w in windows[1:]:
            if w.raw_text.startswith("- netflow "):  # type: ignore[attr-defined]
                assert w.event_time is None  # type: ignore[attr-defined]
                assert w.raw_text.startswith(("- netflow file ", "- netflow header "))  # type: ignore[attr-defined]
                continue
            assert w.event_time is not None, (tool, w.raw_text)  # type: ignore[attr-defined]
            assert _EVENT_TIME.match(w.event_time), (tool, w.raw_text)  # type: ignore[attr-defined]
            assert w.raw_text.startswith(f"{w.event_time} netflow ")  # type: ignore[attr-defined]
            body = w.raw_text.split(" netflow ", 1)[1]  # type: ignore[attr-defined]
            kind, *fields = body.split(" ")
            assert kind in {"flow", "agg", "sweep", "pair", "top", "profile", "summary", "talker",
                            "service", "src_bytes", "dst_bytes", "segment"}  # fmt: skip
            assert all("=" in f for f in fields), w.raw_text  # type: ignore[attr-defined]


def test_cite_hint_names_the_source_and_search_forms(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    hint = resp["hint"]
    name = resp["source_name"]
    assert f"under source '{name}'" in hint
    assert resp["tool_call_id"] in hint
    assert f"get_raw_output('{name}', limit=1)" in hint
    assert "search(query='\"10.0.3.44\"', source='netflow')" in hint
    assert "search(query='\"dport=445\"', source='netflow', t_start='2001-02-03T14:22:07'" in hint
    # the regex example is the first row's /24
    assert "search(query=r'10\\.0\\.3\\.\\d+', regex=True, source='netflow')" in hint
    assert "get_timeline(t_start='2001-02-03T14:22:07'" in hint
    assert "T-separated" in hint
    assert " " not in Path(resp["evidence_path"]).name
    from mulder.server.tools.netflow import tools

    assert tools._subnet_regex("10.0.3.44") == "10\\.0\\.3\\.\\d+"
    assert tools._subnet_regex("2001:db8::1") == "192\\.0\\.2\\.\\d+"
    assert tools._subnet_regex("10.0.3.0/24") == "192\\.0\\.2\\.\\d+"


def test_hints_state_endpoint_double_counting_and_record_semantics(nf_env: Env) -> None:
    """ip/port statistics count a flow under both endpoints and flows=/bytes= are exporter record
    sums; the hints state both."""
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    top_ip = nf_env.call("run_netflow_top", evidence_path=str(day_dir), stat="ip")
    assert "once per endpoint" in top_ip["hint"] and "exceed 100%" in top_ip["hint"]
    assert "record counts and upper bounds" in top_ip["hint"]
    inv = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert "once per endpoint" in inv["hint"] and "can exceed 100%" in inv["hint"]
    query = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), filter="src ip 10.0.3.44",
        aggregate=["srcip", "dstip", "dstport"],
    )  # fmt: skip
    assert "aggregated rows too" in query["hint"] and "not connection counts" in query["hint"]
