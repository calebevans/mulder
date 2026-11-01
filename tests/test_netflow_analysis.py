"""``run_netflow_analysis``: the one-shot extractor that runs the NetFlow sections in one call.

What: the extractor runs the inventory, the lateral-movement sweep, three ranked lists and one
profile per busiest internal host (bytes sent plus received, internal per ``internal_nets``), in
that order and with the pivots' default parameters; every section is indexed under the same
``netflow.<kind>.<id>`` name the matching pivot would use, so a later pivot with identical
parameters is a duplicate (``skipped``); a section that fails after the inventory leaves the run
``partial`` with the other sources intact, an exception inside a section is an ``internal_error``
entry, an inventory failure is an ``error`` and nothing else runs; a section timeout surfaces as
``error_type="timeout"`` at the top level (the job store defers and retries) and a re-run without
``force`` resumes a partial run, whose summary is ``netflow.analysis-partial.<id>``, under the
completed-run name (finished sections skip themselves); the call-level
deadline marks sections it could not start ``not_run``; ``force`` re-runs every section; the
whole call writes ONE audit entry whose ``source`` is the ``netflow.analysis.<id>`` summary and
whose ``sources`` list every section source; that summary lists one row per section plus key
facts stamped with the data window's start, also when the inventory section was skipped (facts
and the readable file set are read back from its rows); the batch-skip prefix is the rowless
completion marker registered after the summary rows; the coverage audit counts the directory as
covered only by a summary source for it whose stored header says ``status=success``;
``profile_hosts`` is clamped and honours ``internal_nets``; the response carries no inline
section rows, a ``caveats`` map and a hint naming a real address.
When: hermetic; nfdump is a fake answering synthetic tables (RFC 1918 / RFC 5737 addresses,
dates in 2001, round numbers) chosen by argv shape, so nothing here depends on a captured data set.
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterator
from typing import Any

import pytest

import mulder.server.app as app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.helpers import TOOL_SOURCE_PREFIXES
from mulder.server.jobs import JobStore
from mulder.server.tool_access import Role, get_tools_for_role
from mulder.server.tools.netflow import core, tools
from tests.conftest import Env, make_tree, nfcapd

_NAME = re.compile(
    r"^netflow\.(analysis|analysis-partial|inventory|top|profile|sweep)\.[0-9a-f]{16}(-r\d+)?$"
)
_PARTIAL = "netflow.analysis-partial."
_EVENT_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
_FIXED = ["inventory", "sweep", "top_egress_bytes", "top_web_direct", "top_ingress_sources"]
_SWEEP_ARGV = "srcip,dstip,dstport,flags"
_PIVOTS = ("run_netflow_top", "run_netflow_host_profile", "run_netflow_sweep",
           "run_netflow_pair_timeline", "run_netflow_query")  # fmt: skip

# --- synthetic nfdump answers ------------------------------------------------------------------
# 981161200 = 2001-02-03T00:46:40Z; the exporter's window is 02-03T00:46:40 .. 02-04T00:00:00.
_DASH_I = """Ident: edge-router
Flows: 100
Flows_tcp: 80
Flows_udp: 15
Flows_icmp: 5
Flows_other: 0
Packets: 1000
Packets_tcp: 800
Packets_udp: 150
Packets_icmp: 50
Packets_other: 0
Bytes: 100000
Bytes_tcp: 80000
Bytes_udp: 15000
Bytes_icmp: 5000
Bytes_other: 0
First: 981161200
Last: 981244800
msec_first: 0
msec_last: 0
Sequence failures: 0
"""
_HDR = "ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,ipps,ibps,ibpp\n"
_T = "2001-02-03 00:46:40,2001-02-03 23:59:59,83599.000"
# table 0: ip/flows (both endpoints); the external 203.0.113.77 is the third talker
_TALKERS = _HDR + (
    f"{_T},any,10.0.3.44,40,40.0,400,40.0,40000,40.0,0,3,100\n"
    f"{_T},any,10.0.2.37,30,30.0,300,30.0,30000,30.0,0,3,100\n"
    f"{_T},any,203.0.113.77,20,20.0,200,20.0,20000,20.0,0,2,100\n"
)
_SERVICES = _HDR + (
    f"{_T},6    ,443,50,50.0,500,50.0,50000,50.0,0,4,100\n"
    f"{_T},6    ,445,30,30.0,300,30.0,30000,30.0,0,2,100\n"
)
# bytes per address, summed over src_bytes and dst_bytes: 10.0.2.37 95000, 203.0.113.77 80000
# (external), 10.0.3.44 70000, 10.0.5.83 30000 -> busiest internal: 10.0.2.37, 10.0.3.44, 10.0.5.83
_SRC_BYTES = _HDR + (
    f"{_T},any,10.0.2.37,10,10.0,100,10.0,90000,60.0,0,8,900\n"
    f"{_T},any,203.0.113.77,5,5.0,50,5.0,80000,30.0,0,7,1600\n"
    f"{_T},any,10.0.3.44,20,20.0,200,20.0,10000,10.0,0,1,50\n"
)
_DST_BYTES = _HDR + (
    f"{_T},any,10.0.3.44,20,20.0,200,20.0,60000,60.0,0,5,300\n"
    f"{_T},any,10.0.5.83,5,5.0,50,5.0,30000,30.0,0,2,600\n"
    f"{_T},any,10.0.2.37,10,10.0,100,10.0,5000,5.0,0,0,50\n"
)
_INVENTORY_STAT = _TALKERS + _SERVICES + _SRC_BYTES + _DST_BYTES
_SEGMENTS = (
    "firstSeen,lastSeen,srcAddr,dstAddr,packets,bytes,flows\n"
    "981161200.000,981244800.000,10.0.2.0,10.0.3.0,700,130000,28\n"
    "981161200.000,981244800.000,10.0.3.0,10.0.2.0,470,100000,27\n"
)
_SWEEP = (
    "firstSeen,lastSeen,srcAddr,dstAddr,dstPort,flags,packets,bytes,flows\n"
    "981165000.100,981165001.200,10.0.2.37,10.0.3.11,445,...A..SF,4,210,4\n"
    "981165000.300,981165001.500,10.0.2.37,10.0.3.12,445,...A..SF,4,210,4\n"
    "981165000.600,981165001.900,10.0.2.37,10.0.3.13,445,...A..SF,4,210,4\n"
)


def _profile_tables(host: str) -> str:
    """Four STAT tables: the exact host table, dstport:p, peer/flows, peer/bytes."""
    return (
        _HDR
        + f"{_T},any,{host},50,100.0,500,100.0,50000,100.0,0,10,100\n"
        + _HDR
        + f"{_T},6    ,443,6,12.0,60,12.0,6000,12.0,0,1,100\n"
        + _HDR
        + f"{_T},any,203.0.113.77,6,12.0,60,12.0,6000,12.0,0,1,100\n"
        + _HDR
        + f"{_T},any,203.0.113.77,6,12.0,60,12.0,6000,12.0,0,1,100\n"
    )


def _synthetic(cmd: list[str]) -> str | None:
    """The synthetic answer for one nfdump argv (``None`` = let the default fixtures answer)."""
    if "-I" in cmd:
        return _DASH_I
    stats = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-s"]
    filt = cmd[-1]
    if "-A" in cmd:
        keys = cmd[cmd.index("-A") + 1]
        return _SWEEP if "flags" in keys else _SEGMENTS
    if stats and stats[0] == "ip/flows" and len(stats) == 4:
        return _INVENTORY_STAT
    if stats and stats[0] in ("srcip/flows", "dstip/flows") and len(stats) == 4:
        m = re.search(r"(?:src|dst) ip (\S+)", filt)
        return _profile_tables(m.group(1) if m else "10.0.0.1")
    if len(stats) == 1:
        key = stats[0].split("/", 1)[0]
        return _TALKERS if core.stat_ip_valued(key) else _SERVICES
    return None


@pytest.fixture()
def env(nf_env: Env) -> Env:
    nf_env.fake.responder = _synthetic
    return nf_env


@pytest.fixture()
def store(nf_env: Env) -> Iterator[JobStore]:
    nf_env.monkeypatch.setattr(app, "wait_for_resources", lambda *a, **k: None)
    js = JobStore(max_workers=2, tool_dispatch=_tool_dispatch_sync)
    nf_env.monkeypatch.setattr(app, "_job_store", js)
    try:
        yield js
    finally:
        js.shutdown(wait=True)


def _analysis(env: Env, **kwargs: Any) -> dict[str, Any]:
    day_dir = env.tree(days=range(50, 52), strays=False)
    return env.call("run_netflow_analysis", evidence_path=str(day_dir), **kwargs)


def _sources(env: Env) -> list[str]:
    return [s.source_name for s in env.db.get_sources()]


def _texts(env: Env, name: str) -> list[str]:
    windows, _ = env.db.get_windows_page(name, limit=1000)
    return [str(w.raw_text) for w in windows]


def _raise_on(env: Env, marker: str, exc: BaseException, times: int = 10**9) -> list[int]:
    """Raise ``exc`` from the fake for the first ``times`` argv containing ``marker``."""
    count = [0]

    def hook(argv: list[str]) -> None:
        if any(marker in str(a) for a in argv) and count[0] < times:
            count[0] += 1
            raise exc

    env.fake.hook = hook
    return count


# ---------------------------------------------------------------------------
# section order, parameters, response shape
# ---------------------------------------------------------------------------


def test_sections_run_in_order_with_the_pivots_defaults(env: Env) -> None:
    resp = _analysis(env, profile_hosts=2)
    assert resp["status"] == "success", resp
    assert resp["tool"] == "run_netflow_analysis"
    assert _NAME.match(resp["source_name"]) and resp["source_name"].startswith("netflow.analysis.")
    sections = resp["sections"]
    assert [s["section"] for s in sections] == [*_FIXED, "profile", "profile"]
    assert [s["status"] for s in sections] == ["success"] * 7
    # the busiest INTERNAL hosts by bytes sent + received, in rank order (the external
    # 203.0.113.77 would rank second by bytes and is never profiled)
    assert [s["host"] for s in sections[5:]] == ["10.0.2.37", "10.0.3.44"]
    kinds = {s["section"]: s["source"].split(".")[1] for s in sections}
    assert kinds == {
        "inventory": "inventory", "sweep": "sweep", "top_egress_bytes": "top",
        "top_web_direct": "top", "top_ingress_sources": "top", "profile": "profile",
    }  # fmt: skip
    assert all(_NAME.match(s["source"]) for s in sections)
    assert sections[0]["manifest_source"] == sections[0]["source"] + ".manifest"
    assert sections[0]["summary"]["exporter"] == "edge-router"
    assert sections[1]["summary"]["top"]["src"] == "10.0.2.37"
    for s in sections:
        assert s["row_count"] >= 1 and s["elapsed_s"] >= 0
        assert "rows" not in s and "hint" not in s  # never inline: the rows are in the DB

    argv = [c.nfdump_argv for c in env.fake.calls]
    # inventory: one -I per file, then the STAT and segment passes
    assert argv[0][1] == "-I" and argv[1][1] == "-I"
    assert argv[2][argv[2].index("-s") + 1] == "ip/flows"
    assert argv[3][argv[3].index("-A") + 1] == core.SEG_AGG_KEYS
    # sweep with the pivot's defaults, RFC 1918 both sides
    sweep = argv[4]
    assert _SWEEP_ARGV in sweep
    assert sweep[-1].startswith(
        "proto tcp and flags S and dst port in [ 22 135 139 445 3389 5985 5986 ]"
    )
    assert sweep[sweep.index("-n") + 1] == str(core.SWEEP_TUPLE_CAP)
    # three ranked lists with the documented stat/order/direction/filter
    tops = argv[5:8]
    assert [a[a.index("-s") + 1] for a in tops] == ["dstip/bytes", "srcip/flows", "srcip/flows"]
    assert all(a[a.index("-n") + 1] == "50" for a in tops)
    src_nets = "src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16"
    dst_nets = "dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16"
    egress = f"(({src_nets}) and not ({dst_nets}))"
    assert tops[0][-1] == egress
    assert tops[1][-1] == "(dst port 80 or dst port 443) and " + egress
    assert tops[2][-1] == f"(({dst_nets}) and not ({src_nets}))"
    # two profiles, two passes each, in host order, with the pivot's default n
    profiles = argv[8:]
    assert [p[-1] for p in profiles] == [
        "src ip 10.0.2.37",
        "dst ip 10.0.2.37",
        "src ip 10.0.3.44",
        "dst ip 10.0.3.44",
    ]
    assert all(p[p.index("-n") + 1] == str(core.DEFAULT_PROFILE_N) for p in profiles)
    assert resp["params_effective"] == {
        "internal_nets": list(core.DEFAULT_INTERNAL_NETS), "n": 50, "profile_hosts": 2,
    }  # fmt: skip


def test_response_is_small_and_carries_caveats_and_argv_passes(env: Env) -> None:
    resp = _analysis(env, profile_hosts=25)
    assert len(json.dumps(resp)) < 16_000, len(json.dumps(resp))
    assert set(resp["caveats"]) == {"inventory", "sweep", "top", "profile", "analysis"}
    assert "once per endpoint" in resp["caveats"]["inventory"]
    assert "can exceed 100%" in resp["caveats"]["inventory"]
    assert "record counts" in resp["caveats"]["top"] and "targets=" in resp["caveats"]["sweep"]
    assert "top-n peer rows only" in resp["caveats"]["profile"]
    assert "not an event time" in resp["caveats"]["analysis"]
    inventory = resp["sections"][0]
    assert set(inventory["passes"]) == {"I", "stat", "segment"}
    assert set(inventory["nfdump_argv_passes"]) == {"I", "stat", "segment"}
    assert inventory["nfdump_argv_passes"]["I"] == env.fake.calls[0].cmd
    assert inventory["nfdump_argv_passes"]["stat"] == env.fake.calls[2].cmd
    assert inventory["nfdump_argv_passes"]["segment"] == env.fake.calls[3].cmd
    assert "nfdump_argv_passes" not in resp["sections"][1]
    # the hint's search example names a real address from the facts, never the placeholder
    assert "192.0.2.10" not in resp["hint"] and '"10.0.3.44"' in resp["hint"]
    assert "run_netflow_pair_timeline" in resp["hint"] and "caveats" in resp["hint"]


def test_summary_source_lists_sections_and_facts(env: Env) -> None:
    resp = _analysis(env, profile_hosts=1)
    name = resp["source_name"]
    texts = _texts(env, name)
    header, data = texts[0], texts[1:]
    assert resp["line_count"] == len(texts)
    assert header.startswith("- netflow header tool=run_netflow_analysis ")
    assert f" tool_call_id={resp['tool_call_id']} " in header
    assert (
        " n=50 profile_hosts=1 sections=6 sections_error=0 sections_not_run=0 status=success "
        in header
    )
    assert "section=" not in header
    section_rows = [t for t in data if " netflow section " in t]
    assert len(section_rows) == 6
    assert (
        section_rows[0]
        .split(" netflow section ")[1]
        .startswith(
            f"section=inventory status=success source={resp['sections'][0]['source']} rows="
        )
    )
    assert (
        " section=profile host=10.0.2.37 status=success source=netflow.profile." in section_rows[5]
    )
    facts = {t.split(" fact=")[1].split(" ")[0]: t for t in data if " netflow fact " in t}
    assert set(facts) == {
        "exporter", "top_talker", "top_sweep", "top_egress_dst", "top_web_direct_src",
        "top_ingress_src",
    }  # fmt: skip
    assert " exporter=edge-router files=2 flows=200 " in facts["exporter"]
    assert " ip=10.0.3.44 flows=40 bytes=40000" in facts["top_talker"]
    assert " src=10.0.2.37 dport=445 targets=3 burst_targets=3" in facts["top_sweep"]
    assert " ip=10.0.3.44 " in facts["top_egress_dst"]
    # every data row carries the data window's start (to the second) as its time
    windows, _ = env.db.get_windows_page(name, limit=1000)
    assert {w.event_time for w in windows[1:]} == {"2001-02-03T00:46:40"}
    assert resp["summary"] == {
        "status": "success", "sections": 6, "sections_ok": 6, "sections_skipped": 0,
        "sections_error": 0, "sections_not_run": 0, "profiles": 1, "exporter": "edge-router",
        "files": 2, "flows": 200, "first": "2001-02-03T00:46:40.000",
        "last": "2001-02-04T00:00:00.000",
    }  # fmt: skip
    assert resp["rows"][0]["kind"] == "fact" and resp["rows"][-1]["kind"] == "caveat"
    assert resp["row_count"] == len(data)
    # the reading notes are rows of the summary source, so the analyst finds them with search
    # and get_raw_output (the envelope's caveats{} never reaches a model that used a batch)
    caveats = {t.split(" about=")[1].split(" ", 1)[0]: t for t in data if " netflow caveat " in t}
    assert set(caveats) == {"inventory", "sweep", "top", "profile", "analysis"}
    assert "once per endpoint" in caveats["inventory"] and "exceed 100%" in caveats["inventory"]
    assert "targets= and burst_targets=" in caveats["sweep"]
    assert (
        resp["rows"][-1]["about"] == "analysis" and "not an event time" in resp["rows"][-1]["text"]
    )
    hits = env.db.search_windows(
        "once per endpoint", source_name="netflow.analysis", max_results=5
    )
    assert hits and " netflow caveat about=inventory " in hits[0][0].raw_text
    # the section sources are reachable by their names and share the extractor's call id
    for s in resp["sections"]:
        first = _texts(env, s["source"])[0]
        assert first.startswith("- netflow header tool=run_netflow_analysis ")
        assert f" tool_call_id={resp['tool_call_id']} section={s['section']} " in first
    assert env.db.search_windows("netflow", source_name="netflow.analysis", max_results=100)


def test_progress_source_records_running_then_the_outcome(env: Env) -> None:
    resp = _analysis(env, profile_hosts=0)
    hid = resp["source_name"].split(".")[2]
    names = _sources(env)
    assert names[0] == f"netflow.progress.{hid}"  # registered before any section
    assert names[-2] == resp["source_name"]  # the summary, then the rowless completion marker
    assert names[-1] == f"netflow.complete.{hid}"
    header, footer = _texts(env, f"netflow.progress.{hid}")
    assert " status=running " in header and f" summary_planned={resp['source_name']} " in header
    assert f" summary_id={hid} " in header  # the hash pairs progress and summary runs
    assert " sections_planned=5 " in header and f" tool_call_id={resp['tool_call_id']} " in header
    assert footer.startswith("- netflow footer status=success ")
    assert f" summary={resp['source_name']} sections=5 sections_error=0" in footer
    # the progress rows are bookkeeping without an event time; the summary rows carry the window
    assert not env.db.search_windows("netflow", source_name="netflow.progress", max_results=10,
                                     time_start="2000-01-01T00:00:00")  # fmt: skip
    assert env.db.search_windows("netflow", source_name="netflow.analysis", max_results=10,
                                 time_start="2000-01-01T00:00:00")  # fmt: skip


# ---------------------------------------------------------------------------
# duplicates, prefix, audit, coverage, roles
# ---------------------------------------------------------------------------


def test_pivots_with_section_parameters_are_duplicates(env: Env) -> None:
    resp = _analysis(env, profile_hosts=1)
    day_dir = resp["evidence_path"]
    by_name = {s["section"]: s for s in resp["sections"]}
    calls_before = len(env.fake.calls)

    sweep = env.call("run_netflow_sweep", evidence_path=day_dir)
    assert sweep["status"] == "skipped" and sweep["source_name"] == by_name["sweep"]["source"]
    top = env.call("run_netflow_top", evidence_path=day_dir, stat="dstip", order="bytes",
                   direction="egress", n=50)  # fmt: skip
    assert (
        top["status"] == "skipped" and top["source_name"] == by_name["top_egress_bytes"]["source"]
    )
    web = env.call("run_netflow_top", evidence_path=day_dir, stat="srcip", order="flows", n=50,
                   direction="egress", filter="dst port 80 or dst port 443")  # fmt: skip
    assert web["status"] == "skipped" and web["source_name"] == by_name["top_web_direct"]["source"]
    ingress = env.call("run_netflow_top", evidence_path=day_dir, stat="srcip", n=50,
                       direction="ingress")  # fmt: skip
    assert ingress["status"] == "skipped"
    assert ingress["source_name"] == by_name["top_ingress_sources"]["source"]
    profile = env.call("run_netflow_host_profile", evidence_path=day_dir, host="10.0.2.37")
    assert (
        profile["status"] == "skipped" and profile["source_name"] == by_name["profile"]["source"]
    )
    assert len(env.fake.calls) == calls_before  # no nfdump ran for a duplicate
    for dup in (sweep, top, web, ingress, profile):
        assert f"get_raw_output('{dup['source_name']}')" in dup["hint"]
    # a different window or host is a new call
    other = env.call("run_netflow_top", evidence_path=day_dir, stat="dstip", order="bytes",
                     direction="egress", n=50, t_start="2001-02-19T00:00:00",
                     t_end="2001-02-19T23:59:59")  # fmt: skip
    assert other["status"] == "success" and other["source_name"] != top["source_name"]
    fresh = env.call("run_netflow_host_profile", evidence_path=day_dir, host="10.0.5.83")
    assert fresh["status"] == "success" and fresh["source_name"] != profile["source_name"]


def test_batch_prefix_is_the_completion_marker_and_roles_are_split() -> None:
    assert TOOL_SOURCE_PREFIXES["run_netflow_analysis"] == ["netflow.complete."]
    extract = {t.removeprefix("mcp__mulder__") for t in get_tools_for_role(Role.EXTRACT_EXECUTOR)}
    analyst = {t.removeprefix("mcp__mulder__") for t in get_tools_for_role(Role.EXTRACT_ANALYST)}
    cross = {t.removeprefix("mcp__mulder__") for t in get_tools_for_role(Role.CROSS_EXECUTOR)}
    assert "run_netflow_analysis" in extract
    assert "run_netflow_analysis" not in analyst and "run_netflow_analysis" not in cross
    for pivot in _PIVOTS:
        assert pivot in analyst and pivot in cross and pivot not in extract, pivot


def test_batch_skips_the_extractor_only_after_a_completed_run(env: Env, store: JobStore) -> None:
    day_dir = str(env.tree(days=range(50, 52), strays=False))
    task = [
        {"tool": "run_netflow_analysis", "args": {"evidence_path": day_dir, "profile_hosts": 0}}
    ]
    # a pivot (or a crashed run) leaves netflow.* sources; they must not hide the extractor
    assert env.call("run_netflow_sweep", evidence_path=day_dir)["status"] == "success"
    first = env.call("start_extraction_batch", tasks=task)
    assert first["status"] != "error" and first.get("tasks_skipped", []) == [], first
    (batch_id,) = store.batch_ids()
    assert store.wait_for_batch(batch_id, timeout=120)
    (result,) = env.call("get_completed_results", batch_id=batch_id)["results"]
    assert result["result_status"] == "success"
    assert result["source_name"].startswith("netflow.analysis.")
    # the completed run registered its rowless completion marker LAST, after the summary rows
    marker = "netflow.complete." + result["source_name"].split(".", 2)[2]
    names = _sources(env)
    assert names[-1] == marker and names[-2] == result["source_name"]
    assert env.db.get_windows_by_source(marker) == []
    # the sweep section was the pivot's duplicate; the marker is what hides a second task
    second = env.call("start_extraction_batch", tasks=task)
    skipped = second.get("tasks_skipped", [])
    assert [t["tool"] for t in skipped] == ["run_netflow_analysis"]
    assert skipped[0]["existing_sources"] == [marker]


def test_one_audit_entry_carries_every_section_source(env: Env) -> None:
    resp = _analysis(env, profile_hosts=2)
    entries = env.audit_entries()
    assert len(entries) == 1, [e["tool_name"] for e in entries]
    (entry,) = entries
    assert entry["tool_call_id"] == resp["tool_call_id"]
    assert entry["tool_name"] == "run_netflow_analysis"
    assert entry["params"]["source"] == resp["source_name"]
    assert entry["params"]["evidence_path"] == resp["evidence_path"]
    assert entry["params"]["profile_hosts"] == 2
    expected = [s["source"] for s in resp["sections"]]
    expected.insert(1, resp["sections"][0]["manifest_source"])
    assert entry["params"]["sources"] == expected
    assert env.audit.has_tool_call(resp["tool_call_id"])
    assert env.audit.summary().tool_call_counts == {"run_netflow_analysis": 1}
    # the provenance chain resolves a finding citing the extractor to the summary and every
    # section source, manifest included
    env.audit.log_finding_submission("f_test", [resp["tool_call_id"]])
    chain = env.audit.get_provenance_chain("f_test", env.db)
    assert {s.source_name for s in chain.sources} == {resp["source_name"], *expected}
    skipped = _analysis(env, profile_hosts=2)
    assert skipped["status"] == "skipped"
    assert env.audit_entry(skipped["tool_call_id"])["params"]["source"] == resp["source_name"]
    assert len(env.audit_entries()) == 2


def test_coverage_counts_only_a_summary_for_the_directory(env: Env) -> None:
    day_dir = str(env.tree(days=range(50, 52), strays=False))
    other = str(make_tree(env.evidence_root / "other", days=range(50, 51), strays=False))

    def items() -> dict[str, dict[str, Any]]:
        cov = env.call("audit_tool_coverage")
        assert cov["status"] == "success", cov
        return {i["path"]: i for i in cov["coverage"] if i["artifact_type"] == "netflow_capture"}

    # a pivot alone, and an extractor run on ANOTHER directory, cover nothing here
    assert env.call("run_netflow_sweep", evidence_path=day_dir)["status"] == "success"
    assert (
        env.call("run_netflow_analysis", evidence_path=other, profile_hosts=0)["status"]
        == "success"
    )
    before = items()
    assert before[day_dir]["tools_run"] == [] and before[day_dir]["tools_not_run"] == [
        "run_netflow_analysis"
    ]
    assert before[other]["tools_run"] == ["run_netflow_analysis"]
    # a failed run leaves no summary and covers nothing
    env.fake.returncode, env.fake.stderr = 250, "Error open file: x\n"
    assert (
        env.call("run_netflow_analysis", evidence_path=day_dir, profile_hosts=0)["status"]
        == "error"
    )
    env.fake.returncode, env.fake.stderr = 0, ""
    assert items()[day_dir]["tools_run"] == []
    # a summary registered for the directory (here: via its parent) covers it
    parent = str(env.evidence_root / "netflow")
    ok = env.call("run_netflow_analysis", evidence_path=parent, profile_hosts=0)
    assert ok["status"] == "success", ok
    after = items()
    assert (
        after[day_dir]["tools_run"] == ["run_netflow_analysis"]
        and after[day_dir]["tools_not_run"] == []
    )


def test_planner_and_analyst_prompts_advertise_the_right_tools() -> None:
    from mulder.orchestrator.phases import CROSS_SYSTEM, EXTRACTION

    extraction = EXTRACTION.planner_system_prompt
    block = extraction[extraction.index("When the evidence includes NETFLOW") :]
    block = block[: block.index("\n\n")]
    assert "run_netflow_analysis(evidence_path=" in block and "foundation" in block
    assert not re.search(r"run_netflow_(top|host_profile|sweep|pair_timeline|query)", block)
    assert "never from another system's plan" in block
    cross = CROSS_SYSTEM.planner_system_prompt
    para = cross[cross.index("For NetFlow evidence") : cross.index("OUTPUT (MANDATORY)")]
    assert "run_netflow_analysis" not in para and "netflow.analysis.*" in para
    analyst = EXTRACTION.analyst_system_prompt
    follow = analyst[analyst.index("TARGETED FOLLOW-UP TOOLS (NetFlow)") :]
    follow = follow[: follow.index("\n\n")]
    assert all(p in follow for p in _PIVOTS) and "run_netflow_analysis" not in follow
    assert "once per endpoint" in analyst and "not an event time" in analyst
    assert re.search(r"data\s+window's start", analyst)
    assert "targets=/burst_targets=" in analyst and "hints_partial=true" in analyst
    # in flight vs finished incomplete: the progress footer and the -partial summary decide
    assert "netflow.progress.<id>" in analyst and re.search(r"in\s+flight", analyst)
    assert "netflow.analysis-partial.<id>" in analyst and "status=partial/error" in analyst
    # closure and dead-run rules: a newer completed summary closes older records of the id; a
    # header-only progress record next to a completed summary or marker is not in flight
    assert re.search(r"status=success exists, which closes every older record", analyst)
    assert re.search(r"netflow\.complete\.<id> for that id exists", analyst)
    assert re.search(r"regex=True", analyst) and re.search(r"without\s+t_start/t_end", analyst)
    assert re.search(r"src/dst/dport/first", analyst)
    assert "recurring bulk egress" in analyst  # the T1048 example names no protocol
    assert re.search(r"fan-out\s+T1046/T1021;", analyst)  # nor a sub-technique for the fan-out
    assert "analysis-partial" in para
    cross_analyst = CROSS_SYSTEM.analyst_system_prompt
    assert "netflow.analysis.<id>" in cross_analyst and "record counts" in cross_analyst
    assert (
        "netflow.analysis-partial.<id>" in cross_analyst
        and "netflow.progress.<id>" in cross_analyst
    )
    assert (
        re.search(r"data\s+window's start", cross_analyst) and "once per endpoint" in cross_analyst
    )
    assert re.search(r"sweep rows\s+burst_start", cross_analyst)
    assert re.search(r"status=success\s+closes every older", cross_analyst)
    assert re.search(r"netflow\.complete source for that id exists", cross_analyst)
    assert "tool_call_id" in cross_analyst[cross_analyst.index("NETFLOW EVIDENCE:") :]


# ---------------------------------------------------------------------------
# failure semantics: partial, internal errors, audited errors, resume, timeouts, deadline
# ---------------------------------------------------------------------------


def test_later_section_failure_is_partial_then_resumes(env: Env) -> None:
    _raise_on(env, _SWEEP_ARGV, OSError("exec failed on the sweep"))
    resp = _analysis(env, profile_hosts=1)
    assert resp["status"] == "partial", resp
    assert "error_type" not in resp  # a non-timeout failure does not fail the job
    statuses = {s["section"]: s["status"] for s in resp["sections"]}
    assert statuses == {
        "inventory": "success", "sweep": "error", "top_egress_bytes": "success",
        "top_web_direct": "success", "top_ingress_sources": "success", "profile": "success",
    }  # fmt: skip
    sweep = resp["sections"][1]
    assert sweep["error_type"] == "os_error" and "exec failed" in sweep["error"]
    assert "source" not in sweep
    names = _sources(env)
    assert not any(n.startswith("netflow.sweep.") for n in names)
    # a partial summary registers no completion marker, so a batch retry reaches the tool
    assert resp["source_name"].startswith(_PARTIAL) and _NAME.match(resp["source_name"])
    assert not any(n.startswith("netflow.analysis.") for n in names)
    assert resp["sections"][0]["source"] in names and resp["source_name"] == names[-1]
    assert resp["summary"]["sections_error"] == 1 and resp["summary"]["sections_ok"] == 5
    text = "\n".join(_texts(env, resp["source_name"]))
    assert " section=sweep status=error source=- rows=0 error_type=os_error" in text
    assert " sections=6 sections_error=1 sections_not_run=0 status=partial " in text
    assert " footer status=partial " in _texts(env, _sources(env)[0])[1]
    assert f" summary={resp['source_name']} " in _texts(env, _sources(env)[0])[1]
    assert "resume" in resp["hint"]
    (entry,) = env.audit_entries()
    assert entry["tool_call_id"] == resp["tool_call_id"]
    assert entry["params"]["source"] == resp["source_name"]
    cov = env.call("audit_tool_coverage")
    item = next(i for i in cov["coverage"] if i["path"] == resp["evidence_path"])
    assert item["tools_not_run"] == ["run_netflow_analysis"]  # a partial run covers nothing

    # a re-run without force RESUMES: the failed section runs again, the others skip themselves,
    # and the completed run's summary takes the netflow.analysis. name (then the marker)
    env.fake.hook = None
    calls = len(env.fake.calls)
    again = _analysis(env, profile_hosts=1)
    hid = resp["source_name"].removeprefix(_PARTIAL)
    assert again["status"] == "success" and again["source_name"] == f"netflow.analysis.{hid}"
    assert again["summary"]["resumed"] == resp["source_name"]
    assert [s["status"] for s in again["sections"]] == [
        "skipped",
        "success",
        "skipped",
        "skipped",
        "skipped",
        "skipped",
    ]
    assert again["sections"][1]["source"].startswith("netflow.sweep.")
    assert len(env.fake.calls) == calls + 1  # only the sweep ran
    assert _texts(env, again["source_name"])[0].endswith(f" supersedes={resp['source_name']}")
    # ... and a completed run is skipped as usual
    assert _analysis(env, profile_hosts=1)["status"] == "skipped"


def test_exception_inside_a_section_is_internal_error_and_run_continues(env: Env) -> None:
    _raise_on(env, "dst port 80 or dst port 443", RuntimeError("boom in the web list"))
    resp = _analysis(env, profile_hosts=1)
    assert resp["status"] == "partial", resp
    assert "error_type" not in resp
    web = resp["sections"][3]
    assert web["section"] == "top_web_direct" and web["status"] == "error"
    assert web["error_type"] == "internal_error" and "boom in the web list" in web["error"]
    assert [s["status"] for s in resp["sections"]] == [
        "success",
        "success",
        "success",
        "error",
        "success",
        "success",
    ]
    assert resp["source_name"] in _sources(env)
    assert len(env.audit_entries()) == 1
    # the nfdump slot was released by the failing section: the sections after it ran
    assert len([c for c in env.fake.calls if "src ip 10.0.2.37" in c.cmd[-1]]) == 1


def test_exception_after_sections_is_an_audited_error_with_sources(env: Env) -> None:
    real = tools._index_rows

    def boom(name: str, path: str, rows: Any) -> Any:
        if name.startswith("netflow.analysis."):
            raise RuntimeError("database write failed")
        return real(name, path, rows)

    env.monkeypatch.setattr(tools, "_index_rows", boom)
    resp = _analysis(env, profile_hosts=1)
    assert resp["status"] == "error" and resp["error_type"] == "internal_error", resp
    assert "database write failed" in resp["error_message"]
    assert "retry run_netflow_analysis" in resp["error_message"]  # the recovery reaches a batch
    assert [s["status"] for s in resp["sections"]] == ["success"] * 6
    assert resp["sources"] and resp["sources"][0].startswith("netflow.inventory.")
    (entry,) = env.audit_entries()
    assert entry["tool_call_id"] == resp["tool_call_id"]
    assert entry["params"]["sources"] == resp["sources"]  # the headers' call id is on record
    assert not any(n.startswith("netflow.analysis.") for n in _sources(env))
    assert " footer status=error " in _texts(env, _sources(env)[0])[1]
    # the next call is not skipped (no summary) and finds every section already indexed
    env.monkeypatch.setattr(tools, "_index_rows", real)
    again = _analysis(env, profile_hosts=1)
    assert again["status"] == "success" and again["summary"]["sections_skipped"] == 6


def test_inventory_failure_is_an_error_and_stops(env: Env) -> None:
    env.fake.responder = None
    env.fake.returncode = 250
    env.fake.stderr = "Error open file: x\n"
    resp = _analysis(env)
    assert resp["status"] == "error" and resp["error_type"] == "file_not_found", resp
    assert resp["error_message"].startswith("inventory section failed: no readable nfcapd files")
    assert resp["sections"] == [{
        "section": "inventory", "status": "error", "error_type": "file_not_found",
        "error": resp["error_message"].removeprefix("inventory section failed: "),
        "suggestion": "every candidate failed nfdump -I; see files_excluded",
    }]  # fmt: skip
    assert all(c.nfdump_argv[1] == "-I" for c in env.fake.calls)
    assert [n for n in _sources(env) if not n.startswith("netflow.progress.")] == []
    (entry,) = env.audit_entries()
    assert entry["tool_call_id"] == resp["tool_call_id"] and "source" not in entry["params"]


def test_section_timeout_surfaces_at_the_top_level_and_resume_reruns_it(env: Env) -> None:
    _raise_on(env, _SWEEP_ARGV, subprocess.TimeoutExpired(cmd="nfdump", timeout=5), times=1)
    resp = _analysis(env, profile_hosts=1)
    assert resp["status"] == "partial" and resp["error_type"] == "timeout", resp
    assert "sweep" in resp["error_message"] and "re-run without force" in resp["error_message"]
    assert resp["sections"][1]["error_type"] == "timeout"
    assert resp["summary"]["sections_error"] == 1
    assert resp["source_name"].startswith(_PARTIAL)
    again = _analysis(env, profile_hosts=1)
    assert again["status"] == "success" and "error_type" not in again
    assert again["source_name"] == "netflow.analysis." + resp["source_name"].removeprefix(_PARTIAL)
    assert again["sections"][1]["status"] == "success"


def test_batch_defers_a_timed_out_section_and_the_retry_resumes(env: Env, store: JobStore) -> None:
    day_dir = str(env.tree(days=range(50, 52), strays=False))
    _raise_on(env, _SWEEP_ARGV, subprocess.TimeoutExpired(cmd="nfdump", timeout=5), times=1)
    env.monkeypatch.setattr("mulder.server.jobs.should_defer", lambda other_running: True)
    batch = store.submit_batch(
        [{"tool": "run_netflow_analysis", "args": {"evidence_path": day_dir, "profile_hosts": 1}}]
    )
    assert batch.done_event.wait(timeout=120)
    status = store.get_batch_status(batch.batch_id)
    assert status is not None and status["completed"] == 1 and status["failed"] == 0, status
    (result,) = env.call("get_completed_results", batch_id=batch.batch_id)["results"]
    assert result["result_status"] == "success"
    # the deferred retry resumed the partial run: its summary took the completed-run name
    partial = [n for n in _sources(env) if n.startswith(_PARTIAL)]
    done = [n for n in _sources(env) if n.startswith("netflow.analysis.")]
    assert len(partial) == 1 and done == [result["source_name"]]
    assert result["source_name"] == "netflow.analysis." + partial[0].removeprefix(_PARTIAL)


def test_deadline_marks_the_remaining_sections_not_run(env: Env) -> None:
    env.monkeypatch.setattr(core, "ANALYSIS_DEADLINE_S", tools._DEADLINE_MARGIN_S - 1)
    resp = _analysis(env, profile_hosts=2)
    assert resp["status"] == "partial" and resp["error_type"] == "timeout", resp
    # the four fixed sections and the two profiles the inventory would have chosen
    assert [s["status"] for s in resp["sections"]] == ["success", *["not_run"] * 6]
    assert [s.get("host") for s in resp["sections"][5:]] == ["10.0.2.37", "10.0.3.44"]
    assert (
        resp["sections"][1]["error_type"] == "timeout"
        and "deadline" in resp["sections"][1]["error"]
    )
    assert resp["summary"]["sections_not_run"] == 6 and resp["summary"]["profiles"] == 0
    assert "not started" in resp["error_message"]
    assert len(env.fake.calls) == 4  # the inventory only
    text = "\n".join(_texts(env, resp["source_name"]))
    assert " section=sweep status=not_run source=- rows=0 error_type=timeout" in text
    assert " sections_not_run=6 status=partial " in text
    # with the deadline restored, a re-run resumes and runs what was not started
    env.monkeypatch.setattr(core, "ANALYSIS_DEADLINE_S", 7200)
    again = _analysis(env, profile_hosts=2)
    assert again["status"] == "success" and again["source_name"].startswith("netflow.analysis.")
    assert again["summary"]["resumed"] == resp["source_name"]
    assert [s["status"] for s in again["sections"]] == ["skipped", *["success"] * 6]


def test_deadline_caps_every_nfdump_timeout(env: Env) -> None:
    env.monkeypatch.setattr(core, "ANALYSIS_DEADLINE_S", 100)
    resp = _analysis(env, profile_hosts=1)
    assert resp["status"] == "success"
    assert all(c.timeout <= 100 for c in env.fake.calls)
    assert all(c.timeout >= 1 for c in env.fake.calls)
    pivot = env.call("run_netflow_top", evidence_path=resp["evidence_path"], stat="srcport")
    assert pivot["status"] == "success"
    assert (
        env.fake.last.timeout > 100
    )  # a pivot on its own is not capped by the extractor's deadline


def test_force_reruns_every_section_as_r1(env: Env) -> None:
    first = _analysis(env, profile_hosts=1)
    forced = _analysis(env, profile_hosts=1, force=True)
    assert forced["status"] == "success"
    assert forced["source_name"] == first["source_name"] + "-r1"
    for a, b in zip(first["sections"], forced["sections"], strict=True):
        assert b["status"] == "success" and b["source"] == a["source"] + "-r1"
    assert (
        forced["sections"][0]["manifest_source"] == first["sections"][0]["source"] + "-r1.manifest"
    )
    assert _texts(env, forced["source_name"])[0].endswith(f" supersedes={first['source_name']}")
    dup = env.call("run_netflow_sweep", evidence_path=first["evidence_path"])
    assert dup["status"] == "skipped" and dup["source_name"] == forced["sections"][1]["source"]
    assert dup["existing_sources"] == [
        first["sections"][1]["source"],
        forced["sections"][1]["source"],
    ]


# ---------------------------------------------------------------------------
# a skipped inventory: facts, hosts and the readable file set come from its rows
# ---------------------------------------------------------------------------


def test_skipped_inventory_keeps_window_facts_and_hosts(env: Env) -> None:
    first = _analysis(env, profile_hosts=0)
    assert [s["status"] for s in first["sections"]] == ["success"] * 5
    again = _analysis(env, profile_hosts=3)  # a different id: profile_hosts is a parameter
    assert again["status"] == "success" and again["source_name"] != first["source_name"]
    assert [s["status"] for s in again["sections"][:5]] == ["skipped"] * 5
    assert [s["source"] for s in again["sections"][:5]] == [s["source"] for s in first["sections"]]
    assert again["sections"][0]["row_count"] == first["sections"][0]["row_count"]
    # the busiest hosts come from the indexed inventory rows, so the profiles still run
    assert [s["host"] for s in again["sections"][5:]] == ["10.0.2.37", "10.0.3.44", "10.0.5.83"]
    assert [s["status"] for s in again["sections"][5:]] == ["success"] * 3
    assert again["summary"] == {
        **first["summary"], "sections": 8, "sections_ok": 3, "sections_skipped": 5, "profiles": 3,
    }  # fmt: skip
    assert len(env.fake.calls) == 2 + 2 + 1 + 3 + 2 * 3  # only the profiles ran the second time
    # the resumed call's audit entry and provenance chain still carry the inventory manifest
    entry = env.audit_entry(again["tool_call_id"])
    assert f"{again['sections'][0]['source']}.manifest" in entry["params"]["sources"]
    env.audit.log_finding_submission("f_skip", [again["tool_call_id"]])
    chain = {s.source_name for s in env.audit.get_provenance_chain("f_skip", env.db).sources}
    assert f"{again['sections'][0]['source']}.manifest" in chain and again["source_name"] in chain
    # the summary rows keep the window and every fact, read back from the skipped sections
    first_texts, again_texts = _texts(env, first["source_name"]), _texts(env, again["source_name"])

    def facts(ts: list[str]) -> set[str]:
        return {t.split(" fact=")[1] for t in ts if " netflow fact " in t}

    assert facts(again_texts) == facts(first_texts)
    windows, _ = env.db.get_windows_page(again["source_name"], limit=1000)
    assert {w.event_time for w in windows[1:]} == {"2001-02-03T00:46:40"}
    assert '"10.0.3.44"' in again["hint"]


def test_skipped_inventory_reads_only_the_files_it_accepted(env: Env) -> None:
    day_dir = env.tree(days=range(50, 53), strays=False)
    bad = str(day_dir / "nfcapd.200102200000")
    real = env.fake.responder

    def responder(cmd: list[str]) -> str | None:
        if "-I" in cmd and cmd[-1] == bad:
            env.fake.returncode, env.fake.stderr = 250, "Error open file: x\n"
        else:
            env.fake.returncode, env.fake.stderr = 0, ""
        return real(cmd) if real else None

    env.fake.responder = responder
    first = env.call("run_netflow_analysis", evidence_path=str(day_dir), profile_hosts=0)
    assert first["status"] == "success" and first["files_scanned"] == 2, first
    assert [e["path"] for e in first["files_excluded"]] == [bad]
    again = env.call("run_netflow_analysis", evidence_path=str(day_dir), profile_hosts=0,
                     internal_nets=["10.0.0.0/8"])  # fmt: skip
    assert again["status"] == "success", again
    assert again["sections"][0]["status"] == "skipped" and again["files_scanned"] == 2
    assert [s["status"] for s in again["sections"][1:]] == ["success"] * 4
    staged = [c for c in env.fake.calls if c.read_args[0] == "-R"]
    assert len(staged) == 2 + 4 + 4 and not any(bad in a for c in staged for a in c.cmd)
    assert any("not in the indexed inventory's manifest" in w for w in again["warnings"])
    # the dropped file is listed, as the first run listed it
    assert [e["path"] for e in again["files_excluded"]] == [bad]
    assert "manifest" in again["files_excluded"][0]["reason"]
    assert again["sections"][0]["manifest_source"] == first["sections"][0]["manifest_source"]


def test_inventory_id_salts_n_only_when_not_default(env: Env) -> None:
    default = _analysis(env, profile_hosts=0)
    explicit = _analysis(env, profile_hosts=1, n=50)
    assert explicit["sections"][0]["status"] == "skipped"
    assert explicit["sections"][0]["source"] == default["sections"][0]["source"]
    bigger = _analysis(env, profile_hosts=0, n=100)
    assert bigger["sections"][0]["status"] == "success"
    assert bigger["sections"][0]["source"] != default["sections"][0]["source"]
    assert " n=100 " in _texts(env, bigger["sections"][0]["source"])[0]
    assert bigger["sections"][2]["status"] == "success"  # the tops carry n in their ids too


# ---------------------------------------------------------------------------
# profile_hosts and internal_nets, arguments
# ---------------------------------------------------------------------------


def test_profile_hosts_clamped_internal_only_and_zero(env: Env) -> None:
    resp = _analysis(env, profile_hosts=99)
    assert resp["params_effective"]["profile_hosts"] == 25
    assert [s["host"] for s in resp["sections"] if s["section"] == "profile"] == [
        "10.0.2.37",
        "10.0.3.44",
        "10.0.5.83",  # every internal host, never 203.0.113.77
    ]
    env.fake.calls.clear()
    day_dir = resp["evidence_path"]
    narrow = env.call("run_netflow_analysis", evidence_path=day_dir, profile_hosts=5,
                      internal_nets=["10.0.3.0/24"])  # fmt: skip
    assert narrow["status"] == "success" and narrow["source_name"] != resp["source_name"]
    assert [s["host"] for s in narrow["sections"] if s["section"] == "profile"] == ["10.0.3.44"]
    assert narrow["params_effective"]["internal_nets"] == ["10.0.3.0/24"]
    # the narrowed nets also drive the sweep and direction clauses (new section ids, not skips);
    # the inventory (path-only id) is a skip and the host came from its indexed rows
    assert [s["status"] for s in narrow["sections"]] == ["skipped", *["success"] * 5]
    sweep_argv = [c.nfdump_argv for c in env.fake.calls if _SWEEP_ARGV in c.nfdump_argv]
    assert (
        len(sweep_argv) == 1
        and "(src net 10.0.3.0/24) and (dst net 10.0.3.0/24)" in sweep_argv[0][-1]
    )
    zero = env.call("run_netflow_analysis", evidence_path=day_dir, profile_hosts=0, force=True)
    assert zero["status"] == "success"
    assert not any(s["section"] == "profile" for s in zero["sections"])
    assert zero["summary"]["profiles"] == 0


def test_profiles_counts_only_the_profiles_that_ran(env: Env) -> None:
    _raise_on(env, "dst ip 10.0.3.44", OSError("exec failed"))
    resp = _analysis(env, profile_hosts=2)
    assert resp["status"] == "partial"
    assert [s["status"] for s in resp["sections"][5:]] == ["success", "error"]
    assert resp["summary"]["profiles"] == 1


def test_invalid_arguments_are_audited_and_run_nothing(env: Env) -> None:
    day_dir = env.tree(days=range(50, 52), strays=False)
    for kwargs in (
        {"n": "fifty"},
        {"profile_hosts": "many"},
        {"internal_nets": ["not-a-net"]},
        {"internal_nets": ["10.0.0.0/8"] * 9},
    ):
        resp = env.call("run_netflow_analysis", evidence_path=str(day_dir), **kwargs)
        assert resp["status"] == "error" and resp["error_type"] == "invalid_argument", (
            kwargs,
            resp,
        )
        assert resp["tool"] == "run_netflow_analysis" and "sections" not in resp
        assert env.audit_entry(resp["tool_call_id"])["tool_name"] == "run_netflow_analysis"
    assert env.fake.calls == [] and _sources(env) == []


# ---------------------------------------------------------------------------
# batch 4: the manifest read-back, the outer guard, the batch retry, sizes, progress re-runs
# ---------------------------------------------------------------------------


def _rotation_tree(env: Env, count: int, sub: str = "edge-router") -> Any:
    """``count`` magic-valid files at nfcapd's default 5-minute rotation from 2001-02-03."""
    from datetime import datetime, timedelta

    d = env.evidence_root / "rotation" / sub / "2001" / "02"
    t0 = datetime(2001, 2, 3)
    for i in range(count):
        nfcapd(d, name=f"nfcapd.{t0 + timedelta(minutes=5 * i):%Y%m%d%H%M}")
    return d


def test_more_than_400_files_run_and_a_skipped_inventory_still_reads_every_file(env: Env) -> None:
    """The file cap is not the old 400 (two days of 5-minute rotation), and the manifest a
    later call reads back is not capped at one page: every accepted file is read again."""
    assert core.MAX_FILES > 600  # the tests below do not override it
    d = _rotation_tree(env, 600)
    first = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0)
    assert first["status"] == "success" and first["files_scanned"] == 600, first
    assert first["sections"][0]["manifest_source"].endswith(".manifest")
    assert len(_texts(env, first["sections"][0]["manifest_source"])) == 601  # header + 600
    # a re-run with other parameters skips the inventory and reads the SAME 600 files
    calls = len(env.fake.calls)
    again = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0,
                     internal_nets=["10.0.0.0/8"])  # fmt: skip
    assert again["status"] == "success" and again["files_scanned"] == 600, again
    assert again["sections"][0]["status"] == "skipped"
    assert again["files_excluded"] == [] and not any("manifest" in w for w in again["warnings"])
    assert len(env.fake.calls) == calls + 4  # sweep + three lists, no -I pass
    # ... and so does a resume after a failed section
    _raise_on(env, _SWEEP_ARGV, subprocess.TimeoutExpired(cmd="nfdump", timeout=5), times=1)
    forced = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0, force=True)
    assert forced["status"] == "partial" and forced["files_scanned"] == 600
    env.fake.hook = None
    resumed = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0)
    assert resumed["status"] == "success" and resumed["files_scanned"] == 600, resumed
    # the first run's sweep (same parameters, complete) already exists, so it is a skip
    assert resumed["sections"][1]["status"] == "skipped"
    assert resumed["sections"][1]["source"] == first["sections"][1]["source"]
    assert resumed["summary"]["resumed"] == forced["source_name"]


def test_manifest_matches_files_by_full_path_not_by_name(env: Env) -> None:
    """Two exporters may keep a file of the same name; a digit-only name must survive the
    read-back as text.  The rejected twin stays excluded on a re-run, the accepted one and the
    digit-only file are read."""
    root = env.evidence_root / "twins"
    good = nfcapd(root / "rtr-a", name="nfcapd.200102030000")
    bad = nfcapd(root / "rtr-b", name="nfcapd.200102030000")
    digits = nfcapd(root / "rtr-a", name="000123")
    real = env.fake.responder

    def responder(cmd: list[str]) -> str | None:
        if "-I" in cmd and cmd[-1] == str(bad):
            env.fake.returncode, env.fake.stderr = 250, "Error open file: x\n"
        else:
            env.fake.returncode, env.fake.stderr = 0, ""
        return real(cmd) if real else None

    env.fake.responder = responder
    first = env.call("run_netflow_analysis", evidence_path=str(root), profile_hosts=0)
    assert first["status"] == "success" and first["files_scanned"] == 2, first
    assert [e["path"] for e in first["files_excluded"]] == [str(bad)]
    manifest = "\n".join(_texts(env, first["sections"][0]["manifest_source"]))
    assert " name=000123 " in manifest and f" path={digits} " in manifest
    again = env.call("run_netflow_analysis", evidence_path=str(root), profile_hosts=0,
                     internal_nets=["10.0.0.0/8"])  # fmt: skip
    assert again["status"] == "success" and again["files_scanned"] == 2, again
    assert again["sections"][0]["status"] == "skipped"
    assert [e["path"] for e in again["files_excluded"]] == [str(bad)]
    read = {a for c in env.fake.calls[-4:] for a in c.cmd}
    assert not any(str(bad) in a for a in read)
    assert good.exists() and digits.exists()


def test_persistent_db_failure_still_returns_an_audited_error(env: Env) -> None:
    """Every write fails once the summary is being written (a full disk): the call still
    returns an audited internal_error envelope instead of raising."""
    import sqlite3

    real_index, real_insert = tools._index_rows, env.db.insert_windows
    failing = {"on": False}

    def index_rows(name: str, path: str, rows: Any) -> Any:
        if name.startswith("netflow.analysis"):
            failing["on"] = True
        return real_index(name, path, rows)

    def insert(sid: int, windows: Any) -> None:
        if failing["on"]:
            raise sqlite3.OperationalError("database or disk is full")
        real_insert(sid, windows)

    env.monkeypatch.setattr(tools, "_index_rows", index_rows)
    env.monkeypatch.setattr(env.db, "insert_windows", insert)
    resp = _analysis(env, profile_hosts=1)
    assert resp["status"] == "error" and resp["error_type"] == "internal_error", resp
    assert "disk is full" in resp["error_message"]
    (entry,) = env.audit_entries()
    assert entry["tool_call_id"] == resp["tool_call_id"] and entry["params"]["sources"]


def test_footer_write_failure_after_success_keeps_one_audit_entry(env: Env) -> None:
    """The progress footer is bookkeeping: when its write fails after the summary was indexed
    and audited, the call still returns success with exactly one audit entry."""
    import sqlite3

    real_insert = env.db.insert_windows

    def insert(sid: int, windows: Any) -> None:
        if any(str(w.raw_text).startswith("- netflow footer") for w in windows):
            raise sqlite3.OperationalError("database is locked")
        real_insert(sid, windows)

    env.monkeypatch.setattr(env.db, "insert_windows", insert)
    resp = _analysis(env, profile_hosts=1)
    assert resp["status"] == "success", resp
    entries = env.audit_entries()
    assert len(entries) == 1 and entries[0]["params"]["source"] == resp["source_name"]
    assert len(_texts(env, _sources(env)[0])) == 1  # header only: no footer could be written
    # a persistent failure of the footer on the error path is logged, not raised, either
    _raise_on(env, "-I", OSError("no exec"))
    err = env.call("run_netflow_analysis", evidence_path=resp["evidence_path"], profile_hosts=1,
                   force=True)  # fmt: skip
    assert err["status"] == "error" and len(env.audit_entries()) == 2


def test_name_lookup_failure_is_an_audited_error(env: Env) -> None:
    """A database error before the first section (naming the summary) ends as an audited
    internal_error, never as an exception."""
    env.monkeypatch.setattr(tools, "_runs_of", lambda prep, base: 1 / 0)
    resp = _analysis(env, profile_hosts=0)
    assert resp["status"] == "error" and resp["error_type"] == "internal_error", resp
    assert "ZeroDivisionError" in resp["error_message"] and resp["sections"] == []
    (entry,) = env.audit_entries()
    assert entry["tool_call_id"] == resp["tool_call_id"]


def test_section_that_died_mid_write_is_rerun_on_resume(env: Env) -> None:
    """A section that raised after registering its source (rows missing) is re-run as -r<k>
    on the next call instead of being skipped as if complete."""
    real = tools._index_rows
    died = {"once": False}

    def index_rows(name: str, path: str, rows: Any) -> Any:
        if name.startswith("netflow.sweep.") and not died["once"]:
            died["once"] = True
            env.db.register_source(name, path, "blake2b:none", core.EXTRACTOR, len(rows))
            raise RuntimeError("write failed after register_source")
        return real(name, path, rows)

    env.monkeypatch.setattr(tools, "_index_rows", index_rows)
    resp = _analysis(env, profile_hosts=0)
    assert resp["status"] == "partial" and resp["sections"][1]["error_type"] == "internal_error"
    orphan = [n for n in _sources(env) if n.startswith("netflow.sweep.")]
    assert len(orphan) == 1 and not env.db.get_windows_by_source(orphan[0])
    again = _analysis(env, profile_hosts=0)
    assert again["status"] == "success", again
    sweep = again["sections"][1]
    assert sweep["status"] == "success" and sweep["source"] == orphan[0] + "-r1"
    assert any("died mid-write" in w for w in again["warnings"])
    assert len(env.db.get_windows_by_source(sweep["source"])) == sweep["row_count"] + 1


def test_batch_retry_under_low_load_resumes_a_partial_run(env: Env, store: JobStore) -> None:
    """The executor's path: a section times out in a batch that is NOT deferred (no other job,
    low load: the job is marked failed), the one retry goes through start_extraction_batch
    again and must not be skipped by the partial summary."""
    day_dir = str(env.tree(days=range(50, 52), strays=False))
    task = [
        {"tool": "run_netflow_analysis", "args": {"evidence_path": day_dir, "profile_hosts": 1}}
    ]
    _raise_on(env, _SWEEP_ARGV, subprocess.TimeoutExpired(cmd="nfdump", timeout=5), times=1)
    env.monkeypatch.setattr("mulder.server.jobs.should_defer", lambda other_running: False)
    first = env.call("start_extraction_batch", tasks=task)
    assert first.get("tasks_skipped", []) == [], first
    (batch_id,) = store.batch_ids()
    assert store.wait_for_batch(batch_id, timeout=120)
    status = store.get_batch_status(batch_id)
    assert status is not None and status["failed"] == 1 and status["completed"] == 0, status
    assert [n for n in _sources(env) if n.startswith(_PARTIAL)]
    retry = env.call("start_extraction_batch", tasks=task)
    assert retry.get("tasks_skipped", []) == [] and retry["status"] != "all_skipped", retry
    batch_id2 = [b for b in store.batch_ids() if b != batch_id][0]
    assert store.wait_for_batch(batch_id2, timeout=120)
    (result,) = env.call("get_completed_results", batch_id=batch_id2)["results"]
    assert result["result_status"] == "success"
    assert result["source_name"].startswith("netflow.analysis.")
    assert len(env.fake.calls) == 4 + 1 + 3 + 2 + 1  # the retry ran only the sweep
    # now the completed run hides a third task
    third = env.call("start_extraction_batch", tasks=task)
    assert third["status"] == "all_skipped"


def test_progress_record_of_a_retry_is_registered_as_rk(env: Env) -> None:
    _raise_on(env, "-I", OSError("no exec"), times=1)  # the inventory stops at the first failure
    day_dir = str(env.tree(days=range(50, 52), strays=False))
    err = env.call("run_netflow_analysis", evidence_path=day_dir, profile_hosts=0)
    assert err["status"] == "error"
    ok = env.call("run_netflow_analysis", evidence_path=day_dir, profile_hosts=0)
    assert ok["status"] == "success"
    progress = [n for n in _sources(env) if n.startswith("netflow.progress.")]
    assert len(progress) == 2 and progress[1] == progress[0] + "-r1"
    assert _texts(env, progress[1])[1].startswith("- netflow footer status=success ")


# ---------------------------------------------------------------------------
# batch 5: manifest completeness, the 0-row summary, the file cap, worst-case envelope size
# ---------------------------------------------------------------------------


def test_inventory_with_an_incomplete_manifest_is_rerun_not_resumed(env: Env) -> None:
    """The manifest is written after the main inventory source, in INSERT_BATCH chunks: a call
    that dies between chunks leaves a complete main source and a short manifest.  The next call
    must re-run the inventory instead of trusting the short manifest (which would drop the
    missing files as if -I had rejected them)."""
    import sqlite3

    env.monkeypatch.setattr(core, "INSERT_BATCH", 2)
    d = env.tree(days=range(50, 60), strays=False)  # 10 files -> 11 manifest rows, 6 chunks
    real_insert = env.db.insert_windows
    calls: dict[int, int] = {}
    failing = {"armed": True}

    def insert(sid: int, windows: Any) -> None:
        names = {s.source_id: s.source_name for s in env.db.get_sources()}
        if failing["armed"] and names.get(sid, "").endswith(".manifest"):
            calls[sid] = calls.get(sid, 0) + 1
            if calls[sid] == 3:
                failing["armed"] = False
                raise sqlite3.OperationalError("disk I/O error")
        real_insert(sid, windows)

    env.monkeypatch.setattr(env.db, "insert_windows", insert)
    first = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0)
    assert first["status"] == "error" and first["error_type"] == "internal_error", first
    assert "retry run_netflow_analysis" in first["error_message"]
    manifests = [s for s in env.db.get_sources() if s.source_name.endswith(".manifest")]
    assert len(manifests) == 1 and len(env.db.get_windows_by_source(manifests[0].source_name)) < 11
    again = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0)
    assert again["status"] == "success" and again["files_scanned"] == 10, again
    inventory = again["sections"][0]
    assert inventory["status"] == "success" and inventory["source"].endswith("-r1")
    assert again["files_excluded"] == []
    assert any("died mid-write" in w for w in again["warnings"])
    assert len(_texts(env, inventory["manifest_source"])) == 11
    # a manifest that was never registered at all is treated the same way
    env.monkeypatch.setattr(core, "INSERT_BATCH", 5000)
    other = make_tree(env.evidence_root / "other", days=range(67, 70), strays=False)
    real_index = tools._index_rows

    def no_manifest(name: str, path: str, rows: Any) -> Any:
        if name.endswith(".manifest"):
            raise RuntimeError("register failed")
        return real_index(name, path, rows)

    env.monkeypatch.setattr(tools, "_index_rows", no_manifest)
    assert (
        env.call("run_netflow_analysis", evidence_path=str(other), profile_hosts=0)["status"]
        == "error"
    )
    env.monkeypatch.setattr(tools, "_index_rows", real_index)
    fixed = env.call("run_netflow_analysis", evidence_path=str(other), profile_hosts=0)
    assert fixed["status"] == "success" and fixed["sections"][0]["source"].endswith("-r1")
    assert fixed["files_scanned"] == 3 and fixed["files_excluded"] == []


def test_summary_registered_without_rows_is_recovered_by_a_batch_retry(
    env: Env, store: JobStore
) -> None:
    """The summary's rows fail to insert after register_source (a full disk): the rowless summary
    is NOT the batch-skip prefix (the completion marker is registered only after the rows), so
    the executor's batch retry reaches the tool and resumes; the 0-row summary covers nothing;
    the error message names the recovery, since a batch exposes only error_message."""
    day_dir = str(env.tree(days=range(50, 52), strays=False))
    task = [
        {"tool": "run_netflow_analysis", "args": {"evidence_path": day_dir, "profile_hosts": 0}}
    ]
    real = tools._index_rows

    def register_then_fail(name: str, path: str, rows: Any) -> Any:
        if name.startswith("netflow.analysis."):
            env.db.register_source(name, path, "blake2b:none", core.EXTRACTOR, len(rows))
            raise RuntimeError("database or disk is full")
        return real(name, path, rows)

    env.monkeypatch.setattr(tools, "_index_rows", register_then_fail)
    first = env.call("start_extraction_batch", tasks=task)
    assert first.get("tasks_skipped", []) == [], first
    (batch_id,) = store.batch_ids()
    assert store.wait_for_batch(batch_id, timeout=120)
    status = store.get_batch_status(batch_id)
    assert status is not None and status["failed"] == 1, status
    error = status["failed_jobs"][0]["error"]
    assert "disk is full" in error and "retry run_netflow_analysis" in error, error
    empty = [n for n in _sources(env) if n.startswith("netflow.analysis.")]
    assert len(empty) == 1 and env.db.get_windows_by_source(empty[0]) == []
    assert not any(n.startswith("netflow.complete.") for n in _sources(env))
    # coverage needs a stored status=success header, so the 0-row summary covers nothing
    cov = env.call("audit_tool_coverage")
    item = next(i for i in cov["coverage"] if i["path"] == day_dir)
    assert item["tools_run"] == [] and item["tools_not_run"] == ["run_netflow_analysis"]
    # the executor's retry, again through a batch, is not skipped: it resumes and completes
    env.monkeypatch.setattr(tools, "_index_rows", real)
    retry = env.call("start_extraction_batch", tasks=task)
    assert retry.get("tasks_skipped", []) == [] and retry["status"] != "all_skipped", retry
    batch_id2 = [b for b in store.batch_ids() if b != batch_id][0]
    assert store.wait_for_batch(batch_id2, timeout=120)
    (result,) = env.call("get_completed_results", batch_id=batch_id2)["results"]
    assert result["result_status"] == "success" and result["source_name"] == empty[0] + "-r1"
    item = next(i for i in env.call("audit_tool_coverage")["coverage"] if i["path"] == day_dir)
    assert item["tools_run"] == ["run_netflow_analysis"]
    assert env.call("start_extraction_batch", tasks=task)["status"] == "all_skipped"


def test_file_cap_counts_the_files_a_call_reads(env: Env) -> None:
    """A huge flat directory refuses the extractor and an unwindowed pivot with the ways out,
    while a windowed pivot that selects fewer files than the cap runs."""
    from datetime import date, timedelta

    env.monkeypatch.setattr(core, "MAX_FILES", 50)
    d = env.evidence_root / "flat" / "edge-router"
    for i in range(51):  # one file a day for 51 days, no subdirectories
        nfcapd(d, name=f"nfcapd.{date(2001, 2, 3) + timedelta(days=i):%Y%m%d}0000")
    refused = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0)
    assert refused["status"] == "error" and refused["error_type"] == "invalid_argument", refused
    assert (
        "51 nfcapd files under" in refused["error_message"]
        and "refused" in refused["error_message"]
    )
    assert (
        "subdirectory" in refused["suggestion"]
        and "no per-window fallback" in refused["suggestion"]
    )
    unwindowed = env.call("run_netflow_top", evidence_path=str(d), stat="srcip")
    assert unwindowed["status"] == "error" and "t_start/t_end" in unwindowed["suggestion"]
    assert env.fake.calls == []  # nothing ran
    windowed = env.call("run_netflow_top", evidence_path=str(d), stat="srcip",
                        t_start="2001-02-23T10:00:00", t_end="2001-02-23T11:00:00")  # fmt: skip
    assert windowed["status"] == "success", windowed
    assert windowed["files_scanned"] == 10  # the day, 1 before and 8 after
    wide = env.call("run_netflow_top", evidence_path=str(d), stat="srcip",
                    t_start="2001-02-03T00:00:00", t_end="2001-03-30T00:00:00")  # fmt: skip
    assert wide["status"] == "error" and "selected by the window" in wide["error_message"]
    assert "narrow t_start/t_end" in wide["suggestion"]


def _profile_tables_many(host: str, peers: list[str]) -> str:
    """Four STAT tables with ``peers`` in both peer tables (the worst case for the summary)."""
    peer_rows = "".join(
        f"{_T},any,{p},{6 + i},1.0,{60 + i},1.0,{6000 + i},1.0,0,1,100\n"
        for i, p in enumerate(peers)
    )
    return (
        _HDR
        + f"{_T},any,{host},50,100.0,500,100.0,50000,100.0,0,10,100\n"
        + _HDR
        + f"{_T},6    ,443,6,12.0,60,12.0,6000,12.0,0,1,100\n"
        + _HDR
        + peer_rows
        + _HDR
        + peer_rows
    )


def _worst_case_env(env: Env, hosts: list[str], peers: list[str], nets_text: str) -> None:
    many = _HDR + "".join(
        f"{_T},any,{h},{40 - i % 30},1.0,{400 - i},1.0,{99000 - 100 * i},1.0,0,1,100\n"
        for i, h in enumerate(hosts)
    )
    real = env.fake.responder

    def responder(cmd: list[str]) -> str | None:
        stats = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-s"]
        filt = cmd[-1]
        if stats and stats[0] == "ip/flows" and len(stats) == 4:
            return many + _SERVICES + many + _DST_BYTES
        if stats and stats[0] in ("srcip/flows", "dstip/flows") and len(stats) == 4:
            m = re.search(r"(?:src|dst) ip (\S+)", filt)
            return _profile_tables_many(m.group(1) if m else hosts[0], peers)
        return real(cmd) if real else None

    env.fake.responder = responder


def test_response_stays_bounded_at_the_maximum_profiles(env: Env) -> None:
    """Thirty internal hosts, profile_hosts=25, n=100 and twenty distinct external peers in every
    peer table: the envelope stays bounded because no section carries rows inline and the
    per-profile peer list stays in the indexed summary row."""
    hosts = [f"10.0.9.{i}" for i in range(1, 31)]
    peers = [f"203.0.113.{i}" for i in range(1, 21)]
    _worst_case_env(env, hosts, peers, "rfc1918")
    resp = _analysis(env, profile_hosts=25, n=100)
    assert resp["status"] == "success", resp
    profiles = [s for s in resp["sections"] if s["section"] == "profile"]
    assert len(profiles) == 25 and profiles[0]["host"] == "10.0.9.1"
    assert profiles[0]["summary"]["external_peers"] == 20
    assert "external_peer_ips" not in profiles[0]["summary"]  # in the indexed summary row only
    row = _texts(env, profiles[0]["source"])[1]
    assert " external_peers=20 " in row and "203.0.113.1," in row
    assert len(json.dumps(resp)) < 40_000, len(json.dumps(resp))


def test_response_stays_bounded_with_ipv6_hosts_and_peers(env: Env) -> None:
    """The same worst case with full-length IPv6 addresses (a ULA internal range and global
    external peers), which are four times as long as IPv4 ones."""
    hosts = [f"fd12:3456:789a:1::{i:x}" for i in range(1, 31)]
    peers = [f"2001:db8:abcd:ef01:2345:6789:abcd:{i:04x}" for i in range(1, 21)]
    _worst_case_env(env, hosts, peers, "ula")
    resp = _analysis(env, profile_hosts=25, n=100, internal_nets=["fd00::/8"])
    assert resp["status"] == "success", resp
    profiles = [s for s in resp["sections"] if s["section"] == "profile"]
    assert len(profiles) == 25 and profiles[0]["host"] == "fd12:3456:789a:1::1"
    assert profiles[0]["summary"]["external_peers"] == 20
    assert len(json.dumps(resp)) < 40_000, len(json.dumps(resp))


# ---------------------------------------------------------------------------
# batch 6: the progress footer names what was registered; manifest read-back paging; undated caps
# ---------------------------------------------------------------------------


def _footer(env: Env, resp: dict[str, Any]) -> str:
    progress = [n for n in _sources(env) if n.startswith("netflow.progress.")]
    rows = _texts(env, progress[-1])
    assert len(rows) == 2 and rows[1].startswith("- netflow footer "), rows
    return rows[1]


def test_error_footer_names_the_registered_summary_or_none(env: Env) -> None:
    """The footer names the summary THIS call registered (read back from the database), never the
    planned name: "none" after an inventory error or an exception before the summary, the
    -partial name when the exception came after a partial summary was registered."""
    # 1. an exception after the sections, before any summary
    real = tools._index_rows

    def summary_fails(name: str, path: str, rows: Any) -> Any:
        if name.startswith("netflow.analysis"):
            raise RuntimeError("no summary")
        return real(name, path, rows)

    env.monkeypatch.setattr(tools, "_index_rows", summary_fails)
    resp = _analysis(env, profile_hosts=0)
    assert resp["status"] == "error"
    assert " summary=none " in _footer(env, resp) + " "
    env.monkeypatch.setattr(tools, "_index_rows", real)
    # 2. an inventory error: no summary either
    _raise_on(env, "-I", OSError("no exec"), times=1)
    other = make_tree(env.evidence_root / "other", days=range(67, 69), strays=False)
    resp = env.call("run_netflow_analysis", evidence_path=str(other), profile_hosts=0)
    assert resp["status"] == "error" and resp["error_type"] != "internal_error"
    assert " summary=none " in _footer(env, resp) + " "
    env.fake.hook = None
    # 3. a partial summary was registered, then the call died: the footer names it
    third = make_tree(env.evidence_root / "third", days=range(71, 73), strays=False)
    _raise_on(env, _SWEEP_ARGV, OSError("exec failed on the sweep"))

    def partial_then_fail(name: str, path: str, rows: Any) -> Any:
        if name.startswith(_PARTIAL):
            env.db.register_source(name, path, "blake2b:none", core.EXTRACTOR, len(rows))
            raise RuntimeError("died after registering the partial summary")
        return real(name, path, rows)

    env.monkeypatch.setattr(tools, "_index_rows", partial_then_fail)
    resp = env.call("run_netflow_analysis", evidence_path=str(third), profile_hosts=0)
    assert resp["status"] == "error" and resp["error_type"] == "internal_error"
    partial = [n for n in _sources(env) if n.startswith(_PARTIAL)]
    assert len(partial) == 1
    assert f" summary={partial[0]} " in _footer(env, resp) + " "
    # ... and a normal partial run names its -partial summary in the footer as well
    env.monkeypatch.setattr(tools, "_index_rows", real)
    fourth = make_tree(env.evidence_root / "fourth", days=range(74, 76), strays=False)
    resp = env.call("run_netflow_analysis", evidence_path=str(fourth), profile_hosts=0)
    assert resp["status"] == "partial" and resp["source_name"].startswith(_PARTIAL)
    assert f" summary={resp['source_name']} " in _footer(env, resp) + " "


@pytest.mark.parametrize("page", [43, 50])
def test_manifest_read_back_pages_through_every_row(env: Env, page: int) -> None:
    """A skipped inventory reads its manifest back in pages of INSERT_BATCH rows: 301 rows at 43
    (seven full pages then an empty one) and at 50 (a short last page) both yield every file."""
    d = _rotation_tree(env, 300, sub=f"pager-{page}")
    first = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0)
    assert first["status"] == "success" and first["files_scanned"] == 300, first
    env.monkeypatch.setattr(core, "INSERT_BATCH", page)
    again = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0,
                     internal_nets=["10.0.0.0/8"])  # fmt: skip
    assert again["status"] == "success" and again["sections"][0]["status"] == "skipped", again
    assert again["files_scanned"] == 300 and again["files_excluded"] == []
    assert not any("manifest" in w for w in again["warnings"])


def test_undated_files_over_the_cap_are_refused_with_the_right_way_out(env: Env) -> None:
    """Renamed captures carry no rotation date, so every window keeps them: the refusal must not
    suggest narrowing the window."""
    env.monkeypatch.setattr(core, "MAX_FILES", 20)
    d = env.evidence_root / "undated" / "edge-router"
    for i in range(21):
        nfcapd(d, name=f"capture.{i:03d}")
    resp = env.call("run_netflow_top", evidence_path=str(d), stat="srcip",
                    t_start="2001-02-03T00:00:00", t_end="2001-02-03T01:00:00")  # fmt: skip
    assert resp["status"] == "error" and resp["error_type"] == "invalid_argument", resp
    assert "selected by the window under" in resp["error_message"]
    assert "carry no rotation date" in resp["suggestion"] and "subdirectory" in resp["suggestion"]
    assert "narrow" not in resp["suggestion"]


# ---------------------------------------------------------------------------
# batch 7: the footer and this call's hid; supersedes on every path; healed marker; undated caps
# ---------------------------------------------------------------------------


def test_error_footer_names_only_this_calls_summary(env: Env) -> None:
    """Two extractor calls on one directory with different parameters have different hids (and
    locks): a crashed call's footer must not name the other call's completed summary."""
    done = _analysis(env, profile_hosts=1)
    assert done["status"] == "success"
    real = tools._index_rows

    def summary_fails(name: str, path: str, rows: Any) -> Any:
        if name.startswith("netflow.analysis"):
            raise RuntimeError("no summary")
        return real(name, path, rows)

    env.monkeypatch.setattr(tools, "_index_rows", summary_fails)
    crashed = _analysis(env, profile_hosts=0)  # a different hid on the same path
    assert crashed["status"] == "error"
    progress = [n for n in _sources(env) if n.startswith("netflow.progress.")]
    assert len(progress) == 2
    header, footer = _texts(env, progress[-1])
    assert " summary_id=" in header and _hid(done["source_name"]) not in header
    assert " summary=none" in footer and done["source_name"] not in footer


def _hid(name: str) -> str:
    return name.split(".", 2)[2].split("-r", 1)[0]


def test_fresh_and_forced_runs_supersede_the_record_they_close(env: Env) -> None:
    """The summary header's supersedes= names the record a run closes on every path, not only
    on a resume: the errored progress record after an inventory error, the partial summary
    after a forced re-run."""
    # inventory error, then a fresh success
    _raise_on(env, "-I", OSError("no exec"), times=1)
    err = _analysis(env, profile_hosts=0)
    assert err["status"] == "error"
    env.fake.hook = None
    ok = _analysis(env, profile_hosts=0)
    assert ok["status"] == "success" and ok["source_name"].startswith("netflow.analysis.")
    progress = [n for n in _sources(env) if n.startswith("netflow.progress.")]
    assert _texts(env, ok["source_name"])[0].endswith(f" supersedes={progress[0]}")
    # a partial run, then a forced success
    other = make_tree(env.evidence_root / "other", days=range(67, 69), strays=False)
    _raise_on(env, _SWEEP_ARGV, OSError("exec failed on the sweep"))
    partial = env.call("run_netflow_analysis", evidence_path=str(other), profile_hosts=0)
    assert partial["status"] == "partial" and partial["source_name"].startswith(_PARTIAL)
    env.fake.hook = None
    forced = env.call(
        "run_netflow_analysis", evidence_path=str(other), profile_hosts=0, force=True
    )
    assert forced["status"] == "success" and forced["source_name"].startswith("netflow.analysis.")
    assert _texts(env, forced["source_name"])[0].endswith(f" supersedes={partial['source_name']}")


def test_missing_completion_marker_is_registered_on_the_skip_path(
    env: Env, store: JobStore
) -> None:
    """A run that completed but could not register its marker is re-submitted by every batch;
    the skip path registers the missing marker, so the next batch skips the task."""
    real = tools._index_rows

    def marker_fails(name: str, path: str, rows: Any) -> Any:
        if name.startswith("netflow.complete."):
            raise RuntimeError("marker write failed")
        return real(name, path, rows)

    env.monkeypatch.setattr(tools, "_index_rows", marker_fails)
    done = _analysis(env, profile_hosts=0)
    assert done["status"] == "success"
    assert not any(n.startswith("netflow.complete.") for n in _sources(env))
    env.monkeypatch.setattr(tools, "_index_rows", real)
    day_dir = done["evidence_path"]
    task = [
        {"tool": "run_netflow_analysis", "args": {"evidence_path": day_dir, "profile_hosts": 0}}
    ]
    first = env.call("start_extraction_batch", tasks=task)
    assert first.get("tasks_skipped", []) == [], first  # no marker: the tool runs ...
    (batch_id,) = store.batch_ids()
    assert store.wait_for_batch(batch_id, timeout=120)
    (result,) = env.call("get_completed_results", batch_id=batch_id)["results"]
    assert result["result_status"] == "skipped"  # ... and skips itself on the completed summary
    marker = "netflow.complete." + done["source_name"].split(".", 2)[2]
    assert marker in _sources(env)  # healed on that skip path
    assert env.call("start_extraction_batch", tasks=task)["status"] == "all_skipped"
    skipped = _analysis(env, profile_hosts=0)
    assert skipped["status"] == "skipped" and not any(
        "registered now" in w for w in skipped.get("warnings", [])
    )


def test_undated_files_decide_the_cap_way_out(env: Env) -> None:
    """With more undated files than the cap, no window can help: every call is told to use a
    subdirectory; with few undated files, a windowed pivot is told to narrow the window."""
    env.monkeypatch.setattr(core, "MAX_FILES", 20)
    d = env.evidence_root / "mixed" / "edge-router"
    for i in range(21):
        nfcapd(d, name=f"capture.{i:03d}")
    nfcapd(d, name="nfcapd.200102030000")
    window = {"t_start": "2001-02-03T00:00:00", "t_end": "2001-02-03T01:00:00"}
    windowed = env.call("run_netflow_top", evidence_path=str(d), stat="srcip", **window)
    unwindowed = env.call("run_netflow_top", evidence_path=str(d), stat="srcip")
    extractor = env.call("run_netflow_analysis", evidence_path=str(d), profile_hosts=0)
    for resp in (windowed, unwindowed, extractor):
        assert resp["status"] == "error" and resp["error_type"] == "invalid_argument", resp
        assert (
            "subdirectory" in resp["suggestion"]
            and "21 of the files carry no rotation date" in resp["suggestion"]
        )
        assert "narrow" not in resp["suggestion"] and "t_start/t_end" not in resp["suggestion"]
    assert "selected by the window under" in windowed["error_message"]
    assert env.fake.calls == []
    # few undated files: a window brings the selection down to them, so narrowing is the way out
    few = env.evidence_root / "few" / "edge-router"
    for i in range(3):
        nfcapd(few, name=f"capture.{i:03d}")
    for i in range(30):
        nfcapd(few, name=f"nfcapd.200102{(i // 24) + 3:02d}{i % 24:02d}00")
    resp = env.call("run_netflow_top", evidence_path=str(few), stat="srcip",
                    t_start="2001-02-03T00:00:00", t_end="2001-02-05T00:00:00")  # fmt: skip
    assert resp["status"] == "error" and resp["suggestion"].startswith("narrow t_start/t_end")
