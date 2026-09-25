"""JobStore / start_extraction_batch integration: NetFlow results carry the batch-visible keys.

What: a ``run_netflow_sweep`` submitted through ``JobStore.submit_batch`` completes and
``get_completed_results`` (the MCP tool the executor calls) shows ``source_name``, ``line_count``,
``windows_indexed`` and ``result_status == "success"``; the audit entry carries the batch id and
``params["source"]``; a finding whose ``evidence_refs`` is the sweep's ``tool_call_id`` resolves to
the ``netflow.sweep.<id>`` source through ``get_provenance_chain``; a timeout result is deferred or
failed but never ``completed``; ``start_extraction_batch`` skips a repeated inventory through
``TOOL_SOURCE_PREFIXES`` and never batch-skips the per-invocation tools.
When: hermetic (fake subprocess, real CaseDB); ``wait_for_resources`` is stubbed.
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Iterator

import pytest

import mulder.server.app as app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.jobs import JobStore
from tests.netflow_harness import Env

_SWEEP_NAME = re.compile(r"^netflow\.sweep\.[0-9a-f]{16}$")


@pytest.fixture()
def store(nf_env: Env) -> Iterator[JobStore]:
    nf_env.monkeypatch.setattr(app, "wait_for_resources", lambda *a, **k: None)
    js = JobStore(max_workers=2, tool_dispatch=_tool_dispatch_sync)
    nf_env.monkeypatch.setattr(app, "_job_store", js)
    try:
        yield js
    finally:
        js.shutdown(wait=True)


def test_batch_result_carries_source_name_and_counts(nf_env: Env, store: JobStore) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    batch = store.submit_batch(
        [
            {
                "tool": "run_netflow_sweep",
                "args": {"evidence_path": str(day_dir), "ports": [445, 3389]},
            }
        ]
    )
    assert batch.done_event.wait(timeout=60)
    status = store.get_batch_status(batch.batch_id)
    assert status is not None and status["completed"] == 1 and status["all_done"]

    summary = nf_env.call("get_completed_results", batch_id=batch.batch_id)
    assert summary["status"] == "success" and summary["results_returned"] == 1
    (r,) = summary["results"]
    assert r["tool"] == "run_netflow_sweep"
    assert _SWEEP_NAME.match(r["source_name"])
    assert r["line_count"] == 3 and r["windows_indexed"] == 3
    assert r["result_status"] == "success"
    assert r["tool_call_id"].startswith("tc_")

    entry = nf_env.audit_entry(r["tool_call_id"])
    assert entry["batch_id"] == batch.batch_id
    assert entry["params"]["source"] == r["source_name"]
    assert entry["params"]["ports"] == [445, 3389]

    nf_env.audit.log_finding_submission("f-nf-1", [r["tool_call_id"]])
    chain = nf_env.audit.get_provenance_chain("f-nf-1", nf_env.db)
    assert [t.tool_name for t in chain.tool_calls] == ["run_netflow_sweep"]
    assert chain.tool_calls[0].batch_id == batch.batch_id
    assert [s.source_name for s in chain.sources] == [r["source_name"]]
    assert chain.sources[0].source_path == str(day_dir)
    assert chain.sources[0].extractor == "nfdump"


def test_identical_tasks_in_one_batch_register_one_source(nf_env: Env, store: JobStore) -> None:
    """Two identical tasks in one start_extraction_batch both pass the submit-time dedupe (it
    only sees sources already in the DB) and run on two workers at once; the per-name lock makes
    the second wait, re-check and answer ``skipped`` instead of registering the same
    ``netflow.sweep.<hid>`` twice."""
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    nf_env.fake.hook = lambda _argv: time.sleep(0.5)
    task = {
        "tool": "run_netflow_sweep",
        "args": {"evidence_path": str(day_dir), "ports": [22, 3389]},
    }
    first = nf_env.call("start_extraction_batch", tasks=[task, dict(task)])
    assert first["status"] != "error", first
    assert first.get("tasks_skipped", []) == [], first  # the submit-time check cannot see it
    (batch_id,) = store.batch_ids()
    assert store.wait_for_batch(batch_id, timeout=120)
    summary = nf_env.call("get_completed_results", batch_id=batch_id)
    results = summary["results"]
    statuses = sorted(str(r.get("result_status")) for r in results)
    assert statuses == ["skipped", "success"], results
    names = {r["source_name"] for r in results}
    assert len(names) == 1 and _SWEEP_NAME.match(names.pop())
    assert (
        len([s for s in nf_env.db.get_sources() if s.source_name.startswith("netflow.sweep.")])
        == 1
    )
    assert len(nf_env.fake.calls) == 1


def test_timeout_result_is_never_completed(nf_env: Env, store: JobStore) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    nf_env.fake.raise_exc = subprocess.TimeoutExpired(cmd="nfdump", timeout=150)
    batch = store.submit_batch(
        [{"tool": "run_netflow_sweep", "args": {"evidence_path": str(day_dir)}}]
    )
    assert batch.done_event.wait(timeout=120)
    status = store.get_batch_status(batch.batch_id)
    assert status is not None and status["completed"] == 0
    assert status["failed"] == 1 and status["all_done"]
    assert "timed out" in status["failed_jobs"][0]["error"]
    assert store.get_completed_results(batch.batch_id) == []
    assert nf_env.db.get_sources() == []


def test_error_result_is_failed_with_message(nf_env: Env, store: JobStore) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    batch = store.submit_batch(
        [
            {
                "tool": "run_netflow_query",
                "args": {"evidence_path": str(day_dir), "filter": "src ipp 1"},
            }
        ]
    )
    assert batch.done_event.wait(timeout=60)
    status = store.get_batch_status(batch.batch_id)
    assert status is not None and status["failed"] == 1
    assert "'ipp'" in status["failed_jobs"][0]["error"]


def test_start_extraction_batch_skips_only_inventory_by_prefix(
    nf_env: Env, store: JobStore
) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    tasks = [
        {"tool": "run_netflow_inventory", "args": {"evidence_path": str(day_dir)}},
        {"tool": "run_netflow_sweep", "args": {"evidence_path": str(day_dir)}},
        {"tool": "run_netflow_top", "args": {"evidence_path": str(day_dir), "stat": "srcip"}},
    ]
    first = nf_env.call("start_extraction_batch", tasks=tasks)
    assert first["status"] != "error", first
    assert first.get("tasks_skipped", []) == [] and first.get("tasks_rejected", []) == []
    (batch_id,) = store.batch_ids()
    assert store.wait_for_batch(batch_id, timeout=120)
    results = nf_env.call("get_completed_results", batch_id=batch_id)["results"]
    assert {r["tool"]: r["result_status"] for r in results} == {
        "run_netflow_inventory": "success", "run_netflow_sweep": "success",
        "run_netflow_top": "success",
    }  # fmt: skip
    names = {r["tool"]: r["source_name"] for r in results}
    assert names["run_netflow_inventory"].startswith("netflow.inventory.")

    second = nf_env.call("start_extraction_batch", tasks=tasks)
    skipped = {t["tool"]: t for t in second.get("tasks_skipped", [])}
    assert set(skipped) == {"run_netflow_inventory"}
    assert skipped["run_netflow_inventory"]["existing_sources"] == [
        names["run_netflow_inventory"], names["run_netflow_inventory"] + ".manifest",
    ]  # fmt: skip
    assert second["status"] != "error"
    batch_id2 = [b for b in store.batch_ids() if b != batch_id][0]
    assert store.wait_for_batch(batch_id2, timeout=120)
    results2 = nf_env.call("get_completed_results", batch_id=batch_id2)["results"]
    # the per-invocation tools ran again and skipped themselves through their exact source name
    assert {r["tool"]: r["result_status"] for r in results2} == {
        "run_netflow_sweep": "skipped", "run_netflow_top": "skipped",
    }  # fmt: skip
    assert {r["source_name"] for r in results2} == {names["run_netflow_sweep"],
                                                    names["run_netflow_top"]}  # fmt: skip
    assert all(r["line_count"] > 0 for r in results2)

    only_inventory = nf_env.call("start_extraction_batch", tasks=tasks[:1])
    assert only_inventory["status"] == "all_skipped"


def test_start_extraction_batch_rejects_wrong_argument_names(nf_env: Env, store: JobStore) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call(
        "start_extraction_batch",
        tasks=[
            {"tool": "run_netflow_query", "args": {"evidence_path": str(day_dir), "filtre": "any"}}
        ],
    )
    assert resp["status"] == "error"
    (rejected,) = resp["tasks_rejected"]
    assert "'filtre'" in rejected["error"] and "filter" in rejected["error"]
    assert store.batch_ids() == []
