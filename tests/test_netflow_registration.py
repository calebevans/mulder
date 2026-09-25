"""Registration: roles, source prefixes, argument validation, dispatch tables, audit params.

What: importing ``mulder.server.app`` registers the six ``run_netflow_*`` tools with exactly the
documented role table (EXTRACT_EXECUTOR gets all six, CROSS_EXECUTOR five, nobody else any);
``validate_tool_args`` accepts ``{"evidence_path": "x"}`` for the four tools whose other parameters
are optional and names the missing ``host`` / ``src``,``dst`` for the other two; a typo is reported
with the accepted parameter names; ``TOOL_SOURCE_PREFIXES`` holds only the inventory entry; every
tool is in both dispatch tables; ``fill_case_id`` leaves the args alone; the registry totals 159;
every audit entry written by a tool carries ``params["source"]`` equal to the response ``source``.
When: hermetic.
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import inspect
import re

import mulder.server.app  # noqa: F401  (registers every tool)
from mulder.server.app import _tool_dispatch, _tool_dispatch_sync
from mulder.server.helpers import TOOL_SOURCE_PREFIXES
from mulder.server.jobs import fill_case_id, validate_tool_args
from mulder.server.tool_access import ALL_ROLES, Role, get_tools_for_role
from mulder.server.tools.netflow import tools
from tests.netflow_harness import NETFLOW_TOOLS, Env

_SIX = set(NETFLOW_TOOLS)


def _names(role: Role) -> set[str]:
    return {t.removeprefix("mcp__mulder__") for t in get_tools_for_role(role)}


def test_role_table_holds_exactly() -> None:
    assert _names(Role.EXTRACT_EXECUTOR) >= _SIX
    assert _names(Role.CROSS_EXECUTOR) & _SIX == _SIX - {"run_netflow_inventory"}
    for role in (
        Role.CATALOG, Role.EXTRACT_PLANNER, Role.EXTRACT_ANALYST, Role.CROSS_PLANNER,
        Role.CROSS_ANALYST, Role.NARRATIVE_PLANNER, Role.NARRATIVE_EXECUTOR,
        Role.NARRATIVE_ANALYST, Role.REPORT,
    ):  # fmt: skip
        assert not (_names(role) & _SIX), role


def test_total_registered_tools_is_159() -> None:
    assert len(get_tools_for_role(ALL_ROLES)) == 159
    assert _names(ALL_ROLES) >= _SIX


def test_dispatch_tables_and_wrappers() -> None:
    for name in NETFLOW_TOOLS:
        assert name in _tool_dispatch_sync and name in _tool_dispatch
        sync_fn = _tool_dispatch_sync[name]
        assert not inspect.iscoroutinefunction(sync_fn)
        assert inspect.iscoroutinefunction(_tool_dispatch[name])
        assert sync_fn.__name__ == name
        # the module attribute is the async wrapper installed by app._concurrent_tool
        assert inspect.iscoroutinefunction(getattr(tools, name))
        assert getattr(tools, name).__wrapped__ is sync_fn  # type: ignore[attr-defined]


def test_signature_conventions() -> None:
    for name in NETFLOW_TOOLS:
        params = inspect.signature(_tool_dispatch_sync[name]).parameters
        first = next(iter(params))
        assert (
            first == "evidence_path" and params["evidence_path"].default is inspect.Parameter.empty
        )
        assert params["force"].default is False
        assert params["max_inline_rows"].default == 20
        assert "case_id" not in params
        doc = inspect.getdoc(_tool_dispatch_sync[name]) or ""
        assert doc and doc.split("\n")[0].strip()
        assert re.search(r"calls on\s+one\s+directory\s+serialise", doc), name
    assert (
        inspect.signature(_tool_dispatch_sync["run_netflow_query"]).parameters["limit"].default
        == 100
    )
    assert inspect.signature(_tool_dispatch_sync["run_netflow_top"]).parameters["n"].default == 25
    assert (
        inspect.signature(_tool_dispatch_sync["run_netflow_sweep"]).parameters["ports"].default
        is None
    )


def test_validate_tool_args_minimal_and_required() -> None:
    for name in (
        "run_netflow_inventory",
        "run_netflow_top",
        "run_netflow_sweep",
        "run_netflow_query",
    ):
        assert validate_tool_args(_tool_dispatch_sync[name], {"evidence_path": "x"}) is None, name
    msg = validate_tool_args(
        _tool_dispatch_sync["run_netflow_host_profile"], {"evidence_path": "x"}
    )
    assert msg is not None and "missing required parameter(s) 'host'" in msg
    assert (
        validate_tool_args(
            _tool_dispatch_sync["run_netflow_host_profile"],
            {"evidence_path": "x", "host": "192.0.2.99"},
        )
        is None
    )
    msg = validate_tool_args(
        _tool_dispatch_sync["run_netflow_pair_timeline"], {"evidence_path": "x"}
    )
    assert msg is not None and "'src'" in msg and "'dst'" in msg
    assert (
        validate_tool_args(
            _tool_dispatch_sync["run_netflow_pair_timeline"],
            {"evidence_path": "x", "src": "192.0.2.99", "dst": "192.0.2.98"},
        )
        is None
    )


def test_validate_tool_args_names_accepted_parameters_on_typo() -> None:
    msg = validate_tool_args(
        _tool_dispatch_sync["run_netflow_query"],
        {"evidence_path": "x", "filtre": "any", "limt": 5},
    )
    assert msg is not None
    assert "unexpected parameter(s) 'filtre', 'limt'" in msg
    for accepted in (
        "filter",
        "limit",
        "max_inline_rows",
        "aggregate",
        "order",
        "t_start",
        "t_end",
        "direction",
        "internal_nets",
        "force",
    ):
        assert accepted in msg.split("accepted:")[1]


def test_tool_source_prefixes_only_inventory() -> None:
    assert TOOL_SOURCE_PREFIXES["run_netflow_inventory"] == ["netflow.inventory."]
    assert [k for k in TOOL_SOURCE_PREFIXES if k.startswith("run_netflow_")] == [
        "run_netflow_inventory"
    ]


def test_fill_case_id_leaves_args_untouched() -> None:
    for name in NETFLOW_TOOLS:
        args = {"evidence_path": "/x"}
        assert fill_case_id(_tool_dispatch_sync[name], args, "nf-test") == {"evidence_path": "/x"}


def test_audit_params_carry_source_for_every_status(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    success = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    skipped = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    empty = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), filter="src ip 192.0.2.99"
    )
    assert (success["status"], skipped["status"], empty["status"]) == (
        "success",
        "skipped",
        "indexed_empty",
    )
    for resp in (success, skipped, empty):
        entry = nf_env.audit_entry(resp["tool_call_id"])
        assert entry["tool_name"] == resp["tool"]
        assert entry["params"]["source"] == resp["source"] == resp["source_name"]
        assert entry["params"]["evidence_path"] == str(day_dir)
        assert entry.get("batch_id") is None
        assert entry["output_hash"].startswith("blake2b:")
        assert entry["duration_ms"] >= 0
    error = nf_env.call("run_netflow_query", evidence_path=str(day_dir), filter="src ipp 1")
    entry = nf_env.audit_entry(error["tool_call_id"])
    assert "source" not in entry["params"] and entry["params"]["filter"] == "src ipp 1"
    assert len(nf_env.audit_entries()) == 4
    assert nf_env.audit.has_tool_call(success["tool_call_id"])


def test_error_envelopes_name_the_tool(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir), stat="nope")
    assert resp["status"] == "error" and resp["tool"] == "run_netflow_top"
    assert set(resp) >= {"tool_call_id", "status", "error_type", "error_message"}
    assert "'nope'" in resp["error_message"]
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir), filter="src ipp 1")
    assert resp["tool"] == "run_netflow_top" and "examples" in resp["suggestion"]


def test_cross_planner_netflow_sentence_points_at_data_the_planner_can_read() -> None:
    """The cross planner can call neither ``search`` nor ``get_raw_output`` and header rows have
    no event_time for ``get_timeline``: the NetFlow sentence must send it to ``list_sources``'
    ``source_path`` and name only tools it or its executor can run."""
    from mulder.orchestrator.phases import CROSS_SYSTEM

    prompt = CROSS_SYSTEM.planner_system_prompt
    start = prompt.index("For NetFlow evidence")
    para = prompt[start : prompt.index("OUTPUT (MANDATORY)", start)]
    assert "list_sources" in para and "source_path" in para, para
    assert "header row" not in para, para
    named = set(re.findall(r"\b[a-z][a-z0-9_]*\b", para)) & _names(ALL_ROLES)
    reachable = _names(Role.CROSS_PLANNER) | _names(Role.CROSS_EXECUTOR)
    assert {"run_netflow_query", "run_netflow_host_profile", "run_netflow_pair_timeline"} <= named
    assert named <= reachable, named - reachable
    assert not ({"search", "get_raw_output"} & _names(Role.CROSS_PLANNER))


def test_analyst_prompt_states_per_kind_event_time() -> None:
    """The analyst prompt states the event_time of each row kind."""
    from pathlib import Path

    import mulder

    prompts = Path(mulder.__file__).parent / "orchestrator" / "prompts"
    analyst = (prompts / "extract_analyst.md").read_text()
    assert "sweep rows use\nburst_start" in analyst or "sweep rows use burst_start" in analyst
