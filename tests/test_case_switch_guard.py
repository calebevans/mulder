"""A case switch must not move a running tool call's results to the new case.

Tools read the open case with ``get_ctx()`` only when they index their output
and log the call, so a call started in case A and finished after a switch to
case B used to write its source and audit entry into case B. ``load_case`` and
``_close_current_ctx`` already refused to switch while a job-store batch ran;
they now also refuse while a tool call is still running on the open case.
"""

from __future__ import annotations

import threading
from collections.abc import Awaitable, Callable, Coroutine, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import anyio
import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server import app
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import make_tool_call_id, tool_response
from mulder.server.tools import case  # noqa: F401  (registers open_case)

_SOURCE = "switch.strings"
_ARGS = {"target_path": "/evidence/a.bin"}


async def _no_resource_wait(tool_name: str = "") -> None:
    return None


@pytest.fixture
def two_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Cases ``case-a`` and ``case-b`` in *tmp_path*, with ``case-a`` open."""
    for case_id in ("case-a", "case-b"):
        evidence = tmp_path / case_id
        evidence.mkdir()
        CaseDB.create(case_id=case_id, evidence_root=str(evidence), db_dir=tmp_path).close()
    cfg = SimpleNamespace(db_dir=tmp_path)
    monkeypatch.delenv("MULDER_CASE_ID", raising=False)
    with (
        patch("mulder.server.app.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.app._ctx", None),
        patch("mulder.server.app._job_store", None),
        patch("mulder.server.app._tool_limiter", anyio.CapacityLimiter(4)),
        patch("mulder.server.app.async_wait_for_resources", _no_resource_wait),
    ):
        app.load_case("case-a")
        try:
            yield tmp_path
        finally:
            app._close_current_ctx()


def _source_names(db_dir: Path, case_id: str) -> list[str]:
    db = CaseDB.open(case_id, db_dir)
    try:
        return [source.source_name for source in db.get_sources()]
    finally:
        db.close()


def _logged_tools(db_dir: Path, case_id: str) -> list[str]:
    entries = AuditLog(db_dir / f"{case_id}.audit.jsonl").tool_call_entries()
    return [str(entry.get("tool_name")) for entry in entries]


def _evidence_names(db_dir: Path, case_id: str) -> list[str]:
    db = CaseDB.open(case_id, db_dir)
    try:
        return [Path(str(entry["file_path"])).name for entry in db.get_evidence_registry()]
    finally:
        db.close()


def _slow_tool(
    started: threading.Event, release: threading.Event
) -> Callable[..., Awaitable[dict[str, object]]]:
    """A sync tool, wrapped like a registered one, that indexes once *release* is set."""

    def slow_index(target_path: str) -> dict[str, object]:
        started.set()
        assert release.wait(timeout=10), "tool was not released"
        summary = extract_and_index("case switch marker line\n", _SOURCE, target_path, "strings")
        return tool_response(
            make_tool_call_id(), "slow_index", {"target_path": target_path}, summary, _SOURCE
        )

    return app._wrap_sync_tool(slow_index)


def _during_call(
    call: Callable[[Callable[..., Awaitable[Any]]], Coroutine[Any, Any, None]],
    during: Callable[[], Awaitable[Any]],
) -> Any:
    """Start *call* with a slow tool, run *during* while it blocks, then release it."""
    started, release = threading.Event(), threading.Event()
    result: dict[str, Any] = {}

    async def scenario() -> None:
        async with anyio.create_task_group() as tg:
            tg.start_soon(call, _slow_tool(started, release))
            try:
                await anyio.to_thread.run_sync(started.wait)
                result["during"] = await during()
            finally:
                release.set()

    anyio.run(scenario)
    return result["during"]


def test_open_case_is_refused_while_a_tool_call_runs(two_cases: Path) -> None:
    async def call(tool: Callable[..., Awaitable[Any]]) -> None:
        await tool(**_ARGS)

    async def switch() -> Any:
        return await app._tool_dispatch["open_case"]("case-b")

    refused = _during_call(call, switch)

    assert refused["status"] == "error"
    assert "Cannot switch cases" in str(refused["error_message"])
    assert _SOURCE in _source_names(two_cases, "case-a")
    assert _SOURCE not in _source_names(two_cases, "case-b")
    assert "slow_index" in _logged_tools(two_cases, "case-a")

    app.load_case("case-b")
    assert app.get_ctx().case_id == "case-b"


def test_switch_is_refused_while_a_job_store_batch_runs(two_cases: Path) -> None:
    store = MagicMock()
    store.batch_ids.return_value = ["batch-1"]
    store.get_batch_status.return_value = {"all_done": False}
    with (
        patch("mulder.server.app._job_store", store),
        pytest.raises(RuntimeError, match="Cannot switch cases"),
    ):
        app.load_case("case-b")


def test_tool_call_waits_for_a_switch_in_progress(two_cases: Path) -> None:
    switching, release_switch = threading.Event(), threading.Event()
    started, release = threading.Event(), threading.Event()
    release.set()
    original_open = CaseDB.open
    tool = _slow_tool(started, release)

    async def run_tool() -> None:
        await tool(**_ARGS)

    def slow_open(case_id: str, db_dir: Path) -> CaseDB:
        if case_id == "case-b":
            switching.set()
            assert release_switch.wait(timeout=10), "switch was not released"
        return original_open(case_id, db_dir)

    async def scenario() -> None:
        async with anyio.create_task_group() as tg:
            tg.start_soon(anyio.to_thread.run_sync, app.load_case, "case-b")
            try:
                assert await anyio.to_thread.run_sync(switching.wait, 5)
                tg.start_soon(run_tool)
                await anyio.sleep(0.05)
                assert not started.is_set(), "tool call started during the switch"
                with pytest.raises(RuntimeError, match="another case switch"):
                    app.load_case("case-a")
            finally:
                release_switch.set()

    with patch.object(CaseDB, "open", side_effect=slow_open):
        anyio.run(scenario)

    assert app.get_ctx().case_id == "case-b"
    assert _SOURCE in _source_names(two_cases, "case-b")
    assert _SOURCE not in _source_names(two_cases, "case-a")


def test_failed_switch_releases_the_guard(two_cases: Path) -> None:
    with (
        patch.object(CaseDB, "open", side_effect=OSError("cannot open database")),
        pytest.raises(OSError, match="cannot open"),
    ):
        app.load_case("case-b")
    app.load_case("case-b")
    assert app.get_ctx().case_id == "case-b"


def test_scan_evidence_keeps_its_new_case_until_it_returns(two_cases: Path) -> None:
    """Evidence hashes and the audit entry stay with the case scan_evidence created."""
    evidence = two_cases / "case-c"
    evidence.mkdir()
    (evidence / "note.txt").write_text("evidence of case c\n")
    paused, release, done = threading.Event(), threading.Event(), threading.Event()
    result: dict[str, Any] = {}

    def pause(original: Callable[..., Any]) -> Callable[..., Any]:
        def paused_call(*args: Any, **kwargs: Any) -> Any:
            paused.set()
            assert release.wait(timeout=10), "scan_evidence was not released"
            return original(*args, **kwargs)

        return paused_call

    hook = patch.object(
        case, "_hash_and_register_evidence", pause(case._hash_and_register_evidence)
    )

    def scan() -> None:
        try:
            scan_evidence = app._tool_dispatch["scan_evidence"]
            result.update(anyio.run(lambda: scan_evidence(str(evidence), "case-c")))
        finally:
            done.set()

    with hook:
        threading.Thread(target=scan, daemon=True).start()
        try:
            assert paused.wait(timeout=10), "scan_evidence did not reach the pause"
            with pytest.raises(RuntimeError, match="Cannot switch cases"):
                app.load_case("case-b")
        finally:
            release.set()
        assert done.wait(timeout=10), "scan_evidence did not finish"

    assert result["status"] == "success"
    assert app.get_ctx().case_id == "case-c"
    assert _evidence_names(two_cases, "case-c") == ["note.txt"]
    assert _evidence_names(two_cases, "case-b") == []
    assert "scan_evidence" in _logged_tools(two_cases, "case-c")


@pytest.mark.parametrize("tool", ["open_case", "scan_evidence"])
def test_run_parallel_refuses_tools_that_switch_cases(two_cases: Path, tool: str) -> None:
    args: dict[str, Any] = {"case_id": "case-b"}
    if tool == "scan_evidence":
        args = {"evidence_path": str(two_cases / "case-b"), "case_id": "case-c"}

    out = anyio.run(app._tool_dispatch["run_parallel"], [{"tool": tool, "args": args}])

    assert "call it directly" in str(out["parallel_results"][0]["result"])
    assert app.get_ctx().case_id == "case-a"
