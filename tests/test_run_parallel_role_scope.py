"""run_parallel may only dispatch tools an executor could call directly."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import anyio
import pytest

from mulder.server import app, tool_access
from mulder.server.tool_access import ANALYSTS, EXECUTORS, Role

_calls: list[str] = []


async def _executor_tool() -> dict[str, str]:
    _calls.append("executor_tool")
    return {"status": "ok"}


async def _analyst_tool() -> dict[str, str]:
    _calls.append("analyst_tool")
    return {"status": "ok"}


def _run(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _calls.clear()
    stubs = {"executor_tool": _executor_tool, "analyst_tool": _analyst_tool}
    with (
        patch.dict(app._tool_dispatch, stubs),
        patch.dict(tool_access._registry, {"executor_tool": EXECUTORS, "analyst_tool": ANALYSTS}),
        patch("mulder.server.app.has_ctx", return_value=False),
    ):
        result = anyio.run(app.run_parallel, tasks)
    return [r["result"] for r in result["parallel_results"]]


def test_off_role_task_is_refused_and_the_rest_still_run() -> None:
    results = _run([{"tool": "analyst_tool"}, {"tool": "executor_tool"}])

    assert "not available through run_parallel" in results[0]["error"]
    assert results[1]["status"] == "ok"
    assert _calls == ["executor_tool"]


@pytest.mark.parametrize(
    "tool", ["submit_finding", "delete_finding", "finalize_report", "submit_narrative"]
)
def test_findings_and_report_tools_are_refused(tool: str) -> None:
    assert not tool_access._registry[tool] & EXECUTORS
    [result] = _run([{"tool": tool, "args": {}}])

    assert "not available through run_parallel" in result["error"]


@pytest.mark.parametrize("tool", ["run_parallel", "start_extraction_batch"])
def test_dispatchers_do_not_nest(tool: str) -> None:
    assert tool_access._registry[tool] & EXECUTORS != Role(0)
    [result] = _run([{"tool": tool, "args": {"tasks": [{"tool": "analyst_tool"}]}}])

    assert "not available through run_parallel" in result["error"]
    assert _calls == []
