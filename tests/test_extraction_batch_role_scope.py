"""start_extraction_batch may only queue tools its own callers could call directly."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server import app, tool_access
from mulder.server.jobs import JobStore
from mulder.server.tool_access import ANALYSTS, Role
from mulder.server.tools import jobs as job_tools

_calls: list[str] = []


def _extract_tool() -> dict[str, str]:
    _calls.append("extract_tool")
    return {"status": "ok"}


def _analyst_tool() -> dict[str, str]:
    _calls.append("analyst_tool")
    return {"status": "ok"}


def _submit(
    tasks: list[dict[str, Any]], extra: dict[str, Callable[..., Any]] | None = None
) -> Any:
    _calls.clear()
    dispatch: dict[str, Callable[..., Any]] = {
        "extract_tool": _extract_tool,
        "analyst_tool": _analyst_tool,
        **(extra or {}),
    }
    roles = {"extract_tool": Role.EXTRACT_EXECUTOR, "analyst_tool": ANALYSTS}
    store = JobStore(max_workers=1, tool_dispatch=dispatch)
    start_extraction_batch = app._tool_dispatch_sync[job_tools.start_extraction_batch.__name__]
    with (
        patch("mulder.server.app._tool_dispatch_sync", dispatch),
        patch.dict(tool_access._registry, roles),
        patch("mulder.server.app.get_job_store", return_value=store),
        patch("mulder.server.tools.jobs.tool_already_indexed", return_value=None),
    ):
        result = start_extraction_batch(tasks)
    if result["status"] == "submitted":
        assert store.wait_for_batch(result["batch_id"], timeout=5.0)
    store.shutdown(wait=True)
    return result


def test_off_role_task_is_rejected_and_the_rest_still_run() -> None:
    result = _submit([{"tool": "analyst_tool"}, {"tool": "extract_tool"}])

    assert result["status"] == "submitted"
    assert [t["tool"] for t in result["tasks_submitted"]] == ["extract_tool"]
    [rejected] = result["tasks_rejected"]
    assert rejected["tool"] == "analyst_tool"
    assert "not available through start_extraction_batch" in rejected["error"]
    assert _calls == ["extract_tool"]


@pytest.mark.parametrize(
    "tool", ["submit_finding", "delete_finding", "finalize_report", "submit_narrative"]
)
def test_findings_and_report_tools_are_rejected(tool: str) -> None:
    batch_roles = tool_access._registry["start_extraction_batch"]
    assert not tool_access._registry[tool] & batch_roles
    result = _submit([{"tool": tool, "args": {}}], {tool: app._tool_dispatch_sync[tool]})

    assert result["status"] == "error"
    assert "not available through start_extraction_batch" in result["tasks_rejected"][0]["error"]


@pytest.mark.parametrize("tool", ["run_parallel", "start_extraction_batch"])
def test_dispatchers_do_not_nest(tool: str) -> None:
    batch_roles = tool_access._registry["start_extraction_batch"]
    assert tool_access._registry[tool] & batch_roles != Role(0)
    nested = {"tasks": [{"tool": "analyst_tool"}]}
    result = _submit([{"tool": tool, "args": nested}], {tool: app._tool_dispatch_sync[tool]})

    assert result["status"] == "error"
    assert "not available through start_extraction_batch" in result["tasks_rejected"][0]["error"]
    assert _calls == []
