"""start_extraction_batch may only queue tools the calling session could call itself."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server import app
from mulder.server.jobs import JobStore
from mulder.server.tool_access import ALLOWED_TOOLS_ENV, Role, get_tools_for_role

_calls: list[str] = []


def _extract_tool() -> dict[str, str]:
    _calls.append("extract_tool")
    return {"status": "ok"}


def _other_tool() -> dict[str, str]:
    _calls.append("other_tool")
    return {"status": "ok"}


def _submit(
    tasks: list[dict[str, Any]], extra: dict[str, Callable[..., Any]] | None = None
) -> Any:
    _calls.clear()
    dispatch: dict[str, Callable[..., Any]] = {
        "extract_tool": _extract_tool,
        "other_tool": _other_tool,
        **(extra or {}),
    }
    store = JobStore(max_workers=1, tool_dispatch=dispatch)
    start_extraction_batch = app._tool_dispatch_sync["start_extraction_batch"]
    with (
        patch("mulder.server.app._tool_dispatch_sync", dispatch),
        patch("mulder.server.app.get_job_store", return_value=store),
        patch("mulder.server.tools.jobs.tool_already_indexed", return_value=None),
        # Permission tests must not wait on the host's CPU/memory pressure.
        patch("mulder.server.app.wait_for_resources", return_value=None),
    ):
        try:
            result = start_extraction_batch(tasks)
            if result["status"] == "submitted":
                assert store.wait_for_batch(result["batch_id"], timeout=5.0)
        finally:
            store.shutdown(wait=True)
    return result


@pytest.fixture(autouse=True)
def _session_allows_only_extract_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ALLOWED_TOOLS_ENV, "mcp__mulder__extract_tool")


def test_task_outside_the_sessions_tools_is_refused_and_the_rest_still_run() -> None:
    result = _submit([{"tool": "other_tool"}, {"tool": "extract_tool"}])

    assert result["status"] == "submitted"
    assert [t["tool"] for t in result["tasks_submitted"]] == ["extract_tool"]
    [refused] = result["tasks_not_available"]
    assert refused["tool"] == "other_tool"
    assert "not available through start_extraction_batch" in refused["error"]
    assert "tasks_rejected" not in result
    assert "Do not resubmit" in result["hint"]
    assert _calls == ["extract_tool"]


def test_a_tool_with_no_registry_entry_is_refused_by_a_restricted_session() -> None:
    """A dispatch entry nobody registered for any role must not slip through."""
    assert "other_tool" not in app._tool_dispatch_sync
    result = _submit([{"tool": "other_tool"}])

    assert result["status"] == "error"
    assert result["tasks_not_available"][0]["tool"] == "other_tool"
    assert _calls == []


def test_a_fully_refused_batch_says_not_to_resubmit() -> None:
    result = _submit([{"tool": "other_tool"}])

    assert result["status"] == "error"
    assert "Resubmitting will not help" in result["error_message"]
    assert "Fix the arguments" not in result["error_message"]


def test_argument_errors_stay_resubmittable_and_apart_from_refusals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def typed_tool(path: str) -> dict[str, str]:
        return {"status": "ok"}

    monkeypatch.setenv(ALLOWED_TOOLS_ENV, "mcp__mulder__typed_tool")
    result = _submit(
        [{"tool": "typed_tool", "args": {"bad": 1}}, {"tool": "other_tool"}],
        {"typed_tool": typed_tool},
    )

    assert result["status"] == "error"
    assert [t["tool"] for t in result["tasks_rejected"]] == ["typed_tool"]
    assert [t["tool"] for t in result["tasks_not_available"]] == ["other_tool"]
    assert "Fix the arguments" in result["error_message"]
    assert "Resubmitting will not help" in result["error_message"]


@pytest.mark.parametrize("tool", ["update_finding", "delete_finding", "submit_narrative"])
def test_real_findings_tools_are_refused_for_an_extraction_executor(
    monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    monkeypatch.setenv(ALLOWED_TOOLS_ENV, ",".join(get_tools_for_role(Role.EXTRACT_EXECUTOR)))
    result = _submit([{"tool": tool, "args": {}}], {tool: app._tool_dispatch_sync[tool]})

    assert result["status"] == "error"
    assert result["tasks_not_available"][0]["tool"] == tool


def test_unset_env_restricts_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ALLOWED_TOOLS_ENV)
    result = _submit([{"tool": "other_tool"}])

    assert result["status"] == "submitted"
    assert _calls == ["other_tool"]
