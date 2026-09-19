"""Role tool lists are enforced, sessions verify their MCP tools, and an
executor that runs nothing fails its attempt (issue #164)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from claude_agent_sdk import ClaudeAgentOptions
from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport
from claude_agent_sdk.types import AssistantMessage, SystemMessage, TextBlock

from mulder.orchestrator.phases import CATALOG, CROSS_SYSTEM, EXTRACTION, REPORT
from mulder.orchestrator.roles import _EXECUTOR_CONTROL_TOOLS, RoleRunner
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.session import _MCP_CONNECT_ATTEMPTS, builtin_tools, off_role_tools
from mulder.orchestrator.types import AnalystResult, ExecutionResults, PhaseResult, Plan
from mulder.server.tool_access import ALL_ROLES, get_tools_for_role

ALL_TOOLS = frozenset(get_tools_for_role(ALL_ROLES))

#: ``@tool_access(Role.EXTRACT_EXECUTOR)`` only; the analyst called all six
#: in the benchmark run that exposed the bug.
EXECUTOR_ONLY = [
    f"mcp__mulder__{name}"
    for name in (
        "run_mmls",
        "run_fls",
        "run_fsstat",
        "run_bulk_extractor",
        "run_mft_parser",
        "run_mactime",
    )
]

ROLE_LISTS: dict[str, list[str]] = {
    "extract_planner": EXTRACTION.planner_allowed_tools,
    "extract_executor": EXTRACTION.executor_allowed_tools,
    "extract_analyst": EXTRACTION.analyst_allowed_tools,
    "catalog": CATALOG.single_allowed_tools,
    "report": REPORT.single_allowed_tools,
}


def _plan(*tools: str) -> Plan:
    return Plan(
        plan_id="plan-1",
        tasks=[{"tool": t, "args": {}, "purpose": "p"} for t in tools],
        investigation_questions=[],
        expected_sources=[],
        raw_text="plan",
        turns_used=1,
    )


def _init(status: str | None, tools: list[str]) -> SystemMessage:
    servers = [] if status is None else [{"name": "mulder", "status": status}]
    return SystemMessage(subtype="init", data={"mcp_servers": servers, "tools": tools})


def _cli_args(options: ClaudeAgentOptions) -> list[str]:
    transport = SubprocessCLITransport(prompt="x", options=options)
    transport._cli_path = "claude"
    cmd: list[str] = transport._build_command()
    return cmd


def _flag(cmd: list[str], flag: str) -> list[str]:
    return cmd[cmd.index(flag) + 1].split(",")


async def _capture_options(
    orch: Orchestrator, allowed: list[str], disallowed: list[str], utility: bool = False
) -> ClaudeAgentOptions:
    captured: dict[str, ClaudeAgentOptions] = {}

    async def fake_query(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[object]:
        captured["options"] = options
        return
        yield  # pragma: no cover

    with patch("mulder.orchestrator.session.query", fake_query):
        if utility:
            await orch._session.execute_utility("wait", allowed, "wait_all")
        else:
            await orch._session.execute("sys", "prompt", "test-model", allowed, disallowed, 5)
    return captured["options"]


# ---------------------------------------------------------------------------
# (c) the disallowed complement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", sorted(ROLE_LISTS))
def test_off_role_tools_is_exact_complement(role: str) -> None:
    allowed = ROLE_LISTS[role]
    off = off_role_tools(allowed)
    assert allowed, role
    assert set(off).isdisjoint(allowed)
    assert set(off) | set(allowed) == ALL_TOOLS
    assert len(off) == len(set(off))


def test_executor_only_tools_hidden_from_other_roles() -> None:
    for role in ("extract_planner", "extract_analyst", "catalog", "report"):
        assert set(EXECUTOR_ONLY) <= set(off_role_tools(ROLE_LISTS[role])), role
    assert set(EXECUTOR_ONLY).isdisjoint(off_role_tools(ROLE_LISTS["extract_executor"]))


def test_dynamic_executor_allowlist_keeps_control_tools() -> None:
    allowed = RoleRunner._build_dynamic_allowlist(
        _plan("run_mmls"), EXTRACTION.executor_allowed_tools
    )
    off = set(off_role_tools(allowed))
    assert "mcp__mulder__run_mmls" in allowed
    assert set(allowed) >= _EXECUTOR_CONTROL_TOOLS
    assert _EXECUTOR_CONTROL_TOOLS.isdisjoint(off)
    # Executor-role tools the plan did not ask for are hidden too.
    assert "mcp__mulder__run_bulk_extractor" in off


@pytest.mark.asyncio()
async def test_cli_command_disallows_off_role_tools(tmp_path: Path) -> None:
    orch = Orchestrator("/evidence", cwd=str(tmp_path))
    options = await _capture_options(
        orch, EXTRACTION.analyst_allowed_tools, EXTRACTION.disallowed_tools
    )
    cmd = _cli_args(options)

    allowed = _flag(cmd, "--allowedTools")
    disallowed = _flag(cmd, "--disallowedTools")
    assert set(allowed) == set(EXTRACTION.analyst_allowed_tools)
    assert set(EXECUTOR_ONLY) <= set(disallowed)
    assert set(disallowed).isdisjoint(allowed)
    assert set(EXTRACTION.disallowed_tools) <= set(disallowed)
    assert set(disallowed) == set(EXTRACTION.disallowed_tools) | (ALL_TOOLS - set(allowed))
    assert len(disallowed) == len(set(disallowed))
    assert _flag(cmd, "--permission-mode") == ["bypassPermissions"]
    # ``--tools ""`` disables every Claude Code built-in (Read, Grep, Glob,
    # Write, WebFetch, ...) while MCP tools stay loaded (issue #213).
    assert cmd[cmd.index("--tools") + 1] == ""
    assert options.env["ENABLE_TOOL_SEARCH"] == "false"
    # No workspace .mcp.json: the CLI keeps its own MCP discovery.
    assert "--mcp-config" not in cmd
    assert "--strict-mcp-config" not in cmd


@pytest.mark.asyncio()
async def test_cli_command_uses_workspace_mcp_config(tmp_path: Path) -> None:
    mcp_json = tmp_path / ".mcp.json"
    mcp_json.write_text('{"mcpServers": {"mulder": {"command": "mulder", "args": ["serve"]}}}')
    orch = Orchestrator("/evidence", cwd=str(tmp_path))
    cmd = _cli_args(await _capture_options(orch, CATALOG.single_allowed_tools, ["Bash"]))
    assert _flag(cmd, "--mcp-config") == [str(mcp_json)]
    assert "--strict-mcp-config" in cmd


@pytest.mark.asyncio()
async def test_session_with_case_id_preloads_case_in_mcp_server(tmp_path: Path) -> None:
    """The mulder server starts with the case so query tools work before
    the model calls open_case; other servers in .mcp.json are kept (issue #230)."""
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"mulder": {"command": "mulder", "args": ["serve"]},'
        ' "other": {"command": "other-server"}}}'
    )
    orch = Orchestrator("/evidence", cwd=str(tmp_path), case_id="CASE-230")
    options = await _capture_options(orch, CATALOG.single_allowed_tools, ["Bash"])
    servers = cast("dict[str, dict[str, object]]", options.mcp_servers)
    assert servers["mulder"]["command"] == "mulder"
    assert servers["mulder"]["args"] == ["serve", "--case-id", "CASE-230"]
    assert servers["other"] == {"command": "other-server"}
    assert options.strict_mcp_config is True


@pytest.mark.asyncio()
async def test_session_without_case_id_keeps_workspace_mcp_config(tmp_path: Path) -> None:
    mcp_json = tmp_path / ".mcp.json"
    mcp_json.write_text('{"mcpServers": {"mulder": {"command": "mulder", "args": ["serve"]}}}')
    orch = Orchestrator("/evidence", cwd=str(tmp_path))
    options = await _capture_options(orch, CATALOG.single_allowed_tools, ["Bash"])
    assert options.mcp_servers == str(mcp_json)
    assert options.strict_mcp_config is True


@pytest.mark.asyncio()
async def test_utility_query_is_restricted_too(tmp_path: Path) -> None:
    orch = Orchestrator("/evidence", cwd=str(tmp_path))
    allowed = ["mcp__mulder__wait_all", "mcp__mulder__open_case", "mcp__mulder__list_cases"]
    options = await _capture_options(orch, allowed, [], utility=True)
    assert set(options.disallowed_tools) == ALL_TOOLS - set(allowed)
    assert options.tools == []
    assert options.env["ENABLE_TOOL_SEARCH"] == "false"


@pytest.mark.asyncio()
async def test_proxy_env_added_after_construction_still_reaches_sessions(
    tmp_path: Path,
) -> None:
    orch = Orchestrator("/evidence", cwd=str(tmp_path))
    orch.env["ANTHROPIC_BASE_URL"] = "http://localhost:4000"
    options = await _capture_options(orch, CATALOG.single_allowed_tools, [])
    assert options.env["ANTHROPIC_BASE_URL"] == "http://localhost:4000"
    assert options.env["ENABLE_TOOL_SEARCH"] == "false"


# ---------------------------------------------------------------------------
# (a) sessions must start with their MCP tools
# ---------------------------------------------------------------------------

ALLOWED = ["mcp__mulder__open_case", "mcp__mulder__search"]


@pytest.mark.parametrize(
    ("status", "tools"),
    [
        ("failed", ["Read", "Edit"]),
        ("pending", ["Read", "Edit"]),
        (None, ["Read", "Edit"]),
        ("connected", ["Read", "mcp__mulder__open_case"]),
    ],
)
@pytest.mark.asyncio()
async def test_session_without_its_tools_is_aborted_and_retried(
    status: str | None, tools: list[str], caplog: pytest.LogCaptureFixture
) -> None:
    orch = Orchestrator("/evidence")
    calls = 0
    closed = 0

    async def no_tools_query(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[object]:
        nonlocal calls, closed
        calls += 1
        try:
            yield _init(status, tools)
            yield AssistantMessage(content=[TextBlock(text="I have no tools")], model="m")
        except GeneratorExit:
            closed += 1
            raise

    with (
        patch("mulder.orchestrator.session.query", no_tools_query),
        caplog.at_level(logging.ERROR),
    ):
        result = await orch._session.execute("sys", "p", "test-model", ALLOWED, [], 5, "host-a")

    assert calls == _MCP_CONNECT_ATTEMPTS
    assert closed == _MCP_CONNECT_ATTEMPTS, "each aborted session must be closed explicitly"
    assert not result.success
    assert result.messages == [] and result.tool_names == []
    assert caplog.text.count("Session started without its tools") == _MCP_CONNECT_ATTEMPTS
    lines = [line.plain for line in orch.dashboard._log_lines]
    assert any("[host-a] Session started without its tools" in line for line in lines)


@pytest.mark.asyncio()
@pytest.mark.parametrize("leaked", [[], ["Read", "Grep"]])
async def test_session_with_its_tools_proceeds_and_flags_builtins(
    leaked: list[str], caplog: pytest.LogCaptureFixture
) -> None:
    """A session with its MCP tools runs; any built-in still present is a
    CLI drift warning, not an abort (issue #213)."""
    orch = Orchestrator("/evidence")
    calls = 0

    async def healthy_query(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[object]:
        nonlocal calls
        calls += 1
        yield _init("connected", [*leaked, *ALLOWED, "mcp__mulder__run_mmls"])
        yield AssistantMessage(content=[TextBlock(text="working")], model="m")

    with (
        patch("mulder.orchestrator.session.query", healthy_query),
        caplog.at_level(logging.WARNING, logger="mulder.orchestrator.session"),
    ):
        result = await orch._session.execute("sys", "p", "test-model", ALLOWED, [], 5)

    assert calls == 1
    assert result.messages == ["working"]
    warnings = [r for r in caplog.records if "built-in tool(s) despite tools=[]" in r.message]
    assert len(warnings) == (1 if leaked else 0)
    if leaked:
        assert "Grep, Read" in warnings[0].message


def test_builtin_tools_is_every_non_mcp_name() -> None:
    init = _init("connected", ["Write", "mcp__mulder__open_case", "Bash", "mcp__other__x"])
    assert builtin_tools(init) == ["Bash", "Write"]
    assert builtin_tools(SystemMessage(subtype="init", data={})) == []


@pytest.mark.asyncio()
async def test_session_without_mcp_allowlist_skips_check() -> None:
    """JSON repair runs with no tools at all; an absent server is fine there."""
    orch = Orchestrator("/evidence")

    async def bare_query(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[object]:
        yield _init(None, ["Read"])
        yield AssistantMessage(content=[TextBlock(text='{"tasks": []}')], model="m")

    with patch("mulder.orchestrator.session.query", bare_query):
        result = await orch._session.execute("sys", "p", "test-model", [], ["Bash"], 1)

    assert result.messages == ['{"tasks": []}']


# ---------------------------------------------------------------------------
# (b) an executor that runs nothing fails its attempt
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_run_executor_reports_tool_calls() -> None:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence")
    orch._case_id = "case"

    async def mock_execute(**kwargs: object) -> PhaseResult:
        return PhaseResult(
            phase_name="query",
            success=False,
            messages=['{"results": [{"tool": "run_mmls", "status": "ok"}]}'],
            tool_names=["open_case", "run_mmls"],
            turns_used=2,
        )

    with patch.object(orch._session, "execute", side_effect=mock_execute):
        results = await orch._roles.run_executor(EXTRACTION, _plan("run_mmls"))

    assert results.tool_calls == 1


@pytest.mark.asyncio()
@pytest.mark.parametrize(
    ("tool_names", "expected"),
    [
        (["open_case", "wait", "wait_all", "check_extraction_status", "get_completed_results"], 0),
        (["open_case", "start_extraction_batch", "wait"], 1),
        (["open_case", "run_parallel"], 1),
        (["list_cases", "open_case", "run_mmls"], 1),
    ],
)
async def test_run_executor_counts_only_extraction_calls(
    tool_names: list[str], expected: int
) -> None:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence")
    orch._case_id = "case"

    async def mock_execute(**kwargs: object) -> PhaseResult:
        return PhaseResult(
            phase_name="query", success=False, messages=[], tool_names=tool_names, turns_used=2
        )

    with patch.object(orch._session, "execute", side_effect=mock_execute):
        results = await orch._roles.run_executor(EXTRACTION, _plan("run_mmls"))

    assert results.tool_calls == expected


@pytest.mark.asyncio()
async def test_control_only_executor_is_retried() -> None:
    """open_case + wait with no extraction call is idle; one real call is not."""
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence")
    orch._case_id = "case"
    sessions = iter([["open_case", "wait"], ["open_case", "run_mmls"]])
    analyst_calls = 0

    async def mock_execute(**kwargs: object) -> PhaseResult:
        return PhaseResult(
            phase_name="q", success=False, messages=[], tool_names=next(sessions), turns_used=1
        )

    async def mock_analyst(*args: object, **kwargs: object) -> AnalystResult:
        nonlocal analyst_calls
        analyst_calls += 1
        return AnalystResult(
            findings_submitted=1, follow_up_request=None, messages=["done"], turns_used=1
        )

    with (
        patch.object(orch._session, "execute", side_effect=mock_execute),
        patch.object(orch._roles, "run_planner", return_value=_plan("run_mmls")),
        patch.object(orch._roles, "run_analyst", side_effect=mock_analyst),
        patch.object(orch._roles, "ensure_batches_complete", AsyncMock()),
        patch.object(orch, "_validate_phase", return_value=None),
    ):
        result = await orch._run_split_phase(EXTRACTION)

    assert result.success
    assert analyst_calls == 1
    cast("MagicMock", orch.dashboard.log_gate_fail).assert_any_call(
        "Executor made no extraction tool calls; skipping analyst "
        f"(attempt 1/{1 + EXTRACTION.max_retries})"
    )


def _split_phase_mocks(
    tool_calls_per_attempt: list[int],
) -> tuple[dict[str, int], dict[str, object]]:
    counts = {"planner": 0, "executor": 0, "analyst": 0}

    async def mock_planner(
        phase: object,
        prompt_vars: object = None,
        follow_up_context: str = "",
        log_prefix: str = "",
    ) -> Plan:
        counts["planner"] += 1
        return _plan("search")

    async def mock_executor(
        phase: object, plan: Plan, log_prefix: str = "", task_system: str = ""
    ) -> ExecutionResults:
        counts["executor"] += 1
        return ExecutionResults(
            plan_id=plan.plan_id,
            results=[],
            turns_used=1,
            has_failures=False,
            tool_calls=tool_calls_per_attempt[counts["executor"] - 1],
        )

    async def mock_analyst(
        phase: object,
        plan: Plan,
        exec_results: ExecutionResults,
        prompt_vars: object = None,
        log_prefix: str = "",
        task_system: str = "",
    ) -> AnalystResult:
        counts["analyst"] += 1
        return AnalystResult(
            findings_submitted=1, follow_up_request=None, messages=["done"], turns_used=1
        )

    return counts, {"planner": mock_planner, "executor": mock_executor, "analyst": mock_analyst}


@pytest.mark.asyncio()
async def test_zero_tool_executor_skips_analyst_and_retries_phase() -> None:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence")
    counts, mocks = _split_phase_mocks([0, 3])
    wait = AsyncMock()

    with (
        patch.object(orch._roles, "run_planner", side_effect=mocks["planner"]),
        patch.object(orch._roles, "run_executor", side_effect=mocks["executor"]),
        patch.object(orch._roles, "run_analyst", side_effect=mocks["analyst"]),
        patch.object(orch._roles, "ensure_batches_complete", wait),
        patch.object(orch, "_validate_phase", return_value=None),
    ):
        result = await orch._run_split_phase(CROSS_SYSTEM)

    assert result.success
    assert counts == {"planner": 2, "executor": 2, "analyst": 1}
    assert wait.await_count == 1
    # Failed attempt's planner + executor turns are still accounted for.
    assert result.turns_used == 2 + 3
    cast("MagicMock", orch.dashboard.log_gate_fail).assert_any_call(
        f"Executor made no extraction tool calls; skipping analyst "
        f"(attempt 1/{1 + CROSS_SYSTEM.max_retries})"
    )


@pytest.mark.asyncio()
async def test_zero_tool_executor_on_every_attempt_fails_phase() -> None:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence")
    attempts = 1 + CROSS_SYSTEM.max_retries
    counts, mocks = _split_phase_mocks([0] * attempts)

    with (
        patch.object(orch._roles, "run_planner", side_effect=mocks["planner"]),
        patch.object(orch._roles, "run_executor", side_effect=mocks["executor"]),
        patch.object(orch._roles, "run_analyst", side_effect=mocks["analyst"]),
        patch.object(orch, "_validate_phase", return_value=None),
    ):
        result = await orch._run_split_phase(CROSS_SYSTEM)

    assert not result.success
    assert counts == {"planner": attempts, "executor": attempts, "analyst": 0}
    cast("MagicMock", orch.dashboard.log_gate_fail).assert_any_call(
        f"{CROSS_SYSTEM.name} FAILED after {attempts} attempts"
    )
