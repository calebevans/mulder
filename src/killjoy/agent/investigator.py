"""Thin autonomous investigation agent that drives Killjoy's MCP tools via litellm."""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

import litellm
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import BaseModel

from killjoy.agent.prompts import INVESTIGATION_STRATEGY, SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_SUPPORTS_COLOR = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def _c(code: str, text: str) -> str:
    if _SUPPORTS_COLOR:
        return f"\033[{code}m{text}\033[0m"
    return text


def _green(t: str) -> str:
    return _c("32", t)


def _blue(t: str) -> str:
    return _c("34", t)


def _cyan(t: str) -> str:
    return _c("36", t)


def _yellow(t: str) -> str:
    return _c("33", t)


def _magenta(t: str) -> str:
    return _c("35", t)


def _red(t: str) -> str:
    return _c("31", t)


def _bold(t: str) -> str:
    return _c("1", t)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


class InvestigationResult(BaseModel):
    case_id: str
    iterations: int
    findings_submitted: int
    findings_confirmed: int
    findings_inference: int
    total_tool_calls: int
    elapsed_seconds: float


# ---------------------------------------------------------------------------
# Investigator
# ---------------------------------------------------------------------------


class _LoopStats:
    """Mutable counters shared across the agent loop."""

    __slots__ = (
        "iteration",
        "total_tool_calls",
        "findings_submitted",
        "findings_confirmed",
        "findings_inference",
    )

    def __init__(self) -> None:
        self.iteration = 0
        self.total_tool_calls = 0
        self.findings_submitted = 0
        self.findings_confirmed = 0
        self.findings_inference = 0


class Investigator:
    """Thin agent loop: litellm tool-use against a Killjoy MCP server."""

    def __init__(
        self,
        model: str,
        max_iterations: int = 20,
        case_id: str = "",
        verbose: bool = True,
    ) -> None:
        self._model = model
        self._max_iterations = max_iterations
        self._case_id = case_id
        self._verbose = verbose

    # -- public entry point -------------------------------------------------

    async def run(self, server_params: StdioServerParameters) -> InvestigationResult:
        t_start = time.monotonic()
        stats = _LoopStats()

        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                tool_list_result = await session.list_tools()
                tools_for_llm = self._convert_tools(tool_list_result.tools)

                self._log_info(
                    _bold(f"Connected to MCP server -- {len(tools_for_llm)} tools available")
                )

                messages: list[dict[str, Any]] = [
                    {
                        "role": "system",
                        "content": SYSTEM_PROMPT.format(max_iterations=self._max_iterations),
                    },
                    {"role": "user", "content": INVESTIGATION_STRATEGY},
                ]

                stats.iteration = await self._agent_loop(
                    session, messages, tools_for_llm, stats
                )

                await self._finalize(session)

        elapsed = time.monotonic() - t_start
        result = InvestigationResult(
            case_id=self._case_id,
            iterations=stats.iteration,
            findings_submitted=stats.findings_submitted,
            findings_confirmed=stats.findings_confirmed,
            findings_inference=stats.findings_inference,
            total_tool_calls=stats.total_tool_calls,
            elapsed_seconds=round(elapsed, 2),
        )
        self._print_summary(result)
        return result

    # -- core loop -----------------------------------------------------------

    async def _agent_loop(
        self,
        session: ClientSession,
        messages: list[dict[str, Any]],
        tools_for_llm: list[dict[str, Any]],
        stats: _LoopStats,
    ) -> int:
        """Run the main tool-use loop, returning the final iteration count."""
        iteration = 0
        while iteration < self._max_iterations:
            iteration += 1
            self._log_info(_bold(f"\n{'='*60}"))
            self._log_info(_bold(f"Iteration {iteration}/{self._max_iterations}"))
            self._log_info(_bold(f"{'='*60}"))

            try:
                response = await litellm.acompletion(
                    model=self._model,
                    messages=messages,
                    tools=tools_for_llm,
                    timeout=120,
                )
            except Exception as exc:
                self._log_error(f"LLM call failed: {exc}")
                break

            assistant_msg = response.choices[0].message
            messages.append(assistant_msg.model_dump(exclude_none=True))

            if assistant_msg.content:
                self._log_think(assistant_msg.content)

            if not assistant_msg.tool_calls:
                self._log_info(_green("Agent finished reasoning -- no more tool calls."))
                break

            await self._process_tool_calls(session, messages, assistant_msg.tool_calls, stats)

        return iteration

    async def _process_tool_calls(
        self,
        session: ClientSession,
        messages: list[dict[str, Any]],
        tool_calls: list,
        stats: _LoopStats,
    ) -> None:
        for tc in tool_calls:
            tc_name = tc.function.name
            try:
                tc_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            except json.JSONDecodeError:
                tc_args = {}

            stats.total_tool_calls += 1
            self._log_tool_call(tc_name, tc_args)

            try:
                mcp_result = await session.call_tool(tc_name, tc_args)
                result_text = self._extract_result_text(mcp_result)
            except Exception as exc:
                result_text = json.dumps({"error": str(exc)})
                self._log_error(f"Tool {tc_name} failed: {exc}")

            self._log_result(tc_name, result_text)

            if tc_name == "submit_finding":
                sub, conf, inf = self._track_finding(result_text)
                stats.findings_submitted += sub
                stats.findings_confirmed += conf
                stats.findings_inference += inf

            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result_text})

    async def _finalize(self, session: ClientSession) -> None:
        self._log_info(_bold("\nFinalising investigation report ..."))
        try:
            report_result = await session.call_tool("finalize_report", {})
            report_text = self._extract_result_text(report_result)
            self._log_info(_green(f"Report generated: {report_text}"))
        except Exception as exc:
            self._log_error(f"finalize_report failed: {exc}")

    # -- tool schema conversion ---------------------------------------------

    @staticmethod
    def _convert_tools(mcp_tools: list) -> list[dict[str, Any]]:
        """Convert MCP Tool objects to litellm/OpenAI function-calling format."""
        converted: list[dict[str, Any]] = []
        for tool in mcp_tools:
            schema = tool.inputSchema if isinstance(tool.inputSchema, dict) else {}
            converted.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description or "",
                        "parameters": schema,
                    },
                }
            )
        return converted

    # -- MCP result extraction -----------------------------------------------

    @staticmethod
    def _extract_result_text(result: Any) -> str:
        """Pull text content from an MCP CallToolResult."""
        parts: list[str] = []
        for block in result.content:
            if hasattr(block, "text"):
                parts.append(block.text)
        return "\n".join(parts) if parts else "{}"

    # -- finding tracking ----------------------------------------------------

    @staticmethod
    def _track_finding(result_text: str) -> tuple[int, int, int]:
        """Return (submitted, confirmed, inference) counts from a submit_finding result."""
        try:
            data = json.loads(result_text)
        except json.JSONDecodeError:
            return (0, 0, 0)
        if data.get("status") == "accepted":
            conf = data.get("confidence", "")
            return (1, int(conf == "confirmed"), int(conf == "inference"))
        return (0, 0, 0)

    # -- verbose output helpers ----------------------------------------------

    def _log_info(self, msg: str) -> None:
        if self._verbose:
            print(msg, file=sys.stderr)

    def _log_think(self, text: str) -> None:
        if not self._verbose:
            return
        truncated = text[:500] + (" ..." if len(text) > 500 else "")
        print(f"{_green('[THINK]')} {truncated}", file=sys.stderr)

    def _log_tool_call(self, name: str, args: dict) -> None:
        if not self._verbose:
            return
        tag = _magenta("[VERIFY]") if name == "correlate_across_sources" else _blue("[TOOL]")
        args_str = json.dumps(args, default=str)
        if len(args_str) > 200:
            args_str = args_str[:200] + " ..."
        print(f"{tag} {_bold(name)}({args_str})", file=sys.stderr)

    def _log_result(self, name: str, result_text: str) -> None:
        if not self._verbose:
            return
        if name == "submit_finding":
            self._log_finding(result_text)
            return
        try:
            data = json.loads(result_text)
            count = data.get("result_count", "?")
            reduced = " (reduced)" if data.get("reduced") else ""
            summary = f"{count} result(s){reduced}"
        except (json.JSONDecodeError, AttributeError):
            summary = f"{len(result_text)} chars"
        print(f"{_cyan('[RESULT]')} {name} -> {summary}", file=sys.stderr)

    def _log_finding(self, result_text: str) -> None:
        try:
            data = json.loads(result_text)
        except json.JSONDecodeError:
            data = {}
        if data.get("status") == "accepted":
            fid = data.get("finding_id", "?")
            conf = data.get("confidence", "?")
            print(
                f"{_yellow('[FINDING]')} Accepted: {fid} (confidence={conf})",
                file=sys.stderr,
            )
        elif "error" in data:
            print(
                f"{_red('[FINDING]')} Rejected: {data['error']}",
                file=sys.stderr,
            )

    def _log_error(self, msg: str) -> None:
        print(f"{_red('[ERROR]')} {msg}", file=sys.stderr)

    def _print_summary(self, result: InvestigationResult) -> None:
        print(f"\n{_bold('='*60)}", file=sys.stderr)
        print(_bold("Investigation Summary"), file=sys.stderr)
        print(f"{_bold('='*60)}", file=sys.stderr)
        print(f"  Case:            {result.case_id}", file=sys.stderr)
        print(f"  Iterations:      {result.iterations}", file=sys.stderr)
        print(f"  Tool calls:      {result.total_tool_calls}", file=sys.stderr)
        print(f"  Findings:        {result.findings_submitted}", file=sys.stderr)
        print(f"    Confirmed:     {result.findings_confirmed}", file=sys.stderr)
        print(f"    Inference:     {result.findings_inference}", file=sys.stderr)
        print(f"  Elapsed:         {result.elapsed_seconds:.1f}s", file=sys.stderr)
        print(f"{_bold('='*60)}\n", file=sys.stderr)
