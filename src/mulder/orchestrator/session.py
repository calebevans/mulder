"""SDK session execution, message streaming, and token tracking.

Encapsulates all interactions with the Claude Agent SDK ``query`` function.
Processes streamed messages (assistant text, tool use, results) and reports
token usage and tool activity to the dashboard.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions, query
from claude_agent_sdk.types import (
    AssistantMessage,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
)
from rich.text import Text

from mulder.orchestrator.display import InvestigationDashboard
from mulder.orchestrator.errors import AuthenticationError, ModelNotAvailableError
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.proxy import ModelSettings, is_proxy_model
from mulder.orchestrator.types import EffortLevel, PhaseResult, extract_json_from_text
from mulder.server.tool_access import ALL_ROLES, get_tools_for_role

logger = logging.getLogger(__name__)


@dataclass
class _MessageStats:
    """What one ``AssistantMessage`` contributed to the running session totals."""

    in_tokens: int = 0
    out_tokens: int = 0
    tool_calls: int = 0
    hit_context: bool = False
    thinking_blocks: int = 0
    thinking_chars: int = 0
    #: A non-empty text block (after markup trimming) or a tool call.
    has_output: bool = False
    msg_id: str | None = None


_MCP_SERVER_NAME: str = "mulder"
_MCP_TOOL_PREFIX: str = f"mcp__{_MCP_SERVER_NAME}__"

#: Sessions that start without their MCP tools are aborted at the CLI's
#: ``init`` message and respawned this many times in total.
_MCP_CONNECT_ATTEMPTS: int = 3

#: Claude Code's tool search (default ``auto``) defers MCP tools behind a
#: ``ToolSearch`` tool once their schemas pass a context threshold, at which
#: point the model no longer sees the role's tool list. Every mulder role is
#: defined by exactly which tools the model sees, so deferral is off.
_SESSION_ENV: dict[str, str] = {"ENABLE_TOOL_SEARCH": "false"}


def off_role_tools(allowed_tools: list[str]) -> list[str]:
    """Return every registered mulder MCP tool that is not in *allowed_tools*.

    ``ClaudeAgentOptions.allowed_tools`` only auto-approves permissions, and
    ``bypassPermissions`` already approves everything, so on its own the
    role allowlist restricts nothing. ``disallowed_tools`` is the option that
    removes tools from the model's context, so the complement of the
    allowlist is what makes the allowlist real.

    Args:
        allowed_tools: Fully qualified tool names the session may use.

    Returns:
        Sorted MCP tool names the session must not see.
    """
    allowed = frozenset(allowed_tools)
    return [t for t in get_tools_for_role(ALL_ROLES) if t not in allowed]


def _missing_mcp_tools(init: SystemMessage, expected: set[str]) -> str:
    """Explain why the CLI's ``init`` message lacks the session's MCP tools.

    Args:
        init: The ``system``/``init`` message emitted before the first turn.
        expected: Fully qualified mulder tool names the session relies on.

    Returns:
        Empty string when the server is connected and every expected tool
        is present, otherwise a one-line reason for the dashboard and log.
    """
    servers = init.data.get("mcp_servers") or []
    status = next(
        (
            s.get("status")
            for s in servers
            if isinstance(s, dict) and s.get("name") == _MCP_SERVER_NAME
        ),
        None,
    )
    if status != "connected":
        return f"MCP server '{_MCP_SERVER_NAME}' status={status or 'not configured'}"
    missing = sorted(expected - set(init.data.get("tools") or []))
    if missing:
        return f"{len(missing)} allowed tool(s) absent from session (e.g. {missing[0]})"
    return ""


def builtin_tools(init: SystemMessage) -> list[str]:
    """Return the non-MCP (Claude Code built-in) tools an ``init`` message lists.

    Sessions run with ``tools=[]``, so this should be empty; anything here
    means the CLI's built-in handling drifted and the model can read
    evidence, write the workspace or reach the network outside the audit
    log.

    Args:
        init: The ``system``/``init`` message emitted before the first turn.

    Returns:
        Sorted tool names that do not start with ``mcp__``.
    """
    return sorted(t for t in init.data.get("tools") or [] if not t.startswith("mcp__"))


_AUTH_PATTERNS: tuple[str, ...] = (
    "not logged in",
    "please run /login",
    "invalid api key",
    "invalid x-api-key",
    "authentication_error",
    "could not authenticate",
    "permission denied",
    "accessdeniedexception",
)

_MODEL_PATTERNS: tuple[str, ...] = (
    "is not available on your",
    "model is not available",
    "is not available in your",
    "model not found",
    "you could try using",
)


#: Provider phrasings for a request that no longer fits the model's context
#: window. Anthropic: "prompt is too long: N tokens > M maximum" and "input
#: length and `max_tokens` exceed context limit". Bedrock Claude: "Input is
#: too long for requested model". OpenAI-compatible providers and Bedrock
#: open-weight models via LiteLLM: "This model's maximum context length is N
#: tokens" with error code ``context_length_exceeded``. Claude Code's own
#: stop reason: "The model has reached its context window limit".
_CONTEXT_PATTERNS: tuple[str, ...] = (
    "prompt is too long",
    "input is too long",
    "exceed context limit",
    "maximum context length",
    "context_length_exceeded",
    "context window limit",
)


def _is_context_exhausted(text: str) -> bool:
    """Return True when *text* is a provider's context-overflow rejection.

    Args:
        text: Error message or streamed text content.

    Returns:
        True if any known overflow phrasing appears (case-insensitive).
    """
    lower = text.lower()
    return any(pattern in lower for pattern in _CONTEXT_PATTERNS)


#: ``ResultMessage.subtype`` the CLI emits when the agent loop stopped at
#: ``max_turns`` without a final answer. The SDK then raises a ``ResultError``
#: carrying the same subtype ("Claude Code returned an error result: Reached
#: maximum number of turns (N)").
_MAX_TURNS_SUBTYPE = "error_max_turns"


def _is_turns_exhausted(message: object) -> bool:
    """Return True when a ResultMessage or SDK error reports the turn limit.

    Args:
        message: A ``ResultMessage`` or an exception raised by ``query``.

    Returns:
        True if its structured ``subtype`` is ``error_max_turns``.
    """
    return getattr(message, "subtype", None) == _MAX_TURNS_SUBTYPE


def _classify_fatal_error(text: str) -> tuple[str, str]:
    """Classify text as an auth error, model error, or neither.

    Args:
        text: Error message or streamed text content.

    Returns:
        Tuple of (category, matched_text) where category is
        "auth", "model", or "" (empty string for no match).
    """
    lower = text.lower()
    for pattern in _AUTH_PATTERNS:
        if pattern in lower:
            return "auth", text
    for pattern in _MODEL_PATTERNS:
        if pattern in lower:
            return "model", text
    return "", ""


def _auth_suggestion() -> str:
    """Build an actionable suggestion for auth failures.

    Returns:
        Multi-line string with provider-specific guidance.
    """
    lines = ["Authentication failed. To fix this:"]
    if os.environ.get("CLAUDE_CODE_USE_VERTEX") == "1":
        lines.append(
            "  - Vertex AI: run `gcloud auth application-default login` "
            "and verify GOOGLE_CLOUD_PROJECT is set"
        )
    elif os.environ.get("CLAUDE_CODE_USE_BEDROCK") == "1":
        lines.append(
            "  - Bedrock: verify AWS credentials "
            "(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION)"
        )
    else:
        lines.append("  - Set ANTHROPIC_API_KEY in your environment")
        lines.append("  - Or run `claude /login` to authenticate interactively")
    return "\n".join(lines)


def _extract_alternative_model(text: str) -> str:
    """Extract an alternative model name from an SDK error message.

    Looks for patterns like "You could try using <model> instead".

    Args:
        text: The full error message text.

    Returns:
        Alternative model identifier, or empty string if none found.
    """
    match = re.search(
        r"(?:try using|try|use)\s+([\w.@:/-]+)\s+instead",
        text,
        re.IGNORECASE,
    )
    return match.group(1) if match else ""


def _is_bare_markup_token(text: str) -> bool:
    """Return True when a text block is only a leaked special token.

    Non-Anthropic models behind the LiteLLM proxy can leak their native
    tool-call markup as a stray text block next to the real ToolUseBlock,
    e.g. ``<｜DSML｜function_calls``, ``<|python_tag|>``, ``<tool_call>``,
    ``[TOOL_CALLS]``. Conservative on purpose: one whitespace-free token
    opening with ``<`` or ``[``. Prose contains spaces and JSON opens with
    ``{``, so neither can ever match.

    Args:
        text: Raw text block content.

    Returns:
        True if the block should be dropped from the message log.
    """
    token = text.strip()
    return bool(token) and token[0] in "<[" and not any(c.isspace() for c in token)


def _trim_edge_markup_lines(text: str) -> str:
    """Strip leaked markup tokens from the first and last lines of a block.

    The leak usually rides along with prose rather than arriving as its own
    block, e.g. ``"Now let me search the timeline.\n<｜DSML｜function_calls"``.
    Leading and trailing lines that are blank or individually satisfy
    :func:`_is_bare_markup_token` are removed, so a marker separated from
    the edge only by whitespace still goes; interior lines are untouched.

    Args:
        text: Raw text block content.

    Returns:
        The block with edge markup and blank lines removed (may be empty).
    """
    lines = text.splitlines()
    while lines and _is_edge_trimmable(lines[0]):
        lines.pop(0)
    while lines and _is_edge_trimmable(lines[-1]):
        lines.pop()
    return "\n".join(lines)


def _is_edge_trimmable(line: str) -> bool:
    return not line.strip() or _is_bare_markup_token(line)


_TASK_PANEL_SKIP: frozenset[str] = frozenset(
    {
        "search",
        "get_raw_output",
        "get_findings",
        "get_investigation_summary",
        "get_source_stats",
        "get_timeline",
        "get_bookmarks",
        "open_case",
        "list_cases",
        "list_sources",
        "track_progress",
        "check_extraction_status",
        "get_completed_results",
        "wait",
        "wait_all",
        "submit_finding",
        "update_finding",
        "bookmark_window",
    }
)

_MAX_BUFFER_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB

# Claude Code auto-titles every session with an extra model request that
# mulder never reads. This env var suppresses it in headless/SDK sessions
# (Claude Code changelog 2.1.110). Caller env still wins.
_NO_SESSION_TITLE: dict[str, str] = {"CLAUDE_CODE_DISABLE_TERMINAL_TITLE": "1"}


class SessionExecutor:
    """Executes Claude Agent SDK query sessions and processes streamed messages.

    This class owns the low-level SDK interaction layer: constructing query
    options, iterating over streamed messages, processing assistant and result
    messages, tracking token usage, and detecting context exhaustion.

    All phase and role runners delegate to this class for actual SDK
    communication.
    """

    def __init__(
        self,
        dashboard: InvestigationDashboard,
        model_config: ModelConfig,
        cwd: str,
        env: dict[str, str],
        effort: EffortLevel,
        using_proxy: bool = False,
        no_thinking: bool = False,
        show_cli_stderr: bool = False,
    ) -> None:
        """Initialize the session executor.

        Args:
            dashboard: Live dashboard for real-time display and token tracking.
            model_config: Model identifiers for utility model resolution.
            cwd: Working directory for agent sessions.
            env: Environment variables passed to agent subprocesses.
            effort: Effort level for agent sessions (max, xhigh, high, low).
            using_proxy: Whether a LiteLLM proxy is active (disables
                per-message token tracking to avoid double counting).
            no_thinking: Disable extended thinking for phase and utility queries.
            show_cli_stderr: Stream agent CLI diagnostics to the dashboard and log.
        """
        self._dashboard = dashboard
        self._model_config = model_config
        self._cwd = cwd
        self._env = env
        self._effort = effort
        self._using_proxy = using_proxy
        #: Effective limits per proxy-routed model, filled by the orchestrator
        #: from the proxy once it is healthy.
        self._proxy_settings: dict[str, ModelSettings] = {}
        self._no_thinking = no_thinking
        self._show_cli_stderr = show_cli_stderr

    def _stderr_callback(self, label: str) -> Callable[[str], None]:
        """Keep diagnostics scoped to their query and inside the live dashboard."""
        if not self._show_cli_stderr:
            return self._dashboard.suppress_stderr

        def log_stderr(line: str) -> None:
            for text in Text.from_ansi(line).plain.splitlines():
                if text.strip():
                    self._dashboard.log(f"[{label}] CLI stderr: {text}")

        return log_stderr

    def _gateway_env(self, model: str) -> dict[str, str]:
        """Context and output limits Claude Code should assume for *model*.

        Claude Code sizes a model ID it does not recognise as a Claude model:
        32000 output tokens per request and a 200K context window. Behind
        the LiteLLM proxy that means a 163K model is never auto-compacted
        before the provider rejects the request. Both env vars are the
        CLI's documented overrides for gateway model IDs; native Anthropic,
        Bedrock-Claude and Vertex sessions keep the CLI defaults.

        Args:
            model: Model identifier for the session.

        Returns:
            Env vars for proxy-routed models, empty otherwise.
        """
        if not is_proxy_model(model):
            return {}
        settings = self._proxy_settings.get(model) or ModelSettings()
        env = {"CLAUDE_CODE_MAX_OUTPUT_TOKENS": str(settings.max_output_tokens)}
        if settings.context_window:
            env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"] = str(settings.context_window)
        return env

    def _shared_options(
        self, allowed_tools: list[str], disallowed_tools: list[str], model: str
    ) -> dict[str, Any]:
        """Options every session gets: tool enforcement, env, MCP config.

        The workspace ``.mcp.json`` is handed to the CLI explicitly (with
        ``strict_mcp_config``) so the session does not depend on project
        MCP approval state or pick up unrelated user-level servers. When
        the run is pinned to a case (``MULDER_CASE_ID`` in *env*, set by the
        orchestrator) the ``mulder`` server is started with ``--case-id``
        so query tools work before the model calls ``open_case``
        (issue #230); other servers in ``.mcp.json`` are kept.

        Args:
            allowed_tools: Role allowlist for this session.
            disallowed_tools: Phase blocklist; the off-role complement of
                *allowed_tools* is appended so the model never sees it.
            model: Model identifier, for gateway context/output limits.

        Returns:
            Keyword arguments for ``ClaudeAgentOptions``.
        """
        mcp_config = Path(self._cwd) / ".mcp.json"
        servers: dict[str, Any] | str = str(mcp_config) if mcp_config.is_file() else {}
        case_id = self._env.get("MULDER_CASE_ID", "")
        if case_id:
            if mcp_config.is_file():
                servers = dict(json.loads(mcp_config.read_text()).get("mcpServers") or {})
            else:
                servers = {}
            servers["mulder"] = {
                "type": "stdio",
                "command": "mulder",
                "args": ["serve", "--case-id", case_id],
            }
        return {
            # ``[]`` disables every Claude Code built-in (Read, Grep, Glob,
            # Write, Edit, WebFetch, Task, ...) while MCP tools stay loaded,
            # so the audited MCP path is the only path (issue #213).
            "tools": [],
            "allowed_tools": allowed_tools,
            "disallowed_tools": list(
                dict.fromkeys([*disallowed_tools, *off_role_tools(allowed_tools)])
            ),
            "permission_mode": "bypassPermissions",
            "cwd": self._cwd,
            # Title opt-out and gateway limits are defaults the caller may
            # override; tool-search off is enforced so the role allowlists
            # reach the model upfront.
            "env": {
                **_NO_SESSION_TITLE,
                **self._gateway_env(model),
                **self._env,
                **_SESSION_ENV,
            },
            "mcp_servers": servers,
            "strict_mcp_config": bool(servers),
        }

    async def execute(
        self,
        system_prompt: str,
        prompt: str,
        model: str,
        allowed_tools: list[str],
        disallowed_tools: list[str],
        max_turns: int,
        log_prefix: str = "",
        task_system: str = "",
    ) -> PhaseResult:
        """Execute a single SDK query session.

        Constructs query options, streams messages from the SDK, and
        collects results including text output, tool invocations, and
        token usage. Detects context exhaustion via error messages and
        exception handling.

        Args:
            system_prompt: System prompt for the session.
            prompt: User message prompt.
            model: Model identifier.
            allowed_tools: Tool whitelist.
            disallowed_tools: Tool blocklist.
            max_turns: Maximum tool-use turns.
            log_prefix: Optional prefix for dashboard log lines.
            task_system: When non-empty, tool use blocks update the
                dashboard task panel for this system name.

        Returns:
            PhaseResult with collected messages and usage information.
        """
        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            model=model,
            max_turns=max_turns,
            effort=None if self._no_thinking else self._effort,
            thinking={"type": "disabled"} if self._no_thinking else None,
            stderr=self._stderr_callback(log_prefix or task_system or model),
            max_buffer_size=_MAX_BUFFER_SIZE_BYTES,
            **self._shared_options(allowed_tools, disallowed_tools, model),
        )
        expected_mcp_tools = {t for t in allowed_tools if t.startswith(_MCP_TOOL_PREFIX)}

        messages: list[str] = []
        collected_tool_names: list[str] = []
        collected_batch_ids: set[str] = set()
        turns_used = 0
        session_id = ""

        logger.info(
            "Starting query (model=%s, max_turns=%d)",
            model,
            max_turns,
        )

        tool_count = 0
        phase_in_tokens = 0
        phase_out_tokens = 0
        seen_message_ids: set[str] = set()
        thinking_blocks = 0
        thinking_chars = 0
        # The CLI can emit one AssistantMessage per content block of the same
        # API turn (same message_id), so silence is judged per turn, not per
        # SDK message; the running turn is closed when the id changes or at
        # the ResultMessage.
        turn_id: str | None = None
        turn_has_output = False
        last_silent = False
        got_result = False
        hit_context_limit = False
        hit_turn_limit = False

        for connect_attempt in range(1, _MCP_CONNECT_ATTEMPTS + 1):
            mcp_problem = ""
            try:
                stream = query(prompt=prompt, options=options)
                async for message in stream:
                    if isinstance(message, SystemMessage) and message.subtype == "init":
                        # The CLI runs the first turn even when the MCP server
                        # failed to connect, so the model would answer with
                        # built-in tools only. Kill the session before that.
                        if expected_mcp_tools:
                            mcp_problem = _missing_mcp_tools(message, expected_mcp_tools)
                        if mcp_problem:
                            await stream.aclose()
                            break
                        if leaked := builtin_tools(message):
                            logger.warning(
                                "Session has %d built-in tool(s) despite tools=[] (model=%s): %s",
                                len(leaked),
                                model,
                                ", ".join(leaked),
                            )

                    elif isinstance(message, AssistantMessage):
                        stats = self._process_assistant_message(
                            message,
                            log_prefix,
                            seen_message_ids,
                            messages,
                            tool_names_out=collected_tool_names,
                            task_system=task_system,
                        )
                        phase_in_tokens += stats.in_tokens
                        phase_out_tokens += stats.out_tokens
                        tool_count += stats.tool_calls
                        thinking_blocks += stats.thinking_blocks
                        thinking_chars += stats.thinking_chars
                        if stats.hit_context:
                            hit_context_limit = True
                        if stats.msg_id != turn_id:
                            if turn_id is not None and not turn_has_output:
                                self._log_silent_turn(log_prefix)
                            turn_id, turn_has_output = stats.msg_id, False
                        turn_has_output = turn_has_output or stats.has_output

                    elif isinstance(message, ResultMessage):
                        if _is_turns_exhausted(message):
                            hit_turn_limit = True
                        last_silent = turn_id is not None and not turn_has_output
                        if last_silent:
                            self._log_silent_turn(log_prefix)
                        (
                            turns_used,
                            session_id,
                            got_result,
                            phase_in_tokens,
                            phase_out_tokens,
                        ) = self._process_result_message(
                            message,
                            model,
                            tool_count,
                            turns_used,
                            phase_in_tokens,
                            phase_out_tokens,
                            thinking=(thinking_blocks, thinking_chars),
                            last_silent=last_silent,
                        )

                    self._extract_batch_ids_from_message(message, collected_batch_ids)
            except KeyboardInterrupt:
                raise
            except SystemExit:
                raise
            except (AuthenticationError, ModelNotAvailableError):
                raise
            except Exception as exc:
                exc_msg = str(exc)
                exc_lower = exc_msg.lower()

                category, _ = _classify_fatal_error(exc_msg)
                if category == "auth":
                    raise AuthenticationError(
                        message=exc_msg,
                        suggestion=_auth_suggestion(),
                    ) from exc
                if category == "model":
                    alt = _extract_alternative_model(exc_msg)
                    raise ModelNotAvailableError(
                        message=exc_msg,
                        model=model,
                        alternative=alt,
                    ) from exc

                if hit_turn_limit or _is_turns_exhausted(exc):
                    # The CLI already yielded the error_max_turns result; the
                    # trailing exception is its deliberate non-zero exit.
                    hit_turn_limit = True
                    self._dashboard.log_info(f"Turn limit reached ({max_turns}); will continue")
                    logger.warning("Turn limit reached (max_turns=%d): %s", max_turns, exc_msg)
                elif _is_context_exhausted(exc_msg):
                    self._dashboard.log_info(f"Context exhausted: {exc_msg}")
                    logger.warning("Context exhausted: %s", exc_msg)
                    hit_context_limit = True
                elif "error result: success" in exc_lower:
                    self._dashboard.log_info("Query completed (SDK reported success as error)")
                else:
                    self._dashboard.log_gate_fail(f"Query error: {exc_msg}")
                    logger.error("Query error: %s", exc_msg)

            if not mcp_problem:
                break
            pfx = f"[{log_prefix}] " if log_prefix else ""
            self._dashboard.log_gate_fail(
                f"{pfx}Session started without its tools: {mcp_problem} "
                f"(attempt {connect_attempt}/{_MCP_CONNECT_ATTEMPTS})"
            )
            logger.error(
                "Session started without its tools (model=%s, attempt %d/%d): %s",
                model,
                connect_attempt,
                _MCP_CONNECT_ATTEMPTS,
                mcp_problem,
            )

        if not got_result and (phase_in_tokens or phase_out_tokens):
            logger.warning(
                "Query ended without ResultMessage; token count may be "
                "incomplete (tracked: in=%d, out=%d)",
                phase_in_tokens,
                phase_out_tokens,
            )

        return PhaseResult(
            phase_name="query",
            success=False,
            messages=messages,
            tool_names=collected_tool_names,
            turns_used=turns_used,
            session_id=session_id,
            context_exhausted=hit_context_limit or hit_turn_limit,
            turns_exhausted=hit_turn_limit,
            batch_ids=collected_batch_ids,
        )

    def _process_assistant_message(
        self,
        message: AssistantMessage,
        log_prefix: str,
        seen_message_ids: set[str],
        messages: list[str],
        tool_names_out: list[str] | None = None,
        task_system: str = "",
    ) -> _MessageStats:
        """Process content blocks from an AssistantMessage.

        Args:
            message: The assistant message to process.
            log_prefix: Prefix for dashboard log lines.
            seen_message_ids: Set of already-processed message IDs (mutated).
            messages: Accumulator for text block content (mutated).
            tool_names_out: When provided, MCP tool short names are
                appended here for structured gate validation (mutated).
            task_system: When non-empty, tool use blocks update the
                dashboard task panel for this system.

        Returns:
            Token deltas, tool/thinking counts and whether the message
            produced visible output (see ``_MessageStats``).
        """
        msg_id = getattr(message, "message_id", None)
        stats = _MessageStats(msg_id=msg_id)
        msg_usage = getattr(message, "usage", None) or {}
        msg_in = msg_usage.get("input_tokens", 0) or 0
        msg_out = msg_usage.get("output_tokens", 0) or 0

        is_new_step = msg_id is None or msg_id not in seen_message_ids
        if msg_id is not None:
            seen_message_ids.add(msg_id)

        if is_new_step and (msg_in or msg_out) and not self._using_proxy:
            stats.in_tokens = msg_in
            stats.out_tokens = msg_out
            self._dashboard.add_tokens(msg_in, msg_out)

        pfx = f"[{log_prefix}] " if log_prefix else ""

        for block in message.content:
            if isinstance(block, TextBlock):
                text = _trim_edge_markup_lines(block.text)
                if text != block.text:
                    logger.debug("Trimmed leaked markup from text block: %r", block.text)
                    if not text.strip():
                        continue
                messages.append(text)
                if text.strip():
                    stats.has_output = True

                category, _ = _classify_fatal_error(text)
                if category == "auth":
                    raise AuthenticationError(
                        message=text,
                        suggestion=_auth_suggestion(),
                    )
                if category == "model":
                    alt = _extract_alternative_model(text)
                    raise ModelNotAvailableError(
                        message=text,
                        model="",
                        alternative=alt,
                    )

                if _is_context_exhausted(text):
                    stats.hit_context = True
                    self._dashboard.log_info(f"{pfx}Context exhausted (detected in response)")
                else:
                    display_text = text.replace("<thinking>", "").replace("</thinking>", "")
                    stripped = display_text.strip()
                    if stripped.startswith("{") and stripped.endswith("}") and len(stripped) > 100:
                        try:
                            parsed = json.loads(stripped)
                            if "tasks" in parsed:
                                task_names = [
                                    t.get("tool", "?") if isinstance(t, dict) else "?"
                                    for t in parsed["tasks"][:5]
                                ]
                                summary = ", ".join(task_names)
                                extra = (
                                    f" +{len(parsed['tasks']) - 5} more"
                                    if len(parsed["tasks"]) > 5
                                    else ""
                                )
                                self._dashboard.log_tool(
                                    f"{pfx}Plan: {len(parsed['tasks'])} tasks ({summary}{extra})"
                                )
                            elif "results" in parsed:
                                results = parsed["results"]
                                _ok = ("ok", "success")
                                ok_count = sum(1 for r in results if r.get("status") in _ok)
                                fail_count = len(results) - ok_count
                                status = f"{ok_count}/{len(results)} ok"
                                if fail_count:
                                    status += f", {fail_count} failed"
                                self._dashboard.log_tool(f"{pfx}Results: {status}")
                            else:
                                self._dashboard.log(f"{pfx}[JSON output]")
                        except (json.JSONDecodeError, TypeError):
                            self._dashboard.log(f"{pfx}[JSON output]")
                        continue
                    if display_text.strip():
                        self._dashboard.log(f"{pfx}{display_text}" if pfx else display_text)
            elif (
                isinstance(block, ThinkingBlock) or type(block).__name__ == "RedactedThinkingBlock"
            ):
                # SDK 0.2.152 has no RedactedThinkingBlock; the name check
                # covers one appearing later. Length only, never content.
                stats.thinking_blocks += 1
                stats.thinking_chars += len(getattr(block, "thinking", "") or "")
            elif isinstance(block, ToolUseBlock):
                stats.tool_calls += 1
                stats.has_output = True
                tool_short = block.name.replace("mcp__mulder__", "")
                if tool_names_out is not None:
                    tool_names_out.append(tool_short)
                if tool_short == "submit_finding":
                    tool_input = getattr(block, "input", None) or {}
                    severity = str(tool_input.get("severity", "unknown"))
                    title = str(tool_input.get("title", "Untitled"))
                    self._dashboard.log_finding(severity, f"{pfx}{title}" if pfx else title)
                else:
                    self._dashboard.log_tool(f"{pfx}{tool_short}" if pfx else tool_short)
                if task_system and tool_short not in _TASK_PANEL_SKIP:
                    if tool_short == "start_extraction_batch":
                        tool_input = getattr(block, "input", None) or {}
                        batch_tools = tool_input.get("tasks", [])
                        for bt in batch_tools:
                            batch_tool_name = str(bt.get("tool", ""))
                            if batch_tool_name:
                                self._dashboard.update_task(
                                    task_system, batch_tool_name, "running"
                                )
                    else:
                        self._dashboard.update_task(task_system, tool_short, "running")

        if stats.thinking_blocks:
            logger.info(
                "%sthinking: %d blocks, %d chars", pfx, stats.thinking_blocks, stats.thinking_chars
            )
        return stats

    @staticmethod
    def _log_silent_turn(log_prefix: str) -> None:
        """Warn that an assistant turn produced no text and no tool use.

        With reasoning enabled through a proxy the answer can land in the
        thinking block with an empty text block, which otherwise looks like
        silence in the log while the session ends (#199).
        """
        pfx = f"[{log_prefix}] " if log_prefix else ""
        logger.warning(
            "%sassistant turn had no text and no tool use (thinking-only or empty); "
            "session may end here",
            pfx,
        )

    @staticmethod
    def _extract_tokens(message: Any) -> tuple[int, int]:
        """Extract (input_tokens, output_tokens) from a ResultMessage.

        Checks ``message.usage`` first, then falls back to ``model_usage``
        aggregation for SDK versions that report per-model token counts.

        Args:
            message: A ResultMessage (or any object with usage/model_usage).

        Returns:
            Tuple of (input_tokens, output_tokens).
        """
        usage = getattr(message, "usage", None) or {}
        tok_in: int = usage.get("input_tokens", 0) or 0
        tok_out: int = usage.get("output_tokens", 0) or 0
        if not tok_in and not tok_out:
            mu = getattr(message, "model_usage", None)
            if mu and isinstance(mu, dict):
                for _mname, mvals in mu.items():
                    if isinstance(mvals, dict):
                        tok_in += mvals.get("inputTokens", 0) or 0
                        tok_out += mvals.get("outputTokens", 0) or 0
        return tok_in, tok_out

    @staticmethod
    def _extract_batch_ids_from_message(message: Any, batch_ids: set[str]) -> None:
        """Extract batch IDs from tool_result content blocks in a message.

        Inspects any message with a ``content`` attribute for blocks whose
        ``type`` is ``"tool_result"``. When the block content is a JSON string
        containing a ``batch_id`` field, that ID is added to the accumulator.

        Args:
            message: A streamed message from the SDK (any type).
            batch_ids: Accumulator set to add discovered IDs to (mutated).
        """
        content = getattr(message, "content", None)
        if not content:
            return
        if not isinstance(content, list):
            return

        for block in content:
            if getattr(block, "type", None) != "tool_result":
                continue
            block_content = getattr(block, "content", None)
            if not isinstance(block_content, str):
                continue
            try:
                data = json.loads(block_content)
                if isinstance(data, dict) and "batch_id" in data:
                    batch_ids.add(data["batch_id"])
            except (json.JSONDecodeError, TypeError):
                pass

    def _process_result_message(
        self,
        message: ResultMessage,
        model_label: str,
        tool_count: int,
        turns_used: int,
        phase_in_tokens: int,
        phase_out_tokens: int,
        thinking: tuple[int, int] = (0, 0),
        last_silent: bool = False,
    ) -> tuple[int, str, bool, int, int]:
        """Process a ResultMessage and reconcile token counts.

        Args:
            message: The result message from the SDK.
            model_label: Model identifier for logging.
            tool_count: Running tool call count.
            turns_used: Current turn count (overridden from message).
            phase_in_tokens: Running input token count.
            phase_out_tokens: Running output token count.
            thinking: (block count, total chars) of thinking seen this query.
            last_silent: The final assistant turn had no text and no tool use.

        Returns:
            Tuple of (turns_used, session_id, got_result,
            reconciled_in_tokens, reconciled_out_tokens).
        """
        turns_used = getattr(message, "num_turns", 0) or 0
        session_id: str = getattr(message, "session_id", "") or ""

        result_in, result_out = self._extract_tokens(message)

        correction_in = result_in - phase_in_tokens
        correction_out = result_out - phase_out_tokens
        if correction_in or correction_out:
            self._dashboard.add_tokens(correction_in, correction_out)
            logger.info(
                "[%s] token reconciliation: in %+d, out %+d",
                model_label,
                correction_in,
                correction_out,
            )
            phase_in_tokens = result_in
            phase_out_tokens = result_out

        model_usage = getattr(message, "model_usage", None)
        if model_usage and isinstance(model_usage, dict):
            self._dashboard.add_model_usage(model_usage)

        total_phase_tokens = phase_in_tokens + phase_out_tokens
        self._dashboard.log_phase_done(tool_count, turns_used, total_phase_tokens)
        logger.info(
            "Query complete (model=%s): turns=%d, in=%d, out=%d, thinking=%d blocks/%d chars%s",
            model_label,
            turns_used,
            phase_in_tokens,
            phase_out_tokens,
            thinking[0],
            thinking[1],
            f"; ended on a silent turn (stop_reason={message.stop_reason})" if last_silent else "",
        )

        return turns_used, session_id, True, phase_in_tokens, phase_out_tokens

    async def execute_utility(
        self,
        prompt: str,
        allowed_tools: list[str],
        label: str,
        max_turns: int = 5,
    ) -> dict[str, Any] | None:
        """Run a lightweight utility query against the MCP server.

        Used for operations requiring the MCP server's in-process state
        (e.g., ``wait_all`` which polls the ``JobStore``). All other
        utility queries use direct tool invocations instead.

        Args:
            prompt: The prompt to send.
            allowed_tools: Tool names auto-approved for this query.
            label: Human-readable label for logging.
            max_turns: Maximum tool-use turns.

        Returns:
            Parsed JSON dictionary, or None if the query failed.
        """
        utility_model = self._model_config.resolve("utility", "planner")

        options = ClaudeAgentOptions(
            model=utility_model,
            max_turns=max_turns,
            effort=None if self._no_thinking else "low",
            thinking={"type": "disabled"} if self._no_thinking else None,
            stderr=self._stderr_callback(f"utility: {label}"),
            **self._shared_options(allowed_tools, [], utility_model),
        )

        collected_text: list[str] = []
        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            collected_text.append(block.text)
                            category, _ = _classify_fatal_error(block.text)
                            if category == "auth":
                                raise AuthenticationError(
                                    message=block.text,
                                    suggestion=_auth_suggestion(),
                                )
                            if category == "model":
                                alt = _extract_alternative_model(block.text)
                                raise ModelNotAvailableError(
                                    message=block.text,
                                    model="",
                                    alternative=alt,
                                )
                elif isinstance(message, ResultMessage):
                    self._track_utility_tokens(message, label)
        except (AuthenticationError, ModelNotAvailableError):
            raise
        except Exception as exc:
            exc_msg = str(exc)
            category, _ = _classify_fatal_error(exc_msg)
            if category == "auth":
                raise AuthenticationError(
                    message=exc_msg,
                    suggestion=_auth_suggestion(),
                ) from exc
            if category == "model":
                alt = _extract_alternative_model(exc_msg)
                raise ModelNotAvailableError(
                    message=exc_msg,
                    model="",
                    alternative=alt,
                ) from exc
            logger.warning("Utility query '%s' failed: %s", label, exc)
            return None

        full_text = "\n".join(collected_text)
        parsed = extract_json_from_text(full_text)
        return parsed if parsed else None

    def _track_utility_tokens(self, result: ResultMessage, label: str) -> None:
        """Extract token usage from a utility query's ResultMessage.

        Args:
            result: The ResultMessage from the utility query.
            label: Human-readable label for log messages.
        """
        tok_in, tok_out = self._extract_tokens(result)

        if tok_in or tok_out:
            self._dashboard.add_tokens(tok_in, tok_out)

        model_usage = getattr(result, "model_usage", None)
        if model_usage and isinstance(model_usage, dict):
            self._dashboard.add_model_usage(model_usage)
