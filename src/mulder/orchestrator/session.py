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
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions, query
from claude_agent_sdk.types import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
)

from mulder.orchestrator.display import InvestigationDashboard
from mulder.orchestrator.errors import AuthenticationError, ModelNotAvailableError
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.types import EffortLevel, PhaseResult, extract_json_from_text

logger = logging.getLogger(__name__)

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
        """
        self._dashboard = dashboard
        self._model_config = model_config
        self._cwd = cwd
        self._env = env
        self._effort = effort
        self._using_proxy = using_proxy

    async def execute(
        self,
        system_prompt: str,
        prompt: str,
        model: str,
        allowed_tools: list[str],
        disallowed_tools: list[str],
        max_turns: int,
        max_budget: float,
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
            max_budget: Spend cap in USD.
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
            max_budget_usd=max_budget,
            allowed_tools=allowed_tools,
            disallowed_tools=disallowed_tools,
            permission_mode="bypassPermissions",
            cwd=self._cwd,
            effort=self._effort,
            env=self._env,
            stderr=self._dashboard.suppress_stderr,
            max_buffer_size=_MAX_BUFFER_SIZE_BYTES,
        )

        messages: list[str] = []
        collected_tool_names: list[str] = []
        collected_batch_ids: set[str] = set()
        turns_used = 0
        session_id = ""

        logger.info(
            "Starting query (model=%s, max_turns=%d, budget=$%.2f)",
            model,
            max_turns,
            max_budget,
        )

        tool_count = 0
        phase_in_tokens = 0
        phase_out_tokens = 0
        seen_message_ids: set[str] = set()
        got_result = False
        hit_context_limit = False

        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    delta_in, delta_out, delta_tools, ctx_hit = self._process_assistant_message(
                        message,
                        log_prefix,
                        seen_message_ids,
                        messages,
                        tool_names_out=collected_tool_names,
                        task_system=task_system,
                    )
                    phase_in_tokens += delta_in
                    phase_out_tokens += delta_out
                    tool_count += delta_tools
                    if ctx_hit:
                        hit_context_limit = True

                elif isinstance(message, ResultMessage):
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

            if "maximum" in exc_lower or "prompt is too long" in exc_lower:
                self._dashboard.log_info(f"Context exhausted: {exc_msg}")
                logger.warning("Context exhausted: %s", exc_msg)
                hit_context_limit = True
            elif "error result: success" in exc_lower:
                self._dashboard.log_info("Query completed (SDK reported success as error)")
            else:
                self._dashboard.log_gate_fail(f"Query error: {exc_msg}")
                logger.error("Query error: %s", exc_msg)

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
            context_exhausted=hit_context_limit,
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
    ) -> tuple[int, int, int, bool]:
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
            Tuple of (input_token_delta, output_token_delta,
            tool_count_delta, hit_context_limit).
        """
        msg_id = getattr(message, "message_id", None)
        msg_usage = getattr(message, "usage", None) or {}
        msg_in = msg_usage.get("input_tokens", 0) or 0
        msg_out = msg_usage.get("output_tokens", 0) or 0

        is_new_step = msg_id is None or msg_id not in seen_message_ids
        if msg_id is not None:
            seen_message_ids.add(msg_id)

        delta_in = 0
        delta_out = 0
        if is_new_step and (msg_in or msg_out) and not self._using_proxy:
            delta_in = msg_in
            delta_out = msg_out
            self._dashboard.add_tokens(msg_in, msg_out)

        pfx = f"[{log_prefix}] " if log_prefix else ""
        tool_count = 0
        hit_context = False

        for block in message.content:
            if isinstance(block, TextBlock):
                messages.append(block.text)

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

                if "prompt is too long" in block.text.lower():
                    hit_context = True
                    self._dashboard.log_info(f"{pfx}Context exhausted (detected in response)")
                else:
                    display_text = block.text.replace("<thinking>", "").replace("</thinking>", "")
                    stripped = display_text.strip()
                    if stripped.startswith("{") and stripped.endswith("}") and len(stripped) > 100:
                        try:
                            parsed = json.loads(stripped)
                            if "tasks" in parsed:
                                task_names = [t.get("tool", "?") for t in parsed["tasks"][:5]]
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
            elif isinstance(block, ToolUseBlock):
                tool_count += 1
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

        return delta_in, delta_out, tool_count, hit_context

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
    ) -> tuple[int, str, bool, int, int]:
        """Process a ResultMessage and reconcile token counts.

        Args:
            message: The result message from the SDK.
            model_label: Model identifier for logging.
            tool_count: Running tool call count.
            turns_used: Current turn count (overridden from message).
            phase_in_tokens: Running input token count.
            phase_out_tokens: Running output token count.

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
            "Query complete (model=%s): turns=%d, in=%d, out=%d",
            model_label,
            turns_used,
            phase_in_tokens,
            phase_out_tokens,
        )

        return turns_used, session_id, True, phase_in_tokens, phase_out_tokens

    async def execute_utility(
        self,
        prompt: str,
        allowed_tools: list[str],
        label: str,
        max_turns: int = 5,
        budget: float = 1.50,
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
            budget: Spending cap in USD.

        Returns:
            Parsed JSON dictionary, or None if the query failed.
        """
        utility_model = self._model_config.resolve("utility", "planner")

        options = ClaudeAgentOptions(
            model=utility_model,
            max_turns=max_turns,
            max_budget_usd=budget,
            allowed_tools=allowed_tools,
            permission_mode="bypassPermissions",
            cwd=self._cwd,
            effort="low",
            env=self._env,
            stderr=self._dashboard.suppress_stderr,
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
