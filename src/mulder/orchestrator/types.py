"""Data structures for inter-agent communication in the orchestrator.

Defines the structured types exchanged between planner, executor, and analyst
agents, plus JSON parsing utilities for extracting structured data from
unstructured agent output.

These types use @dataclass rather than Pydantic BaseModel because they
are internal to the orchestrator and never serialized to the MCP wire
or stored in the database. Pydantic validation overhead is unnecessary
for in-process data transfer between planner, executor, and analyst.

For types that cross the wire or persist to disk, see mulder.models.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Literal

logger = logging.getLogger(__name__)

EffortLevel = Literal["low", "medium", "high", "xhigh", "max"]
"""Effort levels accepted by ``ClaudeAgentOptions``.

Mirrors the SDK's own literal union so the value survives the trip from
``click.Choice`` through :class:`~mulder.orchestrator.runner.Orchestrator` into
the SDK without a type error.
"""

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n\s*```", re.DOTALL)
_JSON_DECODER = json.JSONDecoder()

_PLAN_REQUIRED_KEYS: set[str] = {"tasks"}
_EXECUTOR_REQUIRED_KEYS: set[str] = {"results"}
_FOLLOW_UP_REQUIRED_KEYS: set[str] = {"request"}
_CATALOG_REQUIRED_KEYS: set[str] = {"systems"}
_FOLLOW_UP_REQUEST_VALUE = "additional_plan"


@dataclass
class Plan:
    """Structured execution plan from a planner agent.

    Attributes:
        plan_id: Unique identifier ``{phase}-plan-{case_id}-{short_uuid}``.
        tasks: List of task dicts with keys: tool, args, purpose.
        investigation_questions: Questions the planner wants the analyst to answer.
        expected_sources: Source names the planner expects after execution.
        raw_text: Full planner output for debugging/logging.
        turns_used: SDK turns consumed by the planner session.
    """

    plan_id: str
    tasks: list[dict[str, Any]]
    investigation_questions: list[str]
    expected_sources: list[str]
    raw_text: str
    turns_used: int


@dataclass
class ExecutionResults:
    """Structured results from an executor agent.

    Attributes:
        plan_id: Matches the plan that was executed.
        results: List of result dicts with keys: tool, status, source, error.
        turns_used: SDK turns consumed.
        has_failures: True if any result has status "error".
        messages: Raw text messages from the executor session, used to
            extract batch IDs for the post-executor wait step.
        batch_ids: Batch IDs captured structurally from start_extraction_batch
            tool result blocks during execution.
        tool_calls: Number of extraction tool calls (including batch
            launches) the executor made across its session and any
            continuations; passive control tools such as open_case and
            wait are not counted. Zero means the plan was not executed.
    """

    plan_id: str
    results: list[dict[str, Any]]
    turns_used: int
    has_failures: bool
    messages: list[str] = field(default_factory=list)
    batch_ids: set[str] = field(default_factory=set)
    tool_calls: int = 0


@dataclass
class AnalystResult:
    """Output from an analyst agent.

    Attributes:
        findings_submitted: Count of submit_finding calls detected.
        follow_up_request: Parsed JSON follow-up request, or None if done.
        messages: All text output from the analyst (for gate validation).
        turns_used: SDK turns consumed.
    """

    findings_submitted: int
    follow_up_request: dict[str, Any] | None
    messages: list[str]
    turns_used: int


@dataclass
class PhaseResult:
    """Result from a complete phase (all roles combined).

    Attributes:
        phase_name: Identifier of the completed phase.
        success: Whether the phase and its gate both passed.
        messages: Collected assistant text messages from the phase.
        tool_names: MCP tool short names invoked during the phase,
            captured from ToolUseBlock events. Used by gate validators
            (e.g. report gate checks for ``finalize_report``).
        turns_used: Total tool-use turns consumed.
        session_id: Agent session identifier from the final attempt.
        gate_result: Validation gate outcome, if a gate was evaluated.
        plans_executed: Number of plans executed in this phase.
        follow_ups_used: Number of follow-up iterations used.
        context_exhausted: True if the session ended without a final
            answer and needs a continuation: the provider rejected the
            prompt as too long, or the CLI stopped at ``max_turns``.
        turns_exhausted: True when the reason was the turn limit
            (``ResultMessage.subtype == "error_max_turns"``) rather than
            a context overflow. Implies ``context_exhausted``.
        batch_ids: Batch IDs captured structurally from start_extraction_batch
            tool result blocks during the session.
    """

    phase_name: str
    success: bool = False
    messages: list[str] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    turns_used: int = 0
    session_id: str = ""
    gate_result: Any = None
    plans_executed: int = 0
    follow_ups_used: int = 0
    context_exhausted: bool = False
    turns_exhausted: bool = False
    batch_ids: set[str] = field(default_factory=set)


@dataclass
class InvestigationResult:
    """Aggregate result across all investigation phases.

    Attributes:
        phases: Results from each completed phase.
        total_turns: Sum of turns across all phases.
        success: Whether the full investigation succeeded.
    """

    phases: list[PhaseResult] = field(default_factory=list)
    total_turns: int = 0
    success: bool = False


def extract_json_plan(messages: list[str], allow_empty: bool = False) -> dict[str, Any] | None:
    """Extract a JSON plan/results object from agent messages.

    Searches messages in reverse order for a valid JSON object
    containing the expected keys (at minimum "tasks"). Handles both
    code-fenced and inline JSON. Tasks must be a list of objects, and
    non-empty unless *allow_empty* is set.

    Args:
        messages: List of text messages from an agent session.
        allow_empty: Accept ``{"tasks": []}``. On a follow-up cycle an
            empty plan means "nothing more to run", not a failed plan.

    Returns:
        Parsed dict if a valid plan JSON was found, None otherwise.
    """
    for msg in reversed(messages):
        result = _try_extract_json(msg, _PLAN_REQUIRED_KEYS)
        if result is not None:
            tasks = result.get("tasks")
            if (
                isinstance(tasks, list)
                and (allow_empty or len(tasks) > 0)
                and all(isinstance(task, dict) for task in tasks)
            ):
                return result
    return None


def extract_executor_results(messages: list[str]) -> dict[str, Any] | None:
    """Extract executor results JSON from agent messages.

    Searches messages in reverse order for a valid JSON object
    containing a "results" key with a non-empty list.

    Args:
        messages: List of text messages from an executor session.

    Returns:
        Parsed dict if valid executor results found, None otherwise.
    """
    for msg in reversed(messages):
        result = _try_extract_json(msg, _EXECUTOR_REQUIRED_KEYS)
        if result is not None:
            results = result.get("results")
            if isinstance(results, list) and len(results) > 0:
                return result
    return None


def extract_follow_up_request(messages: list[str]) -> dict[str, Any] | None:
    """Extract a follow-up request JSON from analyst output.

    A valid follow-up must contain a "request" key with value
    "additional_plan" and a non-empty "suggested_tools" list. An
    analyst that emits the request shape while saying it is done (no
    tools named) is not asking for another planner/executor cycle.

    Args:
        messages: List of text messages from an analyst session.

    Returns:
        Parsed follow-up dict if found, None otherwise.
    """
    for msg in reversed(messages):
        result = _try_extract_json(msg, _FOLLOW_UP_REQUIRED_KEYS)
        if result is not None and result.get("request") == _FOLLOW_UP_REQUEST_VALUE:
            tools = result.get("suggested_tools")
            if isinstance(tools, list) and len(tools) > 0:
                return result
    return None


def extract_catalog_result(messages: list[str]) -> dict[str, Any] | None:
    """Extract the structured catalog JSON from catalog agent messages.

    Searches messages in reverse order for a valid JSON object containing
    a "systems" key with a non-empty list. Each entry in "systems" must
    have at least a "name" field.

    Args:
        messages: List of text messages from the catalog agent session.

    Returns:
        Parsed dict with catalog data if valid JSON found, None otherwise.
    """
    for msg in reversed(messages):
        result = _try_extract_json(msg, _CATALOG_REQUIRED_KEYS)
        if result is not None:
            systems = result.get("systems")
            if (
                isinstance(systems, list)
                and len(systems) > 0
                and all(isinstance(s, dict) and s.get("name") for s in systems)
            ):
                return result
    return None


def _try_extract_json(text: str, required_keys: set[str]) -> dict[str, Any] | None:
    """Attempt to extract a JSON object from text.

    Tries code-fenced blocks first, then falls back to finding
    JSON objects directly in the text.

    Args:
        text: Raw text that may contain JSON.
        required_keys: Keys that must be present in the parsed object.

    Returns:
        Parsed dict if valid JSON with required keys found, None otherwise.
    """
    for match in _JSON_FENCE_RE.finditer(text):
        parsed = _safe_parse(match.group(1), required_keys)
        if parsed is not None:
            return parsed

    parsed = _safe_parse(text, required_keys)
    if parsed is not None:
        return parsed

    return None


def extract_json_from_text(text: str) -> dict[str, Any]:
    """Extract and parse a JSON object from free-form text.

    Canonical implementation for extracting JSON from unstructured agent
    output. Tries direct parsing, code-fenced blocks, and brace-delimited
    fallback in order.

    Args:
        text: Raw text that may contain a JSON object.

    Returns:
        Parsed dictionary, or empty dict if no valid JSON is found.
    """
    result = _try_extract_json(text, set())
    if result is not None:
        return result

    logger.warning("Failed to parse JSON from tool response: %s", text[:200])
    return {}


def _safe_parse(text: str, required_keys: set[str]) -> dict[str, Any] | None:
    """Return the largest balanced JSON object in text that has required_keys.

    Tries ``raw_decode`` at every ``{``, so markup before or after the
    object (leaked tool-call tokens, ``<think>`` blocks, prose with braces)
    cannot break the parse the way a first-``{``/last-``}`` slice does.
    Largest wins so a leaked ``{"name": ...}`` tool-call stub loses to the
    real output whichever side of it the stub lands on.

    Args:
        text: Text potentially containing a JSON object.
        required_keys: Keys that must be present for the parse to succeed.

    Returns:
        Parsed dict or None.
    """
    # ponytail: O(n * braces) rescans; fine for transcripts, revisit if a
    # multi-MB message ever shows up here.
    best: dict[str, Any] | None = None
    best_len = -1
    pos = text.find("{")
    while pos != -1:
        try:
            obj, end = _JSON_DECODER.raw_decode(text, pos)
        except ValueError:
            obj, end = None, pos
        if isinstance(obj, dict) and required_keys.issubset(obj) and end - pos > best_len:
            best, best_len = obj, end - pos
        pos = text.find("{", pos + 1)
    return best
