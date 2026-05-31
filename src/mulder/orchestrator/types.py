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
from typing import Any

logger = logging.getLogger(__name__)

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n\s*```", re.DOTALL)

_PLAN_REQUIRED_KEYS: set[str] = {"tasks"}
_EXECUTOR_REQUIRED_KEYS: set[str] = {"results"}
_FOLLOW_UP_REQUIRED_KEYS: set[str] = {"request"}
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
    """

    plan_id: str
    results: list[dict[str, Any]]
    turns_used: int
    has_failures: bool


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
        turns_used: Total tool-use turns consumed.
        session_id: Claude Code session identifier from the final attempt.
        gate_result: Validation gate outcome, if a gate was evaluated.
        plans_executed: Number of plans executed in this phase.
        follow_ups_used: Number of follow-up iterations used.
        context_exhausted: True if the session ended due to context
            window limits (prompt too long or max turns reached).
    """

    phase_name: str
    success: bool = False
    messages: list[str] = field(default_factory=list)
    turns_used: int = 0
    session_id: str = ""
    gate_result: Any = None
    plans_executed: int = 0
    follow_ups_used: int = 0
    context_exhausted: bool = False


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


def extract_json_plan(messages: list[str]) -> dict[str, Any] | None:
    """Extract a JSON plan/results object from agent messages.

    Searches messages in reverse order for a valid JSON object
    containing the expected keys (at minimum "tasks"). Handles both
    code-fenced and inline JSON. Plans with empty tasks are invalid.

    Args:
        messages: List of text messages from an agent session.

    Returns:
        Parsed dict if a valid plan JSON was found, None otherwise.
    """
    for msg in reversed(messages):
        result = _try_extract_json(msg, _PLAN_REQUIRED_KEYS)
        if result is not None:
            tasks = result.get("tasks")
            if isinstance(tasks, list) and len(tasks) > 0:
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
    "additional_plan".

    Args:
        messages: List of text messages from an analyst session.

    Returns:
        Parsed follow-up dict if found, None otherwise.
    """
    for msg in reversed(messages):
        result = _try_extract_json(msg, _FOLLOW_UP_REQUIRED_KEYS)
        if result is not None and result.get("request") == _FOLLOW_UP_REQUEST_VALUE:
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


def _safe_parse(text: str, required_keys: set[str]) -> dict[str, Any] | None:
    """Parse JSON from text, returning None on failure or missing keys.

    Finds the first '{' and last '}' to handle text surrounding JSON.

    Args:
        text: Text potentially containing a JSON object.
        required_keys: Keys that must be present for the parse to succeed.

    Returns:
        Parsed dict or None.
    """
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    candidate = text[start : end + 1]
    try:
        obj = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(obj, dict):
        return None

    if not required_keys.issubset(obj.keys()):
        return None

    return obj
