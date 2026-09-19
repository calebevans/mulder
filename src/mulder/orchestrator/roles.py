"""Planner, executor, and analyst role execution logic.

Runs the three split-mode roles (planner, executor, analyst) within
investigation phases. Handles plan parsing, JSON repair, dynamic
tool allowlists, batch completion waits, and compaction loops for
context-exhausted sessions.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from uuid import uuid4

from mulder.orchestrator.display import InvestigationDashboard
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.phases import PhaseConfig
from mulder.orchestrator.session import SessionExecutor
from mulder.orchestrator.types import (
    AnalystResult,
    ExecutionResults,
    PhaseResult,
    Plan,
    extract_executor_results,
    extract_follow_up_request,
    extract_json_plan,
)

logger = logging.getLogger(__name__)

_BATCH_ID_RE: re.Pattern[str] = re.compile(r"\bbg_[a-f0-9]{8}\b")

_PLANNER_TURN_BUDGET: str = (
    "\n\nTURN BUDGET: This session allows {max_turns} turns. Every tool call "
    "uses one turn and your final JSON plan needs one, so make at most "
    "{max_calls} tool calls. Stop reading as soon as you can write the plan; "
    "a plan built from what you have already read is better than no plan."
)

_PLANNER_OUT_OF_TURNS: str = (
    "OUT OF TURNS: Your previous planning session reached its turn limit "
    "before emitting the plan. Tools are disabled now; do NOT call any "
    "(ignore the instruction to call open_case). Using the case context "
    "above and your notes below, respond with ONLY the JSON plan.\n\n"
    "YOUR NOTES FROM THE PREVIOUS SESSION:\n"
)

_MAX_PLANNER_NOTES_CHARS: int = 20_000

_REPAIR_MAX_CHARS: int = 24_000
"""Cap on planner text sent to the JSON-repair utility model (~6K tokens)."""

_EXECUTOR_CONTROL_TOOLS: frozenset[str] = frozenset(
    {
        "mcp__mulder__open_case",
        "mcp__mulder__list_cases",
        "mcp__mulder__start_extraction_batch",
        "mcp__mulder__check_extraction_status",
        "mcp__mulder__get_completed_results",
        "mcp__mulder__wait",
        "mcp__mulder__wait_all",
        "mcp__mulder__run_parallel",
    }
)

_EXECUTOR_PASSIVE_TOOLS: frozenset[str] = frozenset(
    t.removeprefix("mcp__mulder__")
    for t in _EXECUTOR_CONTROL_TOOLS
    if t not in {"mcp__mulder__start_extraction_batch", "mcp__mulder__run_parallel"}
)
"""Control tools that extract nothing: open the case, poll, wait, fetch.

Batch launches are deliberately not here: ``start_extraction_batch`` and
``run_parallel`` are how the executor runs most of its plan, so a session
consisting of one batch launch plus a wait has done real work.
"""

_EXECUTOR_TOOLS_SECTION: str = (
    "\n\nEXECUTOR TOOLS: the {phase} executor can call exactly these tools; "
    "a task naming any other tool is dropped from the plan:\n{tools}"
)


def executor_tools_section(phase: PhaseConfig) -> str:
    """Render the tools a planner may put in its plan for *phase*.

    Built from the executor role allowlist so the prompt cannot drift from
    what the executor is actually permitted to call. Executor control
    tools (open_case, batch management) are omitted: they are not
    something to plan.

    Args:
        phase: Split-mode phase configuration.

    Returns:
        Prompt suffix listing the plannable tool names, prefix stripped.
    """
    names = sorted(
        t.removeprefix("mcp__mulder__")
        for t in phase.executor_allowed_tools
        if t not in _EXECUTOR_CONTROL_TOOLS
    )
    return _EXECUTOR_TOOLS_SECTION.format(phase=phase.name, tools=", ".join(names))


def _sanitize_for_prompt(text: str, max_len: int = 200) -> str:
    """Strip control characters and cap length for prompt-safe content.

    Args:
        text: Raw text from evidence-derived content.
        max_len: Maximum allowed character length.

    Returns:
        Sanitized string safe for prompt injection.
    """
    if not text:
        return ""
    cleaned = "".join(c for c in text if c.isprintable() or c in ("\n", "\t"))
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "..."
    return cleaned


class RoleRunner:
    """Runs planner, executor, and analyst roles within split-mode phases.

    Encapsulates the role execution logic that was previously inlined in
    the Orchestrator. Each role method builds prompts, calls the session
    executor, and parses structured output. The compaction loop handles
    context exhaustion retries for both executor and analyst roles.

    All SDK query execution is delegated to the ``SessionExecutor``
    instance directly via ``self._session.execute(...)``.
    """

    def __init__(
        self,
        session: SessionExecutor,
        dashboard: InvestigationDashboard,
        model_config: ModelConfig,
        case_id: str,
        env: dict[str, str],
        cwd: str,
        max_compactions: int,
    ) -> None:
        """Initialize the role runner.

        Args:
            session: Session executor for SDK query delegation.
            dashboard: Live dashboard for real-time display.
            model_config: Model identifiers for each agent role.
            case_id: Case identifier for plan IDs and utility queries.
            env: Environment variables for agent sessions.
            cwd: Working directory for agent sessions.
            max_compactions: Continuation sessions allowed per role session
                after context exhaustion.
        """
        self._session = session
        self._dashboard = dashboard
        self._model_config = model_config
        self._case_id = case_id
        self._env = env
        self._cwd = cwd
        self._max_compactions = max_compactions

    async def run_planner(
        self,
        phase: PhaseConfig,
        prompt_vars: dict[str, str] | None = None,
        follow_up_context: str = "",
        log_prefix: str = "",
    ) -> Plan | None:
        """Run the planner and parse its JSON plan output.

        Args:
            phase: Phase configuration with planner fields.
            prompt_vars: Template variables for the planner prompt.
            follow_up_context: Serialized follow-up request from a prior
                analyst iteration, if any.
            log_prefix: Prefix for dashboard log lines.

        Returns:
            Parsed Plan, or None if the planner failed to produce one. With
            *follow_up_context* the Plan may have no tasks, meaning the
            planner found nothing more to run.
        """
        model = self._model_config.resolve(phase.name, "planner")
        effective_vars = dict(prompt_vars or {})

        try:
            prompt = phase.planner_prompt_template.format(**effective_vars)
        except KeyError as exc:
            logger.warning(
                "Phase '%s' planner template references missing variable %s; "
                "substituting empty string. Provided: %s",
                phase.name,
                exc,
                sorted(effective_vars),
            )
            import string

            field_names = [
                fname
                for _, fname, _, _ in string.Formatter().parse(phase.planner_prompt_template)
                if fname is not None
            ]
            for fname in field_names:
                if fname not in effective_vars:
                    effective_vars[fname] = ""
            prompt = phase.planner_prompt_template.format(**effective_vars)

        prompt += executor_tools_section(phase)

        if follow_up_context:
            prompt += f"\n\nFOLLOW-UP REQUEST:\n{follow_up_context}"

        prompt += _PLANNER_TURN_BUDGET.format(
            max_turns=phase.planner_max_turns,
            max_calls=max(phase.planner_max_turns - 1, 1),
        )

        result = await self._session.execute(
            system_prompt=phase.planner_system_prompt,
            prompt=prompt,
            model=model,
            allowed_tools=phase.planner_allowed_tools,
            disallowed_tools=phase.disallowed_tools,
            max_turns=phase.planner_max_turns,
            log_prefix=log_prefix,
        )

        # On a follow-up cycle an empty plan is a valid answer ("nothing
        # more to run"), not malformed output to send through JSON repair.
        plan_json = extract_json_plan(result.messages, allow_empty=bool(follow_up_context))
        if plan_json is None and result.context_exhausted:
            plan_json = await self._request_plan_from_notes(
                phase, prompt, model, result, log_prefix
            )
        if plan_json is None:
            plan_json = await self._repair_json(result.messages, phase.name)
        if plan_json is None:
            self._dashboard.log_gate_fail("Planner failed to produce valid plan")
            logger.warning("Phase '%s' planner did not produce a valid plan", phase.name)
            return None

        return Plan(
            plan_id=f"{phase.name}-plan-{self._case_id}-{uuid4().hex[:8]}",
            tasks=plan_json.get("tasks", []),
            investigation_questions=plan_json.get("investigation_questions", []),
            expected_sources=plan_json.get("expected_sources", []),
            raw_text="\n".join(result.messages),
            turns_used=result.turns_used,
        )

    async def run_executor(
        self,
        phase: PhaseConfig,
        plan: Plan,
        log_prefix: str = "",
        task_system: str = "",
    ) -> ExecutionResults:
        """Run the executor with a structured plan.

        Handles context exhaustion by spawning continuation sessions
        with the remaining tasks.

        Args:
            phase: Phase configuration with executor fields.
            plan: Structured plan from the planner.
            log_prefix: Prefix for dashboard log lines.
            task_system: When non-empty, forward to the session so tool
                use blocks update the task panel.

        Returns:
            ExecutionResults with tool outputs and status.
        """
        model = self._model_config.resolve(phase.name, "executor")
        tasks, dropped = self._executable_tasks(plan, phase.executor_allowed_tools)
        if dropped:
            msg = (
                f"Plan names tools the {phase.name} executor role may not call; "
                f"dropped from the plan: {', '.join(dropped)}"
            )
            logger.warning("[%s] %s", phase.name, msg)
            self._dashboard.log_info(msg)
        plan_text = json.dumps({"tasks": tasks}, indent=2)

        try:
            prompt = phase.executor_prompt_template.format(plan=plan_text, case_id=self._case_id)
        except KeyError:
            prompt = plan_text

        allowed_tools = self._build_dynamic_allowlist(plan, phase.executor_allowed_tools)

        result = await self._session.execute(
            system_prompt=phase.executor_system_prompt,
            prompt=prompt,
            model=model,
            allowed_tools=allowed_tools,
            disallowed_tools=phase.disallowed_tools,
            max_turns=phase.executor_max_turns,
            log_prefix=log_prefix,
            task_system=task_system,
        )

        extra_turns = await self.compaction_loop(
            result=result,
            system_prompt=phase.executor_system_prompt,
            model=model,
            allowed_tools=allowed_tools,
            disallowed_tools=phase.disallowed_tools,
            max_turns=phase.executor_max_turns,
            continuation_prompt=(
                "CONTINUATION: The previous executor session exhausted its "
                "context window. All tool results have been saved. Continue "
                "executing remaining tasks from this plan that have not yet "
                "succeeded.\n\n"
                f"ORIGINAL PLAN:\n{plan_text}\n\n"
                "Do NOT re-run tools that already succeeded."
            ),
            role_label="Executor",
            log_prefix=log_prefix,
            task_system=task_system,
        )
        total_turns = result.turns_used + extra_turns

        results_json = extract_executor_results(result.messages)

        _FAILURE_STATUSES = {"error", "failed"}
        if task_system and results_json:
            for r in results_json.get("results", []):
                tool_name = str(r.get("tool", ""))
                if not tool_name:
                    continue
                if r.get("status") in _FAILURE_STATUSES:
                    error_msg = str(r.get("error", "")) or None
                    self._dashboard.update_task(task_system, tool_name, "failed", error=error_msg)
                else:
                    self._dashboard.update_task(task_system, tool_name, "done")

        return ExecutionResults(
            plan_id=plan.plan_id,
            results=results_json.get("results", []) if results_json else [],
            turns_used=total_turns,
            has_failures=any(
                r.get("status") == "error" for r in (results_json or {}).get("results", [])
            ),
            messages=result.messages,
            batch_ids=result.batch_ids,
            tool_calls=sum(t not in _EXECUTOR_PASSIVE_TOOLS for t in result.tool_names),
        )

    async def run_analyst(
        self,
        phase: PhaseConfig,
        plan: Plan,
        exec_results: ExecutionResults,
        prompt_vars: dict[str, str] | None = None,
        log_prefix: str = "",
        task_system: str = "",
    ) -> AnalystResult:
        """Run the analyst with execution results.

        The analyst interprets results, submits findings, and may request
        follow-up iterations by emitting a structured JSON follow-up.

        Args:
            phase: Phase configuration with analyst fields.
            plan: The plan that was executed.
            exec_results: Results from the executor.
            prompt_vars: Additional template variables (e.g. system_name).
            log_prefix: Prefix for dashboard log lines.
            task_system: Task panel system name for tool tracking.

        Returns:
            AnalystResult with findings count and optional follow-up request.
        """
        model = self._model_config.resolve(phase.name, "analyst")

        sanitized_results = [
            {
                "tool": _sanitize_for_prompt(r.get("tool", ""), 100),
                "status": r.get("status", ""),
                "source": _sanitize_for_prompt(r.get("source", ""), 150),
            }
            for r in exec_results.results
        ]

        context: dict[str, str] = {
            "execution_results": json.dumps(sanitized_results),
            "investigation_questions": json.dumps(plan.investigation_questions),
        }
        if prompt_vars:
            context.update(prompt_vars)

        try:
            prompt = phase.analyst_prompt_template.format(**context)
        except KeyError:
            prompt = (
                f"Execution results:\n{context['execution_results']}\n\n"
                f"Investigation questions:\n{context['investigation_questions']}"
            )

        return await self._analyst_session(phase, prompt, model, log_prefix, task_system)

    async def run_remediation(
        self,
        phase: PhaseConfig,
        gaps: list[str],
        log_prefix: str = "",
        task_system: str = "",
    ) -> AnalystResult:
        """Run an analyst-only session that fixes a failed gate's gaps.

        Cheaper than a full planner/executor/analyst cycle: the gate has
        already named what is missing, and every gap it reports is fixable
        with the analyst's own tools (``update_finding``, ``submit_finding``,
        ``submit_narrative``, the audit tools).

        Args:
            phase: Phase configuration with analyst fields.
            gaps: Gap list from the failed ``GateResult``.
            log_prefix: Prefix for dashboard log lines.
            task_system: Task panel system name for tool tracking.

        Returns:
            AnalystResult for the remediation session.
        """
        model = self._model_config.resolve(phase.name, "analyst")
        gap_text = "\n".join(f"- {gap}" for gap in gaps)
        prompt = (
            f"Case ID: {self._case_id}\n"
            f"Call open_case(case_id='{self._case_id}') as your FIRST action.\n\n"
            f"GATE FAILED for phase '{phase.name}':\n{gap_text}\n\n"
            "Fix exactly these gaps and nothing else. For each finding named "
            "above, either set event_time_start via update_finding using a "
            "precise timestamp from evidence you have already examined, or, "
            "if it describes a state rather than a timed event, set its "
            "severity to 'info'; if it records a hypothesis you ruled out, "
            "prefix its title with '[NEGATIVE]'. Do not fabricate timestamps. "
            "Do not re-run extraction and do not submit new findings unless "
            "a gap explicitly asks for one. Call check_finalize_readiness "
            "when done."
        )
        self._dashboard.log_info(f"{phase.name}: Remediating gate gaps (analyst only)")
        logger.info("[%s] Running gate remediation for gaps: %s", phase.name, gaps)
        return await self._analyst_session(phase, prompt, model, log_prefix, task_system)

    async def _analyst_session(
        self,
        phase: PhaseConfig,
        prompt: str,
        model: str,
        log_prefix: str,
        task_system: str,
    ) -> AnalystResult:
        """Run one analyst session plus its continuation loop."""
        result = await self._session.execute(
            system_prompt=phase.analyst_system_prompt,
            prompt=prompt,
            model=model,
            allowed_tools=phase.analyst_allowed_tools,
            disallowed_tools=phase.disallowed_tools,
            max_turns=phase.analyst_max_turns,
            log_prefix=log_prefix,
            task_system=task_system,
        )

        extra_turns = await self.compaction_loop(
            result=result,
            system_prompt=phase.analyst_system_prompt,
            model=model,
            allowed_tools=phase.analyst_allowed_tools,
            disallowed_tools=phase.disallowed_tools,
            max_turns=phase.analyst_max_turns,
            continuation_prompt=(
                "CONTINUATION: The previous analyst session ended before it "
                "finished (context window or turn limit). All submitted "
                "findings are saved. Review the investigation summary and "
                "continue analysis. Submit any remaining findings. Do NOT "
                "re-submit existing findings."
            ),
            role_label="Analyst",
            log_prefix=log_prefix,
        )
        total_turns = result.turns_used + extra_turns

        follow_up = extract_follow_up_request(result.messages)
        findings_count = result.tool_names.count("submit_finding")

        return AnalystResult(
            findings_submitted=findings_count,
            follow_up_request=follow_up,
            messages=result.messages,
            turns_used=total_turns,
        )

    async def ensure_batches_complete(
        self,
        exec_results: ExecutionResults,
        log_prefix: str = "",
    ) -> None:
        """Block until all extraction batches from the executor finish.

        Prefers structurally captured batch IDs from tool_result blocks.
        Falls back to regex scanning executor messages when no structural
        IDs were captured.

        Args:
            exec_results: Results from the executor session.
            log_prefix: Optional prefix for dashboard log lines.
        """
        batch_ids: set[str] = set(exec_results.batch_ids)
        if not batch_ids:
            for msg in exec_results.messages:
                batch_ids.update(_BATCH_ID_RE.findall(msg))

        if not batch_ids:
            return

        ids_list = sorted(batch_ids)
        pfx = f"[{log_prefix}] " if log_prefix else ""
        self._dashboard.log_info(
            f"{pfx}Waiting for {len(ids_list)} extraction batch(es) to complete"
        )

        ids_json = json.dumps(ids_list)
        result = await self._session.execute_utility(
            prompt=(
                f'Call open_case with case_id="{self._case_id}", '
                f"then call wait_all with batch_ids={ids_json}. "
                "Return only its raw JSON output."
            ),
            allowed_tools=[
                "mcp__mulder__wait_all",
                "mcp__mulder__open_case",
                "mcp__mulder__list_cases",
            ],
            label="wait_all_batches",
            max_turns=5,
        )

        if result and result.get("all_done"):
            self._dashboard.log_info(f"{pfx}All extraction batches confirmed complete")
        elif result and result.get("status") == "timeout":
            still = result.get("still_running", [])
            self._dashboard.log_info(
                f"{pfx}Batch wait timed out; {len(still)} batch(es) still running"
            )
        else:
            self._dashboard.log_info(f"{pfx}Batch wait returned; proceeding to analysis")

    async def compaction_loop(
        self,
        result: PhaseResult,
        system_prompt: str,
        model: str,
        allowed_tools: list[str],
        disallowed_tools: list[str],
        max_turns: int,
        continuation_prompt: str,
        role_label: str = "",
        log_prefix: str = "",
        task_system: str = "",
    ) -> int:
        """Run compaction retries when a session exhausts its context window.

        Spawns continuation sessions until context is no longer exhausted
        or ``max_compactions`` is reached. Continuation messages, tool names,
        and batch IDs are merged back into *result* in place.

        Args:
            result: Phase result to extend with continuation data (mutated).
            system_prompt: System prompt for continuation sessions.
            model: Model identifier.
            allowed_tools: Tool whitelist.
            disallowed_tools: Tool blocklist.
            max_turns: Maximum tool-use turns per continuation.
            continuation_prompt: Prompt for the continuation session.
            role_label: Role name for dashboard messages (e.g. "Executor").
            log_prefix: Prefix for SDK query log lines.
            task_system: Task panel system name for tool tracking.

        Returns:
            Additional turns consumed across all compaction attempts.
        """
        compaction_count = 0
        additional_turns = 0
        while result.context_exhausted and compaction_count < self._max_compactions:
            compaction_count += 1
            why = "ran out of turns; continuing" if result.turns_exhausted else "auto-compacting"
            self._dashboard.log_info(
                f"{role_label} {why} (#{compaction_count}/{self._max_compactions})"
            )
            continuation = await self._session.execute(
                system_prompt=system_prompt,
                prompt=continuation_prompt,
                model=model,
                allowed_tools=allowed_tools,
                disallowed_tools=disallowed_tools,
                max_turns=max_turns,
                log_prefix=log_prefix,
                task_system=task_system,
            )
            additional_turns += continuation.turns_used
            result.messages.extend(continuation.messages)
            result.tool_names.extend(continuation.tool_names)
            result.context_exhausted = continuation.context_exhausted
            result.turns_exhausted = continuation.turns_exhausted
            result.batch_ids.update(continuation.batch_ids)
        return additional_turns

    async def _request_plan_from_notes(
        self,
        phase: PhaseConfig,
        prompt: str,
        model: str,
        result: PhaseResult,
        log_prefix: str = "",
    ) -> dict[str, Any] | None:
        """Ask a planner that ran out of turns to emit its plan from its notes.

        A planner that spends every turn on read tools never reaches the
        final JSON message, and JSON repair cannot fix output that does
        not exist. This runs one tool-less, single-turn session with the
        original case prompt plus the planner's own text messages so far.
        The follow-up's messages and turns are merged into *result*.

        Args:
            phase: Phase configuration with planner fields.
            prompt: The user prompt the planner session was given.
            model: Model identifier.
            result: Planner session result (mutated).
            log_prefix: Prefix for dashboard log lines.

        Returns:
            Parsed JSON plan dict, or None if no plan was produced.
        """
        self._dashboard.log_info("Planner hit its turn limit; requesting plan from its notes")
        logger.info("[%s] Planner exhausted turns without a plan; requesting plan", phase.name)
        notes = "\n".join(result.messages)[-_MAX_PLANNER_NOTES_CHARS:]
        follow_up = await self._session.execute(
            system_prompt=phase.planner_system_prompt,
            prompt=f"{prompt}\n\n{_PLANNER_OUT_OF_TURNS}{notes}",
            model=model,
            allowed_tools=[],
            disallowed_tools=[*phase.disallowed_tools, *phase.planner_allowed_tools],
            max_turns=1,
            log_prefix=log_prefix,
        )
        result.messages.extend(follow_up.messages)
        result.tool_names.extend(follow_up.tool_names)
        result.turns_used += follow_up.turns_used
        return extract_json_plan(follow_up.messages)

    async def _repair_json(
        self,
        messages: list[str],
        phase_name: str,
    ) -> dict[str, Any] | None:
        """Attempt to repair malformed JSON from planner output.

        Tries deterministic extraction and task validation first via
        ``extract_json_plan``. Falls back to an LLM utility session
        when deterministic parsing or validation fails.

        Args:
            messages: Raw text messages from the planner session.
            phase_name: Phase name for logging.

        Returns:
            Parsed JSON plan dict, or None if repair failed.
        """
        raw_text = "\n".join(messages[-3:])
        # Nothing brace-shaped means nothing to repair (e.g. the planner ran
        # out of turns mid-investigation); skip the utility call entirely.
        start = raw_text.find("{")
        if start == -1:
            logger.info("[%s] No JSON object in planner output; skipping repair", phase_name)
            return None
        raw_text = raw_text[start : start + _REPAIR_MAX_CHARS]

        deterministic = extract_json_plan([raw_text])
        if deterministic is not None:
            logger.info("[%s] Deterministic JSON extraction succeeded", phase_name)
            self._dashboard.log_info("JSON repair succeeded (deterministic)")
            return deterministic

        self._dashboard.log_info("Attempting JSON repair via utility model...")
        logger.info("[%s] Attempting JSON repair on planner output", phase_name)

        repair_prompt = (
            "The following text contains a JSON plan that may have syntax errors, "
            "be wrapped in markdown fences, or have extra text around it. "
            "It may also contain tool-call markup, special tokens, or reasoning "
            "that is not JSON; ignore all of that. "
            "Extract and fix the JSON so it is valid. Return ONLY the corrected "
            "JSON object with keys: tasks, investigation_questions, expected_sources. "
            "tasks must be a non-empty array of objects with tool, args, and purpose keys, "
            'not strings. If the text contains no plan at all, return {"tasks": []}.\n\n'
            f"TEXT:\n{raw_text}"
        )

        executor_model = self._model_config.resolve(phase_name, "executor")
        repair_result = await self._session.execute(
            system_prompt="You fix malformed JSON. Return only valid JSON, nothing else.",
            prompt=repair_prompt,
            model=executor_model,
            allowed_tools=[],
            disallowed_tools=["Bash", "Shell"],
            max_turns=1,
        )

        repaired = extract_json_plan(repair_result.messages)
        if repaired is not None:
            logger.info("[%s] JSON repair succeeded", phase_name)
            self._dashboard.log_info("JSON repair successful")
        else:
            logger.warning("[%s] JSON repair failed", phase_name)
        return repaired

    @staticmethod
    def _executable_tasks(
        plan: Plan,
        executor_allowed: list[str],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Split plan tasks into those the executor role may run and the rest.

        A task whose tool is off the role allowlist would only ever fail
        with "Tool not available", so it is removed from the plan handed
        to the executor and its tool name reported for logging.

        Args:
            plan: Structured plan from the planner.
            executor_allowed: Full phase-level executor allowlist.

        Returns:
            ``(tasks, dropped)``: executable tasks in plan order, and the
            sorted unique tool names that were dropped.
        """
        allowed_set = frozenset(executor_allowed)
        tasks: list[dict[str, Any]] = []
        dropped: set[str] = set()
        for task in plan.tasks:
            tool = task.get("tool")
            if tool and f"mcp__mulder__{tool}" not in allowed_set:
                dropped.add(str(tool))
            else:
                tasks.append(task)
        return tasks, sorted(dropped)

    @staticmethod
    def _build_dynamic_allowlist(
        plan: Plan,
        fallback_allowed: list[str],
    ) -> list[str]:
        """Restrict executor tools to those referenced in the plan.

        Extracts tool names from the planner's task list and intersects
        them with the role-based allowlist. Falls back to the full phase
        allowlist when the plan contains no recognizable tool references.

        Args:
            plan: Structured plan from the planner.
            fallback_allowed: Full phase-level tool allowlist (role-based).

        Returns:
            Sorted list of MCP tool names for the executor session.
        """
        plan_tools = {f"mcp__mulder__{t['tool']}" for t in plan.tasks if t.get("tool")}
        if not plan_tools:
            return fallback_allowed

        allowed_set = frozenset(fallback_allowed)
        safe_plan_tools = plan_tools & allowed_set
        dynamic = safe_plan_tools | _EXECUTOR_CONTROL_TOOLS
        return sorted(dynamic)
