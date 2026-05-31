"""Multi-pass investigation orchestrator using the Claude Agent SDK.

Decomposes forensic investigations into programmatic phases with hard
quality gates between them. Split-mode phases use a planner/executor/analyst
pipeline where each role runs in a fresh SDK session. Single-mode phases
(catalog, report) run one agent. The orchestrator retries failed phases
with increased budgets and gap-specific instructions.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from claude_agent_sdk import ClaudeAgentOptions, query
from claude_agent_sdk.types import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
)

from mulder.orchestrator.display import InvestigationDashboard
from mulder.orchestrator.gates import (
    GateResult,
    validate_audit,
    validate_catalog,
    validate_cross_system,
    validate_extraction,
    validate_report,
)
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.phases import (
    ALTERNATIVE_NARRATIVE,
    AUDIT,
    CATALOG,
    CROSS_SYSTEM,
    EXTRACTION,
    REPORT,
    PhaseConfig,
)
from mulder.orchestrator.proxy import ProxyManager
from mulder.orchestrator.types import (
    AnalystResult,
    ExecutionResults,
    InvestigationResult,
    PhaseResult,
    Plan,
    extract_executor_results,
    extract_follow_up_request,
    extract_json_plan,
)

logger = logging.getLogger(__name__)

_RETRY_BUDGET_MULTIPLIER: float = 1.5
_MAX_COMPACTIONS: int = 3

_MAX_SIMPLE_SYSTEMS_PER_SESSION: int = 4
_MAX_BUFFER_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB


class Orchestrator:
    """Runs multi-pass forensic investigations with quality gates.

    The orchestrator executes a fixed sequence of investigation phases,
    validating each phase's output before proceeding. Split-mode phases
    decompose work across planner, executor, and analyst agents. Failed
    phases are retried with increased budgets and targeted remediation
    prompts.
    """

    def __init__(
        self,
        evidence_path: str,
        cwd: str | Path = "/mulder-investigation",
        model_config: ModelConfig | None = None,
        effort: str = "max",
        env: dict[str, str] | None = None,
        parallel_extractions: int = 3,
        proxy_config: str | None = None,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            evidence_path: Filesystem path to the evidence directory.
            cwd: Working directory for agent sessions.
            model_config: Model identifiers for each agent role. Uses
                built-in defaults when not provided.
            effort: Effort level (max, xhigh, high).
            env: Additional environment variables for agent sessions.
            parallel_extractions: Maximum number of extraction sessions
                to run concurrently.
            proxy_config: Optional path to a LiteLLM config YAML for
                custom model routing.
        """
        self.evidence_path = evidence_path
        self.cwd = str(cwd)
        self.model_config = model_config or ModelConfig()
        self.effort = effort
        self.env = env or {}
        self._case_id: str = ""
        self._last_session_id: str = ""
        self._parallel_extractions = max(1, parallel_extractions)
        self._phase_counter = 0
        self._total_phases = 0
        self._proxy_config = proxy_config
        self._proxy: ProxyManager | None = None
        self._using_proxy = False
        self.dashboard = InvestigationDashboard()

    async def run(self) -> InvestigationResult:
        """Execute the full investigation pipeline.

        Runs phases sequentially: catalog, extraction (per system),
        cross-system analysis, alternative narrative, audit, and report.
        Each phase is validated by a quality gate before proceeding.

        Returns:
            InvestigationResult with all phase results and aggregate metrics.
        """
        result = InvestigationResult()
        self._total_phases = 6
        self._phase_counter = 0

        self._start_proxy_if_needed()
        self.dashboard.start()

        try:
            return await self._run_pipeline(result)
        finally:
            self.dashboard.stop()
            self._stop_proxy()

    def _start_proxy_if_needed(self) -> None:
        """Start a LiteLLM proxy if any configured model requires one."""
        if not self.model_config.requires_proxy and not self._proxy_config:
            return

        all_models = [
            self.model_config.planner,
            self.model_config.executor,
            self.model_config.analyst,
        ]
        for overrides in self.model_config.phase_overrides.values():
            all_models.extend(overrides.values())

        from mulder.orchestrator.proxy import is_proxy_model

        proxy_models = sorted({m for m in all_models if is_proxy_model(m)})

        self._proxy = ProxyManager(
            models=proxy_models,
            config_path=self._proxy_config,
        )
        self._proxy.start()
        self._using_proxy = True
        self.env.update(self._proxy.env_overrides)
        logger.info(
            "Proxy active; routing %d model(s) through localhost:%d",
            len(proxy_models),
            self._proxy.port,
        )

    def _stop_proxy(self) -> None:
        """Stop the LiteLLM proxy if one was started."""
        if self._proxy is not None:
            self._proxy.stop()
            self._proxy = None

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    async def _run_pipeline(self, result: InvestigationResult) -> InvestigationResult:
        """Execute the full pipeline within the dashboard context.

        Args:
            result: Accumulator for phase results.

        Returns:
            Completed InvestigationResult.
        """
        # Phase 1: Catalog evidence (single-mode)
        catalog_result = await self._run_single_phase(
            CATALOG,
            prompt_vars={"evidence_path": self.evidence_path},
        )
        result.phases.append(catalog_result)
        self._accumulate(result, catalog_result)

        if not catalog_result.success:
            logger.error("Catalog phase failed; cannot proceed.")
            return result

        self._last_session_id = catalog_result.session_id
        self._case_id = await self._discover_case_id()

        systems = self._identify_systems_from_catalog(catalog_result)

        # Phase 2: Extraction (split-mode, rolling worker pool)
        groups = self._group_systems(systems, catalog_result)
        self._total_phases = 6
        self.dashboard.log_info(
            f"Extraction plan: {len(groups)} session(s) for {len(systems)} systems"
            f" (workers: {self._parallel_extractions})"
        )

        self._phase_counter += 1
        planner_model = self.model_config.resolve(EXTRACTION.name, "planner")
        self.dashboard.set_phase(
            label=f"Phase 2: Extraction (0/{len(groups)} done, 0 active)",
            phase_num=self._phase_counter,
            total_phases=self._total_phases,
            model=planner_model,
            max_turns=EXTRACTION.executor_max_turns,
        )

        await self._run_extraction_pool(groups, result)

        # Phase 3: Cross-system analysis (split-mode)
        cross_result = await self._run_split_phase(CROSS_SYSTEM)
        result.phases.append(cross_result)
        self._accumulate(result, cross_result)

        # Phase 4: Alternative narrative (split-mode)
        alt_result = await self._run_split_phase(ALTERNATIVE_NARRATIVE)
        result.phases.append(alt_result)
        self._accumulate(result, alt_result)

        # Phase 5: Audit (split-mode, with consistency preamble)
        consistency_report = await self._build_consistency_report()
        audit_vars = {"consistency_report": consistency_report or ""}
        audit_result = await self._run_split_phase(AUDIT, prompt_vars=audit_vars)
        result.phases.append(audit_result)
        self._accumulate(result, audit_result)

        # Phase 6: Report (single-mode)
        report_result = await self._run_single_phase(REPORT)
        result.phases.append(report_result)
        self._accumulate(result, report_result)

        result.success = all(p.success for p in result.phases)
        self._write_model_usage()
        return result

    # ------------------------------------------------------------------
    # Evidence context builder
    # ------------------------------------------------------------------

    def _build_evidence_context(self, system_name: str) -> str:
        """Build a pre-populated evidence context string for a system.

        Scans the evidence directory and the extracted directory to locate
        disk images and memory dumps belonging to this system. The result
        is injected into the planner prompt so it can plan without calling
        list_directory.

        Args:
            system_name: Identifier for the target system (e.g. "base-dc").

        Returns:
            Multi-line context string listing discovered file paths, or a
            fallback instruction when no files are found.
        """
        evidence_path = Path(self.evidence_path)
        extracted_dir = Path.home() / ".mulder" / "cases" / "extracted"

        _DISK_EXTENSIONS = frozenset((".e01", ".raw", ".dd", ".img", ".vmdk", ".vhd", ".vhdx"))
        sys_lower = system_name.lower()

        disk_images: list[str] = []
        if evidence_path.is_dir():
            for f in evidence_path.rglob("*"):
                if (
                    f.is_file()
                    and sys_lower in f.name.lower()
                    and f.suffix.lower() in _DISK_EXTENSIONS
                ):
                    disk_images.append(str(f))

        memory_files: list[str] = []
        if extracted_dir.is_dir():
            for subdir in extracted_dir.iterdir():
                if subdir.is_dir() and sys_lower in subdir.name.lower():
                    for f in subdir.iterdir():
                        if f.is_file():
                            memory_files.append(str(f))

        lines: list[str] = [f"System: {system_name}"]
        if disk_images:
            lines.append("Disk images:")
            for p in sorted(disk_images):
                lines.append(f"  {p}")
        if memory_files:
            lines.append("Extracted memory dumps:")
            for p in sorted(memory_files):
                lines.append(f"  {p}")
        if not disk_images and not memory_files:
            lines.append(
                "(No pre-populated paths available. "
                f"Call list_directory on {self.evidence_path} to discover files.)"
            )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Rolling extraction pool
    # ------------------------------------------------------------------

    async def _run_extraction_pool(
        self,
        groups: list[list[str]],
        result: InvestigationResult,
    ) -> None:
        """Run extraction for all systems with a rolling worker pool.

        Submits all groups as tasks immediately. An asyncio.Semaphore
        limits concurrency to ``self._parallel_extractions``. As each
        group finishes, the next waiting group acquires the semaphore
        and starts immediately (no batch boundaries).

        Args:
            groups: System groups to extract, each processed in one session.
            result: Accumulator for phase results (mutated in place).
        """
        semaphore = asyncio.Semaphore(self._parallel_extractions)
        total = len(groups)
        done_count = 0
        active_count = 0
        lock = asyncio.Lock()

        async def _extract_one(group: list[str]) -> PhaseResult:
            nonlocal done_count, active_count
            async with semaphore:
                async with lock:
                    active_count += 1
                    self.dashboard.set_extraction_counts(total, done_count, active_count)
                try:
                    evidence_context = self._build_evidence_context(group[0])
                    phase_result = await self._run_split_phase(
                        EXTRACTION,
                        prompt_vars={
                            "system_name": ", ".join(group),
                            "evidence_path": self.evidence_path,
                            "evidence_context": evidence_context,
                        },
                        skip_phase_header=True,
                    )
                    for system_name in group:
                        self.dashboard.clear_system_tasks(system_name)
                    return phase_result
                finally:
                    async with lock:
                        done_count += 1
                        active_count -= 1
                        self.dashboard.set_extraction_counts(total, done_count, active_count)

        tasks = [_extract_one(group) for group in groups]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, res in enumerate(results):
            if isinstance(res, BaseException):
                system_label = ", ".join(groups[i])
                logger.error("Extraction failed for [%s]: %s", system_label, res)
                self.dashboard.log_gate_fail(f"Extraction error for {system_label}: {res}")
                failed = PhaseResult(phase_name="extraction", success=False)
                result.phases.append(failed)
                self._accumulate(result, failed)
            else:
                result.phases.append(res)
                self._accumulate(result, res)

    # ------------------------------------------------------------------
    # Single-mode phase execution
    # ------------------------------------------------------------------

    async def _run_single_phase(
        self,
        phase: PhaseConfig,
        prompt_vars: dict[str, str] | None = None,
    ) -> PhaseResult:
        """Execute a single-agent phase with retry on gate failure.

        Used for catalog and report phases where a single agent session
        handles the entire task.

        Args:
            phase: Phase configuration with single-mode fields populated.
            prompt_vars: Template variables for the phase prompt.

        Returns:
            PhaseResult from the best attempt.
        """
        effective_vars = dict(prompt_vars or {})

        try:
            prompt = phase.single_prompt_template.format(**effective_vars)
        except KeyError as exc:
            logger.warning(
                "Phase '%s' single template references missing variable %s; "
                "substituting empty string.",
                phase.name,
                exc,
            )
            import string

            for _, fname, _, _ in string.Formatter().parse(phase.single_prompt_template):
                if fname is not None and fname not in effective_vars:
                    effective_vars[fname] = ""
            prompt = phase.single_prompt_template.format(**effective_vars)

        model = self.model_config.resolve(phase.name, phase.single_role)
        budget = phase.single_max_budget_usd
        accumulated_turns = 0
        last_result: PhaseResult | None = None

        self._phase_counter += 1
        self.dashboard.set_phase(
            label=phase.name,
            phase_num=self._phase_counter,
            total_phases=self._total_phases,
            model=model,
            max_turns=phase.single_max_turns,
        )

        for attempt in range(1 + phase.max_retries):
            if attempt > 0:
                budget = budget * _RETRY_BUDGET_MULTIPLIER
                gap_info = ""
                if last_result and last_result.gate_result:
                    gap_info = " Gaps from previous attempt: " + "; ".join(
                        last_result.gate_result.gaps
                    )

                try:
                    retry_prompt = phase.single_prompt_template.format(**effective_vars)
                except KeyError as exc:
                    raise ValueError(
                        f"Phase '{phase.name}' single_prompt_template references "
                        f"variable {exc} but only {sorted(effective_vars)} were provided"
                    ) from exc

                prompt = (
                    f"RETRY (attempt {attempt + 1}/{1 + phase.max_retries}). "
                    f"{retry_prompt}{gap_info}"
                )
                self.dashboard.log_info(
                    f"Retry {attempt}/{phase.max_retries} (budget: ${budget:.2f})"
                )

            phase_result = await self._execute_query(
                system_prompt=phase.single_system_prompt,
                prompt=prompt,
                model=model,
                allowed_tools=phase.single_allowed_tools,
                disallowed_tools=phase.disallowed_tools,
                max_turns=phase.single_max_turns,
                max_budget=budget,
            )
            accumulated_turns += phase_result.turns_used

            # Auto-compaction for context exhaustion
            compaction_count = 0
            while phase_result.context_exhausted and compaction_count < _MAX_COMPACTIONS:
                compaction_count += 1
                self.dashboard.log_info(
                    f"Auto-compacting: restarting with DB state "
                    f"(compaction #{compaction_count}/{_MAX_COMPACTIONS})"
                )
                compact_prompt = self._build_compaction_prompt(phase, effective_vars)
                continuation = await self._execute_query(
                    system_prompt=phase.single_system_prompt,
                    prompt=compact_prompt,
                    model=model,
                    allowed_tools=phase.single_allowed_tools,
                    disallowed_tools=phase.disallowed_tools,
                    max_turns=phase.single_max_turns,
                    max_budget=budget,
                )
                accumulated_turns += continuation.turns_used
                phase_result.messages.extend(continuation.messages)
                phase_result.turns_used = accumulated_turns

            gate = await self._validate_phase(phase, phase_result)
            phase_result.gate_result = gate
            phase_result.turns_used = accumulated_turns

            if gate is None or gate.passed:
                phase_result.success = True
                self.dashboard.log_gate_pass(phase.name, accumulated_turns)
                logger.info(
                    "Phase '%s' completed successfully (turns=%d)",
                    phase.name,
                    accumulated_turns,
                )
                return phase_result

            last_result = phase_result
            self.dashboard.log_gate_fail(f"Gate failed: {'; '.join(gate.gaps)}")

        self.dashboard.log_gate_fail(f"{phase.name} FAILED after {1 + phase.max_retries} attempts")
        if last_result is not None:
            last_result.success = False
            return last_result
        return PhaseResult(phase_name=phase.name, success=False)

    # ------------------------------------------------------------------
    # Split-mode phase execution (planner / executor / analyst)
    # ------------------------------------------------------------------

    async def _run_split_phase(
        self,
        phase: PhaseConfig,
        prompt_vars: dict[str, str] | None = None,
        skip_phase_header: bool = False,
    ) -> PhaseResult:
        """Execute a planner/executor/analyst phase.

        The three roles run in sequence. The analyst may request follow-up
        iterations (up to ``phase.max_follow_ups``). Gate validation runs
        after the analyst completes, and the entire cycle retries on gate
        failure up to ``phase.max_retries`` times.

        Args:
            phase: Phase configuration with split-mode fields populated.
            prompt_vars: Template variables for role prompts.
            skip_phase_header: If True, do not update the dashboard phase
                header. Used when the caller manages headers externally
                (e.g. parallel extraction batches).

        Returns:
            PhaseResult aggregating work from all roles and iterations.
        """
        log_prefix = ""
        if (
            prompt_vars
            and "system_name" in prompt_vars
            and self._parallel_extractions > 1
            and phase.name == "extraction"
        ):
            log_prefix = prompt_vars["system_name"].split(",")[0].strip()

        if not skip_phase_header:
            self._phase_counter += 1
            planner_model = self.model_config.resolve(phase.name, "planner")
            self.dashboard.set_phase(
                label=phase.name,
                phase_num=self._phase_counter,
                total_phases=self._total_phases,
                model=planner_model,
                max_turns=phase.executor_max_turns,
            )

        combined_result = PhaseResult(phase_name=phase.name)

        for attempt in range(1 + phase.max_retries):
            follow_up_count = 0
            follow_up_context: str = ""

            while True:
                # Step 1: Planner
                self._update_dashboard_sub_step(phase, "Planning", log_prefix)
                plan = await self._run_planner(phase, prompt_vars, follow_up_context, log_prefix)

                if plan is None:
                    combined_result.success = False
                    return combined_result

                combined_result.plans_executed += 1

                if plan.tasks:
                    task_label = (prompt_vars or {}).get("system_name", phase.name)
                    tool_names = [str(t.get("tool", "")) for t in plan.tasks if t.get("tool")]
                    if tool_names:
                        self.dashboard.set_tasks(task_label, tool_names)

                # Step 2: Executor
                self._update_dashboard_sub_step(phase, "Executing", log_prefix)
                task_sys = (prompt_vars or {}).get("system_name", "") or phase.name
                exec_results = await self._run_executor(
                    phase, plan, log_prefix, task_system=task_sys
                )

                # Step 3: Analyst
                self._update_dashboard_sub_step(phase, "Analyzing", log_prefix)
                analyst_out = await self._run_analyst(
                    phase, plan, exec_results, prompt_vars, log_prefix
                )

                combined_result.turns_used += (
                    plan.turns_used + exec_results.turns_used + analyst_out.turns_used
                )
                combined_result.messages.extend(analyst_out.messages)

                # Check for follow-up request
                if analyst_out.follow_up_request and follow_up_count < phase.max_follow_ups:
                    follow_up_count += 1
                    follow_up_context = json.dumps(analyst_out.follow_up_request)
                    self.dashboard.log_info(
                        f"Follow-up {follow_up_count}/{phase.max_follow_ups}: "
                        f"{analyst_out.follow_up_request.get('reason', '')}"
                    )
                    continue

                break

            combined_result.follow_ups_used = follow_up_count

            # Gate validation after analyst completes
            gate = await self._validate_phase(phase, combined_result)
            combined_result.gate_result = gate

            if gate is None or gate.passed:
                combined_result.success = True
                self.dashboard.log_gate_pass(phase.name, combined_result.turns_used)
                task_label = (prompt_vars or {}).get("system_name", "") or phase.name
                self.dashboard.clear_system_tasks(task_label)
                logger.info(
                    "Phase '%s' completed successfully (turns=%d, plans=%d, follow_ups=%d)",
                    phase.name,
                    combined_result.turns_used,
                    combined_result.plans_executed,
                    combined_result.follow_ups_used,
                )
                return combined_result

            self.dashboard.log_gate_fail(f"Gate failed: {'; '.join(gate.gaps)}")
            logger.warning(
                "Phase '%s' gate failed (attempt %d): %s",
                phase.name,
                attempt + 1,
                gate.gaps,
            )
            # Reset for retry
            follow_up_context = ""

        self.dashboard.log_gate_fail(f"{phase.name} FAILED after {1 + phase.max_retries} attempts")
        combined_result.success = False
        return combined_result

    # ------------------------------------------------------------------
    # Individual role runners
    # ------------------------------------------------------------------

    async def _run_planner(
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
            Parsed Plan, or None if the planner failed to produce one.
        """
        model = self.model_config.resolve(phase.name, "planner")
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
            # Fill missing vars with empty strings and retry
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

        if follow_up_context:
            prompt += f"\n\nFOLLOW-UP REQUEST:\n{follow_up_context}"

        result = await self._execute_query(
            system_prompt=phase.planner_system_prompt,
            prompt=prompt,
            model=model,
            allowed_tools=phase.planner_allowed_tools,
            disallowed_tools=phase.disallowed_tools,
            max_turns=phase.planner_max_turns,
            max_budget=phase.planner_max_budget_usd,
            log_prefix=log_prefix,
        )

        plan_json = extract_json_plan(result.messages)
        if plan_json is None:
            # Attempt JSON repair via utility model
            plan_json = await self._repair_json(result.messages, phase.name)
        if plan_json is None:
            self.dashboard.log_gate_fail("Planner failed to produce valid plan")
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

    async def _repair_json(
        self,
        messages: list[str],
        phase_name: str,
    ) -> dict[str, Any] | None:
        """Attempt to repair malformed JSON from planner output using utility model.

        Sends the raw planner output to a cheap model with instructions to
        extract and fix the JSON. Returns parsed dict or None if repair fails.

        Args:
            messages: Raw text messages from the planner session.
            phase_name: Phase name for logging.

        Returns:
            Parsed JSON plan dict, or None if repair failed.
        """
        raw_text = "\n".join(messages[-3:])  # last few messages most likely have the plan
        if not raw_text.strip():
            return None

        self.dashboard.log_info("Attempting JSON repair via utility model...")
        logger.info("[%s] Attempting JSON repair on planner output", phase_name)

        repair_prompt = (
            "The following text contains a JSON plan that may have syntax errors, "
            "be wrapped in markdown fences, or have extra text around it. "
            "Extract and fix the JSON so it is valid. Return ONLY the corrected "
            "JSON object with keys: tasks, investigation_questions, expected_sources.\n\n"
            f"TEXT:\n{raw_text}"
        )

        executor_model = self.model_config.resolve(phase_name, "executor")
        repair_result = await self._execute_query(
            system_prompt="You fix malformed JSON. Return only valid JSON, nothing else.",
            prompt=repair_prompt,
            model=executor_model,
            allowed_tools=[],
            disallowed_tools=["Bash", "Shell"],
            max_turns=1,
            max_budget=0.50,
        )

        repaired = extract_json_plan(repair_result.messages)
        if repaired is not None:
            logger.info("[%s] JSON repair succeeded", phase_name)
            self.dashboard.log_info("JSON repair successful")
        else:
            logger.warning("[%s] JSON repair failed", phase_name)
        return repaired

    async def _run_executor(
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
            task_system: When non-empty, forward to ``_execute_query``
                so tool use blocks update the task panel.

        Returns:
            ExecutionResults with tool outputs and status.
        """
        model = self.model_config.resolve(phase.name, "executor")
        plan_text = json.dumps({"tasks": plan.tasks}, indent=2)

        try:
            prompt = phase.executor_prompt_template.format(plan=plan_text)
        except KeyError:
            prompt = plan_text

        result = await self._execute_query(
            system_prompt=phase.executor_system_prompt,
            prompt=prompt,
            model=model,
            allowed_tools=phase.executor_allowed_tools,
            disallowed_tools=phase.disallowed_tools,
            max_turns=phase.executor_max_turns,
            max_budget=phase.executor_max_budget_usd,
            log_prefix=log_prefix,
            task_system=task_system,
        )

        # Handle context exhaustion with compaction restarts
        compaction_count = 0
        total_turns = result.turns_used
        while result.context_exhausted and compaction_count < _MAX_COMPACTIONS:
            compaction_count += 1
            self.dashboard.log_info(
                f"Executor auto-compacting (#{compaction_count}/{_MAX_COMPACTIONS})"
            )
            compact_prompt = (
                "CONTINUATION: The previous executor session exhausted its "
                "context window. All tool results have been saved. Review "
                "progress and continue executing any remaining tasks from "
                "the plan. Do NOT re-run tools that already succeeded."
            )
            continuation = await self._execute_query(
                system_prompt=phase.executor_system_prompt,
                prompt=compact_prompt,
                model=model,
                allowed_tools=phase.executor_allowed_tools,
                disallowed_tools=phase.disallowed_tools,
                max_turns=phase.executor_max_turns,
                max_budget=phase.executor_max_budget_usd,
                log_prefix=log_prefix,
                task_system=task_system,
            )
            total_turns += continuation.turns_used
            result.messages.extend(continuation.messages)
            result.context_exhausted = continuation.context_exhausted

        results_json = extract_executor_results(result.messages)

        # Update task panel with final statuses from executor results
        if task_system and results_json:
            for r in results_json.get("results", []):
                tool_name = str(r.get("tool", ""))
                if not tool_name:
                    continue
                if r.get("status") == "ok":
                    self.dashboard.update_task(task_system, tool_name, "done")
                else:
                    error_msg = str(r.get("error", "")) or None
                    self.dashboard.update_task(task_system, tool_name, "failed", error=error_msg)

        return ExecutionResults(
            plan_id=plan.plan_id,
            results=results_json.get("results", []) if results_json else [],
            turns_used=total_turns,
            has_failures=any(
                r.get("status") == "error" for r in (results_json or {}).get("results", [])
            ),
        )

    async def _run_analyst(
        self,
        phase: PhaseConfig,
        plan: Plan,
        exec_results: ExecutionResults,
        prompt_vars: dict[str, str] | None = None,
        log_prefix: str = "",
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

        Returns:
            AnalystResult with findings count and optional follow-up request.
        """
        model = self.model_config.resolve(phase.name, "analyst")

        context: dict[str, str] = {
            "execution_results": json.dumps(exec_results.results, indent=2),
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

        result = await self._execute_query(
            system_prompt=phase.analyst_system_prompt,
            prompt=prompt,
            model=model,
            allowed_tools=phase.analyst_allowed_tools,
            disallowed_tools=phase.disallowed_tools,
            max_turns=phase.analyst_max_turns,
            max_budget=phase.analyst_max_budget_usd,
            log_prefix=log_prefix,
        )

        # Handle context exhaustion with compaction restarts
        compaction_count = 0
        total_turns = result.turns_used
        while result.context_exhausted and compaction_count < _MAX_COMPACTIONS:
            compaction_count += 1
            self.dashboard.log_info(
                f"Analyst auto-compacting (#{compaction_count}/{_MAX_COMPACTIONS})"
            )
            compact_prompt = (
                "CONTINUATION: The previous analyst session exhausted its "
                "context window. All submitted findings are saved. Review "
                "the investigation summary and continue analysis. Submit "
                "any remaining findings. Do NOT re-submit existing findings."
            )
            continuation = await self._execute_query(
                system_prompt=phase.analyst_system_prompt,
                prompt=compact_prompt,
                model=model,
                allowed_tools=phase.analyst_allowed_tools,
                disallowed_tools=phase.disallowed_tools,
                max_turns=phase.analyst_max_turns,
                max_budget=phase.analyst_max_budget_usd,
                log_prefix=log_prefix,
            )
            total_turns += continuation.turns_used
            result.messages.extend(continuation.messages)
            result.context_exhausted = continuation.context_exhausted

        follow_up = extract_follow_up_request(result.messages)
        findings_count = _count_finding_submissions(result)

        return AnalystResult(
            findings_submitted=findings_count,
            follow_up_request=follow_up,
            messages=result.messages,
            turns_used=total_turns,
        )

    # ------------------------------------------------------------------
    # Low-level SDK query execution
    # ------------------------------------------------------------------

    async def _execute_query(
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

        This is the low-level method that all phase/role runners delegate
        to. It handles prompt augmentation (open_case), message streaming,
        token tracking, and context exhaustion detection.

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
        effective_prompt = prompt
        if self._case_id:
            effective_prompt = (
                f'FIRST: Call open_case with case_id="{self._case_id}" '
                f"to load the active investigation. Then proceed.\n\n{prompt}"
            )

        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            model=model,
            max_turns=max_turns,
            max_budget_usd=max_budget,
            allowed_tools=allowed_tools,
            disallowed_tools=disallowed_tools,
            permission_mode="bypassPermissions",
            cwd=self.cwd,
            effort=self.effort,
            env=self.env,
            stderr=self.dashboard.suppress_stderr,
            max_buffer_size=_MAX_BUFFER_SIZE_BYTES,
        )

        messages: list[str] = []
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
            async for message in query(prompt=effective_prompt, options=options):
                if isinstance(message, AssistantMessage):
                    delta_in, delta_out, delta_tools, ctx_hit = self._process_assistant_message(
                        message,
                        log_prefix,
                        seen_message_ids,
                        messages,
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
        except KeyboardInterrupt:
            raise
        except SystemExit:
            raise
        except Exception as exc:
            exc_msg = str(exc)
            exc_lower = exc_msg.lower()

            if "auth" in exc_lower or "unauthorized" in exc_lower:
                logger.error("Authentication failure: %s", exc_msg)
                raise

            if "maximum" in exc_lower or "prompt is too long" in exc_lower:
                self.dashboard.log_info(f"Context exhausted: {exc_msg}")
                logger.warning("Context exhausted: %s", exc_msg)
                hit_context_limit = True
            elif "error result: success" in exc_lower:
                self.dashboard.log_info("Query completed (SDK reported success as error)")
            else:
                self.dashboard.log_gate_fail(f"Query error: {exc_msg}")
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
            turns_used=turns_used,
            session_id=session_id,
            context_exhausted=hit_context_limit,
        )

    def _process_assistant_message(
        self,
        message: AssistantMessage,
        log_prefix: str,
        seen_message_ids: set[str],
        messages: list[str],
        task_system: str = "",
    ) -> tuple[int, int, int, bool]:
        """Process content blocks from an AssistantMessage.

        Args:
            message: The assistant message to process.
            log_prefix: Prefix for dashboard log lines.
            seen_message_ids: Set of already-processed message IDs (mutated).
            messages: Accumulator for text block content (mutated).
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
            self.dashboard.add_tokens(msg_in, msg_out)

        pfx = f"[{log_prefix}] " if log_prefix else ""
        tool_count = 0
        hit_context = False

        for block in message.content:
            if isinstance(block, TextBlock):
                messages.append(block.text)
                if "prompt is too long" in block.text.lower():
                    hit_context = True
                    self.dashboard.log_info(f"{pfx}Context exhausted (detected in response)")
                else:
                    display_text = block.text.replace("<thinking>", "").replace("</thinking>", "")
                    stripped = display_text.strip()
                    # Summarize raw JSON output from planner/executor
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
                                self.dashboard.log_tool(
                                    f"{pfx}Plan: {len(parsed['tasks'])} tasks ({summary}{extra})"
                                )
                            elif "results" in parsed:
                                results = parsed["results"]
                                ok_count = sum(1 for r in results if r.get("status") == "ok")
                                fail_count = len(results) - ok_count
                                status = f"{ok_count}/{len(results)} ok"
                                if fail_count:
                                    status += f", {fail_count} failed"
                                self.dashboard.log_tool(f"{pfx}Results: {status}")
                            else:
                                self.dashboard.log(f"{pfx}[JSON output]")
                        except (json.JSONDecodeError, TypeError):
                            self.dashboard.log(f"{pfx}[JSON output]")
                        continue
                    if display_text.strip():
                        self.dashboard.log(f"{pfx}{display_text}" if pfx else display_text)
            elif isinstance(block, ToolUseBlock):
                tool_count += 1
                tool_short = block.name.replace("mcp__mulder__", "")
                if tool_short == "submit_finding":
                    tool_input = getattr(block, "input", None) or {}
                    severity = str(tool_input.get("severity", "unknown"))
                    title = str(tool_input.get("title", "Untitled"))
                    self.dashboard.log_finding(severity, f"{pfx}{title}" if pfx else title)
                else:
                    self.dashboard.log_tool(f"{pfx}{tool_short}" if pfx else tool_short)
                if task_system:
                    if tool_short == "start_extraction_batch":
                        tool_input = getattr(block, "input", None) or {}
                        batch_tools = tool_input.get("tasks", [])
                        for bt in batch_tools:
                            batch_tool_name = str(bt.get("tool", ""))
                            if batch_tool_name:
                                self.dashboard.update_task(task_system, batch_tool_name, "running")
                    else:
                        self.dashboard.update_task(task_system, tool_short, "running")

        return delta_in, delta_out, tool_count, hit_context

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

        usage = getattr(message, "usage", None) or {}
        result_in: int = usage.get("input_tokens", 0) or 0
        result_out: int = usage.get("output_tokens", 0) or 0

        if not result_in and not result_out:
            mu = getattr(message, "model_usage", None)
            if mu and isinstance(mu, dict):
                for _mname, mvals in mu.items():
                    if isinstance(mvals, dict):
                        result_in += mvals.get("inputTokens", 0) or 0
                        result_out += mvals.get("outputTokens", 0) or 0

        correction_in = result_in - phase_in_tokens
        correction_out = result_out - phase_out_tokens
        if correction_in or correction_out:
            self.dashboard.add_tokens(correction_in, correction_out)
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
            self.dashboard.add_model_usage(model_usage)

        total_phase_tokens = phase_in_tokens + phase_out_tokens
        self.dashboard.log_phase_done(tool_count, turns_used, total_phase_tokens)
        logger.info(
            "Query complete (model=%s): turns=%d, in=%d, out=%d",
            model_label,
            turns_used,
            phase_in_tokens,
            phase_out_tokens,
        )

        return turns_used, session_id, True, phase_in_tokens, phase_out_tokens

    # ------------------------------------------------------------------
    # Dashboard helpers
    # ------------------------------------------------------------------

    def _update_dashboard_sub_step(
        self,
        phase: PhaseConfig,
        step: str,
        log_prefix: str = "",
    ) -> None:
        """Log a sub-step transition within a split-mode phase.

        Args:
            phase: Current phase.
            step: Sub-step label (Planning, Executing, Analyzing).
            log_prefix: Optional prefix for log lines.
        """
        pfx = f"[{log_prefix}] " if log_prefix else ""
        self.dashboard.log_info(f"{pfx}{phase.name}: {step}")

    # ------------------------------------------------------------------
    # Phase validation gates
    # ------------------------------------------------------------------

    async def _validate_phase(
        self,
        phase: PhaseConfig,
        phase_result: PhaseResult,
    ) -> GateResult | None:
        """Run the appropriate quality gate for a completed phase.

        Args:
            phase: The phase configuration that was just executed.
            phase_result: The result from executing the phase.

        Returns:
            GateResult from the validation, or None if no gate exists.
        """
        if phase.name == "catalog":
            full_text = " ".join(phase_result.messages).lower()
            has_evidence = any(
                kw in full_text
                for kw in (
                    "evidence",
                    "case",
                    "scan_evidence",
                    "classified",
                    "memory dump",
                )
            )
            summary: dict[str, Any] = {"case_id": "pending" if has_evidence else None}
            return validate_catalog(summary)

        if phase.name == "extraction":
            summary_result = await self._get_summary()
            return validate_extraction(summary_result)

        if phase.name == "cross_system":
            summary_result = await self._get_summary()
            return validate_cross_system(summary_result)

        if phase.name == "audit":
            summary_result = await self._get_summary()
            readiness = await self._get_readiness()
            return validate_audit(summary_result, readiness)

        if phase.name == "report":
            msg_dicts = [{"text": m} for m in phase_result.messages]
            return validate_report(msg_dicts)

        return None

    # ------------------------------------------------------------------
    # Utility queries
    # ------------------------------------------------------------------

    async def _get_summary(self) -> dict[str, Any] | None:
        """Retrieve the investigation summary via a lightweight SDK query.

        Returns:
            Parsed dictionary from ``get_investigation_summary``, or None.
        """
        return await self._run_utility_query(
            prompt=self._build_tool_prompt("get_investigation_summary"),
            allowed_tools=[
                "mcp__mulder__get_investigation_summary",
                "mcp__mulder__open_case",
                "mcp__mulder__list_cases",
            ],
            label="get_investigation_summary",
        )

    async def _get_readiness(self) -> dict[str, Any] | None:
        """Retrieve finalize readiness via a lightweight SDK query.

        Returns:
            Parsed dictionary from ``check_finalize_readiness``, or None.
        """
        return await self._run_utility_query(
            prompt=self._build_tool_prompt("check_finalize_readiness"),
            allowed_tools=[
                "mcp__mulder__check_finalize_readiness",
                "mcp__mulder__open_case",
                "mcp__mulder__list_cases",
            ],
            label="check_finalize_readiness",
        )

    def _build_tool_prompt(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> str:
        """Build a utility query prompt for a single MCP tool invocation.

        Args:
            tool_name: The MCP tool to invoke.
            args: Optional arguments to pass to the tool.

        Returns:
            Formatted prompt string.
        """
        args_clause = ""
        if args:
            args_clause = f" with arguments {json.dumps(args)}"

        if self._case_id:
            return (
                f'Call open_case with case_id="{self._case_id}", '
                f"then call {tool_name}{args_clause} and return only its "
                f"raw JSON output. Do not add any commentary."
            )
        return (
            f"Call {tool_name}{args_clause} and return only its raw JSON "
            f"output. Do not add any commentary."
        )

    async def _run_utility_query(
        self,
        prompt: str,
        allowed_tools: list[str],
        label: str,
        max_turns: int = 5,
        budget: float = 1.50,
    ) -> dict[str, Any] | None:
        """Run a lightweight utility query against the MCP server.

        Uses the planner model at low effort for fast, cheap queries.

        Args:
            prompt: The prompt to send.
            allowed_tools: Tool names auto-approved for this query.
            label: Human-readable label for logging.
            max_turns: Maximum tool-use turns.
            budget: Spending cap in USD.

        Returns:
            Parsed JSON dictionary, or None if the query failed.
        """
        utility_model = self.model_config.resolve("utility", "planner")

        options = ClaudeAgentOptions(
            model=utility_model,
            max_turns=max_turns,
            max_budget_usd=budget,
            allowed_tools=allowed_tools,
            permission_mode="bypassPermissions",
            cwd=self.cwd,
            effort="low",
            env=self.env,
            stderr=self.dashboard.suppress_stderr,
        )

        collected_text: list[str] = []
        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            collected_text.append(block.text)
                elif isinstance(message, ResultMessage):
                    self._track_utility_tokens(message, label)
        except Exception as exc:
            logger.warning("Utility query '%s' failed: %s", label, exc)
            return None

        full_text = "\n".join(collected_text)
        parsed = _parse_json_from_text(full_text)
        return parsed if parsed else None

    async def _discover_case_id(self) -> str:
        """Discover the case ID created during the catalog phase.

        Returns:
            The case ID string for use with ``open_case``.
        """
        parsed = await self._run_utility_query(
            prompt=(
                "Call list_cases and return only its raw JSON output. Do not add any commentary."
            ),
            allowed_tools=["mcp__mulder__list_cases"],
            label="list_cases",
            max_turns=3,
            budget=1.0,
        )

        if parsed:
            cases = parsed.get("cases", [])
            if cases and isinstance(cases, list):
                case_id = str(
                    cases[0].get("case_id", "") if isinstance(cases[0], dict) else cases[0]
                )
                if case_id:
                    logger.info("Discovered case_id: %s", case_id)
                    return case_id

        fallback = Path(self.evidence_path).name
        logger.warning("Could not discover case_id, using fallback: %s", fallback)
        return fallback

    def _track_utility_tokens(self, result: ResultMessage, label: str) -> None:
        """Extract token usage from a utility query's ResultMessage.

        Args:
            result: The ResultMessage from the utility query.
            label: Human-readable label for log messages.
        """
        usage = getattr(result, "usage", None) or {}
        tok_in: int = usage.get("input_tokens", 0) or 0
        tok_out: int = usage.get("output_tokens", 0) or 0

        if not tok_in and not tok_out:
            mu = getattr(result, "model_usage", None)
            if mu and isinstance(mu, dict):
                for _mname, mvals in mu.items():
                    if isinstance(mvals, dict):
                        tok_in += mvals.get("inputTokens", 0) or 0
                        tok_out += mvals.get("outputTokens", 0) or 0

        if tok_in or tok_out:
            self.dashboard.add_tokens(tok_in, tok_out)

        model_usage = getattr(result, "model_usage", None)
        if model_usage and isinstance(model_usage, dict):
            self.dashboard.add_model_usage(model_usage)

    # ------------------------------------------------------------------
    # Consistency report for audit phase
    # ------------------------------------------------------------------

    async def _build_consistency_report(self) -> str:
        """Build a consistency report identifying dedup clusters.

        Queries all findings, extracts IOCs using regex, groups findings
        by shared IOCs, and returns a formatted report.

        Returns:
            Formatted string for the audit planner prompt, or empty string.
        """
        findings_data = await self._run_utility_query(
            prompt=self._build_tool_prompt("get_findings"),
            allowed_tools=[
                "mcp__mulder__get_findings",
                "mcp__mulder__open_case",
                "mcp__mulder__list_cases",
            ],
            label="get_findings",
        )
        if findings_data is None:
            return ""

        findings_list = findings_data.get("findings", [])
        if not findings_list or not isinstance(findings_list, list):
            return ""

        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        path_re = re.compile(
            r"(?:[A-Z]:\\[^\s,\"']+|"
            r"/(?:usr|var|etc|home|tmp|opt|root|proc|sys|run|mnt|media)[^\s,\"']+)"
        )
        proc_re = re.compile(
            r"\b(\w+\.exe|"
            r"(?:sshd|cron|bash|sh|python[23]?|perl|ruby|java|node|nginx|"
            r"apache2?|httpd|mysqld|postgres|systemd|init|kworker|"
            r"iptables|netcat|nc|ncat|wget|curl|chmod|chown|dd|"
            r"rsync|ssh|scp|sftp|su|sudo))\b",
            re.IGNORECASE,
        )
        hash_re = re.compile(r"\b[a-f0-9]{32,64}\b")
        domain_re = re.compile(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"(?:com|net|org|io|info|biz|xyz|top|ru|cn|uk|de|fr|"
            r"onion|local)\b",
            re.IGNORECASE,
        )

        ioc_to_findings: dict[str, list[str]] = {}

        for f in findings_list:
            if not isinstance(f, dict):
                continue
            fid = f.get("finding_id", "")
            text = f"{f.get('title', '')} {f.get('description', '')}"

            iocs: set[str] = set()
            for ip in ip_re.findall(text):
                if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                    iocs.add(f"ip:{ip}")
            for path in path_re.findall(text):
                iocs.add(f"path:{path[:60]}")
            for proc in proc_re.findall(text):
                iocs.add(f"proc:{proc.lower()}")
            for h in hash_re.findall(text):
                iocs.add(f"hash:{h}")
            for domain in domain_re.findall(text):
                iocs.add(f"domain:{domain.lower()}")

            for ioc in iocs:
                if ioc not in ioc_to_findings:
                    ioc_to_findings[ioc] = []
                ioc_to_findings[ioc].append(fid)

        clusters: list[str] = []
        seen_clusters: set[frozenset[str]] = set()
        for ioc, fids in sorted(ioc_to_findings.items()):
            if len(fids) < 2:
                continue
            cluster_key = frozenset(fids)
            if cluster_key in seen_clusters:
                continue
            seen_clusters.add(cluster_key)
            clusters.append(f"  - IOC '{ioc}' shared by: {', '.join(fids)}")

        if not clusters:
            return ""

        report_lines = [
            "CONSISTENCY ANALYSIS (auto-generated):",
            f"Found {len(clusters)} potential dedup clusters:",
        ]
        report_lines.extend(clusters[:30])
        report_lines.append(
            "\nReview these clusters for duplicate findings that should be "
            "consolidated and for contradictions that need resolution."
        )
        return "\n".join(report_lines)

    # ------------------------------------------------------------------
    # Compaction prompt builder
    # ------------------------------------------------------------------

    def _build_compaction_prompt(
        self,
        phase: PhaseConfig,
        prompt_vars: dict[str, str],
    ) -> str:
        """Build a compaction continuation prompt for a single-mode phase.

        Args:
            phase: The phase being compacted.
            prompt_vars: Template variables from the original invocation.

        Returns:
            Continuation prompt string.
        """
        original_task = phase.single_prompt_template
        with contextlib.suppress(KeyError):
            original_task = phase.single_prompt_template.format(**prompt_vars)
        return (
            "CONTINUATION: The previous session exhausted its context window. "
            "All findings and progress have been saved to the database.\n\n"
            "Recover your state:\n"
            "1. Call get_investigation_summary to review overall progress\n"
            "2. Review findings and sources already collected\n\n"
            f"Original task: {original_task}\n\n"
            "Continue where the previous session left off. Do NOT repeat "
            "work that has already been completed."
        )

    # ------------------------------------------------------------------
    # System identification and grouping
    # ------------------------------------------------------------------

    def _identify_systems_from_catalog(
        self,
        catalog_result: PhaseResult,
    ) -> list[str]:
        """Extract system names from the catalog phase output.

        Uses a multi-strategy approach:
        1. Looks for a structured SYSTEMS section.
        2. Falls back to labeled patterns (System:, Device:, Host:).
        3. Final fallback: treats the evidence path as a single system.

        Args:
            catalog_result: The completed catalog phase result.

        Returns:
            List of system identifiers for per-system extraction phases.
        """
        full_text = "\n".join(catalog_result.messages)

        systems = self._parse_structured_systems_section(full_text)
        if systems:
            logger.info(
                "Identified %d systems from structured section: %s",
                len(systems),
                systems,
            )
            return systems

        label_pattern = (
            r"(?:system|device|host|machine|computer|hostname)"
            r"[:\s]+[`*]*([a-zA-Z0-9][\w.\-]+)[`*]*"
        )
        labeled = re.findall(label_pattern, full_text, re.IGNORECASE)

        bold_pattern = r"\*\*([a-zA-Z0-9][\w.\-]+)\*\*"
        tick_pattern = r"`([a-zA-Z0-9][\w.\-]+)`"
        formatted_candidates = re.findall(bold_pattern, full_text) + re.findall(
            tick_pattern, full_text
        )

        _NON_SYSTEM_TOKENS = {
            "e01",
            "7z",
            "raw",
            "mem",
            "vmem",
            "dmp",
            "pcap",
            "pcapng",
            "evtx",
            "true",
            "false",
            "none",
            "null",
            "disk",
            "memory",
            "image",
            "dump",
            "capture",
            "archive",
            "file",
            "directory",
            "system",
            "device",
            "host",
            "evidence",
            "scan_evidence",
            "list_directory",
            "extract_archive",
            "list_sources",
            "get_source_stats",
            "run_parallel",
            "classified",
        }

        seen: set[str] = set()
        systems = []

        for name in labeled:
            lower = name.lower()
            if lower in seen or lower in _NON_SYSTEM_TOKENS:
                continue
            if len(lower) < 2:
                continue
            seen.add(lower)
            systems.append(name)

        if not systems:
            for name in formatted_candidates:
                lower = name.lower()
                if lower in seen or lower in _NON_SYSTEM_TOKENS:
                    continue
                if len(lower) < 3:
                    continue
                has_separator = any(c in lower for c in "-_.")
                has_digit = any(c.isdigit() for c in lower)
                if has_separator or has_digit:
                    seen.add(lower)
                    systems.append(name)

        if systems:
            logger.info(
                "Identified %d systems from catalog text: %s",
                len(systems),
                systems,
            )
            return systems

        fallback = [Path(self.evidence_path).name]
        logger.warning(
            "Could not parse systems from catalog, using fallback: %s",
            fallback,
        )
        return fallback

    @staticmethod
    def _parse_structured_systems_section(text: str) -> list[str]:
        """Parse a structured SYSTEMS section from catalog output.

        Args:
            text: Full catalog assistant output text.

        Returns:
            List of system names, or empty list if no section found.
        """
        pattern = r"#{1,4}\s*SYSTEMS?\s*\n([\s\S]*?)(?=\n#{1,4}\s|\Z)"
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            return []

        section = match.group(1)
        systems: list[str] = []
        seen: set[str] = set()

        for line in section.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            cleaned = re.sub(r"^[-*\d.)\s]+", "", line).strip()
            cleaned = re.sub(r"[`*]", "", cleaned).strip()
            if ":" in cleaned:
                cleaned = cleaned.split(":")[0].strip()
            elif "  " in cleaned:
                cleaned = cleaned.split("  ")[0].strip()

            if cleaned and cleaned.lower() not in seen and len(cleaned) >= 2:
                seen.add(cleaned.lower())
                systems.append(cleaned)

        return systems

    @staticmethod
    def _group_systems(
        systems: list[str],
        catalog_result: PhaseResult,
    ) -> list[list[str]]:
        """Group systems into extraction sessions.

        Systems with rich evidence get individual sessions. Systems with
        simpler evidence are batched together.

        Args:
            systems: Full list of system identifiers.
            catalog_result: Catalog phase result for evidence type hints.

        Returns:
            List of system groups, each group processed in one session.
        """
        full_text = "\n".join(catalog_result.messages).lower()
        rich_systems: list[str] = []
        simple_systems: list[str] = []

        _DISK_INDICATORS = (
            "disk image",
            "disk_image",
            ".e01",
            ".vmdk",
            ".vhd",
            ".raw disk",
            ".dd",
            "filesystem image",
            "partition",
        )
        _MEMORY_INDICATORS = (
            "memory dump",
            "memory_dump",
            ".mem",
            ".vmem",
            ".dmp",
            "ram capture",
            "memory image",
            "physical memory",
        )

        for sys_name in systems:
            sys_lower = sys_name.lower()
            context = _extract_system_context(full_text, sys_lower)

            has_disk = any(ind in context for ind in _DISK_INDICATORS)
            has_memory = any(ind in context for ind in _MEMORY_INDICATORS)

            if has_disk:
                rich_systems.append(sys_name)
            elif has_memory and len(systems) > 3:
                simple_systems.append(sys_name)
            else:
                rich_systems.append(sys_name)

        groups: list[list[str]] = []
        for sys_name in rich_systems:
            groups.append([sys_name])

        for i in range(0, len(simple_systems), _MAX_SIMPLE_SYSTEMS_PER_SESSION):
            groups.append(simple_systems[i : i + _MAX_SIMPLE_SYSTEMS_PER_SESSION])

        if not groups:
            fallback_name = systems[0] if systems else "unknown"
            return [[fallback_name]]
        return groups

    # ------------------------------------------------------------------
    # Model usage persistence
    # ------------------------------------------------------------------

    def _write_model_usage(self) -> None:
        """Write per-model token usage to a JSON sidecar file."""
        model_data = self.dashboard.model_tokens
        if not model_data or not self._case_id:
            return

        db_dir = Path("~/.mulder/cases").expanduser()
        usage_path = db_dir / f"{self._case_id}.model_usage.json"
        try:
            entries = []
            for model_name, counts in sorted(model_data.items()):
                entries.append(
                    {
                        "model": model_name,
                        "input_tokens": counts["input"],
                        "output_tokens": counts["output"],
                    }
                )
            usage_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
            logger.info("Wrote model usage to %s", usage_path)
        except OSError:
            logger.warning("Failed to write model usage file", exc_info=True)

    @staticmethod
    def _accumulate(
        result: InvestigationResult,
        phase_result: PhaseResult,
    ) -> None:
        """Add a phase's turns to the aggregate result.

        Args:
            result: The running investigation result to update.
            phase_result: The phase result to accumulate from.
        """
        result.total_turns += phase_result.turns_used


def _count_finding_submissions(result: PhaseResult) -> int:
    """Count submit_finding tool calls in the phase messages.

    Scans for the characteristic submit_finding confirmation patterns
    in agent text output.

    Args:
        result: PhaseResult whose messages are scanned.

    Returns:
        Number of submit_finding calls detected.
    """
    count = 0
    for msg in result.messages:
        count += msg.lower().count("submit_finding")
    return count


def _extract_system_context(full_text: str, system_name: str) -> str:
    """Extract text surrounding a system name for evidence type detection.

    Args:
        full_text: Lowercased full catalog output text.
        system_name: Lowercased system identifier to search for.

    Returns:
        Concatenated context strings around all occurrences.
    """
    contexts: list[str] = []
    start = 0
    while True:
        idx = full_text.find(system_name, start)
        if idx == -1:
            break
        ctx_start = max(0, idx - 200)
        ctx_end = min(len(full_text), idx + len(system_name) + 200)
        contexts.append(full_text[ctx_start:ctx_end])
        start = idx + len(system_name)

    return " ".join(contexts) if contexts else full_text


def _parse_json_from_text(text: str) -> dict[str, Any]:
    """Extract and parse a JSON object from free-form text.

    Args:
        text: Raw text that may contain a JSON object.

    Returns:
        Parsed dictionary, or empty dict if no valid JSON is found.
    """
    stripped = text.strip()
    try:
        parsed: object = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass

    for marker in ("```json", "```"):
        if marker in stripped:
            start = stripped.index(marker) + len(marker)
            end = stripped.find("```", start)
            if end > start:
                try:
                    parsed = json.loads(stripped[start:end].strip())
                    if isinstance(parsed, dict):
                        return parsed
                except (json.JSONDecodeError, ValueError):
                    pass

    brace_start = stripped.find("{")
    brace_end = stripped.rfind("}")
    if brace_start >= 0 and brace_end > brace_start:
        try:
            parsed = json.loads(stripped[brace_start : brace_end + 1])
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

    logger.warning("Failed to parse JSON from tool response: %s", text[:200])
    return {}
