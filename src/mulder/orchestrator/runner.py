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
from pathlib import Path
from typing import Any

from mulder.orchestrator.display import InvestigationDashboard
from mulder.orchestrator.errors import AuthenticationError, ModelNotAvailableError
from mulder.orchestrator.evidence import EvidenceContext, ServerBridge
from mulder.orchestrator.gates import (
    GateResult,
    validate_catalog,
    validate_cross_system,
    validate_extraction,
    validate_narrative,
    validate_report,
)
from mulder.orchestrator.log_tailer import LogTailer
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.phases import (
    ALTERNATIVE_NARRATIVE,
    CATALOG,
    CROSS_SYSTEM,
    EXTRACTION,
    REPORT,
    PhaseConfig,
)
from mulder.orchestrator.proxy import ProxyManager
from mulder.orchestrator.roles import RoleRunner
from mulder.orchestrator.session import SessionExecutor
from mulder.orchestrator.types import (
    EffortLevel,
    InvestigationResult,
    PhaseResult,
    extract_catalog_result,
)
from mulder.patterns import DEFAULT_DB_DIR, DEFAULT_WORKSPACE_DIR

logger = logging.getLogger(__name__)

_RETRY_BUDGET_MULTIPLIER: float = 1.5
_MAX_COMPACTIONS: int = 3


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
        cwd: str | Path = DEFAULT_WORKSPACE_DIR,
        model_config: ModelConfig | None = None,
        effort: EffortLevel = "max",
        env: dict[str, str] | None = None,
        parallel_extractions: int = 3,
        proxy_config: str | None = None,
        case_id: str = "",
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
            case_id: Case identifier used for the database filename and
                referenced by all phases.
        """
        self.evidence_path = evidence_path
        self.cwd = str(cwd)
        self.model_config = model_config or ModelConfig()
        self.effort = effort
        self.env = env or {}
        self._case_id: str = case_id
        if self._case_id:
            self.env["MULDER_CASE_ID"] = self._case_id
        self._last_session_id: str = ""
        self._parallel_extractions = max(1, parallel_extractions)
        self._phase_counter = 0
        self._total_phases = 0
        self._case_briefing: str = ""
        self._proxy_config = proxy_config
        self._proxy: ProxyManager | None = None
        self._using_proxy = False
        self._running = False
        self._active_systems: list[str] = []
        self._cached_catalog_data: dict[str, Any] | None = None
        self.dashboard = InvestigationDashboard()
        self._session = SessionExecutor(
            dashboard=self.dashboard,
            model_config=self.model_config,
            cwd=self.cwd,
            env=self.env,
            effort=self.effort,
            using_proxy=self._using_proxy,
        )
        self._roles = RoleRunner(
            session=self._session,
            dashboard=self.dashboard,
            model_config=self.model_config,
            case_id=self._case_id,
            env=self.env,
            cwd=self.cwd,
        )
        self._evidence = EvidenceContext(evidence_path=evidence_path)
        self._server = ServerBridge(case_id=self._case_id)
        self._log_tailer = LogTailer(
            dashboard=self.dashboard,
            log_path=Path(DEFAULT_DB_DIR).expanduser() / "mulder.log",
        )

    async def run(self) -> InvestigationResult:
        """Execute the full investigation pipeline.

        Runs phases sequentially: catalog, extraction (per system),
        cross-system analysis, alternative narrative, and report.
        Each phase is validated by a quality gate before proceeding.

        Returns:
            InvestigationResult with all phase results and aggregate metrics.
        """
        result = InvestigationResult()
        self._total_phases = 5
        self._phase_counter = 0

        self._start_proxy_if_needed()
        self._running = True
        self._log_tailer.start(is_running=lambda: self._running)
        self.dashboard.start()

        try:
            return await self._run_pipeline(result)
        finally:
            self._running = False
            self.dashboard.stop()
            self._stop_proxy()
            self._server.cleanup()

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
        self._session._using_proxy = True
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
        from mulder.orchestrator.gates import reset_gate_failure_counters

        reset_gate_failure_counters()
        self._case_briefing = self._evidence.load_case_briefing()

        # Phase 1: Catalog evidence (single-mode)
        catalog_result = await self._run_single_phase(
            CATALOG,
            prompt_vars={
                "evidence_path": self.evidence_path,
                "case_id_instruction": (
                    f' Use case_id="{self._case_id}" when calling scan_evidence.'
                ),
            },
        )
        result.phases.append(catalog_result)
        self._accumulate(result, catalog_result)

        if not catalog_result.success:
            logger.error("Catalog phase failed; cannot proceed.")
            return result

        self._last_session_id = catalog_result.session_id

        systems, catalog_data = self._identify_systems_from_catalog(catalog_result)
        if not systems:
            logger.error("No systems identified from catalog output; cannot proceed.")
            return result

        # Phase 2: Extraction (split-mode, rolling worker pool)
        groups = EvidenceContext.group_systems(systems, catalog_data)
        self._total_phases = 5
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

        # Phase 3: Cross-system analysis (split-mode) — skip for single-host cases
        if len(systems) > 1:
            cross_result = await self._run_split_phase(
                CROSS_SYSTEM,
                prompt_vars={
                    "case_briefing": self._case_briefing,
                    "case_id": self._case_id,
                },
            )
            result.phases.append(cross_result)
            self._accumulate(result, cross_result)
        else:
            logger.info(
                "Skipping cross-system phase: only %d system(s) in catalog "
                "(cross-host correlation requires 2+ systems)",
                len(systems),
            )
            self._phase_counter += 1
            self.dashboard.set_phase(
                label="cross_system (skipped: single system)",
                phase_num=self._phase_counter,
                total_phases=self._total_phases,
                model="\u2014",
                max_turns=0,
            )
            self.dashboard.log_info(
                "Skipping cross-system phase (single system; nothing to correlate)"
            )
            skipped_result = PhaseResult(
                phase_name="cross_system",
                success=True,
            )
            result.phases.append(skipped_result)

        # Phase 4: Alternative narrative + audit (split-mode, with consistency preamble)
        consistency_report = self._server.build_consistency_report()
        narrative_vars = {
            "consistency_report": consistency_report or "",
            "case_briefing": self._case_briefing,
            "case_id": self._case_id,
        }
        alt_result = await self._run_split_phase(ALTERNATIVE_NARRATIVE, prompt_vars=narrative_vars)
        result.phases.append(alt_result)
        self._accumulate(result, alt_result)

        # Persist SDK-reported token usage before the report phase so that
        # finalize_report can inject real counts into the rendered report.
        self._write_model_usage()

        # Phase 5: Report (single-mode)
        report_result = await self._run_single_phase(
            REPORT,
            prompt_vars={"case_briefing": self._case_briefing},
        )
        result.phases.append(report_result)
        self._accumulate(result, report_result)

        result.success = all(p.success for p in result.phases)
        # Re-write with final totals (includes report phase overhead).
        self._write_model_usage()
        return result

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
                    self._active_systems.extend(group)
                    self.dashboard.set_extraction_counts(total, done_count, active_count)
                try:
                    evidence_context = self._evidence.build_evidence_context(group[0])
                    if self._case_briefing:
                        evidence_context = self._case_briefing + "\n" + evidence_context
                    phase_result = await self._run_split_phase(
                        EXTRACTION,
                        prompt_vars={
                            "system_name": ", ".join(group),
                            "evidence_path": self.evidence_path,
                            "evidence_context": evidence_context,
                            "case_id": self._case_id,
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
                        for system_name in group:
                            if system_name in self._active_systems:
                                self._active_systems.remove(system_name)
                        self.dashboard.set_extraction_counts(total, done_count, active_count)

        tasks = [_extract_one(group) for group in groups]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, res in enumerate(results):
            if isinstance(res, AuthenticationError | ModelNotAvailableError):
                self.dashboard.log_gate_fail(str(res))
                raise res
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
                self.dashboard.log_info(f"Retry {attempt}/{phase.max_retries}")

            try:
                phase_result = await self._session.execute(
                    system_prompt=phase.single_system_prompt,
                    prompt=prompt,
                    model=model,
                    allowed_tools=phase.single_allowed_tools,
                    disallowed_tools=phase.disallowed_tools,
                    max_turns=phase.single_max_turns,
                    max_budget=budget,
                )
            except (AuthenticationError, ModelNotAvailableError) as exc:
                self.dashboard.log_gate_fail(str(exc))
                raise
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
                continuation = await self._session.execute(
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
                phase_result.tool_names.extend(continuation.tool_names)
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
            if attempt > 0:
                task_label = (prompt_vars or {}).get("system_name", "") or phase.name
                self.dashboard.clear_system_tasks(task_label)

            follow_up_count = 0
            follow_up_context: str = ""
            follow_up_history: list[dict[str, Any]] = []

            while True:
                try:
                    # Step 1: Planner
                    self._update_dashboard_sub_step(phase, "Planning", log_prefix)
                    plan = await self._roles.run_planner(
                        phase, prompt_vars, follow_up_context, log_prefix
                    )

                    if plan is None:
                        combined_result.success = False
                        return combined_result

                    combined_result.plans_executed += 1

                    # Step 2: Executor
                    self._update_dashboard_sub_step(phase, "Executing", log_prefix)
                    task_sys = (prompt_vars or {}).get("system_name", "") or phase.name
                    exec_results = await self._roles.run_executor(
                        phase, plan, log_prefix, task_system=task_sys
                    )

                    # Step 2.5: Wait for all background batches to finish
                    await self._roles.ensure_batches_complete(exec_results, log_prefix)

                    # Step 3: Analyst
                    self._update_dashboard_sub_step(phase, "Analyzing", log_prefix)
                    analyst_out = await self._roles.run_analyst(
                        phase,
                        plan,
                        exec_results,
                        prompt_vars,
                        log_prefix,
                        task_system=task_sys,
                    )
                except (AuthenticationError, ModelNotAvailableError):
                    raise

                combined_result.turns_used += (
                    plan.turns_used + exec_results.turns_used + analyst_out.turns_used
                )
                combined_result.messages.extend(analyst_out.messages)

                # Check for follow-up request
                if analyst_out.follow_up_request and follow_up_count < phase.max_follow_ups:
                    follow_up_count += 1
                    follow_up_history.append(analyst_out.follow_up_request)
                    follow_up_context = json.dumps(
                        {
                            "previous_follow_ups": follow_up_history[:-1],
                            "current_request": analyst_out.follow_up_request,
                        }
                    )
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
            catalog_json = extract_catalog_result(phase_result.messages)
            self._cached_catalog_data = catalog_json
            return validate_catalog(catalog_json or {})

        if phase.name == "extraction":
            summary_result = self._server.get_summary()
            return validate_extraction(summary_result)

        if phase.name == "cross_system":
            summary_result = self._server.get_summary()
            return validate_cross_system(summary_result)

        if phase.name == "alternative_narrative":
            summary_result = self._server.get_summary()
            readiness = self._server.get_readiness()
            if readiness is None and "check_finalize_readiness" in phase_result.tool_names:
                readiness = {"ready_to_finalize": True, "gates": []}
            return validate_narrative(summary_result, readiness)

        if phase.name == "report":
            return validate_report(phase_result.tool_names)

        return None

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
    # System identification delegations (thin wrappers for test compat)
    # ------------------------------------------------------------------

    def _identify_systems_from_catalog(
        self,
        catalog_result: PhaseResult,
    ) -> tuple[list[str], dict[str, Any]]:
        """Delegate system identification to EvidenceContext.

        Passes the cached catalog data from gate validation and clears it
        after use, preserving the original caching optimization.

        Args:
            catalog_result: The completed catalog phase result.

        Returns:
            Tuple of (system name list, full catalog JSON dict).
        """
        cached = self._cached_catalog_data
        self._cached_catalog_data = None
        return self._evidence.identify_systems(catalog_result, cached)

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
