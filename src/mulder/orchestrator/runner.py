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
import hashlib
import json
import logging
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal

from mulder import __version__
from mulder.adapters import (
    IntakeError,
    IntakeManifest,
    load_intake_manifest,
    prepare_evidence_case,
    verify_intake_source,
)
from mulder.adapters.catalog import evidence_types
from mulder.orchestrator.capabilities import identity_for_phase
from mulder.orchestrator.display import InvestigationDashboard
from mulder.orchestrator.errors import AuthenticationError, ModelNotAvailableError
from mulder.orchestrator.evidence import EvidenceContext, ServerBridge
from mulder.orchestrator.gates import (
    GateCheck,
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
    AUTORUNS_INGEST,
    CATALOG,
    CROSS_SYSTEM,
    EXTRACTION,
    REPORT,
    PhaseConfig,
)
from mulder.orchestrator.proxy import ProxyManager, snapshot_proxy_config
from mulder.orchestrator.roles import RoleRunner
from mulder.orchestrator.session import SessionExecutor
from mulder.orchestrator.types import (
    EffortLevel,
    InvestigationResult,
    PhaseResult,
    extract_catalog_result,
)
from mulder.packs.base import DomainPackActivation
from mulder.patterns import DEFAULT_DB_DIR, DEFAULT_WORKSPACE_DIR
from mulder.review.events import RunEventDraft, RunEventJournal
from mulder.run_state import (
    PROFILES,
    RunCancelled,
    RunHandle,
    RunLedger,
    RunProfile,
    RunStateError,
    digest_value,
    evidence_identity,
)
from mulder.security.provider_policy import (
    OutboundManifest,
    ProviderPolicy,
    ProviderPolicyError,
    preflight_zero_egress,
    zero_egress_environment,
)

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
        db_dir: str | Path = DEFAULT_DB_DIR,
        pack_activation: DomainPackActivation | None = None,
        approval_before_report: bool = False,
        resume_after_approval: bool = False,
        run_event_path: str | Path | None = None,
        run_profile: RunProfile = "full",
        run_id: str | None = None,
        resume_run: bool = False,
        run_state_path: str | Path | None = None,
        prepared_intake: IntakeManifest | None = None,
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
            db_dir: Case sidecar directory for outbound manifest records.
            pack_activation: Preflighted domain-pack workflows to insert after
                extraction. Raw manifests are never loaded by the orchestrator.
            approval_before_report: Persist a state-bound review request and
                stop before the report until an examiner approves it.
            resume_after_approval: Run only the report phase after validating
                a durable approval checkpoint from a prior invocation.
            run_event_path: Optional case audit path used for durable,
                resumable operational events. No event journal is created
                when omitted.
            run_profile: ``quick`` sampled triage or ``full`` evidence-bounded work.
            run_id: Optional caller-selected durable run handle.
            resume_run: Resume the exact persisted handle and evidence identity.
            run_state_path: Optional SQLite run ledger. Enabling it also enables
                phase checkpoints and cooperative cancellation.
            prepared_intake: Content-bound evidence preparation produced by the
                CLI before this orchestrator is constructed.
        """
        self.evidence_path = evidence_path
        self.cwd = str(cwd)
        self.model_config = model_config or ModelConfig()
        self.effort = effort
        self.env = env or {}
        self._case_id: str = case_id
        self._db_dir = Path(db_dir).expanduser().resolve(strict=False)
        self._prepared_intake = prepared_intake
        self._approval_before_report = approval_before_report
        self._resume_after_approval = resume_after_approval
        profile_spec = PROFILES.get(run_profile)
        if profile_spec is None:
            raise RunStateError(f"unsupported run profile: {run_profile!r}")
        if resume_run and run_id is None:
            raise RunStateError("resume_run requires an explicit run_id")
        if run_state_path is not None and (not self._case_id or run_event_path is None):
            raise RunStateError("durable runs require both a safe case_id and run_event_path")
        if resume_run and run_state_path is None:
            raise RunStateError("resume_run requires run_state_path")
        if resume_after_approval and run_state_path is not None and not resume_run:
            raise RunStateError("resume_after_approval requires an explicit durable run resume")
        if self._prepared_intake is not None:
            self._validate_prepared_intake(self._prepared_intake)
        elif run_state_path is not None:
            self._prepared_intake = self._prepare_input()
        self._run_profile = run_profile
        self._run_profile_spec = profile_spec
        self._run_scope_instruction = (
            "RUN SCOPE: QUICK/SAMPLED TRIAGE. Treat every result as partial. "
            "Never state or imply that the evidence, host, time range, or case "
            "received full coverage."
            if run_profile == "quick"
            else "RUN SCOPE: FULL EVIDENCE-BOUNDED WORKFLOW. Do not claim full "
            "coverage unless the durable coverage register affirmatively supports it."
        )
        if self._case_id:
            self.env["MULDER_CASE_ID"] = self._case_id
        self.env["MULDER_RUN_PROFILE"] = run_profile
        self.env["MULDER_DATA_POLICY"] = self.model_config.data_policy.value
        if self.model_config.zero_egress:
            self.env.update(zero_egress_environment())
        self._last_session_id: str = ""
        self._parallel_extractions = max(1, parallel_extractions)
        self._phase_counter = 0
        self._total_phases = 0
        self._case_briefing: str = ""
        self._proxy_config: str | None = None
        self._proxy_config_snapshot: bytes | None = None
        if proxy_config is not None:
            try:
                self._proxy_config, self._proxy_config_snapshot = snapshot_proxy_config(
                    proxy_config
                )
            except (OSError, ValueError) as exc:
                raise RunStateError(f"cannot snapshot proxy configuration: {exc}") from exc
        self._proxy: ProxyManager | None = None
        self._pack_activation = pack_activation
        self._using_proxy = False
        self._running = False
        self._active_systems: list[str] = []
        self._cached_catalog_data: dict[str, Any] | None = None
        self._provider_policy = ProviderPolicy(
            self.model_config.data_policy,
            zero_egress=self.model_config.zero_egress,
            manifest=OutboundManifest(self._db_dir / f"{self._case_id}.outbound.jsonl"),
        )
        self._event_journal = (
            RunEventJournal(Path(run_event_path), self._case_id)
            if run_event_path is not None
            else None
        )
        self._run_ledger: RunLedger | None = None
        self._run_handle: RunHandle | None = None
        self._run_summary_path: Path | None = None
        if run_state_path is not None:
            assert run_event_path is not None
            resolved_run_state = Path(run_state_path).expanduser().resolve(strict=False)
            if resolved_run_state.parent != self._db_dir:
                raise RunStateError("run_state_path must be beside the case database")
            resolved_run_events = Path(run_event_path).expanduser().resolve(strict=False)
            expected_run_events = self._db_dir / f"{self._case_id}.audit.jsonl"
            if resolved_run_events != expected_run_events:
                raise RunStateError("durable checkpoints require the case's standard audit path")
            input_digest = self._resolve_run_input_digest()
            approval_required = approval_before_report or resume_after_approval
            if resume_after_approval:
                from mulder.review.decisions import ReviewWorkflow, ReviewWorkflowError

                try:
                    ReviewWorkflow(self._case_id, self._db_dir).require_approved_state()
                except ReviewWorkflowError as exc:
                    raise RunStateError(
                        f"approved-report resume is not authorized: {exc}"
                    ) from exc
            contract_digest = self._run_contract_digest(
                approval_required=approval_required,
            )
            self._run_ledger = RunLedger(
                self._case_id,
                resolved_run_state,
                resolved_run_events,
            )
            self._run_handle = self._run_ledger.open_run(
                profile=run_profile,
                input_digest=input_digest,
                contract_digest=contract_digest,
                approval_required=approval_required,
                allow_awaiting_review_resume=resume_after_approval,
                run_id=run_id,
                resume=resume_run,
            )
            self.env["MULDER_RUN_ID"] = self._run_handle.run_id
            self.env["MULDER_RUN_GENERATION"] = str(self._run_handle.generation)
            self.env["MULDER_DB_DIR"] = str(self._db_dir)
            self._run_summary_path = self._db_dir / f"{self._case_id}.run.json"
            self._run_ledger.write_summary(
                self._run_handle.run_id,
                self._run_summary_path,
            )
            self._run_ledger.write_summary(
                self._run_handle.run_id,
                self._db_dir / f"{self._case_id}.{self._run_handle.run_id}.run.json",
            )
        self.dashboard = InvestigationDashboard(event_journal=self._event_journal)
        self._session = SessionExecutor(
            dashboard=self.dashboard,
            model_config=self.model_config,
            cwd=self.cwd,
            env=self.env,
            effort=self.effort,
            using_proxy=self._using_proxy,
            provider_policy=self._provider_policy,
            case_id=self._case_id,
        )
        self._roles = RoleRunner(
            session=self._session,
            dashboard=self.dashboard,
            model_config=self.model_config,
            case_id=self._case_id,
            env=self.env,
            cwd=self.cwd,
            budget_multiplier=profile_spec.budget_multiplier,
            scope_instruction=self._run_scope_instruction,
        )
        self._evidence = EvidenceContext(
            evidence_path=evidence_path,
            manifest=self._prepared_intake,
        )
        self._server = ServerBridge(case_id=self._case_id)
        self._log_tailer = LogTailer(
            dashboard=self.dashboard,
            log_path=self._db_dir / "mulder.log",
        )

    @property
    def run_handle(self) -> RunHandle | None:
        """Return the durable job handle when run persistence is enabled."""
        return self._run_handle

    def _resolve_run_input_digest(self) -> str:
        """Prefer a verified intake commitment over a mutable path inventory."""
        if self._prepared_intake is not None:
            return self._prepared_intake.collection_digest
        evidence = Path(self.evidence_path).expanduser().resolve(strict=True)
        intake_path = self._db_dir / f"{self._case_id}.intake.json"
        if not intake_path.exists():
            return evidence_identity(evidence)
        try:
            intake = load_intake_manifest(intake_path)
        except IntakeError as exc:
            raise RunStateError(f"cannot bind run to intake: {exc}") from exc
        if intake.case_id != self._case_id:
            raise RunStateError("intake manifest belongs to a different case")
        intake_source = Path(intake.source_path).expanduser().resolve(strict=False)
        if intake_source != evidence:
            raise RunStateError("evidence path does not match the case's immutable intake source")
        return intake.collection_digest

    def _validate_prepared_intake(self, manifest: IntakeManifest) -> None:
        """Reject a caller-provided preparation for a different case or path."""
        if manifest.case_id != self._case_id:
            raise RunStateError("prepared intake belongs to a different case")
        evidence = Path(self.evidence_path).expanduser().resolve(strict=True)
        source = Path(manifest.source_path).expanduser().resolve(strict=False)
        if source != evidence:
            raise RunStateError("prepared intake belongs to a different evidence path")

    def _prepare_input(self) -> IntakeManifest:
        """Commit and register the CLI-selected evidence without model authority."""
        if not self._case_id:
            raise RunStateError("case_id is required to prepare evidence")
        try:
            manifest = prepare_evidence_case(
                Path(self.evidence_path),
                self._case_id,
                self._db_dir,
            )
        except IntakeError as exc:
            raise RunStateError(f"evidence preparation failed: {exc}") from exc
        self._validate_prepared_intake(manifest)
        return manifest

    def _catalog_snapshot_json(self) -> str:
        """Return the bounded first page handed to the catalog model."""
        return self._evidence.catalog_snapshot_json()

    def _autoruns_artifact_ids(self) -> list[str]:
        """Return exact committed Autoruns inputs for the dedicated ingest seat."""
        manifest = self._prepared_intake
        if manifest is None:
            return []
        return [
            f"{manifest.collection_digest}:{index}"
            for index, entry in enumerate(manifest.entries)
            if "autoruns" in evidence_types(entry)
        ]

    def _run_contract_digest(self, *, approval_required: bool) -> str:
        """Bind every execution-policy input that can change phase semantics."""
        proxy: dict[str, object] | None = None
        if self._proxy_config is not None:
            assert self._proxy_config_snapshot is not None
            proxy = {
                "path": self._proxy_config,
                "sha256": "sha256:" + hashlib.sha256(self._proxy_config_snapshot).hexdigest(),
            }
        packs = (
            self._pack_activation.receipt.model_dump(mode="json")
            if self._pack_activation is not None
            else None
        )
        return digest_value(
            "mulder.run-contract:v1",
            {
                "profile": self._run_profile,
                "models": {
                    "planner": self.model_config.planner,
                    "executor": self.model_config.executor,
                    "analyst": self.model_config.analyst,
                    "phase_overrides": self.model_config.phase_overrides,
                },
                "effort": self.effort,
                "parallel_extractions": self._parallel_extractions,
                "data_policy": self.model_config.data_policy.value,
                "zero_egress": self.model_config.zero_egress,
                "proxy": proxy,
                "packs": packs,
                "approval_required": approval_required,
            },
        )

    def _finish_durable_run(
        self,
        status: Literal["awaiting_review", "completed", "failed", "cancelled"],
    ) -> None:
        """Persist terminal status and refresh the receipt-friendly summary."""
        if self._run_ledger is None or self._run_handle is None:
            return
        self._run_handle = self._run_ledger.finish(
            self._run_handle.run_id,
            status,
            generation=self._run_handle.generation,
        )
        if self._run_summary_path is not None:
            self._run_ledger.write_summary(
                self._run_handle.run_id,
                self._run_summary_path,
            )
            self._run_ledger.write_summary(
                self._run_handle.run_id,
                self._db_dir / f"{self._case_id}.{self._run_handle.run_id}.run.json",
            )

    def _checkpoint_identity(
        self,
        phase: PhaseConfig,
        prompt_vars: dict[str, str] | None,
    ) -> tuple[str, str]:
        """Bind a logical phase step to exact run input and prompt variables."""
        if self._run_handle is None:
            raise RunStateError("checkpoint requested without a durable run")
        input_digest = digest_value(
            "mulder.phase-input:v1",
            {
                "run_input": self._run_handle.input_digest,
                "run_contract": self._run_handle.contract_digest,
                "profile": self._run_profile,
                "phase": phase.name,
                "phase_config": asdict(phase),
                "models": {
                    "planner": self.model_config.resolve(phase.name, "planner"),
                    "executor": self.model_config.resolve(phase.name, "executor"),
                    "analyst": self.model_config.resolve(phase.name, "analyst"),
                },
                "effort": self.effort,
                "parallel_extractions": self._parallel_extractions,
                "data_policy": self.model_config.data_policy.value,
                "zero_egress": self.model_config.zero_egress,
                "approval_required": self._run_handle.approval_required,
                "mulder_version": __version__,
                "prompt_vars": dict(sorted((prompt_vars or {}).items())),
            },
        )
        return f"{phase.name}:{input_digest.removeprefix('sha256:')[:20]}", input_digest

    def _resume_or_begin_checkpoint(
        self,
        phase: PhaseConfig,
        prompt_vars: dict[str, str] | None,
    ) -> tuple[PhaseResult | None, str | None]:
        """Restore an exact successful phase or open a new durable attempt."""
        if self._run_ledger is None or self._run_handle is None:
            return None, None
        step_key, input_digest = self._checkpoint_identity(phase, prompt_vars)
        restored = self._run_ledger.resume_phase(
            self._run_handle.run_id,
            generation=self._run_handle.generation,
            step_key=step_key,
            input_digest=input_digest,
        )
        if restored is not None:
            self.dashboard.log_info(f"Resumed completed checkpoint: {step_key}")
            return restored, None
        attempt_id = self._run_ledger.begin_phase(
            self._run_handle.run_id,
            generation=self._run_handle.generation,
            step_key=step_key,
            phase_name=phase.name,
            input_digest=input_digest,
        )
        return None, attempt_id

    def _complete_checkpoint(self, attempt_id: str | None, result: PhaseResult) -> None:
        """Commit only gate-passing results; failed attempts must be rerun."""
        if attempt_id is None or not result.success or self._run_ledger is None:
            return
        if self._run_handle is None:
            raise RunStateError("checkpoint completion has no durable run handle")
        self._run_ledger.assert_active(
            self._run_handle.run_id,
            generation=self._run_handle.generation,
        )
        self._run_ledger.complete_phase(
            attempt_id,
            result,
            generation=self._run_handle.generation,
        )

    def _scoped_prompt(self, prompt: str) -> str:
        """Make profile limits explicit in every single-agent invocation."""
        return f"{self._run_scope_instruction}\n\n{prompt}"

    async def run(self) -> InvestigationResult:
        """Execute the full investigation pipeline.

        Runs phases sequentially: catalog, extraction (per system),
        cross-system analysis, alternative narrative, and report.
        Each phase is validated by a quality gate before proceeding.

        Returns:
            InvestigationResult with all phase results and aggregate metrics.
        """
        result = InvestigationResult(
            run_id=self._run_handle.run_id if self._run_handle is not None else None,
            profile=self._run_profile,
            coverage_ceiling=self._run_profile_spec.coverage_ceiling,
        )
        pack_phase_count = (
            len(self._pack_activation.workflow_steps) if self._pack_activation else 0
        )
        self._total_phases = 5 + pack_phase_count
        self._phase_counter = 0

        try:
            if self._case_id and self._prepared_intake is None:
                self._prepared_intake = self._prepare_input()
            if self._prepared_intake is not None:
                self._evidence.bind_manifest(self._prepared_intake)
                try:
                    verify_intake_source(self._prepared_intake)
                except IntakeError as exc:
                    raise RunStateError(
                        f"prepared evidence changed before provider startup: {exc}"
                    ) from exc
            self._total_phases = 5 + pack_phase_count + (1 if self._autoruns_artifact_ids() else 0)
            self._preflight_provider_routes()
            self._start_proxy_if_needed()
            self._running = True
            self._log_tailer.start(is_running=lambda: self._running)
            self.dashboard.start()
            if self._event_journal is not None:
                self._event_journal.append(
                    RunEventDraft(
                        kind="investigation_started",
                        total_phases=self._total_phases,
                        message=(
                            f"Investigation run started ({self._run_profile}, "
                            f"{self._run_profile_spec.coverage_ceiling})"
                        ),
                    )
                )
            completed = (
                await self._run_approved_report(result)
                if self._resume_after_approval
                else await self._run_pipeline(result)
            )
            if self._run_ledger is not None and self._run_handle is not None:
                self._run_ledger.assert_active(
                    self._run_handle.run_id,
                    generation=self._run_handle.generation,
                )
        except RunCancelled:
            if self._event_journal is not None:
                self._event_journal.append(
                    RunEventDraft(
                        kind="investigation_finished",
                        total_phases=self._total_phases,
                        turns=result.total_turns,
                        success=False,
                        message="Investigation run cancelled at a safe boundary",
                    )
                )
            with contextlib.suppress(Exception):
                self._finish_durable_run("cancelled")
            raise
        except BaseException:
            if self._event_journal is not None:
                self._event_journal.append(
                    RunEventDraft(
                        kind="investigation_finished",
                        total_phases=self._total_phases,
                        turns=result.total_turns,
                        success=False,
                        message="Investigation run terminated before completion",
                    )
                )
            with contextlib.suppress(Exception):
                self._finish_durable_run("failed")
            raise
        else:
            if self._event_journal is not None:
                self._event_journal.append(
                    RunEventDraft(
                        kind="investigation_finished",
                        total_phases=self._total_phases,
                        turns=completed.total_turns,
                        success=completed.success,
                        message="Investigation run finished",
                    )
                )
            terminal_status: Literal["awaiting_review", "completed", "failed", "cancelled"] = (
                "awaiting_review"
                if completed.review_state == "awaiting_review"
                else "completed"
                if completed.success
                else "failed"
            )
            self._finish_durable_run(terminal_status)
            return completed
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
            config_snapshot=self._proxy_config_snapshot,
            process_env=self.env,
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

    def _preflight_provider_routes(self) -> None:
        """Reject unverifiable airgap routes before starting an adapter."""
        if not self.model_config.zero_egress:
            return
        violations = preflight_zero_egress(
            models=self.model_config.all_models,
            env={**os.environ, **self.env},
            proxy_config=self._proxy_config,
        )
        if violations:
            raise ProviderPolicyError("zero-egress preflight failed: " + "; ".join(violations))

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
                "case_id": self._case_id,
                "catalog_snapshot": self._catalog_snapshot_json(),
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

        autoruns_ids = self._autoruns_artifact_ids()
        if autoruns_ids:
            autoruns_result = await self._run_single_phase(
                AUTORUNS_INGEST,
                prompt_vars={
                    "case_id": self._case_id,
                    "artifact_ids_json": json.dumps(autoruns_ids),
                },
            )
            result.phases.append(autoruns_result)
            self._accumulate(result, autoruns_result)
            if not autoruns_result.success:
                logger.error("Committed Autoruns ingestion failed; cannot proceed.")
                return result

        # Phase 2: Extraction (split-mode, rolling worker pool)
        groups = EvidenceContext.group_systems(systems, catalog_data)
        pack_phase_count = (
            len(self._pack_activation.workflow_steps) if self._pack_activation else 0
        )
        self._total_phases = 5 + pack_phase_count + (1 if autoruns_ids else 0)
        self.dashboard.log_info(
            f"Extraction plan: {len(groups)} session(s) for {len(systems)} systems"
            f" (workers: {self._parallel_extractions})"
        )

        self._phase_counter += 1
        planner_model = self.model_config.resolve(EXTRACTION.name, "planner")
        self.dashboard.set_phase(
            label=f"Extraction (0/{len(groups)} done, 0 active)",
            phase_num=self._phase_counter,
            total_phases=self._total_phases,
            model=planner_model,
            max_turns=EXTRACTION.executor_max_turns,
        )

        await self._run_extraction_pool(groups, result)

        # Domain workflows are supplied by the preflighted pack activation.
        # New packs therefore add phases without modifying this central sequence.
        if self._pack_activation is not None:
            for workflow in self._pack_activation.workflow_steps:
                pack_result = await self._run_split_phase(
                    workflow.phase,
                    prompt_vars={
                        "case_id": self._case_id,
                        "evidence_path": self.evidence_path,
                        "case_briefing": self._case_briefing,
                    },
                )
                result.phases.append(pack_result)
                self._accumulate(result, pack_result)

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

        if self._approval_before_report:
            from mulder.review.decisions import ReviewWorkflow, ReviewWorkflowError

            review_workflow = ReviewWorkflow(self._case_id, self._db_dir)
            status = review_workflow.status()
            if status.state != "approved":
                try:
                    request = review_workflow.request_approval(requested_by="orchestrator")
                except ReviewWorkflowError:
                    # A rejected unchanged snapshot remains rejected; it must
                    # change before a fresh request can be created.
                    result.review_state = review_workflow.status().state
                    result.success = False
                    return result
                result.review_state = "awaiting_review"
                result.approval_request_id = request.request_id
                result.success = False
                return result
            result.review_state = "approved"

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

    async def _run_approved_report(self, result: InvestigationResult) -> InvestigationResult:
        """Resume at report only after validating a persisted exact-state approval."""
        from mulder.review.decisions import ReviewWorkflow

        status = ReviewWorkflow(self._case_id, self._db_dir).require_approved_state()
        result.review_state = status.state
        result.approval_request_id = (
            status.request.request_id if status.request is not None else None
        )
        self._total_phases = 1
        self._case_briefing = self._evidence.load_case_briefing()
        report_result = await self._run_single_phase(
            REPORT,
            prompt_vars={"case_briefing": self._case_briefing},
        )
        result.phases.append(report_result)
        self._accumulate(result, report_result)
        result.success = report_result.success
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
        budget = phase.single_max_budget_usd * self._run_profile_spec.budget_multiplier
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
        restored, checkpoint_attempt = self._resume_or_begin_checkpoint(
            phase,
            effective_vars,
        )
        if restored is not None:
            return restored

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
                    prompt=self._scoped_prompt(prompt),
                    model=model,
                    allowed_tools=phase.single_allowed_tools,
                    disallowed_tools=phase.disallowed_tools,
                    max_turns=phase.single_max_turns,
                    max_budget=budget,
                    identity=identity_for_phase(phase.name, "single"),
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
                    prompt=self._scoped_prompt(compact_prompt),
                    model=model,
                    allowed_tools=phase.single_allowed_tools,
                    disallowed_tools=phase.disallowed_tools,
                    max_turns=phase.single_max_turns,
                    max_budget=budget,
                    identity=identity_for_phase(phase.name, "single"),
                )
                accumulated_turns += continuation.turns_used
                phase_result.messages.extend(continuation.messages)
                phase_result.tool_names.extend(continuation.tool_names)
                phase_result.tool_outcomes.extend(continuation.tool_outcomes)
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
                self._complete_checkpoint(checkpoint_attempt, phase_result)
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

        restored, checkpoint_attempt = self._resume_or_begin_checkpoint(
            phase,
            prompt_vars,
        )
        if restored is not None:
            return restored

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
                    combined_result.tool_names.extend(
                        str(item.get("tool", "")).removeprefix("mcp__mulder__")
                        for item in exec_results.results
                        if item.get("tool")
                    )
                    combined_result.batch_ids.update(exec_results.batch_ids)

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
                self._complete_checkpoint(checkpoint_attempt, combined_result)
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

        if phase.name == "autoruns_ingest":
            invoked = "parse_autoruns" in phase_result.tool_names
            succeeded = ("parse_autoruns", "success") in phase_result.tool_outcomes
            manifest = self._prepared_intake
            expected_source = (
                "autoruns.intake." + manifest.collection_digest.removeprefix("sha256:")
                if manifest is not None
                else ""
            )
            persisted = bool(expected_source) and self._server.has_source_name(expected_source)
            passed = invoked and succeeded and persisted
            if passed:
                detail = "Dedicated ingest produced a persisted Autoruns source"
                gaps: list[str] = []
            elif not invoked:
                detail = "Dedicated ingest tool was not invoked"
                gaps = ["parse_autoruns was not invoked"]
            elif not succeeded:
                detail = "Dedicated ingest tool did not return success"
                gaps = ["parse_autoruns did not successfully verify and ingest every input"]
            else:
                detail = "Dedicated ingest invocation produced no persisted Autoruns source"
                gaps = ["parse_autoruns did not persist a verified Autoruns source"]
            return GateResult(
                passed=passed,
                phase_name=phase.name,
                checks=[
                    GateCheck(
                        name="committed_autoruns_ingested",
                        passed=passed,
                        detail=detail,
                    )
                ],
                gaps=gaps,
            )

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

        if self._pack_activation is not None:
            workflow = self._pack_activation.workflow_for_phase(phase.name)
            if workflow is not None:
                return workflow.validate(phase_result.tool_names)

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

        usage_path = self._db_dir / f"{self._case_id}.model_usage.json"
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

    def _accumulate(
        self,
        result: InvestigationResult,
        phase_result: PhaseResult,
    ) -> None:
        """Add a phase's turns to the aggregate result.

        Args:
            result: The running investigation result to update.
            phase_result: The phase result to accumulate from.
        """
        result.total_turns += phase_result.turns_used
        if self._event_journal is not None:
            self._event_journal.append(
                RunEventDraft(
                    kind="phase_result",
                    phase=phase_result.phase_name,
                    turns=phase_result.turns_used,
                    success=phase_result.success,
                )
            )
