"""Versioned, machine-readable contracts for offline Mulder benchmarks."""

from __future__ import annotations

from collections import Counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mulder.models import JsonScalar, ToolOutcomeStatus

SCHEMA_VERSION: Literal[1] = 1
METHODOLOGY_VERSION: Literal["1.0"] = "1.0"
SupportedMethodologyVersion = Literal["1.0", "1.1"]

Sha256 = str
VerificationState = Literal[
    "verified", "contradicted", "inconclusive", "unsupported", "unverified"
]
Verdict = Literal["positive", "no_evil_within_coverage", "no_verdict"]
Severity = Literal["informational", "low", "medium", "high", "critical"]
BenchmarkStage = Literal[
    "candidate_filters",
    "verifier",
    "independence_gate",
    "alternative_narrative",
    "blind_reviewer",
]
AblationTarget = Literal[
    "without-candidate-filters",
    "without-verifier",
    "without-independence-gate",
    "without-alternative-narrative",
    "without-blind-reviewer",
]
WorkflowAction = Literal["remove_claim", "set_verification_state", "revise_claim"]

EXECUTABLE_ABLATIONS = frozenset(
    {
        "without-candidate-filters",
        "without-verifier",
        "without-independence-gate",
        "without-alternative-narrative",
        "without-blind-reviewer",
    }
)


def _ground_truth_scalar_key(value: JsonScalar) -> tuple[str, str]:
    """Mirror the scorer's type-sensitive normalization for schema checks."""
    if value is None:
        return ("null", "null")
    if isinstance(value, bool):
        return ("boolean", "true" if value else "false")
    if isinstance(value, int):
        return ("integer", str(value))
    if isinstance(value, float):
        return ("number", repr(value))
    return ("string", value.strip().casefold())


class StrictModel(BaseModel):
    """Base class that rejects silently ignored benchmark fields."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class EvidenceLicense(StrictModel):
    """License and redistribution terms for one benchmark artifact."""

    name: str = Field(min_length=1)
    spdx_id: str | None = Field(default=None, min_length=1)
    url: str | None = Field(default=None, min_length=1)


class EvidenceArtifact(StrictModel):
    """Content-addressed evidence declared by a benchmark case."""

    artifact_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    origin: Literal["synthetic", "real"]
    redistribution: Literal["redistributable", "restricted", "manifest_only"]
    license: EvidenceLicense
    size_bytes: int | None = Field(default=None, ge=0)
    source_url: str | None = Field(default=None, min_length=1)


class CoverageExpectation(StrictModel):
    """Expected applicability and content state for one evidence domain."""

    domain: str = Field(min_length=1)
    applicability: Literal["applicable", "not_applicable"]
    expected_content: Literal["empty", "nonempty", "either", "not_applicable"]
    acceptable_statuses: list[ToolOutcomeStatus] = Field(min_length=1)
    required: bool = True

    @model_validator(mode="after")
    def _check_applicability(self) -> CoverageExpectation:
        if self.applicability == "not_applicable" and self.expected_content != "not_applicable":
            raise ValueError("not_applicable coverage must expect not_applicable content")
        if self.applicability == "applicable" and self.expected_content == "not_applicable":
            raise ValueError("applicable coverage cannot expect not_applicable content")
        if len(set(self.acceptable_statuses)) != len(self.acceptable_statuses):
            raise ValueError("acceptable_statuses must be unique")
        if self.applicability == "not_applicable" and self.acceptable_statuses != [
            ToolOutcomeStatus.NOT_APPLICABLE
        ]:
            raise ValueError("not_applicable coverage must accept only NOT_APPLICABLE")
        if (
            self.applicability == "applicable"
            and ToolOutcomeStatus.NOT_APPLICABLE in self.acceptable_statuses
        ):
            raise ValueError("applicable coverage cannot accept NOT_APPLICABLE")
        return self


class ExpectedClaim(StrictModel):
    """One true atomic proposition in the benchmark answer key."""

    claim_id: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    predicate: str = Field(min_length=1)
    object_value: JsonScalar
    qualifiers: dict[str, JsonScalar] = Field(default_factory=dict)
    severity: Severity | None = None


class ExpectedAnchor(StrictModel):
    """A known evidence locator and the claims it is allowed to support."""

    anchor_id: str = Field(min_length=1)
    artifact_id: str = Field(min_length=1)
    selector: str = Field(min_length=1)
    exact_text_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    supports_claim_ids: list[str] = Field(min_length=1)


class BenchmarkCase(StrictModel):
    """Ground truth and evidence metadata for one benchmark case."""

    case_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    ground_truth_label: Literal["clean", "nonempty"]
    applicability: list[str] = Field(min_length=1)
    expected_verdict: Verdict
    evidence: list[EvidenceArtifact] = Field(min_length=1)
    coverage: list[CoverageExpectation] = Field(min_length=1)
    expected_claims: list[ExpectedClaim] = Field(default_factory=list)
    anchors: list[ExpectedAnchor] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_case_references(self) -> BenchmarkCase:
        artifact_ids = [artifact.artifact_id for artifact in self.evidence]
        if len(set(artifact_ids)) != len(artifact_ids):
            raise ValueError("evidence artifact_id values must be unique within a case")

        claim_ids = [claim.claim_id for claim in self.expected_claims]
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("expected claim_id values must be unique within a case")
        claim_keys = [
            (
                claim.subject.strip().casefold(),
                claim.predicate.strip().casefold(),
                _ground_truth_scalar_key(claim.object_value),
                tuple(
                    sorted(
                        (key.strip().casefold(), _ground_truth_scalar_key(value))
                        for key, value in claim.qualifiers.items()
                    )
                ),
            )
            for claim in self.expected_claims
        ]
        if len(set(claim_keys)) != len(claim_keys):
            raise ValueError("duplicate atomic propositions are not valid ground truth")

        anchor_ids = [anchor.anchor_id for anchor in self.anchors]
        if len(set(anchor_ids)) != len(anchor_ids):
            raise ValueError("anchor_id values must be unique within a case")
        known_artifacts = set(artifact_ids)
        known_claims = set(claim_ids)
        for anchor in self.anchors:
            if anchor.artifact_id not in known_artifacts:
                raise ValueError(f"anchor {anchor.anchor_id!r} references an unknown artifact")
            unknown_claims = set(anchor.supports_claim_ids) - known_claims
            if unknown_claims:
                raise ValueError(
                    f"anchor {anchor.anchor_id!r} references unknown claims: "
                    f"{sorted(unknown_claims)!r}"
                )

        domains = [item.domain for item in self.coverage]
        if len(set(domains)) != len(domains):
            raise ValueError("coverage domains must be unique within a case")
        if len(set(self.applicability)) != len(self.applicability):
            raise ValueError("applicability tags must be unique within a case")

        if self.ground_truth_label == "clean":
            if self.expected_claims:
                raise ValueError("clean cases cannot contain expected claims")
            if self.expected_verdict == "positive":
                raise ValueError("clean cases cannot expect a positive verdict")
        elif not self.expected_claims:
            raise ValueError("nonempty cases require at least one expected claim")
        return self


class BenchmarkManifest(StrictModel):
    """Versioned benchmark definition independent of any agent run."""

    schema_version: Literal[1] = SCHEMA_VERSION
    benchmark_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    methodology_version: SupportedMethodologyVersion = METHODOLOGY_VERSION
    cases: list[BenchmarkCase] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_case_ids(self) -> BenchmarkManifest:
        case_ids = [case.case_id for case in self.cases]
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("case_id values must be unique")
        return self


class ObservedClaim(StrictModel):
    """One atomic proposition emitted by a benchmarked system."""

    claim_id: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    predicate: str = Field(min_length=1)
    object_value: JsonScalar
    qualifiers: dict[str, JsonScalar] = Field(default_factory=dict)
    verification_state: VerificationState
    citations: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)
    severity: Severity | None = None


class ClaimRevision(StrictModel):
    """Auditable before/after assertion revision; correctness is scored externally."""

    revision_id: str = Field(min_length=1)
    claim_id: str = Field(min_length=1)
    iteration: int = Field(ge=1)
    stage: str = Field(min_length=1)
    before: ObservedClaim
    after: ObservedClaim
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_revision(self) -> ClaimRevision:
        if self.before.claim_id != self.claim_id or self.after.claim_id != self.claim_id:
            raise ValueError("revision before/after claim IDs must match claim_id")
        if self.before == self.after:
            raise ValueError("revision must change the claim")
        return self


class ObservedCoverage(StrictModel):
    """Observed outcome for one declared evidence domain."""

    domain: str = Field(min_length=1)
    status: ToolOutcomeStatus


class CaseRunResult(StrictModel):
    """Normalized output for one case in an offline benchmark run."""

    case_id: str = Field(min_length=1)
    verdict: Verdict
    cell_status: Literal["completed", "failed", "no_verdict"] = "completed"
    failure_reason: str | None = Field(default=None, min_length=1)
    claims: list[ObservedClaim] = Field(default_factory=list)
    coverage: list[ObservedCoverage] = Field(default_factory=list)
    revisions: list[ClaimRevision] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_result_ids(self) -> CaseRunResult:
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("observed claim_id values must be unique within a case")
        domains = [item.domain for item in self.coverage]
        if len(set(domains)) != len(domains):
            raise ValueError("observed coverage domains must be unique within a case")
        revision_ids = [revision.revision_id for revision in self.revisions]
        if len(set(revision_ids)) != len(revision_ids):
            raise ValueError("revision_id values must be unique within a case")
        revision_steps = [(revision.claim_id, revision.iteration) for revision in self.revisions]
        if len(set(revision_steps)) != len(revision_steps):
            raise ValueError("claim revision iterations must be unique within a case")
        final_claims = {claim.claim_id: claim for claim in self.claims}
        revisions_by_claim: dict[str, list[ClaimRevision]] = {}
        for revision in self.revisions:
            revisions_by_claim.setdefault(revision.claim_id, []).append(revision)
        for claim_id, revisions in revisions_by_claim.items():
            revisions.sort(key=lambda revision: revision.iteration)
            if [revision.iteration for revision in revisions] != list(
                range(1, len(revisions) + 1)
            ):
                raise ValueError("claim revision iterations must be contiguous from one")
            if any(
                earlier.after != later.before
                for earlier, later in zip(revisions, revisions[1:], strict=False)
            ):
                raise ValueError("claim revision before/after values must form a chain")
            if claim_id not in final_claims or revisions[-1].after != final_claims[claim_id]:
                raise ValueError("the last claim revision must equal the published claim")
        if self.cell_status == "failed":
            if self.failure_reason is None:
                raise ValueError("failed cells require failure_reason")
            if self.verdict != "no_verdict":
                raise ValueError("failed cells must use the no_verdict verdict")
        elif self.failure_reason is not None:
            raise ValueError("failure_reason is valid only for failed cells")
        if self.cell_status == "no_verdict" and self.verdict != "no_verdict":
            raise ValueError("no_verdict cells must use the no_verdict verdict")
        return self


class WorkflowOperation(StrictModel):
    """One typed, replayable benchmark workflow transformation."""

    action: WorkflowAction
    claim_id: str = Field(min_length=1)
    verification_state: VerificationState | None = None
    replacement: ObservedClaim | None = None
    revision_id: str | None = Field(default=None, min_length=1)
    iteration: int | None = Field(default=None, ge=1)
    reason: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _check_payload(self) -> WorkflowOperation:
        if self.action == "remove_claim":
            if any(
                value is not None
                for value in (
                    self.verification_state,
                    self.replacement,
                    self.revision_id,
                    self.iteration,
                    self.reason,
                )
            ):
                raise ValueError("remove_claim does not accept an operation payload")
        elif self.action == "set_verification_state":
            if self.verification_state is None:
                raise ValueError("set_verification_state requires verification_state")
            if any(
                value is not None
                for value in (self.replacement, self.revision_id, self.iteration, self.reason)
            ):
                raise ValueError("set_verification_state accepts only verification_state")
        else:
            if any(
                value is None
                for value in (self.replacement, self.revision_id, self.iteration, self.reason)
            ):
                raise ValueError(
                    "revise_claim requires replacement, revision_id, iteration, and reason"
                )
            assert self.replacement is not None
            if self.replacement.claim_id != self.claim_id:
                raise ValueError("replacement claim ID must match claim_id")
            if self.verification_state is not None:
                raise ValueError("revise_claim does not accept verification_state")
        return self


class WorkflowStageTrace(StrictModel):
    """Operations attributed to exactly one benchmark workflow component."""

    stage: BenchmarkStage
    operations: list[WorkflowOperation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_stage_actions(self) -> WorkflowStageTrace:
        permitted: dict[str, set[str]] = {
            "candidate_filters": {"remove_claim"},
            "verifier": {"set_verification_state"},
            "independence_gate": {"set_verification_state"},
            "alternative_narrative": {"revise_claim"},
            "blind_reviewer": {"remove_claim"},
        }
        invalid = [op.action for op in self.operations if op.action not in permitted[self.stage]]
        if invalid:
            raise ValueError(f"stage {self.stage!r} cannot execute actions {invalid!r}")
        return self


class CaseWorkflowTrace(StrictModel):
    """Complete, ordered stage trace used only by the benchmark ablation engine."""

    case_id: str = Field(min_length=1)
    input_claims: list[ObservedClaim]
    stages: list[WorkflowStageTrace]

    @model_validator(mode="after")
    def _check_trace(self) -> CaseWorkflowTrace:
        expected: list[str] = [
            "candidate_filters",
            "verifier",
            "independence_gate",
            "alternative_narrative",
            "blind_reviewer",
        ]
        observed = [stage.stage for stage in self.stages]
        if observed != expected:
            raise ValueError(f"workflow stages must be complete and ordered: {expected!r}")
        claim_ids = [claim.claim_id for claim in self.input_claims]
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("workflow input claim IDs must be unique")
        return self


class AblationExecutionReceipt(StrictModel):
    """Content-bound proof that benchmark stages were replayed or skipped."""

    receipt_version: Literal["mulder.benchmark.ablation/v1"] = (
        "mulder.benchmark.ablation/v1"
    )
    base_run_id: str = Field(min_length=1)
    base_matrix_cell: str = Field(min_length=1)
    base_result_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    workflow_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    disabled: list[AblationTarget] = Field(min_length=1)
    executed_stages: list[BenchmarkStage]
    skipped_stages: list[BenchmarkStage] = Field(min_length=1)
    case_operation_counts: dict[str, dict[BenchmarkStage, int]]

    @model_validator(mode="after")
    def _check_receipt(self) -> AblationExecutionReceipt:
        if len(set(self.disabled)) != len(self.disabled):
            raise ValueError("disabled ablations must be unique")
        if len(set(self.executed_stages)) != len(self.executed_stages):
            raise ValueError("executed stages must be unique")
        if len(set(self.skipped_stages)) != len(self.skipped_stages):
            raise ValueError("skipped stages must be unique")
        if set(self.executed_stages) & set(self.skipped_stages):
            raise ValueError("a stage cannot be both executed and skipped")
        return self


class ResourceUsage(StrictModel):
    """Measured resources for one complete benchmark run."""

    runtime_ms: int | None = Field(default=None, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    unattributed_tokens: int = Field(default=0, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens + self.unattributed_tokens


class RunIdentity(StrictModel):
    """Comparable run identity for repeats, matrices, and ablations."""

    matrix_cell: str = Field(min_length=1)
    models: dict[str, str] = Field(default_factory=dict)
    prompt_set_sha256: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    toolset_sha256: Sha256 | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    orchestrator_version: str = Field(min_length=1)
    methodology_version: str = Field(min_length=1)
    repeat_index: int = Field(default=0, ge=0)
    seed: int | None = None
    ablations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_identity(self) -> RunIdentity:
        if any(not role.strip() or not model.strip() for role, model in self.models.items()):
            raise ValueError("model role and identifier values must be non-empty")
        if len(set(self.ablations)) != len(self.ablations):
            raise ValueError("ablation labels must be unique")
        return self


class SourceAdjudicationItem(StrictModel):
    """One unchanged label imported from an earlier human adjudication."""

    item_id: str = Field(min_length=1)
    status: str = Field(min_length=1)
    ground_truth: str = Field(min_length=1)
    observed: str = Field(min_length=1)


class SourceAdjudication(StrictModel):
    """Provenance envelope retaining a historical evaluation verbatim."""

    scheme: str = Field(min_length=1)
    source_path: str = Field(min_length=1)
    source_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    reported_counts: dict[str, int] = Field(min_length=1)
    items: list[SourceAdjudicationItem] = Field(min_length=1)
    count_mismatch_note: str | None = Field(default=None, min_length=1)
    note: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_adjudication(self) -> SourceAdjudication:
        if any(count < 0 for count in self.reported_counts.values()):
            raise ValueError("adjudication counts cannot be negative")
        item_ids = [item.item_id for item in self.items]
        if len(set(item_ids)) != len(item_ids):
            raise ValueError("adjudication item IDs must be unique")
        actual = Counter(item.status for item in self.items)
        if dict(actual) != self.reported_counts and self.count_mismatch_note is None:
            raise ValueError(
                "a count_mismatch_note is required when reported_counts differ from item statuses"
            )
        if dict(actual) == self.reported_counts and self.count_mismatch_note is not None:
            raise ValueError(
                "count_mismatch_note is valid only when reported_counts differ from item statuses"
            )
        return self


class BenchmarkRunResult(StrictModel):
    """Versioned, committed result object consumed by the scorer."""

    schema_version: Literal[1] = SCHEMA_VERSION
    benchmark_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    system_name: str = Field(min_length=1)
    system_version: str = Field(min_length=1)
    identity: RunIdentity | None = None
    cases: list[CaseRunResult] = Field(min_length=1)
    resources: ResourceUsage
    source_adjudication: SourceAdjudication | None = None
    workflow_traces: list[CaseWorkflowTrace] = Field(default_factory=list)
    ablation_receipt: AblationExecutionReceipt | None = None

    @model_validator(mode="after")
    def _check_case_ids(self) -> BenchmarkRunResult:
        case_ids = [case.case_id for case in self.cases]
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("case_id values must be unique within a run")
        trace_ids = [trace.case_id for trace in self.workflow_traces]
        if len(set(trace_ids)) != len(trace_ids):
            raise ValueError("workflow trace case IDs must be unique")
        if trace_ids and set(trace_ids) != set(case_ids):
            raise ValueError("workflow traces must cover the result case set exactly")
        executable = (
            set(self.identity.ablations) & EXECUTABLE_ABLATIONS
            if self.identity is not None
            else set()
        )
        if executable and self.ablation_receipt is None:
            raise ValueError("executable ablation labels require an execution receipt")
        if self.ablation_receipt is not None:
            if self.identity is None:
                raise ValueError("an ablation receipt requires run identity")
            if executable != set(self.identity.ablations):
                raise ValueError("executable ablations cannot be mixed with legacy labels")
            if executable != set(self.ablation_receipt.disabled):
                raise ValueError("ablation identity and receipt disagree")
            if not self.workflow_traces:
                raise ValueError("an ablation receipt requires complete workflow traces")
        return self


class SetScore(StrictModel):
    """Micro-averaged set comparison with explicit confusion counts."""

    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)


class CitationScore(StrictModel):
    """Citation resolution and claim-support validity counts."""

    total: int = Field(ge=0)
    resolved: int = Field(ge=0)
    valid: int = Field(ge=0)
    unresolved: int = Field(ge=0)
    verified_claims: int = Field(ge=0)
    claims_with_valid_citation: int = Field(ge=0)
    uncited_verified_claims: int = Field(ge=0)
    resolution_rate: float = Field(ge=0, le=1)
    validity_rate: float = Field(ge=0, le=1)
    claim_citation_rate: float = Field(ge=0, le=1)


class EpistemicScore(StrictModel):
    """Distribution of claim verification states before assertion filtering."""

    total_claims: int = Field(ge=0)
    verified: int = Field(ge=0)
    contradicted: int = Field(ge=0)
    inconclusive: int = Field(ge=0)
    unsupported: int = Field(ge=0)
    unverified: int = Field(ge=0)
    contradicted_rate: float = Field(ge=0, le=1)
    inconclusive_rate: float = Field(ge=0, le=1)
    unsupported_rate: float = Field(ge=0, le=1)


class CoverageScore(StrictModel):
    """Exact expected-outcome coverage score."""

    expected_domains: int = Field(ge=0)
    matched_expected_outcomes: int = Field(ge=0)
    required_domains: int = Field(ge=0)
    completed_required_domains: int = Field(ge=0)
    unexpected_domains: int = Field(ge=0)
    expectation_accuracy: float = Field(ge=0, le=1)
    required_completeness: float = Field(ge=0, le=1)


class VerdictScore(StrictModel):
    """Verdict accuracy and abstention/unsafe-clean behavior."""

    total_cases: int = Field(ge=0)
    completed_cases: int = Field(ge=0)
    failed_cases: int = Field(ge=0)
    correct: int = Field(ge=0)
    no_verdict: int = Field(ge=0)
    expected_no_verdict: int = Field(ge=0)
    correct_no_verdict: int = Field(ge=0)
    unsafe_clean_verdicts: int = Field(ge=0)
    accuracy: float = Field(ge=0, le=1)
    no_verdict_rate: float = Field(ge=0, le=1)
    no_verdict_recall: float = Field(ge=0, le=1)


class ConfidenceCalibrationScore(StrictModel):
    """Calibration of declared claim probabilities against exact ground truth."""

    count: int = Field(ge=0)
    mean_confidence: float | None = Field(default=None, ge=0, le=1)
    empirical_accuracy: float | None = Field(default=None, ge=0, le=1)
    brier_score: float | None = Field(default=None, ge=0, le=1)
    expected_calibration_error: float | None = Field(default=None, ge=0, le=1)


class SeverityCalibrationScore(StrictModel):
    """Ordinal severity agreement for claims that exactly match ground truth."""

    count: int = Field(ge=0)
    exact_matches: int = Field(ge=0)
    unmatched_predictions: int = Field(ge=0)
    exact_rate: float | None = Field(default=None, ge=0, le=1)
    mean_absolute_error: float | None = Field(default=None, ge=0, le=4)


class RevisionScore(StrictModel):
    """Externally adjudicated effects of auditable before/after revisions."""

    revision_events: int = Field(ge=0)
    assertion_revisions: int = Field(ge=0)
    iterations_observed: int = Field(ge=0)
    errors_fixed: int = Field(ge=0)
    errors_introduced: int = Field(ge=0)
    correct_preserved: int = Field(ge=0)
    errors_persisted: int = Field(ge=0)
    net_errors_fixed: int


class ScoreSlice(StrictModel):
    """Scores for all cases or one clean/nonempty subset."""

    case_count: int = Field(ge=0)
    atomic_claims: SetScore
    entities: SetScore
    predicates: SetScore
    citations: CitationScore
    epistemic: EpistemicScore
    coverage: CoverageScore
    verdicts: VerdictScore
    confidence_calibration: ConfidenceCalibrationScore
    severity_calibration: SeverityCalibrationScore
    revisions: RevisionScore
    duplicate_claims: int = Field(ge=0)
    duplicate_citations: int = Field(ge=0)


class CaseScore(ScoreSlice):
    """Detailed score for a single benchmark case."""

    case_id: str
    ground_truth_label: Literal["clean", "nonempty"]


class RunScore(StrictModel):
    """One scored system run and its resource measurements."""

    run_id: str
    system_name: str
    system_version: str
    identity: RunIdentity | None = None
    result_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    overall: ScoreSlice
    clean: ScoreSlice
    nonempty: ScoreSlice
    cases: list[CaseScore]
    resources: ResourceUsage


class MetricDistribution(StrictModel):
    """Population statistics for one metric across comparable repeats."""

    count: int = Field(ge=0)
    mean: float | None = None
    population_variance: float | None = Field(default=None, ge=0)
    population_stddev: float | None = Field(default=None, ge=0)
    minimum: float | None = None
    maximum: float | None = None


class AggregateScore(StrictModel):
    """Repeat-aware score distributions for one explicit matrix cell."""

    matrix_cell: str
    run_ids: list[str]
    repeat_count: int = Field(ge=1)
    metrics: dict[str, MetricDistribution]


class BenchmarkScoreDocument(StrictModel):
    """Deterministic comparison artifact emitted by the benchmark CLI."""

    schema_version: Literal[1] = SCHEMA_VERSION
    score_schema: Literal["mulder.benchmark.score/v1"] = "mulder.benchmark.score/v1"
    benchmark_id: str
    manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    methodology_version: SupportedMethodologyVersion = METHODOLOGY_VERSION
    runs: list[RunScore]
    aggregates: list[AggregateScore] = Field(default_factory=list)
