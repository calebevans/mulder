"""Versioned, machine-readable contracts for offline Mulder benchmarks."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mulder.models import JsonScalar, ToolOutcomeStatus

SCHEMA_VERSION: Literal[1] = 1
METHODOLOGY_VERSION: Literal["1.0"] = "1.0"

Sha256 = str
VerificationState = Literal[
    "verified", "contradicted", "inconclusive", "unsupported", "unverified"
]
Verdict = Literal["positive", "no_evil_within_coverage", "no_verdict"]


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
    methodology_version: Literal["1.0"] = METHODOLOGY_VERSION
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


class ObservedCoverage(StrictModel):
    """Observed outcome for one declared evidence domain."""

    domain: str = Field(min_length=1)
    status: ToolOutcomeStatus


class CaseRunResult(StrictModel):
    """Normalized output for one case in an offline benchmark run."""

    case_id: str = Field(min_length=1)
    verdict: Verdict
    claims: list[ObservedClaim] = Field(default_factory=list)
    coverage: list[ObservedCoverage] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_result_ids(self) -> CaseRunResult:
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("observed claim_id values must be unique within a case")
        domains = [item.domain for item in self.coverage]
        if len(set(domains)) != len(domains):
            raise ValueError("observed coverage domains must be unique within a case")
        return self


class ResourceUsage(StrictModel):
    """Measured resources for one complete benchmark run."""

    runtime_ms: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_usd: float = Field(ge=0)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class BenchmarkRunResult(StrictModel):
    """Versioned, committed result object consumed by the scorer."""

    schema_version: Literal[1] = SCHEMA_VERSION
    benchmark_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    system_name: str = Field(min_length=1)
    system_version: str = Field(min_length=1)
    cases: list[CaseRunResult] = Field(min_length=1)
    resources: ResourceUsage

    @model_validator(mode="after")
    def _check_case_ids(self) -> BenchmarkRunResult:
        case_ids = [case.case_id for case in self.cases]
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("case_id values must be unique within a run")
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
    correct: int = Field(ge=0)
    no_verdict: int = Field(ge=0)
    expected_no_verdict: int = Field(ge=0)
    correct_no_verdict: int = Field(ge=0)
    unsafe_clean_verdicts: int = Field(ge=0)
    accuracy: float = Field(ge=0, le=1)
    no_verdict_rate: float = Field(ge=0, le=1)
    no_verdict_recall: float = Field(ge=0, le=1)


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
    result_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    overall: ScoreSlice
    clean: ScoreSlice
    nonempty: ScoreSlice
    cases: list[CaseScore]
    resources: ResourceUsage


class BenchmarkScoreDocument(StrictModel):
    """Deterministic comparison artifact emitted by the benchmark CLI."""

    schema_version: Literal[1] = SCHEMA_VERSION
    score_schema: Literal["mulder.benchmark.score/v1"] = "mulder.benchmark.score/v1"
    benchmark_id: str
    manifest_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    methodology_version: Literal["1.0"] = METHODOLOGY_VERSION
    runs: list[RunScore]
