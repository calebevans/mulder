"""Pydantic models shared across the Mulder project."""

from __future__ import annotations

from enum import Enum
from typing import Literal, TypeAlias

from pydantic import AwareDatetime, BaseModel, Field, model_validator


class ToolOutcomeStatus(str, Enum):
    """Machine-readable execution state for a forensic tool result.

    The legacy MCP response ``status`` remains ``success`` or ``error`` for
    backwards compatibility.  This enum carries the more precise state needed
    to decide what conclusions the result can support.
    """

    SUCCESS_NONEMPTY = "SUCCESS_NONEMPTY"
    SUCCESS_EMPTY = "SUCCESS_EMPTY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    PARTIAL = "PARTIAL"
    SAMPLED = "SAMPLED"
    NOT_RUN = "NOT_RUN"


class FallbackAttempt(BaseModel):
    """One earlier adapter attempt retained when a fallback produced a result."""

    adapter: str
    status: ToolOutcomeStatus
    reason: str | None = None
    tool_version: str | None = None
    parser_version: str | None = None


class CoverageMetadata(BaseModel):
    """Structured scope and implementation provenance for a tool outcome.

    ``examined`` values describe content successfully examined, rather than
    content merely discovered or attempted.  Unknown values stay ``None``;
    callers must not turn an unknown total into an implicit complete result.
    """

    bytes_examined: int | None = Field(default=None, ge=0)
    bytes_total: int | None = Field(default=None, ge=0)
    rows_examined: int | None = Field(default=None, ge=0)
    rows_total: int | None = Field(default=None, ge=0)
    truncation_reason: str | None = None
    sample_reason: str | None = None
    tool_version: str | None = None
    parser_version: str | None = None
    fallback_lineage: list[FallbackAttempt] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_scope_bounds(self) -> CoverageMetadata:
        """Reject coverage that claims to examine more than the known total."""
        if (
            self.bytes_examined is not None
            and self.bytes_total is not None
            and self.bytes_examined > self.bytes_total
        ):
            raise ValueError("bytes_examined cannot exceed bytes_total")
        if (
            self.rows_examined is not None
            and self.rows_total is not None
            and self.rows_examined > self.rows_total
        ):
            raise ValueError("rows_examined cannot exceed rows_total")
        return self


class ToolExecutionMetadata(BaseModel):
    """Exact execution commitment attached to a non-legacy tool outcome."""

    source_ids: list[str] = Field(default_factory=list)
    started_at: AwareDatetime
    ended_at: AwareDatetime
    output_digest: str = Field(pattern=r"^(?:sha256|blake2b):[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _check_time_order(self) -> ToolExecutionMetadata:
        if self.ended_at < self.started_at:
            raise ValueError("ended_at cannot precede started_at")
        return self


class ToolOutcome(BaseModel):
    """Versioned, serializable execution semantics for an MCP tool response."""

    schema_version: Literal[1] = 1
    status: ToolOutcomeStatus
    coverage: CoverageMetadata = Field(default_factory=CoverageMetadata)
    reason: str | None = None
    execution: ToolExecutionMetadata | None = None
    legacy_mapping: Literal["LEGACY_UNCLASSIFIED"] | None = "LEGACY_UNCLASSIFIED"

    @model_validator(mode="after")
    def _check_status_metadata(self) -> ToolOutcome:
        """Require the scope explanation that makes sampled results auditable."""
        if self.status is ToolOutcomeStatus.SAMPLED and not self.coverage.sample_reason:
            raise ValueError("SAMPLED outcomes require coverage.sample_reason")
        if self.execution is not None and self.legacy_mapping is not None:
            raise ValueError("execution metadata and legacy_mapping are mutually exclusive")
        if self.execution is None and self.legacy_mapping is None:
            raise ValueError("outcome must carry execution metadata or an explicit legacy mapping")
        return self


class CoverageKey(BaseModel):
    """Stable coordinates for one evidence-domain coverage assertion."""

    system_name: str = Field(min_length=1)
    evidence_domain: str = Field(min_length=1)
    check_name: str = Field(min_length=1)


class CoverageRecord(BaseModel):
    """Persisted result and scope for one case/system/domain/check tuple."""

    case_id: str
    key: CoverageKey
    outcome: ToolOutcome
    source_name: str | None = None
    tool_call_id: str | None = None
    recorded_at: str


class CoverageRequirement(BaseModel):
    """Declarative mandatory check that must be represented before sealing."""

    case_id: str
    key: CoverageKey
    required_tool: str
    rationale: str
    declared_at: str


class ScopedNegativeVerdict(BaseModel):
    """A negative conclusion explicitly limited to completed coverage."""

    verdict: Literal["NO_EVIL_WITHIN_COVERAGE"] = "NO_EVIL_WITHIN_COVERAGE"
    scope: list[CoverageKey] = Field(min_length=1)


JsonScalar: TypeAlias = str | int | float | bool | None


class WindowRow(BaseModel):
    """A single windowed slice of evidence text from an indexed source."""

    window_id: int | None = None
    source_id: int
    line_start: int
    line_end: int
    event_time: str | None
    raw_text: str


class SourceRow(BaseModel):
    """Metadata for a registered evidence source in the case database."""

    source_id: int
    case_id: str
    source_name: str
    source_path: str
    source_hash: str
    extractor: str
    line_count: int
    windows_hash: str | None = None


class CaseMetadataRow(BaseModel):
    """Top-level metadata record for a forensic case."""

    case_id: str
    ingested_at: str
    evidence_root: str
    extractor_versions: dict[str, str]
    narrative: str | None = None


class Finding(BaseModel):
    """An investigative finding backed by evidence references."""

    finding_id: str
    case_id: str
    title: str
    description: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["confirmed", "inference"]
    evidence_refs: list[str]
    sources: list[str]
    mitre_attack_ids: list[str] = []
    event_time_start: str | None = None
    event_time_end: str | None = None
    negative_verdict: ScopedNegativeVerdict | None = None
    claim_state: Literal["atomic", "legacy_unverified"] = "legacy_unverified"
    submitted_at: str

    @model_validator(mode="after")
    def _check_evidence_refs_nonempty(self) -> Finding:
        """Require at least one evidence_refs entry (tool_call_id citations)."""
        if not self.evidence_refs:
            raise ValueError("evidence_refs must contain at least one tool_call_id")
        return self


class FindingRevision(BaseModel):
    """Immutable snapshot recording one visible change to a finding."""

    revision_id: str
    finding_id: str
    revision_number: int = Field(ge=1)
    parent_revision_id: str | None = None
    state: Literal[
        "draft", "indicated", "confirmed", "refuted", "quarantined", "unknown", "withdrawn"
    ]
    snapshot: Finding
    actor_kind: Literal["investigator", "deterministic_rule", "blind_reviewer", "human", "system"]
    actor_id: str | None = None
    reason_code: str
    changed_fields: list[str] = Field(default_factory=list)
    evidence_added: list[str] = Field(default_factory=list)
    evidence_removed: list[str] = Field(default_factory=list)
    contradiction_ids: list[str] = Field(default_factory=list)
    tombstone: bool = False
    created_at: str


class EvidenceAnchorInput(BaseModel):
    """Caller-supplied locator for an exact quote in an evidence window.

    The caller identifies a previously returned window and the exact character
    range it is relying on.  Source identity, hashes, extractor family, and the
    independence key are resolved by :class:`CaseDB`; callers cannot assert
    those provenance fields themselves.
    """

    tool_call_id: str = Field(min_length=1)
    window_id: int = Field(gt=0)
    char_start: int = Field(ge=0)
    char_end: int = Field(gt=0)
    expected_text: str = Field(min_length=1)
    selector_type: Literal[
        "text_span",
        "csv_cell",
        "json_pointer",
        "evtx_field",
        "sqlite_cell",
        "byte_range",
        "parsed_record",
    ] = "text_span"
    selector: dict[str, JsonScalar] = Field(default_factory=dict)
    artifact_family: str | None = None
    value_type: str = "text"
    normalized_value: JsonScalar = None
    role: Literal["supports", "contradicts"] = "supports"

    @model_validator(mode="after")
    def _check_character_range(self) -> EvidenceAnchorInput:
        if self.char_end <= self.char_start:
            raise ValueError("char_end must be greater than char_start")
        return self


class AtomicClaimInput(BaseModel):
    """A material statement and the exact evidence anchors offered for it."""

    statement: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    predicate: str = Field(min_length=1)
    object_value: JsonScalar
    qualifiers: dict[str, JsonScalar] = Field(default_factory=dict)
    material: bool = True
    anchors: list[EvidenceAnchorInput] = Field(min_length=1)


class EvidenceAnchor(BaseModel):
    """Server-resolved immutable evidence locator for an atomic claim."""

    anchor_id: str
    claim_id: str
    tool_call_id: str
    source_id: int
    source_name: str
    source_hash: str
    window_id: int
    line_start: int
    line_end: int
    char_start: int
    char_end: int
    exact_text: str
    selector_type: Literal[
        "text_span",
        "csv_cell",
        "json_pointer",
        "evtx_field",
        "sqlite_cell",
        "byte_range",
        "parsed_record",
    ] = "text_span"
    selector: dict[str, JsonScalar] = Field(default_factory=dict)
    artifact_family: str
    extractor_family: str
    independence_key: str
    artifact_independence_key: str | None = None
    acquisition_independence_key: str | None = None
    extractor_independence_key: str | None = None
    observation_independence_key: str | None = None
    value_type: str
    normalized_value: JsonScalar = None
    role: Literal["supports", "contradicts"] = "supports"


class AtomicClaim(BaseModel):
    """Persisted atomic finding statement with resolved evidence anchors."""

    claim_id: str
    finding_id: str
    ordinal: int = Field(ge=0)
    statement: str
    subject: str
    predicate: str
    object_value: JsonScalar
    qualifiers: dict[str, JsonScalar] = Field(default_factory=dict)
    material: bool = True
    epistemic_state: Literal[
        "legacy_unverified", "unverified", "verified", "contradicted", "inconclusive"
    ] = "unverified"
    anchors: list[EvidenceAnchor] = Field(default_factory=list)


class VerificationDecision(BaseModel):
    """Pure deterministic decision returned by the claim verifier module."""

    result: Literal["verified", "contradicted", "inconclusive"]
    reason_code: str
    details: dict[str, JsonScalar] = Field(default_factory=dict)


class ClaimVerification(VerificationDecision):
    """Append-only persisted execution of a deterministic claim verifier."""

    verification_id: str
    claim_id: str
    verifier_name: str
    verifier_version: str
    verified_at: str


class ClaimConfirmation(BaseModel):
    """Policy decision for one claim in a confirmed finding."""

    claim_id: str
    accepted: bool
    reason_code: str
    independent_sources: int = Field(ge=0)
    required_sources: int = Field(ge=1)
    policy_id: str = "material-two-artifact-v2"
    independence_dimensions: dict[str, int] = Field(default_factory=dict)
    required_independence_dimensions: dict[str, int] = Field(default_factory=dict)


class ConfirmationAssessment(BaseModel):
    """Server-owned corroboration decision for an entire finding."""

    accepted: bool
    claims: list[ClaimConfirmation] = Field(default_factory=list)


class ToolCallEntry(BaseModel):
    """A single tool invocation recorded in the audit log."""

    tool_call_id: str
    tool_name: str
    params: dict[str, object]
    output_hash: str
    timestamp: str
    duration_ms: float
    batch_id: str | None = None


class SourceProvenance(BaseModel):
    """Original evidence file backing one or more tool calls."""

    source_name: str
    source_path: str
    source_hash: str
    extractor: str


class ProvenanceChain(BaseModel):
    """Full trace from a finding back to the original evidence files."""

    finding_id: str
    tool_calls: list[ToolCallEntry]
    sources: list[SourceProvenance]


class AuditSummary(BaseModel):
    """Aggregate statistics over an entire audit log."""

    total_tool_calls: int
    total_findings: int
    tool_call_counts: dict[str, int]
    total_duration_ms: float
    wall_clock_ms: float = 0.0
    first_timestamp: str
    last_timestamp: str
    tool_durations: dict[str, float] = {}
    estimated_input_tokens: int = 0
    estimated_output_tokens: int = 0
    estimated_cost_usd: float = 0.0
