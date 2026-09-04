"""Pydantic models shared across the Mulder project."""

from __future__ import annotations

from typing import Literal, TypeAlias

from pydantic import BaseModel, Field, model_validator

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
    submitted_at: str

    @model_validator(mode="after")
    def _check_evidence_refs_nonempty(self) -> Finding:
        """Require at least one evidence_refs entry (tool_call_id citations)."""
        if not self.evidence_refs:
            raise ValueError("evidence_refs must contain at least one tool_call_id")
        return self


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
    artifact_family: str
    extractor_family: str
    independence_key: str
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
