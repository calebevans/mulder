"""Pydantic models shared across the Mulder project."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, model_validator


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


class ToolOutcome(BaseModel):
    """Versioned, serializable execution semantics for an MCP tool response."""

    schema_version: Literal[1] = 1
    status: ToolOutcomeStatus
    coverage: CoverageMetadata = Field(default_factory=CoverageMetadata)
    reason: str | None = None

    @model_validator(mode="after")
    def _check_status_metadata(self) -> ToolOutcome:
        """Require the scope explanation that makes sampled results auditable."""
        if self.status is ToolOutcomeStatus.SAMPLED and not self.coverage.sample_reason:
            raise ValueError("SAMPLED outcomes require coverage.sample_reason")
        return self


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
