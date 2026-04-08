"""Pydantic models shared across the Killjoy project."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, model_validator


class WindowRow(BaseModel):
    window_id: int
    source_id: int
    line_start: int
    line_end: int
    event_time: str | None
    raw_text: str


class SourceRow(BaseModel):
    source_id: int
    case_id: str
    source_name: str
    source_path: str
    source_hash: str
    extractor: str
    line_count: int


class CaseMetadataRow(BaseModel):
    case_id: str
    ingested_at: str
    evidence_root: str
    extractor_versions: dict[str, str]


class Finding(BaseModel):
    finding_id: str
    case_id: str
    title: str
    description: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["confirmed", "inference"]
    evidence_refs: list[str]
    sources: list[str]
    event_time_start: str | None = None
    event_time_end: str | None = None
    submitted_at: str

    @model_validator(mode="after")
    def _check_evidence_refs_nonempty(self) -> Finding:
        if not self.evidence_refs:
            raise ValueError("evidence_refs must contain at least one tool_call_id")
        return self


# ------------------------------------------------------------------
# Audit trail models (Piece 11)
# ------------------------------------------------------------------


class ToolCallEntry(BaseModel):
    """A single tool invocation recorded in the audit log."""

    tool_call_id: str
    tool_name: str
    params: dict
    output_hash: str
    timestamp: str
    duration_ms: float


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
    first_timestamp: str
    last_timestamp: str
