"""Pydantic models shared across the Mulder project."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, model_validator


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
