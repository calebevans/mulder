"""Durable, resumable investigation events carried by the case audit chain."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mulder.audit import AuditLog

RUN_EVENT_SCHEMA: Literal["mulder.run-event"] = "mulder.run-event"
RUN_EVENT_VERSION: Literal[1] = 1
MAX_RUN_EVENT_PAGE = 1000

RunEventKind = Literal[
    "investigation_started",
    "investigation_finished",
    "phase_changed",
    "extraction_progress",
    "task_registered",
    "task_state",
    "tasks_cleared",
    "tool_observed",
    "finding_observed",
    "session_metrics",
    "phase_result",
    "gate_result",
    "info",
]


class RunEventError(ValueError):
    """Raised when durable run events cannot be safely read or appended."""


class _EventModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class RunEventDraft(_EventModel):
    """Typed event fields accepted by the journal append interface.

    There is deliberately no arbitrary command, tool-argument, or extension
    payload.  Browser consumers can observe investigation state but cannot use
    this schema as an untyped tool invocation path.
    """

    event_schema: Literal["mulder.run-event"] = RUN_EVENT_SCHEMA
    event_version: Literal[1] = RUN_EVENT_VERSION
    kind: RunEventKind
    phase: str | None = None
    phase_index: int | None = Field(default=None, ge=0)
    total_phases: int | None = Field(default=None, ge=0)
    model: str | None = None
    max_turns: int | None = Field(default=None, ge=0)
    total: int | None = Field(default=None, ge=0)
    done: int | None = Field(default=None, ge=0)
    active: int | None = Field(default=None, ge=0)
    system: str | None = None
    tool: str | None = None
    status: Literal["pending", "running", "done", "failed", "cleared"] | None = None
    elapsed_seconds: float | None = Field(default=None, ge=0)
    severity: str | None = None
    title: str | None = None
    message: str | None = None
    turns: int | None = Field(default=None, ge=0)
    tokens: int | None = Field(default=None, ge=0)
    success: bool | None = None


class RunEvent(RunEventDraft):
    """A run event with the durable sequence assigned by the audit chain."""

    case_id: str
    sequence: int = Field(gt=0)
    timestamp: str


class RunEventPage(_EventModel):
    """Bounded replay page read from one verified audit snapshot."""

    after_sequence: int = Field(ge=0)
    limit: int = Field(gt=0, le=MAX_RUN_EVENT_PAGE)
    high_watermark: int = Field(ge=0)
    events: tuple[RunEvent, ...]
    audit_integrity_status: str
    skipped_legacy_events: int = Field(ge=0)

    @property
    def has_more(self) -> bool:
        return bool(self.events) and self.events[-1].sequence < self.high_watermark


class RunEventJournal:
    """Deep interface for durable append and bounded replay of run events.

    Run events are operational observations in the existing append-only case
    audit log, not a second evidence or finding store.  Their ID is the audit
    chain sequence, so an SSE client can resume strictly after Last-Event-ID.
    """

    def __init__(self, audit_path: Path, case_id: str) -> None:
        if not case_id or Path(case_id).name != case_id or case_id in {".", ".."}:
            raise RunEventError("case_id must be one safe path segment")
        self._audit = AuditLog(audit_path)
        self._case_id = case_id

    def append(self, draft: RunEventDraft) -> RunEvent:
        """Durably append ``draft`` and return the exact sequenced event."""
        event_fields = draft.model_dump(mode="json", exclude_none=True)
        written = self._audit.log_run_event(self._case_id, event_fields)
        return self._parse_entry(written)

    def read(self, *, after_sequence: int = 0, limit: int = 1000) -> RunEventPage:
        """Return native run events with sequence strictly greater than a cursor."""
        try:
            integrity, entries, high_watermark, skipped_legacy = (
                self._audit.read_run_event_entries(
                    after_sequence=after_sequence,
                    limit=limit,
                )
            )
        except ValueError as exc:
            raise RunEventError(str(exc)) from exc
        if not integrity.ok:
            raise RunEventError(
                "cannot replay events from an invalid audit chain: "
                f"{integrity.error_code or integrity.message}"
            )
        events = tuple(self._parse_entry(entry) for entry in entries)
        return RunEventPage(
            after_sequence=after_sequence,
            limit=limit,
            high_watermark=high_watermark,
            events=events,
            audit_integrity_status=integrity.status,
            skipped_legacy_events=skipped_legacy,
        )

    def _parse_entry(self, entry: dict[str, object]) -> RunEvent:
        if entry.get("case_id") != self._case_id:
            raise RunEventError("run event case_id does not match the requested case")
        value = {
            key: item
            for key, item in entry.items()
            if key
            not in {
                "type",
                "schema",
                "version",
                "previous_hash",
                "entry_hash",
                "legacy_prefix_entries",
            }
        }
        try:
            return RunEvent.model_validate(value)
        except ValidationError as exc:
            sequence = entry.get("sequence", "unknown")
            raise RunEventError(f"invalid run event at audit sequence {sequence}: {exc}") from exc


def encode_sse(event: RunEvent) -> bytes:
    """Encode one event as an SSE frame safe for arbitrary Unicode strings."""
    data = event.model_dump_json(exclude_none=True)
    # Pydantic emits compact single-line JSON; defensively split if that ever
    # changes so user-controlled text cannot inject an SSE field.
    data_lines = "".join(f"data: {line}\n" for line in data.splitlines() or [""])
    return (
        f"id: {event.sequence}\n"
        f"event: {event.kind}\n"
        f"{data_lines}\n"
    ).encode()
