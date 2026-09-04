"""MCP Adapter from indexed evidence into the anti-forensics clock Module."""

from __future__ import annotations

import csv
import hashlib
import io
import time
from collections.abc import Sequence
from datetime import datetime

from mulder.models import SourceRow, ToolOutcomeStatus, WindowRow
from mulder.packs.anti_forensics_clock import (
    ArtifactFamily,
    ClockEvidenceRequest,
    ObservationKind,
    SourceEvidence,
    TemporalObservation,
    TemporalProvenance,
    analyze_clock_evidence,
    preserve_time,
)
from mulder.security.evidence_envelope import envelope_evidence
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import hash_output, make_tool_call_id
from mulder.server.tool_access import Role, tool_access

_NORMALIZER_VERSION = "1.0"
_MFT_SI_CREATED = ("Created0x10_0", "Created0x10")
_MFT_FN_CREATED = ("Created0x30_0", "Created0x30")
_MFT_SI_MODIFIED = (
    "LastModified0x10_0",
    "Modified0x10_0",
    "Modified0x10",
    "LastModified0x10",
)
_FILE_NAME = ("FileName", "Filename", "filename", "File Name")
_PARENT_PATH = ("ParentPath", "Parent Path", "parentpath")
_USN_SEQUENCE = ("UpdateSequenceNumber", "Update Sequence Number", "USN", "EntryNumber")
_USN_TIMESTAMP = ("UpdateTimestamp", "Update Timestamp", "Timestamp", "TimeStamp")
_USN_REASON = ("UpdateReasons", "Update Reasons", "Reason", "Reasons")
_FALSE_POSITIVE_PATHS = (
    "\\windows\\winsxs\\",
    "\\windows\\installer\\",
    "\\windows\\servicing\\",
    "\\windows\\softwaredistribution\\",
    "\\$recycle.bin\\",
    "\\system volume information\\",
    "\\windows\\assembly\\",
)


def _first(headers: Sequence[str], candidates: Sequence[str]) -> str | None:
    return next((candidate for candidate in candidates if candidate in headers), None)


def _raw_source(windows: Sequence[WindowRow]) -> str:
    return "".join(window.raw_text for window in sorted(windows, key=lambda item: item.line_start))


def _provenance(
    source: SourceRow,
    raw: str,
    *,
    selector: str,
    parser_id: str,
) -> TemporalProvenance:
    envelope = envelope_evidence(
        raw,
        source_id=str(source.source_id),
        source_name=source.source_name,
        selector=selector,
        max_characters=1,
    )
    return TemporalProvenance(
        source_id=str(source.source_id),
        source_name=source.source_name,
        selector=selector,
        raw_digest=envelope.provenance.digest,
        parser_id=parser_id,
        parser_version=_NORMALIZER_VERSION,
        independence_key=f"source:{source.source_hash}",
        evidence_flags=envelope.flags,
    )


def _observation_id(source: SourceRow, row_number: int, kind: ObservationKind) -> str:
    material = f"{source.source_hash}\0{row_number}\0{kind.value}".encode()
    return "obs_" + hashlib.sha256(material).hexdigest()[:20]


def _source_result(
    source: SourceRow,
    family: ArtifactFamily,
    parser_id: str,
    observations: Sequence[TemporalObservation],
    *,
    rows_examined: int,
    rows_total: int,
    unsupported_reason: str | None = None,
    partial_reason: str | None = None,
) -> SourceEvidence:
    if unsupported_reason:
        status = ToolOutcomeStatus.UNSUPPORTED_VERSION
        reason = unsupported_reason
    elif partial_reason:
        status = ToolOutcomeStatus.PARTIAL
        reason = partial_reason
    elif observations:
        status = ToolOutcomeStatus.SUCCESS_NONEMPTY
        reason = None
    else:
        status = ToolOutcomeStatus.SUCCESS_EMPTY
        reason = None
    return SourceEvidence(
        source_id=str(source.source_id),
        family=family,
        parser_id=parser_id,
        parser_version=_NORMALIZER_VERSION,
        status=status,
        reason=reason,
        rows_examined=rows_examined,
        rows_total=rows_total,
        observations=tuple(observations),
    )


def _mft_evidence(source: SourceRow, windows: Sequence[WindowRow]) -> SourceEvidence:
    parser_id = "mftecmd-si-fn"
    raw = _raw_source(windows)
    reader = csv.DictReader(io.StringIO(raw))
    headers = [header.strip() for header in (reader.fieldnames or []) if header]
    si_name = _first(headers, _MFT_SI_CREATED)
    fn_name = _first(headers, _MFT_FN_CREATED)
    modified_name = _first(headers, _MFT_SI_MODIFIED)
    file_name = _first(headers, _FILE_NAME)
    parent_name = _first(headers, _PARENT_PATH)
    if si_name is None or fn_name is None:
        return _source_result(
            source,
            ArtifactFamily.MFT,
            parser_id,
            (),
            rows_examined=0,
            rows_total=max(source.line_count - 1, 0),
            unsupported_reason="MFTECmd schema lacks SI/FN creation columns",
        )

    observations: list[TemporalObservation] = []
    rows = 0
    provenance = _provenance(source, raw, selector="csv:all", parser_id=parser_id)
    for row_number, row in enumerate(reader, start=2):
        rows += 1
        si = preserve_time(row.get(si_name, ""), normalization_rule="mftecmd-timestamp")
        fn = preserve_time(row.get(fn_name, ""), normalization_rule="mftecmd-timestamp")
        modified = (
            preserve_time(
                row.get(modified_name, ""), normalization_rule="mftecmd-timestamp"
            )
            if modified_name
            else None
        )
        if si is None or fn is None:
            continue
        name = (row.get(file_name, "") if file_name else "").strip()
        parent = (row.get(parent_name, "") if parent_name else "").strip()
        subject = f"{parent}\\{name}" if parent else name
        if not subject or any(path in subject.casefold() for path in _FALSE_POSITIVE_PATHS):
            continue
        si_dt = _iso_datetime(si.normalized_utc)
        fn_dt = _iso_datetime(fn.normalized_utc)
        modified_dt = _iso_datetime(modified.normalized_utc) if modified else None
        candidate = (fn_dt - si_dt).total_seconds() > 10 or (
            modified_dt is not None and (si_dt - modified_dt).total_seconds() > 10
        )
        if not candidate:
            continue
        for kind, timestamp in (
            (ObservationKind.MFT_SI_CREATED, si),
            (ObservationKind.MFT_FN_CREATED, fn),
            (ObservationKind.MFT_SI_MODIFIED, modified),
        ):
            if timestamp is None:
                continue
            observations.append(
                TemporalObservation(
                    observation_id=_observation_id(source, row_number, kind),
                    kind=kind,
                    subject=subject,
                    time=timestamp,
                    provenance=provenance.model_copy(
                        update={"selector": f"csv:row={row_number};column={kind.value}"}
                    ),
                    attributes={"record_number": row_number},
                )
            )
    return _source_result(
        source,
        ArtifactFamily.MFT,
        parser_id,
        observations,
        rows_examined=rows,
        rows_total=rows,
    )


def _parse_sequence(value: str) -> int | None:
    try:
        return int(value.strip(), 0)
    except ValueError:
        return None


def _iso_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _usn_evidence(
    source: SourceRow,
    windows: Sequence[WindowRow],
    candidate_subjects: set[str],
) -> SourceEvidence:
    parser_id = "mftecmd-usn-order"
    raw = _raw_source(windows)
    reader = csv.DictReader(io.StringIO(raw))
    headers = [header.strip() for header in (reader.fieldnames or []) if header]
    sequence_name = _first(headers, _USN_SEQUENCE)
    timestamp_name = _first(headers, _USN_TIMESTAMP)
    reason_name = _first(headers, _USN_REASON)
    file_name = _first(headers, _FILE_NAME)
    parent_name = _first(headers, _PARENT_PATH)
    if sequence_name is None or timestamp_name is None or reason_name is None:
        return _source_result(
            source,
            ArtifactFamily.USN,
            parser_id,
            (),
            rows_examined=0,
            rows_total=max(source.line_count - 1, 0),
            unsupported_reason="USN schema lacks sequence, timestamp, or reason columns",
        )

    parsed: list[TemporalObservation] = []
    rows = 0
    provenance = _provenance(source, raw, selector="csv:all", parser_id=parser_id)
    for row_number, row in enumerate(reader, start=2):
        rows += 1
        sequence = _parse_sequence(row.get(sequence_name, ""))
        timestamp = preserve_time(
            row.get(timestamp_name, ""), normalization_rule="mftecmd-usn-timestamp"
        )
        action = row.get(reason_name, "").strip()
        if sequence is None or timestamp is None or not action:
            continue
        name = (row.get(file_name, "") if file_name else "").strip()
        parent = (row.get(parent_name, "") if parent_name else "").strip()
        subject = f"{parent}\\{name}" if parent else name
        parsed.append(
            TemporalObservation(
                observation_id=_observation_id(source, row_number, ObservationKind.USN_CHANGE),
                kind=ObservationKind.USN_CHANGE,
                subject=subject or f"usn:{sequence}",
                time=timestamp,
                provenance=provenance.model_copy(
                    update={"selector": f"csv:row={row_number};sequence={sequence}"}
                ),
                sequence_number=sequence,
                action=action,
            )
        )

    # Retain candidate witnesses and both sides of sequence/time reversals.
    relevant_ids: set[str] = {
        item.observation_id
        for item in parsed
        if item.subject.casefold() in candidate_subjects
    }
    ordered = sorted(parsed, key=lambda item: (item.sequence_number or 0, item.observation_id))
    for previous, current in zip(ordered, ordered[1:], strict=False):
        backwards = _iso_datetime(previous.time.normalized_utc) - _iso_datetime(
            current.time.normalized_utc
        )
        if backwards.total_seconds() > 10:
            relevant_ids.update((previous.observation_id, current.observation_id))
    observations = [item for item in parsed if item.observation_id in relevant_ids]
    return _source_result(
        source,
        ArtifactFamily.USN,
        parser_id,
        observations,
        rows_examined=rows,
        rows_total=rows,
    )


def _event_log_evidence(source: SourceRow, windows: Sequence[WindowRow]) -> SourceEvidence:
    parser_id = "python-evtx-line"
    raw = _raw_source(windows)
    observations: list[TemporalObservation] = []
    malformed = 0
    rows = 0
    provenance = _provenance(source, raw, selector="line:all", parser_id=parser_id)
    for row_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        rows += 1
        parts = line.split(" | ", 3)
        if len(parts) != 4:
            malformed += 1
            continue
        timestamp = preserve_time(parts[0], normalization_rule="python-evtx-record-time")
        try:
            event_id = int(parts[1])
        except ValueError:
            malformed += 1
            continue
        if timestamp is None:
            malformed += 1
            continue
        if event_id not in {104, 1102}:
            continue
        action = "security_log_cleared" if event_id == 1102 else "system_log_cleared"
        observations.append(
            TemporalObservation(
                observation_id=_observation_id(
                    source, row_number, ObservationKind.EVENT_LOG_CLEAR
                ),
                kind=ObservationKind.EVENT_LOG_CLEAR,
                subject=parts[2] or source.source_name,
                time=timestamp,
                provenance=provenance.model_copy(
                    update={"selector": f"line:{row_number};event_id={event_id}"}
                ),
                action=action,
                attributes={"event_id": event_id},
            )
        )
    return _source_result(
        source,
        ArtifactFamily.EVENT_LOG,
        parser_id,
        observations,
        rows_examined=rows - malformed,
        rows_total=rows,
        partial_reason=(f"{malformed} event rows had unsupported shape" if malformed else None),
    )


def _vss_evidence(source: SourceRow, windows: Sequence[WindowRow]) -> SourceEvidence:
    parser_id = "libvshadow-info"
    raw = _raw_source(windows)
    observations: list[TemporalObservation] = []
    provenance = _provenance(source, raw, selector="line:all", parser_id=parser_id)
    rows = 0
    for row_number, line in enumerate(raw.splitlines(), start=1):
        if "creation time" not in line.casefold():
            continue
        rows += 1
        value = line.split(":", 1)[-1].strip()
        timestamp = preserve_time(value, normalization_rule="libvshadow-creation-time")
        if timestamp is None:
            continue
        observations.append(
            TemporalObservation(
                observation_id=_observation_id(
                    source, row_number, ObservationKind.VSS_SNAPSHOT
                ),
                kind=ObservationKind.VSS_SNAPSHOT,
                subject=f"snapshot:{row_number}",
                time=timestamp,
                provenance=provenance.model_copy(
                    update={"selector": f"line:{row_number};creation_time"}
                ),
            )
        )
    return _source_result(
        source,
        ArtifactFamily.VSS,
        parser_id,
        observations,
        rows_examined=rows,
        rows_total=rows,
        partial_reason=(
            "VSS inventory has no normalized per-file historical timestamps"
            if raw.strip()
            else None
        ),
    )


def _indexed_request() -> ClockEvidenceRequest:
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    source_evidence: list[SourceEvidence] = []

    mft_rows = [source for source in sources if source.source_name.startswith("ez.mft")]
    for source in mft_rows:
        source_evidence.append(
            _mft_evidence(source, ctx.db.get_windows_by_source(source.source_name))
        )
    candidate_subjects = {
        observation.subject.casefold()
        for evidence in source_evidence
        for observation in evidence.observations
        if observation.kind is ObservationKind.MFT_SI_CREATED
    }
    for source in sources:
        windows = ctx.db.get_windows_by_source(source.source_name)
        if source.source_name.startswith("ez.usnjrnl"):
            source_evidence.append(_usn_evidence(source, windows, candidate_subjects))
        elif source.source_name.startswith("evtx."):
            source_evidence.append(_event_log_evidence(source, windows))
        elif source.source_name.startswith("vshadow.info"):
            source_evidence.append(_vss_evidence(source, windows))

    return ClockEvidenceRequest(
        case_id=ctx.db.get_case_metadata().case_id,
        sources=tuple(source_evidence),
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR)
def analyze_anti_forensics_clock() -> dict[str, object]:
    """Normalize indexed anti-forensics evidence and apply versioned clock rules.

    Existing MFTECmd MFT/USN, python-evtx line, and libvshadow inventory
    formats are parsed locally. Raw ``$LogFile`` and process/file correlation
    have no supported Adapter yet and are reported as ``UNSUPPORTED_VERSION``.
    """
    ctx = get_ctx()
    tool_call_id = make_tool_call_id()
    started = time.monotonic()
    result = analyze_clock_evidence(_indexed_request())
    payload = result.model_dump(mode="json")
    ctx.audit.log_tool_call(
        tool_call_id=tool_call_id,
        tool_name="analyze_anti_forensics_clock",
        params={},
        output_hash=hash_output(payload),
        duration_ms=(time.monotonic() - started) * 1000,
    )
    return {
        "tool_call_id": tool_call_id,
        "status": "success",
        **payload,
    }
