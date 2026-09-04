"""MCP Adapter from indexed evidence into the anti-forensics clock Module."""

from __future__ import annotations

import csv
import hashlib
import io
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath

from mulder.db import CaseDB
from mulder.models import CoverageMetadata, SourceRow, ToolOutcome, ToolOutcomeStatus, WindowRow
from mulder.packs.anti_forensics_clock import (
    ArtifactFamily,
    ClockAnalysisResult,
    ClockAnchor,
    ClockEvidenceRequest,
    ObservationKind,
    PreservedTime,
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
_MAX_INDEXED_SOURCES = 128
_MAX_SOURCE_ROWS = 100_000
_MAX_SOURCE_WINDOWS = 1_024
_MAX_SOURCE_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
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
_LOGFILE_SEQUENCE = ("LSN", "Lsn", "SequenceNumber", "Sequence Number")
_LOGFILE_TIMESTAMP = ("Timestamp", "TimeStamp", "EventTimestamp", "UpdateTimestamp")
_LOGFILE_ACTION = ("Operation", "Action", "RedoOperation", "TransactionType")
_FULL_PATH = ("FilePath", "FullPath", "Path")
_VSS_SNAPSHOT_ID = ("SnapshotId", "SnapshotID", "ShadowCopyId")
_VSS_CREATED = ("CreatedTimestamp", "FileCreatedTimestamp", "BirthTimestamp")
_VSS_SNAPSHOT_CREATED = ("SnapshotCreatedTimestamp", "SnapshotTimestamp")
_UNCERTAINTY = ("UncertaintyMs", "TimestampUncertaintyMs")
_PS_PID = ("PID", "Pid", "ProcessId")
_PS_IMAGE = ("ImageFileName", "Image", "Name")
_PS_CREATED = ("CreateTime", "Create Time")
_PS_EXITED = ("ExitTime", "Exit Time")
_CMD_PROCESS = ("Process", "ImageFileName", "Name")
_CMD_ARGS = ("Args", "CommandLine", "Command Line")
_ANCHOR_ID = ("AnchorId", "AnchorID")
_ANCHOR_SOURCE = ("SourceName", "Source")
_ANCHOR_SOURCE_TIME = ("SourceTimestamp", "SourceTime")
_ANCHOR_REFERENCE_TIME = ("ReferenceTimestamp", "ReferenceTime")
_ANCHOR_REFERENCE_SOURCE = ("ReferenceSource", "ReferenceClock")
_ANCHOR_SOURCE_UNCERTAINTY = ("SourceUncertaintyMs",)
_ANCHOR_REFERENCE_UNCERTAINTY = ("ReferenceUncertaintyMs",)
_FALSE_POSITIVE_PATHS = (
    "\\windows\\winsxs\\",
    "\\windows\\installer\\",
    "\\windows\\servicing\\",
    "\\windows\\softwaredistribution\\",
    "\\$recycle.bin\\",
    "\\system volume information\\",
    "\\windows\\assembly\\",
)
_FLS_LINE = re.compile(
    r"^\s*\S+\s+(?P<deleted>\*\s+)?(?P<inode>[^:]+):\s*(?P<path>.+?)\s*$"
)


class _UnsupportedAdapterInput(ValueError):
    """A recognized indexed source does not match its versioned schema."""


@dataclass(frozen=True)
class _ProcessRecord:
    row_number: int
    pid: int
    image_name: str
    created: PreservedTime


@dataclass(frozen=True)
class _CommandRecord:
    row_number: int
    process_name: str
    image_path: str


@dataclass(frozen=True)
class _DeletedFileRecord:
    source: SourceRow
    raw: str
    row_number: int
    inode: str
    path: str


@dataclass(frozen=True)
class _ClockAnchorAdapterResult:
    anchors: tuple[ClockAnchor, ...]
    outcome: ToolOutcome


def _first(headers: Sequence[str], candidates: Sequence[str]) -> str | None:
    return next((candidate for candidate in candidates if candidate in headers), None)


def _text_field(row: Mapping[str, str | None], name: str | None) -> str:
    """Return one CSV field as text without trusting a complete row shape."""
    if name is None:
        return ""
    return row.get(name) or ""


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


def _observation_id(
    source: SourceRow,
    row_number: int,
    kind: ObservationKind,
    qualifier: str = "",
) -> str:
    material = f"{source.source_hash}\0{row_number}\0{kind.value}\0{qualifier}".encode()
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


def _bounded_source_result(
    source: SourceRow,
    family: ArtifactFamily,
    parser_id: str,
    reason: str,
) -> SourceEvidence:
    return _source_result(
        source,
        family,
        parser_id,
        (),
        rows_examined=0,
        rows_total=max(source.line_count - 1, 0),
        partial_reason=reason,
    )


def _is_indexed_clock_source(source: SourceRow) -> bool:
    return source.source_name.startswith(
        (
            "ez.mft",
            "ez.usnjrnl",
            "ez.logfile",
            "ntfs.logfile",
            "evtx.",
            "vshadow.info",
            "vshadow.files",
            "volatility.pslist",
            "volatility.cmdline",
            "tsk.filelist",
            "clock.anchors",
            "clock.reference.",
        )
    )


def _bounded_source_windows(
    db: CaseDB,
    sources: Sequence[SourceRow],
) -> tuple[dict[int, tuple[WindowRow, ...]], dict[int, str], ToolOutcome | None]:
    """Load only recognized sources after SQL-side row/window/byte inventory checks."""
    recognized = [source for source in sources if _is_indexed_clock_source(source)]
    if len(recognized) > _MAX_INDEXED_SOURCES:
        reason = (
            f"indexed clock source limit exceeded: {len(recognized)} > "
            f"{_MAX_INDEXED_SOURCES}"
        )
        return {}, {source.source_id: reason for source in recognized}, ToolOutcome(
            status=ToolOutcomeStatus.PARTIAL,
            coverage=CoverageMetadata(
                rows_examined=0,
                rows_total=len(recognized),
                truncation_reason=reason,
            ),
            reason=reason,
        )

    limited: dict[int, str] = {}
    candidates: list[SourceRow] = []
    for source in recognized:
        if source.line_count > _MAX_SOURCE_ROWS:
            limited[source.source_id] = (
                f"source row limit exceeded: {source.line_count} > {_MAX_SOURCE_ROWS}"
            )
        else:
            candidates.append(source)

    inventory = db.get_window_inventory_by_sources(
        [source.source_name for source in candidates]
    )
    total_bytes = sum(byte_count for _count, byte_count in inventory.values())
    for source in candidates:
        window_count, byte_count = inventory[source.source_name]
        if window_count > _MAX_SOURCE_WINDOWS:
            limited[source.source_id] = (
                f"source window limit exceeded: {window_count} > {_MAX_SOURCE_WINDOWS}"
            )
        elif byte_count > _MAX_SOURCE_BYTES:
            limited[source.source_id] = (
                f"source byte limit exceeded: {byte_count} > {_MAX_SOURCE_BYTES}"
            )
    if total_bytes > _MAX_TOTAL_BYTES:
        reason = f"aggregate source byte limit exceeded: {total_bytes} > {_MAX_TOTAL_BYTES}"
        for source in candidates:
            limited.setdefault(source.source_id, reason)

    loadable = [source for source in candidates if source.source_id not in limited]
    capped = db.get_capped_windows_by_sources(
        [source.source_name for source in loadable],
        max_per_source=_MAX_SOURCE_WINDOWS,
    )
    windows = {
        source.source_id: tuple(capped[source.source_name][0]) for source in loadable
    }
    for source in recognized:
        windows.setdefault(source.source_id, ())

    if not limited:
        return windows, limited, None
    reasons = sorted(set(limited.values()))
    reason = "; ".join(reasons)
    examined_bytes = sum(
        inventory[source.source_name][1]
        for source in loadable
        if source.source_name in inventory
    )
    return windows, limited, ToolOutcome(
        status=ToolOutcomeStatus.PARTIAL,
        coverage=CoverageMetadata(
            bytes_examined=examined_bytes,
            bytes_total=total_bytes,
            rows_examined=len(loadable),
            rows_total=len(recognized),
            truncation_reason=reason,
        ),
        reason=reason,
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
    malformed = 0
    provenance = _provenance(source, raw, selector="csv:all", parser_id=parser_id)
    for row_number, row in enumerate(reader, start=2):
        rows += 1
        si = preserve_time(_text_field(row, si_name), normalization_rule="mftecmd-timestamp")
        fn = preserve_time(_text_field(row, fn_name), normalization_rule="mftecmd-timestamp")
        modified = (
            preserve_time(
                _text_field(row, modified_name), normalization_rule="mftecmd-timestamp"
            )
            if modified_name
            else None
        )
        name = _text_field(row, file_name).strip()
        parent = _text_field(row, parent_name).strip()
        subject = _normalize_windows_path(f"{parent}\\{name}" if parent else name)
        if si is None or fn is None or not subject:
            malformed += 1
            continue
        if any(path in subject.casefold() for path in _FALSE_POSITIVE_PATHS):
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
        rows_examined=rows - malformed,
        rows_total=rows,
        partial_reason=(
            f"{malformed} MFT rows lacked required typed values" if malformed else None
        ),
    )


def _parse_sequence(value: str) -> int | None:
    try:
        parsed = int(value.strip(), 0)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _parse_uncertainty(value: str, *, default: int = 1_000) -> int | None:
    if not value.strip():
        return default
    parsed = _parse_sequence(value)
    return parsed


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
    malformed = 0
    provenance = _provenance(source, raw, selector="csv:all", parser_id=parser_id)
    for row_number, row in enumerate(reader, start=2):
        rows += 1
        sequence = _parse_sequence(_text_field(row, sequence_name))
        timestamp = preserve_time(
            _text_field(row, timestamp_name), normalization_rule="mftecmd-usn-timestamp"
        )
        action = _text_field(row, reason_name).strip()
        name = _text_field(row, file_name).strip()
        parent = _text_field(row, parent_name).strip()
        subject = _normalize_windows_path(f"{parent}\\{name}" if parent else name)
        if sequence is None or timestamp is None or not action or not subject:
            malformed += 1
            continue
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
        rows_examined=rows - malformed,
        rows_total=rows,
        partial_reason=(
            f"{malformed} USN rows lacked required typed values" if malformed else None
        ),
    )


def _logfile_evidence(source: SourceRow, windows: Sequence[WindowRow]) -> SourceEvidence:
    parser_id = "ntfs-logfile-csv"
    raw = _raw_source(windows)
    reader = csv.DictReader(io.StringIO(raw))
    headers = [header.strip() for header in (reader.fieldnames or []) if header]
    sequence_name = _first(headers, _LOGFILE_SEQUENCE)
    timestamp_name = _first(headers, _LOGFILE_TIMESTAMP)
    action_name = _first(headers, _LOGFILE_ACTION)
    full_path_name = _first(headers, _FULL_PATH)
    file_name = _first(headers, _FILE_NAME)
    parent_name = _first(headers, _PARENT_PATH)
    if (
        sequence_name is None
        or timestamp_name is None
        or action_name is None
        or (full_path_name is None and file_name is None)
    ):
        return _source_result(
            source,
            ArtifactFamily.LOGFILE,
            parser_id,
            (),
            rows_examined=0,
            rows_total=max(source.line_count - 1, 0),
            unsupported_reason=(
                "$LogFile CSV schema lacks LSN, timestamp, operation, or file path columns"
            ),
        )

    observations: list[TemporalObservation] = []
    rows = 0
    malformed = 0
    provenance = _provenance(source, raw, selector="csv:all", parser_id=parser_id)
    for row_number, row in enumerate(reader, start=2):
        rows += 1
        sequence = _parse_sequence(row.get(sequence_name, ""))
        timestamp = preserve_time(
            row.get(timestamp_name, ""), normalization_rule="ntfs-logfile-timestamp"
        )
        action = row.get(action_name, "").strip()
        subject = _text_field(row, full_path_name).strip()
        if not subject:
            name = _text_field(row, file_name).strip()
            parent = _text_field(row, parent_name).strip()
            subject = f"{parent}\\{name}" if parent else name
        subject = _normalize_windows_path(subject)
        if sequence is None or timestamp is None or not action or not subject:
            malformed += 1
            continue
        attributes: dict[str, str | int | float | bool | None] = {}
        transaction_id = row.get("TransactionId", "").strip()
        if transaction_id:
            attributes["transaction_id"] = transaction_id
        observations.append(
            TemporalObservation(
                observation_id=_observation_id(
                    source, row_number, ObservationKind.LOGFILE_CHANGE
                ),
                kind=ObservationKind.LOGFILE_CHANGE,
                subject=subject,
                time=timestamp,
                provenance=provenance.model_copy(
                    update={"selector": f"csv:row={row_number};lsn={sequence}"}
                ),
                sequence_number=sequence,
                action=action,
                attributes=attributes,
            )
        )
    return _source_result(
        source,
        ArtifactFamily.LOGFILE,
        parser_id,
        observations,
        rows_examined=rows - malformed,
        rows_total=rows,
        partial_reason=(
            f"{malformed} $LogFile rows lacked required typed values" if malformed else None
        ),
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


def _vss_file_evidence(source: SourceRow, windows: Sequence[WindowRow]) -> SourceEvidence:
    parser_id = "vshadow-file-csv"
    raw = _raw_source(windows)
    reader = csv.DictReader(io.StringIO(raw))
    headers = [header.strip() for header in (reader.fieldnames or []) if header]
    snapshot_id_name = _first(headers, _VSS_SNAPSHOT_ID)
    path_name = _first(headers, _FULL_PATH)
    created_name = _first(headers, _VSS_CREATED)
    snapshot_created_name = _first(headers, _VSS_SNAPSHOT_CREATED)
    uncertainty_name = _first(headers, _UNCERTAINTY)
    if snapshot_id_name is None or path_name is None or created_name is None:
        return _source_result(
            source,
            ArtifactFamily.VSS,
            parser_id,
            (),
            rows_examined=0,
            rows_total=max(source.line_count - 1, 0),
            unsupported_reason=(
                "VSS per-file CSV schema lacks snapshot ID, file path, or creation timestamp"
            ),
        )

    observations: list[TemporalObservation] = []
    rows = 0
    malformed = 0
    provenance = _provenance(source, raw, selector="csv:all", parser_id=parser_id)
    for row_number, row in enumerate(reader, start=2):
        rows += 1
        snapshot_id = row.get(snapshot_id_name, "").strip()
        subject = _normalize_windows_path(_text_field(row, path_name))
        uncertainty = _parse_uncertainty(
            row.get(uncertainty_name, "") if uncertainty_name else ""
        )
        created = (
            preserve_time(
                row.get(created_name, ""),
                default_uncertainty_ms=uncertainty,
                normalization_rule="vshadow-file-created",
            )
            if uncertainty is not None
            else None
        )
        if not snapshot_id or not subject or created is None:
            malformed += 1
            continue
        observations.append(
            TemporalObservation(
                observation_id=_observation_id(
                    source, row_number, ObservationKind.VSS_FILE
                ),
                kind=ObservationKind.VSS_FILE,
                subject=subject,
                time=created,
                provenance=provenance.model_copy(
                    update={
                        "selector": (
                            f"csv:row={row_number};column={created_name};"
                            f"snapshot={snapshot_id}"
                        )
                    }
                ),
                attributes={"snapshot_id": snapshot_id, "timestamp_role": "created"},
            )
        )
        if snapshot_created_name and uncertainty is not None:
            snapshot_created = preserve_time(
                row.get(snapshot_created_name, ""),
                default_uncertainty_ms=uncertainty,
                normalization_rule="vshadow-snapshot-created",
            )
            if snapshot_created is not None:
                observations.append(
                    TemporalObservation(
                        observation_id=_observation_id(
                            source,
                            row_number,
                            ObservationKind.VSS_SNAPSHOT,
                            snapshot_id,
                        ),
                        kind=ObservationKind.VSS_SNAPSHOT,
                        subject=f"snapshot:{snapshot_id}",
                        time=snapshot_created,
                        provenance=provenance.model_copy(
                            update={
                                "selector": (
                                    f"csv:row={row_number};column={snapshot_created_name};"
                                    f"snapshot={snapshot_id}"
                                )
                            }
                        ),
                    )
                )
    return _source_result(
        source,
        ArtifactFamily.VSS,
        parser_id,
        observations,
        rows_examined=rows - malformed,
        rows_total=rows,
        partial_reason=(
            f"{malformed} VSS file rows lacked required typed values" if malformed else None
        ),
    )


def _normalize_windows_path(value: str) -> str:
    normalized = value.strip().strip('"').replace("/", "\\")
    if normalized.startswith("\\??\\"):
        normalized = normalized[4:]
    return str(PureWindowsPath(normalized)) if normalized else ""


def _filesystem_path_key(value: str) -> str:
    """Compare a Volatility drive path to an fls volume-relative path."""
    normalized = _normalize_windows_path(value)
    path = PureWindowsPath(normalized)
    without_drive = normalized[len(path.drive) :] if path.drive else normalized
    return without_drive.lstrip("\\").casefold()


def _command_image_path(arguments: str) -> str:
    value = arguments.strip()
    if not value:
        return ""
    if value.startswith('"'):
        closing = value.find('"', 1)
        token = value[1:closing] if closing >= 1 else ""
    else:
        token = value.split(maxsplit=1)[0]
    return _normalize_windows_path(token)


def _process_file_evidence(
    source: SourceRow,
    windows: Sequence[WindowRow],
    cmdline_source: SourceRow | None,
    cmdline_windows: Sequence[WindowRow],
    file_sources: Sequence[tuple[SourceRow, Sequence[WindowRow]]],
    *,
    dependency_reason: str | None = None,
) -> SourceEvidence:
    parser_id = "volatility-process-file-correlation"
    raw = _raw_source(windows)
    reader = csv.DictReader(io.StringIO(raw), delimiter="\t")
    headers = [header.strip() for header in (reader.fieldnames or []) if header]
    pid_name = _first(headers, _PS_PID)
    image_name = _first(headers, _PS_IMAGE)
    created_name = _first(headers, _PS_CREATED)
    exited_name = _first(headers, _PS_EXITED)
    if pid_name is None or image_name is None or created_name is None or exited_name is None:
        return _source_result(
            source,
            ArtifactFamily.PROCESS_FILE_STATE,
            parser_id,
            (),
            rows_examined=0,
            rows_total=max(source.line_count - 1, 0),
            unsupported_reason=(
                "Volatility pslist schema lacks PID, image, create-time, or exit-time columns"
            ),
        )
    if cmdline_source is None:
        return _source_result(
            source,
            ArtifactFamily.PROCESS_FILE_STATE,
            parser_id,
            (),
            rows_examined=0,
            rows_total=max(source.line_count - 1, 0),
            partial_reason=dependency_reason or (
                "running process rows are indexed, but matching Volatility cmdline "
                "evidence is unavailable"
            ),
        )

    processes: dict[int, _ProcessRecord] = {}
    process_rows = 0
    process_malformed = 0
    for row_number, row in enumerate(reader, start=2):
        process_rows += 1
        pid = _parse_sequence(row.get(pid_name, ""))
        image = row.get(image_name, "").strip()
        created = preserve_time(
            row.get(created_name, ""), normalization_rule="volatility-process-created"
        )
        exited = row.get(exited_name, "").strip()
        if pid is None or not image or created is None:
            process_malformed += 1
            continue
        if exited and exited.casefold() not in {"n/a", "none", "-"}:
            continue
        processes[pid] = _ProcessRecord(row_number, pid, image, created)

    cmdline_raw = _raw_source(cmdline_windows)
    cmdline_reader = csv.DictReader(io.StringIO(cmdline_raw), delimiter="\t")
    cmdline_headers = [
        header.strip() for header in (cmdline_reader.fieldnames or []) if header
    ]
    cmd_pid_name = _first(cmdline_headers, _PS_PID)
    command_process_name = _first(cmdline_headers, _CMD_PROCESS)
    arguments_name = _first(cmdline_headers, _CMD_ARGS)
    if cmd_pid_name is None or command_process_name is None or arguments_name is None:
        return _source_result(
            source,
            ArtifactFamily.PROCESS_FILE_STATE,
            parser_id,
            (),
            rows_examined=0,
            rows_total=process_rows,
            unsupported_reason=(
                "Volatility cmdline schema lacks PID, process, or command-line columns"
            ),
        )

    commands: dict[int, _CommandRecord] = {}
    malformed = process_malformed
    for row_number, row in enumerate(cmdline_reader, start=2):
        pid = _parse_sequence(row.get(cmd_pid_name, ""))
        process_name = row.get(command_process_name, "").strip()
        image_path = _command_image_path(row.get(arguments_name, ""))
        if pid is None or not process_name or not image_path:
            malformed += 1
            continue
        commands[pid] = _CommandRecord(row_number, process_name, image_path)

    deleted_by_path: dict[str, _DeletedFileRecord] = {}
    file_rows = 0
    unparsed_file_rows = 0
    for file_source, source_windows in file_sources:
        file_raw = _raw_source(source_windows)
        for row_number, line in enumerate(file_raw.splitlines(), start=1):
            if not line.strip():
                continue
            file_rows += 1
            match = _FLS_LINE.match(line)
            if match is None:
                unparsed_file_rows += 1
                continue
            if match.group("deleted") is None:
                continue
            path = _normalize_windows_path(match.group("path"))
            deleted_by_path[_filesystem_path_key(path)] = _DeletedFileRecord(
                source=file_source,
                raw=file_raw,
                row_number=row_number,
                inode=match.group("inode").strip(),
                path=path,
            )

    observations: list[TemporalObservation] = []
    provenance = _provenance(source, raw, selector="tsv:all", parser_id=parser_id)
    cmdline_provenance = _provenance(
        cmdline_source,
        cmdline_raw,
        selector="tsv:all",
        parser_id="volatility-cmdline",
    )
    for pid, process in sorted(processes.items()):
        command = commands.get(pid)
        if command is None:
            continue
        basename = PureWindowsPath(command.image_path).name
        path_mismatch = basename.casefold() != process.image_name.casefold()
        deleted = deleted_by_path.get(_filesystem_path_key(command.image_path))
        if deleted is None and not path_mismatch:
            continue
        if deleted is not None and path_mismatch:
            action = "running_image_deleted_and_path_mismatch"
        elif deleted is not None:
            action = "running_image_deleted"
        else:
            action = "running_image_path_mismatch"
        attributes: dict[str, str | int | float | bool | None] = {
            "pid": pid,
            "process_name": process.image_name,
            "image_path": command.image_path,
            "running": True,
            "deleted": deleted is not None,
            "path_mismatch": path_mismatch,
            "cmdline_source_id": str(cmdline_source.source_id),
            "cmdline_selector": f"tsv:row={command.row_number};pid={pid}",
            "cmdline_raw_digest": cmdline_provenance.raw_digest,
        }
        if deleted is not None:
            deleted_provenance = _provenance(
                deleted.source,
                deleted.raw,
                selector=(
                    f"line:{deleted.row_number};inode={deleted.inode}"
                ),
                parser_id="sleuthkit-fls",
            )
            attributes.update(
                {
                    "deleted_file_source_id": str(deleted.source.source_id),
                    "deleted_file_selector": deleted_provenance.selector,
                    "deleted_file_raw_digest": deleted_provenance.raw_digest,
                }
            )
        observations.append(
            TemporalObservation(
                observation_id=_observation_id(
                    source, process.row_number, ObservationKind.PROCESS_FILE_MISMATCH
                ),
                kind=ObservationKind.PROCESS_FILE_MISMATCH,
                subject=command.image_path,
                time=process.created,
                provenance=provenance.model_copy(
                    update={"selector": f"tsv:row={process.row_number};pid={pid}"}
                ),
                action=action,
                attributes=attributes,
            )
        )

    limitations: list[str] = []
    if dependency_reason:
        limitations.append(dependency_reason)
    if not file_sources:
        limitations.append("deleted-file comparison is unavailable without tsk.filelist")
    if unparsed_file_rows:
        limitations.append(f"{unparsed_file_rows}/{file_rows} filesystem rows were unparsed")
    if malformed:
        limitations.append(f"{malformed} process/cmdline rows lacked required typed values")
    return _source_result(
        source,
        ArtifactFamily.PROCESS_FILE_STATE,
        parser_id,
        observations,
        rows_examined=process_rows - process_malformed,
        rows_total=process_rows,
        partial_reason="; ".join(limitations) or None,
    )


def _partner_source(
    source: SourceRow,
    candidates: Sequence[SourceRow],
    *,
    source_prefix: str,
    partner_prefix: str,
) -> tuple[SourceRow | None, str | None]:
    suffix = source.source_name.removeprefix(source_prefix)
    matches = [
        candidate
        for candidate in candidates
        if candidate.source_name == f"{partner_prefix}{suffix}"
    ]
    if len(matches) == 1:
        return matches[0], None
    if not matches:
        return None, f"matching {partner_prefix}{suffix} source is unavailable"
    return None, f"matching {partner_prefix}{suffix} source is ambiguous"


def _named_acquisition_scope(source_name: str, prefix: str) -> str:
    """Return the explicit suffix scope, ignoring TSK partition suffixes."""
    suffix = source_name.removeprefix(prefix).removeprefix(".")
    if prefix == "tsk.filelist":
        parts = suffix.split(".") if suffix else []
        if parts and re.fullmatch(r"p\d+", parts[-1]):
            parts.pop()
        suffix = ".".join(parts)
    return suffix


def _same_acquisition_scope(process_source: SourceRow, file_source: SourceRow) -> bool:
    """Require an explicit matching scope or a common acquisition directory."""
    process_scope = _named_acquisition_scope(
        process_source.source_name, "volatility.pslist"
    )
    file_scope = _named_acquisition_scope(file_source.source_name, "tsk.filelist")
    if process_scope or file_scope:
        return bool(process_scope) and process_scope == file_scope
    return Path(process_source.source_path).parent == Path(file_source.source_path).parent


def _clock_anchors(
    anchor_sources: Sequence[SourceRow],
    source_windows: Mapping[int, Sequence[WindowRow]],
    normalized_sources: Sequence[SourceEvidence],
    indexed_sources: Sequence[SourceRow],
    limited_sources: Mapping[int, str],
) -> _ClockAnchorAdapterResult:
    targets_by_name: dict[str, SourceRow] = {}
    indexed_by_name: dict[str, list[SourceRow]] = {}
    for source in indexed_sources:
        indexed_by_name.setdefault(source.source_name, []).append(source)
    normalized_ids = {source.source_id for source in normalized_sources}
    for source in indexed_sources:
        if str(source.source_id) not in normalized_ids:
            continue
        if source.source_name in targets_by_name:
            continue
        targets_by_name[source.source_name] = source

    anchors: list[ClockAnchor] = []
    seen_anchor_ids: set[str] = set()
    rows_total = 0
    malformed = 0
    schema_errors: list[str] = []
    for anchor_source in anchor_sources:
        if anchor_source.source_id in limited_sources:
            schema_errors.append(limited_sources[anchor_source.source_id])
            rows_total += max(anchor_source.line_count - 1, 0)
            continue
        raw = _raw_source(source_windows[anchor_source.source_id])
        reader = csv.DictReader(io.StringIO(raw))
        headers = [header.strip() for header in (reader.fieldnames or []) if header]
        anchor_id_name = _first(headers, _ANCHOR_ID)
        source_name = _first(headers, _ANCHOR_SOURCE)
        source_time_name = _first(headers, _ANCHOR_SOURCE_TIME)
        reference_time_name = _first(headers, _ANCHOR_REFERENCE_TIME)
        reference_source_name = _first(headers, _ANCHOR_REFERENCE_SOURCE)
        source_uncertainty_name = _first(headers, _ANCHOR_SOURCE_UNCERTAINTY)
        reference_uncertainty_name = _first(headers, _ANCHOR_REFERENCE_UNCERTAINTY)
        required = (
            anchor_id_name,
            source_name,
            source_time_name,
            reference_time_name,
            reference_source_name,
            source_uncertainty_name,
            reference_uncertainty_name,
        )
        if any(name is None for name in required):
            schema_errors.append(
                "clock anchor CSV schema lacks IDs, source/reference timestamps, "
                "reference identity, or uncertainty columns"
            )
            rows_total += max(anchor_source.line_count - 1, 0)
            continue
        assert anchor_id_name is not None
        assert source_name is not None
        assert source_time_name is not None
        assert reference_time_name is not None
        assert reference_source_name is not None
        assert source_uncertainty_name is not None
        assert reference_uncertainty_name is not None
        calibration_provenance = _provenance(
            anchor_source,
            raw,
            selector="csv:all",
            parser_id="clock-anchor-csv",
        )
        for row_number, row in enumerate(reader, start=2):
            rows_total += 1
            anchor_id = _text_field(row, anchor_id_name).strip()
            target_name = _text_field(row, source_name).strip()
            reference_name = _text_field(row, reference_source_name).strip()
            target = targets_by_name.get(target_name)
            references = indexed_by_name.get(reference_name, [])
            reference = references[0] if len(references) == 1 else None
            source_uncertainty = _parse_sequence(
                _text_field(row, source_uncertainty_name)
            )
            reference_uncertainty = _parse_sequence(
                _text_field(row, reference_uncertainty_name)
            )
            if (
                not anchor_id
                or anchor_id in seen_anchor_ids
                or target is None
                or reference is None
                or reference.source_id in limited_sources
                or reference.source_id == target.source_id
                or reference.source_id == anchor_source.source_id
                or reference.source_hash == target.source_hash
                or reference.source_hash == anchor_source.source_hash
                or target.source_hash == anchor_source.source_hash
                or source_uncertainty is None
                or reference_uncertainty is None
            ):
                malformed += 1
                continue
            source_time = preserve_time(
                _text_field(row, source_time_name),
                default_uncertainty_ms=source_uncertainty,
                normalization_rule="clock-anchor-source-time",
            )
            reference_time = preserve_time(
                _text_field(row, reference_time_name),
                default_uncertainty_ms=reference_uncertainty,
                normalization_rule="clock-anchor-reference-time",
            )
            if source_time is None or reference_time is None:
                malformed += 1
                continue
            selector = (
                f"csv:row={row_number};anchor={anchor_id};reference={reference_name}"
            )
            try:
                reference_raw = _raw_source(source_windows[reference.source_id])
                anchors.append(
                    ClockAnchor(
                        anchor_id=anchor_id,
                        source_id=str(target.source_id),
                        source_time=source_time,
                        reference_time=reference_time,
                        reference_provenance=_provenance(
                            reference,
                            reference_raw,
                            selector="source:all",
                            parser_id="clock-reference-source",
                        ),
                        calibration_provenance=calibration_provenance.model_copy(
                            update={"selector": selector}
                        ),
                    )
                )
                seen_anchor_ids.add(anchor_id)
            except ValueError:
                malformed += 1

    reasons = list(dict.fromkeys(schema_errors))
    if malformed:
        reasons.append(
            f"{malformed}/{rows_total} clock anchor rows were malformed or unresolvable"
        )
    if reasons:
        status = (
            ToolOutcomeStatus.PARTIAL
            if anchors or malformed
            else ToolOutcomeStatus.UNSUPPORTED_VERSION
        )
        reason = "; ".join(reasons)
    elif anchors:
        status = ToolOutcomeStatus.SUCCESS_NONEMPTY
        reason = None
    else:
        status = ToolOutcomeStatus.SUCCESS_EMPTY
        reason = None
    return _ClockAnchorAdapterResult(
        anchors=tuple(anchors),
        outcome=ToolOutcome(
            status=status,
            coverage=CoverageMetadata(
                rows_examined=len(anchors),
                rows_total=rows_total,
                parser_version=_NORMALIZER_VERSION,
            ),
            reason=reason,
        ),
    )


def _combine_adapter_outcomes(
    loading: ToolOutcome | None,
    anchors: ToolOutcome,
) -> ToolOutcome:
    """Combine independent adapter stages without hiding either limitation."""
    if loading is None:
        return anchors
    if anchors.status in {
        ToolOutcomeStatus.SUCCESS_EMPTY,
        ToolOutcomeStatus.SUCCESS_NONEMPTY,
    }:
        return loading
    reasons = [reason for reason in (loading.reason, anchors.reason) if reason]
    return ToolOutcome(
        status=ToolOutcomeStatus.PARTIAL,
        coverage=CoverageMetadata(
            bytes_examined=loading.coverage.bytes_examined,
            bytes_total=loading.coverage.bytes_total,
            rows_examined=loading.coverage.rows_examined,
            rows_total=loading.coverage.rows_total,
            truncation_reason=loading.coverage.truncation_reason,
            parser_version=_NORMALIZER_VERSION,
        ),
        reason="; ".join(dict.fromkeys(reasons)) or None,
    )


def _indexed_request() -> ClockEvidenceRequest:
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    windows_by_source, limited_sources, load_outcome = _bounded_source_windows(
        ctx.db, sources
    )
    for source in sources:
        windows_by_source.setdefault(source.source_id, ())
    source_evidence: list[SourceEvidence] = []

    mft_rows = [source for source in sources if source.source_name.startswith("ez.mft")]
    for source in mft_rows:
        if reason := limited_sources.get(source.source_id):
            source_evidence.append(
                _bounded_source_result(
                    source, ArtifactFamily.MFT, "mftecmd-si-fn", reason
                )
            )
        else:
            source_evidence.append(
                _mft_evidence(source, windows_by_source[source.source_id])
            )
    candidate_subjects = {
        observation.subject.casefold()
        for evidence in source_evidence
        for observation in evidence.observations
        if observation.kind is ObservationKind.MFT_SI_CREATED
    }
    for source in sources:
        windows = windows_by_source[source.source_id]
        if source.source_name.startswith("ez.usnjrnl"):
            if reason := limited_sources.get(source.source_id):
                source_evidence.append(
                    _bounded_source_result(
                        source, ArtifactFamily.USN, "mftecmd-usn", reason
                    )
                )
            else:
                source_evidence.append(_usn_evidence(source, windows, candidate_subjects))
        elif source.source_name.startswith(("ez.logfile", "ntfs.logfile")):
            if reason := limited_sources.get(source.source_id):
                source_evidence.append(
                    _bounded_source_result(
                        source, ArtifactFamily.LOGFILE, "logfile-csv", reason
                    )
                )
            else:
                source_evidence.append(_logfile_evidence(source, windows))
        elif source.source_name.startswith("evtx."):
            if reason := limited_sources.get(source.source_id):
                source_evidence.append(
                    _bounded_source_result(
                        source, ArtifactFamily.EVENT_LOG, "python-evtx-lines", reason
                    )
                )
            else:
                source_evidence.append(_event_log_evidence(source, windows))
        elif source.source_name.startswith("vshadow.info"):
            if reason := limited_sources.get(source.source_id):
                source_evidence.append(
                    _bounded_source_result(
                        source, ArtifactFamily.VSS, "vshadowinfo-csv", reason
                    )
                )
            else:
                source_evidence.append(_vss_evidence(source, windows))
        elif source.source_name.startswith("vshadow.files"):
            if reason := limited_sources.get(source.source_id):
                source_evidence.append(
                    _bounded_source_result(
                        source, ArtifactFamily.VSS, "vshadow-files-csv", reason
                    )
                )
            else:
                source_evidence.append(_vss_file_evidence(source, windows))

    pslist_sources = [
        source for source in sources if source.source_name.startswith("volatility.pslist")
    ]
    cmdline_sources = [
        source for source in sources if source.source_name.startswith("volatility.cmdline")
    ]
    tsk_sources = [
        source for source in sources if source.source_name.startswith("tsk.filelist")
    ]
    for source in pslist_sources:
        if limit_reason := limited_sources.get(source.source_id):
            source_evidence.append(
                _bounded_source_result(
                    source,
                    ArtifactFamily.PROCESS_FILE_STATE,
                    "volatility-process-file-correlation",
                    limit_reason,
                )
            )
            continue
        partner, reason = _partner_source(
            source,
            cmdline_sources,
            source_prefix="volatility.pslist",
            partner_prefix="volatility.cmdline",
        )
        if partner is not None and partner.source_id in limited_sources:
            reason = limited_sources[partner.source_id]
            partner = None
        scoped_tsk_sources = [
            item for item in tsk_sources if _same_acquisition_scope(source, item)
        ]
        bounded_tsk_reasons = [
            limited_sources[item.source_id]
            for item in scoped_tsk_sources
            if item.source_id in limited_sources
        ]
        scoped_tsk_sources = [
            item for item in scoped_tsk_sources if item.source_id not in limited_sources
        ]
        file_sources = [
            (item, windows_by_source[item.source_id]) for item in scoped_tsk_sources
        ]
        if bounded_tsk_reasons:
            reason = (
                (reason + "; " if reason else "")
                + "; ".join(sorted(set(bounded_tsk_reasons)))
            )
        if tsk_sources and not scoped_tsk_sources:
            reason = (
                (reason + "; " if reason else "")
                + "matching tsk.filelist acquisition scope is unavailable"
            )
        source_evidence.append(
            _process_file_evidence(
                source,
                windows_by_source[source.source_id],
                partner,
                windows_by_source[partner.source_id] if partner else (),
                file_sources,
                dependency_reason=reason,
            )
        )

    anchor_result = _clock_anchors(
        [source for source in sources if source.source_name.startswith("clock.anchors")],
        windows_by_source,
        source_evidence,
        sources,
        limited_sources,
    )
    if (
        load_outcome is None
        and anchor_result.outcome.status is ToolOutcomeStatus.UNSUPPORTED_VERSION
    ):
        raise _UnsupportedAdapterInput(
            anchor_result.outcome.reason or "clock anchor schema is unsupported"
        )
    adapter_outcome = _combine_adapter_outcomes(load_outcome, anchor_result.outcome)

    try:
        return ClockEvidenceRequest(
            case_id=ctx.db.get_case_metadata().case_id,
            sources=tuple(source_evidence),
            clock_anchors=anchor_result.anchors,
            adapter_outcome=adapter_outcome,
        )
    except ValueError as exc:
        raise _UnsupportedAdapterInput(
            f"indexed clock evidence violates the versioned schema: {exc}"
        ) from exc


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR)
def analyze_anti_forensics_clock() -> dict[str, object]:
    """Normalize indexed anti-forensics evidence and apply versioned clock rules.

    Supports MFTECmd MFT/USN, parsed ``$LogFile`` CSV, python-evtx lines,
    Volatility/TSK process-file correlation, VSS inventory/per-file CSV, and
    explicit independent clock-anchor CSV. Recognized schema drift remains loud.
    """
    ctx = get_ctx()
    tool_call_id = make_tool_call_id()
    started = time.monotonic()
    try:
        result = analyze_clock_evidence(_indexed_request())
    except _UnsupportedAdapterInput as exc:
        result = ClockAnalysisResult(
            case_id=ctx.db.get_case_metadata().case_id,
            outcome=ToolOutcome(
                status=ToolOutcomeStatus.UNSUPPORTED_VERSION,
                reason=str(exc),
            ),
            coverage=(),
            clock_anchors=(),
            clock_models=(),
            observations=(),
            findings=(),
        )
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
