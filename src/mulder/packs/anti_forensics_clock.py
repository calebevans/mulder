"""Normalize and assess anti-forensics and clock evidence.

The Interface accepts one strict, versioned request and returns preserved
observations, typed coverage, clock calibration, and deterministic findings.
Raw strings remain data: presentation or instruction-shaped content is carried
as provenance flags and never influences a finding.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from enum import Enum
from statistics import median
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from mulder.models import CoverageMetadata, JsonScalar, ToolOutcome, ToolOutcomeStatus
from mulder.security.evidence_envelope import EvidenceFlag

CLOCK_EVIDENCE_SCHEMA: Literal["mulder.anti-forensics-clock"] = (
    "mulder.anti-forensics-clock"
)
CLOCK_EVIDENCE_SCHEMA_VERSION: Literal[1] = 1
CLOCK_ANALYSIS_VERSION: Literal["1.0"] = "1.0"

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
_TIMESTOMP_THRESHOLD_MS = 10_000
_UNKNOWN_TIMEZONE_UNCERTAINTY_MS = 12 * 60 * 60 * 1000
_TIMESTOMP_FALSE_POSITIVE_PATHS = (
    "\\windows\\winsxs\\",
    "\\windows\\installer\\",
    "\\windows\\servicing\\",
    "\\windows\\softwaredistribution\\",
    "\\$recycle.bin\\",
    "\\system volume information\\",
    "\\windows\\assembly\\",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class ArtifactFamily(str, Enum):
    """Evidence families whose coverage is always made explicit."""

    MFT = "mft"
    USN = "usn"
    LOGFILE = "logfile"
    EVENT_LOG = "event_log"
    PROCESS_FILE_STATE = "process_file_state"
    VSS = "vss"


class ObservationKind(str, Enum):
    """Normalized facts understood by the anti-forensics analysis."""

    MFT_SI_CREATED = "mft_si_created"
    MFT_FN_CREATED = "mft_fn_created"
    MFT_SI_MODIFIED = "mft_si_modified"
    USN_CHANGE = "usn_change"
    LOGFILE_CHANGE = "logfile_change"
    EVENT_LOG_CLEAR = "event_log_clear"
    PROCESS_FILE_MISMATCH = "process_file_mismatch"
    VSS_FILE = "vss_file"
    VSS_SNAPSHOT = "vss_snapshot"


class TimeBasis(str, Enum):
    """How an original timestamp acquired its UTC interpretation."""

    EXPLICIT_UTC = "explicit_utc"
    EXPLICIT_OFFSET = "explicit_offset"
    SOURCE_DECLARED = "source_declared"
    UNKNOWN_ASSUMED_UTC = "unknown_assumed_utc"


class TemporalProvenance(_StrictModel):
    """Exact source coordinates and parser identity for one observation."""

    source_id: str = Field(pattern=_ID_PATTERN)
    source_name: str = Field(min_length=1)
    selector: str = Field(min_length=1)
    raw_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    parser_id: str = Field(pattern=_ID_PATTERN)
    parser_version: str = Field(min_length=1)
    independence_key: str = Field(min_length=1)
    evidence_flags: tuple[EvidenceFlag, ...] = ()


class PreservedTime(_StrictModel):
    """Original and normalized time with explicit uncertainty."""

    original: str = Field(min_length=1)
    normalized_utc: str = Field(min_length=1)
    basis: TimeBasis
    uncertainty_ms: int = Field(ge=0)
    normalization_rule: str = Field(pattern=_ID_PATTERN)
    normalization_version: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_time(self) -> PreservedTime:
        _parse_utc(self.normalized_utc)
        if (
            self.basis is TimeBasis.UNKNOWN_ASSUMED_UTC
            and self.uncertainty_ms < _UNKNOWN_TIMEZONE_UNCERTAINTY_MS
        ):
            raise ValueError(
                "unknown timezone assumptions require at least 12 hours uncertainty"
            )
        return self


class TemporalObservation(_StrictModel):
    """One normalized fact; free text is retained only as inert attributes."""

    observation_id: str = Field(pattern=_ID_PATTERN)
    kind: ObservationKind
    subject: str = Field(min_length=1)
    time: PreservedTime
    provenance: TemporalProvenance
    sequence_number: int | None = Field(default=None, ge=0)
    action: str | None = None
    attributes: Mapping[str, JsonScalar] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_kind_fields(self) -> TemporalObservation:
        if self.kind in {ObservationKind.USN_CHANGE, ObservationKind.LOGFILE_CHANGE}:
            if self.sequence_number is None:
                raise ValueError(f"{self.kind.value} requires sequence_number")
            if not self.action:
                raise ValueError(f"{self.kind.value} requires action")
        if self.kind is ObservationKind.EVENT_LOG_CLEAR and self.action not in {
            "security_log_cleared",
            "system_log_cleared",
        }:
            raise ValueError("event_log_clear requires a recognized clear action")
        if self.kind is ObservationKind.PROCESS_FILE_MISMATCH and not self.action:
            raise ValueError("process_file_mismatch requires an action")
        return self


class SourceEvidence(_StrictModel):
    """One parser/source result and the observations it actually produced."""

    source_id: str = Field(pattern=_ID_PATTERN)
    family: ArtifactFamily
    parser_id: str = Field(pattern=_ID_PATTERN)
    parser_version: str = Field(min_length=1)
    status: ToolOutcomeStatus
    reason: str | None = None
    rows_examined: int = Field(ge=0)
    rows_total: int | None = Field(default=None, ge=0)
    observations: tuple[TemporalObservation, ...] = ()

    @model_validator(mode="after")
    def _check_outcome(self) -> SourceEvidence:
        if self.rows_total is not None and self.rows_examined > self.rows_total:
            raise ValueError("rows_examined cannot exceed rows_total")
        if self.status is ToolOutcomeStatus.SUCCESS_NONEMPTY and not self.observations:
            raise ValueError("SUCCESS_NONEMPTY source evidence requires observations")
        if self.status is ToolOutcomeStatus.SUCCESS_EMPTY and self.observations:
            raise ValueError("SUCCESS_EMPTY source evidence cannot carry observations")
        if any(item.provenance.source_id != self.source_id for item in self.observations):
            raise ValueError("observation source_id must match its SourceEvidence")
        return self


class ClockAnchor(_StrictModel):
    """A source-clock reading paired with an independent reference clock."""

    anchor_id: str = Field(pattern=_ID_PATTERN)
    source_id: str = Field(pattern=_ID_PATTERN)
    source_time: PreservedTime
    reference_time: PreservedTime
    reference_record_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    reference_provenance: TemporalProvenance
    calibration_provenance: TemporalProvenance | None = None


class ClockEvidenceRequest(_StrictModel):
    """Complete normalized input to the analysis Interface."""

    schema_name: Literal["mulder.anti-forensics-clock"] = Field(
        default=CLOCK_EVIDENCE_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = CLOCK_EVIDENCE_SCHEMA_VERSION
    case_id: str = Field(min_length=1)
    sources: tuple[SourceEvidence, ...]
    clock_anchors: tuple[ClockAnchor, ...] = ()
    adapter_outcome: ToolOutcome | None = None

    @model_validator(mode="after")
    def _check_graph(self) -> ClockEvidenceRequest:
        source_ids = [source.source_id for source in self.sources]
        observation_ids = [
            observation.observation_id
            for source in self.sources
            for observation in source.observations
        ]
        anchor_ids = [anchor.anchor_id for anchor in self.clock_anchors]
        for values, label in (
            (source_ids, "source IDs"),
            (observation_ids, "observation IDs"),
            (anchor_ids, "clock anchor IDs"),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"duplicate {label}")
        unknown_anchor_sources = {
            anchor.source_id for anchor in self.clock_anchors
        } - set(source_ids)
        if unknown_anchor_sources:
            raise ValueError(
                f"clock anchors reference unknown sources: {sorted(unknown_anchor_sources)!r}"
            )
        return self


class SourceCoverage(_StrictModel):
    """Typed coverage for one required artifact family and optional source."""

    family: ArtifactFamily
    source_id: str | None = None
    parser_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    outcome: ToolOutcome


class SourceClockModel(_StrictModel):
    """Estimated source-clock correction and its limitations."""

    source_id: str
    outcome: ToolOutcome
    source_reference_utc: str | None = None
    offset_ms: int | None = None
    drift_ppm: float | None = None
    uncertainty_ms: int | None = Field(default=None, ge=0)
    anchor_ids: tuple[str, ...] = ()


class TemporalFinding(_StrictModel):
    """One versioned and justified conclusion over normalized observations."""

    finding_id: str = Field(pattern=_ID_PATTERN)
    finding_type: Literal[
        "timestomp",
        "usn_order_anomaly",
        "log_clear",
        "process_file_mismatch",
    ]
    state: Literal["indicated", "confirmed"]
    subject: str = Field(min_length=1)
    rule_id: str = Field(pattern=_ID_PATTERN)
    rule_version: str = Field(min_length=1)
    justification: str = Field(min_length=1)
    observation_ids: tuple[str, ...] = Field(min_length=1)
    independent_witness_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_confirmation(self) -> TemporalFinding:
        if len(set(self.observation_ids)) != len(self.observation_ids):
            raise ValueError("duplicate finding observation IDs")
        if len(set(self.independent_witness_ids)) != len(self.independent_witness_ids):
            raise ValueError("duplicate independent witness IDs")
        if set(self.observation_ids) & set(self.independent_witness_ids):
            raise ValueError("an observation cannot also be its own independent witness")
        if self.finding_type == "timestomp" and self.state == "confirmed":
            explicit_rule = (
                self.rule_id,
                self.rule_version,
            ) == ("ntfs-si-after-modified", "1.0")
            if not self.independent_witness_ids and not explicit_rule:
                raise ValueError(
                    "confirmed timestomp requires an independent witness or explicit rule"
                )
        return self


class ClockAnalysisResult(_StrictModel):
    """Deterministic analysis output with no implicit clean state."""

    schema_version: Literal[1] = 1
    analysis_version: Literal["1.0"] = CLOCK_ANALYSIS_VERSION
    case_id: str
    outcome: ToolOutcome
    adapter_outcome: ToolOutcome | None = None
    coverage: tuple[SourceCoverage, ...]
    clock_anchors: tuple[ClockAnchor, ...]
    clock_models: tuple[SourceClockModel, ...]
    observations: tuple[TemporalObservation, ...]
    findings: tuple[TemporalFinding, ...]

    @model_validator(mode="after")
    def _check_finding_graph(self) -> ClockAnalysisResult:
        observations = {item.observation_id: item for item in self.observations}
        anchors = {item.anchor_id: item for item in self.clock_anchors}
        for model in self.clock_models:
            missing_anchors = set(model.anchor_ids) - anchors.keys()
            if missing_anchors:
                raise ValueError(
                    f"clock model {model.source_id!r} references unknown anchors: "
                    f"{sorted(missing_anchors)!r}"
                )
            wrong_source = [
                anchor_id
                for anchor_id in model.anchor_ids
                if anchors[anchor_id].source_id != model.source_id
            ]
            if wrong_source:
                raise ValueError(
                    f"clock model {model.source_id!r} references anchors for another "
                    f"source: {sorted(wrong_source)!r}"
                )
        for finding in self.findings:
            referenced = set(finding.observation_ids) | set(
                finding.independent_witness_ids
            )
            missing = referenced - observations.keys()
            if missing:
                raise ValueError(
                    f"finding {finding.finding_id!r} references unknown observations: "
                    f"{sorted(missing)!r}"
                )
            if finding.finding_type != "timestomp" or not finding.independent_witness_ids:
                continue
            primary_keys = {
                observations[observation_id].provenance.independence_key
                for observation_id in finding.observation_ids
            }
            for witness_id in finding.independent_witness_ids:
                witness = observations[witness_id]
                if witness.kind not in {
                    ObservationKind.USN_CHANGE,
                    ObservationKind.LOGFILE_CHANGE,
                    ObservationKind.VSS_FILE,
                }:
                    raise ValueError(
                        f"timestomp witness {witness_id!r} has an unsupported kind"
                    )
                if witness.provenance.independence_key in primary_keys:
                    raise ValueError(
                        f"timestomp witness {witness_id!r} is not independent"
                    )
        return self


def _parse_utc(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("normalized_utc must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def preserve_time(
    original: str,
    *,
    default_uncertainty_ms: int = 1_000,
    normalization_rule: str = "iso8601",
    normalization_version: str = "1.0",
) -> PreservedTime | None:
    """Parse a known timestamp shape without discarding its original text."""
    value = original.strip()
    if not value:
        return None
    parsed: datetime | None = None
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ):
        try:
            parsed = datetime.strptime(value, fmt)
            break
        except ValueError:
            continue
    if parsed is None:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    if parsed.tzinfo is None:
        basis = TimeBasis.UNKNOWN_ASSUMED_UTC
        uncertainty = max(default_uncertainty_ms, _UNKNOWN_TIMEZONE_UNCERTAINTY_MS)
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        offset = parsed.utcoffset()
        basis = (
            TimeBasis.EXPLICIT_UTC
            if offset == timedelta(0)
            else TimeBasis.EXPLICIT_OFFSET
        )
        uncertainty = default_uncertainty_ms
    return PreservedTime(
        original=original,
        normalized_utc=parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        basis=basis,
        uncertainty_ms=uncertainty,
        normalization_rule=normalization_rule,
        normalization_version=normalization_version,
    )


def _clock_models(request: ClockEvidenceRequest) -> tuple[SourceClockModel, ...]:
    by_source: dict[str, list[ClockAnchor]] = defaultdict(list)
    for anchor in request.clock_anchors:
        by_source[anchor.source_id].append(anchor)

    models: list[SourceClockModel] = []
    for source in sorted(request.sources, key=lambda item: item.source_id):
        anchors = sorted(
            by_source.get(source.source_id, []),
            key=lambda item: (_parse_utc(item.source_time.normalized_utc), item.anchor_id),
        )
        if not anchors:
            models.append(
                SourceClockModel(
                    source_id=source.source_id,
                    outcome=ToolOutcome(
                        status=ToolOutcomeStatus.UNAVAILABLE,
                        reason="no independent clock anchors supplied",
                    ),
                )
            )
            continue

        offsets_ms = [
            round(
                (
                    _parse_utc(anchor.reference_time.normalized_utc)
                    - _parse_utc(anchor.source_time.normalized_utc)
                ).total_seconds()
                * 1000
            )
            for anchor in anchors
        ]
        offset_ms = round(median(offsets_ms))
        uncertainty_ms = max(
            anchor.source_time.uncertainty_ms + anchor.reference_time.uncertainty_ms
            for anchor in anchors
        ) + max(abs(offset - offset_ms) for offset in offsets_ms)

        drift_ppm: float | None = None
        status = ToolOutcomeStatus.PARTIAL
        reason: str | None = "one clock anchor estimates offset but not drift"
        if len(anchors) >= 2:
            elapsed = (
                _parse_utc(anchors[-1].source_time.normalized_utc)
                - _parse_utc(anchors[0].source_time.normalized_utc)
            ).total_seconds()
            if elapsed > 0:
                drift_ppm = round((offsets_ms[-1] - offsets_ms[0]) / elapsed * 1000, 6)
                status = ToolOutcomeStatus.SUCCESS_NONEMPTY
                reason = None
            else:
                reason = "clock anchors do not span positive source time"
        models.append(
            SourceClockModel(
                source_id=source.source_id,
                outcome=ToolOutcome(
                    status=status,
                    coverage=CoverageMetadata(
                        rows_examined=len(anchors), rows_total=len(anchors)
                    ),
                    reason=reason,
                ),
                source_reference_utc=anchors[0].source_time.normalized_utc,
                offset_ms=offset_ms,
                drift_ppm=drift_ppm,
                uncertainty_ms=uncertainty_ms,
                anchor_ids=tuple(anchor.anchor_id for anchor in anchors),
            )
        )
    return tuple(models)


def _coverage(request: ClockEvidenceRequest) -> tuple[SourceCoverage, ...]:
    covered = {source.family for source in request.sources}
    cells = [
        SourceCoverage(
            family=source.family,
            source_id=source.source_id,
            parser_id=source.parser_id,
            outcome=ToolOutcome(
                status=source.status,
                coverage=CoverageMetadata(
                    rows_examined=source.rows_examined,
                    rows_total=source.rows_total,
                    parser_version=source.parser_version,
                ),
                reason=source.reason,
            ),
        )
        for source in sorted(request.sources, key=lambda item: (item.family.value, item.source_id))
    ]
    for family in ArtifactFamily:
        if family in covered:
            continue
        cells.append(
            SourceCoverage(
                family=family,
                outcome=ToolOutcome(
                    status=ToolOutcomeStatus.UNAVAILABLE,
                    reason="required artifact family was not supplied",
                ),
            )
        )
    return tuple(sorted(cells, key=lambda item: (item.family.value, item.source_id or "")))


def _finding_id(kind: str, subject: str, observation_ids: Sequence[str]) -> str:
    encoded = json.dumps(
        [kind, subject, sorted(observation_ids)],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "acf_" + hashlib.sha256(encoded).hexdigest()[:20]


def _effective_time(
    observation: TemporalObservation,
    clock_models: Mapping[str, SourceClockModel],
) -> datetime:
    """Correct normalized UTC by a source's measured offset and drift."""
    timestamp = _parse_utc(observation.time.normalized_utc)
    model = clock_models.get(observation.provenance.source_id)
    if model is None or model.offset_ms is None:
        return timestamp
    drift_ms = 0.0
    if model.drift_ppm is not None and model.source_reference_utc is not None:
        elapsed_seconds = (
            timestamp - _parse_utc(model.source_reference_utc)
        ).total_seconds()
        drift_ms = model.drift_ppm * elapsed_seconds / 1000
    return timestamp + timedelta(milliseconds=model.offset_ms + drift_ms)


def _ms_between(
    left: TemporalObservation,
    right: TemporalObservation,
    clock_models: Mapping[str, SourceClockModel],
) -> int:
    return round(
        (_effective_time(left, clock_models) - _effective_time(right, clock_models))
        .total_seconds()
        * 1000
    )


def _comparison_uncertainty(
    left: TemporalObservation,
    right: TemporalObservation,
    clock_models: Mapping[str, SourceClockModel],
) -> int:
    if left.provenance.source_id == right.provenance.source_id:
        # Unknown timezone is a shared systematic offset within one parser
        # source and cancels for ordering/delta comparisons.
        return min(left.time.uncertainty_ms, 1_000) + min(
            right.time.uncertainty_ms, 1_000
        )
    uncertainty = left.time.uncertainty_ms + right.time.uncertainty_ms
    for observation in (left, right):
        model = clock_models.get(observation.provenance.source_id)
        if model is not None and model.uncertainty_ms is not None:
            uncertainty += model.uncertainty_ms
    return uncertainty


def _timestomp_findings(
    observations: Sequence[TemporalObservation],
    clock_models: Mapping[str, SourceClockModel],
) -> list[TemporalFinding]:
    by_subject: dict[str, list[TemporalObservation]] = defaultdict(list)
    for observation in observations:
        by_subject[observation.subject.casefold()].append(observation)

    findings: list[TemporalFinding] = []
    witness_kinds = {
        ObservationKind.USN_CHANGE,
        ObservationKind.LOGFILE_CHANGE,
        ObservationKind.VSS_FILE,
    }
    for subject_key in sorted(by_subject):
        subject_observations = by_subject[subject_key]
        if any(path in subject_key for path in _TIMESTOMP_FALSE_POSITIVE_PATHS):
            continue
        si_values = [
            item for item in subject_observations if item.kind is ObservationKind.MFT_SI_CREATED
        ]
        fn_values = [
            item for item in subject_observations if item.kind is ObservationKind.MFT_FN_CREATED
        ]
        modified_values = [
            item for item in subject_observations if item.kind is ObservationKind.MFT_SI_MODIFIED
        ]
        witnesses = [item for item in subject_observations if item.kind in witness_kinds]
        for si in si_values:
            for modified in modified_values:
                difference = _ms_between(si, modified, clock_models)
                uncertainty = _comparison_uncertainty(si, modified, clock_models)
                if difference <= max(_TIMESTOMP_THRESHOLD_MS, uncertainty):
                    continue
                ids = (si.observation_id, modified.observation_id)
                findings.append(
                    TemporalFinding(
                        finding_id=_finding_id("timestomp", si.subject, ids),
                        finding_type="timestomp",
                        state="confirmed",
                        subject=si.subject,
                        rule_id="ntfs-si-after-modified",
                        rule_version="1.0",
                        justification=(
                            "$STANDARD_INFORMATION creation is later than its modification "
                            "time beyond declared uncertainty; this versioned NTFS rule is "
                            "the explicit no-independent-witness exception"
                        ),
                        observation_ids=ids,
                    )
                )

            for fn in fn_values:
                difference = _ms_between(fn, si, clock_models)
                uncertainty = _comparison_uncertainty(si, fn, clock_models)
                if difference <= max(_TIMESTOMP_THRESHOLD_MS, uncertainty):
                    continue
                corroborating = [
                    witness
                    for witness in witnesses
                    if witness.provenance.independence_key
                    not in {si.provenance.independence_key, fn.provenance.independence_key}
                    and abs(_ms_between(witness, fn, clock_models))
                    + _comparison_uncertainty(witness, fn, clock_models)
                    < max(
                        abs(_ms_between(witness, si, clock_models))
                        - _comparison_uncertainty(witness, si, clock_models),
                        0,
                    )
                ]
                ids = (si.observation_id, fn.observation_id)
                witness_ids = tuple(sorted(item.observation_id for item in corroborating))
                state: Literal["indicated", "confirmed"] = (
                    "confirmed" if witness_ids else "indicated"
                )
                findings.append(
                    TemporalFinding(
                        finding_id=_finding_id(
                            "timestomp", si.subject, (*ids, *witness_ids)
                        ),
                        finding_type="timestomp",
                        state=state,
                        subject=si.subject,
                        rule_id="ntfs-si-fn-backdate",
                        rule_version="1.0",
                        justification=(
                            "$STANDARD_INFORMATION creation predates $FILE_NAME creation "
                            "beyond declared uncertainty"
                            + (
                                "; an independent change/snapshot witness is closer to "
                                "$FILE_NAME creation"
                                if witness_ids
                                else "; no independent confirming witness is available"
                            )
                        ),
                        observation_ids=ids,
                        independent_witness_ids=witness_ids,
                    )
                )
    return findings


def _usn_findings(
    observations: Sequence[TemporalObservation],
    clock_models: Mapping[str, SourceClockModel],
) -> list[TemporalFinding]:
    by_source: dict[str, list[TemporalObservation]] = defaultdict(list)
    for observation in observations:
        if observation.kind is ObservationKind.USN_CHANGE:
            by_source[observation.provenance.source_id].append(observation)

    findings: list[TemporalFinding] = []
    for source_id in sorted(by_source):
        ordered = sorted(
            by_source[source_id],
            key=lambda item: (item.sequence_number or 0, item.observation_id),
        )
        for previous, current in zip(ordered, ordered[1:], strict=False):
            backwards = _ms_between(previous, current, clock_models)
            uncertainty = _comparison_uncertainty(previous, current, clock_models)
            if backwards <= max(_TIMESTOMP_THRESHOLD_MS, uncertainty):
                continue
            ids = (previous.observation_id, current.observation_id)
            findings.append(
                TemporalFinding(
                    finding_id=_finding_id("usn_order_anomaly", source_id, ids),
                    finding_type="usn_order_anomaly",
                    state="indicated",
                    subject=source_id,
                    rule_id="usn-sequence-time-order",
                    rule_version="1.0",
                    justification=(
                        "increasing USN sequence numbers move backwards in normalized time "
                        "beyond declared uncertainty"
                    ),
                    observation_ids=ids,
                )
            )
    return findings


def _direct_findings(observations: Sequence[TemporalObservation]) -> list[TemporalFinding]:
    findings: list[TemporalFinding] = []
    for observation in observations:
        if observation.kind is ObservationKind.EVENT_LOG_CLEAR:
            ids = (observation.observation_id,)
            findings.append(
                TemporalFinding(
                    finding_id=_finding_id("log_clear", observation.subject, ids),
                    finding_type="log_clear",
                    state="confirmed",
                    subject=observation.subject,
                    rule_id="windows-log-clear-event",
                    rule_version="1.0",
                    justification=(
                        "structured Windows event 104 or 1102 directly records a log clear"
                    ),
                    observation_ids=ids,
                )
            )
        elif observation.kind is ObservationKind.PROCESS_FILE_MISMATCH:
            ids = (observation.observation_id,)
            findings.append(
                TemporalFinding(
                    finding_id=_finding_id(
                        "process_file_mismatch", observation.subject, ids
                    ),
                    finding_type="process_file_mismatch",
                    state="indicated",
                    subject=observation.subject,
                    rule_id="running-deleted-path-mismatch",
                    rule_version="1.0",
                    justification=(
                        "a normalized process/file Adapter reported running, deleted, or "
                        "image-path disagreement; corroboration is still required"
                    ),
                    observation_ids=ids,
                )
            )
    return findings


def analyze_clock_evidence(
    payload: ClockEvidenceRequest | Mapping[str, object],
) -> ClockAnalysisResult:
    """Assess a normalized request through the module's sole analysis Interface."""
    if isinstance(payload, ClockEvidenceRequest):
        request = payload
    else:
        schema = payload.get("schema")
        version = payload.get("schema_version")
        if schema != CLOCK_EVIDENCE_SCHEMA or version != CLOCK_EVIDENCE_SCHEMA_VERSION:
            return ClockAnalysisResult(
                case_id=str(payload.get("case_id") or "unknown"),
                outcome=ToolOutcome(
                    status=ToolOutcomeStatus.UNSUPPORTED_VERSION,
                    reason=f"unsupported clock evidence schema {schema!r} version {version!r}",
                ),
                coverage=(),
                clock_anchors=(),
                clock_models=(),
                observations=(),
                findings=(),
            )
        try:
            request = ClockEvidenceRequest.model_validate(payload)
        except ValidationError as exc:
            return ClockAnalysisResult(
                case_id=str(payload.get("case_id") or "unknown"),
                outcome=ToolOutcome(
                    status=ToolOutcomeStatus.UNSUPPORTED_VERSION,
                    reason=f"clock evidence schema drift or invalid normalized input: {exc}",
                ),
                coverage=(),
                clock_anchors=(),
                clock_models=(),
                observations=(),
                findings=(),
            )

    observations = tuple(
        sorted(
            (
                observation
                for source in request.sources
                for observation in source.observations
            ),
            key=lambda item: item.observation_id,
        )
    )
    coverage = _coverage(request)
    clock_models = _clock_models(request)
    clock_models_by_source = {model.source_id: model for model in clock_models}
    findings = tuple(
        sorted(
            [
                *_timestomp_findings(observations, clock_models_by_source),
                *_usn_findings(observations, clock_models_by_source),
                *_direct_findings(observations),
            ],
            key=lambda item: item.finding_id,
        )
    )

    if (
        request.adapter_outcome is not None
        and request.adapter_outcome.status is ToolOutcomeStatus.UNSUPPORTED_VERSION
        and not request.sources
    ):
        return ClockAnalysisResult(
            case_id=request.case_id,
            outcome=request.adapter_outcome,
            adapter_outcome=request.adapter_outcome,
            coverage=(),
            clock_anchors=tuple(sorted(request.clock_anchors, key=lambda item: item.anchor_id)),
            clock_models=(),
            observations=(),
            findings=(),
        )

    incomplete = [
        cell
        for cell in coverage
        if cell.outcome.status
        not in {ToolOutcomeStatus.SUCCESS_EMPTY, ToolOutcomeStatus.SUCCESS_NONEMPTY}
    ]
    sources_with_observations = {
        source.source_id for source in request.sources if source.observations
    }
    clock_incomplete = [
        model
        for model in clock_models
        if model.source_id in sources_with_observations
        and model.outcome.status is not ToolOutcomeStatus.SUCCESS_NONEMPTY
    ]
    adapter_incomplete = request.adapter_outcome is not None and (
        request.adapter_outcome.status
        not in {ToolOutcomeStatus.SUCCESS_EMPTY, ToolOutcomeStatus.SUCCESS_NONEMPTY}
    )
    if incomplete or clock_incomplete or adapter_incomplete:
        status = ToolOutcomeStatus.PARTIAL
        reason = (
            "indicators found, but artifact/clock coverage is incomplete"
            if findings
            else "no indicators found, but required artifact/clock coverage is incomplete"
        )
    elif findings:
        status = ToolOutcomeStatus.SUCCESS_NONEMPTY
        reason = None
    else:
        status = ToolOutcomeStatus.SUCCESS_EMPTY
        reason = "no anti-forensics indicators within complete declared coverage"

    return ClockAnalysisResult(
        case_id=request.case_id,
        outcome=ToolOutcome(
            status=status,
            coverage=CoverageMetadata(
                rows_examined=sum(cell.outcome.coverage.rows_examined or 0 for cell in coverage),
                rows_total=(
                    sum(cell.outcome.coverage.rows_total or 0 for cell in coverage)
                    if all(cell.outcome.coverage.rows_total is not None for cell in coverage)
                    else None
                ),
            ),
            reason=reason,
        ),
        adapter_outcome=request.adapter_outcome,
        coverage=coverage,
        clock_anchors=tuple(sorted(request.clock_anchors, key=lambda item: item.anchor_id)),
        clock_models=clock_models,
        observations=observations,
        findings=findings,
    )


def clock_evidence_schema() -> dict[str, object]:
    """Return the strict normalized-input JSON Schema."""
    return ClockEvidenceRequest.model_json_schema()
