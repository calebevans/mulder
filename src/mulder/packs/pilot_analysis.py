"""Strict local analyzers for the EVTX, Kubernetes, and CloudTrail pilot packs.

The three public functions are the Module's Interface.  They accept immutable
local documents and return typed coverage, normalized observations,
relationships, rule commitments, and exact proof selectors.  No function
performs discovery, network access, or caller-defined querying.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import shlex
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from enum import Enum
from typing import Literal
from xml.etree import ElementTree

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from yaml.tokens import AliasToken, AnchorToken  # type: ignore[import-untyped]

from mulder.models import CoverageMetadata, JsonScalar, ToolOutcome, ToolOutcomeStatus
from mulder.security.evidence_envelope import EvidenceFlag, envelope_evidence

PILOT_ANALYSIS_VERSION: Literal[1] = 1
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_DOCUMENTS = 256
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
DocumentMediaType = Literal[
    "application/json",
    "application/x-ndjson",
    "application/yaml",
    "application/x-evtx-lines",
    "text/csv",
]
DocumentCompression = Literal["none", "gzip"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class PilotDomain(str, Enum):
    WINDOWS_EVTX = "windows.evtx"
    KUBERNETES = "kubernetes"
    AWS_CLOUDTRAIL = "aws.cloudtrail"


class LocalEvidenceDocument(_StrictModel):
    """One local file or indexed source supplied to a domain analyzer."""

    source_id: str = Field(pattern=_ID_PATTERN)
    source_name: str = Field(min_length=1)
    media_type: DocumentMediaType
    content: bytes
    compression: DocumentCompression = "none"


class EvidenceProof(_StrictModel):
    """Stable coordinates for the exact record fields supporting a claim."""

    source_id: str = Field(pattern=_ID_PATTERN)
    source_name: str = Field(min_length=1)
    record_selector: str = Field(min_length=1)
    field_selectors: tuple[str, ...] = Field(min_length=1)
    source_digest: str = Field(pattern=_SHA256_PATTERN)
    content_digest: str = Field(pattern=_SHA256_PATTERN)
    record_digest: str = Field(pattern=_SHA256_PATTERN)
    encoding: str = Field(min_length=1)
    evidence_flags: tuple[EvidenceFlag, ...] = ()
    sensitivity_labels: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_selectors(self) -> EvidenceProof:
        if len(set(self.field_selectors)) != len(self.field_selectors):
            raise ValueError("duplicate proof field selectors")
        return self


class NormalizedObservation(_StrictModel):
    """A structured domain fact; attacker-controlled text stays in attributes."""

    observation_id: str = Field(pattern=_ID_PATTERN)
    kind: str = Field(pattern=_ID_PATTERN)
    subject: str = Field(min_length=1)
    timestamp_original: str | None = None
    timestamp_utc: str | None = None
    attributes: Mapping[str, JsonScalar] = Field(default_factory=dict)
    proof: EvidenceProof


class EvidenceRelationship(_StrictModel):
    """A directional relationship recovered from one exact local record."""

    relationship_id: str = Field(pattern=_ID_PATTERN)
    subject: str = Field(min_length=1)
    predicate: str = Field(pattern=_ID_PATTERN)
    object: str = Field(min_length=1)
    proof: EvidenceProof


class RuleFinding(_StrictModel):
    """A deterministic rule result committed to its declaration hash."""

    finding_id: str = Field(pattern=_ID_PATTERN)
    finding_type: str = Field(pattern=_ID_PATTERN)
    state: Literal["indicated", "confirmed"]
    subject: str = Field(min_length=1)
    title: str = Field(min_length=1)
    rule_id: str = Field(pattern=_ID_PATTERN)
    rule_version: str = Field(min_length=1)
    rule_hash: str = Field(pattern=_SHA256_PATTERN)
    justification: str = Field(min_length=1)
    proofs: tuple[EvidenceProof, ...] = Field(min_length=1)


class DomainCoverage(_StrictModel):
    """Typed outcome for one required family in a pilot pack."""

    family: str = Field(pattern=_ID_PATTERN)
    outcome: ToolOutcome


class PilotAnalysisResult(_StrictModel):
    """Portable output shared by all three domain-specific Interfaces."""

    schema_version: Literal[1] = PILOT_ANALYSIS_VERSION
    domain: PilotDomain
    analysis_version: Literal[1] = PILOT_ANALYSIS_VERSION
    outcome: ToolOutcome
    coverage: tuple[DomainCoverage, ...]
    ruleset_hash: str = Field(pattern=_SHA256_PATTERN)
    rule_hashes: Mapping[str, str]
    observations: tuple[NormalizedObservation, ...]
    relationships: tuple[EvidenceRelationship, ...]
    findings: tuple[RuleFinding, ...]

    @model_validator(mode="after")
    def _check_rule_commitments(self) -> PilotAnalysisResult:
        for finding in self.findings:
            if self.rule_hashes.get(finding.rule_id) != finding.rule_hash:
                raise ValueError(
                    f"finding {finding.finding_id!r} does not match its rule commitment"
                )
        return self


class _Rule(_StrictModel):
    rule_id: str = Field(pattern=_ID_PATTERN)
    version: str = Field(min_length=1)
    finding_type: str = Field(pattern=_ID_PATTERN)
    title: str = Field(min_length=1)
    logic: str = Field(min_length=1)

    @property
    def digest(self) -> str:
        return _digest(
            json.dumps(
                self.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        )


class _Coverage:
    """Local mutable accumulator hidden behind the result Interface."""

    def __init__(self, families: Sequence[str]) -> None:
        self._families = tuple(families)
        self._examined: dict[str, int] = defaultdict(int)
        self._total: dict[str, int] = defaultdict(int)
        self._seen: set[str] = set()
        self._unsupported: dict[str, list[str]] = defaultdict(list)

    def record(self, family: str, *, examined: int = 1, total: int = 1) -> None:
        self._seen.add(family)
        self._examined[family] += examined
        self._total[family] += total

    def unsupported(self, family: str, reason: str) -> None:
        self._seen.add(family)
        self._unsupported[family].append(reason)

    def results(self) -> tuple[DomainCoverage, ...]:
        cells: list[DomainCoverage] = []
        for family in self._families:
            reasons = sorted(set(self._unsupported[family]))
            examined = self._examined[family]
            total = self._total[family]
            if reasons and examined:
                status = ToolOutcomeStatus.PARTIAL
                reason = "; ".join(reasons)
            elif reasons:
                status = ToolOutcomeStatus.UNSUPPORTED_VERSION
                reason = "; ".join(reasons)
            elif family not in self._seen:
                status = ToolOutcomeStatus.UNAVAILABLE
                reason = "required artifact family was not supplied"
            elif examined:
                status = ToolOutcomeStatus.SUCCESS_NONEMPTY
                reason = None
            else:
                status = ToolOutcomeStatus.SUCCESS_EMPTY
                reason = None
            cells.append(
                DomainCoverage(
                    family=family,
                    outcome=ToolOutcome(
                        status=status,
                        coverage=CoverageMetadata(
                            rows_examined=examined,
                            rows_total=total if family in self._seen else None,
                            parser_version=str(PILOT_ANALYSIS_VERSION),
                        ),
                        reason=reason,
                    ),
                )
            )
        return tuple(cells)


class _DocumentContext:
    def __init__(self, document: LocalEvidenceDocument) -> None:
        self.document = document
        source = envelope_evidence(
            document.content,
            source_id=document.source_id,
            source_name=document.source_name,
            selector="document",
            max_characters=1,
        )
        self.source_digest = source.provenance.digest
        try:
            content = (
                _decompress_gzip(document.content)
                if document.compression == "gzip"
                else document.content
            )
        except (gzip.BadGzipFile, EOFError, OSError) as exc:
            raise ValueError(f"invalid gzip stream: {exc}") from exc
        if len(content) > MAX_DOCUMENT_BYTES:
            raise ValueError(
                f"decompressed document exceeds {MAX_DOCUMENT_BYTES} byte local limit"
            )
        self.content = content
        envelope = envelope_evidence(
            content,
            source_id=document.source_id,
            source_name=document.source_name,
            selector="document-content",
            max_characters=1,
        )
        self.text = envelope.decoded_text
        self.content_digest = envelope.provenance.digest
        self.encoding = envelope.provenance.encoding
        self.flags = envelope.flags
        self.sensitivity_labels = envelope.sensitivity_labels

    def proof(
        self,
        record: object,
        record_selector: str,
        field_selectors: Iterable[str],
    ) -> EvidenceProof:
        if isinstance(record, bytes):
            raw = record
        elif isinstance(record, str):
            raw = record.encode("utf-8", errors="surrogatepass")
        else:
            raw = json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            ).encode("utf-8")
        return EvidenceProof(
            source_id=self.document.source_id,
            source_name=self.document.source_name,
            record_selector=record_selector,
            field_selectors=tuple(dict.fromkeys(field_selectors)),
            source_digest=self.source_digest,
            content_digest=self.content_digest,
            record_digest=_digest(raw),
            encoding=self.encoding,
            evidence_flags=self.flags,
            sensitivity_labels=self.sensitivity_labels,
        )


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _decompress_gzip(value: bytes) -> bytes:
    """Read at most the documented local limit from a gzip transport."""
    with gzip.GzipFile(fileobj=io.BytesIO(value)) as stream:
        content = stream.read(MAX_DOCUMENT_BYTES + 1)
    return content


def _stable_id(prefix: str, *parts: str) -> str:
    material = json.dumps(parts, separators=(",", ":"), ensure_ascii=False).encode()
    return f"{prefix}_{hashlib.sha256(material).hexdigest()[:20]}"


def _ruleset(rules: Sequence[_Rule]) -> tuple[dict[str, str], str]:
    hashes = {rule.rule_id: rule.digest for rule in sorted(rules, key=lambda item: item.rule_id)}
    return hashes, _digest(
        json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _finding(
    rule: _Rule,
    *,
    state: Literal["indicated", "confirmed"],
    subject: str,
    justification: str,
    proofs: Sequence[EvidenceProof],
) -> RuleFinding:
    selectors = [f"{proof.source_id}:{proof.record_selector}" for proof in proofs]
    return RuleFinding(
        finding_id=_stable_id("finding", rule.rule_id, subject, *selectors),
        finding_type=rule.finding_type,
        state=state,
        subject=subject,
        title=rule.title,
        rule_id=rule.rule_id,
        rule_version=rule.version,
        rule_hash=rule.digest,
        justification=justification,
        proofs=tuple(proofs),
    )


def _finish(
    domain: PilotDomain,
    coverage: _Coverage,
    rules: Sequence[_Rule],
    observations: Sequence[NormalizedObservation],
    relationships: Sequence[EvidenceRelationship],
    findings: Sequence[RuleFinding],
) -> PilotAnalysisResult:
    cells = coverage.results()
    statuses = {cell.outcome.status for cell in cells}
    completed = {ToolOutcomeStatus.SUCCESS_EMPTY, ToolOutcomeStatus.SUCCESS_NONEMPTY}
    unsupported_only = ToolOutcomeStatus.UNSUPPORTED_VERSION in statuses and not statuses & {
        ToolOutcomeStatus.SUCCESS_EMPTY,
        ToolOutcomeStatus.SUCCESS_NONEMPTY,
    }
    if unsupported_only:
        status = ToolOutcomeStatus.UNSUPPORTED_VERSION
        reason = "all supplied artifacts use unsupported schemas"
    elif not statuses <= completed:
        status = ToolOutcomeStatus.PARTIAL
        reason = (
            "findings present, but required artifact coverage is incomplete"
            if findings
            else "no findings, but required artifact coverage is incomplete"
        )
    elif findings:
        status = ToolOutcomeStatus.SUCCESS_NONEMPTY
        reason = None
    else:
        status = ToolOutcomeStatus.SUCCESS_EMPTY
        reason = "no pilot-pack indicators within complete declared coverage"
    rule_hashes, ruleset_hash = _ruleset(rules)
    return PilotAnalysisResult(
        domain=domain,
        outcome=ToolOutcome(
            status=status,
            coverage=CoverageMetadata(
                parser_version=str(PILOT_ANALYSIS_VERSION),
            ),
            reason=reason,
        ),
        coverage=cells,
        ruleset_hash=ruleset_hash,
        rule_hashes=rule_hashes,
        observations=tuple(sorted(observations, key=lambda item: item.observation_id)),
        relationships=tuple(sorted(relationships, key=lambda item: item.relationship_id)),
        findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
    )


def _utc(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value.strip():
        return None, None
    original = value
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return original, None
    if parsed.tzinfo is None:
        return original, None
    return original, parsed.isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Windows EVTX


_EVTX_RULES = (
    _Rule(
        rule_id="evtx-log-cleared",
        version="1.0",
        finding_type="log_clear",
        title="Windows event log was cleared",
        logic="EventID is 104 or 1102 in a structured EVTX record",
    ),
    _Rule(
        rule_id="evtx-encoded-powershell",
        version="1.0",
        finding_type="encoded_powershell",
        title="Encoded PowerShell invocation recorded",
        logic="EventID is 4104 or 4688 and structured command/script field has encoded token",
    ),
    _Rule(
        rule_id="evtx-service-installed",
        version="1.0",
        finding_type="service_install",
        title="Windows service installation recorded",
        logic="EventID is 7045 and the structured service image field is present",
    ),
)
_EVTX_FAMILIES = ("security", "system", "powershell", "sysmon")


class _EvtxRecord:
    def __init__(
        self,
        *,
        context: _DocumentContext,
        raw: object,
        selector: str,
        fields: Mapping[str, object],
        field_selectors: Mapping[str, str],
    ) -> None:
        self.context = context
        self.raw = raw
        self.selector = selector
        self.fields = dict(fields)
        self.field_selectors = dict(field_selectors)

    def value(self, *names: str) -> tuple[object | None, str | None]:
        lowered = {key.casefold(): key for key in self.fields}
        for name in names:
            actual = lowered.get(name.casefold())
            if actual is not None:
                return self.fields[actual], self.field_selectors.get(actual, actual)
        return None, None

    def proof(self, selectors: Iterable[str | None]) -> EvidenceProof:
        selected = [selector for selector in selectors if selector]
        return self.context.proof(self.raw, self.selector, selected or (self.selector,))


def _xml_fields(payload: str) -> tuple[dict[str, object], dict[str, str]]:
    fields: dict[str, object] = {}
    selectors: dict[str, str] = {}
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return fields, selectors
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        text = (element.text or "").strip()
        if not text:
            continue
        if tag == "Data" and element.attrib.get("Name"):
            name = element.attrib["Name"]
            fields[name] = text
            selectors[name] = f"Event.EventData.Data[@Name='{name}']"
        elif tag in {"EventID", "EventRecordID", "Channel", "TimeCreated"}:
            fields[tag] = text
            selectors[tag] = f"Event.System.{tag}"
    return fields, selectors


def _parse_evtx_lines(context: _DocumentContext) -> tuple[list[_EvtxRecord], str | None]:
    records: list[_EvtxRecord] = []
    malformed = 0
    for line_number, line in enumerate(context.text.lstrip("\ufeff").splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split(" | ", 3)
        if len(parts) != 4:
            malformed += 1
            continue
        fields, selectors = _xml_fields(parts[3])
        fields.update(
            {
                "TimeCreated": parts[0],
                "EventID": parts[1],
                "Channel": parts[2],
            }
        )
        selectors.update(
            {
                "TimeCreated": "line.timestamp",
                "EventID": "line.event_id",
                "Channel": "line.channel",
            }
        )
        records.append(
            _EvtxRecord(
                context=context,
                raw=line,
                selector=f"line:{line_number}",
                fields=fields,
                field_selectors=selectors,
            )
        )
    reason = f"{malformed} EVTX lines had an unsupported shape" if malformed else None
    return records, reason


_EVTX_CSV_ALIASES: Mapping[str, tuple[str, ...]] = {
    "timestamp": ("TimeCreated", "Timestamp", "Time Created", "datetime"),
    "event_id": ("EventId", "EventID", "Event ID", "Id"),
    "channel": ("Channel", "ChannelName", "LogName"),
    "record_id": ("RecordNumber", "EventRecordID", "Record ID", "RecordId"),
}


def _csv_header(headers: Sequence[str], logical: str) -> str | None:
    folded = {header.casefold(): header for header in headers}
    return next(
        (
            folded[name.casefold()]
            for name in _EVTX_CSV_ALIASES[logical]
            if name.casefold() in folded
        ),
        None,
    )


def _parse_evtx_csv(context: _DocumentContext) -> tuple[list[_EvtxRecord], str | None]:
    reader = csv.DictReader(io.StringIO(context.text.lstrip("\ufeff")))
    headers = [header.strip() for header in (reader.fieldnames or []) if header]
    resolved = {logical: _csv_header(headers, logical) for logical in _EVTX_CSV_ALIASES}
    missing = [logical for logical, actual in resolved.items() if actual is None]
    if missing:
        return [], f"EVTX CSV schema lacks required fields: {', '.join(sorted(missing))}"
    records: list[_EvtxRecord] = []
    for row_number, row in enumerate(reader, start=2):
        fields = {str(key): value for key, value in row.items() if key is not None}
        selectors = {key: f"csv:row={row_number};field={key}" for key in fields}
        records.append(
            _EvtxRecord(
                context=context,
                raw=fields,
                selector=f"csv:row={row_number}",
                fields=fields,
                field_selectors=selectors,
            )
        )
    return records, None


def _evtx_family(channel: str) -> str | None:
    folded = channel.casefold()
    if "powershell" in folded:
        return "powershell"
    if "sysmon" in folded:
        return "sysmon"
    if "security" in folded:
        return "security"
    if "system" in folded:
        return "system"
    return None


def _evtx_source_family(source_name: str) -> str | None:
    """Infer an empty/partial indexed channel without claiming other channels."""
    return _evtx_family(source_name.replace("-", "/"))


def _encoded_invocation(value: str) -> bool:
    folded = value.casefold()
    if "frombase64string(" in folded:
        return True
    try:
        tokens = shlex.split(value, posix=False)
    except ValueError:
        tokens = value.split()
    encoded_tokens = {"-enc", "-encodedcommand", "/encodedcommand"}
    return any(token.casefold() in encoded_tokens for token in tokens)


def analyze_evtx_documents(documents: Sequence[LocalEvidenceDocument]) -> PilotAnalysisResult:
    """Analyze supported indexed-EVTX text/CSV formats without external calls."""
    coverage = _Coverage(_EVTX_FAMILIES)
    observations: list[NormalizedObservation] = []
    findings: list[RuleFinding] = []
    for document in documents[:MAX_DOCUMENTS]:
        try:
            context = _DocumentContext(document)
        except ValueError as exc:
            for family in _EVTX_FAMILIES:
                coverage.unsupported(family, f"{document.source_name}: {exc}")
            continue
        if document.media_type == "application/x-evtx-lines":
            records, error = _parse_evtx_lines(context)
        elif document.media_type == "text/csv":
            records, error = _parse_evtx_csv(context)
        else:
            records, error = [], f"unsupported EVTX media type {document.media_type!r}"
        source_family = _evtx_source_family(document.source_name)
        error_families = (source_family,) if source_family else _EVTX_FAMILIES
        if error and not records:
            for family in error_families:
                coverage.unsupported(family, f"{document.source_name}: {error}")
            continue
        if error:
            for family in error_families:
                coverage.unsupported(family, f"{document.source_name}: {error}")

        seen_families: set[str] = set()
        for record in records:
            event_value, event_selector = record.value("EventID", "EventId", "Event ID", "Id")
            channel_value, channel_selector = record.value("Channel", "ChannelName", "LogName")
            time_value, time_selector = record.value(
                "TimeCreated", "Timestamp", "Time Created", "datetime"
            )
            record_value, record_selector = record.value(
                "EventRecordID", "RecordNumber", "Record ID", "RecordId"
            )
            try:
                event_id = int(str(event_value))
            except (TypeError, ValueError):
                continue
            channel = str(channel_value or "")
            parsed_family = _evtx_family(channel)
            if parsed_family is None:
                continue
            seen_families.add(parsed_family)
            coverage.record(parsed_family)
            original, normalized = _utc(time_value)
            record_key = str(record_value or record.selector)
            base_proof = record.proof(
                (event_selector, channel_selector, time_selector, record_selector)
            )
            observations.append(
                NormalizedObservation(
                    observation_id=_stable_id(
                        "obs", document.source_id, record.selector, str(event_id)
                    ),
                    kind="windows_event",
                    subject=f"{channel}:{record_key}",
                    timestamp_original=original,
                    timestamp_utc=normalized,
                    attributes={"event_id": event_id, "channel": channel, "record_id": record_key},
                    proof=base_proof,
                )
            )

            if event_id in {104, 1102}:
                findings.append(
                    _finding(
                        _EVTX_RULES[0],
                        state="confirmed",
                        subject=channel,
                        justification=f"structured EventID {event_id} records a log-clear action",
                        proofs=(
                            record.proof((event_selector, channel_selector, record_selector)),
                        ),
                    )
                )
            command, command_selector = record.value(
                "CommandLine", "ScriptBlockText", "HostApplication", "Payload"
            )
            if (
                event_id in {4104, 4688}
                and isinstance(command, str)
                and _encoded_invocation(command)
            ):
                findings.append(
                    _finding(
                        _EVTX_RULES[1],
                        state="indicated",
                        subject=f"{channel}:{record_key}",
                        justification=(
                            "a structured command/script field contains an encoded-execution token"
                        ),
                        proofs=(
                            record.proof((event_selector, command_selector, record_selector)),
                        ),
                    )
                )
            image, image_selector = record.value("ImagePath", "ServiceFileName", "Path")
            if event_id == 7045 and isinstance(image, str) and image.strip():
                findings.append(
                    _finding(
                        _EVTX_RULES[2],
                        state="indicated",
                        subject=image,
                        justification="structured EventID 7045 records a service image path",
                        proofs=(record.proof((event_selector, image_selector, record_selector)),),
                    )
                )
        if source_family and source_family not in seen_families and not error:
            coverage.record(source_family, examined=0, total=0)
    if len(documents) > MAX_DOCUMENTS:
        for family in _EVTX_FAMILIES:
            coverage.unsupported(family, "document collection exceeds deterministic limit")
    return _finish(
        PilotDomain.WINDOWS_EVTX,
        coverage,
        _EVTX_RULES,
        observations,
        (),
        findings,
    )


# ---------------------------------------------------------------------------
# Kubernetes


_K8S_FAMILIES = ("audit", "events", "manifests", "rbac", "images", "egress")
_K8S_RULES = (
    _Rule(
        rule_id="k8s-sensitive-audit-action",
        version="1.0",
        finding_type="sensitive_api_action",
        title="Sensitive Kubernetes API action observed",
        logic="audit.k8s.io/v1 verb targets secrets or pods exec/attach",
    ),
    _Rule(
        rule_id="k8s-privileged-workload",
        version="1.0",
        finding_type="privileged_workload",
        title="Workload requests host or privileged access",
        logic="workload pod spec has privileged=true, hostPID=true, hostNetwork=true, or hostPath",
    ),
    _Rule(
        rule_id="k8s-cluster-admin-binding",
        version="1.0",
        finding_type="cluster_admin_binding",
        title="Cluster-admin role is broadly bound",
        logic="ClusterRoleBinding roleRef.name is cluster-admin outside system:masters bootstrap",
    ),
    _Rule(
        rule_id="k8s-rbac-wildcard",
        version="1.0",
        finding_type="rbac_wildcard",
        title="RBAC role grants wildcard access",
        logic="Role or ClusterRole rule contains wildcard verb or resource",
    ),
    _Rule(
        rule_id="k8s-mutable-image",
        version="1.0",
        finding_type="mutable_image",
        title="Workload uses a mutable image reference",
        logic="container image lacks digest and uses latest or implicit latest tag",
    ),
    _Rule(
        rule_id="k8s-allow-all-egress",
        version="1.0",
        finding_type="allow_all_egress",
        title="NetworkPolicy allows unrestricted egress",
        logic="NetworkPolicy egress rule has no destination selector or permits global CIDR",
    ),
)


def _mapping(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def _sequence(value: object) -> Sequence[object]:
    return value if isinstance(value, list | tuple) else ()


def _parse_structured(context: _DocumentContext) -> tuple[list[object], str | None]:
    try:
        if context.document.media_type == "application/x-ndjson":
            return [
                json.loads(line)
                for line in context.text.lstrip("\ufeff").splitlines()
                if line.strip()
            ], None
        if context.document.media_type == "application/json":
            return [json.loads(context.text.lstrip("\ufeff"))], None
        if context.document.media_type == "application/yaml":
            if any(
                isinstance(token, AliasToken | AnchorToken)
                for token in yaml.scan(context.text.lstrip("\ufeff"))
            ):
                return [], "YAML aliases and anchors are unsupported"
            return list(yaml.safe_load_all(context.text.lstrip("\ufeff"))), None
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        return [], f"structured document could not be parsed: {exc}"
    return [], f"unsupported structured media type {context.document.media_type!r}"


def _object_name(item: Mapping[str, object]) -> tuple[str, str]:
    metadata = _mapping(item.get("metadata")) or {}
    name = str(metadata.get("name") or "unnamed")
    namespace = str(metadata.get("namespace") or "default")
    return name, namespace


def _pod_spec(item: Mapping[str, object]) -> tuple[Mapping[str, object] | None, str]:
    kind = str(item.get("kind") or "")
    spec = _mapping(item.get("spec"))
    if spec is None:
        return None, ".spec"
    if kind == "Pod":
        return spec, ".spec"
    if kind == "CronJob":
        job = _mapping(spec.get("jobTemplate"))
        job_spec = _mapping(job.get("spec")) if job else None
        template = _mapping(job_spec.get("template")) if job_spec else None
        return (_mapping(template.get("spec")) if template else None), (
            ".spec.jobTemplate.spec.template.spec"
        )
    template = _mapping(spec.get("template"))
    return (_mapping(template.get("spec")) if template else None), ".spec.template.spec"


def _iter_k8s_objects(value: object, selector: str) -> Iterable[tuple[Mapping[str, object], str]]:
    item = _mapping(value)
    if item is None:
        return
    kind = str(item.get("kind") or "")
    items = item.get("items")
    if kind in {"List", "EventList"} and isinstance(items, list):
        for index, child in enumerate(items):
            child_mapping = _mapping(child)
            if child_mapping is not None:
                yield child_mapping, f"{selector}.items[{index}]"
        return
    yield item, selector


def _k8s_proof(
    context: _DocumentContext,
    item: Mapping[str, object],
    selector: str,
    *fields: str,
) -> EvidenceProof:
    return context.proof(item, selector, fields)


def _k8s_audit(
    context: _DocumentContext,
    item: Mapping[str, object],
    selector: str,
    coverage: _Coverage,
    observations: list[NormalizedObservation],
    relationships: list[EvidenceRelationship],
    findings: list[RuleFinding],
) -> bool:
    api_version = str(item.get("apiVersion") or "")
    kind = str(item.get("kind") or "")
    if not (api_version.startswith("audit.k8s.io/") or "auditID" in item):
        return False
    if api_version != "audit.k8s.io/v1" or kind not in {"Event", ""}:
        coverage.unsupported("audit", f"unsupported Kubernetes audit schema {api_version}/{kind}")
        return True
    required = {"auditID", "verb", "user", "objectRef", "stage"}
    if not required <= item.keys():
        coverage.unsupported("audit", "audit event lacks required v1 fields")
        return True
    coverage.record("audit")
    audit_id = str(item["auditID"])
    verb = str(item["verb"])
    user = _mapping(item["user"]) or {}
    username = str(user.get("username") or "unknown")
    object_ref = _mapping(item["objectRef"]) or {}
    resource = str(object_ref.get("resource") or "unknown")
    subresource = str(object_ref.get("subresource") or "")
    namespace = str(object_ref.get("namespace") or "default")
    name = str(object_ref.get("name") or "*")
    target = f"{resource}/{name}@{namespace}" + (f"/{subresource}" if subresource else "")
    original, normalized = _utc(item.get("stageTimestamp") or item.get("requestReceivedTimestamp"))
    proof = _k8s_proof(
        context,
        item,
        selector,
        f"{selector}.auditID",
        f"{selector}.verb",
        f"{selector}.user.username",
        f"{selector}.objectRef",
        f"{selector}.stage",
    )
    observations.append(
        NormalizedObservation(
            observation_id=_stable_id("obs", context.document.source_id, selector, audit_id),
            kind="kubernetes_audit_event",
            subject=target,
            timestamp_original=original,
            timestamp_utc=normalized,
            attributes={"audit_id": audit_id, "verb": verb, "username": username},
            proof=proof,
        )
    )
    relationships.append(
        EvidenceRelationship(
            relationship_id=_stable_id("rel", audit_id, username, verb, target),
            subject=username,
            predicate="performs_k8s_action",
            object=f"{verb}:{target}",
            proof=proof,
        )
    )
    response = _mapping(item.get("responseStatus")) or {}
    code = response.get("code")
    succeeded = not isinstance(code, int) or code < 400
    sensitive = resource == "secrets" or (
        resource == "pods" and subresource in {"exec", "attach", "portforward"}
    )
    if sensitive and succeeded:
        findings.append(
            _finding(
                _K8S_RULES[0],
                state="confirmed" if username == "system:anonymous" else "indicated",
                subject=f"{username}->{target}",
                justification=(
                    f"audit.k8s.io/v1 records successful {verb} against {resource}"
                    + (f"/{subresource}" if subresource else "")
                ),
                proofs=(proof,),
            )
        )
    return True


def _k8s_event(
    context: _DocumentContext,
    item: Mapping[str, object],
    selector: str,
    coverage: _Coverage,
    observations: list[NormalizedObservation],
) -> bool:
    if str(item.get("kind") or "") != "Event" or str(item.get("apiVersion") or "") not in {
        "v1",
        "events.k8s.io/v1",
    }:
        return False
    coverage.record("events")
    name, namespace = _object_name(item)
    reason = str(item.get("reason") or "")
    event_type = str(item.get("type") or "")
    original, normalized = _utc(
        item.get("eventTime") or item.get("lastTimestamp") or item.get("firstTimestamp")
    )
    proof = _k8s_proof(
        context,
        item,
        selector,
        f"{selector}.reason",
        f"{selector}.type",
        f"{selector}.regarding",
        f"{selector}.involvedObject",
    )
    observations.append(
        NormalizedObservation(
            observation_id=_stable_id("obs", context.document.source_id, selector, name),
            kind="kubernetes_event",
            subject=f"{namespace}/{name}",
            timestamp_original=original,
            timestamp_utc=normalized,
            attributes={"reason": reason, "type": event_type},
            proof=proof,
        )
    )
    return True


def _k8s_rbac(
    context: _DocumentContext,
    item: Mapping[str, object],
    selector: str,
    coverage: _Coverage,
    observations: list[NormalizedObservation],
    relationships: list[EvidenceRelationship],
    findings: list[RuleFinding],
) -> bool:
    kind = str(item.get("kind") or "")
    if kind not in {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}:
        return False
    api_version = str(item.get("apiVersion") or "")
    if api_version != "rbac.authorization.k8s.io/v1":
        coverage.unsupported("rbac", f"unsupported RBAC schema {api_version!r}")
        return True
    coverage.record("rbac")
    name, namespace = _object_name(item)
    subject = f"{kind}:{namespace}/{name}"
    proof = _k8s_proof(
        context,
        item,
        selector,
        f"{selector}.kind",
        f"{selector}.metadata",
    )
    observations.append(
        NormalizedObservation(
            observation_id=_stable_id("obs", context.document.source_id, selector, subject),
            kind="kubernetes_rbac",
            subject=subject,
            attributes={"kind": kind, "name": name, "namespace": namespace},
            proof=proof,
        )
    )
    if kind in {"Role", "ClusterRole"}:
        for rule_index, rule_value in enumerate(_sequence(item.get("rules"))):
            rule = _mapping(rule_value) or {}
            verbs = {str(value) for value in _sequence(rule.get("verbs"))}
            resources = {str(value) for value in _sequence(rule.get("resources"))}
            if "*" in verbs or "*" in resources:
                findings.append(
                    _finding(
                        _K8S_RULES[3],
                        state="indicated",
                        subject=subject,
                        justification="RBAC rule structurally grants wildcard verb or resource",
                        proofs=(
                            _k8s_proof(
                                context,
                                item,
                                selector,
                                f"{selector}.rules[{rule_index}].verbs",
                                f"{selector}.rules[{rule_index}].resources",
                            ),
                        ),
                    )
                )
    else:
        role_ref = _mapping(item.get("roleRef")) or {}
        role_name = str(role_ref.get("name") or "unknown")
        subjects = _sequence(item.get("subjects"))
        for subject_index, bound_value in enumerate(subjects):
            bound = _mapping(bound_value) or {}
            bound_name = str(bound.get("name") or "unknown")
            bound_kind = str(bound.get("kind") or "unknown")
            relationship_proof = _k8s_proof(
                context,
                item,
                selector,
                f"{selector}.subjects[{subject_index}]",
                f"{selector}.roleRef",
            )
            relationships.append(
                EvidenceRelationship(
                    relationship_id=_stable_id("rel", subject, bound_kind, bound_name, role_name),
                    subject=f"{bound_kind}:{bound_name}",
                    predicate="bound_to_k8s_role",
                    object=role_name,
                    proof=relationship_proof,
                )
            )
        bootstrap_only = bool(subjects) and all(
            (_mapping(value) or {}).get("name") == "system:masters" for value in subjects
        )
        if kind == "ClusterRoleBinding" and role_name == "cluster-admin" and not bootstrap_only:
            findings.append(
                _finding(
                    _K8S_RULES[2],
                    state="indicated",
                    subject=subject,
                    justification=(
                        "ClusterRoleBinding grants cluster-admin outside the system:masters "
                        "bootstrap group"
                    ),
                    proofs=(
                        _k8s_proof(
                            context,
                            item,
                            selector,
                            f"{selector}.roleRef.name",
                            f"{selector}.subjects",
                        ),
                    ),
                )
            )
    return True


def _mutable_image(image: str) -> bool:
    if "@sha256:" in image.casefold():
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.casefold().endswith(":latest")


def _k8s_manifest(
    context: _DocumentContext,
    item: Mapping[str, object],
    selector: str,
    coverage: _Coverage,
    observations: list[NormalizedObservation],
    relationships: list[EvidenceRelationship],
    findings: list[RuleFinding],
) -> bool:
    kind = str(item.get("kind") or "")
    workload_kinds = {
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "Job",
        "CronJob",
        "ReplicaSet",
    }
    if kind not in workload_kinds:
        return False
    api_version = str(item.get("apiVersion") or "")
    pod_spec, pod_path = _pod_spec(item)
    if not api_version or pod_spec is None:
        coverage.unsupported("manifests", f"{kind} lacks apiVersion or pod spec")
        coverage.unsupported("images", f"{kind} lacks a parseable pod spec")
        return True
    coverage.record("manifests")
    name, namespace = _object_name(item)
    workload = f"{kind}:{namespace}/{name}"
    base_proof = _k8s_proof(
        context,
        item,
        selector,
        f"{selector}.apiVersion",
        f"{selector}.kind",
        f"{selector}.metadata",
        f"{selector}{pod_path}",
    )
    observations.append(
        NormalizedObservation(
            observation_id=_stable_id("obs", context.document.source_id, selector, workload),
            kind="kubernetes_workload",
            subject=workload,
            attributes={"kind": kind, "name": name, "namespace": namespace},
            proof=base_proof,
        )
    )

    dangerous_fields: list[str] = []
    if pod_spec.get("hostPID") is True:
        dangerous_fields.append(f"{selector}{pod_path}.hostPID")
    if pod_spec.get("hostNetwork") is True:
        dangerous_fields.append(f"{selector}{pod_path}.hostNetwork")
    for volume_index, volume_value in enumerate(_sequence(pod_spec.get("volumes"))):
        volume = _mapping(volume_value) or {}
        if "hostPath" in volume:
            dangerous_fields.append(f"{selector}{pod_path}.volumes[{volume_index}].hostPath")

    containers = [
        *_sequence(pod_spec.get("initContainers")),
        *_sequence(pod_spec.get("containers")),
        *_sequence(pod_spec.get("ephemeralContainers")),
    ]
    coverage.record("images", examined=0, total=0)
    for container_index, container_value in enumerate(containers):
        container = _mapping(container_value) or {}
        image = str(container.get("image") or "")
        container_name = str(container.get("name") or container_index)
        if not image:
            coverage.unsupported("images", f"{workload} container lacks image")
            continue
        coverage.record("images")
        image_selector = f"{selector}{pod_path}.containers[{container_index}].image"
        image_proof = _k8s_proof(context, item, selector, image_selector)
        relationships.append(
            EvidenceRelationship(
                relationship_id=_stable_id("rel", workload, container_name, image),
                subject=workload,
                predicate="uses_container_image",
                object=image,
                proof=image_proof,
            )
        )
        security = _mapping(container.get("securityContext")) or {}
        if security.get("privileged") is True:
            dangerous_fields.append(
                f"{selector}{pod_path}.containers[{container_index}].securityContext.privileged"
            )
        if _mutable_image(image):
            findings.append(
                _finding(
                    _K8S_RULES[4],
                    state="indicated",
                    subject=f"{workload}/{container_name}",
                    justification="container image uses latest or an implicit mutable tag",
                    proofs=(image_proof,),
                )
            )
    if dangerous_fields:
        findings.append(
            _finding(
                _K8S_RULES[1],
                state="indicated",
                subject=workload,
                justification="workload pod spec requests host or privileged access",
                proofs=(_k8s_proof(context, item, selector, *dangerous_fields),),
            )
        )
    return True


def _k8s_egress(
    context: _DocumentContext,
    item: Mapping[str, object],
    selector: str,
    coverage: _Coverage,
    observations: list[NormalizedObservation],
    relationships: list[EvidenceRelationship],
    findings: list[RuleFinding],
) -> bool:
    if str(item.get("kind") or "") != "NetworkPolicy":
        return False
    api_version = str(item.get("apiVersion") or "")
    if api_version != "networking.k8s.io/v1":
        coverage.unsupported("egress", f"unsupported NetworkPolicy schema {api_version!r}")
        return True
    coverage.record("egress")
    name, namespace = _object_name(item)
    policy = f"NetworkPolicy:{namespace}/{name}"
    spec = _mapping(item.get("spec")) or {}
    proof = _k8s_proof(
        context, item, selector, f"{selector}.spec.podSelector", f"{selector}.spec.egress"
    )
    observations.append(
        NormalizedObservation(
            observation_id=_stable_id("obs", context.document.source_id, selector, policy),
            kind="kubernetes_network_policy",
            subject=policy,
            attributes={"name": name, "namespace": namespace},
            proof=proof,
        )
    )
    for rule_index, rule_value in enumerate(_sequence(spec.get("egress"))):
        rule = _mapping(rule_value) or {}
        destinations = _sequence(rule.get("to"))
        allow_all = not destinations
        for destination_index, destination_value in enumerate(destinations):
            destination = _mapping(destination_value) or {}
            ip_block = _mapping(destination.get("ipBlock"))
            if ip_block:
                target = str(ip_block.get("cidr") or "unknown-cidr")
            elif "namespaceSelector" in destination:
                target = "namespace-selector:" + json.dumps(
                    destination["namespaceSelector"], sort_keys=True, separators=(",", ":")
                )
            elif "podSelector" in destination:
                target = "pod-selector:" + json.dumps(
                    destination["podSelector"], sort_keys=True, separators=(",", ":")
                )
            else:
                target = "all-destinations"
                allow_all = True
            if target in {"0.0.0.0/0", "::/0", "all-destinations"}:
                allow_all = True
            destination_selector = f"{selector}.spec.egress[{rule_index}].to[{destination_index}]"
            relationships.append(
                EvidenceRelationship(
                    relationship_id=_stable_id("rel", policy, target, destination_selector),
                    subject=policy,
                    predicate="allows_egress_to",
                    object=target,
                    proof=_k8s_proof(context, item, selector, destination_selector),
                )
            )
        if allow_all:
            findings.append(
                _finding(
                    _K8S_RULES[5],
                    state="indicated",
                    subject=policy,
                    justification=(
                        "NetworkPolicy egress rule has no destination restriction or permits "
                        "a global CIDR"
                    ),
                    proofs=(
                        _k8s_proof(
                            context,
                            item,
                            selector,
                            f"{selector}.spec.egress[{rule_index}].to",
                        ),
                    ),
                )
            )
    return True


def analyze_kubernetes_documents(
    documents: Sequence[LocalEvidenceDocument],
) -> PilotAnalysisResult:
    """Analyze local Kubernetes audit/events/manifests/RBAC/images/egress."""
    coverage = _Coverage(_K8S_FAMILIES)
    observations: list[NormalizedObservation] = []
    relationships: list[EvidenceRelationship] = []
    findings: list[RuleFinding] = []
    for document in documents[:MAX_DOCUMENTS]:
        try:
            context = _DocumentContext(document)
        except ValueError as exc:
            for family in _K8S_FAMILIES:
                coverage.unsupported(family, f"{document.source_name}: {exc}")
            continue
        roots, error = _parse_structured(context)
        if error:
            for family in _K8S_FAMILIES:
                coverage.unsupported(family, f"{document.source_name}: {error}")
            continue
        recognized = False
        for root_index, root in enumerate(roots):
            for item, selector in _iter_k8s_objects(root, f"document[{root_index}]"):
                recognized = (
                    _k8s_audit(
                        context,
                        item,
                        selector,
                        coverage,
                        observations,
                        relationships,
                        findings,
                    )
                    or _k8s_event(context, item, selector, coverage, observations)
                    or _k8s_rbac(
                        context,
                        item,
                        selector,
                        coverage,
                        observations,
                        relationships,
                        findings,
                    )
                    or _k8s_manifest(
                        context,
                        item,
                        selector,
                        coverage,
                        observations,
                        relationships,
                        findings,
                    )
                    or _k8s_egress(
                        context,
                        item,
                        selector,
                        coverage,
                        observations,
                        relationships,
                        findings,
                    )
                    or recognized
                )
        if not recognized:
            for family in _K8S_FAMILIES:
                coverage.unsupported(
                    family, f"{document.source_name}: no supported Kubernetes object schema"
                )
    if len(documents) > MAX_DOCUMENTS:
        for family in _K8S_FAMILIES:
            coverage.unsupported(family, "document collection exceeds deterministic limit")
    return _finish(
        PilotDomain.KUBERNETES,
        coverage,
        _K8S_RULES,
        observations,
        relationships,
        findings,
    )


# ---------------------------------------------------------------------------
# AWS CloudTrail


_CLOUDTRAIL_FAMILIES = ("records", "identity", "resources", "network_origin")
_CLOUDTRAIL_RULES = (
    _Rule(
        rule_id="cloudtrail-trail-integrity-change",
        version="1.0",
        finding_type="trail_integrity_change",
        title="CloudTrail logging configuration changed",
        logic="eventName is StopLogging, DeleteTrail, UpdateTrail, or PutEventSelectors",
    ),
    _Rule(
        rule_id="cloudtrail-iam-policy-change",
        version="1.0",
        finding_type="iam_policy_change",
        title="IAM privilege configuration changed",
        logic="eventSource is iam.amazonaws.com and eventName is a privileged policy mutation",
    ),
    _Rule(
        rule_id="cloudtrail-root-login-without-mfa",
        version="1.0",
        finding_type="root_login_without_mfa",
        title="Root console login succeeded without MFA",
        logic="ConsoleLogin succeeded for Root and additionalEventData.MFAUsed is not Yes",
    ),
    _Rule(
        rule_id="cloudtrail-public-security-group-ingress",
        version="1.0",
        finding_type="public_security_group_ingress",
        title="Security group ingress opened globally",
        logic="AuthorizeSecurityGroupIngress request structurally contains 0.0.0.0/0 or ::/0",
    ),
)
_IAM_MUTATIONS = {
    "AttachGroupPolicy",
    "AttachRolePolicy",
    "AttachUserPolicy",
    "CreateAccessKey",
    "CreateLoginProfile",
    "CreatePolicyVersion",
    "PutGroupPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
}


def _cloudtrail_version(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split(".", 1)
    if len(parts) != 2:
        return False
    try:
        major, minor = (int(part) for part in parts)
    except ValueError:
        return False
    return major == 1 and minor >= 2


def _global_cidrs(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key in {"cidrIp", "CidrIp", "cidrIpv6", "CidrIpv6"} and child in {
                "0.0.0.0/0",
                "::/0",
            }:
                found.append(str(child))
            found.extend(_global_cidrs(child))
    elif isinstance(value, list | tuple):
        for child in value:
            found.extend(_global_cidrs(child))
    return found


def analyze_cloudtrail_documents(
    documents: Sequence[LocalEvidenceDocument],
) -> PilotAnalysisResult:
    """Analyze documented CloudTrail ``Records`` JSON exports locally/offline."""
    coverage = _Coverage(_CLOUDTRAIL_FAMILIES)
    observations: list[NormalizedObservation] = []
    relationships: list[EvidenceRelationship] = []
    findings: list[RuleFinding] = []
    for document in documents[:MAX_DOCUMENTS]:
        try:
            context = _DocumentContext(document)
        except ValueError as exc:
            for family in _CLOUDTRAIL_FAMILIES:
                coverage.unsupported(family, f"{document.source_name}: {exc}")
            continue
        if document.media_type != "application/json":
            for family in _CLOUDTRAIL_FAMILIES:
                coverage.unsupported(family, "CloudTrail pilot accepts JSON exports only")
            continue
        try:
            root = json.loads(context.text.lstrip("\ufeff"))
        except json.JSONDecodeError as exc:
            for family in _CLOUDTRAIL_FAMILIES:
                coverage.unsupported(family, f"invalid CloudTrail JSON: {exc}")
            continue
        if (
            not isinstance(root, dict)
            or set(root) != {"Records"}
            or not isinstance(root.get("Records"), list)
        ):
            for family in _CLOUDTRAIL_FAMILIES:
                coverage.unsupported(
                    family,
                    "expected documented CloudTrail wrapper with exact Records array",
                )
            continue
        records = root["Records"]
        if not records:
            for family in _CLOUDTRAIL_FAMILIES:
                coverage.record(family, examined=0, total=0)
            continue
        for index, value in enumerate(records):
            record = _mapping(value)
            selector = f"Records[{index}]"
            required = {
                "eventVersion",
                "userIdentity",
                "eventTime",
                "eventSource",
                "eventName",
                "awsRegion",
                "sourceIPAddress",
                "eventID",
                "eventType",
                "requestParameters",
                "responseElements",
            }
            if (
                record is None
                or not required <= record.keys()
                or not _cloudtrail_version(record.get("eventVersion") if record else None)
            ):
                for family in _CLOUDTRAIL_FAMILIES:
                    coverage.unsupported(
                        family,
                        f"{selector} lacks required CloudTrail major-version-1 fields",
                    )
                continue
            for family in _CLOUDTRAIL_FAMILIES:
                coverage.record(family)
            event_id = str(record["eventID"])
            event_name = str(record["eventName"])
            event_source = str(record["eventSource"])
            source_ip = str(record["sourceIPAddress"])
            identity = _mapping(record["userIdentity"]) or {}
            principal = str(
                identity.get("arn")
                or identity.get("principalId")
                or identity.get("userName")
                or identity.get("type")
                or "unknown"
            )
            original, normalized = _utc(record["eventTime"])
            base_proof = context.proof(
                record,
                selector,
                (
                    f"{selector}.eventID",
                    f"{selector}.eventVersion",
                    f"{selector}.eventTime",
                    f"{selector}.eventSource",
                    f"{selector}.eventName",
                    f"{selector}.userIdentity",
                    f"{selector}.sourceIPAddress",
                ),
            )
            observations.append(
                NormalizedObservation(
                    observation_id=_stable_id("obs", document.source_id, selector, event_id),
                    kind="aws_cloudtrail_event",
                    subject=f"{event_source}:{event_name}",
                    timestamp_original=original,
                    timestamp_utc=normalized,
                    attributes={
                        "event_id": event_id,
                        "event_name": event_name,
                        "event_source": event_source,
                        "principal": principal,
                        "source_ip": source_ip,
                    },
                    proof=base_proof,
                )
            )
            relationships.append(
                EvidenceRelationship(
                    relationship_id=_stable_id(
                        "rel", event_id, principal, event_source, event_name
                    ),
                    subject=principal,
                    predicate="calls_aws_control_plane",
                    object=f"{event_source}:{event_name}",
                    proof=base_proof,
                )
            )
            relationships.append(
                EvidenceRelationship(
                    relationship_id=_stable_id("rel", event_id, source_ip, principal),
                    subject=source_ip,
                    predicate="originates_aws_action_by",
                    object=principal,
                    proof=base_proof,
                )
            )
            for resource_index, resource_value in enumerate(_sequence(record.get("resources"))):
                resource = _mapping(resource_value) or {}
                arn = str(resource.get("ARN") or resource.get("arn") or "")
                if not arn:
                    continue
                relationships.append(
                    EvidenceRelationship(
                        relationship_id=_stable_id("rel", event_id, principal, arn),
                        subject=principal,
                        predicate="acts_on_aws_resource",
                        object=arn,
                        proof=context.proof(
                            record,
                            selector,
                            (f"{selector}.resources[{resource_index}]",),
                        ),
                    )
                )

            if event_source == "cloudtrail.amazonaws.com" and event_name in {
                "StopLogging",
                "DeleteTrail",
                "UpdateTrail",
                "PutEventSelectors",
            }:
                findings.append(
                    _finding(
                        _CLOUDTRAIL_RULES[0],
                        state="confirmed",
                        subject=f"{principal}:{event_name}",
                        justification=f"CloudTrail records the {event_name} control-plane action",
                        proofs=(
                            context.proof(
                                record,
                                selector,
                                (
                                    f"{selector}.eventSource",
                                    f"{selector}.eventName",
                                    f"{selector}.eventID",
                                    f"{selector}.userIdentity",
                                ),
                            ),
                        ),
                    )
                )
            if event_source == "iam.amazonaws.com" and event_name in _IAM_MUTATIONS:
                findings.append(
                    _finding(
                        _CLOUDTRAIL_RULES[1],
                        state="indicated",
                        subject=f"{principal}:{event_name}",
                        justification="CloudTrail records a privileged IAM policy mutation",
                        proofs=(
                            context.proof(
                                record,
                                selector,
                                (
                                    f"{selector}.eventSource",
                                    f"{selector}.eventName",
                                    f"{selector}.requestParameters",
                                ),
                            ),
                        ),
                    )
                )
            additional = _mapping(record.get("additionalEventData")) or {}
            response = _mapping(record.get("responseElements")) or {}
            if (
                event_name == "ConsoleLogin"
                and identity.get("type") == "Root"
                and additional.get("MFAUsed") != "Yes"
                and response.get("ConsoleLogin") == "Success"
            ):
                findings.append(
                    _finding(
                        _CLOUDTRAIL_RULES[2],
                        state="confirmed",
                        subject=principal,
                        justification="root ConsoleLogin succeeded and MFAUsed is not Yes",
                        proofs=(
                            context.proof(
                                record,
                                selector,
                                (
                                    f"{selector}.eventName",
                                    f"{selector}.userIdentity.type",
                                    f"{selector}.additionalEventData.MFAUsed",
                                    f"{selector}.responseElements.ConsoleLogin",
                                ),
                            ),
                        ),
                    )
                )
            global_cidrs = sorted(set(_global_cidrs(record.get("requestParameters"))))
            if event_name == "AuthorizeSecurityGroupIngress" and global_cidrs:
                findings.append(
                    _finding(
                        _CLOUDTRAIL_RULES[3],
                        state="confirmed",
                        subject=f"{principal}:{','.join(global_cidrs)}",
                        justification=(
                            "AuthorizeSecurityGroupIngress request structurally contains a "
                            "global IPv4 or IPv6 CIDR"
                        ),
                        proofs=(
                            context.proof(
                                record,
                                selector,
                                (
                                    f"{selector}.eventName",
                                    f"{selector}.requestParameters",
                                    f"{selector}.eventID",
                                ),
                            ),
                        ),
                    )
                )
    if len(documents) > MAX_DOCUMENTS:
        for family in _CLOUDTRAIL_FAMILIES:
            coverage.unsupported(family, "document collection exceeds deterministic limit")
    return _finish(
        PilotDomain.AWS_CLOUDTRAIL,
        coverage,
        _CLOUDTRAIL_RULES,
        observations,
        relationships,
        findings,
    )
