"""Deterministic entity, event, and provenance graph over verified claims.

The public interface lives on :class:`mulder.db.CaseDB`.  This module owns the
projection vocabulary and hides every SQL detail behind rebuild, snapshot, and
edge-provenance operations.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    Column,
    Connection,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
    select,
    update,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from mulder.models import JsonScalar

GRAPH_DERIVATION_RULE = "verified_atomic_claim_projection"
GRAPH_DERIVATION_VERSION = "1"

__all__ = [
    "GRAPH_DERIVATION_RULE",
    "GRAPH_DERIVATION_VERSION",
    "AliasCollision",
    "EdgeProvenance",
    "GraphAlias",
    "GraphAnchorProvenance",
    "GraphBuildResult",
    "GraphClaimProvenance",
    "GraphEntity",
    "GraphEvent",
    "GraphProjection",
    "GraphRelation",
    "GraphSnapshot",
]

ProjectionState = Literal["active", "superseded"]
ValueKind = Literal["null", "boolean", "integer", "number", "string"]
TimeNormalizationState = Literal["normalized", "naive", "unparseable"]

_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_TYPED_REFERENCE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.-]{0,63}):(.*)$", re.DOTALL)
_PREDICATE_SEPARATORS = re.compile(r"[^a-z0-9_.-]+")
_OBJECT_TYPES = {
    "domain_equals": "domain",
    "hash_equals": "hash",
    "hostname_equals": "host",
    "image_name": "process_image",
    "ip_equals": "ip_address",
    "path_equals": "file_path",
    "timestamp_equals": "timestamp",
}


@dataclass(frozen=True)
class _GraphTables:
    projections: Table
    entities: Table
    aliases: Table
    relations: Table
    events: Table
    edge_anchors: Table


def _define_graph_tables(metadata: MetaData) -> _GraphTables:
    """Attach the private projection schema to the authoritative case metadata."""
    projections = Table(
        "graph_projections",
        metadata,
        Column("projection_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column("derivation_rule", Text, nullable=False),
        Column("derivation_version", Text, nullable=False),
        Column("input_sha256", Text, nullable=False),
        Column("source_verification_watermark", Text),
        Column("state", Text, nullable=False, index=True),
        Column(
            "supersedes_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
        ),
        Column(
            "superseded_by_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
        ),
    )
    entities = Table(
        "graph_entities",
        metadata,
        Column("entity_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column("entity_type", Text, nullable=False, index=True),
        Column("value_kind", Text, nullable=False),
        Column("canonical_value", Text, nullable=False),
        Column("display_value", Text, nullable=False),
        Column("host_scope", Text, index=True),
        Column(
            "created_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
            nullable=False,
        ),
        Column(
            "last_seen_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
            nullable=False,
        ),
        Column("state", Text, nullable=False, index=True),
        Column(
            "superseded_by_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
        ),
    )
    aliases = Table(
        "graph_aliases",
        metadata,
        Column("alias_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column(
            "entity_id",
            Text,
            ForeignKey("graph_entities.entity_id"),
            nullable=False,
            index=True,
        ),
        Column("alias", Text, nullable=False),
        Column("normalized_alias", Text, nullable=False, index=True),
        Column("is_primary", Integer, nullable=False),
        Column(
            "created_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
            nullable=False,
        ),
        Column(
            "last_seen_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
            nullable=False,
        ),
        Column("state", Text, nullable=False, index=True),
        Column(
            "superseded_by_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
        ),
        UniqueConstraint("entity_id", "normalized_alias", name="uq_graph_entity_alias"),
    )
    relations = Table(
        "graph_relations",
        metadata,
        Column("edge_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column(
            "source_entity_id",
            Text,
            ForeignKey("graph_entities.entity_id"),
            nullable=False,
            index=True,
        ),
        Column(
            "target_entity_id",
            Text,
            ForeignKey("graph_entities.entity_id"),
            nullable=False,
            index=True,
        ),
        Column("predicate", Text, nullable=False, index=True),
        Column("claim_id", Text, ForeignKey("claims.claim_id"), nullable=False, index=True),
        Column(
            "verification_id",
            Text,
            ForeignKey("claim_verifications.verification_id"),
            nullable=False,
        ),
        Column("qualifiers", Text, nullable=False),
        Column("derivation_rule", Text, nullable=False),
        Column("derivation_version", Text, nullable=False),
        Column(
            "created_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
            nullable=False,
        ),
        Column(
            "last_seen_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
            nullable=False,
        ),
        Column("state", Text, nullable=False, index=True),
        Column(
            "superseded_by_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
        ),
    )
    events = Table(
        "graph_events",
        metadata,
        Column("event_id", Text, primary_key=True),
        Column("case_id", Text, ForeignKey("case_metadata.case_id"), nullable=False, index=True),
        Column("edge_id", Text, ForeignKey("graph_relations.edge_id"), nullable=False, index=True),
        Column("anchor_id", Text, ForeignKey("evidence_anchors.anchor_id"), index=True),
        Column("time_origin", Text, nullable=False),
        Column("original_time", Text, nullable=False),
        Column("normalized_time_utc", Text, index=True),
        Column("utc_offset_minutes", Integer),
        Column("normalization_state", Text, nullable=False),
        Column(
            "created_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
            nullable=False,
        ),
        Column(
            "last_seen_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
            nullable=False,
        ),
        Column("state", Text, nullable=False, index=True),
        Column(
            "superseded_by_projection_id",
            Text,
            ForeignKey("graph_projections.projection_id"),
        ),
    )
    edge_anchors = Table(
        "graph_edge_anchors",
        metadata,
        Column("edge_id", Text, ForeignKey("graph_relations.edge_id"), primary_key=True),
        Column("anchor_id", Text, ForeignKey("evidence_anchors.anchor_id"), primary_key=True),
    )
    return _GraphTables(
        projections=projections,
        entities=entities,
        aliases=aliases,
        relations=relations,
        events=events,
        edge_anchors=edge_anchors,
    )


class _GraphModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class GraphProjection(_GraphModel):
    """One content-addressed derivation of the active verified claim set."""

    projection_id: str
    case_id: str
    derivation_rule: str
    derivation_version: str
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_verification_watermark: str | None = None
    state: ProjectionState
    supersedes_projection_id: str | None = None
    superseded_by_projection_id: str | None = None


class GraphEntity(_GraphModel):
    """A typed, host-scoped entity with a deterministic identity."""

    entity_id: str
    entity_type: str
    value_kind: ValueKind
    canonical_value: str
    display_value: str
    host_scope: str | None = None
    state: ProjectionState
    superseded_by_projection_id: str | None = None


class GraphAlias(_GraphModel):
    """One normalized alias; the same alias may intentionally name several entities."""

    alias_id: str
    entity_id: str
    alias: str
    normalized_alias: str
    is_primary: bool
    state: ProjectionState
    superseded_by_projection_id: str | None = None


class AliasCollision(_GraphModel):
    """An explicit ambiguous alias rather than an implicit entity merge."""

    normalized_alias: str
    entity_ids: list[str] = Field(min_length=2)


class GraphRelation(_GraphModel):
    """A directed claim-derived relation between two typed entities."""

    edge_id: str
    source_entity_id: str
    target_entity_id: str
    predicate: str
    claim_id: str
    verification_id: str
    qualifiers: dict[str, JsonScalar] = Field(default_factory=dict)
    derivation_rule: str
    derivation_version: str
    state: ProjectionState
    superseded_by_projection_id: str | None = None


class GraphEvent(_GraphModel):
    """A timestamp attached to an edge, preserving the original representation."""

    event_id: str
    edge_id: str
    anchor_id: str | None = None
    time_origin: str
    original_time: str
    normalized_time_utc: str | None = None
    utc_offset_minutes: int | None = None
    normalization_state: TimeNormalizationState
    state: ProjectionState
    superseded_by_projection_id: str | None = None


class GraphSnapshot(_GraphModel):
    """Stable typed read model for the current or historical projection."""

    case_id: str
    active_projection: GraphProjection | None = None
    projections: list[GraphProjection] = Field(default_factory=list)
    entities: list[GraphEntity] = Field(default_factory=list)
    aliases: list[GraphAlias] = Field(default_factory=list)
    alias_collisions: list[AliasCollision] = Field(default_factory=list)
    relations: list[GraphRelation] = Field(default_factory=list)
    events: list[GraphEvent] = Field(default_factory=list)


class GraphBuildResult(_GraphModel):
    """Observable result of an atomic projection rebuild."""

    projection: GraphProjection
    unchanged: bool
    verified_claims: int = Field(ge=0)
    active_entities: int = Field(ge=0)
    active_aliases: int = Field(ge=0)
    active_relations: int = Field(ge=0)
    active_events: int = Field(ge=0)


class GraphClaimProvenance(_GraphModel):
    """The exact verified atomic claim responsible for one edge."""

    claim_id: str
    finding_id: str
    statement: str
    subject: str
    predicate: str
    object_value: JsonScalar
    qualifiers: dict[str, JsonScalar] = Field(default_factory=dict)
    verification_id: str
    verification_result: Literal["verified"]
    verification_reason_code: str
    verifier_name: str
    verifier_version: str
    verified_at: str


class GraphAnchorProvenance(_GraphModel):
    """Exact evidence and source locator supporting a projected edge."""

    anchor_id: str
    tool_call_id: str
    source_id: int
    source_name: str
    source_path: str
    source_hash: str
    extractor: str
    window_id: int
    line_start: int
    line_end: int
    char_start: int
    char_end: int
    exact_text: str
    window_text: str


class EdgeProvenance(_GraphModel):
    """Complete edge → verified claim → exact anchors → sources traversal."""

    relation: GraphRelation
    claim: GraphClaimProvenance
    anchors: list[GraphAnchorProvenance] = Field(min_length=1)


@dataclass(frozen=True)
class _EntitySpec:
    entity_id: str
    entity_type: str
    value_kind: ValueKind
    canonical_value: str
    display_value: str
    host_scope: str | None
    aliases: tuple[str, ...]


@dataclass(frozen=True)
class _AnchorSpec:
    anchor_id: str
    source_id: int
    source_name: str
    source_hash: str
    exact_text: str
    role: str
    event_time: str | None
    commitment: str


@dataclass(frozen=True)
class _EventSpec:
    event_id: str
    edge_id: str
    anchor_id: str | None
    time_origin: str
    original_time: str
    normalized_time_utc: str | None
    utc_offset_minutes: int | None
    normalization_state: TimeNormalizationState


@dataclass(frozen=True)
class _RelationSpec:
    edge_id: str
    source: _EntitySpec
    target: _EntitySpec
    predicate: str
    claim_id: str
    verification_id: str
    qualifiers_json: str
    anchor_ids: tuple[str, ...]
    anchor_commitments: tuple[str, ...]
    events: tuple[_EventSpec, ...]


def _canonical_json(value: object) -> str:
    return json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)


def _stable_id(prefix: str, value: object) -> str:
    digest = hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest}"


def _value_parts(value: JsonScalar) -> tuple[ValueKind, str, str]:
    if value is None:
        return ("null", "null", "null")
    if isinstance(value, bool):
        text = "true" if value else "false"
        return ("boolean", text, text)
    if isinstance(value, int):
        return ("integer", str(value), str(value))
    if isinstance(value, float):
        text = _canonical_json(value)
        return ("number", text, text)
    display = unicodedata.normalize("NFKC", value).strip()
    return ("string", display.casefold(), display)


def _entity_type(value: str) -> str:
    candidate = unicodedata.normalize("NFKC", value).strip().casefold()
    return candidate if _TYPE_RE.fullmatch(candidate) else "value"


def _host_scope(value: JsonScalar) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = unicodedata.normalize("NFKC", value).strip().casefold().rstrip(".")
    return normalized or None


def _normalize_entity_value(entity_type: str, canonical: str) -> str:
    try:
        if entity_type in {"ip", "ip_address"}:
            return str(ipaddress.ip_address(canonical))
    except ValueError:
        return canonical
    if entity_type in {"domain", "host", "hostname"}:
        return canonical.rstrip(".")
    if entity_type in {"file_path", "path", "windows_path"}:
        return canonical.replace("\\", "/").rstrip("/")
    return canonical


def _typed_reference(value: str) -> tuple[str, str] | None:
    match = _TYPED_REFERENCE_RE.fullmatch(value.strip())
    if match is None or not match.group(2).strip():
        return None
    return (_entity_type(match.group(1)), match.group(2).strip())


def _optional_alias(qualifiers: dict[str, JsonScalar], key: str) -> str | None:
    value = qualifiers.get(key)
    if not isinstance(value, str):
        return None
    alias = unicodedata.normalize("NFKC", value).strip()
    return alias or None


def _entity(
    case_id: str,
    entity_type: str,
    value: JsonScalar,
    host: JsonScalar,
    extra_alias: str | None,
) -> _EntitySpec:
    kind, canonical, display = _value_parts(value)
    entity_type = _entity_type(entity_type)
    canonical = _normalize_entity_value(entity_type, canonical)
    scope = None if entity_type in {"host", "hostname"} else _host_scope(host)
    entity_id = _stable_id(
        "ge",
        {
            "case_id": case_id,
            "entity_type": entity_type,
            "value_kind": kind,
            "canonical_value": canonical,
            "host_scope": scope,
        },
    )
    aliases = tuple(dict.fromkeys(alias for alias in (display, extra_alias) if alias))
    return _EntitySpec(
        entity_id=entity_id,
        entity_type=entity_type,
        value_kind=kind,
        canonical_value=canonical,
        display_value=display,
        host_scope=scope,
        aliases=aliases,
    )


def _relation_predicate(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    return _PREDICATE_SEPARATORS.sub("_", normalized).strip("_") or "related_to"


def _subject_entity(case_id: str, subject: str, qualifiers: dict[str, JsonScalar]) -> _EntitySpec:
    reference = _typed_reference(subject)
    entity_type, value = reference if reference is not None else ("value", subject)
    return _entity(
        case_id,
        entity_type,
        value,
        qualifiers.get("subject_host"),
        _optional_alias(qualifiers, "subject_alias"),
    )


def _target_entity(
    case_id: str,
    predicate: str,
    object_value: JsonScalar,
    qualifiers: dict[str, JsonScalar],
) -> _EntitySpec:
    explicit_type = qualifiers.get("object_type")
    if isinstance(explicit_type, str):
        entity_type = _entity_type(explicit_type)
        value = object_value
    elif _relation_predicate(predicate) in _OBJECT_TYPES:
        entity_type = _OBJECT_TYPES[_relation_predicate(predicate)]
        value = object_value
    elif isinstance(object_value, str) and (reference := _typed_reference(object_value)):
        entity_type, value = reference
    else:
        entity_type, value = "value", object_value
    return _entity(
        case_id,
        entity_type,
        value,
        qualifiers.get("object_host"),
        _optional_alias(qualifiers, "object_alias"),
    )


def _normalized_time(value: str) -> tuple[str | None, int | None, TimeNormalizationState]:
    encoded = value.strip()
    if encoded.endswith("Z"):
        encoded = f"{encoded[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(encoded)
    except ValueError:
        return (None, None, "unparseable")
    offset = parsed.utcoffset()
    if parsed.tzinfo is None or offset is None:
        return (None, None, "naive")
    offset_minutes = int(offset.total_seconds() / 60)
    normalized = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return (normalized, offset_minutes, "normalized")


def _events_for_relation(
    edge_id: str,
    qualifiers: dict[str, JsonScalar],
    anchors: list[_AnchorSpec],
) -> tuple[_EventSpec, ...]:
    candidates: list[tuple[str | None, str, str]] = []
    qualifier_time = qualifiers.get("event_time")
    if isinstance(qualifier_time, str) and qualifier_time.strip():
        candidates.append((None, "qualifier:event_time", qualifier_time))
    else:
        candidates.extend(
            (anchor.anchor_id, f"anchor:{anchor.anchor_id}", anchor.event_time)
            for anchor in anchors
            if anchor.role == "supports" and anchor.event_time is not None
        )

    events: list[_EventSpec] = []
    for anchor_id, origin, original in sorted(set(candidates), key=lambda item: item[1:]):
        normalized, offset, state = _normalized_time(original)
        event_id = _stable_id(
            "gev",
            {
                "edge_id": edge_id,
                "anchor_id": anchor_id,
                "time_origin": origin,
                "original_time": original,
            },
        )
        events.append(
            _EventSpec(
                event_id=event_id,
                edge_id=edge_id,
                anchor_id=anchor_id,
                time_origin=origin,
                original_time=original,
                normalized_time_utc=normalized,
                utc_offset_minutes=offset,
                normalization_state=state,
            )
        )
    return tuple(events)


def _anchor_integrity_valid(row: Any) -> bool:
    if (
        row.window_source_id is None
        or row.current_window_id is None
        or row.current_line_start is None
        or row.current_line_end is None
        or row.window_text is None
        or row.current_source_name is None
        or row.current_source_hash is None
    ):
        return False
    raw_text = str(row.window_text)
    char_start = int(row.char_start)
    char_end = int(row.char_end)
    return (
        int(row.anchor_source_id) == int(row.window_source_id)
        and int(row.anchor_window_id) == int(row.current_window_id)
        and int(row.anchor_line_start) == int(row.current_line_start)
        and int(row.anchor_line_end) == int(row.current_line_end)
        and str(row.anchor_source_name) == str(row.current_source_name)
        and str(row.anchor_source_hash) == str(row.current_source_hash)
        and 0 <= char_start < char_end <= len(raw_text)
        and raw_text[char_start:char_end] == str(row.exact_text)
    )


def _derive_relations(conn: Connection, case_id: str) -> tuple[list[_RelationSpec], str | None]:
    from mulder.db import (
        claim_verifications_t,
        claims_t,
        evidence_anchors_t,
        findings_t,
        sources_t,
        windows_t,
    )

    claim_rows = conn.execute(
        select(claims_t)
        .select_from(claims_t.join(findings_t, claims_t.c.finding_id == findings_t.c.finding_id))
        .where((findings_t.c.case_id == case_id) & (findings_t.c.is_deleted == 0))
        .order_by(claims_t.c.claim_id)
    ).fetchall()
    claim_ids = [str(row.claim_id) for row in claim_rows]
    if not claim_ids:
        return ([], None)

    verification_rows = conn.execute(
        select(claim_verifications_t)
        .where(claim_verifications_t.c.claim_id.in_(claim_ids))
        .order_by(
            claim_verifications_t.c.claim_id,
            claim_verifications_t.c.verified_at,
            claim_verifications_t.c.verification_id,
        )
    ).fetchall()
    latest_verification = {str(row.claim_id): row for row in verification_rows}
    watermark = (
        max(f"{row.verified_at}#{row.verification_id}" for row in latest_verification.values())
        if latest_verification
        else None
    )
    eligible_claim_ids = [
        str(row.claim_id)
        for row in claim_rows
        if row.epistemic_state == "verified"
        and str(row.claim_id) in latest_verification
        and latest_verification[str(row.claim_id)].result == "verified"
    ]
    if not eligible_claim_ids:
        return ([], watermark)

    anchor_rows = conn.execute(
        select(
            evidence_anchors_t.c.anchor_id,
            evidence_anchors_t.c.claim_id,
            evidence_anchors_t.c.source_id.label("anchor_source_id"),
            evidence_anchors_t.c.source_name.label("anchor_source_name"),
            evidence_anchors_t.c.source_hash.label("anchor_source_hash"),
            evidence_anchors_t.c.window_id.label("anchor_window_id"),
            evidence_anchors_t.c.line_start.label("anchor_line_start"),
            evidence_anchors_t.c.line_end.label("anchor_line_end"),
            evidence_anchors_t.c.char_start,
            evidence_anchors_t.c.char_end,
            evidence_anchors_t.c.exact_text,
            evidence_anchors_t.c.role,
            windows_t.c.source_id.label("window_source_id"),
            windows_t.c.raw_text.label("window_text"),
            windows_t.c.event_time,
            windows_t.c.window_id.label("current_window_id"),
            windows_t.c.line_start.label("current_line_start"),
            windows_t.c.line_end.label("current_line_end"),
            sources_t.c.source_name.label("current_source_name"),
            sources_t.c.source_hash.label("current_source_hash"),
            sources_t.c.source_path,
            sources_t.c.extractor,
        )
        .select_from(
            evidence_anchors_t.outerjoin(
                windows_t, evidence_anchors_t.c.window_id == windows_t.c.window_id
            ).outerjoin(sources_t, windows_t.c.source_id == sources_t.c.source_id)
        )
        .where(evidence_anchors_t.c.claim_id.in_(eligible_claim_ids))
        .order_by(evidence_anchors_t.c.claim_id, evidence_anchors_t.c.anchor_id)
    ).fetchall()
    anchors_by_claim: dict[str, list[Any]] = defaultdict(list)
    for row in anchor_rows:
        anchors_by_claim[str(row.claim_id)].append(row)

    relations: list[_RelationSpec] = []
    for claim_row in claim_rows:
        claim_id = str(claim_row.claim_id)
        if claim_id not in eligible_claim_ids:
            continue
        raw_anchor_rows = anchors_by_claim[claim_id]
        if not raw_anchor_rows or not all(_anchor_integrity_valid(row) for row in raw_anchor_rows):
            continue
        anchors = [
            _AnchorSpec(
                anchor_id=str(row.anchor_id),
                source_id=int(row.anchor_source_id),
                source_name=str(row.anchor_source_name),
                source_hash=str(row.anchor_source_hash),
                exact_text=str(row.exact_text),
                role=str(row.role),
                event_time=str(row.event_time) if row.event_time is not None else None,
                commitment=_stable_id(
                    "gac",
                    {
                        "anchor_id": str(row.anchor_id),
                        "source_id": int(row.anchor_source_id),
                        "source_name": str(row.anchor_source_name),
                        "source_path": str(row.source_path),
                        "source_hash": str(row.anchor_source_hash),
                        "extractor": str(row.extractor),
                        "window_id": int(row.anchor_window_id),
                        "line_start": int(row.anchor_line_start),
                        "line_end": int(row.anchor_line_end),
                        "char_start": int(row.char_start),
                        "char_end": int(row.char_end),
                        "exact_text": str(row.exact_text),
                        "role": str(row.role),
                    },
                ),
            )
            for row in raw_anchor_rows
        ]
        supporting = [anchor for anchor in anchors if anchor.role == "supports"]
        if not supporting:
            continue
        qualifiers: dict[str, JsonScalar] = json.loads(str(claim_row.qualifiers))
        object_value: JsonScalar = json.loads(str(claim_row.object_value))
        source = _subject_entity(case_id, str(claim_row.subject), qualifiers)
        target = _target_entity(
            case_id,
            str(claim_row.predicate),
            object_value,
            qualifiers,
        )
        verification = latest_verification[claim_id]
        qualifiers_json = _canonical_json(qualifiers)
        edge_id = _stable_id(
            "gre",
            {
                "derivation_rule": GRAPH_DERIVATION_RULE,
                "derivation_version": GRAPH_DERIVATION_VERSION,
                "claim_id": claim_id,
                "verification_id": str(verification.verification_id),
                "source_entity_id": source.entity_id,
                "target_entity_id": target.entity_id,
                "predicate": _relation_predicate(str(claim_row.predicate)),
                "qualifiers": qualifiers,
                "anchor_commitments": [anchor.commitment for anchor in supporting],
            },
        )
        relations.append(
            _RelationSpec(
                edge_id=edge_id,
                source=source,
                target=target,
                predicate=_relation_predicate(str(claim_row.predicate)),
                claim_id=claim_id,
                verification_id=str(verification.verification_id),
                qualifiers_json=qualifiers_json,
                anchor_ids=tuple(anchor.anchor_id for anchor in supporting),
                anchor_commitments=tuple(anchor.commitment for anchor in supporting),
                events=_events_for_relation(edge_id, qualifiers, supporting),
            )
        )
    return (relations, watermark)


def _projection_input_sha256(relations: list[_RelationSpec]) -> str:
    document = [
        {
            "edge_id": relation.edge_id,
            "source": relation.source.entity_id,
            "target": relation.target.entity_id,
            "predicate": relation.predicate,
            "claim_id": relation.claim_id,
            "verification_id": relation.verification_id,
            "qualifiers": json.loads(relation.qualifiers_json),
            "anchors": relation.anchor_commitments,
            "events": [event.event_id for event in relation.events],
        }
        for relation in sorted(relations, key=lambda item: item.edge_id)
    ]
    return hashlib.sha256(_canonical_json(document).encode("utf-8")).hexdigest()


def _upsert(
    conn: Connection,
    table: Table,
    primary_key: str,
    values: dict[str, object],
    *,
    preserve: frozenset[str] = frozenset(),
) -> None:
    statement = sqlite_insert(table).values(**values)
    updates = {
        key: getattr(statement.excluded, key)
        for key in values
        if key != primary_key and key not in preserve
    }
    conn.execute(
        statement.on_conflict_do_update(
            index_elements=[getattr(table.c, primary_key)],
            set_=updates,
        )
    )


def _projection_from_row(row: Any) -> GraphProjection:
    return GraphProjection(
        projection_id=row.projection_id,
        case_id=row.case_id,
        derivation_rule=row.derivation_rule,
        derivation_version=row.derivation_version,
        input_sha256=row.input_sha256,
        source_verification_watermark=row.source_verification_watermark,
        state=row.state,
        supersedes_projection_id=row.supersedes_projection_id,
        superseded_by_projection_id=row.superseded_by_projection_id,
    )


def _rebuild_projection(conn: Connection, case_id: str) -> GraphBuildResult:
    """Internal atomic implementation for :meth:`CaseDB.rebuild_entity_graph`."""
    from mulder.db import (
        graph_aliases_t,
        graph_edge_anchors_t,
        graph_entities_t,
        graph_events_t,
        graph_projections_t,
        graph_relations_t,
    )

    relations, watermark = _derive_relations(conn, case_id)
    input_sha256 = _projection_input_sha256(relations)
    active_row = conn.execute(
        select(graph_projections_t)
        .where(
            (graph_projections_t.c.case_id == case_id) & (graph_projections_t.c.state == "active")
        )
        .limit(1)
    ).fetchone()
    unchanged = (
        active_row is not None
        and str(active_row.derivation_rule) == GRAPH_DERIVATION_RULE
        and str(active_row.derivation_version) == GRAPH_DERIVATION_VERSION
        and str(active_row.input_sha256) == input_sha256
    )
    supersedes = None if active_row is None or unchanged else str(active_row.projection_id)
    if unchanged:
        assert active_row is not None
        projection_id = str(active_row.projection_id)
    else:
        projection_id = _stable_id(
            "gp",
            {
                "case_id": case_id,
                "derivation_rule": GRAPH_DERIVATION_RULE,
                "derivation_version": GRAPH_DERIVATION_VERSION,
                "input_sha256": input_sha256,
                "supersedes_projection_id": supersedes,
            },
        )
    _upsert(
        conn,
        graph_projections_t,
        "projection_id",
        {
            "projection_id": projection_id,
            "case_id": case_id,
            "derivation_rule": GRAPH_DERIVATION_RULE,
            "derivation_version": GRAPH_DERIVATION_VERSION,
            "input_sha256": input_sha256,
            "source_verification_watermark": watermark,
            "state": "active",
            "supersedes_projection_id": supersedes,
            "superseded_by_projection_id": None,
        },
        preserve=frozenset({"supersedes_projection_id"}) if unchanged else frozenset(),
    )
    if not unchanged:
        conn.execute(
            update(graph_projections_t)
            .where(
                (graph_projections_t.c.case_id == case_id)
                & (graph_projections_t.c.state == "active")
                & (graph_projections_t.c.projection_id != projection_id)
            )
            .values(state="superseded", superseded_by_projection_id=projection_id)
        )

    for table in (graph_entities_t, graph_aliases_t, graph_relations_t, graph_events_t):
        conn.execute(
            update(table)
            .where((table.c.case_id == case_id) & (table.c.state == "active"))
            .values(state="superseded", superseded_by_projection_id=projection_id)
        )

    entities = {
        entity.entity_id: entity
        for relation in relations
        for entity in (relation.source, relation.target)
    }
    aliases: dict[str, tuple[_EntitySpec, str, str, bool]] = {}
    for entity in entities.values():
        for index, alias in enumerate(entity.aliases):
            normalized_alias = unicodedata.normalize("NFKC", alias).strip().casefold()
            alias_id = _stable_id(
                "ga", {"entity_id": entity.entity_id, "normalized_alias": normalized_alias}
            )
            aliases[alias_id] = (entity, alias, normalized_alias, index == 0)

    for entity in entities.values():
        _upsert(
            conn,
            graph_entities_t,
            "entity_id",
            {
                "entity_id": entity.entity_id,
                "case_id": case_id,
                "entity_type": entity.entity_type,
                "value_kind": entity.value_kind,
                "canonical_value": entity.canonical_value,
                "display_value": entity.display_value,
                "host_scope": entity.host_scope,
                "created_projection_id": projection_id,
                "last_seen_projection_id": projection_id,
                "state": "active",
                "superseded_by_projection_id": None,
            },
            preserve=frozenset({"created_projection_id"}),
        )
    for alias_id, (entity, alias, normalized_alias, is_primary) in aliases.items():
        _upsert(
            conn,
            graph_aliases_t,
            "alias_id",
            {
                "alias_id": alias_id,
                "case_id": case_id,
                "entity_id": entity.entity_id,
                "alias": alias,
                "normalized_alias": normalized_alias,
                "is_primary": int(is_primary),
                "created_projection_id": projection_id,
                "last_seen_projection_id": projection_id,
                "state": "active",
                "superseded_by_projection_id": None,
            },
            preserve=frozenset({"created_projection_id"}),
        )
    for relation in relations:
        _upsert(
            conn,
            graph_relations_t,
            "edge_id",
            {
                "edge_id": relation.edge_id,
                "case_id": case_id,
                "source_entity_id": relation.source.entity_id,
                "target_entity_id": relation.target.entity_id,
                "predicate": relation.predicate,
                "claim_id": relation.claim_id,
                "verification_id": relation.verification_id,
                "qualifiers": relation.qualifiers_json,
                "derivation_rule": GRAPH_DERIVATION_RULE,
                "derivation_version": GRAPH_DERIVATION_VERSION,
                "created_projection_id": projection_id,
                "last_seen_projection_id": projection_id,
                "state": "active",
                "superseded_by_projection_id": None,
            },
            preserve=frozenset({"created_projection_id"}),
        )
        for anchor_id in relation.anchor_ids:
            conn.execute(
                sqlite_insert(graph_edge_anchors_t)
                .values(edge_id=relation.edge_id, anchor_id=anchor_id)
                .on_conflict_do_nothing()
            )
        for event in relation.events:
            _upsert(
                conn,
                graph_events_t,
                "event_id",
                {
                    "event_id": event.event_id,
                    "case_id": case_id,
                    "edge_id": event.edge_id,
                    "anchor_id": event.anchor_id,
                    "time_origin": event.time_origin,
                    "original_time": event.original_time,
                    "normalized_time_utc": event.normalized_time_utc,
                    "utc_offset_minutes": event.utc_offset_minutes,
                    "normalization_state": event.normalization_state,
                    "created_projection_id": projection_id,
                    "last_seen_projection_id": projection_id,
                    "state": "active",
                    "superseded_by_projection_id": None,
                },
                preserve=frozenset({"created_projection_id"}),
            )

    projection_row = conn.execute(
        select(graph_projections_t).where(graph_projections_t.c.projection_id == projection_id)
    ).one()
    return GraphBuildResult(
        projection=_projection_from_row(projection_row),
        unchanged=unchanged,
        verified_claims=len(relations),
        active_entities=len(entities),
        active_aliases=len(aliases),
        active_relations=len(relations),
        active_events=sum(len(relation.events) for relation in relations),
    )


def _entity_from_row(row: Any) -> GraphEntity:
    return GraphEntity(
        entity_id=row.entity_id,
        entity_type=row.entity_type,
        value_kind=row.value_kind,
        canonical_value=row.canonical_value,
        display_value=row.display_value,
        host_scope=row.host_scope,
        state=row.state,
        superseded_by_projection_id=row.superseded_by_projection_id,
    )


def _alias_from_row(row: Any) -> GraphAlias:
    return GraphAlias(
        alias_id=row.alias_id,
        entity_id=row.entity_id,
        alias=row.alias,
        normalized_alias=row.normalized_alias,
        is_primary=bool(row.is_primary),
        state=row.state,
        superseded_by_projection_id=row.superseded_by_projection_id,
    )


def _relation_from_row(row: Any) -> GraphRelation:
    return GraphRelation(
        edge_id=row.edge_id,
        source_entity_id=row.source_entity_id,
        target_entity_id=row.target_entity_id,
        predicate=row.predicate,
        claim_id=row.claim_id,
        verification_id=row.verification_id,
        qualifiers=json.loads(row.qualifiers),
        derivation_rule=row.derivation_rule,
        derivation_version=row.derivation_version,
        state=row.state,
        superseded_by_projection_id=row.superseded_by_projection_id,
    )


def _event_from_row(row: Any) -> GraphEvent:
    return GraphEvent(
        event_id=row.event_id,
        edge_id=row.edge_id,
        anchor_id=row.anchor_id,
        time_origin=row.time_origin,
        original_time=row.original_time,
        normalized_time_utc=row.normalized_time_utc,
        utc_offset_minutes=row.utc_offset_minutes,
        normalization_state=row.normalization_state,
        state=row.state,
        superseded_by_projection_id=row.superseded_by_projection_id,
    )


def _read_snapshot(conn: Connection, case_id: str, *, include_superseded: bool) -> GraphSnapshot:
    """Internal implementation for the bounded graph snapshot interface."""
    from mulder.db import (
        graph_aliases_t,
        graph_entities_t,
        graph_events_t,
        graph_projections_t,
        graph_relations_t,
    )

    tables = (
        graph_projections_t,
        graph_entities_t,
        graph_aliases_t,
        graph_relations_t,
        graph_events_t,
    )
    rows: list[list[Any]] = []
    for table in tables:
        statement = select(table).where(table.c.case_id == case_id)
        if not include_superseded:
            statement = statement.where(table.c.state == "active")
        primary_key = list(table.primary_key.columns)[0]
        rows.append(list(conn.execute(statement.order_by(primary_key)).fetchall()))
    projection_rows, entity_rows, alias_rows, relation_rows, event_rows = rows
    projections = [_projection_from_row(row) for row in projection_rows]
    active_projection = next(
        (projection for projection in projections if projection.state == "active"), None
    )
    aliases = [_alias_from_row(row) for row in alias_rows]
    collision_entities: dict[str, set[str]] = defaultdict(set)
    for alias in aliases:
        if alias.state == "active":
            collision_entities[alias.normalized_alias].add(alias.entity_id)
    collisions = [
        AliasCollision(normalized_alias=alias, entity_ids=sorted(entity_ids))
        for alias, entity_ids in sorted(collision_entities.items())
        if len(entity_ids) > 1
    ]
    return GraphSnapshot(
        case_id=case_id,
        active_projection=active_projection,
        projections=projections,
        entities=[_entity_from_row(row) for row in entity_rows],
        aliases=aliases,
        alias_collisions=collisions,
        relations=[_relation_from_row(row) for row in relation_rows],
        events=[_event_from_row(row) for row in event_rows],
    )


def _read_edge_provenance(conn: Connection, case_id: str, edge_id: str) -> EdgeProvenance | None:
    """Internal implementation of the exact evidence traversal interface."""
    from mulder.db import (
        claim_verifications_t,
        claims_t,
        evidence_anchors_t,
        graph_edge_anchors_t,
        graph_relations_t,
        sources_t,
        windows_t,
    )

    relation_row = conn.execute(
        select(graph_relations_t).where(
            (graph_relations_t.c.case_id == case_id) & (graph_relations_t.c.edge_id == edge_id)
        )
    ).fetchone()
    if relation_row is None:
        return None
    claim_row = conn.execute(
        select(claims_t, claim_verifications_t)
        .select_from(
            claims_t.join(
                claim_verifications_t,
                (claim_verifications_t.c.verification_id == relation_row.verification_id)
                & (claim_verifications_t.c.claim_id == claims_t.c.claim_id),
            )
        )
        .where(claims_t.c.claim_id == relation_row.claim_id)
    ).one()
    anchor_rows = conn.execute(
        select(
            evidence_anchors_t,
            sources_t.c.source_path,
            sources_t.c.extractor,
            windows_t.c.raw_text.label("window_text"),
        )
        .select_from(
            graph_edge_anchors_t.join(
                evidence_anchors_t,
                graph_edge_anchors_t.c.anchor_id == evidence_anchors_t.c.anchor_id,
            )
            .join(sources_t, evidence_anchors_t.c.source_id == sources_t.c.source_id)
            .join(windows_t, evidence_anchors_t.c.window_id == windows_t.c.window_id)
        )
        .where(
            (graph_edge_anchors_t.c.edge_id == edge_id)
            & (evidence_anchors_t.c.claim_id == relation_row.claim_id)
        )
        .order_by(evidence_anchors_t.c.anchor_id)
    ).fetchall()
    return EdgeProvenance(
        relation=_relation_from_row(relation_row),
        claim=GraphClaimProvenance(
            claim_id=claim_row.claim_id,
            finding_id=claim_row.finding_id,
            statement=claim_row.statement,
            subject=claim_row.subject,
            predicate=claim_row.predicate,
            object_value=json.loads(claim_row.object_value),
            qualifiers=json.loads(claim_row.qualifiers),
            verification_id=claim_row.verification_id,
            verification_result=claim_row.result,
            verification_reason_code=claim_row.reason_code,
            verifier_name=claim_row.verifier_name,
            verifier_version=claim_row.verifier_version,
            verified_at=claim_row.verified_at,
        ),
        anchors=[
            GraphAnchorProvenance(
                anchor_id=row.anchor_id,
                tool_call_id=row.tool_call_id,
                source_id=row.source_id,
                source_name=row.source_name,
                source_path=row.source_path,
                source_hash=row.source_hash,
                extractor=row.extractor,
                window_id=row.window_id,
                line_start=row.line_start,
                line_end=row.line_end,
                char_start=row.char_start,
                char_end=row.char_end,
                exact_text=row.exact_text,
                window_text=row.window_text,
            )
            for row in anchor_rows
        ],
    )
