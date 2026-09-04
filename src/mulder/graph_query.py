"""Bounded, provenance-preserving queries over the verified-claim graph.

Callers select one of four typed operations.  This module owns traversal,
historical visibility, result limits, and evidence selectors; SQL remains an
implementation detail behind :meth:`mulder.db.CaseDB.query_entity_graph`.
"""

from __future__ import annotations

import html
import math
import unicodedata
from collections import defaultdict
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Connection, Select, and_, func, or_, select

from mulder.graph import (
    GraphAlias,
    GraphEntity,
    GraphEvent,
    GraphRelation,
    _alias_from_row,
    _entity_from_row,
    _event_from_row,
    _read_edge_provenance,
    _relation_from_row,
)

GRAPH_QUERY_SCHEMA_VERSION: Literal["1"] = "1"
MAX_GRAPH_QUERY_RESULTS = 100
MAX_GRAPH_NEIGHBOR_DEPTH = 4
MAX_GRAPH_PATH_DEPTH = 8
MAX_GRAPH_EDGE_EXPANSIONS = 1_000

__all__ = [
    "GRAPH_QUERY_SCHEMA_VERSION",
    "MAX_GRAPH_EDGE_EXPANSIONS",
    "MAX_GRAPH_NEIGHBOR_DEPTH",
    "MAX_GRAPH_PATH_DEPTH",
    "MAX_GRAPH_QUERY_RESULTS",
    "EventsForEntityQuery",
    "GraphAnchorSelector",
    "GraphEvidenceSelector",
    "GraphPath",
    "GraphQueryEdge",
    "GraphQueryEvent",
    "GraphQueryLimit",
    "GraphQueryNode",
    "GraphQueryRequest",
    "GraphQueryResult",
    "GraphSourceSelector",
    "GraphVisualization",
    "HostTimelineQuery",
    "NeighborsQuery",
    "PathBetweenQuery",
    "render_graph_visualization",
]

ClaimState = Literal["legacy_unverified", "unverified", "verified", "contradicted", "inconclusive"]
EdgeVisibility = Literal["verified", "superseded", "refuted"]
Direction = Literal["incoming", "outgoing", "both"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class _QueryBase(_StrictModel):
    include_superseded: bool = False
    include_refuted: bool = False


class NeighborsQuery(_QueryBase):
    """Return the bounded neighborhood around one exact entity identifier."""

    kind: Literal["neighbors"] = "neighbors"
    entity_id: str = Field(min_length=1, max_length=80)
    depth: int = Field(default=1, ge=1, le=MAX_GRAPH_NEIGHBOR_DEPTH)
    direction: Direction = "both"
    limit: int = Field(default=50, ge=1, le=MAX_GRAPH_QUERY_RESULTS)


class PathBetweenQuery(_QueryBase):
    """Find one deterministic shortest path without accepting a graph language."""

    kind: Literal["path_between"] = "path_between"
    source_entity_id: str = Field(min_length=1, max_length=80)
    target_entity_id: str = Field(min_length=1, max_length=80)
    max_depth: int = Field(default=6, ge=1, le=MAX_GRAPH_PATH_DEPTH)
    directed: bool = False


class EventsForEntityQuery(_QueryBase):
    """Return bounded timestamped relations touching one exact entity."""

    kind: Literal["events_for_entity"] = "events_for_entity"
    entity_id: str = Field(min_length=1, max_length=80)
    limit: int = Field(default=50, ge=1, le=MAX_GRAPH_QUERY_RESULTS)


class HostTimelineQuery(_QueryBase):
    """Return bounded events whose relation has an endpoint scoped to a host."""

    kind: Literal["host_timeline"] = "host_timeline"
    host: str = Field(min_length=1, max_length=255)
    limit: int = Field(default=50, ge=1, le=MAX_GRAPH_QUERY_RESULTS)

    @field_validator("host")
    @classmethod
    def _host_is_not_whitespace(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("host must not be blank")
        return value


GraphQueryRequest = NeighborsQuery | PathBetweenQuery | EventsForEntityQuery | HostTimelineQuery


class GraphSourceSelector(_StrictModel):
    """Stable selector for one evidence source."""

    source_id: int
    source_name: str
    source_path: str
    source_hash: str
    extractor: str


class GraphAnchorSelector(_StrictModel):
    """Stable selector locating an exact supporting span within a source."""

    anchor_id: str
    tool_call_id: str
    source: GraphSourceSelector
    window_id: int
    line_start: int
    line_end: int
    char_start: int
    char_end: int


class GraphEvidenceSelector(_StrictModel):
    """Claim, verification, anchor, and source selectors retained by a graph item."""

    claim_id: str
    projection_verification_id: str
    current_claim_state: ClaimState
    anchors: list[GraphAnchorSelector] = Field(min_length=1)


class GraphQueryNode(_StrictModel):
    """An entity and the returned claim-derived selectors that justify its presence."""

    entity: GraphEntity
    aliases: list[GraphAlias] = Field(default_factory=list)
    evidence_selectors: list[GraphEvidenceSelector] = Field(min_length=1)


class GraphQueryEdge(_StrictModel):
    """A relation with explicit current/historical visibility and provenance selectors."""

    relation: GraphRelation
    visibility: EdgeVisibility
    evidence_selector: GraphEvidenceSelector


class GraphQueryEvent(_StrictModel):
    """A timestamped edge retaining the same provenance selector as its relation."""

    event: GraphEvent
    visibility: EdgeVisibility
    evidence_selector: GraphEvidenceSelector


class GraphPath(_StrictModel):
    """One ordered path through node and edge identifiers."""

    node_ids: list[str] = Field(min_length=1)
    edge_ids: list[str] = Field(default_factory=list)


class GraphQueryLimit(_StrictModel):
    """Server-owned work/output bounds and whether a bound cut off the answer."""

    result_limit: int = Field(ge=1, le=MAX_GRAPH_QUERY_RESULTS)
    depth_limit: int = Field(ge=0, le=MAX_GRAPH_PATH_DEPTH)
    expansion_limit: int = Field(default=MAX_GRAPH_EDGE_EXPANSIONS, ge=1)
    expansions: int = Field(ge=0, le=MAX_GRAPH_EDGE_EXPANSIONS)
    truncated: bool


class GraphQueryResult(_StrictModel):
    """Shared deterministic read model for MCP, reports, and review views."""

    schema_version: Literal["1"] = GRAPH_QUERY_SCHEMA_VERSION
    case_id: str
    projection_id: str | None = None
    query: GraphQueryRequest = Field(discriminator="kind")
    limits: GraphQueryLimit
    no_path: bool = False
    paths: list[GraphPath] = Field(default_factory=list)
    nodes: list[GraphQueryNode] = Field(default_factory=list)
    edges: list[GraphQueryEdge] = Field(default_factory=list)
    events: list[GraphQueryEvent] = Field(default_factory=list)


class GraphVisualization(_StrictModel):
    """Deterministic dependency-free static rendering of a graph query result."""

    schema_version: Literal["1"] = GRAPH_QUERY_SCHEMA_VERSION
    query_kind: Literal["neighbors", "path_between", "events_for_entity", "host_timeline"]
    markdown: str
    svg: str


def _visibility_condition(request: GraphQueryRequest) -> Any:
    from mulder.db import claims_t, graph_relations_t

    active = graph_relations_t.c.state == "active"
    visible: list[Any] = [active]
    if request.include_superseded:
        visible.append(
            and_(
                graph_relations_t.c.state == "superseded",
                claims_t.c.epistemic_state != "contradicted",
            )
        )
    if request.include_refuted:
        visible.append(
            and_(
                graph_relations_t.c.state == "superseded",
                claims_t.c.epistemic_state == "contradicted",
            )
        )
    return or_(*visible)


def _relation_statement(case_id: str, request: GraphQueryRequest) -> Select[Any]:
    from mulder.db import claims_t, graph_relations_t

    return (
        select(
            graph_relations_t,
            claims_t.c.epistemic_state.label("current_claim_state"),
        )
        .select_from(
            graph_relations_t.join(claims_t, graph_relations_t.c.claim_id == claims_t.c.claim_id)
        )
        .where((graph_relations_t.c.case_id == case_id) & _visibility_condition(request))
    )


def _edge_visibility(row: Any) -> EdgeVisibility:
    if str(row.state) == "active":
        return "verified"
    if str(row.current_claim_state) == "contradicted":
        return "refuted"
    return "superseded"


def _neighbors(
    conn: Connection,
    case_id: str,
    request: NeighborsQuery,
) -> tuple[list[Any], int, bool]:
    from mulder.db import graph_relations_t

    selected: dict[str, Any] = {}
    visited = {request.entity_id}
    frontier = {request.entity_id}
    expansions = 0
    truncated = False
    for _depth in range(request.depth):
        if not frontier or len(selected) >= request.limit:
            break
        incident: Any
        if request.direction == "outgoing":
            incident = graph_relations_t.c.source_entity_id.in_(sorted(frontier))
        elif request.direction == "incoming":
            incident = graph_relations_t.c.target_entity_id.in_(sorted(frontier))
        else:
            incident = or_(
                graph_relations_t.c.source_entity_id.in_(sorted(frontier)),
                graph_relations_t.c.target_entity_id.in_(sorted(frontier)),
            )
        statement = _relation_statement(case_id, request).where(incident)
        if selected:
            statement = statement.where(graph_relations_t.c.edge_id.not_in(sorted(selected)))
        remaining_expansions = MAX_GRAPH_EDGE_EXPANSIONS - expansions
        remaining_results = request.limit - len(selected)
        fetch_limit = min(remaining_expansions, remaining_results) + 1
        rows = list(
            conn.execute(
                statement.order_by(graph_relations_t.c.edge_id).limit(fetch_limit)
            ).fetchall()
        )
        accepted = rows[: min(remaining_expansions, remaining_results)]
        expansions += len(accepted)
        if len(rows) > len(accepted):
            truncated = True
        next_frontier: set[str] = set()
        for row in accepted:
            selected[str(row.edge_id)] = row
            if request.direction != "incoming" and str(row.source_entity_id) in frontier:
                next_frontier.add(str(row.target_entity_id))
            if request.direction != "outgoing" and str(row.target_entity_id) in frontier:
                next_frontier.add(str(row.source_entity_id))
            if request.direction == "both":
                if str(row.target_entity_id) in frontier:
                    next_frontier.add(str(row.source_entity_id))
                if str(row.source_entity_id) in frontier:
                    next_frontier.add(str(row.target_entity_id))
        next_frontier -= visited
        visited.update(next_frontier)
        frontier = next_frontier
        if len(selected) >= request.limit and _depth + 1 < request.depth and frontier:
            truncated = True
        if expansions >= MAX_GRAPH_EDGE_EXPANSIONS:
            truncated = True
            break
    return ([selected[key] for key in sorted(selected)], expansions, truncated)


def _path_between(
    conn: Connection,
    case_id: str,
    request: PathBetweenQuery,
) -> tuple[list[Any], list[GraphPath], int, bool, bool]:
    from mulder.db import graph_relations_t

    if request.source_entity_id == request.target_entity_id:
        return (
            [],
            [GraphPath(node_ids=[request.source_entity_id])],
            0,
            False,
            False,
        )

    visited = {request.source_entity_id}
    frontier = {request.source_entity_id}
    parents: dict[str, tuple[str, str]] = {}
    edge_rows: dict[str, Any] = {}
    considered: set[str] = set()
    expansions = 0
    truncated = False
    found = False

    for _depth in range(request.max_depth):
        if not frontier or found:
            break
        incident: Any
        if request.directed:
            incident = graph_relations_t.c.source_entity_id.in_(sorted(frontier))
        else:
            incident = or_(
                graph_relations_t.c.source_entity_id.in_(sorted(frontier)),
                graph_relations_t.c.target_entity_id.in_(sorted(frontier)),
            )
        statement = _relation_statement(case_id, request).where(incident)
        if considered:
            statement = statement.where(graph_relations_t.c.edge_id.not_in(sorted(considered)))
        remaining = MAX_GRAPH_EDGE_EXPANSIONS - expansions
        rows = list(
            conn.execute(
                statement.order_by(graph_relations_t.c.edge_id).limit(remaining + 1)
            ).fetchall()
        )
        accepted = rows[:remaining]
        expansions += len(accepted)
        if len(rows) > len(accepted):
            truncated = True
        adjacency: dict[str, list[tuple[str, str, Any]]] = defaultdict(list)
        for row in accepted:
            edge_id = str(row.edge_id)
            considered.add(edge_id)
            source_id = str(row.source_entity_id)
            target_id = str(row.target_entity_id)
            edge_rows[edge_id] = row
            adjacency[source_id].append((target_id, edge_id, row))
            if not request.directed:
                adjacency[target_id].append((source_id, edge_id, row))

        next_frontier: set[str] = set()
        for current in sorted(frontier):
            for candidate, edge_id, _row in sorted(
                adjacency.get(current, []), key=lambda item: (item[1], item[0])
            ):
                if candidate in visited:
                    continue
                visited.add(candidate)
                parents[candidate] = (current, edge_id)
                next_frontier.add(candidate)
                if candidate == request.target_entity_id:
                    found = True
                    break
            if found:
                break
        frontier = next_frontier
        if expansions >= MAX_GRAPH_EDGE_EXPANSIONS:
            truncated = True
            break

    if not found:
        return ([], [], expansions, truncated, True)

    node_ids = [request.target_entity_id]
    edge_ids: list[str] = []
    current = request.target_entity_id
    while current != request.source_entity_id:
        parent, edge_id = parents[current]
        node_ids.append(parent)
        edge_ids.append(edge_id)
        current = parent
    node_ids.reverse()
    edge_ids.reverse()
    rows = [edge_rows[edge_id] for edge_id in edge_ids]
    return (rows, [GraphPath(node_ids=node_ids, edge_ids=edge_ids)], expansions, truncated, False)


def _event_keys_for_entity(
    conn: Connection,
    case_id: str,
    request: EventsForEntityQuery,
) -> tuple[list[tuple[str, str]], bool]:
    from mulder.db import claims_t, graph_events_t, graph_relations_t

    statement = (
        select(graph_events_t.c.event_id, graph_relations_t.c.edge_id)
        .select_from(
            graph_events_t.join(
                graph_relations_t, graph_events_t.c.edge_id == graph_relations_t.c.edge_id
            ).join(claims_t, graph_relations_t.c.claim_id == claims_t.c.claim_id)
        )
        .where(
            (graph_events_t.c.case_id == case_id)
            & (graph_relations_t.c.case_id == case_id)
            & or_(
                graph_relations_t.c.source_entity_id == request.entity_id,
                graph_relations_t.c.target_entity_id == request.entity_id,
            )
            & _visibility_condition(request)
        )
        .order_by(
            graph_events_t.c.normalized_time_utc.is_(None),
            func.coalesce(graph_events_t.c.normalized_time_utc, graph_events_t.c.original_time),
            graph_events_t.c.event_id,
        )
        .limit(request.limit + 1)
    )
    rows = list(conn.execute(statement).fetchall())
    return (
        [(str(row.event_id), str(row.edge_id)) for row in rows[: request.limit]],
        len(rows) > request.limit,
    )


def _normalized_host(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().casefold().rstrip(".")


def _event_keys_for_host(
    conn: Connection,
    case_id: str,
    request: HostTimelineQuery,
) -> tuple[list[tuple[str, str]], bool]:
    from mulder.db import claims_t, graph_entities_t, graph_events_t, graph_relations_t

    source_entity = graph_entities_t.alias("timeline_source_entity")
    target_entity = graph_entities_t.alias("timeline_target_entity")
    host = _normalized_host(request.host)
    endpoint_matches = or_(
        source_entity.c.host_scope == host,
        target_entity.c.host_scope == host,
        and_(
            source_entity.c.entity_type.in_(("host", "hostname")),
            source_entity.c.canonical_value == host,
        ),
        and_(
            target_entity.c.entity_type.in_(("host", "hostname")),
            target_entity.c.canonical_value == host,
        ),
    )
    statement = (
        select(graph_events_t.c.event_id, graph_relations_t.c.edge_id)
        .select_from(
            graph_events_t.join(
                graph_relations_t, graph_events_t.c.edge_id == graph_relations_t.c.edge_id
            )
            .join(claims_t, graph_relations_t.c.claim_id == claims_t.c.claim_id)
            .join(source_entity, graph_relations_t.c.source_entity_id == source_entity.c.entity_id)
            .join(target_entity, graph_relations_t.c.target_entity_id == target_entity.c.entity_id)
        )
        .where(
            (graph_events_t.c.case_id == case_id)
            & (graph_relations_t.c.case_id == case_id)
            & (source_entity.c.case_id == case_id)
            & (target_entity.c.case_id == case_id)
            & endpoint_matches
            & _visibility_condition(request)
        )
        .order_by(
            graph_events_t.c.normalized_time_utc.is_(None),
            func.coalesce(graph_events_t.c.normalized_time_utc, graph_events_t.c.original_time),
            graph_events_t.c.event_id,
        )
        .limit(request.limit + 1)
    )
    rows = list(conn.execute(statement).fetchall())
    return (
        [(str(row.event_id), str(row.edge_id)) for row in rows[: request.limit]],
        len(rows) > request.limit,
    )


def _relations_by_ids(
    conn: Connection,
    case_id: str,
    request: GraphQueryRequest,
    edge_ids: list[str],
) -> list[Any]:
    from mulder.db import graph_relations_t

    if not edge_ids:
        return []
    return list(
        conn.execute(
            _relation_statement(case_id, request)
            .where(graph_relations_t.c.edge_id.in_(edge_ids))
            .order_by(graph_relations_t.c.edge_id)
        ).fetchall()
    )


def _events_by_ids(conn: Connection, case_id: str, event_ids: list[str]) -> list[Any]:
    from mulder.db import graph_events_t

    if not event_ids:
        return []
    return list(
        conn.execute(
            select(graph_events_t)
            .where(
                (graph_events_t.c.case_id == case_id) & graph_events_t.c.event_id.in_(event_ids)
            )
            .order_by(
                graph_events_t.c.normalized_time_utc.is_(None),
                func.coalesce(
                    graph_events_t.c.normalized_time_utc, graph_events_t.c.original_time
                ),
                graph_events_t.c.event_id,
            )
        ).fetchall()
    )


def _evidence_selector(conn: Connection, case_id: str, row: Any) -> GraphEvidenceSelector:
    provenance = _read_edge_provenance(conn, case_id, str(row.edge_id))
    if provenance is None:
        raise RuntimeError(f"graph edge {row.edge_id!s} lost its provenance")
    anchors = [
        GraphAnchorSelector(
            anchor_id=anchor.anchor_id,
            tool_call_id=anchor.tool_call_id,
            source=GraphSourceSelector(
                source_id=anchor.source_id,
                source_name=anchor.source_name,
                source_path=anchor.source_path,
                source_hash=anchor.source_hash,
                extractor=anchor.extractor,
            ),
            window_id=anchor.window_id,
            line_start=anchor.line_start,
            line_end=anchor.line_end,
            char_start=anchor.char_start,
            char_end=anchor.char_end,
        )
        for anchor in provenance.anchors
    ]
    return GraphEvidenceSelector(
        claim_id=str(row.claim_id),
        projection_verification_id=str(row.verification_id),
        current_claim_state=cast(ClaimState, str(row.current_claim_state)),
        anchors=anchors,
    )


def _active_projection_id(conn: Connection, case_id: str) -> str | None:
    from mulder.db import graph_projections_t

    value = conn.execute(
        select(graph_projections_t.c.projection_id)
        .where(
            (graph_projections_t.c.case_id == case_id) & (graph_projections_t.c.state == "active")
        )
        .limit(1)
    ).scalar_one_or_none()
    return str(value) if value is not None else None


def _assemble_result(
    conn: Connection,
    case_id: str,
    request: GraphQueryRequest,
    relation_rows: list[Any],
    *,
    event_rows: list[Any] | None = None,
    expansions: int,
    truncated: bool,
    no_path: bool = False,
    paths: list[GraphPath] | None = None,
) -> GraphQueryResult:
    from mulder.db import graph_aliases_t, graph_entities_t

    edge_selectors = {
        str(row.edge_id): _evidence_selector(conn, case_id, row) for row in relation_rows
    }
    edges = [
        GraphQueryEdge(
            relation=_relation_from_row(row),
            visibility=_edge_visibility(row),
            evidence_selector=edge_selectors[str(row.edge_id)],
        )
        for row in sorted(relation_rows, key=lambda item: str(item.edge_id))
    ]
    entity_ids = sorted(
        {
            str(entity_id)
            for row in relation_rows
            for entity_id in (row.source_entity_id, row.target_entity_id)
        }
    )
    entity_rows = (
        list(
            conn.execute(
                select(graph_entities_t)
                .where(
                    (graph_entities_t.c.case_id == case_id)
                    & graph_entities_t.c.entity_id.in_(entity_ids)
                )
                .order_by(graph_entities_t.c.entity_id)
            ).fetchall()
        )
        if entity_ids
        else []
    )
    alias_rows = (
        list(
            conn.execute(
                select(graph_aliases_t)
                .where(
                    (graph_aliases_t.c.case_id == case_id)
                    & graph_aliases_t.c.entity_id.in_(entity_ids)
                )
                .order_by(graph_aliases_t.c.entity_id, graph_aliases_t.c.alias_id)
            ).fetchall()
        )
        if entity_ids
        else []
    )
    aliases_by_entity: dict[str, list[GraphAlias]] = defaultdict(list)
    for alias_row in alias_rows:
        aliases_by_entity[str(alias_row.entity_id)].append(_alias_from_row(alias_row))
    selectors_by_entity: dict[str, dict[str, GraphEvidenceSelector]] = defaultdict(dict)
    for row in relation_rows:
        selector = edge_selectors[str(row.edge_id)]
        for entity_id in (str(row.source_entity_id), str(row.target_entity_id)):
            selector_key = f"{selector.claim_id}#{selector.projection_verification_id}"
            selectors_by_entity[entity_id][selector_key] = selector
    nodes = [
        GraphQueryNode(
            entity=_entity_from_row(row),
            aliases=aliases_by_entity[str(row.entity_id)],
            evidence_selectors=[
                selectors_by_entity[str(row.entity_id)][selector_key]
                for selector_key in sorted(selectors_by_entity[str(row.entity_id)])
            ],
        )
        for row in entity_rows
        if selectors_by_entity[str(row.entity_id)]
    ]
    query_events = [
        GraphQueryEvent(
            event=_event_from_row(row),
            visibility=next(
                edge.visibility for edge in edges if edge.relation.edge_id == str(row.edge_id)
            ),
            evidence_selector=edge_selectors[str(row.edge_id)],
        )
        for row in (event_rows or [])
        if str(row.edge_id) in edge_selectors
    ]
    if isinstance(request, PathBetweenQuery):
        result_limit = request.max_depth
        depth_limit = request.max_depth
    else:
        result_limit = request.limit
        depth_limit = request.depth if isinstance(request, NeighborsQuery) else 0
    return GraphQueryResult(
        case_id=case_id,
        projection_id=_active_projection_id(conn, case_id),
        query=request,
        limits=GraphQueryLimit(
            result_limit=result_limit,
            depth_limit=depth_limit,
            expansions=expansions,
            truncated=truncated,
        ),
        no_path=no_path,
        paths=paths or [],
        nodes=nodes,
        edges=edges,
        events=query_events,
    )


def _query_graph(
    conn: Connection,
    case_id: str,
    request: GraphQueryRequest,
) -> GraphQueryResult:
    """Internal implementation for the single typed CaseDB query seam."""
    if isinstance(request, NeighborsQuery):
        rows, expansions, truncated = _neighbors(conn, case_id, request)
        return _assemble_result(
            conn,
            case_id,
            request,
            rows,
            expansions=expansions,
            truncated=truncated,
        )
    if isinstance(request, PathBetweenQuery):
        rows, paths, expansions, truncated, no_path = _path_between(conn, case_id, request)
        return _assemble_result(
            conn,
            case_id,
            request,
            rows,
            expansions=expansions,
            truncated=truncated,
            no_path=no_path,
            paths=paths,
        )
    if isinstance(request, EventsForEntityQuery):
        event_keys, truncated = _event_keys_for_entity(conn, case_id, request)
    else:
        event_keys, truncated = _event_keys_for_host(conn, case_id, request)
    event_ids = [event_id for event_id, _edge_id in event_keys]
    edge_ids = sorted({edge_id for _event_id, edge_id in event_keys})
    rows = _relations_by_ids(conn, case_id, request, edge_ids)
    event_rows = _events_by_ids(conn, case_id, event_ids)
    return _assemble_result(
        conn,
        case_id,
        request,
        rows,
        event_rows=event_rows,
        expansions=len(event_keys),
        truncated=truncated,
    )


def _markdown_cell(value: object) -> str:
    return (
        html.escape(str(value), quote=False)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _selector_summary(selector: GraphEvidenceSelector) -> str:
    anchors = ", ".join(anchor.anchor_id for anchor in selector.anchors)
    sources = ", ".join(sorted({anchor.source.source_name for anchor in selector.anchors}))
    return f"claim={selector.claim_id}; anchors={anchors}; sources={sources}"


def _render_markdown(result: GraphQueryResult) -> str:
    lines = [
        f"### Entity graph: {_markdown_cell(result.query.kind)}",
        "",
        f"Projection: `{_markdown_cell(result.projection_id or 'none')}`. "
        f"Truncated: `{str(result.limits.truncated).lower()}`.",
        "",
    ]
    if result.no_path:
        lines.extend(["No path found within the enforced depth and expansion limits.", ""])
    if result.nodes:
        lines.extend(["| Entity | Type | Host | Evidence selectors |", "|---|---|---|---|"])
        for node in result.nodes:
            selectors = "; ".join(_selector_summary(item) for item in node.evidence_selectors)
            lines.append(
                "| "
                + " | ".join(
                    _markdown_cell(value)
                    for value in (
                        node.entity.display_value,
                        node.entity.entity_type,
                        node.entity.host_scope or "—",
                        selectors,
                    )
                )
                + " |"
            )
        lines.append("")
    if result.edges:
        lines.extend(["| Relation | State | Evidence selector |", "|---|---|---|"])
        for edge in result.edges:
            relation = (
                f"{edge.relation.source_entity_id} —{edge.relation.predicate}→ "
                f"{edge.relation.target_entity_id}"
            )
            lines.append(
                "| "
                + " | ".join(
                    _markdown_cell(value)
                    for value in (
                        relation,
                        edge.visibility,
                        _selector_summary(edge.evidence_selector),
                    )
                )
                + " |"
            )
        lines.append("")
    if result.events:
        lines.extend(["| Time | State | Relation | Evidence selector |", "|---|---|---|---|"])
        for event in result.events:
            lines.append(
                "| "
                + " | ".join(
                    _markdown_cell(value)
                    for value in (
                        event.event.normalized_time_utc or event.event.original_time,
                        event.visibility,
                        event.event.edge_id,
                        _selector_summary(event.evidence_selector),
                    )
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _xml_attr(value: object) -> str:
    return html.escape(str(value), quote=True)


def _short_label(value: str, limit: int = 32) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _render_svg(result: GraphQueryResult) -> str:
    nodes = sorted(result.nodes, key=lambda item: item.entity.entity_id)
    edges = sorted(result.edges, key=lambda item: item.relation.edge_id)
    columns = min(4, max(1, len(nodes)))
    rows = max(1, math.ceil(len(nodes) / columns))
    width = max(420, columns * 210 + 40)
    height = max(180, rows * 120 + 80)
    positions = {
        node.entity.entity_id: (40 + (index % columns) * 210, 45 + (index // columns) * 120)
        for index, node in enumerate(nodes)
    }
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" '
        f'aria-label="Mulder {_xml_attr(result.query.kind)} entity graph" '
        f'viewBox="0 0 {width} {height}" class="mulder-graph-view">',
        "<style>"
        ".gv-bg{fill:#fff}.gv-node{fill:#eef4ff;stroke:#315f9f;stroke-width:2}"
        ".gv-label{font:13px sans-serif;fill:#172033}.gv-type{font:11px monospace;fill:#52627a}"
        ".gv-edge{fill:none;stroke:#315f9f;stroke-width:2}"
        ".gv-superseded{stroke:#6b7280;stroke-dasharray:7 5}"
        ".gv-refuted{stroke:#b42318;stroke-dasharray:3 4}"
        ".gv-edge-label{font:10px sans-serif;fill:#374151}"
        ".gv-state{font:10px monospace}</style>",
        '<rect class="gv-bg" width="100%" height="100%"/>',
        '<defs><marker id="gv-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" '
        'orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="context-stroke"/></marker></defs>',
    ]
    for edge in edges:
        source = positions.get(edge.relation.source_entity_id)
        target = positions.get(edge.relation.target_entity_id)
        if source is None or target is None:
            continue
        x1, y1 = source[0] + 90, source[1] + 32
        x2, y2 = target[0] + 90, target[1] + 32
        selector = edge.evidence_selector
        anchor_ids = ",".join(anchor.anchor_id for anchor in selector.anchors)
        source_names = ",".join(sorted({anchor.source.source_name for anchor in selector.anchors}))
        css_class = "gv-edge" if edge.visibility == "verified" else f"gv-edge gv-{edge.visibility}"
        common = (
            f'class="{css_class}" data-edge-id="{_xml_attr(edge.relation.edge_id)}" '
            f'data-state="{edge.visibility}" data-claim-id="{_xml_attr(selector.claim_id)}" '
            f'data-anchor-ids="{_xml_attr(anchor_ids)}" data-sources="{_xml_attr(source_names)}" '
            'marker-end="url(#gv-arrow)"'
        )
        title = _xml_attr(
            f"{edge.relation.predicate} [{edge.visibility}] claim {selector.claim_id}; "
            f"anchors {anchor_ids}; sources {source_names}"
        )
        if source == target:
            path = f"M{x1},{y1} c45,-55 80,55 8,18"
            parts.append(f'<path {common} d="{path}"><title>{title}</title></path>')
        else:
            parts.append(
                f'<line {common} x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}">'
                f"<title>{title}</title></line>"
            )
        label_x = (x1 + x2) / 2
        label_y = (y1 + y2) / 2 - 5
        parts.append(
            f'<text class="gv-edge-label" x="{label_x:.1f}" y="{label_y:.1f}" '
            f'text-anchor="middle">{_xml_attr(_short_label(edge.relation.predicate, 24))} '
            f"[{edge.visibility}]</text>"
        )
    for node in nodes:
        x, y = positions[node.entity.entity_id]
        claims = ",".join(selector.claim_id for selector in node.evidence_selectors)
        anchors = ",".join(
            anchor.anchor_id for selector in node.evidence_selectors for anchor in selector.anchors
        )
        sources = ",".join(
            sorted(
                {
                    anchor.source.source_name
                    for selector in node.evidence_selectors
                    for anchor in selector.anchors
                }
            )
        )
        parts.append(
            f'<g data-entity-id="{_xml_attr(node.entity.entity_id)}" '
            f'data-claim-ids="{_xml_attr(claims)}" data-anchor-ids="{_xml_attr(anchors)}" '
            f'data-sources="{_xml_attr(sources)}">'
            f"<title>{_xml_attr(node.entity.display_value)}; claims {_xml_attr(claims)}; "
            f"anchors {_xml_attr(anchors)}; sources {_xml_attr(sources)}</title>"
            f'<rect class="gv-node" x="{x}" y="{y}" width="180" height="64" rx="8"/>'
            f'<text class="gv-label" x="{x + 10}" y="{y + 25}">'
            f"{_xml_attr(_short_label(node.entity.display_value))}</text>"
            f'<text class="gv-type" x="{x + 10}" y="{y + 46}">'
            f"{_xml_attr(node.entity.entity_type)} · "
            f"{_xml_attr(node.entity.host_scope or 'global')}"
            f"</text></g>"
        )
    if not nodes:
        message = "No path within limits" if result.no_path else "No graph results"
        parts.append(f'<text class="gv-label" x="20" y="45">{_xml_attr(message)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_graph_visualization(result: GraphQueryResult) -> GraphVisualization:
    """Render one validated query result for static report and review surfaces."""
    return GraphVisualization(
        query_kind=result.query.kind,
        markdown=_render_markdown(result),
        svg=_render_svg(result),
    )
