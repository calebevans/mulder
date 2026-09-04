"""Typed, bounded MCP tools for verified-claim graph review."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from mulder.graph_query import (
    GRAPH_QUERY_SCHEMA_VERSION,
    MAX_GRAPH_NEIGHBOR_DEPTH,
    MAX_GRAPH_PATH_DEPTH,
    MAX_GRAPH_QUERY_RESULTS,
    EventsForEntityQuery,
    GraphQueryRequest,
    HostTimelineQuery,
    NeighborsQuery,
    PathBetweenQuery,
    render_graph_visualization,
)
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import audited_tool
from mulder.server.tool_access import Role, tool_access

_GRAPH_READ_ROLES = Role.CROSS_ANALYST | Role.NARRATIVE_ANALYST | Role.REPORT
_ResultLimit = Annotated[int, Field(ge=1, le=MAX_GRAPH_QUERY_RESULTS)]
_NeighborDepth = Annotated[int, Field(ge=1, le=MAX_GRAPH_NEIGHBOR_DEPTH)]
_PathDepth = Annotated[int, Field(ge=1, le=MAX_GRAPH_PATH_DEPTH)]


def _run_graph_query(request: GraphQueryRequest) -> dict[str, object]:
    result = get_ctx().db.query_entity_graph(request)
    visualization = render_graph_visualization(result)
    return {
        "status": "success",
        "schema_version": GRAPH_QUERY_SCHEMA_VERSION,
        "result": result.model_dump(mode="json"),
        "visualization": visualization.model_dump(mode="json"),
    }


@mcp.tool()
@tool_access(_GRAPH_READ_ROLES)
@audited_tool("neighbors")
def neighbors(
    entity_id: str,
    depth: _NeighborDepth = 1,
    direction: Literal["incoming", "outgoing", "both"] = "both",
    limit: _ResultLimit = 50,
    include_superseded: bool = False,
    include_refuted: bool = False,
) -> dict[str, object]:
    """Return a bounded neighborhood around an exact graph entity ID.

    ``direction`` must be ``incoming``, ``outgoing``, or ``both``. Historical
    superseded and later-refuted edges are excluded unless explicitly opted in.
    Every returned node and edge includes claim, anchor, and source selectors.
    """
    return _run_graph_query(
        NeighborsQuery(
            entity_id=entity_id,
            depth=depth,
            direction=direction,
            limit=limit,
            include_superseded=include_superseded,
            include_refuted=include_refuted,
        )
    )


@mcp.tool()
@tool_access(_GRAPH_READ_ROLES)
@audited_tool("path_between")
def path_between(
    source_entity_id: str,
    target_entity_id: str,
    max_depth: _PathDepth = 6,
    directed: bool = False,
    include_superseded: bool = False,
    include_refuted: bool = False,
) -> dict[str, object]:
    """Find one deterministic shortest path between two exact entity IDs.

    Traversal is undirected by default for investigative pivots. Set
    ``directed`` to follow only source-to-target relations. Cycles and search
    expansion are bounded by the server; no query-language input is accepted.
    """
    return _run_graph_query(
        PathBetweenQuery(
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            max_depth=max_depth,
            directed=directed,
            include_superseded=include_superseded,
            include_refuted=include_refuted,
        )
    )


@mcp.tool()
@tool_access(_GRAPH_READ_ROLES)
@audited_tool("events_for_entity")
def events_for_entity(
    entity_id: str,
    limit: _ResultLimit = 50,
    include_superseded: bool = False,
    include_refuted: bool = False,
) -> dict[str, object]:
    """Return bounded chronological events touching an exact graph entity ID."""
    return _run_graph_query(
        EventsForEntityQuery(
            entity_id=entity_id,
            limit=limit,
            include_superseded=include_superseded,
            include_refuted=include_refuted,
        )
    )


@mcp.tool()
@tool_access(_GRAPH_READ_ROLES)
@audited_tool("host_timeline")
def host_timeline(
    host: str,
    limit: _ResultLimit = 50,
    include_superseded: bool = False,
    include_refuted: bool = False,
) -> dict[str, object]:
    """Return a bounded timeline for normalized host-scoped graph endpoints."""
    return _run_graph_query(
        HostTimelineQuery(
            host=host,
            limit=limit,
            include_superseded=include_superseded,
            include_refuted=include_refuted,
        )
    )
