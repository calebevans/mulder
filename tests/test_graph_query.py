"""Interface-level tests for bounded graph queries and static review views."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import update

from mulder.db import CaseDB, evidence_anchors_t, windows_t
from mulder.graph_query import (
    MAX_GRAPH_NEIGHBOR_DEPTH,
    MAX_GRAPH_PATH_DEPTH,
    MAX_GRAPH_QUERY_RESULTS,
    EventsForEntityQuery,
    HostTimelineQuery,
    NeighborsQuery,
    PathBetweenQuery,
    render_graph_visualization,
)
from mulder.models import (
    AtomicClaim,
    AtomicClaimInput,
    AuditSummary,
    CaseMetadataRow,
    EvidenceAnchorInput,
    Finding,
    JsonScalar,
    WindowRow,
)
from mulder.report.renderer import ReportRenderer
from mulder.server.tool_access import Role, get_tools_for_role


def _add_edge(
    db: CaseDB,
    *,
    finding_id: str,
    source: str,
    target: str,
    qualifiers: dict[str, JsonScalar] | None = None,
    event_time: str | None = None,
    source_name: str | None = None,
    source_path: str | None = None,
) -> AtomicClaim:
    observed = target.split(":", 1)[1] if target.startswith("node:") else target
    object_value = target
    # Keep the typed target for projection while selecting the exact evidence
    # span as the verifier's expected value.
    if target.startswith("node:"):
        object_value = observed
        qualifiers = {**(qualifiers or {}), "object_type": "node"}
    evidence_name = source_name or f"source-{finding_id}"
    evidence_path = source_path or f"/evidence/{finding_id}.log"
    source_id = db.register_source(
        evidence_name,
        evidence_path,
        f"sha256-{finding_id}",
        "text",
        1,
    )
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=3,
                line_end=3,
                event_time=event_time,
                raw_text=observed,
            )
        ],
    )
    window = db.get_windows_by_source(evidence_name)[0]
    assert window.window_id is not None
    finding = Finding(
        finding_id=finding_id,
        case_id=db.get_case_metadata().case_id,
        title=f"Finding {finding_id}",
        description=observed,
        severity="medium",
        confidence="inference",
        evidence_refs=[f"tool-{finding_id}"],
        sources=[evidence_name],
        submitted_at="2026-01-01T00:00:00Z",
    )
    claim = db.insert_finding(
        finding,
        [
            AtomicClaimInput(
                statement=f"{source} equals {object_value}",
                subject=source,
                predicate="equals",
                object_value=object_value,
                qualifiers=qualifiers or {},
                anchors=[
                    EvidenceAnchorInput(
                        tool_call_id=f"tool-{finding_id}",
                        window_id=window.window_id,
                        char_start=0,
                        char_end=len(observed),
                        expected_text=observed,
                    )
                ],
            )
        ],
    )[0]
    assert db.verify_finding_claims(finding_id)[0].result == "verified"
    return claim


def _entity_ids(db: CaseDB) -> dict[str, str]:
    db.rebuild_entity_graph()
    return {entity.display_value: entity.entity_id for entity in db.get_entity_graph().entities}


def test_server_owned_limits_reject_oversize_and_truncate_results(tmp_case_db: CaseDB) -> None:
    with pytest.raises(ValidationError):
        NeighborsQuery(entity_id="ge_x", limit=MAX_GRAPH_QUERY_RESULTS + 1)
    with pytest.raises(ValidationError):
        NeighborsQuery(entity_id="ge_x", depth=MAX_GRAPH_NEIGHBOR_DEPTH + 1)
    with pytest.raises(ValidationError):
        PathBetweenQuery(
            source_entity_id="ge_x",
            target_entity_id="ge_y",
            max_depth=MAX_GRAPH_PATH_DEPTH + 1,
        )

    for index in range(3):
        _add_edge(
            tmp_case_db,
            finding_id=f"limit-{index}",
            source="node:center",
            target=f"node:leaf-{index}",
        )
    center = _entity_ids(tmp_case_db)["center"]
    result = tmp_case_db.query_entity_graph(NeighborsQuery(entity_id=center, limit=2, depth=1))

    assert len(result.edges) == 2
    assert result.limits.result_limit == 2
    assert result.limits.truncated is True
    assert result.limits.expansions == 2


def test_shortest_path_handles_cycles_and_reports_no_path(tmp_case_db: CaseDB) -> None:
    for finding_id, source, target in (
        ("ab", "node:a", "node:b"),
        ("bc", "node:b", "node:c"),
        ("ca", "node:c", "node:a"),
        ("cd", "node:c", "node:d"),
        ("ef", "node:e", "node:f"),
    ):
        _add_edge(tmp_case_db, finding_id=finding_id, source=source, target=target)
    ids = _entity_ids(tmp_case_db)

    path = tmp_case_db.query_entity_graph(
        PathBetweenQuery(
            source_entity_id=ids["a"],
            target_entity_id=ids["d"],
            max_depth=3,
        )
    )
    assert path.no_path is False
    assert path.paths[0].node_ids == [ids["a"], ids["c"], ids["d"]]
    assert len(path.paths[0].edge_ids) == 2
    assert len(set(path.paths[0].node_ids)) == 3

    missing = tmp_case_db.query_entity_graph(
        PathBetweenQuery(
            source_entity_id=ids["a"],
            target_entity_id=ids["e"],
            max_depth=2,
        )
    )
    assert missing.no_path is True
    assert missing.paths == []
    assert missing.edges == []


def test_query_nodes_edges_and_events_preserve_provenance(tmp_case_db: CaseDB) -> None:
    claim = _add_edge(
        tmp_case_db,
        finding_id="selectors",
        source="process:42",
        target="file:/tmp/evil",
        qualifiers={"subject_host": "HOST-A."},
        event_time="2026-01-01T12:00:00+01:00",
        source_path="/evidence/host-a/events.log",
    )
    ids = _entity_ids(tmp_case_db)
    process_id = ids["42"]

    neighbors = tmp_case_db.query_entity_graph(NeighborsQuery(entity_id=process_id))
    assert len(neighbors.edges) == 1
    edge_selector = neighbors.edges[0].evidence_selector
    assert edge_selector.claim_id == claim.claim_id
    assert edge_selector.projection_verification_id == neighbors.edges[0].relation.verification_id
    assert edge_selector.anchors[0].anchor_id == claim.anchors[0].anchor_id
    assert edge_selector.anchors[0].source.source_name == "source-selectors"
    assert edge_selector.anchors[0].source.source_path == "/evidence/host-a/events.log"
    assert edge_selector.anchors[0].source.source_hash == "sha256-selectors"
    assert edge_selector.anchors[0].source.extractor == "text"
    assert all(node.evidence_selectors for node in neighbors.nodes)
    assert all(
        selector.anchors for node in neighbors.nodes for selector in node.evidence_selectors
    )

    events = tmp_case_db.query_entity_graph(EventsForEntityQuery(entity_id=process_id))
    assert events.events[0].event.normalized_time_utc == "2026-01-01T11:00:00Z"
    assert events.events[0].evidence_selector == edge_selector


def test_host_timeline_is_ordered_and_case_isolated(tmp_path: Path) -> None:
    first = CaseDB.create("first-case", "/evidence", tmp_path)
    second = CaseDB.create("second-case", "/evidence", tmp_path)
    try:
        _add_edge(
            first,
            finding_id="first-late",
            source="process:10",
            target="node:late",
            qualifiers={"subject_host": "Host-A"},
            event_time="2026-02-01T12:00:00Z",
        )
        _add_edge(
            first,
            finding_id="first-early",
            source="process:11",
            target="node:early",
            qualifiers={"subject_host": "host-a."},
            event_time="2026-02-01T10:00:00Z",
        )
        _add_edge(
            first,
            finding_id="first-other",
            source="process:12",
            target="node:other",
            qualifiers={"subject_host": "host-b"},
            event_time="2026-02-01T09:00:00Z",
        )
        _add_edge(
            second,
            finding_id="second-secret",
            source="process:99",
            target="node:secret",
            qualifiers={"subject_host": "host-a"},
            event_time="2026-02-01T08:00:00Z",
        )
        first_ids = _entity_ids(first)
        second_ids = _entity_ids(second)

        timeline = first.query_entity_graph(HostTimelineQuery(host="HOST-A."))
        assert [event.event.normalized_time_utc for event in timeline.events] == [
            "2026-02-01T10:00:00Z",
            "2026-02-01T12:00:00Z",
        ]
        assert {
            anchor.source.source_name
            for event in timeline.events
            for anchor in event.evidence_selector.anchors
        } == {"source-first-early", "source-first-late"}

        foreign = first.query_entity_graph(NeighborsQuery(entity_id=second_ids["99"]))
        assert foreign.nodes == []
        assert foreign.edges == []
        assert first_ids["10"] != second_ids["99"]
    finally:
        first.close()
        second.close()


def test_historical_edges_are_opt_in_and_visibly_distinct(tmp_case_db: CaseDB) -> None:
    _add_edge(
        tmp_case_db,
        finding_id="withdrawn",
        source="user:alice",
        target="node:old",
    )
    refuted = _add_edge(
        tmp_case_db,
        finding_id="refuted",
        source="user:alice",
        target="node:false",
    )
    alice = _entity_ids(tmp_case_db)["alice"]
    assert tmp_case_db.delete_finding("withdrawn") is True

    anchor = refuted.anchors[0]
    with tmp_case_db._engine.begin() as conn:
        conn.execute(
            update(windows_t)
            .where(windows_t.c.window_id == anchor.window_id)
            .values(raw_text="different")
        )
        conn.execute(
            update(evidence_anchors_t)
            .where(evidence_anchors_t.c.anchor_id == anchor.anchor_id)
            .values(exact_text="different", char_end=len("different"))
        )
    assert tmp_case_db.verify_finding_claims("refuted")[0].result == "contradicted"

    default = tmp_case_db.query_entity_graph(NeighborsQuery(entity_id=alice))
    superseded = tmp_case_db.query_entity_graph(
        NeighborsQuery(entity_id=alice, include_superseded=True)
    )
    contradicted = tmp_case_db.query_entity_graph(
        NeighborsQuery(entity_id=alice, include_refuted=True)
    )
    all_history = tmp_case_db.query_entity_graph(
        NeighborsQuery(
            entity_id=alice,
            include_superseded=True,
            include_refuted=True,
        )
    )

    assert default.edges == []
    assert [edge.visibility for edge in superseded.edges] == ["superseded"]
    assert [edge.visibility for edge in contradicted.edges] == ["refuted"]
    assert contradicted.edges[0].evidence_selector.current_claim_state == "contradicted"
    assert {edge.visibility for edge in all_history.edges} == {"superseded", "refuted"}
    assert "gv-superseded" in render_graph_visualization(superseded).svg
    assert 'data-state="superseded"' in render_graph_visualization(superseded).svg
    assert "gv-refuted" in render_graph_visualization(contradicted).svg
    assert 'data-state="refuted"' in render_graph_visualization(contradicted).svg


def test_static_visualization_and_report_escape_evidence_text(
    tmp_case_db: CaseDB, tmp_path: Path
) -> None:
    hostile = "<script>alert('node')</script>|name"
    hostile_source = 'source" onload="alert(2)<tag>'
    _add_edge(
        tmp_case_db,
        finding_id="escape",
        source="user:alice",
        target=hostile,
        source_name=hostile_source,
        source_path="/evidence/<img src=x onerror=alert(3)>",
    )
    alice = _entity_ids(tmp_case_db)["alice"]
    result = tmp_case_db.query_entity_graph(NeighborsQuery(entity_id=alice))
    first = render_graph_visualization(result)
    second = render_graph_visualization(result)

    assert first == second
    assert "<script>alert('node')</script>" not in first.svg
    assert "&lt;script&gt;alert(&#x27;node&#x27;)&lt;/script&gt;" in first.svg
    assert 'onload="alert(2)' not in first.svg
    assert "<script>" not in first.markdown
    assert "&lt;script&gt;" in first.markdown
    assert "\\|name" in first.markdown

    metadata = CaseMetadataRow(
        case_id="test-case",
        ingested_at="2026-01-01T00:00:00Z",
        evidence_root="/evidence",
        extractor_versions={},
    )
    summary = AuditSummary(
        total_tool_calls=1,
        total_findings=0,
        tool_call_counts={},
        total_duration_ms=1,
        first_timestamp="2026-01-01T00:00:00Z",
        last_timestamp="2026-01-01T00:00:01Z",
    )
    audit_path = tmp_path / "graph.audit.jsonl"
    audit_path.write_text("", encoding="utf-8")
    markdown = ReportRenderer().render(metadata, [], summary, audit_path, graph_results=[result])
    rendered_html = ReportRenderer().render_html(
        metadata, [], summary, audit_path, graph_results=[result]
    )
    assert "Verified Entity Graph Views" in markdown
    assert "&lt;script&gt;" in markdown
    assert 'class="mulder-graph-view"' in rendered_html
    assert "<script>alert('node')</script>" not in rendered_html


def test_mcp_graph_tools_have_least_privilege_role_registration() -> None:
    import mulder.server.tools.graph  # noqa: F401

    names = {
        "mcp__mulder__neighbors",
        "mcp__mulder__path_between",
        "mcp__mulder__events_for_entity",
        "mcp__mulder__host_timeline",
    }
    for role in (Role.CROSS_ANALYST, Role.NARRATIVE_ANALYST, Role.REPORT):
        assert names <= set(get_tools_for_role(role))
    for role in (
        Role.CATALOG,
        Role.EXTRACT_PLANNER,
        Role.EXTRACT_EXECUTOR,
        Role.EXTRACT_ANALYST,
        Role.CROSS_PLANNER,
        Role.CROSS_EXECUTOR,
        Role.NARRATIVE_PLANNER,
        Role.NARRATIVE_EXECUTOR,
    ):
        assert names.isdisjoint(get_tools_for_role(role))
