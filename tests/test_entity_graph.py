"""Interface-level tests for the verified-claim SQLite graph projection."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from sqlalchemy import text

from mulder.db import CaseDB
from mulder.graph import GRAPH_DERIVATION_RULE, GRAPH_DERIVATION_VERSION
from mulder.models import (
    AtomicClaim,
    AtomicClaimInput,
    EvidenceAnchorInput,
    Finding,
    JsonScalar,
    WindowRow,
)


def _add_claim(
    db: CaseDB,
    *,
    finding_id: str,
    subject: str,
    predicate: str,
    observed: str,
    expected: JsonScalar,
    qualifiers: dict[str, JsonScalar] | None = None,
    event_time: str | None = None,
    verify: bool = True,
) -> AtomicClaim:
    source_name = f"source-{finding_id}"
    source_path = f"/evidence/{finding_id}.log"
    source_id = db.register_source(
        source_name,
        source_path,
        f"sha256-{finding_id}",
        "text",
        1,
    )
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=7,
                line_end=7,
                event_time=event_time,
                raw_text=observed,
            )
        ],
    )
    window = db.get_windows_by_source(source_name)[0]
    assert window.window_id is not None
    finding = Finding(
        finding_id=finding_id,
        case_id=db.get_case_metadata().case_id,
        title=f"Finding {finding_id}",
        description=observed,
        severity="medium",
        confidence="inference",
        evidence_refs=[f"tool-{finding_id}"],
        sources=[source_name],
        submitted_at="2026-01-01T00:00:00Z",
    )
    stored = db.insert_finding(
        finding,
        [
            AtomicClaimInput(
                statement=f"{subject} {predicate} {expected}",
                subject=subject,
                predicate=predicate,
                object_value=expected,
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
    if verify:
        db.verify_finding_claims(finding_id)
    return stored


def test_projection_admits_only_current_verified_claims(tmp_case_db: CaseDB) -> None:
    verified = _add_claim(
        tmp_case_db,
        finding_id="verified",
        subject="process:42",
        predicate="image_name",
        observed="cmd.exe",
        expected="cmd.exe",
    )
    _add_claim(
        tmp_case_db,
        finding_id="unverified",
        subject="process:43",
        predicate="image_name",
        observed="pwsh.exe",
        expected="pwsh.exe",
        verify=False,
    )
    _add_claim(
        tmp_case_db,
        finding_id="contradicted",
        subject="process:44",
        predicate="image_name",
        observed="explorer.exe",
        expected="evil.exe",
    )

    built = tmp_case_db.rebuild_entity_graph()
    snapshot = tmp_case_db.get_entity_graph()

    assert built.verified_claims == 1
    assert built.active_relations == 1
    assert [relation.claim_id for relation in snapshot.relations] == [verified.claim_id]
    assert snapshot.relations[0].derivation_rule == GRAPH_DERIVATION_RULE
    assert snapshot.relations[0].derivation_version == GRAPH_DERIVATION_VERSION


def test_idempotent_rebuild_and_edge_to_raw_evidence_provenance(
    tmp_case_db: CaseDB,
) -> None:
    claim = _add_claim(
        tmp_case_db,
        finding_id="provenance",
        subject="user:alice",
        predicate="equals",
        observed="host:server-b",
        expected="host:server-b",
        qualifiers={"subject_host": "server-a"},
    )

    first = tmp_case_db.rebuild_entity_graph()
    first_snapshot = tmp_case_db.get_entity_graph()
    second = tmp_case_db.rebuild_entity_graph()
    second_snapshot = tmp_case_db.get_entity_graph()

    assert first.unchanged is False
    assert second.unchanged is True
    assert second.projection.projection_id == first.projection.projection_id
    assert second_snapshot == first_snapshot
    assert len(second_snapshot.projections) == 1

    relation = second_snapshot.relations[0]
    provenance = tmp_case_db.get_graph_edge_provenance(relation.edge_id)
    assert provenance is not None
    assert provenance.claim.claim_id == claim.claim_id
    assert provenance.claim.verification_id == relation.verification_id
    assert provenance.claim.verification_result == "verified"
    assert provenance.anchors[0].source_path == "/evidence/provenance.log"
    assert provenance.anchors[0].source_hash == "sha256-provenance"
    assert provenance.anchors[0].line_start == 7
    assert provenance.anchors[0].char_start == 0
    assert provenance.anchors[0].exact_text == "host:server-b"
    assert provenance.anchors[0].window_text == "host:server-b"
    assert tmp_case_db.get_graph_edge_provenance("gre_missing") is None


def test_rebuild_reopens_anchor_and_excludes_stale_verified_claim(
    tmp_case_db: CaseDB,
) -> None:
    _add_claim(
        tmp_case_db,
        finding_id="stale-anchor",
        subject="process:52",
        predicate="image_name",
        observed="trusted.exe",
        expected="trusted.exe",
    )
    assert tmp_case_db.rebuild_entity_graph().active_relations == 1

    # Simulate post-verification evidence corruption. The setup reaches below
    # the public seam; every assertion remains on the public graph interface.
    with tmp_case_db._engine.begin() as conn:
        conn.execute(text("UPDATE windows SET raw_text = 'tampered.exe'"))

    rebuilt = tmp_case_db.rebuild_entity_graph()
    assert rebuilt.active_relations == 0
    assert tmp_case_db.get_entity_graph().relations == []


def test_alias_collisions_stay_separate_and_cross_host_edges_are_explicit(
    tmp_case_db: CaseDB,
) -> None:
    _add_claim(
        tmp_case_db,
        finding_id="host-a-process",
        subject="process:42",
        predicate="image_name",
        observed="agent.exe",
        expected="agent.exe",
        qualifiers={
            "subject_host": "HOST-A.",
            "object_host": "host-a",
            "subject_alias": "shared-agent",
        },
    )
    _add_claim(
        tmp_case_db,
        finding_id="host-b-process",
        subject="process:42",
        predicate="image_name",
        observed="agent.exe",
        expected="agent.exe",
        qualifiers={
            "subject_host": "host-b",
            "object_host": "host-b",
            "subject_alias": "SHARED-AGENT",
        },
    )
    _add_claim(
        tmp_case_db,
        finding_id="cross-host",
        subject="user:alice",
        predicate="equals",
        observed="host:host-b",
        expected="host:host-b",
        qualifiers={"subject_host": "host-a"},
    )

    tmp_case_db.rebuild_entity_graph()
    snapshot = tmp_case_db.get_entity_graph()

    process_entities = [entity for entity in snapshot.entities if entity.entity_type == "process"]
    assert len(process_entities) == 2
    assert {entity.host_scope for entity in process_entities} == {"host-a", "host-b"}
    collision = next(
        item for item in snapshot.alias_collisions if item.normalized_alias == "shared-agent"
    )
    assert set(collision.entity_ids) == {entity.entity_id for entity in process_entities}

    by_id = {entity.entity_id: entity for entity in snapshot.entities}
    cross_edge = next(
        relation
        for relation in snapshot.relations
        if by_id[relation.source_entity_id].entity_type == "user"
    )
    assert by_id[cross_edge.source_entity_id].host_scope == "host-a"
    assert by_id[cross_edge.target_entity_id].entity_type == "host"
    assert by_id[cross_edge.target_entity_id].canonical_value == "host-b"
    assert by_id[cross_edge.target_entity_id].host_scope is None


def test_event_time_preserves_original_and_normalizes_offset_to_utc(
    tmp_case_db: CaseDB,
) -> None:
    _add_claim(
        tmp_case_db,
        finding_id="offset-time",
        subject="process:90",
        predicate="image_name",
        observed="evil.exe",
        expected="evil.exe",
        qualifiers={"event_time": "2025-04-01T12:30:00-05:00"},
        event_time="2025-04-01T12:31:00-05:00",
    )
    _add_claim(
        tmp_case_db,
        finding_id="naive-time",
        subject="process:91",
        predicate="image_name",
        observed="other.exe",
        expected="other.exe",
        qualifiers={"event_time": "2025-04-01 12:30:00"},
    )
    _add_claim(
        tmp_case_db,
        finding_id="anchor-time",
        subject="process:92",
        predicate="image_name",
        observed="anchor.exe",
        expected="anchor.exe",
        event_time="2025-04-01T18:00:00+01:00",
    )

    tmp_case_db.rebuild_entity_graph()
    events = tmp_case_db.get_entity_graph().events

    normalized = next(event for event in events if "-05:00" in event.original_time)
    assert normalized.time_origin == "qualifier:event_time"
    assert normalized.normalized_time_utc == "2025-04-01T17:30:00Z"
    assert normalized.utc_offset_minutes == -300
    assert normalized.normalization_state == "normalized"
    naive = next(event for event in events if event.original_time == "2025-04-01 12:30:00")
    assert naive.normalized_time_utc is None
    assert naive.utc_offset_minutes is None
    assert naive.normalization_state == "naive"
    anchored = next(event for event in events if event.original_time.endswith("+01:00"))
    assert anchored.time_origin.startswith("anchor:")
    assert anchored.anchor_id is not None
    assert anchored.normalized_time_utc == "2025-04-01T17:00:00Z"


def test_withdrawn_claim_supersedes_projection_edges(tmp_case_db: CaseDB) -> None:
    _add_claim(
        tmp_case_db,
        finding_id="withdraw-me",
        subject="file:/tmp/evil",
        predicate="hash_equals",
        observed="abc123",
        expected="abc123",
    )
    first = tmp_case_db.rebuild_entity_graph()
    old_edge = tmp_case_db.get_entity_graph().relations[0]

    assert tmp_case_db.delete_finding("withdraw-me") is True
    second = tmp_case_db.rebuild_entity_graph()
    current = tmp_case_db.get_entity_graph()
    history = tmp_case_db.get_entity_graph(include_superseded=True)

    assert second.unchanged is False
    assert second.projection.supersedes_projection_id == first.projection.projection_id
    assert current.relations == []
    assert len(history.projections) == 2
    historical_edge = next(edge for edge in history.relations if edge.edge_id == old_edge.edge_id)
    assert historical_edge.state == "superseded"
    assert historical_edge.superseded_by_projection_id == second.projection.projection_id


def test_open_migrates_graph_tables_for_existing_case_database(tmp_path: Path) -> None:
    path = tmp_path / "legacy-graph.db"
    db = CaseDB.create("legacy-graph", "/evidence", tmp_path)
    db.close()
    with sqlite3.connect(path) as conn:
        for table in (
            "graph_edge_anchors",
            "graph_events",
            "graph_aliases",
            "graph_relations",
            "graph_entities",
            "graph_projections",
        ):
            conn.execute(f"DROP TABLE {table}")

    reopened = CaseDB.open("legacy-graph", tmp_path)
    try:
        assert reopened.rebuild_entity_graph().active_relations == 0
        assert reopened.get_entity_graph().active_projection is not None
    finally:
        reopened.close()
