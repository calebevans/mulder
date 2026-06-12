"""Tests for orchestrator helper functions: system identification, JSON parsing, etc."""

from __future__ import annotations

import json
from unittest.mock import patch

from mulder.orchestrator.evidence import EvidenceContext
from mulder.orchestrator.runner import (
    Orchestrator,
)
from mulder.orchestrator.types import PhaseResult, extract_catalog_result, extract_json_from_text


def _make_orchestrator(evidence_path: str = "/evidence") -> Orchestrator:
    """Create an Orchestrator with a mocked dashboard for unit testing."""
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        return Orchestrator(evidence_path=evidence_path)


def _catalog_json(
    systems: list[dict[str, object]],
    case_id: str = "evidence",
    evidence_root: str = "/evidence",
) -> str:
    """Build a valid catalog JSON string for test fixtures."""
    return json.dumps(
        {
            "case_id": case_id,
            "evidence_root": evidence_root,
            "systems": systems,
            "archives_extracted": True,
            "total_sources": len(systems),
        }
    )


class TestExtractCatalogResult:
    """Tests for extract_catalog_result in types.py."""

    def test_valid_json_parsed(self) -> None:
        """Valid catalog JSON with systems array is extracted."""
        msg = _catalog_json([{"name": "Rocba", "type": "Windows", "evidence": ["disk_image"]}])
        result = extract_catalog_result([msg])
        assert result is not None
        assert result["case_id"] == "evidence"
        assert len(result["systems"]) == 1
        assert result["systems"][0]["name"] == "Rocba"

    def test_searches_reverse_order(self) -> None:
        """Last valid JSON message wins when multiple are present."""
        old = _catalog_json([{"name": "OldHost", "type": "Linux", "evidence": []}])
        new = _catalog_json([{"name": "NewHost", "type": "Windows", "evidence": ["disk_image"]}])
        result = extract_catalog_result(["some text", old, "more text", new])
        assert result is not None
        assert result["systems"][0]["name"] == "NewHost"

    def test_rejects_empty_systems(self) -> None:
        """JSON with empty systems array returns None."""
        msg = json.dumps({"case_id": "x", "evidence_root": "/e", "systems": []})
        assert extract_catalog_result([msg]) is None

    def test_rejects_missing_name(self) -> None:
        """Systems entries without a name field are rejected."""
        msg = json.dumps({"systems": [{"type": "Windows", "evidence": []}]})
        assert extract_catalog_result([msg]) is None

    def test_returns_none_for_no_json(self) -> None:
        """Plain text with no JSON returns None."""
        assert extract_catalog_result(["No JSON here."]) is None

    def test_handles_json_with_surrounding_text(self) -> None:
        """JSON embedded in surrounding text is still extracted."""
        catalog = _catalog_json([{"name": "host-a", "type": "Linux", "evidence": []}])
        msg = f"Here is the catalog output:\n{catalog}\nDone."
        result = extract_catalog_result([msg])
        assert result is not None
        assert result["systems"][0]["name"] == "host-a"


class TestIdentifySystemsFromCatalog:
    """Tests for Orchestrator._identify_systems_from_catalog (JSON-only)."""

    def test_extracts_systems_from_json(self) -> None:
        """Parses system names from structured catalog JSON."""
        orch = _make_orchestrator()
        msg = _catalog_json(
            [
                {"name": "base-dc", "type": "Windows", "evidence": ["disk_image"]},
                {"name": "base-admin", "type": "Windows", "evidence": ["memory_dump"]},
            ]
        )
        catalog = PhaseResult(phase_name="catalog", success=True, messages=[msg], turns_used=1)
        systems, catalog_data = orch._identify_systems_from_catalog(catalog)
        assert systems == ["base-dc", "base-admin"]
        assert catalog_data["case_id"] == "evidence"

    def test_single_system(self) -> None:
        """Single system in JSON is returned correctly."""
        orch = _make_orchestrator()
        msg = _catalog_json([{"name": "Rocba", "type": "Windows", "evidence": ["disk_image"]}])
        catalog = PhaseResult(phase_name="catalog", success=True, messages=[msg], turns_used=1)
        systems, _ = orch._identify_systems_from_catalog(catalog)
        assert systems == ["Rocba"]

    def test_returns_empty_on_no_json(self) -> None:
        """Returns empty list when catalog has no valid JSON."""
        orch = _make_orchestrator()
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["No JSON output, just markdown text."],
            turns_used=1,
        )
        systems, catalog_data = orch._identify_systems_from_catalog(catalog)
        assert systems == []
        assert catalog_data == {}

    def test_returns_empty_on_invalid_systems(self) -> None:
        """Returns empty list when systems entries lack names."""
        orch = _make_orchestrator()
        msg = json.dumps({"systems": [{"type": "Windows"}]})
        catalog = PhaseResult(phase_name="catalog", success=True, messages=[msg], turns_used=1)
        systems, catalog_data = orch._identify_systems_from_catalog(catalog)
        assert systems == []
        assert catalog_data == {}

    def test_uses_last_json_message(self) -> None:
        """When compaction restarts produce multiple JSON messages, uses the last."""
        orch = _make_orchestrator()
        old_msg = _catalog_json([{"name": "partial", "type": "Unknown", "evidence": []}])
        new_msg = _catalog_json(
            [
                {"name": "Rocba", "type": "Windows", "evidence": ["disk_image", "memory_dump"]},
            ]
        )
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["cataloging...", old_msg, "continuing...", new_msg],
            turns_used=5,
        )
        systems, _ = orch._identify_systems_from_catalog(catalog)
        assert systems == ["Rocba"]


class TestGroupSystems:
    """Tests for EvidenceContext.group_systems (structured catalog data)."""

    def test_disk_system_gets_own_group(self) -> None:
        """System with disk_image evidence is placed alone."""
        catalog_data = {
            "systems": [
                {"name": "host-a", "evidence": ["disk_image"]},
                {"name": "host-b", "evidence": ["memory_dump"]},
            ],
        }
        groups = EvidenceContext.group_systems(["host-a", "host-b"], catalog_data)
        host_a_groups = [g for g in groups if "host-a" in g]
        assert len(host_a_groups) == 1
        assert host_a_groups[0] == ["host-a"]

    def test_memory_only_batched_when_many_systems(self) -> None:
        """Memory-only systems batched when total systems > 3."""
        catalog_data = {
            "systems": [
                {"name": "host-a", "evidence": ["disk_image"]},
                {"name": "host-b", "evidence": ["disk_image"]},
                {"name": "host-c", "evidence": ["memory_dump"]},
                {"name": "host-d", "evidence": ["memory_dump"]},
                {"name": "host-e", "evidence": ["memory_dump"]},
            ],
        }
        systems = ["host-a", "host-b", "host-c", "host-d", "host-e"]
        groups = EvidenceContext.group_systems(systems, catalog_data)
        flat = [s for g in groups for s in g]
        assert sorted(flat) == sorted(systems)
        batched = [g for g in groups if len(g) > 1]
        assert len(batched) >= 1

    def test_all_rich_returns_individual_groups(self) -> None:
        """When all systems have disk evidence, each gets its own group."""
        catalog_data = {
            "systems": [
                {"name": "host-a", "evidence": ["disk_image"]},
                {"name": "host-b", "evidence": ["disk_image"]},
            ],
        }
        groups = EvidenceContext.group_systems(["host-a", "host-b"], catalog_data)
        assert groups == [["host-a"], ["host-b"]]

    def test_empty_systems_fallback(self) -> None:
        """Edge case: empty list still returns one group."""
        groups = EvidenceContext.group_systems([], {"systems": []})
        assert len(groups) == 1

    def test_missing_evidence_field_treated_as_rich(self) -> None:
        """Systems without an evidence field default to individual groups."""
        catalog_data = {
            "systems": [
                {"name": "host-x"},
            ],
        }
        groups = EvidenceContext.group_systems(["host-x"], catalog_data)
        assert groups == [["host-x"]]


class TestParseJsonFromText:
    """Tests for extract_json_from_text."""

    def test_bare_json(self) -> None:
        """Direct JSON string is parsed."""
        result = extract_json_from_text('{"key": "value"}')
        assert result == {"key": "value"}

    def test_fenced_json(self) -> None:
        """JSON inside triple-backtick code fence is extracted."""
        text = 'Some preamble\n```json\n{"tool": "search"}\n```\nDone.'
        result = extract_json_from_text(text)
        assert result == {"tool": "search"}

    def test_embedded_braces(self) -> None:
        """JSON within surrounding prose is found via brace matching."""
        text = 'The result is: {"status": "ok", "count": 3} as expected.'
        result = extract_json_from_text(text)
        assert result == {"status": "ok", "count": 3}

    def test_no_json_returns_empty_dict(self) -> None:
        """Plain text with no JSON returns {}."""
        result = extract_json_from_text("No JSON content here at all.")
        assert result == {}

    def test_invalid_json_returns_empty_dict(self) -> None:
        """Malformed JSON returns {} without raising."""
        result = extract_json_from_text('{"broken": }')
        assert result == {}
