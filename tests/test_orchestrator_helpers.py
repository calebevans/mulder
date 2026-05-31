"""Tests for orchestrator helper functions: system identification, JSON parsing, etc."""

from __future__ import annotations

from unittest.mock import patch

from mulder.orchestrator.runner import (
    Orchestrator,
    _count_finding_submissions,
    _extract_system_context,
    _parse_json_from_text,
)
from mulder.orchestrator.types import PhaseResult


def _make_orchestrator(**kwargs: object) -> Orchestrator:
    """Create an Orchestrator with a mocked dashboard."""
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        if "evidence_path" not in kwargs:
            kwargs["evidence_path"] = "/evidence"
        return Orchestrator(**kwargs)


class TestIdentifySystemsFromCatalog:
    """Tests for Orchestrator._identify_systems_from_catalog."""

    def test_structured_section_preferred(self) -> None:
        """Uses ## SYSTEMS markdown section when present."""
        orch = _make_orchestrator()
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["Evidence cataloged.\n## SYSTEMS\n- base-dc\n- base-admin\n\n## SUMMARY"],
            turns_used=1,
        )
        systems = orch._identify_systems_from_catalog(catalog)
        assert "base-dc" in systems
        assert "base-admin" in systems

    def test_labeled_pattern_fallback(self) -> None:
        """Falls back to 'System: name' regex when no section exists."""
        orch = _make_orchestrator()
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["Found System: web-server-01 with disk evidence."],
            turns_used=1,
        )
        systems = orch._identify_systems_from_catalog(catalog)
        assert "web-server-01" in systems

    def test_formatted_candidates_deduplicated(self) -> None:
        """Bold/backtick names are collected and deduplicated."""
        orch = _make_orchestrator()
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["Found **host-a** and `host-a` evidence. Also **host-b** disk."],
            turns_used=1,
        )
        systems = orch._identify_systems_from_catalog(catalog)
        host_a_count = sum(1 for s in systems if s.lower() == "host-a")
        assert host_a_count == 1

    def test_filters_non_system_tokens(self) -> None:
        """Tokens like 'e01', 'memory', 'disk' are excluded."""
        orch = _make_orchestrator()
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["Device: actual-host and `e01` and **memory** items."],
            turns_used=1,
        )
        systems = orch._identify_systems_from_catalog(catalog)
        lowered = [s.lower() for s in systems]
        assert "e01" not in lowered
        assert "memory" not in lowered
        assert "actual-host" in lowered

    def test_single_system_fallback(self) -> None:
        """Returns evidence path as sole system when no names found."""
        orch = _make_orchestrator(evidence_path="/cases/incident-42")
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["No recognizable systems were found."],
            turns_used=1,
        )
        systems = orch._identify_systems_from_catalog(catalog)
        assert systems == ["incident-42"]


class TestParseStructuredSystemsSection:
    """Tests for Orchestrator._parse_structured_systems_section."""

    def test_h2_heading_parsed(self) -> None:
        """## SYSTEMS heading with bullet list items."""
        text = "Intro\n## SYSTEMS\n- base-dc\n- base-admin\n## NEXT"
        result = Orchestrator._parse_structured_systems_section(text)
        assert result == ["base-dc", "base-admin"]

    def test_h3_heading_parsed(self) -> None:
        """### Systems heading variant recognized."""
        text = "### Systems\n- server-01\n- server-02\n"
        result = Orchestrator._parse_structured_systems_section(text)
        assert result == ["server-01", "server-02"]

    def test_numbered_list(self) -> None:
        """Items prefixed with '1.' are cleaned correctly."""
        text = "## SYSTEMS\n1. host-alpha\n2. host-beta\n"
        result = Orchestrator._parse_structured_systems_section(text)
        assert "host-alpha" in result
        assert "host-beta" in result

    def test_colon_suffix_stripped(self) -> None:
        """'base-dc: Windows DC' yields 'base-dc'."""
        text = "## SYSTEMS\n- base-dc: Windows Domain Controller\n"
        result = Orchestrator._parse_structured_systems_section(text)
        assert result == ["base-dc"]

    def test_empty_section_returns_empty(self) -> None:
        """Heading present but no items yields []."""
        text = "Some intro text\n## SYSTEMS\n"
        result = Orchestrator._parse_structured_systems_section(text)
        assert result == []

    def test_no_section_returns_empty(self) -> None:
        """Text without SYSTEMS heading yields []."""
        text = "Just some text about evidence.\nNothing structured here."
        result = Orchestrator._parse_structured_systems_section(text)
        assert result == []


class TestGroupSystems:
    """Tests for Orchestrator._group_systems."""

    def test_disk_system_gets_own_group(self) -> None:
        """System with '.e01' in catalog context is placed alone."""
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["host-a has disk image host-a.e01, host-b has memory dump host-b.mem"],
            turns_used=1,
        )
        groups = Orchestrator._group_systems(["host-a", "host-b"], catalog)
        host_a_groups = [g for g in groups if "host-a" in g]
        assert len(host_a_groups) == 1
        assert host_a_groups[0] == ["host-a"]

    def test_memory_only_batched_when_many_systems(self) -> None:
        """Memory-only systems batched when total systems > 3."""
        padding = " " * 250
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=[
                f"host-a has disk image host-a.e01.{padding}"
                f"host-b has disk image host-b.vmdk.{padding}"
                f"host-c has memory dump host-c.mem.{padding}"
                f"host-d has memory dump host-d.mem.{padding}"
                "host-e has memory dump host-e.dmp."
            ],
            turns_used=1,
        )
        systems = ["host-a", "host-b", "host-c", "host-d", "host-e"]
        groups = Orchestrator._group_systems(systems, catalog)
        flat = [s for g in groups for s in g]
        assert sorted(flat) == sorted(systems)
        batched = [g for g in groups if len(g) > 1]
        assert len(batched) >= 1

    def test_all_rich_returns_individual_groups(self) -> None:
        """When all systems have disk evidence, each gets its own group."""
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["host-a has disk_image host-a.e01. host-b has disk_image host-b.e01."],
            turns_used=1,
        )
        groups = Orchestrator._group_systems(["host-a", "host-b"], catalog)
        assert groups == [["host-a"], ["host-b"]]

    def test_empty_systems_fallback(self) -> None:
        """Edge case: empty list still returns one group."""
        catalog = PhaseResult(
            phase_name="catalog",
            success=True,
            messages=["No systems found."],
            turns_used=1,
        )
        groups = Orchestrator._group_systems([], catalog)
        assert len(groups) == 1


class TestParseJsonFromText:
    """Tests for _parse_json_from_text."""

    def test_bare_json(self) -> None:
        """Direct JSON string is parsed."""
        result = _parse_json_from_text('{"key": "value"}')
        assert result == {"key": "value"}

    def test_fenced_json(self) -> None:
        """JSON inside triple-backtick code fence is extracted."""
        text = 'Some preamble\n```json\n{"tool": "search"}\n```\nDone.'
        result = _parse_json_from_text(text)
        assert result == {"tool": "search"}

    def test_embedded_braces(self) -> None:
        """JSON within surrounding prose is found via brace matching."""
        text = 'The result is: {"status": "ok", "count": 3} as expected.'
        result = _parse_json_from_text(text)
        assert result == {"status": "ok", "count": 3}

    def test_no_json_returns_empty_dict(self) -> None:
        """Plain text with no JSON returns {}."""
        result = _parse_json_from_text("No JSON content here at all.")
        assert result == {}

    def test_invalid_json_returns_empty_dict(self) -> None:
        """Malformed JSON returns {} without raising."""
        result = _parse_json_from_text('{"broken": }')
        assert result == {}


class TestCountFindingSubmissions:
    """Tests for _count_finding_submissions."""

    def test_counts_multiple_mentions(self) -> None:
        """Multiple 'submit_finding' in messages are counted."""
        phase = PhaseResult(
            phase_name="analysis",
            success=True,
            messages=[
                "Called submit_finding for suspicious process.",
                "Also called submit_finding for lateral movement.",
            ],
            turns_used=2,
        )
        assert _count_finding_submissions(phase) == 2

    def test_case_insensitive(self) -> None:
        """Mixed case 'Submit_Finding' is still counted."""
        phase = PhaseResult(
            phase_name="analysis",
            success=True,
            messages=["Used Submit_Finding for the IOC."],
            turns_used=1,
        )
        assert _count_finding_submissions(phase) == 1

    def test_zero_when_absent(self) -> None:
        """Returns 0 when no submit_finding pattern present."""
        phase = PhaseResult(
            phase_name="analysis",
            success=True,
            messages=["Analysis complete, no findings to report."],
            turns_used=1,
        )
        assert _count_finding_submissions(phase) == 0


class TestExtractSystemContext:
    """Tests for _extract_system_context."""

    def test_extracts_surrounding_200_chars(self) -> None:
        """Context window around each occurrence is 200 chars each side."""
        padding = "x" * 300
        text = f"{padding}target_host{padding}"
        result = _extract_system_context(text, "target_host")
        assert "target_host" in result
        assert len(result) <= 200 + len("target_host") + 200

    def test_multiple_occurrences_concatenated(self) -> None:
        """All occurrences contribute to context string."""
        padding = "x" * 300
        text = f"first target_host here{padding}second target_host there"
        result = _extract_system_context(text, "target_host")
        assert "first" in result
        assert "second" in result
        assert result.count("target_host") >= 2

    def test_no_match_returns_full_text(self) -> None:
        """When system name not found, full text is returned."""
        text = "some text about other systems entirely"
        result = _extract_system_context(text, "nonexistent")
        assert result == text
