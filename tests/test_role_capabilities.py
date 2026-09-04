"""Tests for independent agent identity and tool-effect authorization."""

from __future__ import annotations

import pytest

from mulder.orchestrator.capabilities import (
    VERIFIER_IDENTITY,
    AgentIdentity,
    Capability,
    CapabilityViolation,
    authorize_tool_list,
    identity_for_phase,
)
from mulder.orchestrator.phases import (
    ALTERNATIVE_NARRATIVE,
    CATALOG,
    CROSS_SYSTEM,
    EXTRACTION,
    REPORT,
    PhaseConfig,
)
from mulder.server.tool_access import Role


def _seats(phase: PhaseConfig) -> list[tuple[str, list[str]]]:
    if phase.mode == "single":
        return [("single", phase.single_allowed_tools)]
    return [
        ("planner", phase.planner_allowed_tools),
        ("executor", phase.executor_allowed_tools),
        ("analyst", phase.analyst_allowed_tools),
    ]


def test_every_declared_phase_allowlist_is_authorized() -> None:
    for phase in (CATALOG, EXTRACTION, CROSS_SYSTEM, ALTERNATIVE_NARRATIVE, REPORT):
        for seat, tools in _seats(phase):
            assert authorize_tool_list(identity_for_phase(phase.name, seat), tools) == sorted(
                set(tools)
            )


def test_narrative_identity_cannot_gain_extraction_tool_by_configuration() -> None:
    extraction_tool = next(
        tool
        for tool in EXTRACTION.executor_allowed_tools
        if tool not in ALTERNATIVE_NARRATIVE.executor_allowed_tools
    )

    with pytest.raises(CapabilityViolation):
        authorize_tool_list(
            identity_for_phase("alternative_narrative", "executor"),
            [extraction_tool],
        )


def test_role_declaration_and_effect_capability_are_both_required() -> None:
    extraction_tool = next(
        tool
        for tool in EXTRACTION.executor_allowed_tools
        if tool.startswith("mcp__mulder__")
        and tool not in {"mcp__mulder__open_case", "mcp__mulder__list_cases"}
    )
    underprivileged = AgentIdentity(
        "underprivileged-extractor",
        Role.EXTRACT_EXECUTOR,
        frozenset({Capability.CASE_READ}),
    )

    with pytest.raises(CapabilityViolation, match="lacks"):
        authorize_tool_list(underprivileged, [extraction_tool])


def test_unknown_tool_is_rejected_before_provider_startup() -> None:
    with pytest.raises(CapabilityViolation, match="unknown tool"):
        authorize_tool_list(
            identity_for_phase("extraction", "executor"),
            ["mcp__mulder__arbitrary_shell"],
        )


def test_deterministic_verifier_has_no_model_tool_authority() -> None:
    assert VERIFIER_IDENTITY.capabilities == frozenset({Capability.VERIFICATION})
    assert VERIFIER_IDENTITY.role == Role(0)
    assert authorize_tool_list(VERIFIER_IDENTITY, []) == []
    with pytest.raises(CapabilityViolation):
        authorize_tool_list(VERIFIER_IDENTITY, ["mcp__mulder__search"])
