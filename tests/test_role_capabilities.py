"""Tests for independent agent identity and tool-effect authorization."""

from __future__ import annotations

import inspect
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mulder.orchestrator.capabilities import (
    VERIFIER_IDENTITY,
    AgentIdentity,
    Capability,
    CapabilityViolation,
    authorize_tool,
    authorize_tool_list,
    create_delegation_grant,
    identity_for_phase,
    identity_from_delegation_grant,
)
from mulder.orchestrator.phases import (
    ALTERNATIVE_NARRATIVE,
    CATALOG,
    CROSS_SYSTEM,
    EXTRACTION,
    REPORT,
    PhaseConfig,
)
from mulder.server.tool_access import Role, get_registered_tool_roles


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


def test_declared_phase_allowlists_capture_the_complete_tool_registry() -> None:
    project_root = Path(__file__).resolve().parents[1]
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "\n".join(
                (
                    "from mulder.orchestrator.phases import EXTRACTION",
                    "from mulder.server.tool_access import Role, get_tools_for_role",
                    "declared = EXTRACTION.executor_allowed_tools",
                    "complete = get_tools_for_role(Role.EXTRACT_EXECUTOR)",
                    "missing = sorted(set(complete) - set(declared))",
                    "if missing: raise SystemExit(f'incomplete extraction/executor "
                    "allowlist: {missing!r}')",
                )
            ),
        ],
        cwd=project_root,
        env={**os.environ, "PYTHONPATH": str(project_root / "src")},
        capture_output=True,
        text=True,
        check=False,
    )

    assert probe.returncode == 0, probe.stderr


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
        if get_registered_tool_roles(tool) == Role.EXTRACT_EXECUTOR
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


def test_preflighted_pack_seats_retain_extraction_role_boundaries() -> None:
    identity = identity_for_phase("pack.anti-forensics.clock", "executor")

    assert identity.name == "pack.anti-forensics.clock-executor"
    assert identity.role is Role.EXTRACT_EXECUTOR
    assert Capability.FORENSIC_EXECUTION in identity.capabilities
    with pytest.raises(CapabilityViolation, match="pack identity"):
        identity_for_phase("pack.anti-forensics.clock", "publisher")


def test_delegation_grant_is_tamper_evident() -> None:
    identity = identity_for_phase("alternative_narrative", "executor")
    grant = create_delegation_grant(identity, "session-secret")

    assert identity_from_delegation_grant(grant, "session-secret") == identity
    with pytest.raises(CapabilityViolation, match="invalid nested-tool"):
        identity_from_delegation_grant(grant + "x", "session-secret")


@pytest.mark.asyncio()
async def test_nested_authorization_has_direct_parity_and_preserves_valid_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mulder.server import app

    identity = identity_for_phase("alternative_narrative", "executor")
    secret = "narrative-session-secret"
    grant = create_delegation_grant(identity, secret)
    called: list[str] = []

    async def fake_search(**_kwargs: object) -> dict[str, object]:
        called.append("search")
        return {"status": "success", "results": []}

    async def fake_extraction(**_kwargs: object) -> dict[str, object]:
        called.append("run_volatility")
        return {"status": "success"}

    monkeypatch.setenv("MULDER_TOOL_DELEGATION_SECRET", secret)
    monkeypatch.setitem(app._tool_dispatch, "search", fake_search)
    monkeypatch.setitem(app._tool_dispatch, "run_volatility", fake_extraction)

    authorize_tool(identity, "search")
    with pytest.raises(CapabilityViolation):
        authorize_tool(identity, "run_volatility")

    response = await inspect.unwrap(app.run_parallel)(
        tasks=[
            {"tool": "search", "args": {"query": "x"}},
            {"tool": "run_volatility", "args": {"plugin": "pslist"}},
        ],
        delegation_grant=grant,
    )

    assert called == ["search"]
    assert response["parallel_results"][0]["result"]["status"] == "success"
    assert "Unauthorized nested tool" in response["parallel_results"][1]["result"]["error"]

    extraction_identity = identity_for_phase("extraction", "executor")
    extraction_grant = create_delegation_grant(extraction_identity, secret)
    extraction_response = await inspect.unwrap(app.run_parallel)(
        tasks=[{"tool": "run_volatility", "args": {"plugin": "pslist"}}],
        delegation_grant=extraction_grant,
    )
    assert called == ["search", "run_volatility"]
    assert extraction_response["parallel_results"][0]["result"]["status"] == "success"


@pytest.mark.asyncio()
async def test_parallel_dispatch_without_a_verified_initiator_fails_closed() -> None:
    from mulder.server import app

    with pytest.raises(CapabilityViolation, match="delegation grant is required"):
        await inspect.unwrap(app.run_parallel)(tasks=[{"tool": "search", "args": {}}])
