"""Tests for independent agent identity and tool-effect authorization."""

from __future__ import annotations

import inspect
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mulder.orchestrator.capabilities import (
    DELEGATION_GRANT_ENV,
    DELEGATION_SECRET_ENV,
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
from mulder.server.tool_access import (
    Role,
    ToolEffect,
    get_registered_tool_effect,
    get_registered_tool_effect_set,
    get_registered_tool_effects,
    get_registered_tool_roles,
    tool_access,
)


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


def test_every_registered_tool_has_a_nonempty_immutable_effect_set() -> None:
    from mulder.server.tool_access import _registry

    effects = get_registered_tool_effects()
    assert set(effects) == set(_registry)
    assert all(
        isinstance(effect_set, frozenset)
        and effect_set
        and all(isinstance(effect, ToolEffect) for effect in effect_set)
        for effect_set in effects.values()
    )


def test_mutating_readers_declare_every_security_relevant_effect() -> None:
    assert get_registered_tool_effect_set("correlate_across_sources") == frozenset(
        {ToolEffect.CASE_READ, ToolEffect.CASE_WRITE}
    )
    assert get_registered_tool_effect_set("parse_autoruns") == frozenset(
        {
            ToolEffect.CASE_READ,
            ToolEffect.FORENSIC_EXECUTION,
            ToolEffect.CASE_WRITE,
        }
    )
    assert get_registered_tool_effect_set("scan_evidence") == frozenset(
        {ToolEffect.CASE_READ, ToolEffect.CASE_WRITE}
    )


def test_multi_effect_authorization_requires_every_effect() -> None:
    underprivileged = AgentIdentity(
        "read-only-correlation",
        Role.NARRATIVE_EXECUTOR,
        frozenset({Capability.CASE_READ, Capability.JOB_CONTROL}),
    )
    with pytest.raises(CapabilityViolation, match="case-mutation"):
        authorize_tool(underprivileged, "correlate_across_sources")

    authorize_tool(
        identity_for_phase("alternative_narrative", "executor"),
        "correlate_across_sources",
    )
    authorize_tool(identity_for_phase("extraction", "analyst"), "parse_autoruns")
    authorize_tool(identity_for_phase("cross_system", "executor"), "parse_autoruns")


def test_catalog_and_pack_executors_gain_no_mutating_parser_authority() -> None:
    assert "mcp__mulder__scan_evidence" not in CATALOG.single_allowed_tools
    assert "scan_evidence" not in CATALOG.single_prompt_template
    assert "{catalog_snapshot}" in CATALOG.single_prompt_template
    assert all(
        get_registered_tool_effect_set(tool) == frozenset({ToolEffect.CASE_READ})
        for tool in CATALOG.single_allowed_tools
    )
    with pytest.raises(CapabilityViolation):
        authorize_tool(identity_for_phase("extraction", "executor"), "parse_autoruns")
    with pytest.raises(CapabilityViolation):
        authorize_tool(identity_for_phase("pack.synthetic", "executor"), "parse_autoruns")
    assert "mcp__mulder__parse_autoruns" not in EXTRACTION.executor_allowed_tools
    assert "mcp__mulder__parse_autoruns" in EXTRACTION.analyst_allowed_tools
    assert "parse_autoruns" in EXTRACTION.analyst_system_prompt


def test_identity_capability_sets_are_unchanged() -> None:
    expected = {
        ("catalog", "single"): {Capability.CASE_READ, Capability.JOB_CONTROL},
        ("extraction", "planner"): {Capability.CASE_READ},
        ("extraction", "executor"): {
            Capability.CASE_READ,
            Capability.FORENSIC_EXECUTION,
            Capability.JOB_CONTROL,
        },
        ("extraction", "analyst"): {
            Capability.CASE_READ,
            Capability.CASE_WRITE,
            Capability.FORENSIC_EXECUTION,
        },
        ("cross_system", "planner"): {Capability.CASE_READ},
        ("cross_system", "executor"): {
            Capability.CASE_READ,
            Capability.CASE_WRITE,
            Capability.FORENSIC_EXECUTION,
            Capability.JOB_CONTROL,
        },
        ("cross_system", "analyst"): {
            Capability.CASE_READ,
            Capability.CASE_WRITE,
        },
        ("alternative_narrative", "planner"): {Capability.CASE_READ},
        ("alternative_narrative", "executor"): {
            Capability.CASE_READ,
            Capability.CASE_WRITE,
            Capability.JOB_CONTROL,
        },
        ("alternative_narrative", "analyst"): {
            Capability.CASE_READ,
            Capability.CASE_WRITE,
        },
        ("report", "single"): {
            Capability.CASE_READ,
            Capability.CASE_WRITE,
            Capability.PUBLICATION,
        },
    }
    for phase_seat, capabilities in expected.items():
        assert identity_for_phase(*phase_seat).capabilities == frozenset(capabilities)


def test_raw_analyzers_and_persistent_reasoning_writers_have_strong_effects() -> None:
    for name in (
        "run_capa",
        "run_hindsight",
        "detect_steganography",
        "get_file_metadata",
        "parse_plist",
        "query_sqlite_from_image",
        "filter_timeline",
        "export_timeline_slice",
    ):
        assert get_registered_tool_effect(name) == frozenset(
            {ToolEffect.FORENSIC_EXECUTION}
        )
    for name in (
        "create_hypothesis",
        "record_hypothesis_test",
        "record_contradiction",
        "resolve_contradiction",
        "record_review_verdict",
    ):
        assert get_registered_tool_effect(name) == frozenset({ToolEffect.CASE_WRITE})


def test_registration_without_an_explicit_effect_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="no explicit effect declaration"):

        @tool_access(Role.CATALOG)
        def undeclared_test_tool() -> dict[str, object]:
            return {}


def test_registration_rejects_empty_multi_effect_declaration() -> None:
    with pytest.raises(ValueError, match="nonempty"):
        tool_access(Role.CATALOG, effects=())


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


def test_direct_registered_dispatch_enforces_bound_session_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mulder.server import app

    secret = "direct-dispatch-session-secret"
    narrative = identity_for_phase("alternative_narrative", "executor")
    monkeypatch.setenv(DELEGATION_SECRET_ENV, secret)
    monkeypatch.delenv(DELEGATION_GRANT_ENV, raising=False)
    with pytest.raises(CapabilityViolation, match="incomplete"):
        app._tool_dispatch_sync["search"]("case", "needle")

    monkeypatch.setenv(DELEGATION_GRANT_ENV, create_delegation_grant(narrative, secret))

    with pytest.raises(CapabilityViolation):
        app._tool_dispatch_sync["run_volatility"]("pslist", "/does-not-exist")

    extraction = identity_for_phase("extraction", "executor")
    monkeypatch.setenv(DELEGATION_GRANT_ENV, create_delegation_grant(extraction, secret))
    response = app._tool_dispatch_sync["run_volatility"]("pslist", "/does-not-exist")
    assert response["error_type"] == "file_not_found"


@pytest.mark.asyncio()
async def test_mcp_transport_dispatch_authorizes_before_resource_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mulder.server import app

    secret = "transport-session-secret"
    narrative = identity_for_phase("alternative_narrative", "executor")
    monkeypatch.setenv(DELEGATION_SECRET_ENV, secret)
    monkeypatch.setenv(DELEGATION_GRANT_ENV, create_delegation_grant(narrative, secret))

    with pytest.raises(CapabilityViolation):
        await app._tool_dispatch["run_volatility"]("pslist", "/does-not-exist")


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
async def test_nested_dispatch_rejects_identity_missing_one_declared_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mulder.server import app

    identity = AgentIdentity(
        "read-only-narrative",
        Role.NARRATIVE_EXECUTOR,
        frozenset({Capability.CASE_READ, Capability.JOB_CONTROL}),
    )
    secret = "multi-effect-nested-secret"
    called = False

    async def fake_correlation(**_kwargs: object) -> dict[str, object]:
        nonlocal called
        called = True
        return {"status": "success"}

    monkeypatch.setenv(DELEGATION_SECRET_ENV, secret)
    monkeypatch.setitem(
        app._tool_dispatch,
        "correlate_across_sources",
        fake_correlation,
    )
    response = await inspect.unwrap(app.run_parallel)(
        tasks=[{"tool": "correlate_across_sources", "args": {}}],
        delegation_grant=create_delegation_grant(identity, secret),
    )

    assert called is False
    assert "Unauthorized nested tool" in response["parallel_results"][0]["result"]["error"]


@pytest.mark.asyncio()
async def test_parallel_dispatch_without_a_verified_initiator_fails_closed() -> None:
    from mulder.server import app

    with pytest.raises(CapabilityViolation, match="delegation grant is required"):
        await inspect.unwrap(app.run_parallel)(tasks=[{"tool": "search", "args": {}}])
