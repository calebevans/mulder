"""Provider-bound policy, zero-egress, and outbound-manifest tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.orchestrator.capabilities import (
    DELEGATION_GRANT_ENV,
    DELEGATION_SECRET_ENV,
    identity_for_phase,
    identity_from_delegation_grant,
)
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.session import SessionExecutor
from mulder.security.evidence_envelope import EvidenceFlag, envelope_evidence
from mulder.security.provider_policy import (
    CaseDataPolicy,
    DataClassification,
    EgressCapability,
    OutboundField,
    OutboundManifest,
    OutboundRequest,
    PolicyDecision,
    ProviderPolicy,
    ProviderPolicyError,
    preflight_zero_egress,
    resolve_provider_route,
    summarize_outbound_manifest,
)
from mulder.server.app import _tool_dispatch, _tool_dispatch_sync

_FIXTURE = Path(__file__).parent / "fixtures" / "provider_policy" / "cases.json"


def _fixture() -> dict[str, dict[str, object]]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _request(*fields: OutboundField, model: str = "claude-test") -> OutboundRequest:
    return OutboundRequest(
        case_id="case-42",
        route=resolve_provider_route(model),
        fields=tuple(fields),
        request_id="req-42",
    )


def test_denied_sensitive_content_is_hashed_but_never_written(tmp_path: Path) -> None:
    secret = str(_fixture()["sensitive"]["credential"])
    manifest_path = tmp_path / "case-42.outbound.jsonl"
    policy = ProviderPolicy(
        CaseDataPolicy.METADATA_ONLY,
        manifest=OutboundManifest(manifest_path),
    )
    evidence = envelope_evidence(
        secret,
        source_id="window-7",
        selector="line:19",
    )
    assert EvidenceFlag.SENSITIVE_DATA in evidence.flags

    with pytest.raises(ProviderPolicyError) as exc_info:
        policy.authorize(_request(OutboundField("evidence", secret, evidence=evidence)))

    assert exc_info.value.decision is not None
    assert exc_info.value.decision.decision is PolicyDecision.DENY
    manifest_text = manifest_path.read_text(encoding="utf-8")
    assert secret not in manifest_text
    assert "secret-token-that-must-not-leave" not in manifest_text
    entry = json.loads(manifest_text)
    field = entry["fields"][0]
    assert field["name"] == "evidence"
    assert field["byte_size"] == len(secret.encode())
    assert field["content_hash"] == "sha256:" + hashlib.sha256(secret.encode()).hexdigest()
    assert "sensitive_data" in field["evidence_flags"]
    assert "secret.bearer_token" in field["sensitivity_labels"]


def test_case_policies_distinguish_routes_and_data_classes(tmp_path: Path) -> None:
    local_request = _request(OutboundField("evidence", "full evidence"), model="ollama/qwen3")
    assert ProviderPolicy(CaseDataPolicy.LOCAL_ONLY).authorize(local_request).allowed

    with pytest.raises(ProviderPolicyError, match="local-only"):
        ProviderPolicy(CaseDataPolicy.LOCAL_ONLY).authorize(
            _request(OutboundField("evidence", "full evidence"))
        )

    metadata = _fixture()["benign"]["metadata"]
    metadata_request = _request(
        OutboundField(
            "source_kinds",
            [str(value) for value in metadata],
            DataClassification.METADATA,
        )
    )
    assert ProviderPolicy(CaseDataPolicy.METADATA_ONLY).authorize(metadata_request).allowed

    benign_script = str(_fixture()["benign"]["script"])
    with pytest.raises(ProviderPolicyError, match="script"):
        ProviderPolicy(CaseDataPolicy.METADATA_ONLY).authorize(
            _request(OutboundField("script", benign_script))
        )
    assert (
        ProviderPolicy(CaseDataPolicy.SENSITIVE_APPROVED)
        .authorize(_request(OutboundField("script", benign_script)))
        .allowed
    )


def test_zero_egress_preflight_closes_routes_fallbacks_telemetry_and_adapters() -> None:
    violations = preflight_zero_egress(
        models=["ollama/qwen3", "openai/gpt-5"],
        fallback_models=["claude-haiku-4-5"],
        env={"OTEL_EXPORTER_OTLP_ENDPOINT": "https://telemetry.example"},
        proxy_config="/tmp/litellm.yaml",
        external_threat_intelligence=True,
        egress_adapters=["external-threat-intelligence"],
    )

    assert any("cloud model route" in item for item in violations)
    assert any("cloud model fallback" in item for item in violations)
    assert any("telemetry" in item for item in violations)
    assert any("external threat intelligence" in item for item in violations)
    assert any("custom proxy" in item for item in violations)
    assert any("external-threat-intelligence" in item for item in violations)
    assert preflight_zero_egress(models=["ollama/qwen3"]) == ()
    assert any(
        "cloud model route" in item
        for item in preflight_zero_egress(
            models=["ollama/qwen3"],
            env={"OLLAMA_HOST": "remote-model.example:11434"},
        )
    )


def _session(policy: ProviderPolicy) -> SessionExecutor:
    return SessionExecutor(
        dashboard=MagicMock(),
        model_config=ModelConfig(),
        cwd="/tmp",
        env={},
        effort="max",
        provider_policy=policy,
        case_id="case-42",
    )


@pytest.mark.asyncio()
async def test_rejected_pii_never_reaches_sdk_serialization_or_query(tmp_path: Path) -> None:
    pii = str(_fixture()["sensitive"]["pii"])
    policy = ProviderPolicy(
        CaseDataPolicy.METADATA_ONLY,
        manifest=OutboundManifest(tmp_path / "case-42.outbound.jsonl"),
    )
    session = _session(policy)

    with (
        patch("mulder.orchestrator.session.ClaudeAgentOptions") as serializer,
        patch("mulder.orchestrator.session.query") as provider_query,
        pytest.raises(ProviderPolicyError, match="metadata-only"),
    ):
        await session.execute(
            system_prompt="trusted system instructions",
            prompt=pii,
            model="claude-test",
            allowed_tools=[],
            disallowed_tools=[],
            max_turns=1,
            max_budget=1.0,
        )

    serializer.assert_not_called()
    provider_query.assert_not_called()
    manifest_text = (tmp_path / "case-42.outbound.jsonl").read_text(encoding="utf-8")
    assert pii not in manifest_text
    entry = json.loads(manifest_text)
    prompt_field = next(field for field in entry["fields"] if field["name"] == "prompt")
    assert prompt_field["sensitivity_labels"] == ["pii.email", "pii.us_ssn"]


@pytest.mark.asyncio()
async def test_allowed_request_manifest_matches_fields_at_sdk_seam(tmp_path: Path) -> None:
    manifest_path = tmp_path / "case-42.outbound.jsonl"
    session = _session(
        ProviderPolicy(
            CaseDataPolicy.SENSITIVE_APPROVED,
            manifest=OutboundManifest(manifest_path),
        )
    )

    async def empty_query(**_kwargs: object):  # type: ignore[no-untyped-def]
        if False:
            yield None

    with (
        patch("mulder.orchestrator.session.ClaudeAgentOptions", return_value=object()) as options,
        patch("mulder.orchestrator.session.query", empty_query),
    ):
        await session.execute(
            system_prompt="system",
            prompt="question",
            model="claude-test",
            allowed_tools=["Read"],
            disallowed_tools=["Bash"],
            max_turns=1,
            max_budget=1.0,
        )

    options.assert_called_once()
    assert "PostToolUse" in options.call_args.kwargs["hooks"]
    entry = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert entry["decision"] == "allow"
    assert entry["provider"] == "anthropic"
    assert entry["model"] == "claude-test"
    assert entry["field_count"] == 2
    assert entry["item_count"] == 2
    expected_bytes = len(b"system") + len(b"question")
    assert entry["byte_size"] == expected_bytes
    assert summarize_outbound_manifest(manifest_path) == {
        "status": "recorded",
        "request_count": 1,
        "allowed_count": 1,
        "denied_count": 0,
        "allowed_byte_size": expected_bytes,
        "providers": ["anthropic"],
        "models": ["claude-test"],
        "field_names": ["prompt", "system_prompt"],
        "denied_field_names": [],
        "policy": "sensitive-approved",
        "zero_egress": False,
    }


@pytest.mark.asyncio()
async def test_sdk_session_environment_binds_signed_direct_dispatch_identity() -> None:
    session = _session(ProviderPolicy())
    identity = identity_for_phase("alternative_narrative", "executor")

    async def empty_query(**_kwargs: object):  # type: ignore[no-untyped-def]
        if False:
            yield None

    with (
        patch("mulder.orchestrator.session.ClaudeAgentOptions", return_value=object()) as options,
        patch("mulder.orchestrator.session.query", empty_query),
    ):
        await session.execute(
            system_prompt="system",
            prompt="question",
            model="claude-test",
            allowed_tools=["search"],
            disallowed_tools=[],
            max_turns=1,
            max_budget=1.0,
            identity=identity,
        )

    session_env = options.call_args.kwargs["env"]
    secret = session_env[DELEGATION_SECRET_ENV]
    assert (
        identity_from_delegation_grant(session_env[DELEGATION_GRANT_ENV], secret)
        == identity
    )


@pytest.mark.asyncio()
async def test_sdk_hook_manifests_dynamic_tool_results_without_content(tmp_path: Path) -> None:
    secret = str(_fixture()["sensitive"]["credential"])
    manifest_path = tmp_path / "case-42.outbound.jsonl"
    session = _session(ProviderPolicy(manifest=OutboundManifest(manifest_path)))
    hooks = session._provider_policy_hooks(resolve_provider_route("claude-test"))
    callback = hooks["PostToolUse"][0].hooks[0]

    result = await callback(
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "get_raw_output",
            "tool_input": {},
            "tool_response": {"evidence": secret},
            "tool_use_id": "tool-1",
            "session_id": "session-1",
            "transcript_path": "/tmp/transcript",
            "cwd": "/tmp",
            "permission_mode": "bypassPermissions",
        },
        "tool-1",
        {"signal": None},
    )

    assert result == {}
    manifest_text = manifest_path.read_text(encoding="utf-8")
    assert secret not in manifest_text
    entry = json.loads(manifest_text)
    assert entry["fields"][0]["name"] == "tool_response:get_raw_output"
    assert entry["fields"][0]["sensitivity_labels"] == ["secret.bearer_token"]


@pytest.mark.asyncio()
async def test_pre_tool_hook_binds_parallel_call_to_signed_session_identity() -> None:
    session = _session(ProviderPolicy())
    identity = identity_for_phase("alternative_narrative", "executor")
    hooks = session._provider_policy_hooks(
        resolve_provider_route("claude-test"),
        identity=identity,
        delegation_secret="session-only-secret",
    )
    callback = hooks["PreToolUse"][0].hooks[0]

    result = await callback(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__mulder__run_parallel",
            "tool_input": {"tasks": []},
            "tool_use_id": "tool-1",
            "session_id": "session-1",
            "transcript_path": "/tmp/transcript",
            "cwd": "/tmp",
            "permission_mode": "bypassPermissions",
        },
        "tool-1",
        {"signal": None},
    )

    updated = result["hookSpecificOutput"]["updatedInput"]
    assert updated["tasks"] == []
    assert (
        identity_from_delegation_grant(updated["delegation_grant"], "session-only-secret")
        == identity
    )


@pytest.mark.asyncio()
async def test_airgap_external_ti_rejects_before_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MULDER_ZERO_EGRESS", "1")
    network_adapter = MagicMock()
    assert "enrich_iocs" not in _tool_dispatch_sync
    handler = _tool_dispatch["enrich_iocs"]

    with (
        patch("mulder.server.tools.enrichment.httpx.AsyncClient", network_adapter),
        pytest.raises(
            ProviderPolicyError,
            match=EgressCapability.EXTERNAL_THREAT_INTELLIGENCE.value,
        ),
    ):
        await handler(case_id="case-42", iocs=["203.0.113.7"])

    network_adapter.assert_not_called()
