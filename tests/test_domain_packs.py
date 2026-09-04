"""Contract and integration tests for static domain packs."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.extractors.classifier import ClassifierConfig, EvidenceClassifier
from mulder.models import ToolOutcomeStatus
from mulder.orchestrator.phases import PhaseConfig
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import InvestigationResult, PhaseResult
from mulder.packs import (
    DomainPackManifest,
    DomainPackRegistry,
    PackContractError,
    PackRuntimeInventory,
    domain_pack_schema,
    parse_pack_manifest,
)
from mulder.server.tool_access import Role, tool_access

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "domain_packs"


def _payload() -> dict[str, object]:
    return json.loads((FIXTURE_ROOT / "valid-pack.json").read_text(encoding="utf-8"))


def _manifest(payload: dict[str, object] | None = None) -> DomainPackManifest:
    result = parse_pack_manifest(payload or _payload())
    assert result.manifest is not None
    return result.manifest


def _inventory(**changes: object) -> PackRuntimeInventory:
    values: dict[str, object] = {
        "available_capabilities": ("forensic.local-read",),
        "parser_versions": {"acme-parser": "2.0"},
        "fixture_root": FIXTURE_ROOT,
    }
    values.update(changes)
    return PackRuntimeInventory.model_validate(values)


def _resolver(name: str) -> Role | None:
    if name == "inspect_acme":
        return Role.EXTRACT_EXECUTOR
    return None


def test_manifest_and_schema_are_deterministic() -> None:
    first = _manifest()
    second = _manifest(copy.deepcopy(_payload()))

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.digest == second.digest
    schema = domain_pack_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == 1  # type: ignore[index]


def test_unknown_contract_version_is_typed_unsupported() -> None:
    payload = _payload()
    payload["schema_version"] = 99

    result = parse_pack_manifest(payload)

    assert result.manifest is None
    assert result.outcome.status is ToolOutcomeStatus.UNSUPPORTED_VERSION


def test_schema_drift_and_undeclared_references_are_rejected() -> None:
    drifted = _payload()
    drifted["future_field"] = "silently dangerous"
    with pytest.raises(PackContractError, match="future_field"):
        parse_pack_manifest(drifted)

    undeclared = _payload()
    hunts = undeclared["hunts"]
    assert isinstance(hunts, list)
    hunts[0]["tool_binding_ids"] = ["not-declared"]
    with pytest.raises(PackContractError, match="undeclared tools"):
        parse_pack_manifest(undeclared)


def test_duplicate_nested_and_registry_ids_are_rejected() -> None:
    duplicate = _payload()
    tools = duplicate["tool_bindings"]
    assert isinstance(tools, list)
    tools.append(copy.deepcopy(tools[0]))
    with pytest.raises(PackContractError, match="duplicate tool binding IDs"):
        parse_pack_manifest(duplicate)

    registry = DomainPackRegistry(tool_resolver=_resolver)
    registry.register(_manifest())
    with pytest.raises(PackContractError, match="duplicate pack ID"):
        registry.register(_manifest())


def test_preflight_activates_complete_workflow_and_receipt(tmp_path: Path) -> None:
    registry = DomainPackRegistry(tool_resolver=_resolver)
    registry.register(_manifest())

    result = registry.enable(["synthetic.acme"], _inventory())

    assert result.ready
    assert result.outcome.status is ToolOutcomeStatus.SUCCESS_NONEMPTY
    assert result.activation is not None
    activation = result.activation
    assert [step.phase.name for step in activation.workflow_steps] == [
        "pack.synthetic.acme.persistence"
    ]
    step = activation.workflow_steps[0]
    assert step.phase.executor_allowed_tools == ["mcp__mulder__inspect_acme"]
    assert step.validate(["inspect_acme"]).passed
    assert not step.validate([]).passed

    receipt_path = tmp_path / "case.packs.json"
    activation.receipt.write(receipt_path)
    assert receipt_path.read_bytes() == activation.receipt.canonical_bytes() + b"\n"
    record = activation.receipt.packs[0]
    assert record.tool_bindings == {"inspect": "inspect_acme"}
    assert record.parser_versions == {"acme-parser": "2.0"}
    assert record.fixture_digests == {
        "minimal-acme": "b6ff5bc114a75b49eb821e86b978f38d33d4d864ad22dc4b5b54e41b26659c32"
    }


def test_activation_classifier_adds_new_artifact_without_core_edit() -> None:
    registry = DomainPackRegistry(tool_resolver=_resolver)
    registry.register(_manifest())
    result = registry.enable(["synthetic.acme"], _inventory())
    assert result.activation is not None

    classifier = EvidenceClassifier(
        ClassifierConfig(pack_rules=result.activation.classifier_rules)
    )
    classified = classifier.classify(FIXTURE_ROOT / "sample.acme")

    assert len(classified) == 1
    assert classified[0].artifact_type == "acme_artifact"


def test_default_resolver_uses_existing_tool_access_registry() -> None:
    @tool_access(Role.EXTRACT_EXECUTOR)
    def inspect_acme() -> None:
        return None

    registry = DomainPackRegistry()
    registry.register(_manifest())

    assert registry.enable(["synthetic.acme"], _inventory()).ready


@pytest.mark.asyncio()
async def test_orchestrator_inserts_pack_workflow_without_phase_list_edit() -> None:
    registry = DomainPackRegistry(tool_resolver=_resolver)
    registry.register(_manifest())
    preflight = registry.enable(["synthetic.acme"], _inventory())
    assert preflight.activation is not None
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orchestrator = Orchestrator(
            evidence_path=str(FIXTURE_ROOT),
            case_id="pack-case",
            pack_activation=preflight.activation,
        )

    catalog = PhaseResult(
        phase_name="catalog",
        success=True,
        messages=[
            json.dumps(
                {
                    "case_id": "pack-case",
                    "evidence_root": str(FIXTURE_ROOT),
                    "systems": [{"name": "host-a", "evidence": ["acme_artifact"]}],
                }
            )
        ],
    )
    report = PhaseResult(phase_name="report", success=True)
    single_results = iter((catalog, report))
    observed_split_phases: list[str] = []

    async def fake_single(*_args: object, **_kwargs: object) -> PhaseResult:
        return next(single_results)

    async def fake_pool(
        _groups: list[list[str]], result: InvestigationResult
    ) -> None:
        extraction = PhaseResult(phase_name="extraction", success=True)
        result.phases.append(extraction)
        orchestrator._accumulate(result, extraction)

    async def fake_split(phase: PhaseConfig, **_kwargs: object) -> PhaseResult:
        phase_name = phase.name
        observed_split_phases.append(phase_name)
        return PhaseResult(phase_name=phase_name, success=True)

    result = InvestigationResult()
    with (
        patch.object(orchestrator._evidence, "load_case_briefing", return_value=""),
        patch.object(orchestrator, "_run_single_phase", side_effect=fake_single),
        patch.object(orchestrator, "_run_extraction_pool", side_effect=fake_pool),
        patch.object(orchestrator, "_run_split_phase", side_effect=fake_split),
        patch.object(orchestrator._server, "build_consistency_report", return_value=""),
        patch.object(orchestrator, "_write_model_usage"),
    ):
        completed = await orchestrator._run_pipeline(result)

    assert "pack.synthetic.acme.persistence" in observed_split_phases
    assert completed.success
    assert orchestrator._total_phases == 6


@pytest.mark.parametrize(
    ("inventory_changes", "resolver", "code", "status"),
    [
        (
            {"parser_versions": {"acme-parser": "3.0"}},
            _resolver,
            "unsupported_parser",
            ToolOutcomeStatus.UNSUPPORTED_VERSION,
        ),
        (
            {"parser_versions": {}},
            _resolver,
            "missing_parser",
            ToolOutcomeStatus.UNSUPPORTED_VERSION,
        ),
        (
            {"available_capabilities": ()},
            _resolver,
            "missing_capability",
            ToolOutcomeStatus.UNAVAILABLE,
        ),
        (
            {},
            lambda _name: None,
            "missing_tool",
            ToolOutcomeStatus.UNAVAILABLE,
        ),
        (
            {},
            lambda _name: Role.EXTRACT_ANALYST,
            "tool_role_mismatch",
            ToolOutcomeStatus.UNAVAILABLE,
        ),
        (
            {"fixture_root": FIXTURE_ROOT / "absent"},
            _resolver,
            "missing_fixture",
            ToolOutcomeStatus.UNAVAILABLE,
        ),
    ],
)
def test_preflight_fails_closed(
    inventory_changes: dict[str, object],
    resolver: Callable[[str], Role | None],
    code: str,
    status: ToolOutcomeStatus,
) -> None:
    registry = DomainPackRegistry(tool_resolver=resolver)
    registry.register(_manifest())

    result = registry.enable(["synthetic.acme"], _inventory(**inventory_changes))

    assert not result.ready
    assert result.outcome.status is status
    assert code in {issue.code for issue in result.issues}


def test_activation_order_does_not_depend_on_registration_order() -> None:
    alpha_payload = _payload()
    alpha_payload["pack_id"] = "alpha"
    alpha_payload["receipt_replay"]["receipt_namespace"] = "alpha"  # type: ignore[index]
    beta_payload = _payload()
    beta_payload["pack_id"] = "beta"
    beta_payload["receipt_replay"]["receipt_namespace"] = "beta"  # type: ignore[index]

    first = DomainPackRegistry(tool_resolver=_resolver)
    first.register(_manifest(beta_payload))
    first.register(_manifest(alpha_payload))
    second = DomainPackRegistry(tool_resolver=_resolver)
    second.register(_manifest(alpha_payload))
    second.register(_manifest(beta_payload))

    first_result = first.enable(["beta", "alpha"], _inventory())
    second_result = second.enable(["alpha", "beta"], _inventory())
    assert first_result.activation is not None
    assert second_result.activation is not None
    assert first_result.activation.receipt.canonical_bytes() == (
        second_result.activation.receipt.canonical_bytes()
    )
    assert [record.pack_id for record in first_result.activation.receipt.packs] == [
        "alpha",
        "beta",
    ]
