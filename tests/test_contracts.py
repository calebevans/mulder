"""Published contract-schema and compatibility fixture tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from mulder.contracts import CoreContractBundle, core_contract_schema
from mulder.models import AtomicClaim, FindingRevision, ToolOutcome, ToolOutcomeStatus
from mulder.receipt import MANIFEST_SCHEMA, MANIFEST_VERSION

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "contracts"
SCHEMA = ROOT / "schemas" / "core-contract-v1.schema.json"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def test_valid_contract_fixture_round_trips() -> None:
    payload = _load(FIXTURES / "core-valid-v1.json")
    bundle = CoreContractBundle.model_validate(payload)
    assert bundle.schema_version == 1
    assert bundle.atomic_claim.anchors[0].exact_text == "cmd.exe"
    assert bundle.finding_revision.snapshot.finding_id == bundle.atomic_claim.finding_id
    assert bundle.model_dump(mode="json", exclude_unset=True) == payload


def test_invalid_contract_fixtures_stay_invalid() -> None:
    models: dict[str, type[BaseModel]] = {
        "tool_outcome": ToolOutcome,
        "atomic_claim": AtomicClaim,
        "finding_revision": FindingRevision,
    }
    invalid = _load(FIXTURES / "core-invalid-v1.json")
    for case in invalid["cases"]:
        with pytest.raises(ValidationError):
            models[case["model"]].model_validate(case["payload"])


def test_committed_schema_matches_authoritative_models() -> None:
    assert _load(SCHEMA) == core_contract_schema()


def test_tool_outcome_enum_cannot_drift_from_published_schema() -> None:
    schema = _load(SCHEMA)
    published = set(schema["$defs"]["ToolOutcomeStatus"]["enum"])
    assert published == {status.value for status in ToolOutcomeStatus}


def test_receipt_contract_identity_is_stable() -> None:
    assert MANIFEST_SCHEMA == "mulder.case-manifest"
    assert MANIFEST_VERSION == 1
