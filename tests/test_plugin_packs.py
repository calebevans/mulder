"""Adversarial tests for explicit declarative pack discovery and activation."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, cast

import pytest
from click.testing import CliRunner

from mulder.cli import cli
from mulder.db import CaseDB
from mulder.plugin_packs import (
    CapabilityApproval,
    ComponentInventory,
    PluginActivationRequest,
    PluginDiscoveryRequest,
    PluginPackError,
    UnsupportedPluginVersion,
    discover_plugin_packs,
)
from mulder.receipt import ReplayInventory, assess_replay, seal_case

FIXTURES = Path(__file__).parent / "fixtures" / "plugin_packs"
GOOD_PACK = FIXTURES / "good"


def _approval() -> CapabilityApproval:
    return CapabilityApproval.model_validate_json((FIXTURES / "approval.json").read_text())


def _inventory() -> ComponentInventory:
    return ComponentInventory.model_validate_json((FIXTURES / "inventory.json").read_text())


def _request(*roots: Path, inventory: ComponentInventory | None = None) -> PluginDiscoveryRequest:
    return PluginDiscoveryRequest(
        approved_roots=roots,
        capability_approval=_approval(),
        inventory=inventory or _inventory(),
    )


def _copy_good(tmp_path: Path, name: str = "pack") -> Path:
    target = tmp_path / name
    shutil.copytree(GOOD_PACK, target)
    return target


def _manifest(pack: Path) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((pack / "mulder-plugin.json").read_text(encoding="utf-8")),
    )


def _write_manifest(pack: Path, manifest: dict[str, Any]) -> None:
    (pack / "mulder-plugin.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_no_approved_location_discovers_nothing() -> None:
    catalog = discover_plugin_packs(PluginDiscoveryRequest())

    assert catalog.schema_version == 1
    assert catalog.packs == ()


def test_discovery_metadata_and_digests_are_deterministic() -> None:
    request = _request(GOOD_PACK)

    first = discover_plugin_packs(request)
    second = discover_plugin_packs(request)

    assert first == second
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    pack = first.packs[0]
    assert pack.status == "READY"
    assert pack.plugin_digest.startswith("sha256:")
    assert pack.manifest_digest.startswith("sha256:")
    assert [check.status for check in pack.compatibility] == [
        "COMPATIBLE",
        "COMPATIBLE",
        "COMPATIBLE",
    ]


def test_exact_manifest_is_an_independent_opt_in_boundary() -> None:
    request = PluginDiscoveryRequest(
        approved_manifests=(GOOD_PACK / "mulder-plugin.json",),
        capability_approval=_approval(),
        inventory=_inventory(),
    )

    catalog = discover_plugin_packs(request)

    assert [pack.manifest.plugin.plugin_id for pack in catalog.packs] == [
        "example.evtx-hunt"
    ]


@pytest.mark.parametrize(
    ("mutation", "reason_code"),
    [
        ("path_escape", "INVALID_MANIFEST"),
        ("network_escalation", "CAPABILITY_ESCALATION"),
        ("digest_drift", "DIGEST_DRIFT"),
        ("undeclared_entry_point", "INVALID_MANIFEST"),
        ("undeclared_import", "UNDECLARED_FILE"),
    ],
)
def test_malicious_pack_is_rejected(
    tmp_path: Path,
    mutation: str,
    reason_code: str,
) -> None:
    pack = _copy_good(tmp_path)
    manifest = _manifest(pack)
    if mutation == "path_escape":
        manifest["resources"][0]["path"] = "../outside.json"
        _write_manifest(pack, manifest)
    elif mutation == "network_escalation":
        manifest["capabilities"]["network"] = "outbound"
        _write_manifest(pack, manifest)
    elif mutation == "digest_drift":
        (pack / "rules" / "hunt.json").write_text("tampered\n", encoding="utf-8")
    elif mutation == "undeclared_entry_point":
        manifest["entry_point"] = "evil:run"
        _write_manifest(pack, manifest)
    elif mutation == "undeclared_import":
        (pack / "evil.py").write_text("raise RuntimeError('imported')\n", encoding="utf-8")

    with pytest.raises(PluginPackError) as caught:
        discover_plugin_packs(_request(pack))

    assert caught.value.reason_code == reason_code


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tools", ["undeclared-tool"]),
        ("path_scopes", ["evidence_read"]),
        ("write_scopes", ["case_database"]),
    ],
)
def test_each_symbolic_capability_dimension_has_an_examiner_ceiling(
    tmp_path: Path,
    field: str,
    value: list[str],
) -> None:
    pack = _copy_good(tmp_path)
    manifest = _manifest(pack)
    manifest["capabilities"][field] = value
    if field == "tools":
        manifest["compatibility"].append(
            {
                "kind": "tool",
                "name": "undeclared-tool",
                "supported_versions": ["1"],
                "supported_digests": ["sha256:" + "f" * 64],
            }
        )
    _write_manifest(pack, manifest)

    with pytest.raises(PluginPackError) as caught:
        discover_plugin_packs(_request(pack))

    assert caught.value.reason_code == "CAPABILITY_ESCALATION"


def test_symlink_inside_pack_is_rejected(tmp_path: Path) -> None:
    pack = _copy_good(tmp_path)
    (pack / "linked.json").symlink_to(pack / "rules" / "hunt.json")

    with pytest.raises(PluginPackError) as caught:
        discover_plugin_packs(_request(pack))

    assert caught.value.reason_code == "SYMLINK_DENIED"


def test_duplicate_plugin_ids_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "packs"
    root.mkdir()
    _copy_good(root, "one")
    _copy_good(root, "two")

    with pytest.raises(PluginPackError) as caught:
        discover_plugin_packs(_request(root))

    assert caught.value.reason_code == "DUPLICATE_PLUGIN_ID"


def test_incompatible_version_is_visible_and_activation_fails_loudly(tmp_path: Path) -> None:
    components = tuple(
        component.model_copy(update={"version": "99.0"})
        if component.kind == "parser"
        else component
        for component in _inventory().components
    )
    request = _request(GOOD_PACK, inventory=ComponentInventory(components=components))

    catalog = discover_plugin_packs(request)
    assert catalog.packs[0].status == "UNSUPPORTED_VERSION"
    parser = next(
        check for check in catalog.packs[0].compatibility if check.requirement.kind == "parser"
    )
    assert parser.status == "UNSUPPORTED_VERSION"

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with (
        CaseDB.create("unsupported", str(evidence), tmp_path) as db,
        pytest.raises(UnsupportedPluginVersion) as caught,
    ):
        db.activate_plugin_packs(
            PluginActivationRequest(
                discovery=request,
                plugin_ids=("example.evtx-hunt",),
            )
        )
    assert caught.value.status == "UNSUPPORTED_VERSION"


def test_component_digest_drift_is_not_reported_as_version_mismatch() -> None:
    components = tuple(
        component.model_copy(update={"digest": "sha256:" + "f" * 64})
        if component.kind == "binary"
        else component
        for component in _inventory().components
    )

    pack = discover_plugin_packs(
        _request(GOOD_PACK, inventory=ComponentInventory(components=components))
    ).packs[0]

    binary = next(check for check in pack.compatibility if check.requirement.kind == "binary")
    assert binary.status == "DIGEST_DRIFT"
    assert pack.status == "UNSUPPORTED_VERSION"


def test_activation_is_case_local_idempotent_and_receipted(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    discovery = _request(GOOD_PACK)
    activation_request = PluginActivationRequest(
        discovery=discovery,
        plugin_ids=("example.evtx-hunt",),
    )
    with CaseDB.create("pack-case", str(evidence), tmp_path) as db:
        first = db.activate_plugin_packs(activation_request)
        second = db.activate_plugin_packs(activation_request)
        persisted = db.get_plugin_activations()
    assert first == second == persisted
    assert len(first) == 1

    (tmp_path / "pack-case.audit.jsonl").touch()
    manifest_path = seal_case("pack-case", tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    methodology = manifest["methodology"]
    activation = methodology["plugin_activations"][0]
    replay = methodology["replay"]

    assert activation["plugin"]["plugin_id"] == "example.evtx-hunt"
    assert activation["plugin"]["license"] == "Apache-2.0"
    assert replay["plugin_digests"] == {
        "example.evtx-hunt@1.2.0": activation["plugin_digest"]
    }
    assert any(key.endswith("/binary:chainsaw") for key in replay["binary_versions"])
    assert len(replay["component_digests"]) == 3
    assert assess_replay(manifest, ReplayInventory.from_mapping(replay)).status == "EXACT"

    drifted = dict(replay)
    drifted["plugin_digests"] = {"example.evtx-hunt@1.2.0": "sha256:" + "0" * 64}
    assert assess_replay(manifest, ReplayInventory.from_mapping(drifted)).status == "DRIFTED"


def test_existing_activation_refuses_manifest_drift(tmp_path: Path) -> None:
    pack = _copy_good(tmp_path / "approved")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    request = PluginActivationRequest(
        discovery=_request(pack),
        plugin_ids=("example.evtx-hunt",),
    )
    with CaseDB.create("immutable", str(evidence), tmp_path) as db:
        db.activate_plugin_packs(request)
        manifest = _manifest(pack)
        manifest["description"] = "changed after activation"
        _write_manifest(pack, manifest)

        with pytest.raises(PluginPackError) as caught:
            db.activate_plugin_packs(request)

    assert caught.value.reason_code == "ACTIVATION_DRIFT"


def test_plugin_cli_is_opt_in_and_machine_readable() -> None:
    runner = CliRunner()

    empty = runner.invoke(cli, ["plugins", "discover", "--json"])
    ready = runner.invoke(
        cli,
        [
            "plugins",
            "discover",
            "--root",
            str(GOOD_PACK),
            "--approval",
            str(FIXTURES / "approval.json"),
            "--inventory",
            str(FIXTURES / "inventory.json"),
            "--json",
        ],
    )

    assert empty.exit_code == 0
    empty_catalog = json.loads(empty.output)
    assert empty_catalog["schema"] == "mulder.plugin-catalog"
    assert empty_catalog["version"] == 1
    assert empty_catalog["packs"] == []
    assert ready.exit_code == 0, ready.output
    assert json.loads(ready.output)["packs"][0]["status"] == "READY"
