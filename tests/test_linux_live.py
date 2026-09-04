"""Fixture-backed safety and integrity tests for Linux live acquisition."""

from __future__ import annotations

import hashlib
import inspect
import json
import shutil
import socket
import zipfile
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from mulder.cli import cli
from mulder.db import CaseDB
from mulder.linux_live import (
    ALL_LINUX_CHECKS,
    LinuxCheck,
    LinuxCollectionRequest,
    LinuxCollectionScope,
    LinuxLiveCollectionError,
    collect_linux_live_state,
    linux_live_pack_descriptor,
    linux_live_pack_fixture_root,
    verify_linux_live_bundle,
)
from mulder.models import ToolOutcomeStatus

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "linux_live" / "root"
FIXTURE_TEMPLATES = FIXTURE_ROOT.parent / "templates"


@pytest.fixture()
def linux_root(tmp_path: Path) -> Path:
    root = tmp_path / "linux-root"
    shutil.copytree(FIXTURE_ROOT, root)
    auth_log = root / "var" / "log" / "auth.log"
    nginx_log = root / "var" / "log" / "nginx" / "access.log"
    auth_log.parent.mkdir(parents=True, exist_ok=True)
    nginx_log.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURE_TEMPLATES / "auth-log.txt", auth_log)
    shutil.copyfile(FIXTURE_TEMPLATES / "nginx-access.txt", nginx_log)
    return root


def _scope(
    root: Path,
    output: Path,
    *,
    checks: tuple[LinuxCheck, ...] = ALL_LINUX_CHECKS,
) -> LinuxCollectionScope:
    output.mkdir(parents=True, exist_ok=True)
    return LinuxCollectionScope(
        host_id="fixture-host",
        physical_root=root.absolute(),
        output_root=output.absolute(),
        allowed_checks=checks,
    )


def _request(
    name: str,
    *,
    checks: tuple[LinuxCheck, ...] = ALL_LINUX_CHECKS,
    max_bytes_per_file: int = 2 * 1024 * 1024,
) -> LinuxCollectionRequest:
    return LinuxCollectionRequest(
        host_id="fixture-host",
        checks=checks,
        bundle_name=name,
        max_bytes_per_file=max_bytes_per_file,
    )


def _rewrite_bundle(
    source: Path,
    destination: Path,
    change: Callable[[dict[str, bytes]], None],
) -> Path:
    with zipfile.ZipFile(source) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    change(members)
    with zipfile.ZipFile(destination, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            archive.writestr(name, members[name])
    return destination


def test_clean_collection_covers_every_domain_and_verifies(
    linux_root: Path, tmp_path: Path
) -> None:
    result = collect_linux_live_state(
        _scope(linux_root, tmp_path / "out"), _request("all-domains")
    )

    assert result.manifest.scope.host_id == "fixture-host"
    assert result.manifest.scope.command_execution is False
    assert result.manifest.scope.network_access is False
    assert result.manifest.scope.remote_access is False
    assert result.manifest.scope.tool_methods == ("filesystem-read", "procfs-read")
    assert set(result.manifest.scope.paths_by_check) == {check.value for check in ALL_LINUX_CHECKS}
    assert tuple(item.check for item in result.manifest.coverage) == tuple(
        sorted(ALL_LINUX_CHECKS, key=lambda check: check.value)
    )
    assert all(item.status == "success" for item in result.manifest.coverage)
    assert verify_linux_live_bundle(result.bundle_path).status == "valid"


def test_inventory_and_archive_are_deterministic(linux_root: Path, tmp_path: Path) -> None:
    scope = _scope(linux_root, tmp_path / "out")
    first = collect_linux_live_state(scope, _request("first"))
    second = collect_linux_live_state(scope, _request("second"))

    assert first.manifest.canonical_bytes() == second.manifest.canonical_bytes()
    assert first.bundle_path.read_bytes() == second.bundle_path.read_bytes()
    assert first.bundle_sha256 == second.bundle_sha256


def test_host_check_and_output_scope_are_enforced(linux_root: Path, tmp_path: Path) -> None:
    scope = _scope(
        linux_root,
        tmp_path / "out",
        checks=(LinuxCheck.JOURNAL_AUTH,),
    )
    with pytest.raises(LinuxLiveCollectionError, match="host scope mismatch"):
        collect_linux_live_state(
            scope,
            LinuxCollectionRequest(
                host_id="other-host",
                checks=(LinuxCheck.JOURNAL_AUTH,),
                bundle_name="denied-host",
            ),
        )
    with pytest.raises(LinuxLiveCollectionError, match="check scope denied"):
        collect_linux_live_state(scope, _request("denied-check", checks=(LinuxCheck.CRON_AT,)))
    with pytest.raises(ValidationError, match="bundle_name"):
        _request("../outside", checks=(LinuxCheck.JOURNAL_AUTH,))

    outside = tmp_path / "outside.mlive"
    outside.write_bytes(b"do not overwrite")
    (scope.output_root / "escaped.mlive").symlink_to(outside)
    with pytest.raises(LinuxLiveCollectionError, match="unsafe output scope"):
        collect_linux_live_state(scope, _request("escaped", checks=(LinuxCheck.JOURNAL_AUTH,)))
    assert outside.read_bytes() == b"do not overwrite"


def test_symlink_escape_is_not_followed_and_marks_partial(
    linux_root: Path, tmp_path: Path
) -> None:
    secret = tmp_path / "outside-secret"
    secret.write_text("must-not-be-collected", encoding="utf-8")
    escape = linux_root / "etc" / "cron.d" / "escape"
    escape.symlink_to("../../../outside-secret")

    result = collect_linux_live_state(
        _scope(linux_root, tmp_path / "out"),
        _request("symlink", checks=(LinuxCheck.CRON_AT,)),
    )
    coverage = result.manifest.coverage[0]
    assert coverage.status == "partial"
    assert coverage.tool_outcome().status is ToolOutcomeStatus.PARTIAL
    assert any("symlink target escapes" in error for error in coverage.errors)
    with zipfile.ZipFile(result.bundle_path) as archive:
        assert b"must-not-be-collected" not in b"".join(
            archive.read(name) for name in archive.namelist()
        )
    assert verify_linux_live_bundle(result.bundle_path).ok


def test_per_file_limit_is_precise_partial_coverage(linux_root: Path, tmp_path: Path) -> None:
    result = collect_linux_live_state(
        _scope(linux_root, tmp_path / "out"),
        _request("bounded", checks=(LinuxCheck.JOURNAL_AUTH,), max_bytes_per_file=8),
    )
    coverage = result.manifest.coverage[0]

    assert coverage.status == "partial"
    assert coverage.files_examined == coverage.files_discovered == 1
    assert coverage.bytes_examined == 8
    assert coverage.bytes_discovered > coverage.bytes_examined
    assert coverage.omitted_files == 1
    assert coverage.tool_outcome().coverage.truncation_reason is not None


def test_empty_and_failed_are_distinct_coverage_states(tmp_path: Path) -> None:
    empty_root = tmp_path / "empty-root"
    empty_root.mkdir()
    empty = collect_linux_live_state(
        _scope(empty_root, tmp_path / "empty-out"),
        _request("empty", checks=(LinuxCheck.JOURNAL_AUTH,)),
    ).manifest.coverage[0]
    assert empty.status == "empty"
    assert empty.tool_outcome().status is ToolOutcomeStatus.SUCCESS_EMPTY

    failed_root = tmp_path / "failed-root"
    cron = failed_root / "etc" / "cron.d"
    cron.mkdir(parents=True)
    (tmp_path / "outside").write_text("outside", encoding="utf-8")
    (cron / "escape").symlink_to("../../../outside")
    failed = collect_linux_live_state(
        _scope(failed_root, tmp_path / "failed-out"),
        _request("failed", checks=(LinuxCheck.CRON_AT,)),
    ).manifest.coverage[0]
    assert failed.status == "failed"
    assert failed.tool_outcome().status is ToolOutcomeStatus.FAILED
    assert failed.tool_outcome().coverage.bytes_total is None


@pytest.mark.parametrize("mutation", ["same_size", "missing"])
def test_artifact_mutation_or_removal_breaks_seal_verification(
    linux_root: Path, tmp_path: Path, mutation: str
) -> None:
    result = collect_linux_live_state(
        _scope(linux_root, tmp_path / "out"),
        _request("original", checks=(LinuxCheck.JOURNAL_AUTH,)),
    )
    source_name = next(
        item.bundle_path for item in result.manifest.artifacts if item.artifact_type == "source"
    )

    def change(members: dict[str, bytes]) -> None:
        if mutation == "missing":
            members.pop(source_name)
        else:
            original = members[source_name]
            members[source_name] = bytes([original[0] ^ 1]) + original[1:]

    tampered = _rewrite_bundle(result.bundle_path, tmp_path / f"{mutation}.mlive", change)
    verification = verify_linux_live_bundle(tampered)

    assert verification.status == "invalid"
    expected_code = "artifact_missing" if mutation == "missing" else "artifact_digest_mismatch"
    assert expected_code in {diagnostic.code for diagnostic in verification.diagnostics}


def test_changed_manifest_and_unsupported_schema_are_distinct(
    linux_root: Path, tmp_path: Path
) -> None:
    result = collect_linux_live_state(
        _scope(linux_root, tmp_path / "out"),
        _request("original", checks=(LinuxCheck.CRON_AT,)),
    )

    def change_scope(members: dict[str, bytes]) -> None:
        manifest = json.loads(members["manifest.json"])
        manifest["scope"]["host_id"] = "changed-host"
        members["manifest.json"] = json.dumps(manifest).encode()

    changed = _rewrite_bundle(result.bundle_path, tmp_path / "changed.mlive", change_scope)
    changed_result = verify_linux_live_bundle(changed)
    assert changed_result.status == "invalid"
    assert "seal_mismatch" in {item.code for item in changed_result.diagnostics}

    def change_version(members: dict[str, bytes]) -> None:
        manifest = json.loads(members["manifest.json"])
        manifest["schema_version"] = 99
        members["manifest.json"] = json.dumps(manifest).encode()

    unsupported = _rewrite_bundle(
        result.bundle_path, tmp_path / "unsupported.mlive", change_version
    )
    assert verify_linux_live_bundle(unsupported).status == "unsupported"


def test_collector_has_no_arbitrary_command_or_remote_primitive() -> None:
    from mulder.server.app import _tool_dispatch_sync

    endpoint = _tool_dispatch_sync["collect_linux_live_state_bundle"]
    parameters = inspect.signature(endpoint).parameters
    forbidden = {"command", "shell", "ssh", "hostname", "input_path", "output_path"}

    assert forbidden.isdisjoint(parameters)
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxCollectionRequest.model_validate(
            {
                "host_id": "fixture-host",
                "checks": ["journal_auth"],
                "bundle_name": "safe",
                "command": "id",
            }
        )


def test_endpoint_persists_each_check_in_case_coverage(
    linux_root: Path,
    tmp_path: Path,
    tmp_case_db: CaseDB,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mulder.server.app import _tool_dispatch_sync
    from mulder.server.tools import linux_live as endpoint_module

    fixture_result = collect_linux_live_state(
        _scope(linux_root, tmp_path / "fixture-out"),
        _request(
            "endpoint-fixture",
            checks=(LinuxCheck.JOURNAL_AUTH, LinuxCheck.CRON_AT),
        ),
    )
    monkeypatch.setattr(endpoint_module, "get_ctx", lambda: SimpleNamespace(db=tmp_case_db))
    monkeypatch.setattr(
        endpoint_module, "get_cfg", lambda: SimpleNamespace(db_dir=tmp_path / "cases")
    )
    monkeypatch.setattr(
        endpoint_module,
        "collect_linux_live_state",
        lambda _scope, _request: fixture_result,
    )
    endpoint = _tool_dispatch_sync["collect_linux_live_state_bundle"]

    response = endpoint(
        host_id=socket.gethostname(),
        checks=["journal_auth", "cron_at"],
        bundle_name="endpoint",
    )
    records = tmp_case_db.get_coverage(system_name=socket.gethostname())

    assert response["status"] == "success"
    assert {record.key.check_name for record in records} == {"journal_auth", "cron_at"}
    assert all(record.key.evidence_domain == "linux_live" for record in records)


def test_pack_descriptor_is_stable_and_declares_complete_workflow() -> None:
    first = linux_live_pack_descriptor()
    second = linux_live_pack_descriptor()

    assert first == second
    assert first["schema"] == "mulder.domain-pack"
    assert first["support_version"] == "1.0"
    assert first["pack_id"] == "linux.live-state"
    hunts = {item["hunt_id"] for item in first["hunts"]}
    assert hunts == {check.value for check in ALL_LINUX_CHECKS}
    assert first["required_capabilities"] == ["forensic.local-live-read"]
    fixture = first["fixtures"][0]
    fixture_path = linux_live_pack_fixture_root() / fixture["path"]
    assert fixture_path.stat().st_size == fixture["size_bytes"]
    assert hashlib.sha256(fixture_path.read_bytes()).hexdigest() == fixture["sha256"]


def test_offline_verifier_cli_reports_valid_bundle(linux_root: Path, tmp_path: Path) -> None:
    result = collect_linux_live_state(
        _scope(linux_root, tmp_path / "out"),
        _request("cli", checks=(LinuxCheck.CONTAINER_KUBERNETES,)),
    )
    invoked = CliRunner().invoke(cli, ["verify-linux-live", str(result.bundle_path), "--json"])

    assert invoked.exit_code == 0
    payload: dict[str, Any] = json.loads(invoked.output)
    assert payload["status"] == "valid"
    assert payload["host_id"] == "fixture-host"
