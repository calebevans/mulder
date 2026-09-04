"""Deterministic offline release-metadata generation and verification tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mulder.cli import cli
from mulder.supply_chain import (
    ReleaseMetadataRequest,
    SupplyChainError,
    generate_release_metadata,
    verify_release_metadata,
)


def _release_tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "release"
    dist = root / "dist"
    dist.mkdir(parents=True)
    lock = root / "uv.lock"
    lock.write_text(
        "version = 1\n\n"
        "[[package]]\n"
        'name = "mulder-dfir"\n'
        'source = { editable = "." }\n\n'
        "[[package]]\n"
        'name = "example-dependency"\n'
        'version = "2.3.4"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        'sdist = { url = "https://example.invalid/pkg.tar.gz", size = 12 }\n'
        "wheels = [\n"
        '    { url = "https://example.invalid/pkg.whl", '
        'hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", '
        "size = 12 },\n"
        "]\n",
        encoding="utf-8",
    )
    artifact = dist / "mulder-1.0.0-py3-none-any.whl"
    artifact.write_bytes(b"deterministic wheel bytes")
    return root, lock, artifact


def _request(root: Path, lock: Path, artifact: Path, output: Path) -> ReleaseMetadataRequest:
    return ReleaseMetadataRequest(
        project_root=root,
        artifact_paths=(artifact,),
        output_path=output,
        project_name="mulder-dfir",
        project_version="1.0.0",
        source_revision="abc123",
        source_date_epoch=1_700_000_000,
        builder_id="https://github.com/example/mulder/actions/release",
        invocation={"command": "uv build", "runner": "ubuntu-latest"},
        dependency_lock_path=lock,
    )


def test_release_metadata_is_deterministic_and_verifies_offline(tmp_path: Path) -> None:
    root, lock, artifact = _release_tree(tmp_path)
    first_path = root / "first.json"
    second_path = root / "second.json"

    first = generate_release_metadata(_request(root, lock, artifact, first_path))
    second = generate_release_metadata(_request(root, lock, artifact, second_path))

    assert first == second
    assert first_path.read_bytes() == second_path.read_bytes()
    assert first.sbom.components[0].name == "example-dependency"
    assert first.sbom.components[0].sha256 == "sha256:" + "a" * 64
    result = verify_release_metadata(first_path, root)
    assert result.ok
    assert result.artifacts_checked == 2


def test_verification_detects_artifact_and_document_drift(tmp_path: Path) -> None:
    root, lock, artifact = _release_tree(tmp_path)
    output = root / "release.json"
    generate_release_metadata(_request(root, lock, artifact, output))

    artifact.write_bytes(b"replacement")
    drift = verify_release_metadata(output, root)
    assert not drift.ok
    assert any("artifact drift" in diagnostic for diagnostic in drift.diagnostics)

    document = json.loads(output.read_text(encoding="utf-8"))
    document["provenance"]["source_revision"] = "different"
    output.write_text(json.dumps(document), encoding="utf-8")
    changed = verify_release_metadata(output, root)
    assert not changed.ok
    assert any("document digest" in diagnostic for diagnostic in changed.diagnostics)


def test_release_inputs_cannot_escape_or_cross_symlinks(tmp_path: Path) -> None:
    root, lock, artifact = _release_tree(tmp_path)
    outside = tmp_path / "outside.whl"
    outside.write_bytes(b"outside")

    with pytest.raises(SupplyChainError, match="escapes project root"):
        generate_release_metadata(_request(root, lock, outside, root / "escape.json"))

    link = root / "dist" / "link.whl"
    link.symlink_to(artifact)
    with pytest.raises(SupplyChainError, match="symlink"):
        generate_release_metadata(_request(root, lock, link, root / "link.json"))


def test_release_metadata_cli_generate_and_verify(tmp_path: Path) -> None:
    root, _lock, artifact = _release_tree(tmp_path)
    output = root / "release.json"
    runner = CliRunner()

    generated = runner.invoke(
        cli,
        [
            "release-metadata",
            "generate",
            "--project-root",
            str(root),
            "--artifact",
            str(artifact),
            "--output",
            str(output),
            "--source-revision",
            "abc123",
            "--source-date-epoch",
            "1700000000",
            "--builder-id",
            "test-builder",
        ],
    )
    verified = runner.invoke(
        cli,
        [
            "release-metadata",
            "verify",
            str(output),
            "--release-root",
            str(root),
            "--json",
        ],
    )

    assert generated.exit_code == 0, generated.output
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["status"] == "verified"
