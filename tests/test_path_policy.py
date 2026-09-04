"""Adversarial tests for resolved filesystem path containment."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from mulder.path_policy import PathPolicyError, resolve_allowed_path


def test_allows_root_and_nested_file(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    nested = evidence_root / "host" / "logs" / "security.evtx"
    nested.parent.mkdir(parents=True)
    nested.touch()

    assert resolve_allowed_path(evidence_root, [evidence_root]) == evidence_root.resolve()
    assert resolve_allowed_path(nested, [evidence_root]) == nested.resolve()


def test_rejects_sibling_with_same_string_prefix(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    sibling = tmp_path / "evidence-other" / "secrets.txt"
    evidence_root.mkdir()
    sibling.parent.mkdir()
    sibling.touch()

    with pytest.raises(PathPolicyError, match="outside allowed directories"):
        resolve_allowed_path(sibling, [evidence_root])


def test_dotdot_is_checked_after_resolution(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    inside = evidence_root / "host" / ".." / "timeline.csv"
    outside = evidence_root / ".." / "outside.txt"

    assert resolve_allowed_path(inside, [evidence_root]) == (evidence_root / "timeline.csv")
    with pytest.raises(PathPolicyError, match="outside allowed directories"):
        resolve_allowed_path(outside, [evidence_root])


def test_rejects_existing_symlink_escape(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    outside_root = tmp_path / "outside"
    evidence_root.mkdir()
    outside_root.mkdir()
    secret = outside_root / "secret.txt"
    secret.touch()
    escape = evidence_root / "escape"
    escape.symlink_to(outside_root, target_is_directory=True)

    with pytest.raises(PathPolicyError, match="outside allowed directories"):
        resolve_allowed_path(escape / "secret.txt", [evidence_root])


def test_allows_symlink_whose_destination_is_inside_root(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    real_dir = evidence_root / "real"
    real_dir.mkdir(parents=True)
    artifact = real_dir / "artifact.txt"
    artifact.touch()
    link = evidence_root / "link"
    link.symlink_to(real_dir, target_is_directory=True)

    assert resolve_allowed_path(link / "artifact.txt", [evidence_root]) == artifact.resolve()


def test_nonexistent_descendant_is_provisionally_allowed(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    missing = evidence_root / "not-created" / "artifact.txt"

    assert not missing.exists()
    assert resolve_allowed_path(missing, [evidence_root]) == missing.resolve(strict=False)


def test_dangling_symlink_is_checked_by_destination(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    dangling_escape = evidence_root / "dangling"
    dangling_escape.symlink_to(tmp_path / "outside" / "missing.txt")

    with pytest.raises(PathPolicyError, match="outside allowed directories"):
        resolve_allowed_path(dangling_escape, [evidence_root])


def test_accepts_evidence_and_case_roots_but_not_common_parent(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    case_root = tmp_path / "cases"
    evidence_file = evidence_root / "image.E01"
    case_file = case_root / "case.sqlite3"
    unrelated = tmp_path / "other.txt"
    evidence_root.mkdir()
    case_root.mkdir()
    evidence_file.touch()
    case_file.touch()
    unrelated.touch()
    roots = [evidence_root, case_root]

    assert resolve_allowed_path(evidence_file, roots) == evidence_file.resolve()
    assert resolve_allowed_path(case_file, roots) == case_file.resolve()
    with pytest.raises(PathPolicyError, match="outside allowed directories"):
        resolve_allowed_path(unrelated, roots)


def test_artifact_adapter_uses_configured_evidence_and_case_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mulder.server.tools import artifacts

    evidence_root = tmp_path / "evidence"
    case_root = tmp_path / "cases"
    evidence_root.mkdir()
    case_root.mkdir()
    evidence_file = evidence_root / "artifact.txt"
    case_file = case_root / "case.sqlite3"
    evidence_file.touch()
    case_file.touch()

    metadata = SimpleNamespace(evidence_root=str(evidence_root))
    db = SimpleNamespace(get_case_metadata=lambda: metadata)
    monkeypatch.setattr(artifacts, "get_cfg", lambda: SimpleNamespace(db_dir=case_root))
    monkeypatch.setattr(artifacts, "get_ctx", lambda: SimpleNamespace(db=db))

    assert artifacts._resolve_artifact_path(evidence_file) == evidence_file.resolve()
    assert artifacts._resolve_artifact_path(case_file) == case_file.resolve()


def test_file_root_does_not_authorize_sibling_prefix(tmp_path: Path) -> None:
    evidence_image = tmp_path / "image.E01"
    sibling = tmp_path / "image.E01.backup"
    evidence_image.touch()
    sibling.touch()

    assert resolve_allowed_path(evidence_image, [evidence_image]) == evidence_image.resolve()
    with pytest.raises(PathPolicyError, match="outside allowed directories"):
        resolve_allowed_path(sibling, [evidence_image])


def test_symlink_loop_fails_closed(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    loop = evidence_root / "loop"
    loop.symlink_to(loop)

    with pytest.raises(PathPolicyError, match="Cannot resolve path"):
        resolve_allowed_path(loop, [evidence_root])
