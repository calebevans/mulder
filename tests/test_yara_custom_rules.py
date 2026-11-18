"""The investigator can supply their own YARA rules for every scan."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools import yara
from mulder.server.tools.yara import (
    _build_rules_args,
    _collect_custom_rules,
    _collect_rules_for_ruleset,
    yara_scan_files,
)

_RULE = 'rule mine { strings: $a = "x" condition: $a }\n'


@pytest.fixture
def rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A mounted rules directory, and a stand-in signature-base."""
    mounted = tmp_path / "rules"
    (mounted / "team" / "apt").mkdir(parents=True)
    (mounted / "a.yar").write_text(_RULE)
    (mounted / "team" / "apt" / "b.YARA").write_text(_RULE)
    (mounted / "README.md").write_text("not a rule")
    base = tmp_path / "signature-base" / "yara"
    base.mkdir(parents=True)
    (base / "stock.yar").write_text(_RULE)
    monkeypatch.setattr(yara, "_signature_base_dir", lambda: base.parent)
    monkeypatch.setenv(yara.ENV_YARA_RULES, str(mounted))
    return mounted


def test_rules_are_found_recursively_by_either_extension(rules: Path) -> None:
    assert _collect_custom_rules() == [
        str(rules / "a.yar"),
        str(rules / "team" / "apt" / "b.YARA"),
    ]


def test_several_files_and_directories_can_be_given(
    rules: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    single = tmp_path / "one-off.yar"
    single.write_text(_RULE)
    paths = [str(rules), str(single), str(tmp_path / "missing"), str(rules), ""]
    monkeypatch.setenv(yara.ENV_YARA_RULES, os.pathsep.join(paths))

    found = _collect_custom_rules()

    # A missing path is ignored, and a path given twice is not loaded twice.
    assert found == [
        str(rules / "a.yar"),
        str(rules / "team" / "apt" / "b.YARA"),
        str(single),
    ]


def test_without_the_setting_nothing_is_added(
    rules: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(yara.ENV_YARA_RULES)

    assert _collect_custom_rules() == []
    assert [Path(p).name for p in _collect_rules_for_ruleset("builtin")] == ["stock.yar"]


def test_default_scans_use_both_and_custom_uses_only_the_investigators(rules: Path) -> None:
    def names(ruleset: str) -> list[str]:
        return [Path(p).name for p in _collect_rules_for_ruleset(ruleset)]

    assert names("builtin") == ["stock.yar", "a.yar", "b.YARA"]
    assert names("standard") == names("full") == names("builtin")
    assert names("custom") == ["a.yar", "b.YARA"]


def test_the_scan_is_given_an_index_of_every_rule_file(rules: Path) -> None:
    """The existing validate-and-index path is what receives them."""
    with patch.object(yara, "_validate_rule_files", side_effect=lambda paths: paths):
        args, cleanup = _build_rules_args(None, ruleset="builtin")

    assert cleanup is True
    try:
        index = Path(args[0]).read_text()
    finally:
        Path(args[0]).unlink()
    assert index.count("include ") == 3
    assert f'include "{rules / "a.yar"}"' in index


def test_rule_files_in_the_evidence_are_never_loaded(rules: Path, tmp_path: Path) -> None:
    """Evidence is not a source of detection logic."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "planted.yar").write_text(_RULE)

    assert all("planted" not in path for path in _collect_rules_for_ruleset("builtin"))


def _scan(target: Path, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run yara_scan_files with yara itself stubbed; return (response, audit params)."""
    seen: dict[str, Any] = {}

    def _run(**call: Any) -> dict[str, object]:
        seen.update(call["audit_params"])
        return {"status": "success"}

    def _error(*args: Any) -> dict[str, object]:
        seen.update(args[3])
        return {"status": "error", "error": args[5]}

    with (
        patch.object(yara, "get_ctx", return_value=MagicMock()),
        patch("mulder.server.tools.yara.shutil.which", return_value="/usr/bin/yara"),
        patch.object(yara, "_update_community_rules"),
        patch.object(yara, "_validate_rule_files", side_effect=lambda paths: paths),
        patch.object(yara, "_run_yara_scan", side_effect=_run),
        patch.object(yara, "_yara_error", side_effect=_error),
    ):
        result = yara_scan_files.__wrapped__(str(target), **kwargs)  # type: ignore[attr-defined]
    return result, seen


def test_the_audit_log_records_how_many_custom_rule_files_a_scan_used(
    rules: Path, tmp_path: Path
) -> None:
    result, audit = _scan(tmp_path)

    assert result["status"] == "success"
    assert audit["custom_rule_files"] == 2

    _result, inline = _scan(tmp_path, rules=_RULE)
    assert inline["custom_rule_files"] == 0, "rules passed in the call replace the configured ones"


def test_asking_for_custom_rules_when_none_are_configured_says_how_to_supply_them(
    rules: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(yara.ENV_YARA_RULES)

    result, _ = _scan(tmp_path, ruleset="custom")

    assert result["status"] == "error"
    assert "MULDER_YARA_RULES" in result["error"]
    assert "/rules/yara" in result["error"]


def test_the_image_sets_the_mount_point_the_docs_and_the_error_name() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()

    assert "ENV MULDER_YARA_RULES=/rules/yara" in dockerfile
