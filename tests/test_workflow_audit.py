"""run_workflow_audit: findings and the secrets map are indexed; evidence cannot hide them."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server import app
from mulder.server.tools import workflowaudit
from mulder.server.tools.workflowaudit import _workflow_files, run_workflow_audit

_WORKFLOW = """\
on:
  workflow_dispatch:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "releasing ${{ inputs.tag }}"
      - run: ./publish.sh
        env:
          PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
          GCP_KEY: ${{ secrets.GCP_SA_KEY }}
"""


@pytest.fixture
def case(tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    return tmp_case_db


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    workflows = tmp_path / "repo" / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text(_WORKFLOW)
    (workflows / "lint.yaml").write_text("on: push\njobs: {}\n")
    (tmp_path / "repo" / "docker-compose.yml").write_text("services: {}\n")
    return tmp_path / "repo"


def _finding(ident: str, severity: str, file: Path, row: int, ignored: bool = False) -> Any:
    """One finding in the shape zizmor 1.32.0's ``--format=json`` writes."""
    return {
        "ident": ident,
        "desc": "code injection via template expansion",
        "determinations": {"confidence": "High", "severity": severity, "persona": "Regular"},
        "locations": [
            {
                "symbolic": {
                    "key": {"Local": {"verbatim_path": str(file)}},
                    "annotation": "this step",
                    "kind": "Related",
                },
                "concrete": {"location": {"start_point": {"row": 0, "column": 0}}, "feature": "x"},
            },
            {
                "symbolic": {
                    "key": {"Local": {"verbatim_path": str(file)}},
                    "annotation": "may expand into\tattacker-controllable code",
                    "kind": "Primary",
                },
                "concrete": {
                    "location": {"start_point": {"row": row, "column": 8}},
                    "feature": 'run: echo "releasing\n ${{ inputs.tag }}"',
                },
            },
        ],
        "ignored": ignored,
    }


def _audit(target: Path, findings: object, returncode: int = 0) -> tuple[Any, list[str]]:
    """Run the tool with zizmor replaced; return (response, the argv it was given)."""
    argv: list[str] = []

    def _zizmor(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        argv.extend(cmd)
        return subprocess.CompletedProcess(
            args=cmd, returncode=returncode, stdout=json.dumps(findings), stderr="no inputs"
        )

    with (
        patch.object(workflowaudit, "require_binary", return_value="/usr/bin/zizmor"),
        patch.object(workflowaudit, "run_subprocess", side_effect=_zizmor),
    ):
        return run_workflow_audit.__wrapped__(str(target)), argv  # type: ignore[attr-defined]


def _text(db: CaseDB, source: str) -> list[str]:
    return "".join(w.raw_text for w in db.get_windows_by_source(source)).splitlines()


def test_findings_are_indexed_most_severe_first_with_one_based_lines(
    case: CaseDB, repo: Path
) -> None:
    release = repo / ".github" / "workflows" / "release.yml"
    findings = [
        _finding("excessive-permissions", "Medium", release, 4),
        _finding("template-injection", "High", release, 7, ignored=True),
    ]

    result, _argv = _audit(repo, findings)

    summary = result["results"]
    assert summary["total_findings"] == 2
    assert summary["by_severity"] == {"medium": 1, "high": 1}
    assert summary["by_audit"] == {"excessive-permissions": 1, "template-injection": 1}
    assert summary["suppressed_in_source"] == 1

    lines = _text(case, "workflow.findings")
    assert lines[1].split("\t")[:5] == [
        "high",
        "confidence=high",
        "template-injection",
        f"{release}:8",  # zizmor rows are zero-based
        "may expand into attacker-controllable code",  # the primary location, on one line
    ]
    assert "suppressed-in-source" in lines[1]
    assert lines[2].startswith("medium\t")
    assert "suppressed-in-source" not in lines[2]
    assert all(line.count("\t") == 7 for line in lines[1:])


def test_the_secrets_each_workflow_refers_to_are_mapped(case: CaseDB, repo: Path) -> None:
    workflows = repo / ".github" / "workflows"
    (workflows / "deploy.yml").write_text(
        "jobs:\n  call:\n    uses: ./x.yml\n    secrets: inherit\n"
    )

    result, _argv = _audit(repo, [])

    assert result["results"]["workflows_audited"] == 3
    # Only workflows that touch a secret are returned; all three are indexed.
    assert result["results"]["secrets_by_workflow"] == {
        str(workflows / "deploy.yml"): ["(all, via secrets: inherit)"],
        str(workflows / "release.yml"): ["GCP_SA_KEY", "PYPI_TOKEN"],
    }
    lines = _text(case, "workflow.secrets")
    assert f"{workflows / 'release.yml'}\tGCP_SA_KEY, PYPI_TOKEN" in lines
    assert f"{workflows / 'lint.yaml'}\t(none)" in lines


def test_the_audit_is_offline_and_ignores_suppression_in_the_evidence(
    case: CaseDB, repo: Path
) -> None:
    """Verified against zizmor 1.32.0: a .gitignore listing .github/ leaves the
    default collection empty, and a zizmor.yml can disable any audit."""
    _result, argv = _audit(repo, [])

    for flag in ("--offline", "--no-config", "--no-ignores", "--collect=all", "--no-exit-codes"):
        assert flag in argv
    assert argv[-1] == str(repo)


def test_exported_workflow_files_outside_a_repository_layout_are_passed_one_by_one(
    case: CaseDB, tmp_path: Path
) -> None:
    """zizmor finds nothing in a directory that has no .github/workflows."""
    export = tmp_path / "workflows-export"
    export.mkdir()
    (export / "a.yml").write_text(_WORKFLOW)
    (export / "b.yaml").write_text(_WORKFLOW)
    (export / "README.md").write_text("notes")

    _result, argv = _audit(export, [])

    assert argv[-2:] == [str(export / "a.yml"), str(export / "b.yaml")]


def test_only_workflow_folders_count_inside_a_repository(repo: Path) -> None:
    files, is_repo = _workflow_files(repo)

    assert is_repo
    assert [f.name for f in files] == ["lint.yaml", "release.yml"]


@pytest.mark.parametrize(("findings", "returncode"), [({"not": "a list"}, 0), ([], 3)])
def test_a_failed_zizmor_run_is_an_error_not_a_clean_audit(
    case: CaseDB, repo: Path, findings: object, returncode: int
) -> None:
    result, _ = _audit(repo, findings, returncode)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert _text(case, "workflow.findings") == []


def test_a_path_without_workflows_and_a_missing_binary_are_errors(
    case: CaseDB, tmp_path: Path, repo: Path
) -> None:
    empty, _ = _audit(tmp_path / "repo" / ".github", [])  # has workflows below it: fine
    assert empty["status"] == "success"

    (tmp_path / "docs").mkdir()
    none, _ = _audit(tmp_path / "docs", [])
    assert none["error_type"] == "no_data"

    with patch.object(workflowaudit, "require_binary", return_value=None):
        missing = run_workflow_audit.__wrapped__(str(repo), force=True)  # type: ignore[attr-defined]
    assert missing["error_type"] == "binary_missing"
    assert "mulder setup" in str(missing["suggestion"])
