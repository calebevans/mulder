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
from mulder.server.tools.workflowaudit import _secrets_used, _workflow_files, run_workflow_audit

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


def _audit(
    target: Path,
    findings: dict[str, list[Any]] | None = None,
    fail: dict[str, str] | None = None,
) -> tuple[Any, list[list[str]]]:
    """Run the tool with zizmor replaced; return (response, one argv per run).

    *findings* maps a file name to what zizmor prints for it; *fail* maps a
    file name to the stderr of a run that exits 3.
    """
    runs: list[list[str]] = []

    def _zizmor(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        runs.append(cmd)
        assert not any(k.upper().startswith("ZIZMOR_") for k in kwargs["env"])
        name = Path(cmd[-1]).name
        if fail and name in fail:
            return subprocess.CompletedProcess(
                args=cmd, returncode=3, stdout="", stderr=fail[name]
            )
        out = json.dumps((findings or {}).get(name, []))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=out, stderr="")

    with (
        patch.object(workflowaudit, "require_binary", return_value="/usr/bin/zizmor"),
        patch("mulder.server.tools.workflowaudit.subprocess.run", side_effect=_zizmor),
        patch.dict("os.environ", {"ZIZMOR_CONFIG": "/evil.yml"}),
    ):
        return run_workflow_audit.__wrapped__(str(target)), runs  # type: ignore[attr-defined]


def _text(db: CaseDB, source: str) -> list[str]:
    return "".join(w.raw_text for w in db.get_windows_by_source(source)).splitlines()


def test_findings_are_indexed_most_severe_first_with_one_based_lines(
    case: CaseDB, repo: Path
) -> None:
    release = repo / ".github" / "workflows" / "release.yml"
    findings = {
        "release.yml": [
            _finding("excessive-permissions", "Medium", release, 4),
            _finding("template-injection", "High", release, 7, ignored=True),
        ]
    }

    result, _runs = _audit(repo, findings)

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


def test_each_workflow_is_audited_on_its_own_offline_and_deaf_to_the_evidence(
    case: CaseDB, repo: Path
) -> None:
    """Verified against zizmor 1.32.0: given a directory it stops at the first
    .git and honours .gitignore, so a tree can hide its own workflows; a
    zizmor.yml or ZIZMOR_CONFIG can disable any audit."""
    _result, runs = _audit(repo)

    workflows = repo / ".github" / "workflows"
    assert [run[-1] for run in runs] == [
        str((workflows / "lint.yaml").resolve()),
        str((workflows / "release.yml").resolve()),
    ]
    for run in runs:
        for flag in ("--offline", "--no-config", "--no-ignores", "--no-exit-codes"):
            assert flag in run
        assert run[-2] == "--", "a path beginning with '-' must not be read as an option"


def test_nested_checkouts_are_all_audited(case: CaseDB, tmp_path: Path) -> None:
    """A .git and a harmless workflow at the top hid every checkout beneath."""
    home = tmp_path / "home"
    for where in (home, home / "proj", home / "proj" / "vendor" / "dep"):
        (where / ".git").mkdir(parents=True)
        (where / ".github" / "workflows").mkdir(parents=True)
        (where / ".github" / "workflows" / "ci.yml").write_text(_WORKFLOW)
    (home / "proj" / ".github" / "actions" / "setup").mkdir(parents=True)
    (home / "proj" / ".github" / "actions" / "setup" / "action.yml").write_text("runs: {}\n")
    (home / "proj" / "k8s").mkdir()
    (home / "proj" / "k8s" / "deploy.yaml").write_text("kind: Deployment\n")

    result, runs = _audit(home)

    assert result["results"]["workflows_audited"] == 4
    audited = sorted(str(Path(run[-1]).relative_to(home.resolve())) for run in runs)
    assert audited == [
        ".github/workflows/ci.yml",
        "proj/.github/actions/setup/action.yml",
        "proj/.github/workflows/ci.yml",
        "proj/vendor/dep/.github/workflows/ci.yml",
    ]


def test_a_file_zizmor_cannot_audit_is_reported_and_costs_only_itself(
    case: CaseDB, repo: Path
) -> None:
    """A syntax error, a byte-order mark or a non-UTF-8 file used to be dropped
    in silence and still counted as audited, or to abort the whole audit."""
    workflows = repo / ".github" / "workflows"
    release = workflows / "release.yml"
    (workflows / "broken.yml").write_text("on: [push\n")
    (workflows / "pipe.yml").symlink_to("/etc/hosts")

    result, runs = _audit(
        repo,
        {"release.yml": [_finding("template-injection", "High", release, 7)]},
        fail={"broken.yml": " INFO zizmor\n WARN failed to parse input: did not find ']'\n"},
    )

    summary = result["results"]
    assert summary["workflows_audited"] == 2  # lint.yaml and release.yml
    assert summary["total_findings"] == 1
    assert summary["not_audited_count"] == 2
    assert "failed to parse input" in summary["not_audited"][str(workflows / "broken.yml")]
    assert summary["not_audited"][str(workflows / "pipe.yml")] == "symlink, not followed"
    assert not any(run[-1].endswith("pipe.yml") for run in runs)
    assert "workflow.not_audited" in summary["sources"]
    gaps = _text(case, "workflow.not_audited")
    assert f"symlink, not followed\t{workflows / 'pipe.yml'}" in gaps


def test_no_file_audited_is_an_error_not_a_clean_audit(case: CaseDB, repo: Path) -> None:
    result, _ = _audit(repo, fail={"release.yml": "error: x", "lint.yaml": "error: x"})

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert _text(case, "workflow.findings") == []


def test_a_slow_file_times_out_alone(case: CaseDB, repo: Path) -> None:
    def _zizmor(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if cmd[-1].endswith("release.yml"):
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

    with (
        patch.object(workflowaudit, "require_binary", return_value="/usr/bin/zizmor"),
        patch("mulder.server.tools.workflowaudit.subprocess.run", side_effect=_zizmor),
    ):
        result = run_workflow_audit.__wrapped__(str(repo))  # type: ignore[attr-defined]

    summary = result["results"]
    assert summary["workflows_audited"] == 1
    (reason,) = summary["not_audited"].values()
    assert "did not finish within 60s" in reason


def test_the_secrets_each_workflow_refers_to_are_mapped(case: CaseDB, repo: Path) -> None:
    workflows = repo / ".github" / "workflows"
    (workflows / "deploy.yml").write_text(
        "jobs:\n  call:\n    uses: ./x.yml\n    secrets: inherit\n"
    )

    result, _runs = _audit(repo)

    assert result["results"]["workflows_audited"] == 3
    # Only workflows that touch a secret are returned; all three are indexed.
    assert result["results"]["secrets_by_workflow"] == {
        str(workflows / "deploy.yml"): ["(all, via secrets: inherit)"],
        str(workflows / "release.yml"): ["GCP_SA_KEY", "PYPI_TOKEN"],
    }
    lines = _text(case, "workflow.secrets")
    assert f"{workflows / 'release.yml'}\tGCP_SA_KEY, PYPI_TOKEN" in lines
    assert f"{workflows / 'lint.yaml'}\t(none)" in lines


def test_the_secrets_map_sees_every_way_of_naming_a_secret(tmp_path: Path) -> None:
    def used(text: str) -> list[str]:
        file = tmp_path / "w.yml"
        file.write_text(text)
        return _secrets_used(file)

    everything = "(all, via toJSON(secrets) or a computed name)"
    assert used("run: echo '${{ toJSON(secrets) }}'") == [everything]
    assert used("x: ${{ secrets[format('{0}_KEY', matrix.env)] }}") == [everything]
    assert used("x: ${{ secrets['A_B'] }} ${{ secrets[\"C\"] }} ${{ SECRETS.D }}") == [
        "A_B",
        "C",
        "D",
    ]
    # A property called "secrets" on something else is not the secrets context.
    assert used("x: ${{ steps.vault.outputs.secrets }} ${{ my.secrets.NOT_REAL }}") == []
    assert used("\ufeffx: ${{ secrets.BOM }}") == ["BOM"]

    big = tmp_path / "big.yml"
    big.write_text("x: ${{ secrets.HIDDEN }}\n" + "# pad\n" * 200_000)
    assert _secrets_used(big) == ["(not read: file larger than 1 MiB)"]


def test_a_file_name_cannot_forge_a_line_in_the_secrets_map(case: CaseDB, repo: Path) -> None:
    workflows = repo / ".github" / "workflows"
    (workflows / "evil\nhigh\tforged\tx.yml").write_text(_WORKFLOW)

    _audit(repo)

    lines = _text(case, "workflow.secrets")
    assert len(lines) == 1 + 3, "the header and one line per workflow"
    assert all(line.count("\t") == 1 for line in lines[1:])


def test_exported_workflow_files_outside_a_repository_layout_are_audited(
    case: CaseDB, tmp_path: Path
) -> None:
    """Only the directory's own YAML: a tree of unrelated YAML is not workflows."""
    export = tmp_path / "workflows-export"
    (export / "charts").mkdir(parents=True)
    (export / "a.yml").write_text(_WORKFLOW)
    (export / "b.yaml").write_text(_WORKFLOW)
    (export / "README.md").write_text("notes")
    (export / "charts" / "values.yaml").write_text("replicas: 1\n")

    _result, runs = _audit(export)

    assert [Path(run[-1]).name for run in runs] == ["a.yml", "b.yaml"]


def test_only_workflow_folders_count_inside_a_repository(repo: Path) -> None:
    files, left_out = _workflow_files(repo)

    assert [f.name for f in files] == ["lint.yaml", "release.yml"]
    assert left_out == {}


def test_a_path_without_workflows_and_a_missing_binary_are_errors(
    case: CaseDB, tmp_path: Path, repo: Path
) -> None:
    (tmp_path / "docs").mkdir()
    none, _ = _audit(tmp_path / "docs")
    assert none["error_type"] == "no_data"

    with patch.object(workflowaudit, "require_binary", return_value=None):
        missing = run_workflow_audit.__wrapped__(str(repo), force=True)  # type: ignore[attr-defined]
    assert missing["error_type"] == "binary_missing"
    assert "mulder setup" in str(missing["suggestion"])
