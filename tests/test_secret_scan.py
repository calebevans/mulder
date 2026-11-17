"""run_secret_scan: gitleaks findings are indexed, redacted, and cannot be switched off."""

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
from mulder.server.tools import secretscan
from mulder.server.tools.secretscan import run_secret_scan


@pytest.fixture
def case(tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    return tmp_case_db


@pytest.fixture
def logs(tmp_path: Path) -> Path:
    root = tmp_path / "run-logs"
    root.mkdir()
    (root / "3_build.txt").write_text(
        "2026-11-10T12:00:01.1234567Z ##[group]Run ./publish.sh\n"
        "2026-11-10T12:00:02.1234567Z export AWS_ACCESS_KEY_ID=...\n"
    )
    (root / "notes.txt").write_text("password = ...\n")
    return root


def _scan(target: Path, findings: object, returncode: int = 0) -> tuple[Any, list[str]]:
    """Run the tool with gitleaks replaced; return (response, the argv it was given).

    The fake reports files under the path it was asked to scan, as gitleaks does.
    """
    argv: list[str] = []

    def _gitleaks(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        argv.extend(cmd)
        report = next(a for a in cmd if a.startswith("--report-path=")).split("=", 1)[1]
        text = json.dumps(findings).replace("{SCAN}", cmd[2])
        Path(report).write_text(text)
        return subprocess.CompletedProcess(args=cmd, returncode=returncode, stdout="", stderr="x")

    with (
        patch.object(secretscan, "require_binary", return_value="/usr/bin/gitleaks"),
        patch.object(secretscan, "run_subprocess", side_effect=_gitleaks),
    ):
        return run_secret_scan.__wrapped__(str(target)), argv  # type: ignore[attr-defined]


def _finding(file: str, line: int, rule: str = "aws-access-token") -> dict[str, Any]:
    return {
        "RuleID": rule,
        "Description": "Identified a pattern\tthat may indicate credentials",
        "StartLine": line,
        "Secret": "AKIA...",
        "File": file,
    }


def test_findings_are_indexed_with_the_log_time_and_the_real_path(
    case: CaseDB, logs: Path
) -> None:
    findings = [
        _finding("{SCAN}3_build.txt", 2),
        _finding("{SCAN}notes.txt", 1, "generic-api-key"),
    ]

    result, _argv = _scan(logs, findings)

    summary = result["results"]
    assert summary["total_findings"] == 2
    assert summary["by_rule"] == {"aws-access-token": 1, "generic-api-key": 1}
    # Files are reported where they are, not under the temporary scan link.
    assert summary["by_file"] == {str(logs / "3_build.txt"): 1, str(logs / "notes.txt"): 1}

    text = "".join(w.raw_text for w in case.get_windows_by_source("secrets.findings"))
    lines = text.splitlines()
    assert lines[0].endswith("2 findings")
    # The undated finding sorts first; the dated one carries its log line's time.
    assert lines[1].startswith(f"-\tgeneric-api-key\t{logs / 'notes.txt'}:1\tAKIA...\t")
    assert lines[2].startswith(
        f"2026-11-10T12:00:02\taws-access-token\t{logs / '3_build.txt'}:2\tAKIA...\t"
    )
    assert all(line.count("\t") == 4 for line in lines[1:]), "a tab in a field split a record"


def test_evidence_cannot_switch_the_scan_off(case: CaseDB, logs: Path) -> None:
    """The flags and the scan path that neutralise planted suppression.

    Verified against gitleaks 8.30.1: it always loads ``<scanned dir>/.gitleaksignore``,
    whose entries match only the exact path the scan reports, and without
    ``--config`` it loads ``<scanned dir>/.gitleaks.toml``.
    """
    _result, argv = _scan(logs, [])

    assert argv[1] == "dir"
    assert "--ignore-gitleaks-allow" in argv
    config = next(a for a in argv if a.startswith("--config=")).split("=", 1)[1]
    ignore = next(a for a in argv if a.startswith("--gitleaks-ignore-path=")).split("=", 1)[1]
    assert not Path(config).is_relative_to(logs)
    assert not Path(ignore).is_relative_to(logs)
    # Scanned through a link outside the evidence, so no ignore entry can name it.
    assert argv[2].endswith("/evidence/")
    assert not Path(argv[2]).is_relative_to(logs)


def test_secrets_are_redacted_and_leaks_do_not_fail_the_run(case: CaseDB, logs: Path) -> None:
    _result, argv = _scan(logs, [])

    assert "--redact=80" in argv
    assert "--exit-code=0" in argv


def test_a_clean_scan_is_a_success_and_a_second_run_is_skipped(case: CaseDB, logs: Path) -> None:
    first, _ = _scan(logs, [])
    second, _ = _scan(logs, [])

    assert first["results"]["total_findings"] == 0
    assert second["results"]["status"] == "skipped"


def test_a_single_file_is_scanned_in_place(case: CaseDB, logs: Path) -> None:
    file = logs / "3_build.txt"

    result, argv = _scan(file, [_finding(str(file), 2)])

    assert argv[2] == str(file.resolve())
    assert result["results"]["by_file"] == {str(file): 1}


@pytest.mark.parametrize(("findings", "returncode"), [({"not": "a list"}, 0), ([], 1)])
def test_a_failed_gitleaks_run_is_an_error_not_a_clean_scan(
    case: CaseDB, logs: Path, findings: object, returncode: int
) -> None:
    result, _ = _scan(logs, findings, returncode)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert case.get_windows_by_source("secrets.findings") == []


def test_missing_gitleaks_points_at_setup(case: CaseDB, logs: Path) -> None:
    with patch.object(secretscan, "require_binary", return_value=None):
        result = run_secret_scan.__wrapped__(str(logs))  # type: ignore[attr-defined]

    assert result["error_type"] == "binary_missing"
    assert "mulder setup" in str(result["suggestion"])
