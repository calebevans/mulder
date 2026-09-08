"""A failed Chainsaw run must not be reported as a clean, zero-finding scan.

All four Chainsaw runners -- hunt, search, srum and timeline -- called
``subprocess.run(...)`` and returned only the output path, discarding the exit
code. When Chainsaw failed it wrote no results file, and every
``_parse_chainsaw_*_results`` answers a missing file with an empty result dict.
``run_chainsaw`` then reported ``status: success`` with ``Total findings: 0``:
a Sigma hunt that never executed looked exactly like a clean host.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.chainsaw import run_chainsaw

_MODES = ["hunt", "search", "srum", "timeline"]


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    """An evidence directory holding one EVTX file, so the run reaches Chainsaw."""
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"ElfFile\x00")
    return tmp_path


def _invoke(evidence: Path, mode: str, run: Any, rules: Path) -> tuple[Any, list[str]]:
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {}

    kwargs = {"side_effect": run} if callable(run) else {"return_value": run}
    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.subprocess.run", **kwargs),
        patch("mulder.server.tools.chainsaw.extract_and_index", side_effect=_record),
    ):
        result = run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
            str(evidence),
            mode=mode,
            sigma_rules_path=str(rules),
            search_term="powershell",
        )
    return result, indexed


@pytest.mark.parametrize("mode", _MODES)
def test_a_failed_run_is_an_error_not_an_empty_hunt(
    mode: str, evidence: Path, tmp_path: Path
) -> None:
    """Every mode: Chainsaw exits non-zero and writes nothing."""
    rules = tmp_path / "rules"
    rules.mkdir()
    proc = subprocess.CompletedProcess(
        args=["chainsaw", mode],
        returncode=2,
        stdout="",
        stderr="error: the following required arguments were not provided: --mapping",
    )

    result, _indexed = _invoke(evidence, mode, proc, rules)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert mode in message
    assert "exited 2" in message
    assert "--mapping" in message


@pytest.mark.parametrize("mode", _MODES)
def test_a_failed_run_never_reports_a_finding_count(
    mode: str, evidence: Path, tmp_path: Path
) -> None:
    """The summary line 'Total findings: 0' must not be written to the case."""
    rules = tmp_path / "rules"
    rules.mkdir()
    proc = subprocess.CompletedProcess(
        args=["chainsaw", mode], returncode=2, stdout="", stderr="boom"
    )

    _result, indexed = _invoke(evidence, mode, proc, rules)

    assert indexed == [], f"a failed {mode} run was summarised into the case: {indexed}"


@pytest.mark.parametrize("mode", _MODES)
def test_a_genuinely_quiet_host_is_still_a_success(
    mode: str, evidence: Path, tmp_path: Path
) -> None:
    """Pins the fix's narrowness: exit 0 with no results file stays a success.

    Chainsaw exits 0 and writes nothing when no rule matched. That is a real
    answer, not a failure, and must keep reporting as one.
    """
    rules = tmp_path / "rules"
    rules.mkdir()
    proc = subprocess.CompletedProcess(args=["chainsaw", mode], returncode=0, stdout="", stderr="")

    result, indexed = _invoke(evidence, mode, proc, rules)

    assert result["status"] == "success"
    assert indexed, "a successful quiet run must still be summarised"


@pytest.mark.parametrize("mode", _MODES)
def test_findings_written_before_a_non_zero_exit_are_kept(
    mode: str, evidence: Path, tmp_path: Path
) -> None:
    """Chainsaw exits non-zero on one unreadable EVTX after matching others.

    The guard is conjunctive -- non-zero *and* no results file -- so real
    detections are never discarded because one input was corrupt.
    """
    rules = tmp_path / "rules"
    rules.mkdir()
    written: list[Path] = []

    def _write_results(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        outfile = Path(cmd[cmd.index("--output") + 1])
        outfile.write_text(json.dumps([]))
        written.append(outfile)
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr="failed to parse one file"
        )

    result, indexed = _invoke(evidence, mode, _write_results, rules)

    assert written, "the fake Chainsaw never wrote its output file"
    assert result["status"] == "success"
    assert indexed
