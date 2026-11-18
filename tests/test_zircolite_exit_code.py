"""Zircolite failures must not be reported as a clean, zero-detection scan.

``_run_zircolite_process`` discarded the ``CompletedProcess`` entirely, so a
Zircolite invocation that argparse rejected -- or that died on a malformed
ruleset -- left no results file, and ``_parse_zircolite_output`` answered that
with ``total_detections: 0``. The MCP client saw ``status: success`` and no
detections: indistinguishable from a log that genuinely matched no Sigma rule.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools.zircolite import run_zircolite


@pytest.fixture
def evidence(tmp_path: Path) -> dict[str, Path]:
    """A resolvable script, ruleset and events file, so the run reaches Zircolite."""
    script = tmp_path / "zircolite.py"
    script.write_text("")
    events = tmp_path / "audit.log"
    events.write_text("type=EXECVE msg=audit(1700000000.000:1): argc=1\n")
    ruleset = tmp_path / "rules"
    ruleset.mkdir()
    return {"script": script, "events": events, "ruleset": ruleset}


def _invoke(evidence: dict[str, Path], proc: subprocess.CompletedProcess[str]) -> Any:
    """Run ``run_zircolite`` with Zircolite itself replaced by *proc*."""
    with (
        patch("mulder.server.tools.zircolite.sources_already_indexed", return_value=[]),
        patch(
            "mulder.server.tools.zircolite.importlib.util.find_spec",
            return_value=MagicMock(),
        ),
        patch(
            "mulder.server.tools.zircolite._zircolite_script",
            return_value=evidence["script"],
        ),
        patch("mulder.server.tools.zircolite.subprocess.run", return_value=proc),
        patch("mulder.server.tools.zircolite.extract_and_index", return_value={}),
    ):
        return run_zircolite.__wrapped__(  # type: ignore[attr-defined]
            str(evidence["events"]),
            ruleset_path=str(evidence["ruleset"]),
        )


def test_a_rejected_invocation_is_an_error_not_an_empty_scan(
    evidence: dict[str, Path],
) -> None:
    """The exact shape that made this silent: argparse rejects the flags.

    Zircolite exits non-zero before opening a log and writes no results file.
    Before this fix the caller was told the scan succeeded with 0 detections.
    """
    proc = subprocess.CompletedProcess(
        args=["zircolite.py"],
        returncode=2,
        stdout="",
        stderr="zircolite.py: error: unrecognized arguments: --json",
    )

    result = _invoke(evidence, proc)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert "exited 2" in message
    assert "unrecognized arguments" in message
    # The failure must not be dressed up as a result.
    assert "total_detections" not in result
    assert "detections" not in result


def test_the_report_carries_stdout_when_zircolite_is_silent_on_stderr(
    evidence: dict[str, Path],
) -> None:
    """Some Zircolite failures print only to stdout; the detail must survive."""
    proc = subprocess.CompletedProcess(
        args=["zircolite.py"],
        returncode=1,
        stdout="[-] Ruleset is empty or malformed",
        stderr="",
    )

    result = _invoke(evidence, proc)

    assert result["status"] == "error"
    assert "Ruleset is empty or malformed" in str(result["error_message"])


def test_a_genuinely_quiet_log_is_still_a_successful_scan(
    evidence: dict[str, Path],
) -> None:
    """Pins the fix's narrowness: exit 0 and no detections stays a success.

    Zircolite 2.20.0 writes ``[{}]`` when its rules ran and nothing matched.
    That is a real answer, not a failure, and must keep reporting as one.
    """

    def _quiet(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        Path(cmd[cmd.index("--outfile") + 1]).write_text("[{}]")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with (
        patch("mulder.server.tools.zircolite.sources_already_indexed", return_value=[]),
        patch(
            "mulder.server.tools.zircolite.importlib.util.find_spec",
            return_value=MagicMock(),
        ),
        patch(
            "mulder.server.tools.zircolite._zircolite_script",
            return_value=evidence["script"],
        ),
        patch("mulder.server.tools.zircolite.subprocess.run", side_effect=_quiet),
        patch("mulder.server.tools.zircolite.extract_and_index", return_value={}),
    ):
        result = run_zircolite.__wrapped__(  # type: ignore[attr-defined]
            str(evidence["events"]),
            ruleset_path=str(evidence["ruleset"]),
        )

    assert result["status"] == "success"


def test_exit_zero_without_a_results_file_is_an_error(evidence: dict[str, Path]) -> None:
    """Zircolite only skips the results file when it never scanned.

    Every way of getting here found so far (no rules compiled, a parser
    dependency missing) is a failed scan, so it must not depend on recognising
    one particular log message.
    """
    proc = subprocess.CompletedProcess(args=["zircolite.py"], returncode=0, stdout="", stderr="")

    result = _invoke(evidence, proc)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"


def test_partial_results_are_kept_when_zircolite_exits_non_zero(
    evidence: dict[str, Path],
) -> None:
    """A non-zero exit that still wrote detections must not discard them.

    Zircolite exits non-zero on a single unreadable input while having already
    written matches for the rest, so the guard is deliberately conjunctive:
    non-zero *and* no results file.
    """
    written: list[Path] = []

    def _write_results(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        outfile = Path(cmd[cmd.index("--outfile") + 1])
        outfile.write_text('[{"rule_level": "high", "title": "T", "matches": []}]')
        written.append(outfile)
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr="one input was unreadable"
        )

    with (
        patch("mulder.server.tools.zircolite.sources_already_indexed", return_value=[]),
        patch(
            "mulder.server.tools.zircolite.importlib.util.find_spec",
            return_value=MagicMock(),
        ),
        patch(
            "mulder.server.tools.zircolite._zircolite_script",
            return_value=evidence["script"],
        ),
        patch("mulder.server.tools.zircolite.subprocess.run", side_effect=_write_results),
        patch("mulder.server.tools.zircolite.extract_and_index", return_value={}),
    ):
        result = run_zircolite.__wrapped__(  # type: ignore[attr-defined]
            str(evidence["events"]),
            ruleset_path=str(evidence["ruleset"]),
        )

    assert written, "the fake Zircolite never ran"
    assert result["status"] == "success"


def test_a_ruleset_that_loaded_no_rules_is_an_error_not_a_clean_scan(
    evidence: dict[str, Path],
) -> None:
    """Zircolite exits 0 and writes nothing when no rule compiled.

    That is what a Sigma YAML ruleset does without pySigma installed, and it
    used to be reported as a successful scan with no detections.
    """
    proc = subprocess.CompletedProcess(
        args=["zircolite.py"],
        returncode=0,
        stdout="[+] Loading ruleset(s)\n   [-] No rules to execute !\n",
        stderr="",
    )

    result = _invoke(evidence, proc)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert "loaded no rules" in str(result["error_message"])


def test_missing_pysigma_is_reported_by_its_pypi_name(evidence: dict[str, Path]) -> None:
    """Without pySigma no Sigma rule can compile, so the preflight must stop the run."""

    def _find_spec(name: str) -> object:
        if name.startswith("sigma"):
            raise ModuleNotFoundError(name)
        return MagicMock()

    with (
        patch("mulder.server.tools.zircolite.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.zircolite.importlib.util.find_spec", side_effect=_find_spec),
    ):
        result = run_zircolite.__wrapped__(  # type: ignore[attr-defined]
            str(evidence["events"]),
            ruleset_path=str(evidence["ruleset"]),
        )

    assert result["status"] == "error"
    assert result["error_type"] == "binary_missing"
    assert "pysigma, pysigma-backend-sqlite" in str(result["error_message"])
