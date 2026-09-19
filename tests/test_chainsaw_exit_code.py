"""A failed Chainsaw run must not be reported as a clean, zero-finding scan.

All four Chainsaw runners -- hunt, search, srum and timeline -- called
``subprocess.run(...)`` and returned only the output path, discarding the exit
code. Every ``_parse_chainsaw_*_results`` answers a missing or unparseable
file with an empty result dict, so ``run_chainsaw`` reported ``status:
success`` with ``Total findings: 0``: a Sigma hunt that never executed looked
exactly like a clean host.

The first version of this fix guarded on ``returncode != 0 and not
results_path.exists()``, on the assumption that a failed run leaves no file.
That assumption is wrong, and Chainsaw is explicit about it -- it opens the
output file before it validates the evidence path. Verified against Chainsaw
2.16.0::

    $ chainsaw search -e x /nonexistent/evidence --json --output out.json
    [x] Specified event log path is invalid - /nonexistent/evidence
    exit=1   out.json exists, 0 bytes

So the file always exists, the conjunct is never true, and the guard never
fired for the most common failure there is. A nonzero exit is the only signal
available, and it is now the whole test.
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

    mapping = rules / "mapping.yml"
    mapping.write_text("---\n")
    # ``analyse srum`` needs the SOFTWARE hive to resolve its GUID tables, so
    # the srum runs must supply one before they reach Chainsaw at all.
    hive = rules / "SOFTWARE"
    hive.write_bytes(b"regf")
    kwargs = {"side_effect": run} if callable(run) else {"return_value": run}
    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw._default_chainsaw_mapping", return_value=mapping),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.subprocess.run", **kwargs),
        patch("mulder.server.tools.chainsaw.extract_and_index", side_effect=_record),
    ):
        result = run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
            str(evidence),
            mode=mode,
            sigma_rules_path=str(rules),
            search_term="powershell",
            software_hive_path=str(hive) if mode == "srum" else "",
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


_CHAINSAW_BANNER = (
    "\n ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗\n"
    "██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║\n"
    "    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)\n\n"
)


@pytest.mark.parametrize("mode", _MODES)
def test_a_zero_byte_output_file_does_not_rescue_a_failed_run(
    mode: str, evidence: Path, tmp_path: Path
) -> None:
    """The real Chainsaw behaviour: the file exists and is empty.

    Chainsaw opens `--output` before it validates the evidence path, so this
    is what an invalid path actually leaves behind. The previous conjunctive
    guard saw the file, concluded the run had produced results, and reported
    a clean scan.
    """
    rules = tmp_path / "rules"
    rules.mkdir()
    # Recorded inside the fake: run_chainsaw works in a TemporaryDirectory,
    # so the file is gone by the time the assertions run.
    written: list[tuple[bool, int]] = []

    def _touch_then_fail(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        outfile = Path(cmd[cmd.index("--output") + 1])
        outfile.write_bytes(b"")
        written.append((outfile.exists(), outfile.stat().st_size))
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="",
            stderr=(
                _CHAINSAW_BANNER + "\x1b[38;5;9m[x] Specified event log path is invalid"
                " - /nonexistent/evidence\x1b[0m\n"
            ),
        )

    result, indexed = _invoke(evidence, mode, _touch_then_fail, rules)

    assert written == [(True, 0)], "the fake must reproduce Chainsaw's empty output file"
    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert indexed == [], "a failed run must not be summarised into the case"


@pytest.mark.parametrize("mode", _MODES)
def test_real_looking_findings_do_not_rescue_a_failed_run_either(
    mode: str, evidence: Path, tmp_path: Path
) -> None:
    """Even a file with detections in it does not make a failed run a success.

    A run that exited non-zero did not finish, so the detections in the file
    are an unknown fraction of what the evidence holds. Reporting them as the
    result is the same wrong answer in a quieter form -- the analyst cannot
    tell a partial hunt from a complete one.
    """
    rules = tmp_path / "rules"
    rules.mkdir()

    def _write_findings(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        outfile = Path(cmd[cmd.index("--output") + 1])
        outfile.write_text(
            json.dumps([{"name": "Suspicious PowerShell", "level": "high", "timestamp": "t"}])
        )
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr="[x] failed to parse Application.evtx"
        )

    result, indexed = _invoke(evidence, mode, _write_findings, rules)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert "failed to parse Application.evtx" in str(result["error_message"])
    assert indexed == []


def test_the_error_message_is_the_reason_not_the_ascii_logo(
    evidence: Path, tmp_path: Path
) -> None:
    """Chainsaw prints a nine-line logo before anything else.

    Truncating the head of stderr would hand the agent ASCII art and cut off
    the sentence that says what went wrong.
    """
    rules = tmp_path / "rules"
    rules.mkdir()
    proc = subprocess.CompletedProcess(
        args=["chainsaw", "hunt"],
        returncode=1,
        stdout="",
        stderr=(
            _CHAINSAW_BANNER + "\x1b[38;5;9m[x] Specified event log path is invalid"
            " - /nonexistent/evidence\x1b[0m\n"
        ),
    )

    result, _indexed = _invoke(evidence, "hunt", proc, rules)

    message = str(result["error_message"])
    assert "Specified event log path is invalid" in message
    assert "\u2588" not in message, "the banner leaked into the error message"
    assert "\x1b[" not in message, "ANSI escapes leaked into the error message"
