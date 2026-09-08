"""A failed rabin2 parse must never be triaged as a benign binary.

``_run_rabin2`` never read ``proc.returncode``: it returned ``{}`` whenever
stdout was empty or unparseable, which is indistinguishable from a successful
run that genuinely had nothing to report. ``triage_binary`` then swallowed the
resulting ``OSError``/timeout with a ``logger.warning`` and carried on to
``_compute_verdict`` with empty inputs -- where ``score == 0`` falls through to
``classification = "benign_indicators"``, ``confidence = "medium"``.

A malware triage that never parsed the binary was reported to the agent as a
confident clean bill of health.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import mulder.server.tools.binary as binary_module
from mulder.server.tools.binary import _compute_verdict, _run_rabin2, triage_binary

_RWX_SECTION: list[dict[str, object]] = [{"name": ".text", "permissions": "-rwx"}]


# ---------------------------------------------------------------------------
# _run_rabin2 -- the exit code must reach the caller
# ---------------------------------------------------------------------------


def test_a_failed_rabin2_raises_instead_of_returning_an_empty_dict() -> None:
    """The silence itself: {} meant both 'nothing found' and 'never ran'."""
    proc = subprocess.CompletedProcess(
        args=["rabin2", "-Ij", "/evidence/sample.exe"],
        returncode=1,
        stdout="",
        stderr="Cannot open file '/evidence/sample.exe'",
    )

    with (
        patch("mulder.server.tools.binary.subprocess.run", return_value=proc),
        pytest.raises(OSError) as excinfo,
    ):
        _run_rabin2("I", Path("/evidence/sample.exe"))

    message = str(excinfo.value)
    assert "rabin2 -I" in message
    assert "exited 1" in message
    assert "Cannot open file" in message


def test_an_empty_result_from_a_successful_run_is_still_an_empty_dict() -> None:
    """Pins the fix's narrowness: exit 0 with no output is a real answer.

    A binary with no imports makes ``rabin2 -ij`` print nothing and exit 0.
    That must keep returning {} rather than becoming an error.
    """
    proc = subprocess.CompletedProcess(
        args=["rabin2", "-ij", "/evidence/sample.exe"], returncode=0, stdout="", stderr=""
    )

    with patch("mulder.server.tools.binary.subprocess.run", return_value=proc):
        assert _run_rabin2("i", Path("/evidence/sample.exe")) == {}


def test_json_produced_alongside_a_non_zero_exit_is_kept() -> None:
    """The guard is conjunctive: a partial parse is real data.

    rabin2 reports a partially-understood binary by exiting non-zero while
    still emitting JSON. Discarding that would lose evidence.
    """
    proc = subprocess.CompletedProcess(
        args=["rabin2", "-Sj", "/evidence/sample.exe"],
        returncode=1,
        stdout='{"sections": [{"name": ".text"}]}',
        stderr="warning: truncated section table",
    )

    with patch("mulder.server.tools.binary.subprocess.run", return_value=proc):
        result = _run_rabin2("S", Path("/evidence/sample.exe"))

    assert result == {"sections": [{"name": ".text"}]}


# ---------------------------------------------------------------------------
# _compute_verdict -- missing data must not read as a clean binary
# ---------------------------------------------------------------------------


def test_an_incomplete_analysis_is_never_benign() -> None:
    """The core defect: no data scored 0, and 0 meant 'benign, medium'."""
    verdict = _compute_verdict([], {}, {}, [], ["imports/sections/strings unavailable"])

    assert verdict["classification"] == "inconclusive"
    assert verdict["confidence"] == "none"
    reasons = verdict["reasons"]
    assert isinstance(reasons, list)
    assert any("Analysis incomplete" in str(r) for r in reasons)
    assert any("imports/sections/strings unavailable" in str(r) for r in reasons)


def test_a_complete_analysis_finding_nothing_is_still_benign() -> None:
    """Pins the fix's narrowness AND pins the premise.

    With no failures recorded, an empty analysis keeps its original
    ``benign_indicators`` / ``medium`` verdict -- so this test also proves the
    old behaviour is exactly what the incomplete case used to produce.
    """
    verdict = _compute_verdict([], {}, {}, [])

    assert verdict["classification"] == "benign_indicators"
    assert verdict["confidence"] == "medium"


def test_indicators_found_before_a_failure_are_not_thrown_away() -> None:
    """Evidence that *was* found survives an incomplete analysis.

    Downgrading a real RWX-section detection to 'inconclusive' would lose a
    finding, so only a would-be-clean verdict is replaced.
    """
    verdict = _compute_verdict(
        ["UPX section names"],
        {"process_injection": ["WriteProcessMemory", "CreateRemoteThread"]},
        {},
        _RWX_SECTION,
        ["library enumeration unavailable"],
    )

    assert verdict["classification"] == "malicious_indicators"
    assert verdict["confidence"] != "none"
    reasons = verdict["reasons"]
    assert isinstance(reasons, list)
    assert any("Analysis incomplete" in str(r) for r in reasons)


# ---------------------------------------------------------------------------
# triage_binary -- end to end
# ---------------------------------------------------------------------------


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    """A binary that exists, so the run reaches rabin2 itself."""
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ\x90\x00")
    return path


def _triage(sample: Path, run: Any) -> tuple[Any, list[Any]]:
    """Run triage_binary, capturing the results dict it hands to tool_response.

    ``tool_response`` is called with ``source="binary.triage"``, so it returns a
    compact preview envelope rather than the results themselves; capturing the
    argument asserts on what the tool actually computed.
    """
    computed: list[Any] = []
    # mypy --strict refuses attribute access on a re-exported name, so read
    # it out of the module namespace instead.
    real = vars(binary_module)["tool_response"]

    def _capture(tc_id: str, name: str, params: Any, results: Any, *args: Any) -> Any:
        computed.append(results)
        return real(tc_id, name, params, results, *args)

    with (
        patch("mulder.server.tools.binary.require_binary", return_value=True),
        patch("mulder.server.tools.binary.subprocess.run", side_effect=run),
        patch("mulder.server.tools.binary.extract_and_index", return_value={}),
        patch("mulder.server.tools.binary.tool_response", side_effect=_capture),
    ):
        result = triage_binary.__wrapped__(  # type: ignore[attr-defined]
            "case-1", str(sample), depth="standard"
        )
    return result, computed


def test_a_binary_rabin2_could_not_open_is_an_error(sample: Path) -> None:
    """The very first rabin2 call fails: nothing at all was parsed."""

    def _fail(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr="Cannot open file"
        )

    result, _computed = _triage(sample, _fail)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert "Cannot open file" in str(result["error_message"])
    assert "triage_verdict" not in result


def test_a_partial_triage_is_inconclusive_not_benign(sample: Path) -> None:
    """The headline case: headers parsed, everything else failed.

    Before this fix the agent was handed ``benign_indicators`` with
    ``medium`` confidence for a binary whose imports, sections and strings
    were never read.
    """

    def _headers_only(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if "-Ij" in cmd:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='{"info": {"arch": "x86", "bits": 64}}',
                stderr="",
            )
        return subprocess.CompletedProcess(
            args=cmd, returncode=3, stdout="", stderr="rabin2: parse error"
        )

    result, computed = _triage(sample, _headers_only)

    assert result["status"] == "success"
    assert computed, "triage_binary never reached tool_response"
    verdict = computed[0]["triage_verdict"]
    assert verdict["classification"] == "inconclusive"
    assert verdict["confidence"] == "none"
    assert any("Analysis incomplete" in str(r) for r in verdict["reasons"])
    assert any("parse error" in str(r) for r in verdict["reasons"])


def test_a_fully_parsed_clean_binary_is_still_benign(sample: Path) -> None:
    """Pins the fix's narrowness end to end: a real clean result survives."""

    def _all_ok(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if "-Ij" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout='{"info": {"arch": "x86"}}', stderr=""
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="{}", stderr="")

    result, computed = _triage(sample, _all_ok)

    assert result["status"] == "success"
    assert computed, "triage_binary never reached tool_response"
    verdict = computed[0]["triage_verdict"]
    assert verdict["classification"] == "benign_indicators"
    assert verdict["confidence"] == "medium"
