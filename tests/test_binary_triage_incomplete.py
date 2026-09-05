"""A binary that was never analysed came back as "benign_indicators".

``triage_binary`` computes its verdict from imports, sections, the timestamp
and section permissions. The three ``_run_rabin2`` calls that collect the
first two were wrapped in a ``try`` that swallowed ``TimeoutExpired`` and
``OSError`` with a log line, and ``_run_rabin2`` itself discarded the process
return code. So a rabin2 that timed out on a large or corrupted PE -- or
exited non-zero on an obfuscated header -- left ``imports`` and ``sections``
empty:

* ``_classify_imports([])`` returns ``{}``
* ``_detect_packing([], [])`` returns ``[]``
* score stays 0 → ``classification: "benign_indicators"``, ``confidence: "medium"``

with ``status: success`` and nothing in the response saying the analysis had
not happened. The sample most likely to defeat rabin2 is the sample most
worth examining.

The verdict is now ``inconclusive`` with ``confidence: "none"`` when any input
is missing, and the response carries a warning saying which.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import mulder.server.tools.binary as binary
from mulder.server.tools.binary import _compute_verdict, _run_rabin2

INFO_JSON = (
    '{"info": {"arch": "x86", "bits": 64, "bintype": "pe", "os": "windows",'
    ' "compiled": "Wed Mar 12 09:41:03 2025"}}'
)


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["rabin2"], returncode, stdout, stderr)


class TestRabin2FailureIsNotAnEmptyResult:
    def test_a_nonzero_exit_with_no_output_raises(self) -> None:
        with (
            patch(
                "mulder.server.tools.binary.subprocess.run",
                return_value=_completed(returncode=1, stderr="cannot open file"),
            ),
            __import__("pytest").raises(OSError, match="rabin2"),
        ):
            _run_rabin2("i", Path("/fake/x.exe"))

    def test_a_nonzero_exit_that_produced_output_is_kept(self) -> None:
        with patch(
            "mulder.server.tools.binary.subprocess.run",
            return_value=_completed(returncode=1, stdout=INFO_JSON),
        ):
            assert _run_rabin2("I", Path("/fake/x.exe"))["info"]["bintype"] == "pe"

    def test_a_clean_run_with_no_output_is_still_empty(self) -> None:
        """rabin2 exiting 0 with nothing to say is a legitimate empty result."""
        with patch("mulder.server.tools.binary.subprocess.run", return_value=_completed()):
            assert _run_rabin2("i", Path("/fake/x.exe")) == {}


class TestTheVerdictSaysWhenItWasComputedFromNothing:
    def test_an_incomplete_analysis_is_inconclusive(self) -> None:
        verdict = _compute_verdict([], {}, {"validity": "valid"}, [], ["rabin2 timed out"])
        assert verdict["classification"] == "inconclusive"
        assert verdict["confidence"] == "none"

    def test_the_reason_names_what_failed(self) -> None:
        verdict = _compute_verdict([], {}, {"validity": "valid"}, [], ["rabin2 timed out"])
        assert any("rabin2 timed out" in str(r) for r in verdict["reasons"])  # type: ignore[union-attr]

    def test_a_complete_analysis_is_unaffected(self) -> None:
        assert _compute_verdict([], {}, {"validity": "valid"}, [], []) == _compute_verdict(
            [], {}, {"validity": "valid"}, []
        )

    def test_findings_are_not_hidden_by_the_incomplete_flag(self) -> None:
        """A partial run that still found something must keep the reasons."""
        verdict = _compute_verdict(
            ["upx section names"], {}, {"validity": "valid"}, [], ["rahash2 failed"]
        )
        assert verdict["classification"] == "inconclusive"
        assert any("packing indicator" in str(r) for r in verdict["reasons"])  # type: ignore[union-attr]


class TestTriageBinaryEndToEnd:
    @staticmethod
    def _run(tmp_path: Path, standard_effect: object) -> dict[str, Any]:
        target = tmp_path / "sample.exe"
        target.write_bytes(b"MZ" + b"\x00" * 64)
        captured: dict[str, Any] = {}

        calls: list[str] = []

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            flag = cmd[1] if len(cmd) > 1 else ""
            calls.append(flag)
            if flag == "-Ij":
                return _completed(stdout=INFO_JSON)
            if isinstance(standard_effect, BaseException):
                raise standard_effect
            return _completed(stdout="{}")

        def capture_response(
            tc_id: str, tool_name: str, params: object, results: object, *a: object
        ) -> dict[str, object]:
            if isinstance(results, dict):
                captured.update(results)
            return {"status": "success"}

        with (
            patch("mulder.server.tools.binary.subprocess.run", side_effect=fake_run),
            patch.object(binary, "require_binary", return_value="/usr/bin/rabin2"),
            patch.object(binary, "extract_and_index", return_value={}),
            patch.object(binary, "tool_response", capture_response),
        ):
            binary.triage_binary.__wrapped__(  # type: ignore[attr-defined]
                "case-1", str(target), depth="standard"
            )
        return captured

    def test_a_timeout_does_not_produce_a_benign_verdict(self, tmp_path: Path) -> None:
        summary = self._run(tmp_path, subprocess.TimeoutExpired(cmd=["rabin2"], timeout=60))
        verdict = summary["triage_verdict"]
        assert verdict["classification"] == "inconclusive"
        assert verdict["confidence"] == "none"

    def test_the_response_says_the_analysis_was_incomplete(self, tmp_path: Path) -> None:
        summary = self._run(tmp_path, subprocess.TimeoutExpired(cmd=["rabin2"], timeout=60))
        assert summary["analysis_complete"] is False
        assert "not evidence of a clean binary" in str(summary["warning"])

    def test_a_successful_triage_is_marked_complete(self, tmp_path: Path) -> None:
        """A run that collected its evidence still returns a real verdict.

        Which verdict depends on how the ctime-formatted `compiled` value in
        the fixture is scored, which is a separate defect fixed in its own
        change; what matters here is that a complete run is not suppressed.
        """
        summary = self._run(tmp_path, None)
        assert summary["analysis_complete"] is True
        assert "warning" not in summary
        verdict = summary["triage_verdict"]
        assert verdict["classification"] != "inconclusive"
        assert verdict["confidence"] != "none"
