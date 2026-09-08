"""A failed Hayabusa run must not be reported as a clean, zero-alert scan.

``run_hayabusa`` pre-creates its CSV output path with
``tempfile.NamedTemporaryFile(suffix=".csv", delete=False)`` and then guards
failures with ``if proc.returncode != 0 and not Path(out_path).exists():``.
The second half of that condition can never be true -- the file was just
created -- so the guard is dead code. Every non-zero Hayabusa exit fell
through to the empty-output branch and returned ``status: success`` with
``total_alerts: 0``: a Sigma sweep of 3,700+ rules that never ran looked
exactly like a host on which nothing matched.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.hayabusa import run_hayabusa

# A stand-in Hayabusa: given the argv and its resolved -o path, decide what to
# write and how to exit.
Runner = Callable[[list[str], Path], "subprocess.CompletedProcess[str]"]

_CSV_HEADER = "Timestamp,RuleTitle,Level,Computer,MitreAttack\n"
_CSV_ROW = "2026-01-01 00:00:00,Suspicious PowerShell,high,WS01,T1059.001\n"


@pytest.fixture
def evtx_dir(tmp_path: Path) -> Path:
    """A directory holding one .evtx file, so the run reaches Hayabusa."""
    (tmp_path / "Security.evtx").write_bytes(b"ElfFile\x00")
    return tmp_path


def _invoke(evtx_dir: Path, run: Runner) -> tuple[Any, list[str], list[bool]]:
    """Run ``run_hayabusa`` with Hayabusa itself replaced by *run*.

    Returns the response, whatever was handed to ``extract_and_index``, and
    whether the ``-o`` output path already existed when Hayabusa was invoked.
    """
    indexed: list[str] = []
    out_path_existed: list[bool] = []

    def _record(**kwargs: object) -> dict[str, object]:
        indexed.append(str(kwargs.get("raw_output", "")))
        return {}

    def _wrap(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path_existed.append(out_path.exists())
        return run(cmd, out_path)

    with (
        patch(
            "mulder.server.tools.hayabusa._hayabusa_binary",
            return_value="/usr/bin/hayabusa",
        ),
        patch("mulder.server.tools.hayabusa.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.hayabusa.subprocess.run", side_effect=_wrap),
        patch("mulder.server.tools.hayabusa.extract_and_index", side_effect=_record),
    ):
        result = run_hayabusa.__wrapped__(str(evtx_dir))  # type: ignore[attr-defined]
    return result, indexed, out_path_existed


def _failed(stderr: str = "", stdout: str = "", code: int = 1) -> Runner:
    """A Hayabusa that exits non-zero and writes nothing to its output path."""

    def _run(cmd: list[str], _out_path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=cmd, returncode=code, stdout=stdout, stderr=stderr)

    return _run


def test_a_failed_run_is_an_error_not_an_empty_timeline(evtx_dir: Path) -> None:
    """The shape that made this silent: Hayabusa refuses to run at all."""
    result, _indexed, _existed = _invoke(
        evtx_dir,
        _failed(stderr="Failed to create the output file. Use -C to overwrite.", code=1),
    )

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert "exited 1" in message
    assert "Use -C to overwrite" in message


def test_the_output_file_always_exists_so_the_old_guard_was_dead(
    evtx_dir: Path,
) -> None:
    """Pins *why* the guard never fired, not just that failures now surface.

    ``NamedTemporaryFile(delete=False)`` creates the path before Hayabusa is
    invoked, so ``not Path(out_path).exists()`` is False on every run --
    including the failing ones the guard existed to catch. If a future change
    stops pre-creating the file this test fails, which is the moment to
    revisit the content-based predicate.
    """
    _result, _indexed, existed = _invoke(evtx_dir, _failed(stderr="boom"))

    assert existed == [True], (
        "the -o path was not pre-created; the original guard's "
        "`not Path(out_path).exists()` premise no longer holds"
    )


def test_a_failed_run_never_reports_a_zero_alert_count(evtx_dir: Path) -> None:
    """A scan that did not happen must not answer with an alert count.

    Before this fix the response carried ``total_alerts: 0`` -- an assertion
    about the host, manufactured from a run that read no EVTX record.
    """
    result, _indexed, _existed = _invoke(evtx_dir, _failed(stderr="boom"))

    assert "total_alerts" not in json.dumps(result), (
        f"a failed run still reported an alert count: {result}"
    )


def test_the_detail_falls_back_to_stdout(evtx_dir: Path) -> None:
    """Some Hayabusa failures print only to stdout; the detail must survive."""
    result, _indexed, _existed = _invoke(
        evtx_dir, _failed(stdout="[ERROR] no rules loaded", stderr="", code=2)
    )

    assert result["status"] == "error"
    assert "no rules loaded" in str(result["error_message"])


def test_a_genuinely_clean_host_is_still_a_success(evtx_dir: Path) -> None:
    """Pins the fix's narrowness: exit 0 with no alerts stays a success.

    Hayabusa exits 0 having written nothing when no rule matched. That is a
    real answer, not a failure, and must keep reporting as one -- otherwise
    the fix trades silent failures for false alarms.
    """

    def _clean(cmd: list[str], _out_path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    result, _indexed, _existed = _invoke(evtx_dir, _clean)

    assert result["status"] == "success"


def test_detections_written_before_a_non_zero_exit_are_kept(evtx_dir: Path) -> None:
    """Hayabusa can fail on one unreadable EVTX after matching others.

    The guard is conjunctive -- non-zero *and* an empty timeline -- so real
    detections are never discarded because one input was corrupt.
    """

    def _partial(cmd: list[str], out_path: Path) -> subprocess.CompletedProcess[str]:
        out_path.write_text(_CSV_HEADER + _CSV_ROW)
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr="failed to parse one file"
        )

    result, indexed, _existed = _invoke(evtx_dir, _partial)

    assert result["status"] == "success"
    assert indexed == [_CSV_HEADER + _CSV_ROW]
    assert "Suspicious PowerShell" in json.dumps(result)
