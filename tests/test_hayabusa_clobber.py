"""Hayabusa refuses to write over its pre-created output file, so no scan runs.

``run_hayabusa`` creates its ``-o`` path up front with
``tempfile.NamedTemporaryFile(suffix=".csv", delete=False)`` but invokes
Hayabusa without ``-C/--clobber``. Hayabusa 3.8.1 will not overwrite an
existing file: it prints

    [ERROR]  The file <path> already exists. Please specify a different
    filename or add the -C, --clobber option to overwrite.

to **stderr**, writes nothing, and **exits 0**. The zero exit is what makes
this invisible -- no return-code guard can catch it -- so every
``run_hayabusa`` call reads back an empty CSV and reports ``total_alerts: 0``
as a successful scan of 3,700+ Sigma rules that never executed.

The fake Hayabusa below reproduces that contract exactly, verified against the
pinned 3.8.1 release binary.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.hayabusa import run_hayabusa

Runner = Callable[[list[str], Path], "subprocess.CompletedProcess[str]"]

_CSV = (
    "Timestamp,RuleTitle,Level,Computer,MitreAttack\n"
    "2026-01-01 00:00:00,Suspicious PowerShell,high,WS01,T1059.001\n"
)

_REFUSAL = (
    "[ERROR]  The file {path} already exists. Please specify a different "
    "filename or add the -C, --clobber option to overwrite.\n"
)


@pytest.fixture
def evtx_dir(tmp_path: Path) -> Path:
    """A directory holding one .evtx file, so the run reaches Hayabusa."""
    (tmp_path / "Security.evtx").write_bytes(b"ElfFile\x00")
    return tmp_path


def _invoke(evtx_dir: Path, run: Runner) -> tuple[Any, list[list[str]]]:
    """Run ``run_hayabusa`` with Hayabusa itself replaced by *run*."""
    argvs: list[list[str]] = []

    def _wrap(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        argvs.append(list(cmd))
        return run(cmd, Path(cmd[cmd.index("-o") + 1]))

    with (
        patch(
            "mulder.server.tools.hayabusa._hayabusa_binary",
            return_value="/usr/bin/hayabusa",
        ),
        patch("mulder.server.tools.hayabusa.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.hayabusa.subprocess.run", side_effect=_wrap),
        patch("mulder.server.tools.hayabusa.extract_and_index", return_value={}),
    ):
        result = run_hayabusa.__wrapped__(str(evtx_dir))  # type: ignore[attr-defined]
    return result, argvs


def _real_hayabusa_semantics(cmd: list[str], out_path: Path) -> subprocess.CompletedProcess[str]:
    """A faithful Hayabusa 3.8.1: refuse an existing -o unless told to clobber.

    Verified against the pinned release binary: the refusal goes to stderr,
    the output file is left untouched, and the process exits **0**.
    """
    clobbers = {"-C", "--clobber"}
    if out_path.exists() and not clobbers.intersection(cmd):
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="", stderr=_REFUSAL.format(path=out_path)
        )
    out_path.write_text(_CSV)
    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="Saved file", stderr="")


def test_hayabusa_is_told_it_may_overwrite_its_output_file(evtx_dir: Path) -> None:
    """The one-line premise: the flag Hayabusa's own error message asks for."""
    _result, argvs = _invoke(evtx_dir, _real_hayabusa_semantics)

    assert argvs, "Hayabusa was never invoked"
    argv = argvs[0]
    assert "--clobber" in argv or "-C" in argv, (
        f"Hayabusa was given a pre-created -o path with no clobber flag: {argv}"
    )


def test_a_real_scan_reaches_the_analyst_instead_of_a_silent_refusal(
    evtx_dir: Path,
) -> None:
    """The bug, end to end, against a faithful Hayabusa.

    Before this fix the refusal produced ``total_alerts: 0`` reported as a
    success -- indistinguishable from a host on which nothing matched.
    """
    result, _argvs = _invoke(evtx_dir, _real_hayabusa_semantics)

    assert result["status"] == "success"
    results = result.get("results", result)
    preview = str(result.get("preview", "")) + str(results)
    assert '"total_alerts": 1' in preview or "'total_alerts': 1" in preview, (
        f"the scan produced no alerts -- Hayabusa was refused, not run: {result}"
    )


def test_the_refusal_exits_zero_so_no_return_code_guard_can_see_it(
    evtx_dir: Path,
) -> None:
    """Pins why this needed its own fix rather than a better failure guard.

    Hayabusa exits 0 when it refuses, so a guard keyed on ``returncode != 0``
    -- however it decides "produced no output" -- never fires. Only passing
    the flag prevents the refusal in the first place.
    """
    refusals: list[subprocess.CompletedProcess[str]] = []

    def _always_refuse(cmd: list[str], out_path: Path) -> subprocess.CompletedProcess[str]:
        proc = subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="", stderr=_REFUSAL.format(path=out_path)
        )
        refusals.append(proc)
        return proc

    _result, _argvs = _invoke(evtx_dir, _always_refuse)

    assert refusals and refusals[0].returncode == 0
    assert "already exists" in refusals[0].stderr


def test_the_rest_of_the_invocation_is_untouched(evtx_dir: Path) -> None:
    """Narrowness: only the clobber flag is added, nothing else moves."""
    _result, argvs = _invoke(evtx_dir, _real_hayabusa_semantics)
    argv = argvs[0]

    assert argv[1] == "csv-timeline"
    for flag, value in (("-d", str(evtx_dir)), ("-p", "super-verbose"), ("-m", "medium")):
        assert flag in argv, f"{flag} was dropped from the invocation"
        assert argv[argv.index(flag) + 1] == value
    assert "--no-wizard" in argv
    assert argv[argv.index("-o") + 1].endswith(".csv")


def test_a_genuinely_quiet_host_is_still_a_successful_scan(evtx_dir: Path) -> None:
    """Narrowness: an empty timeline from a real run stays a success.

    Hayabusa writing an empty CSV means no rule matched. That is a real
    answer and must not be turned into an error by this change.
    """

    def _quiet(cmd: list[str], out_path: Path) -> subprocess.CompletedProcess[str]:
        out_path.write_text("")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    result, _argvs = _invoke(evtx_dir, _quiet)

    assert result["status"] == "success"


@pytest.mark.skipif(
    not os.environ.get("MULDER_HAYABUSA_BIN"),
    reason="set MULDER_HAYABUSA_BIN to the pinned Hayabusa 3.8.1 binary to run this",
)
def test_the_real_pinned_binary_refuses_without_the_flag(tmp_path: Path) -> None:
    """The empirical premise, against the actual 3.8.1 release binary.

    Skipped unless MULDER_HAYABUSA_BIN points at it, so CI stays hermetic.
    """
    binary = os.environ["MULDER_HAYABUSA_BIN"]
    assert shutil.which(binary) or Path(binary).exists()

    evtx = tmp_path / "evtx"
    evtx.mkdir()
    (evtx / "a.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 4088)
    out = tmp_path / "out.csv"
    out.touch()

    base = [binary, "csv-timeline", "-d", str(evtx), "-o", str(out), "--no-wizard"]
    refused = subprocess.run(base, capture_output=True, text=True, timeout=600, check=False)

    assert refused.returncode == 0, "the refusal is expected to exit 0"
    assert "already exists" in refused.stderr
    assert out.stat().st_size == 0

    allowed = subprocess.run(
        [*base, "--clobber"], capture_output=True, text=True, timeout=600, check=False
    )
    assert "already exists" not in allowed.stderr
