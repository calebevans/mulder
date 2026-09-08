"""Mulder's Zircolite command line must be one Zircolite 2.20.0 accepts.

``_run_zircolite_process`` passed a ``--json`` flag that Zircolite does not
define. Seven of its options begin with that prefix, so argparse rejected the
invocation as ambiguous and exited 2 before opening a single event log --
every ``run_zircolite`` call, on every log format.

The contract test below rebuilds Zircolite's own parser from the option
strings in the pinned release and feeds it the argv mulder actually builds, so
it fails against any invocation that release would refuse.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.assets.manifest import ZIRCOLITE_VERSION
from mulder.server.tools.zircolite import _FORMAT_FLAGS, _run_zircolite_process

_FORMATS = ["auditd", "sysmon_linux", "json", "evtx"]


def _zircolite_parser() -> argparse.ArgumentParser:
    """Zircolite 2.20.0's input-format options, verbatim.

    Copied from ``zircolite.py`` at tag 2.20.0 (the pinned ``git_ref``), lines
    1925-1962: one mutually exclusive group holding every input-format option,
    plus the three flags mulder supplies. ``exit_on_error`` stays default, so
    a rejected option raises ``SystemExit`` exactly as it does in production.
    """
    parser = argparse.ArgumentParser(prog="zircolite.py")
    formats = parser.add_mutually_exclusive_group()
    formats.add_argument(
        "-j", "--jsononly", "--jsonline", "--jsonl", "--json-input", action="store_true"
    )
    formats.add_argument("--jsonarray", "--json-array", "--json-array-input", action="store_true")
    formats.add_argument("-D", "--dbonly", "--db-input", action="store_true")
    formats.add_argument(
        "-S", "--sysmon4linux", "--sysmon-linux", "--sysmon-linux-input", action="store_true"
    )
    formats.add_argument("-AU", "--auditd", "--auditd-input", action="store_true")
    parser.add_argument("-e", "--events", "--evtx", type=str)
    parser.add_argument("-r", "--ruleset", type=str)
    parser.add_argument("-o", "--outfile", type=str)
    return parser


def _built_argv(log_format: str, tmp_path: Path) -> list[str]:
    """The argv mulder hands to Zircolite, minus the interpreter and script."""
    with patch("mulder.server.tools.zircolite.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        _run_zircolite_process(
            str(tmp_path / "zircolite.py"),
            tmp_path / "events.log",
            log_format,
            tmp_path / "rules",
            tmp_path,
        )
    cmd: list[str] = run.call_args[0][0]
    assert cmd[0] == sys.executable
    return cmd[2:]


def test_the_pinned_release_is_the_one_this_contract_describes() -> None:
    """The parser above is transcribed from 2.20.0; fail loudly on a bump."""
    assert ZIRCOLITE_VERSION == "2.20.0"


@pytest.mark.parametrize("log_format", _FORMATS)
def test_zircolite_accepts_the_command_mulder_builds(log_format: str, tmp_path: Path) -> None:
    """The whole point: the pinned release must parse our argv.

    Against the unfixed code this raises SystemExit(2) with
    "ambiguous option: --json could match --jsononly, --jsonline, ...".
    """
    argv = _built_argv(log_format, tmp_path)

    parsed = _zircolite_parser().parse_args(argv)

    assert parsed.events == str(tmp_path / "events.log")
    assert parsed.ruleset == str(tmp_path / "rules")


@pytest.mark.parametrize("log_format", _FORMATS)
def test_no_bare_json_flag_is_passed(log_format: str, tmp_path: Path) -> None:
    """``--json`` is not a Zircolite option in any release mulder pins."""
    assert "--json" not in _built_argv(log_format, tmp_path)


def test_the_input_format_is_still_declared(tmp_path: Path) -> None:
    """Pins the fix's narrowness: removing --json must not lose the format.

    The format is declared by ``_FORMAT_FLAGS`` alone, so a JSON log must
    still arrive as ``--jsononly`` -- otherwise Zircolite would read JSON
    lines as EVTX and find nothing.
    """
    argv = _built_argv("json", tmp_path)

    assert "--jsononly" in argv
    assert _zircolite_parser().parse_args(argv).jsononly is True


def test_every_format_flag_is_a_real_option() -> None:
    """Each mapped flag must be one the pinned release actually defines."""
    parser = _zircolite_parser()
    for log_format, flags in _FORMAT_FLAGS.items():
        for flag in flags:
            try:
                parser.parse_args([flag])
            except SystemExit:  # pragma: no cover - only on a bad mapping
                pytest.fail(f"{log_format} maps to {flag}, which Zircolite does not define")
