"""capa and FLOSS take ``-j/--json`` for JSON output, not ``--format json``.

In both tools ``-f/--format`` selects the *input* format -- capa 9.4.0 accepts
``auto|pe|dotnet|elf|sc32|sc64|cape|drakvuf|vmray|freeze|binexport2|binja_database``
and FLOSS 3.1.0 accepts ``auto|pe|sc32|sc64``. Neither accepts ``json``, so
``--format json`` is rejected by argparse before the sample is ever opened:

    capa:  error: argument -f/--format: invalid choice: 'json'   -> exit 2
    floss: error: argument -f/--format: invalid choice: 'json'   -> exit 255

FLOSS has a second defect on the same command line. ``--only`` and ``--no`` are
both ``nargs="+"`` with ``choices``, so a bare ``--only`` immediately before the
positional sample swallows the sample path as one of its values:

    floss: error: argument --only: invalid choice: 'sample.bin'
           (choose from 'static', 'stack', 'tight', 'decoded')

Both grammars were verified against the pinned release binaries
(capa 9.4.0, floss v3.1.0-0-gdb9af41).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.binary import run_capa, run_floss

# The exact `choices` tuples argparse is built with in each pinned release.
_CAPA_FORMAT_CHOICES = {
    "auto",
    "pe",
    "dotnet",
    "elf",
    "sc32",
    "sc64",
    "cape",
    "drakvuf",
    "vmray",
    "freeze",
    "binexport2",
    "binja_database",
}
_FLOSS_FORMAT_CHOICES = {"auto", "pe", "sc32", "sc64"}
_FLOSS_ANALYSIS_CHOICES = {"static", "stack", "tight", "decoded"}


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ\x90\x00" + b"\x00" * 512)
    return path


def _capture(tool: Any, sample: Path, **kwargs: Any) -> list[str]:
    """Run *tool* with the subprocess replaced, returning the argv it built."""
    captured: list[list[str]] = []

    def _record(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        captured.append(list(cmd))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="{}", stderr="")

    with (
        patch("mulder.server.tools.binary.require_binary", return_value="/usr/bin/tool"),
        patch("mulder.server.tools.binary.subprocess.run", side_effect=_record),
        patch("mulder.server.tools.binary.extract_and_index", return_value={}),
    ):
        tool.__wrapped__("case-1", str(sample), **kwargs)

    assert captured, "the tool never invoked a subprocess"
    return captured[0]


def _format_value(argv: list[str]) -> str | None:
    """The value argparse would bind to -f/--format, if the flag is present."""
    for flag in ("--format", "-f"):
        if flag in argv:
            i = argv.index(flag)
            return argv[i + 1] if i + 1 < len(argv) else None
    return None


def test_capa_does_not_pass_json_as_an_input_format(sample: Path) -> None:
    """capa 9.4.0 exits 2 on ``--format json`` before reading the sample."""
    argv = _capture(run_capa, sample)

    fmt = _format_value(argv)
    assert fmt != "json", "--format json is an invalid choice and capa exits 2"
    if fmt is not None:
        assert fmt in _CAPA_FORMAT_CHOICES, f"{fmt!r} is not a capa --format choice"


def test_capa_requests_json_with_the_json_flag(sample: Path) -> None:
    """The output is parsed as JSON, so the JSON flag must actually be passed."""
    argv = _capture(run_capa, sample)

    assert "--json" in argv or "-j" in argv


def test_floss_does_not_pass_json_as_an_input_format(sample: Path) -> None:
    """FLOSS 3.1.0 exits 255 on ``--format json``."""
    argv = _capture(run_floss, sample)

    fmt = _format_value(argv)
    assert fmt != "json", "--format json is an invalid choice and floss exits 255"
    if fmt is not None:
        assert fmt in _FLOSS_FORMAT_CHOICES, f"{fmt!r} is not a floss --format choice"


def test_floss_requests_json_with_the_json_flag(sample: Path) -> None:
    argv = _capture(run_floss, sample)

    assert "--json" in argv or "-j" in argv


def test_floss_never_leaves_only_or_no_without_an_analysis_type(sample: Path) -> None:
    """``--only``/``--no`` are nargs="+" with choices; a bare one eats the sample.

    Exercised in both directions, since ``include_static=False`` is the branch
    that emitted the bare ``--only``.
    """
    for include_static in (True, False):
        argv = _capture(run_floss, sample, include_static=include_static)

        for flag in ("--only", "--no"):
            if flag not in argv:
                continue
            i = argv.index(flag)
            following = argv[i + 1] if i + 1 < len(argv) else None
            assert following in _FLOSS_ANALYSIS_CHOICES, (
                f"{flag} is followed by {following!r}, which argparse would reject "
                f"as an invalid choice (include_static={include_static})"
            )


def test_floss_puts_the_sample_before_any_list_valued_flag(sample: Path) -> None:
    """Ordering is load-bearing, not cosmetic.

    ``--no static <sample>`` would bind the sample as a second value of --no.
    The positional must come first.
    """
    argv = _capture(run_floss, sample, include_static=False)

    assert str(sample) in argv
    sample_at = argv.index(str(sample))
    for flag in ("--only", "--no"):
        if flag in argv:
            assert argv.index(flag) > sample_at, (
                f"{flag} precedes the sample; argparse would consume the sample path"
            )


def test_the_sample_is_still_passed_exactly_once(sample: Path) -> None:
    """Narrowness guard: the fix must not drop or duplicate the positional."""
    for tool in (run_capa, run_floss):
        argv = _capture(tool, sample)
        assert argv.count(str(sample)) == 1


def test_the_minimum_length_option_is_unchanged(sample: Path) -> None:
    """Narrowness guard: only the format/analysis flags were wrong."""
    argv = _capture(run_floss, sample, minimum_length=7)

    assert "--minimum-length" in argv
    assert argv[argv.index("--minimum-length") + 1] == "7"
