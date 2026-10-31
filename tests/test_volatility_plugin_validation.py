"""Volatility plugin names must be validated before they reach the ``vol`` argv.

``_resolve_plugin_name`` returns any dotted string unchanged, and the result is
appended to the ``vol`` command line as a bare positional.  A value starting
with ``-`` (e.g. ``--plugin-dirs=/evidence/x.d``) would be parsed by the CLI as
an option instead of a plugin.  Names are now checked against a strict dotted
identifier pattern before any subprocess runs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.extract.volatility import (
    _is_valid_plugin_name,
    _run_batch_subprocess_fallback,
    run_volatility,
)

VOL_OUTPUT = "PID\tPPID\tImageFileName\n4\t0\tSystem\n"

OPTION_LIKE = [
    "--plugin-dirs=/evidence/x.d",
    "-p/evidence/x.d",
    "-o/tmp/out.d",
    "--output-dir=/tmp/x.y",
    "-l/tmp/vol.log",
    "--log=/tmp/vol.log",
    "-r.json",
    "-",
    "-o",
]

REAL_PLUGINS = [
    "windows.pslist.PsList",
    "windows.registry.hivelist.HiveList",
    "linux.bash.Bash",
    "linux.bash",
    "mac.pslist.PsList",
    "timeliner.Timeliner",
    "banners.Banners",
]


@pytest.fixture
def memory(tmp_path: Path) -> Path:
    path = tmp_path / "memory.raw"
    path.write_bytes(b"\x00" * 4096)
    return path


def _patches(calls: list[list[str]]) -> Any:
    def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=VOL_OUTPUT, stderr="")

    return (
        patch("mulder.server.tools.extract.volatility._find_vol_binary", return_value=["vol"]),
        patch("mulder.server.tools.extract.volatility.subprocess.run", side_effect=_run),
        patch("mulder.server.tools.extract.volatility.extract_and_index", return_value={}),
    )


def _invoke(memory: Path, plugin: str) -> tuple[Any, list[list[str]]]:
    """Run the tool with subprocess mocked; return (result, argv of each run call)."""
    calls: list[list[str]] = []
    p1, p2, p3 = _patches(calls)
    with p1, p2, p3:
        result = run_volatility.__wrapped__(plugin, str(memory))  # type: ignore[attr-defined]
    return result, calls


@pytest.mark.parametrize("plugin", OPTION_LIKE)
def test_option_like_plugin_names_are_invalid(plugin: str) -> None:
    assert not _is_valid_plugin_name(plugin)


@pytest.mark.parametrize("plugin", REAL_PLUGINS)
def test_real_plugin_names_are_valid(plugin: str) -> None:
    assert _is_valid_plugin_name(plugin)


@pytest.mark.parametrize("plugin", OPTION_LIKE)
def test_option_like_plugin_is_rejected_without_running_vol(memory: Path, plugin: str) -> None:
    result, calls = _invoke(memory, plugin)

    assert result["status"] == "error"
    assert result["error_type"] == "invalid_plugin"
    assert calls == []


@pytest.mark.parametrize("plugin", REAL_PLUGINS)
def test_real_plugin_runs_as_last_positional(memory: Path, plugin: str) -> None:
    result, calls = _invoke(memory, plugin)

    assert result["status"] != "error"
    (cmd,) = calls
    assert cmd == ["vol", "-f", str(memory), plugin]


@pytest.mark.parametrize("plugin", ["pslist", "netscan", "hivelist", "PsList"])
def test_short_names_still_resolve_and_run(memory: Path, plugin: str) -> None:
    result, calls = _invoke(memory, plugin)

    assert result["status"] != "error"
    (cmd,) = calls
    assert cmd[-1].startswith("windows.")


def test_batch_subprocess_fallback_skips_option_like_plugins(memory: Path) -> None:
    calls: list[list[str]] = []
    p1, p2, p3 = _patches(calls)
    aggregate = patch(
        "mulder.server.tools.extract.volatility._aggregate_batch_results",
        side_effect=lambda results, *args, **kwargs: results,
    )
    with p1, p2, p3, aggregate:
        per_plugin = _run_batch_subprocess_fallback(
            ["pslist", "--plugin-dirs=/evidence/x.d", "linux.bash.Bash"],
            str(memory),
            "tc-test",
            0.0,
            {},
        )

    assert [c[-1] for c in calls] == ["windows.pslist.PsList", "linux.bash.Bash"]
    bad: Any = per_plugin["--plugin-dirs=/evidence/x.d"]
    assert bad["status"] == "error"
    assert bad["error_type"] == "invalid_plugin"
