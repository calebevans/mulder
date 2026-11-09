"""RegRipper plugin profiles must be validated before they reach the rip.pl argv.

rip.pl joins the plugindir, the ``-p`` value and ``".pl"`` with
File::Spec->catfile, checks only that the joined file exists, and then
``require``s it -- executing it.  A profile containing ``..`` or ``/``
therefore escapes the plugin directory and runs an arbitrary file as the
mulder server user (GHSA-hpf8-fr4f-crfr).  Profiles are now checked against
a bare-identifier pattern before any subprocess runs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.extract.misc import (
    _is_valid_regripper_profile,
    run_regripper,
)

RIP_OUTPUT = "Launching hidden.exe\n  hidden.exe\n"

TRAVERSAL_PROFILES = [
    "../../../../tmp/evil",
    "../../../../../tmp/vmpoc/db/extracted/evidence-8276200d109b/evil",
    "../../../../../../../../tmp/evil",
    "../evil",
    "a/b",
    "compname/../evil",
    ".",
    "..",
    "/etc/evil",
    "compname ",
    " compname",
    "compname;id",
]

OPTION_LIKE = ["-a", "-p", "--update", "--list", "-o/tmp/out.d", "-"]

REAL_PROFILES = ["compname", "software", "sam", "security", "adobe", "userassist_1"]


@pytest.fixture
def hive(tmp_path: Path) -> Path:
    path = tmp_path / "NTUSER.DAT"
    path.write_bytes(b"\x00" * 4096)
    return path


def _invoke(hive_path: str, profile: str | None) -> tuple[Any, list[list[str]]]:
    """Run the tool with require_binary/subprocess/extract_and_index mocked."""
    calls: list[list[str]] = []

    def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=RIP_OUTPUT, stderr="")

    with (
        patch("mulder.server.tools.extract.misc.require_binary", return_value="/usr/bin/rip.pl"),
        patch("mulder.server.tools.extract.misc.subprocess.run", side_effect=_run),
        patch("mulder.server.tools.extract.misc.extract_and_index", return_value={}),
    ):
        result = run_regripper.__wrapped__(hive_path, profile)  # type: ignore[attr-defined]
    return result, calls


@pytest.mark.parametrize("profile", TRAVERSAL_PROFILES + OPTION_LIKE)
def test_traversal_and_option_like_profiles_are_invalid(profile: str) -> None:
    assert not _is_valid_regripper_profile(profile)


@pytest.mark.parametrize("profile", REAL_PROFILES)
def test_real_profiles_are_valid(profile: str) -> None:
    assert _is_valid_regripper_profile(profile)


@pytest.mark.parametrize("profile", TRAVERSAL_PROFILES + OPTION_LIKE)
def test_invalid_profile_is_rejected_without_running_rip(hive: Path, profile: str) -> None:
    result, calls = _invoke(str(hive), profile)

    assert result["status"] == "error"
    assert result["error_type"] == "invalid_plugin"
    assert calls == []  # rip.pl was never invoked


@pytest.mark.parametrize("profile", REAL_PROFILES)
def test_real_profile_runs_with_dash_p(hive: Path, profile: str) -> None:
    result, calls = _invoke(str(hive), profile)

    assert calls == [["/usr/bin/rip.pl", "-r", str(hive), "-p", profile]]
    assert result["status"] != "error" or result.get("error_type") != "invalid_plugin"


def test_no_profile_runs_all_plugins(hive: Path) -> None:
    result, calls = _invoke(str(hive), None)

    assert calls == [["/usr/bin/rip.pl", "-r", str(hive), "-a"]]
    _ = result
