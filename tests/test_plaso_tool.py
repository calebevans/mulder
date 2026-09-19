"""run_plaso: log2timeline/psort invocation and failure reporting.

plaso dropped the positional storage-file argument years ago; current
releases (20260720 in the container image) reject it with an argparse usage
error.  These tests pin the ``--storage_file`` form, the flags that keep plaso
from prompting on stdin, and that a failure surfaces the last line of output
rather than the head of argparse's usage banner.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools.extract.plaso import _failure_detail, run_plaso

_MOD = "mulder.server.tools.extract.plaso"

_ARGPARSE_STDERR = (
    "usage: log2timeline [-h] [--troubles] [-V] [--artifact_definitions PATH]\n"
    "                    [--custom_artifact_definitions PATH] [--data PATH]\n"
    "                    [SOURCE]\n"
    "log2timeline: error: unrecognized arguments: /evidence/disk.E01\n"
)


def _argv_after(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


class _FakePlaso:
    """subprocess.run stand-in that behaves like a working plaso install."""

    def __init__(self, l2t_returncode: int = 0, l2t_stderr: str = "") -> None:
        self.calls: list[dict[str, Any]] = []
        self.l2t_returncode = l2t_returncode
        self.l2t_stderr = l2t_stderr

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append({"argv": argv, **kwargs})
        tool = Path(argv[0]).name
        if tool == "log2timeline":
            if self.l2t_returncode == 0:
                Path(_argv_after(argv, "--storage_file")).write_bytes(b"plaso")
            return subprocess.CompletedProcess(
                argv, self.l2t_returncode, stdout="", stderr=self.l2t_stderr
            )
        if tool == "psort":
            Path(_argv_after(argv, "-w")).write_text("date,time\n01/15/2025,08:00:00\n")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="stats", stderr="")


@pytest.fixture()
def fake_env(tmp_path: Path) -> Any:
    cfg = MagicMock(db_dir=tmp_path)
    ctx = MagicMock(case_id="case")
    with (
        patch(f"{_MOD}._find_plaso_cmd", side_effect=lambda tool: [f"/usr/bin/{tool}"]),
        patch(f"{_MOD}.get_cfg", return_value=cfg),
        patch(f"{_MOD}.get_ctx", return_value=ctx),
        patch(f"{_MOD}.extract_and_index", return_value={"status": "indexed"}) as index,
    ):
        yield index


def test_argv_uses_storage_file_and_never_prompts(fake_env: MagicMock, tmp_path: Path) -> None:
    fake = _FakePlaso()
    with patch(f"{_MOD}.subprocess.run", fake):
        resp = run_plaso.__wrapped__(  # type: ignore[attr-defined]
            "/evidence/disk.E01", parsers="winevtx,prefetch", time_range="2015-08-01"
        )

    assert resp["status"] == "success"
    l2t, psort, pinfo = (c["argv"] for c in fake.calls)

    assert l2t[0] == "/usr/bin/log2timeline"
    assert _argv_after(l2t, "--storage_file").endswith("timeline.plaso")
    assert l2t[-1] == "/evidence/disk.E01", "source is the single positional argument"
    assert _argv_after(l2t, "--parsers") == "winevtx,prefetch"
    for flag, value in (
        ("--status_view", "none"),
        ("--partitions", "all"),
        ("--volumes", "all"),
        ("--vss_stores", "none"),
    ):
        assert _argv_after(l2t, flag) == value
    assert "-u" in l2t, "unattended: abort instead of prompting"

    assert psort[0] == "/usr/bin/psort"
    assert _argv_after(psort, "-o") == "l2tcsv"
    assert _argv_after(psort, "-w").endswith("timeline.csv")
    assert psort[-2:] == [_argv_after(l2t, "--storage_file"), "date > '2015-08-01'"]
    assert "-u" in psort

    assert pinfo[0] == "/usr/bin/pinfo"
    for call in fake.calls:
        assert call["stdin"] is subprocess.DEVNULL

    # psort's CSV file, not its stdout, is what gets indexed.
    assert fake_env.call_args_list[0].args[0] == "date,time\n01/15/2025,08:00:00"
    assert (tmp_path / "case.plaso").read_bytes() == b"plaso"


def test_l2t_failure_reports_last_stderr_line_and_exit_code(fake_env: MagicMock) -> None:
    fake = _FakePlaso(l2t_returncode=2, l2t_stderr=_ARGPARSE_STDERR)
    with patch(f"{_MOD}.subprocess.run", fake):
        resp = run_plaso.__wrapped__("/evidence/disk.E01")  # type: ignore[attr-defined]

    assert resp["status"] == "error"
    assert resp["error_type"] == "tool_failed"
    msg = str(resp["error_message"])
    assert msg.startswith("log2timeline exited 2: ")
    assert "log2timeline: error: unrecognized arguments: /evidence/disk.E01" in msg
    assert "usage: log2timeline" not in msg
    assert len(fake.calls) == 1, "psort must not run without a storage file"
    fake_env.assert_not_called()


def test_failure_detail_keeps_tail_of_stdout_and_stderr() -> None:
    """plaso writes its own errors to stdout after the dependency check."""
    proc = subprocess.CompletedProcess(
        ["log2timeline"],
        1,
        stdout="Checking availability and versions of dependencies.\n[OK]\n\n"
        "No supported file system found in source.\n",
        stderr="2026-09-19 05:13:44 [INFO] (MainProcess) PID:6 <artifact_definitions> ...\n",
    )
    detail = _failure_detail("log2timeline", proc)
    assert detail.startswith("log2timeline exited 1: ")
    assert "No supported file system found in source." in detail
    assert "[INFO]" in detail
    assert len(detail) < 600


def test_failure_detail_is_capped() -> None:
    proc = subprocess.CompletedProcess(["psort"], 1, stdout="", stderr="x" * 5000)
    assert len(_failure_detail("psort", proc)) <= 500 + len("psort exited 1: ")
