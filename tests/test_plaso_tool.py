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

from mulder.server.tools.extract.plaso import PARSER_PRESETS, _failure_detail, run_plaso

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


# --- the linux_logs preset ---------------------------------------------------

_UNKNOWN = (
    "Processing started.\n"
    'Unknown parser or plugin names in element(s): "text/syslog_traditional,jsonl/'
    'docker_container_log" of parser filter expression: systemd_journal,utmp\n'
)


class _OldPlaso(_FakePlaso):
    """A plaso that lacks some parsers: it rejects the run and leaves a stub storage file."""

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if Path(argv[0]).name == "log2timeline" and any(
            name in _argv_after(argv, "--parsers") for name in ("syslog_traditional", "nosuch")
        ):
            self.calls.append({"argv": argv, **kwargs})
            Path(_argv_after(argv, "--storage_file")).write_bytes(b"stub")
            return subprocess.CompletedProcess(argv, 1, stdout=_UNKNOWN, stderr="")
        return super().__call__(argv, **kwargs)


def test_linux_logs_names_the_login_and_system_log_parsers(fake_env: MagicMock) -> None:
    fake = _FakePlaso()
    with patch(f"{_MOD}.subprocess.run", fake):
        resp = run_plaso.__wrapped__(  # type: ignore[attr-defined]
            "/evidence/web01.E01", parsers="linux_logs"
        )

    assert resp["status"] == "success"
    parsers = _argv_after(fake.calls[0]["argv"], "--parsers").split(",")
    assert parsers == PARSER_PRESETS["linux_logs"].split(",")
    for needed in ("systemd_journal", "utmp", "text/syslog", "text/bash_history", "text/selinux"):
        assert needed in parsers
    # Not plaso's own "linux" preset: filestat writes four events for every file.
    assert "filestat" not in parsers and "linux" not in parsers
    assert fake.calls[0]["argv"][-1] == "/evidence/web01.E01"


def test_parsers_an_older_plaso_lacks_are_dropped_once_and_named(fake_env: MagicMock) -> None:
    fake = _OldPlaso()
    with patch(f"{_MOD}.subprocess.run", fake):
        resp = run_plaso.__wrapped__(  # type: ignore[attr-defined]
            "/evidence/web01.E01", parsers="linux_logs"
        )

    assert resp["status"] == "success"
    first, second = (c["argv"] for c in fake.calls[:2])
    assert "text/syslog_traditional" in _argv_after(first, "--parsers")
    retried = _argv_after(second, "--parsers").split(",")
    assert "text/syslog_traditional" not in retried and "jsonl/docker_container_log" not in retried
    assert "utmp" in retried and "text/syslog" in retried
    assert '"parsers_not_in_this_plaso": ["text/syslog_traditional"' in str(resp["preview"])


def test_a_parser_name_the_caller_got_wrong_is_an_error_not_an_empty_timeline(
    fake_env: MagicMock,
) -> None:
    """The rejected run leaves a storage file, which used to pass for a result."""
    fake = _OldPlaso()
    with patch(f"{_MOD}.subprocess.run", fake):
        resp = run_plaso.__wrapped__(  # type: ignore[attr-defined]
            "/evidence/web01.E01", parsers="nosuch,utmp"
        )

    assert resp["status"] == "error" and resp["error_type"] == "tool_failed"
    assert "Unknown parser or plugin names" in str(resp["error_message"])
    assert len(fake.calls) == 1, "only a preset is retried: the caller's own list is the caller's"
    fake_env.assert_not_called()


class _LockedDisk(_FakePlaso):
    """A disk with a LUKS partition: plaso stops at it unless told which partitions to read."""

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        named = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--partitions"]
        if Path(argv[0]).name == "log2timeline" and named[-1] == "all":  # the last one counts
            self.calls.append({"argv": argv, **kwargs})
            said = "Unable to proceed. Encrypted volume found but no mediator to determine\n"
            return subprocess.CompletedProcess(argv, 1, stdout=said, stderr="")
        return super().__call__(argv, **kwargs)


def test_an_encrypted_partition_does_not_stop_the_timeline_of_the_others(
    fake_env: MagicMock,
) -> None:
    """ext4 beside LUKS is planned as any disk, with linux_logs: plaso read nothing of it."""
    fake = _LockedDisk()
    with (
        patch(f"{_MOD}.subprocess.run", fake),
        patch(f"{_MOD}.unencrypted_partitions", return_value="1,3") as others,
    ):
        resp = run_plaso.__wrapped__(  # type: ignore[attr-defined]
            "/evidence/web01.raw", parsers="linux_logs"
        )

    assert resp["status"] == "success"
    others.assert_called_once_with("/evidence/web01.raw")
    first, second = (c["argv"] for c in fake.calls[:2])
    assert first.count("--partitions") == 1
    assert [second[i + 1] for i, arg in enumerate(second) if arg == "--partitions"][-1] == "1,3"
    assert '"partitions_read": "1,3"' in str(resp["preview"]) and "LUKS" in str(resp["preview"])

    # Nothing but the encrypted volume: said once, and not tried again.
    fake = _LockedDisk()
    with (
        patch(f"{_MOD}.subprocess.run", fake),
        patch(f"{_MOD}.unencrypted_partitions", return_value=""),
    ):
        resp = run_plaso.__wrapped__("/evidence/web01.raw")  # type: ignore[attr-defined]
    assert resp["status"] == "error" and "Encrypted volume found" in str(resp["error_message"])
    assert len(fake.calls) == 1
