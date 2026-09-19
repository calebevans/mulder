"""A failed readpst run must not be reported as a PST containing no mail.

``parse_pst`` called ``subprocess.run(...)`` without even binding the result,
so readpst's exit code was never read. When readpst fails it writes no ``.eml``
files, ``_parse_extracted_emails`` walks an empty directory and answers
``total_emails: 0``, and the wrapper indexes a bare ``"PST Analysis: <path>"``
header into the case DB and returns ``status: success``. A mailbox that was
never opened was indistinguishable from a mailbox with nothing in it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.email import parse_pst

_FAILURE = "Error: unable to open PST file: not a valid PST"


@pytest.fixture
def pst(tmp_path: Path) -> Path:
    """A .pst file that exists, so the run reaches readpst itself."""
    path = tmp_path / "mailbox.pst"
    path.write_bytes(b"!BDN" + b"\x00" * 512)
    return path


def _invoke(pst: Path, run: Any) -> tuple[Any, list[str]]:
    """Run ``parse_pst`` with readpst itself replaced by *run*."""
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {}

    kwargs = {"side_effect": run} if callable(run) else {"return_value": run}
    with (
        patch("mulder.server.tools.email.require_binary", return_value="/usr/bin/readpst"),
        patch("mulder.server.tools.email.subprocess.run", **kwargs),
        patch("mulder.server.tools.email.extract_and_index", side_effect=_record),
    ):
        result = parse_pst.__wrapped__("case-1", str(pst))  # type: ignore[attr-defined]
    return result, indexed


def _write_eml(cmd: list[str], count: int) -> None:
    """Write *count* .eml files into the -o directory readpst was given."""
    outdir = Path(cmd[cmd.index("-o") + 1])
    outdir.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (outdir / f"msg{i}.eml").write_text(
            "From: alice@example.com\n"
            "To: bob@example.com\n"
            "Subject: quarterly numbers\n"
            "Date: Mon, 1 Jan 2024 09:00:00 +0000\n"
            "Content-Type: text/plain\n"
            "\n"
            "body\n"
        )


def test_a_failed_extraction_is_an_error_not_an_empty_mailbox(pst: Path) -> None:
    """The shape that made this silent: readpst rejects the file outright."""
    proc = subprocess.CompletedProcess(args=["readpst"], returncode=1, stdout="", stderr=_FAILURE)

    result, _indexed = _invoke(pst, proc)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert "readpst" in message
    assert "exited 1" in message
    assert "not a valid PST" in message
    # A mailbox that was never opened must not claim a message count.
    assert "total_emails" not in result


def test_a_failed_extraction_is_never_summarised_into_the_case(pst: Path) -> None:
    """The sharpest edge: 'PST Analysis: <path>' entering the case DB.

    That line is a forensic assertion that the PST was read. It must not be
    manufactured from a run that never opened the file.
    """
    proc = subprocess.CompletedProcess(args=["readpst"], returncode=1, stdout="", stderr=_FAILURE)

    _result, indexed = _invoke(pst, proc)

    assert indexed == [], f"a failed extraction was indexed as a result: {indexed}"


def test_the_report_carries_stdout_when_readpst_is_silent_on_stderr(pst: Path) -> None:
    """Some readpst failures print only to stdout; the detail must survive."""
    proc = subprocess.CompletedProcess(
        args=["readpst"], returncode=2, stdout="cannot create output directory", stderr=""
    )

    result, _indexed = _invoke(pst, proc)

    assert result["status"] == "error"
    assert "cannot create output directory" in str(result["error_message"])


def test_a_genuinely_empty_pst_is_still_a_success(pst: Path) -> None:
    """Pins the fix's narrowness: exit 0 with no messages stays a success.

    An archived-but-emptied mailbox is a real answer, not a failure, and must
    keep reporting as one -- otherwise the fix trades silent failures for
    false alarms.
    """
    proc = subprocess.CompletedProcess(args=["readpst"], returncode=0, stdout="", stderr="")

    result, indexed = _invoke(pst, proc)

    assert result["status"] == "success"
    assert indexed, "a successful empty extraction must still be summarised"


def test_messages_extracted_before_a_non_zero_exit_are_kept(pst: Path) -> None:
    """readpst can fail on a corrupt folder after extracting earlier ones.

    The guard is conjunctive -- non-zero *and* no .eml written -- so recovered
    mail is never discarded because of a late failure.
    """
    written: list[int] = []

    def _extract_then_fail(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        _write_eml(cmd, 2)
        written.append(2)
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr="corrupt folder at offset 4096"
        )

    result, indexed = _invoke(pst, _extract_then_fail)

    assert written, "the fake readpst never wrote its .eml files"
    assert result["status"] == "success"
    assert indexed and "quarterly numbers" in indexed[0]
