"""A CLI tool that failed must not be reported as a clean, empty extraction.

``run_cli_tool`` never inspected ``proc.returncode``. It indexed
``proc.stdout.strip()`` -- the empty string, when the tool died before writing
anything -- and returned ``status: success``. Because ``extract_and_index``
registers a source row for empty input (``blake2b:empty``,
``status: indexed_empty``), a failed run left a durable case-DB record
asserting the extraction had happened and found nothing.

Five wrapped tools route through this wrapper: strings, hashdeep, exiftool,
ssdeep and pasco.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.extract.misc import run_exiftool, run_strings


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    """A target that exists, so the run reaches the wrapped binary."""
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"\x00" * 64)
    return path


def _invoke(
    tool: Any, target: Path, proc: subprocess.CompletedProcess[str]
) -> tuple[Any, list[str]]:
    """Run *tool* with the wrapped binary replaced by *proc*.

    ``extract_and_index`` is patched where it is defined, not on ``helpers``:
    ``run_cli_tool`` imports it inside the function body.
    """
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {"source_name": "s", "windows_indexed": 0, "line_count": 0}

    with (
        patch("mulder.server.helpers.require_binary", return_value=True),
        patch("mulder.server.helpers.run_subprocess", return_value=proc),
        patch("mulder.server.extract_helpers.extract_and_index", side_effect=_record),
    ):
        result = tool.__wrapped__(str(target))
    return result, indexed


@pytest.mark.parametrize(
    ("tool", "binary"),
    [(run_strings, "strings"), (run_exiftool, "exiftool")],
)
def test_a_failed_tool_is_an_error_not_an_empty_extraction(
    tool: Any, binary: str, evidence: Path
) -> None:
    """The observed shape: exit 1, message on stderr, nothing on stdout.

    Recorded from the real binary::

        $ strings -n8 /nonexistent/evidence.bin
        exit=1  stdout bytes=0
        stderr: strings: '/nonexistent/evidence.bin': No such file
    """
    proc = subprocess.CompletedProcess(
        args=[binary],
        returncode=1,
        stdout="",
        stderr=f"{binary}: evidence.bin: Permission denied",
    )

    result, _indexed = _invoke(tool, evidence, proc)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert binary in message
    assert "exited 1" in message
    assert "Permission denied" in message


@pytest.mark.parametrize(
    ("tool", "binary"),
    [(run_strings, "strings"), (run_exiftool, "exiftool")],
)
def test_a_failed_tool_registers_no_source_in_the_case(
    tool: Any, binary: str, evidence: Path
) -> None:
    """The durable harm: ``extract_and_index("")`` registers a source row.

    For empty input it writes a source with ``source_hash="blake2b:empty"``
    and ``status="indexed_empty"`` -- a permanent case record saying this
    extractor ran against this evidence and found nothing. A run that never
    read the evidence must not leave that behind, so the wrapper must not
    reach ``extract_and_index`` at all.
    """
    proc = subprocess.CompletedProcess(
        args=[binary], returncode=1, stdout="", stderr="cannot open input"
    )

    _result, indexed = _invoke(tool, evidence, proc)

    assert indexed == [], f"a failed {binary} run was indexed as a source: {indexed!r}"


@pytest.mark.parametrize(
    ("tool", "binary"),
    [(run_strings, "strings"), (run_exiftool, "exiftool")],
)
def test_a_genuinely_empty_result_is_still_a_success(
    tool: Any, binary: str, evidence: Path
) -> None:
    """Pins the fix's narrowness: exit 0 with no output is a real answer.

    Recorded from the real binary -- a file with no printable runs::

        $ strings -n8 zeros.bin
        exit=0  stdout bytes=0  stderr: (empty)

    That is "this evidence contains no strings", which is a finding. It must
    keep reporting as a success and must still be indexed.
    """
    proc = subprocess.CompletedProcess(args=[binary], returncode=0, stdout="", stderr="")

    result, indexed = _invoke(tool, evidence, proc)

    assert result["status"] == "success"
    assert indexed == [""], "a genuinely empty result must still register its source"


@pytest.mark.parametrize(
    ("tool", "binary"),
    [(run_strings, "strings"), (run_exiftool, "exiftool")],
)
def test_output_produced_before_a_non_zero_exit_is_kept(
    tool: Any, binary: str, evidence: Path
) -> None:
    """A tool can fail on one input after writing results for earlier ones.

    The guard is conjunctive -- non-zero *and* empty stdout -- so real output
    is never discarded because of a late failure.
    """
    proc = subprocess.CompletedProcess(
        args=[binary],
        returncode=1,
        stdout="/evidence/one.bin: MZ header found\n",
        stderr="/evidence/two.bin: Permission denied",
    )

    result, indexed = _invoke(tool, evidence, proc)

    assert result["status"] == "success"
    assert indexed == ["/evidence/one.bin: MZ header found"]


def test_whitespace_only_output_counts_as_no_output(evidence: Path) -> None:
    """The guard uses the same ``.strip()`` the index call already uses.

    A tool that emitted only a newline before dying produced nothing usable,
    and must not be treated as having output.
    """
    proc = subprocess.CompletedProcess(
        args=["strings"], returncode=1, stdout="\n  \n", stderr="read error"
    )

    result, indexed = _invoke(run_strings, evidence, proc)

    assert result["status"] == "error"
    assert indexed == []
