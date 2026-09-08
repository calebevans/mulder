"""A failed PhotoRec run must not be indexed as an authoritative empty carve.

``run_photorec`` discarded PhotoRec's ``CompletedProcess`` entirely -- return
code and stderr were never examined. When PhotoRec failed it wrote neither
``report.xml`` nor any carved file, and the wrapper synthesised the string
``"PhotoRec recovered 0 file(s):"`` and indexed *that* into the case DB as the
result. An analyst searching the case later reads a confident statement that
the disk image contained nothing recoverable.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.extract.carving import run_photorec


@pytest.fixture
def image(tmp_path: Path) -> Path:
    """A disk image that exists, so the run reaches PhotoRec itself."""
    path = tmp_path / "evidence.dd"
    path.write_bytes(b"\x00" * 4096)
    return path


def _invoke(image: Path, proc_or_fn: Any) -> tuple[Any, list[str]]:
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {}

    kwargs = {"side_effect": proc_or_fn} if callable(proc_or_fn) else {"return_value": proc_or_fn}
    with (
        patch("mulder.server.tools.extract.carving.require_binary", return_value=True),
        patch(
            "mulder.server.tools.extract.carving.sources_already_indexed",
            return_value=[],
        ),
        patch("mulder.server.tools.extract.carving._check_disk_space", return_value=None),
        patch("mulder.server.tools.extract.carving.subprocess.run", **kwargs),
        patch("mulder.server.tools.extract.carving.extract_and_index", side_effect=_record),
    ):
        result = run_photorec.__wrapped__(str(image))  # type: ignore[attr-defined]
    return result, indexed


def test_a_failed_carve_is_an_error_not_an_empty_result(image: Path) -> None:
    proc = subprocess.CompletedProcess(
        args=["photorec"],
        returncode=1,
        stdout="",
        stderr="photorec: cannot open evidence.dd: Permission denied",
    )

    result, _indexed = _invoke(image, proc)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert "exited 1" in message
    assert "Permission denied" in message


def test_the_zero_files_claim_is_never_written_to_the_case(image: Path) -> None:
    """The sharpest edge: 'PhotoRec recovered 0 file(s)' entering the case DB.

    That sentence is a forensic assertion about the evidence. It must not be
    manufactured from a run that never read the image.
    """
    proc = subprocess.CompletedProcess(
        args=["photorec"], returncode=1, stdout="", stderr="cannot open device"
    )

    _result, indexed = _invoke(image, proc)

    assert indexed == [], f"a failed carve was indexed as a result: {indexed}"


def test_a_genuinely_empty_image_is_still_a_success(image: Path) -> None:
    """Pins the fix's narrowness: PhotoRec exiting 0 having carved nothing.

    A wiped or genuinely empty image is a real answer and must keep reporting
    as a success -- otherwise the fix trades silent failures for false alarms.
    """
    proc = subprocess.CompletedProcess(args=["photorec"], returncode=0, stdout="", stderr="")

    result, indexed = _invoke(image, proc)

    assert result["status"] == "success"
    assert indexed and "recovered 0 file(s)" in indexed[0]


def test_files_carved_before_a_non_zero_exit_are_kept(image: Path) -> None:
    """PhotoRec can hit a bad sector after recovering real files.

    The guard is conjunctive -- non-zero *and* nothing carved -- so recovered
    evidence is never discarded because of a late failure.
    """

    def _carve(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        outdir = Path(cmd[-1].split(",", 1)[1])
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "f0000001.jpg").write_bytes(b"\xff\xd8\xff")
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr="read error at sector 99"
        )

    result, indexed = _invoke(image, _carve)

    assert result["status"] == "success"
    assert indexed and "recovered 1 file(s)" in indexed[0]
