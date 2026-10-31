"""Regression tests for a clamscan run that failed being reported as a clean scan."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.extract.misc import run_clamav

# Recorded from clamscan 1.5.4 with an empty signature database directory.
NO_DATABASE = (
    "LibClamAV Error: cli_loaddbdir: No supported database files found in /var/lib/clamav\n"
    "ERROR: Can't open file or directory\n"
)


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    path = tmp_path / "evidence"
    path.mkdir()
    (path / "a.txt").write_text("hello\n")
    return path


def _invoke(target: Path, proc: subprocess.CompletedProcess[str]) -> tuple[Any, list[str]]:
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {"source_name": "clamav.scan", "windows_indexed": 0, "line_count": 0}

    with (
        patch("mulder.server.tools.extract.misc.require_binary", return_value=True),
        patch("mulder.server.tools.extract.misc.subprocess.run", return_value=proc),
        patch("mulder.server.tools.extract.misc.extract_and_index", side_effect=_record),
    ):
        result = run_clamav.__wrapped__(str(target))  # type: ignore[attr-defined]
    return result, indexed


def test_a_failed_scan_is_an_error_not_zero_detections(evidence: Path) -> None:
    proc = subprocess.CompletedProcess(
        args=["clamscan"], returncode=2, stdout="", stderr=NO_DATABASE
    )

    result, indexed = _invoke(evidence, proc)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert "clamscan exited 2" in message
    assert "No supported database files found" in message
    assert indexed == []


def test_a_detection_is_still_a_success(evidence: Path) -> None:
    proc = subprocess.CompletedProcess(
        args=["clamscan"],
        returncode=1,
        stdout=f"{evidence}/a.txt: Win.Test.EICAR_HDB-1 FOUND\n",
        stderr="",
    )

    result, indexed = _invoke(evidence, proc)

    assert result["status"] == "success"
    assert indexed == [f"{evidence}/a.txt: Win.Test.EICAR_HDB-1 FOUND"]
    assert '"partial"' not in str(result["preview"])


def test_a_clean_scan_is_still_a_success(evidence: Path) -> None:
    proc = subprocess.CompletedProcess(
        args=["clamscan"], returncode=0, stdout=f"{evidence}/a.txt: OK\n", stderr=""
    )

    result, indexed = _invoke(evidence, proc)

    assert result["status"] == "success"
    assert indexed == [f"{evidence}/a.txt: OK"]
    assert '"partial"' not in str(result["preview"])


def test_output_produced_before_a_non_zero_exit_is_kept(evidence: Path) -> None:
    # Recorded from clamscan 1.5.4 with one unreadable file: exit 2, nothing on stderr.
    proc = subprocess.CompletedProcess(
        args=["clamscan"],
        returncode=2,
        stdout=f"{evidence}/locked.txt: Access denied\n{evidence}/a.txt: OK\n",
        stderr="",
    )

    result, indexed = _invoke(evidence, proc)

    assert result["status"] == "success"
    assert indexed == [f"{evidence}/locked.txt: Access denied\n{evidence}/a.txt: OK"]
    preview = str(result["preview"])
    assert '"partial": true' in preview
    assert "locked.txt: Access denied" in preview


def test_a_file_that_was_not_scanned_next_to_a_detection_is_flagged(evidence: Path) -> None:
    # Recorded from clamscan 1.5.4: a detection makes it exit 1 even with an unreadable file.
    proc = subprocess.CompletedProcess(
        args=["clamscan"],
        returncode=1,
        stdout=(
            f"{evidence}/locked.txt: Access denied\n"
            f"{evidence}/a.txt: OK\n"
            f"{evidence}/bad.bin: Mulder.Test.Sig.UNOFFICIAL FOUND\n"
        ),
        stderr="",
    )

    result, _indexed = _invoke(evidence, proc)

    assert result["status"] == "success"
    preview = str(result["preview"])
    assert '"detections": 1' in preview
    assert '"partial": true' in preview
    assert "locked.txt: Access denied" in preview


def test_a_failure_reported_only_on_stderr_is_flagged(evidence: Path) -> None:
    proc = subprocess.CompletedProcess(
        args=["clamscan"],
        returncode=2,
        stdout=f"{evidence}/a.txt: OK\n",
        stderr="LibClamAV Error: cli_scanfile: read error\n",
    )

    result, _indexed = _invoke(evidence, proc)

    preview = str(result["preview"])
    assert '"partial": true' in preview
    assert "read error" in preview
