"""A failed MVT run must not be reported as a clean spyware scan.

``run_mvt_android`` / ``run_mvt_ios`` never read ``proc.returncode``. When MVT
fails it writes no JSON into the output directory, so ``_collect_mvt_results``
comes back empty -- and the wrapper then falls back to *indexing MVT's stderr
as if it were evidence* and returns ``status: success`` with ``detections: 0``.
A Pegasus check that never ran looked exactly like a clean phone.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.mvt import run_mvt_android, run_mvt_ios

_FAILURE = "Error: unable to open backup: not a valid Android backup"


@pytest.fixture
def backup(tmp_path: Path) -> Path:
    """An evidence path that exists, so the run reaches MVT itself."""
    path = tmp_path / "backup.ab"
    path.write_bytes(b"ANDROID BACKUP\n")
    return path


def _invoke(tool: Any, evidence: Path, proc: subprocess.CompletedProcess[str]) -> Any:
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {}

    with (
        patch("mulder.server.tools.mvt.shutil.which", return_value="/usr/bin/mvt"),
        patch("mulder.server.tools.mvt.subprocess.run", return_value=proc),
        patch("mulder.server.tools.mvt.extract_and_index", side_effect=_record),
    ):
        result = tool.__wrapped__(str(evidence))
    return result, indexed


@pytest.mark.parametrize(
    ("tool", "binary"),
    [(run_mvt_android, "mvt-android"), (run_mvt_ios, "mvt-ios")],
)
def test_a_failed_scan_is_an_error_not_a_clean_phone(tool: Any, binary: str, backup: Path) -> None:
    proc = subprocess.CompletedProcess(args=[binary], returncode=1, stdout="", stderr=_FAILURE)

    result, indexed = _invoke(tool, backup, proc)

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert binary in message
    assert "exited 1" in message
    assert "not a valid Android backup" in message
    # The scan never happened, so it must not claim a detection count.
    assert "detections" not in result


@pytest.mark.parametrize(
    ("tool", "binary"),
    [(run_mvt_android, "mvt-android"), (run_mvt_ios, "mvt-ios")],
)
def test_an_error_message_is_never_indexed_as_evidence(
    tool: Any, binary: str, backup: Path
) -> None:
    """The sharpest edge of the bug: stderr was stored in the case DB.

    A later ``search()`` over the case would return MVT's own crash text as if
    it were device evidence.
    """
    proc = subprocess.CompletedProcess(args=[binary], returncode=1, stdout="", stderr=_FAILURE)

    _result, indexed = _invoke(tool, backup, proc)

    assert indexed == [], f"MVT's failure text was indexed as evidence: {indexed}"


@pytest.mark.parametrize(
    ("tool", "binary"),
    [(run_mvt_android, "mvt-android"), (run_mvt_ios, "mvt-ios")],
)
def test_a_genuinely_clean_device_is_still_a_success(tool: Any, binary: str, backup: Path) -> None:
    """Pins the fix's narrowness: MVT exiting 0 with nothing found is a result.

    A clean phone is the common case and must keep reporting as a success.
    """
    proc = subprocess.CompletedProcess(
        args=[binary], returncode=0, stdout="No traces detected", stderr=""
    )

    result, _indexed = _invoke(tool, backup, proc)

    assert result["status"] == "success"


@pytest.mark.parametrize(
    ("tool", "binary"),
    [(run_mvt_android, "mvt-android"), (run_mvt_ios, "mvt-ios")],
)
def test_results_written_before_a_non_zero_exit_are_kept(
    tool: Any, binary: str, backup: Path
) -> None:
    """MVT can fail on one module after others already produced findings.

    The guard is conjunctive -- non-zero *and* no collected results -- so those
    findings are not thrown away.
    """
    proc = subprocess.CompletedProcess(
        args=[binary], returncode=1, stdout="", stderr="one module failed"
    )

    with patch(
        "mulder.server.tools.mvt._collect_mvt_results",
        return_value=("sms_detected: 2 entries", {"sms_detected": 2}),
    ):
        result, indexed = _invoke(tool, backup, proc)

    assert result["status"] == "success"
    assert indexed == ["sms_detected: 2 entries"]
