"""A half-finished extraction must not be reported as a finished one.

``extract_archive`` decided an archive was already unpacked with

    if dest.exists() and any(dest.iterdir()):

but the presence of files proves only that an extraction *started*.  A run
killed by the 600s timeout, a full disk, or a crash leaves a partial tree that
is indistinguishable from a complete one by that test -- so every later call
returned ``already_extracted`` with a truncated file list and never retried.
The missing evidence is silently missing, permanently.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools.case import extract_archive


@pytest.fixture
def cases_dir(tmp_path: Path) -> Path:
    d = tmp_path / "cases"
    d.mkdir()
    return d


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    a = tmp_path / "evidence.zip"
    with zipfile.ZipFile(a, "w") as zf:
        zf.writestr("one.txt", b"1")
        zf.writestr("two.txt", b"2")
        zf.writestr("three.txt", b"3")
    return a


def _invoke(cases_dir: Path, archive: Path, extract_to: Path | None = None) -> Any:
    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
        patch("mulder.server.tools.case.EvidenceClassifier", create=True),
    ):
        return extract_archive.__wrapped__(  # type: ignore[attr-defined]
            str(archive), extract_to=str(extract_to) if extract_to else None
        )


def test_a_partial_extraction_is_retried_not_reported_complete(
    cases_dir: Path, archive: Path, tmp_path: Path
) -> None:
    """The debris of a killed run must not satisfy the idempotency check."""
    dest = tmp_path / "partial"
    dest.mkdir()
    (dest / "one.txt").write_bytes(b"1")  # a crash left exactly one file

    result = _invoke(cases_dir, archive, extract_to=dest)

    assert result["status"] == "success", (
        f"a one-file partial tree was accepted as complete: {result.get('status')}"
    )
    assert result["total_files_extracted"] == 3
    assert (dest / "three.txt").is_file(), "the missing evidence was never recovered"


def test_a_finished_extraction_is_still_idempotent(
    cases_dir: Path, archive: Path, tmp_path: Path
) -> None:
    """Pins narrowness: the idempotency behaviour itself must survive."""
    dest = tmp_path / "done"

    first = _invoke(cases_dir, archive, extract_to=dest)
    second = _invoke(cases_dir, archive, extract_to=dest)

    assert first["status"] == "success"
    assert second["status"] == "already_extracted"
    assert sorted(second["files"]) == ["one.txt", "three.txt", "two.txt"]


def test_the_marker_is_not_reported_as_evidence(
    cases_dir: Path, archive: Path, tmp_path: Path
) -> None:
    """mulder's own bookkeeping file must never appear in a file list."""
    dest = tmp_path / "done"

    first = _invoke(cases_dir, archive, extract_to=dest)
    second = _invoke(cases_dir, archive, extract_to=dest)

    assert first["total_files_extracted"] == 3
    assert all(not f.startswith(".mulder") for f in second["files"]), second["files"]


def test_a_marker_from_a_different_archive_does_not_count(
    cases_dir: Path, archive: Path, tmp_path: Path
) -> None:
    """A slot reused by another archive must not inherit its completion."""
    dest = tmp_path / "shared"
    _invoke(cases_dir, archive, extract_to=dest)

    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as zf:
        zf.writestr("other.txt", b"o")

    result = _invoke(cases_dir, other, extract_to=dest)

    assert result["status"] == "success"
    assert (dest / "other.txt").is_file()
