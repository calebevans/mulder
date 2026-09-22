"""``extract_archive`` must not unpack an archive without limit.

Nothing bounded how much a single archive could expand to, so a small
attacker-supplied zip could fill the disk the case database lives on.

The bound is deliberately a *total size* and a *member count*, never a
per-member compression ratio.  A ratio cannot tell an attack from evidence: a
zeroed 64 MiB region of a disk image compresses about 1029x, and so does a
freshly allocated VM memory dump.  The final test here pins that.
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


def _invoke(cases_dir: Path, archive: Path) -> Any:
    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
        patch("mulder.server.tools.case.EvidenceClassifier", create=True),
    ):
        return extract_archive.__wrapped__(str(archive))  # type: ignore[attr-defined]


def test_an_archive_over_the_byte_cap_is_refused(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cap is lowered for the test so no huge file is ever written."""
    monkeypatch.setattr("mulder.server.tools.case.MAX_EXTRACT_BYTES", 1024, raising=False)

    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", b"\x00" * 64_000)

    result = _invoke(cases_dir, archive)

    assert result["status"] == "error"
    assert result["error_type"] == "resource_limit"
    message = str(result["error_message"])
    assert "bomb.zip" in message
    # The refusal must be about absolute size, not about how well it compressed.
    assert "ratio" not in message.lower()


def test_an_archive_over_the_member_cap_is_refused(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("mulder.server.tools.case.MAX_EXTRACT_MEMBERS", 5, raising=False)

    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(20):
            zf.writestr(f"f{i}.txt", b"x")

    result = _invoke(cases_dir, archive)

    assert result["status"] == "error"
    assert result["error_type"] == "resource_limit"
    assert "members" in str(result["error_message"])


def test_the_refusal_says_what_was_already_written(
    cases_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A partial extraction on disk must be disclosed, not silently left."""
    monkeypatch.setattr("mulder.server.tools.case.MAX_EXTRACT_MEMBERS", 3, raising=False)

    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(10):
            zf.writestr(f"f{i}.txt", b"x")

    result = _invoke(cases_dir, archive)

    assert "file(s) were written to" in str(result["error_message"])


def test_an_ordinary_archive_still_extracts(cases_dir: Path, tmp_path: Path) -> None:
    """Pins narrowness: real evidence under the caps is untouched."""
    archive = tmp_path / "evidence.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("memory.raw", b"MEMORY" * 100)

    result = _invoke(cases_dir, archive)

    assert result["status"] == "success"
    assert result["total_files_extracted"] == 1


def test_a_zeroed_evidence_region_is_not_treated_as_a_bomb(
    cases_dir: Path, tmp_path: Path
) -> None:
    """The test that killed the compression-ratio heuristic.

    A 4 MiB run of zeroes -- an unallocated region of a disk image, or a fresh
    VM memory dump -- compresses by roughly three orders of magnitude.  Any
    ratio-based bomb detector refuses it.  It is ordinary evidence and must
    extract.
    """
    archive = tmp_path / "disk.zip"
    payload = b"\x00" * (4 * 1024 * 1024)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("unallocated.dd", payload)

    ratio = len(payload) / archive.stat().st_size
    assert ratio > 500, f"fixture only compressed {ratio:.0f}x; it must be extreme"

    result = _invoke(cases_dir, archive)

    assert result["status"] == "success", (
        f"a {ratio:.0f}x-compressible evidence region was refused: {result.get('error_message')}"
    )
    assert result["total_files_extracted"] == 1
