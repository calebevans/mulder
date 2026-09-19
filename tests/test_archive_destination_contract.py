"""``extract_archive`` must honour the destination contract it documents.

The docstring promises output goes to "a writable directory under the mulder
cases directory", but the code resolved ``extract_to`` and used it verbatim,
so an MCP client could unpack an attacker-supplied archive anywhere the server
could write.  Separately, the default slot was keyed on ``archive.stem``, so
two unrelated archives called ``evidence.zip`` shared one directory and the
second call reported the *first* archive's files as its own.
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


def _zip(path: Path, name: str, data: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(name, data)
    return path


def _invoke(cases_dir: Path, archive: Path, extract_to: str | None = None) -> Any:
    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
        patch("mulder.server.tools.case.EvidenceClassifier", create=True),
    ):
        return extract_archive.__wrapped__(  # type: ignore[attr-defined]
            str(archive), extract_to=extract_to
        )


def test_an_extract_to_outside_the_cases_dir_is_refused(cases_dir: Path, tmp_path: Path) -> None:
    """The documented contract, now enforced.

    Without this, ``extract_to`` is an arbitrary write primitive: the archive
    decides the filenames and the caller decides the directory.
    """
    archive = _zip(tmp_path / "eq.zip", "payload.txt", b"x")
    outside = tmp_path / "somewhere-else"

    result = _invoke(cases_dir, archive, extract_to=str(outside))

    assert result["status"] == "error"
    assert result["error_type"] == "invalid_input"
    assert "extract_to must stay under" in str(result["error_message"])
    assert not outside.exists(), "the refused destination must not be created"


def test_traversal_out_of_the_extract_root_is_refused(cases_dir: Path, tmp_path: Path) -> None:
    """``..`` segments are collapsed before the containment check, not after."""
    archive = _zip(tmp_path / "eq.zip", "payload.txt", b"x")
    escape = str(cases_dir / "extracted" / ".." / ".." / ".." / "etc")

    result = _invoke(cases_dir, archive, extract_to=escape)

    assert result["status"] == "error"
    assert result["error_type"] == "invalid_input"


def test_an_extract_to_inside_the_extract_root_is_allowed(cases_dir: Path, tmp_path: Path) -> None:
    """Pins the fix's narrowness: a legitimate explicit destination still works."""
    archive = _zip(tmp_path / "eq.zip", "payload.txt", b"hello")
    inside = cases_dir / "extracted" / "my-slot"

    result = _invoke(cases_dir, archive, extract_to=str(inside))

    assert result["status"] == "success"
    assert (inside / "payload.txt").read_bytes() == b"hello"


def test_two_archives_with_the_same_name_do_not_share_a_slot(
    cases_dir: Path, tmp_path: Path
) -> None:
    """The forensic bite: archive B reported archive A's contents as its own.

    Both are called ``evidence.zip``; only their directory differs.
    """
    a_dir = tmp_path / "seizure-a"
    b_dir = tmp_path / "seizure-b"
    a_dir.mkdir()
    b_dir.mkdir()
    a = _zip(a_dir / "evidence.zip", "from-a.txt", b"a")
    b = _zip(b_dir / "evidence.zip", "from-b.txt", b"b")

    first = _invoke(cases_dir, a)
    second = _invoke(cases_dir, b)

    assert first["status"] == "success"
    assert second["status"] == "success"
    assert first["extracted_to"] != second["extracted_to"]

    b_files = list(Path(str(second["extracted_to"])).rglob("*.txt"))
    assert [f.name for f in b_files] == ["from-b.txt"], (
        f"archive B's slot holds {[f.name for f in b_files]}"
    )


def test_the_slot_is_stable_for_one_archive(tmp_path: Path) -> None:
    """Idempotency must survive: the same archive maps to the same slot."""
    from mulder.server.tools.case import _archive_slot

    archive = tmp_path / "evidence.zip"
    assert _archive_slot(archive) == _archive_slot(archive)
    assert archive.stem in _archive_slot(archive)


def test_the_slot_differs_for_same_named_archives_elsewhere(tmp_path: Path) -> None:
    from mulder.server.tools.case import _archive_slot

    a = tmp_path / "one" / "evidence.zip"
    b = tmp_path / "two" / "evidence.zip"
    assert _archive_slot(a) != _archive_slot(b)
