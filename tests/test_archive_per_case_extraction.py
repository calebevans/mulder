"""An archive extraction belongs to one case.

Every case shares the cases directory, and the default extraction slot was
keyed on the archive path alone.  A new case whose archive sat at the same
path -- the documented container layout mounts evidence at ``/evidence`` and
keeps the cases directory between runs -- was answered ``already_extracted``
with the previous case's files, while the case's evidence registry held the
new archive's hash.

The investigate evidence context and the YARA memory fallback read a shared
``extracted/`` root (the former a hard-coded ``~/.mulder`` path) and offered
another case's memory dumps as this case's.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder import patterns
from mulder.orchestrator.evidence import EvidenceContext
from mulder.server.tools import yara
from mulder.server.tools.case import extract_archive


def case_extract_dir(cases_dir: Path, case_id: str) -> Path:
    """Where one case's extractions live (``mulder.patterns.case_extract_dir``)."""
    return cases_dir / "extracted" / case_id


@pytest.fixture
def cases_dir(tmp_path: Path) -> Path:
    d = tmp_path / "cases"
    d.mkdir()
    return d


def _zip(path: Path, members: dict[str, bytes]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def _invoke(
    cases_dir: Path, archive: Path, case_id: str | None = None, extract_to: Path | None = None
) -> Any:
    cfg = MagicMock()
    cfg.db_dir = cases_dir
    ctx = MagicMock()
    ctx.case_id = case_id
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=cfg),
        patch("mulder.server.tools.case.has_ctx", return_value=case_id is not None),
        patch("mulder.server.tools.case.get_ctx", return_value=ctx),
    ):
        return extract_archive.__wrapped__(  # type: ignore[attr-defined]
            str(archive), extract_to=str(extract_to) if extract_to else None
        )


def _txt(result: Any) -> list[str]:
    return sorted(p.name for p in Path(str(result["extracted_to"])).rglob("*.txt"))


def test_a_new_case_does_not_inherit_another_cases_extraction(
    cases_dir: Path, tmp_path: Path
) -> None:
    """The same /evidence path holds a different seizure for the second case."""
    archive = tmp_path / "evidence" / "base-dc.zip"
    _zip(archive, {"from-a.txt": b"a"})
    first = _invoke(cases_dir, archive, case_id="case-a")

    _zip(archive, {"from-b.txt": b"b"})
    second = _invoke(cases_dir, archive, case_id="case-b")

    assert first["status"] == "success"
    assert second["status"] == "success", "case-b was handed case-a's extraction"
    assert _txt(second) == ["from-b.txt"]
    assert _txt(first) == ["from-a.txt"], "case-a's extraction must stay as it was"


def test_each_case_extracts_into_its_own_directory(cases_dir: Path, tmp_path: Path) -> None:
    archive = _zip(tmp_path / "evidence.zip", {"one.txt": b"1"})

    a = _invoke(cases_dir, archive, case_id="case-a")
    b = _invoke(cases_dir, archive, case_id="case-b")

    assert Path(str(a["extracted_to"])).parent == case_extract_dir(cases_dir, "case-a")
    assert Path(str(b["extracted_to"])).parent == case_extract_dir(cases_dir, "case-b")
    assert b["status"] == "success"


def test_the_same_case_still_reuses_a_finished_extraction(cases_dir: Path, tmp_path: Path) -> None:
    """Pins narrowness: idempotency within one case must survive."""
    archive = _zip(tmp_path / "evidence.zip", {"one.txt": b"1"})

    _invoke(cases_dir, archive, case_id="case-a")
    again = _invoke(cases_dir, archive, case_id="case-a")

    assert again["status"] == "already_extracted"
    assert again["files"] == ["one.txt"]


@pytest.mark.parametrize(
    "where",
    [
        pytest.param(("case-a", "x"), id="another case's directory"),
        pytest.param(("x",), id="the shared extracted root"),
    ],
)
def test_extract_to_must_stay_in_the_open_case(
    cases_dir: Path, tmp_path: Path, where: tuple[str, ...]
) -> None:
    archive = _zip(tmp_path / "evidence.zip", {"one.txt": b"1"})

    result = _invoke(
        cases_dir, archive, case_id="case-b", extract_to=cases_dir.joinpath("extracted", *where)
    )

    assert result["status"] == "error"
    assert result["error_type"] == "invalid_input"
    assert str(case_extract_dir(cases_dir, "case-b")) in str(result["error_message"])


def test_extract_to_inside_the_open_case_is_allowed(cases_dir: Path, tmp_path: Path) -> None:
    archive = _zip(tmp_path / "evidence.zip", {"one.txt": b"1"})
    dest = case_extract_dir(cases_dir, "case-b") / "chosen"

    result = _invoke(cases_dir, archive, case_id="case-b", extract_to=dest)

    assert result["status"] == "success"
    assert (dest / "one.txt").is_file()


@pytest.mark.parametrize("case_id", [".", ".."])
def test_a_dot_case_id_does_not_name_an_extraction_directory(
    cases_dir: Path, case_id: str
) -> None:
    """validate_case_id accepts these, but as a directory name they are not the case's own."""
    with pytest.raises(ValueError, match="cannot name an extraction directory"):
        patterns.case_extract_dir(cases_dir, case_id)


def _context(cases_dir: Path, evidence: Path, case_id: str) -> str:
    ctx = EvidenceContext(str(evidence), extracted_dir=case_extract_dir(cases_dir, case_id))
    return ctx.build_evidence_context("base-dc")


def test_evidence_context_lists_only_this_cases_extractions(
    cases_dir: Path, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for case_id, dump in (("case-a", "a.mem"), ("case-b", "b.mem")):
        slot = case_extract_dir(cases_dir, case_id) / "base-dc-123456789abc"
        slot.mkdir(parents=True)
        (slot / dump).write_bytes(b"m")

    text = _context(cases_dir, evidence, "case-b")

    assert "b.mem" in text
    assert "a.mem" not in text, "another case's memory dump was offered"


def test_the_orchestrator_reads_extractions_under_its_db_dir(tmp_path: Path) -> None:
    """--db-dir must be honoured; the path was hard-coded to ~/.mulder/cases."""
    from mulder.orchestrator.runner import Orchestrator

    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator(
            evidence_path=str(tmp_path / "evidence"), case_id="case-x", db_dir=tmp_path / "db"
        )

    assert orch._evidence.extracted_dir == tmp_path / "db" / "extracted" / "case-x"


def _find_memory(cases_dir: Path, case_id: str) -> str:
    ctx = MagicMock()
    ctx.case_id = case_id
    ctx.db.get_sources.return_value = []
    ctx.db.get_case_metadata.return_value = MagicMock(evidence_root="")
    cfg = MagicMock()
    cfg.db_dir = cases_dir
    with (
        patch.object(yara, "get_ctx", return_value=ctx),
        patch("mulder.server.app.get_cfg", return_value=cfg),
    ):
        return yara._find_memory_image()


def test_yara_fallback_ignores_another_cases_memory_dump(cases_dir: Path) -> None:
    other = case_extract_dir(cases_dir, "case-a") / "mem-111111111111"
    other.mkdir(parents=True)
    (other / "memory.raw").write_bytes(b"m")

    with pytest.raises(RuntimeError, match="No memory sources"):
        _find_memory(cases_dir, "case-b")


def test_yara_fallback_finds_this_cases_memory_dump(cases_dir: Path) -> None:
    own = case_extract_dir(cases_dir, "case-b") / "mem-222222222222"
    own.mkdir(parents=True)
    (own / "memory.raw").write_bytes(b"m")

    assert _find_memory(cases_dir, "case-b") == str(own / "memory.raw")
