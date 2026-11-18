"""A triage collection is one evidence item, and each phase is told what it is."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import mulder.server.tools.review  # noqa: F401 ensure tools are registered
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.extractors.classifier import ClassifiedEvidence, EvidenceClassifier
from mulder.orchestrator import prompts
from mulder.orchestrator.evidence import EvidenceContext
from mulder.orchestrator.types import PhaseResult
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools.case import _manifest_entry
from mulder.server.tools.review import (
    _EVIDENCE_INPUT_PARAMS,
    _EVIDENCE_TOOL_MAP,
    _UNPACKED_EVIDENCE_TYPES,
)
from tests.triage_trees import UAC_NAME, kape, uac, velociraptor, windows_volume, write

_FALLBACK = "No pre-populated paths available"
_PROMPTS = {
    p.stem: p.read_text(encoding="utf-8") for p in Path(prompts.__file__).parent.glob("*.md")
}


def _types(root: Path) -> dict[str, str]:
    return {
        str(c.path.relative_to(root.resolve())): c.artifact_type
        for c in EvidenceClassifier().classify(root)
    }


def test_each_collection_is_one_item_not_one_per_file(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    kape(root / "ws01-kape")
    velociraptor(root / "Collection-DESKTOP-9")
    uac(root)
    windows_volume(root / "export" / "C")
    write(root, {"dc01.E01": b"EVF", "loose/Security.evtx": b"ElfFile"})

    assert _types(root) == {
        "Collection-DESKTOP-9": "triage_collection",
        "dc01.E01": "disk_image",
        "export/C": "triage_collection",  # a drive-letter tree with no KAPE logs
        "loose/Security.evtx": "evtx",  # outside any collection: classified as before
        UAC_NAME: "triage_collection",
        "ws01-kape": "triage_collection",
    }


def test_the_evidence_directory_may_itself_be_the_collection(tmp_path: Path) -> None:
    root = kape(tmp_path / "evidence")
    write(root, {"memory.raw": b"\x00" * 64, "notes.txt": "taken 12:39"})

    # One item for the collection; a memory dump left beside KAPE's output is
    # still evidence of its own, KAPE's logs and other loose files are not.
    assert _types(root) == {".": "triage_collection", "memory.raw": "memory_dump"}


def test_the_catalog_is_shown_the_layout_and_the_host(tmp_path: Path) -> None:
    root = kape(tmp_path / "k")

    entry = _manifest_entry(ClassifiedEvidence(path=root, artifact_type="triage_collection"))

    assert entry["collection"] == "KAPE target output, host WS-01"
    assert "not a disk image" in str(entry["note"])


def _context(
    root: Path,
    name: str,
    evidence: list[str] | None = None,
    extracted: Path | None = None,
) -> str:
    ctx = EvidenceContext(str(root), extracted_dir=extracted or root.parent / "no-extractions")
    systems = [{"name": name, "type": "Windows", "evidence": evidence or ["triage_collection"]}]
    systems.append({"name": "dc01", "type": "Windows", "evidence": ["disk_image"]})
    ctx.identify_systems(
        PhaseResult(phase_name="catalog", messages=[]), cached_catalog_data={"systems": systems}
    )
    return ctx.build_evidence_context(name)


def test_the_planner_is_given_the_path_and_how_to_pass_it(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    collection = kape(root / "ws01-kape")
    write(root, {"dc01.E01": b"EVF"})

    text = _context(root, "ws01")

    assert 'Triage collections (type "triage_collection"' in text
    assert f"  {collection}  (KAPE target output, host WS-01)" in text
    assert "index_triage_collection(evidence_path=<directory>)" in text
    assert "image_path (run_registry_parser" in text and "evtx_dir of run_hayabusa" in text
    assert "Do not plan run_mmls, run_bulk_extractor" in text
    assert "run_mactime" not in text  # only a UAC collection has a body file
    assert _FALLBACK not in text and "dc01.E01" not in text

    other = _context(root, "dc01", ["disk_image"])
    assert "Triage collections" not in other and "dc01.E01" in other


def test_a_system_named_for_the_host_gets_its_collection(tmp_path: Path) -> None:
    """The catalog is told to use the host name, which is in no path here."""
    root = tmp_path / "evidence"
    collection = kape(root / "Extracted")

    assert f"  {collection}  (" in _context(root, "WS-01", ["memory_dump"])
    # Named neither for the host nor the directory: the catalog's type decides,
    # as long as no other system claims the collection.
    assert f"  {collection}  (" in _context(root, "Finance laptop")
    assert "Triage collections" not in _context(root, "Finance laptop", ["memory_dump"])


def test_a_uac_collection_is_planned_with_its_body_file_timeline(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    collection = uac(root)

    text = _context(root, "web01")

    assert f"  {collection}  (UAC collection, host web01)" in text
    assert "run_mactime(image_path=<directory>)" in text
    assert "Windows files" not in text


def test_collected_files_are_not_listed_as_dumps_images_or_archives(tmp_path: Path) -> None:
    """A SOFTWARE hive over 100 MB in an unpacked archive was 'ready for Volatility'."""
    root = tmp_path / "evidence"
    kape(root / "ws01-kape")
    write(
        root / "ws01-kape",
        {"C/Windows/MEMORY.DMP": b"PAGEDU64", "C/Users/a/backup.zip": b"PK", "C/x.dd": b"\x00"},
    )
    extracted = tmp_path / "extracted"
    slot = velociraptor(extracted / "Collection-ws01-abc123")
    with (slot / "uploads/auto/C%3A/Windows/System32/config/SOFTWARE").open("wb") as fh:
        fh.truncate(101 * 1024 * 1024)  # sparse

    text = _context(root, "ws01", extracted=extracted)

    assert f"  {slot}  (Velociraptor offline collection, host DESKTOP-9)" in text
    for wrong in ("memory dumps", "NESTED ARCHIVES", "Disk images", "SOFTWARE", "MEMORY.DMP"):
        assert wrong not in text


def test_a_kape_container_unpacked_from_a_zip_is_a_disk_image(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    extracted = tmp_path / "extracted"
    vhdx = extracted / "ws01-kape-abc123" / "2023-03-24T123901_Triage_ws01.vhdx"
    vhdx.parent.mkdir(parents=True)
    with vhdx.open("wb") as fh:
        fh.truncate(101 * 1024 * 1024)

    text = _context(root, "ws01", ["disk_image"], extracted)

    assert f"Disk images:\n  {vhdx}" in text and "memory dumps" not in text


def test_the_coverage_audit_flags_a_collection_nobody_indexed(tmp_path: Path) -> None:
    assert _EVIDENCE_TOOL_MAP["triage_collection"] == ["index_triage_collection"]
    # The name start_extraction_batch scopes its already-indexed check by.
    assert _EVIDENCE_INPUT_PARAMS["index_triage_collection"] == ("evidence_path",)
    assert "triage_collection" in _UNPACKED_EVIDENCE_TYPES

    root = tmp_path / "evidence"
    done = kape(root / "ws01-kape")
    db_dir = tmp_path / "db"
    unpacked = velociraptor(db_dir / "extracted" / "cov" / "Collection-ws02-abc123")
    db = CaseDB.create(case_id="cov", evidence_root=str(root), db_dir=db_dir)
    audit = AuditLog(db_dir / "cov.audit.jsonl")
    audit.log_tool_call("tc_0", "index_triage_collection", {"evidence_path": str(done)}, "h")
    ctx = MagicMock(db=db, audit=audit, case_id="cov")
    try:
        with (
            patch("mulder.server.tools.review.get_ctx", return_value=ctx),
            patch("mulder.server.tools.review.get_cfg", return_value=MagicMock(db_dir=db_dir)),
        ):
            result = _tool_dispatch_sync["audit_tool_coverage"]()
    finally:
        db.close()

    gaps = {str(item["path"]): item["tools_not_run"] for item in result["coverage"]}
    assert gaps == {str(done): [], str(unpacked): ["index_triage_collection"]}


def test_each_role_is_told_what_a_collection_is_and_is_not() -> None:
    catalog, planner, analyst = (
        _PROMPTS[name] for name in ("catalog", "extract_planner", "extract_analyst")
    )

    assert '"triage_collection"' in catalog and 'host name shown\n  after "host"' in catalog
    section = planner.split("TRIAGE COLLECTIONS", 1)[1].split("\n\nWhen the evidence", 1)[0]
    assert "index_triage_collection" in section and "as image_path" in section
    assert "Do NOT plan run_mmls, run_fsstat, run_bulk_extractor" in section
    assert 'means "not collected"' in section
    section = analyst.split("TRIAGE COLLECTIONS:", 1)[1].split("EVIDENCE OUTSIDE THE CASE", 1)[0]
    assert 'write "not collected"' in section and 'never "not present"' in section
    assert "those of the copy" in section and "triage.kape.copylog" in section


def _unpack(archive: str, cases: Path) -> dict[str, Any]:
    with (
        patch("mulder.server.tools.case.get_cfg", return_value=MagicMock(db_dir=cases)),
        patch("mulder.server.tools.case.has_ctx", return_value=False),
    ):
        return dict(_tool_dispatch_sync["extract_archive"](archive_path=archive))


def test_a_collection_delivered_as_an_archive_is_recognised_where_it_lands(
    tmp_path: Path,
) -> None:
    """Velociraptor writes a zip, UAC a tar.gz, KAPE a zip when asked to."""
    cases = tmp_path / "cases"
    cases.mkdir()
    archives = {
        "velociraptor": shutil.make_archive(
            str(tmp_path / "Collection-DESKTOP-9"), "zip", velociraptor(tmp_path / "v")
        ),
        "uac": shutil.make_archive(str(tmp_path / UAC_NAME), "gztar", uac(tmp_path / "u")),
        "kape": shutil.make_archive(str(tmp_path / "ws01"), "zip", kape(tmp_path / "k")),
    }

    found = {name: _unpack(archive, cases) for name, archive in archives.items()}

    for result in found.values():
        assert result["status"] == "success"
        assert result["type_summary"] == {"triage_collection": 1}
        assert [c["path"] for c in result["triage_collections"]] == [result["extracted_to"]]
    assert {n: r["triage_collections"][0]["collection"] for n, r in found.items()} == {
        "velociraptor": "Velociraptor offline collection, host DESKTOP-9",
        "uac": "UAC collection, host web01",  # from the name UAC gave the archive
        "kape": "KAPE target output, host WS-01",
    }
