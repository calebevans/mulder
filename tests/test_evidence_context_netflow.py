"""build_evidence_context lists nfcapd directories for the extraction planner.

The block appears when the exporter directory's relative path contains the catalog's
system name, or, failing that, when the catalog assigns ``netflow_capture`` to that
system; otherwise the pristine ``list_directory`` fallback is kept.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mulder.orchestrator.evidence import EvidenceContext
from mulder.orchestrator.types import PhaseResult
from tests.netflow_harness import yday

_MAGIC = b"\x0c\xa5\x02\x00"
_FALLBACK = "No pre-populated paths available"
_HEADER = "NetFlow (nfdump nfcapd files; pass the DIRECTORY as evidence_path"
_MISMATCH_NOTE = "directory name does not contain the system name"


@pytest.fixture()
def tree(tmp_path: Path) -> tuple[Path, Path]:
    """Evidence root with 28 magic-valid daily files under .../netflow/edge-router/2001/02."""
    root = tmp_path / "evidence"
    exporter = root / "netflow" / "edge-router"
    day_dir = exporter / "2001" / "02"
    day_dir.mkdir(parents=True)
    for day in range(48, 76):
        (day_dir / f"nfcapd.{yday(day)}0000").write_bytes(_MAGIC + b"\x00" * 60)
    (exporter / "zero-length").write_bytes(b"")
    (day_dir / "nfcapd.200103035555").write_text("not a netflow file\n")
    (root / "host-b").mkdir(parents=True)
    (root / "host-b" / "auth.log").write_text("Mar  4 12:38:02 sshd\n")
    return root, day_dir


def _catalog(ctx: EvidenceContext, name: str, evidence: list[str]) -> None:
    result = PhaseResult(phase_name="catalog", messages=[])
    data = {"systems": [{"name": name, "type": "Network", "evidence": evidence}]}
    names, returned = ctx.identify_systems(result, cached_catalog_data=data)
    assert names == [name]
    assert returned is data


def test_matching_system_name_lists_directory(tree: tuple[Path, Path]) -> None:
    root, day_dir = tree
    text = EvidenceContext(str(root)).build_evidence_context("edge-router")

    assert text.startswith("System: edge-router\n")
    assert _HEADER in text
    assert f"  {day_dir}  (28 files, nfcapd.200102170000 .. nfcapd.200103160000)" in text
    assert "run_netflow_inventory, run_netflow_sweep" in text
    assert "run_netflow_host_profile, run_netflow_pair_timeline, run_netflow_query" in text
    assert _FALLBACK not in text
    assert _MISMATCH_NOTE not in text
    # the strays are not counted and the empty exporter dir is not listed
    assert "zero-length" not in text
    assert str(day_dir.parent.parent) + "  (" not in text


def test_name_match_is_case_insensitive(tree: tuple[Path, Path]) -> None:
    root, day_dir = tree
    text = EvidenceContext(str(root)).build_evidence_context("EDGE-ROUTER")
    assert f"  {day_dir}  (28 files" in text
    assert _FALLBACK not in text


def test_catalog_evidence_rescues_mismatched_name(tree: tuple[Path, Path]) -> None:
    root, day_dir = tree
    ctx = EvidenceContext(str(root))
    _catalog(ctx, "Primary router", ["netflow_capture"])
    text = ctx.build_evidence_context("Primary router")

    assert _HEADER in text
    assert f"  {day_dir}  (28 files, nfcapd.200102170000 .. nfcapd.200103160000)" in text
    assert _MISMATCH_NOTE in text
    assert _FALLBACK not in text


def test_mismatched_name_without_netflow_evidence_falls_back(tree: tuple[Path, Path]) -> None:
    root, _ = tree
    ctx = EvidenceContext(str(root))
    _catalog(ctx, "Primary router", ["log_file"])
    text = ctx.build_evidence_context("Primary router")

    assert _FALLBACK in text
    assert _HEADER not in text
    assert "nfcapd" not in text


def test_unknown_system_without_catalog_falls_back(tree: tuple[Path, Path]) -> None:
    root, _ = tree
    text = EvidenceContext(str(root)).build_evidence_context("other")
    assert _FALLBACK in text
    assert _HEADER not in text


def test_catalog_systems_reset_on_each_identify(tree: tuple[Path, Path]) -> None:
    root, _ = tree
    ctx = EvidenceContext(str(root))
    _catalog(ctx, "Primary router", ["netflow_capture"])
    _catalog(ctx, "host-b", ["log_file"])
    text = ctx.build_evidence_context("Primary router")
    assert _FALLBACK in text
    assert _HEADER not in text


def test_no_netflow_files_keeps_pristine_output(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    (root / "host-a").mkdir(parents=True)
    (root / "host-a" / "memory.raw").write_bytes(b"\x00" * 16)
    ctx = EvidenceContext(str(root))
    _catalog(ctx, "host-a", ["netflow_capture"])
    text = ctx.build_evidence_context("host-a")
    assert "Extracted memory dumps" in text
    assert _HEADER not in text
    assert _FALLBACK not in text


def test_missing_evidence_root_falls_back(tmp_path: Path) -> None:
    text = EvidenceContext(str(tmp_path / "missing")).build_evidence_context("edge-router")
    assert _FALLBACK in text


# ---------------------------------------------------------------------------
# extracted archives, lenient catalog matching, per-walk sibling cache
# ---------------------------------------------------------------------------


def _write_files(day_dir: Path, days: range) -> None:
    day_dir.mkdir(parents=True, exist_ok=True)
    for day in days:
        (day_dir / f"nfcapd.{yday(day)}0000").write_bytes(_MAGIC + b"\x00" * 60)


def test_netflow_extracted_from_an_archive_is_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """extract_archive unpacks into a ``<stem>-<digest>`` slot below ``~/.mulder``; the NetFlow
    pass scans slots whose name contains the system name, like the memory-dump pass."""
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "annex-probe-netflow.zip").write_bytes(b"PK\x03\x04" + b"\x00" * 30)
    slot = home / ".mulder" / "cases" / "extracted" / "annex-probe-netflow-0123456789ab"
    day_dir = slot / "annex-probe" / "2001" / "02"
    _write_files(day_dir, range(48, 51))
    (slot / "annex-probe" / "mem.raw").write_bytes(b"\x00" * 16)
    ctx = EvidenceContext(str(root))
    _catalog(ctx, "annex-probe", ["netflow_capture", "memory_dump"])
    text = ctx.build_evidence_context("annex-probe")
    assert "Extracted memory dumps" in text and "NESTED ARCHIVES" in text
    assert _HEADER in text
    assert f"  {day_dir}  (3 files, nfcapd.200102170000 .. nfcapd.200102190000)" in text
    assert _MISMATCH_NOTE not in text  # the slot is filtered by system name: it is "mine"
    assert _FALLBACK not in text
    # a slot for another system is not attributed to this one
    other = home / ".mulder" / "cases" / "extracted" / "branch-probe-netflow-abcdef012345"
    _write_files(other / "branch-probe" / "2001" / "02", range(52, 54))
    text = EvidenceContext(str(root)).build_evidence_context("annex-probe")
    assert str(day_dir) in text and str(other) not in text


def test_catalog_evidence_match_is_lenient_about_the_type_string(tree: tuple[Path, Path]) -> None:
    """A catalog that writes "NetFlow" instead of the literal "netflow_capture" still gets the
    NetFlow block, not the list_directory fallback."""
    root, day_dir = tree
    for evidence in (["NetFlow"], ["netflow capture (nfdump)"], ["Netflow_Capture"]):
        ctx = EvidenceContext(str(root))
        _catalog(ctx, "Primary router", evidence)
        text = ctx.build_evidence_context("Primary router")
        assert _HEADER in text and f"  {day_dir}  (28 files" in text, evidence
        assert _MISMATCH_NOTE in text and _FALLBACK not in text
        assert "several exporter directories" not in text  # one directory: no choose-one note


def _two_exporters(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "evidence"
    a = root / "netflow" / "edge-router" / "2001" / "02"
    b = root / "netflow" / "branch-probe" / "2001" / "02"
    _write_files(a, range(48, 53))
    _write_files(b, range(48, 51))
    return root, a, b


def test_rescue_path_drops_directories_claimed_by_another_catalog_system(tmp_path: Path) -> None:
    """With two exporters, a descriptively named system is shown only the directory no other
    system claims by name."""
    root, a, b = _two_exporters(tmp_path)
    ctx = EvidenceContext(str(root))
    result = PhaseResult(phase_name="catalog", messages=[])
    data = {"systems": [
        {"name": "Primary router", "type": "Network", "evidence": ["netflow_capture"]},
        {"name": "branch-probe", "type": "Network", "evidence": ["netflow_capture"]},
    ]}  # fmt: skip
    ctx.identify_systems(result, cached_catalog_data=data)
    # the compliant name gets exactly its own directory, no note
    text = ctx.build_evidence_context("branch-probe")
    assert str(b) in text and str(a) not in text and _MISMATCH_NOTE not in text
    # the descriptive name is rescued with the directory nobody else claims by name
    text = ctx.build_evidence_context("Primary router")
    assert str(a) in text and str(b) not in text
    assert _MISMATCH_NOTE in text and "several exporter directories" not in text
    # two descriptive names: both directories are shown, with the choose-one note
    data = {"systems": [
        {"name": "Primary router", "type": "Network", "evidence": ["netflow_capture"]},
        {"name": "Branch office", "type": "Network", "evidence": ["netflow_capture"]},
    ]}  # fmt: skip
    ctx.identify_systems(result, cached_catalog_data=data)
    text = ctx.build_evidence_context("Branch office")
    assert str(a) in text and str(b) in text
    assert _MISMATCH_NOTE in text
    assert "several exporter directories; plan only the one that belongs to this system" in text


def test_sibling_cache_is_cleared_per_walk(tmp_path: Path) -> None:
    """The sibling cache behind is_nfcapd is cleared on every walk: a directory first walked
    before it held a rotation-named file is sniffed again once it holds one."""
    root = tmp_path / "evidence"
    day_dir = root / "netflow" / "edge-router" / "2001" / "02"
    day_dir.mkdir(parents=True)
    (day_dir / "exported-flows").write_bytes(_MAGIC + b"\x00" * 60)  # renamed capture, alone
    ctx = EvidenceContext(str(root))
    assert _HEADER not in ctx.build_evidence_context("edge-router")
    (day_dir / "nfcapd.200103040000").write_bytes(_MAGIC + b"\x00" * 60)
    text = ctx.build_evidence_context("edge-router")
    assert f"  {day_dir}  (2 files, exported-flows .. nfcapd.200103040000)" in text
