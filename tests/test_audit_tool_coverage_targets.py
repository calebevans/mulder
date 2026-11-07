"""audit_tool_coverage must credit a tool only to the evidence a call ran on.

The coverage audit used to collect tool names from the whole case's audit log,
so one ``run_fls`` on ``disk-a.dd`` also listed ``run_fls`` as run for every
other disk image in the case (#269). A call now counts for an item only when
one of the tool's evidence-input parameters names that item or a directory
holding it, compared the way the tool reads the path. Output locations such as
``extract_to`` never count, and a path that matches no item counts for none.
"""

from __future__ import annotations

import inspect
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server.app import _tool_dispatch_sync

# Every module that defines a tool in _EVIDENCE_TOOL_MAP, so the policy test
# can read each handler's signature.
from mulder.server.tools import (  # noqa: F401 ensure tools are registered
    artifacts,
    case,
    extract,
    hayabusa,
    review,
    yara,
)


def _evidence(tmp_path: Path) -> Path:
    root = tmp_path / "evidence"
    root.mkdir(exist_ok=True)
    for name in ("disk-a.dd", "disk-b.dd", "host-memory.mem"):
        (root / name).write_bytes(b"x")
    return root


def _zip(path: Path, member: str = "note.txt") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(member, "x")


def _coverage(
    tmp_path: Path, root: Path, calls: list[tuple[str, dict[str, object]]]
) -> dict[str, dict[str, Any]]:
    db = CaseDB.create(case_id="cov", evidence_root=str(root), db_dir=tmp_path)
    audit = AuditLog(tmp_path / "cov.audit.jsonl")
    for i, (tool, params) in enumerate(calls):
        audit.log_tool_call(f"tc_{i}", tool, params, "sha256:x")
    ctx = MagicMock(db=db, audit=audit)
    try:
        with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
            result: dict[str, Any] = _tool_dispatch_sync["audit_tool_coverage"]()
    finally:
        db.close()
    return {Path(str(item["path"])).name: item for item in result["coverage"]}


def _extract_then_audit(
    tmp_path: Path, root: Path, archive_path: str, extract_to: Path
) -> dict[str, dict[str, Any]]:
    """Run a real extraction and audit its sole tool-call entry."""
    db = CaseDB.create(case_id="cov", evidence_root=str(root), db_dir=tmp_path)
    audit = AuditLog(tmp_path / "cov.audit.jsonl")
    ctx = MagicMock(db=db, audit=audit, case_id="cov")
    try:
        with (
            patch("mulder.server.tools.case.get_cfg", return_value=MagicMock(db_dir=tmp_path)),
            patch("mulder.server.tools.case.has_ctx", return_value=True),
            patch("mulder.server.tools.case.get_ctx", return_value=ctx),
            patch("mulder.server.tools.review.get_ctx", return_value=ctx),
        ):
            extraction = _tool_dispatch_sync["extract_archive"](
                archive_path=archive_path, extract_to=str(extract_to)
            )
            assert extraction["status"] == "success"
            assert len(audit.tool_call_entries()) == 1
            assert audit.tool_call_entries()[0]["params"] == {
                "archive_path": archive_path,
                "extract_to": str(extract_to),
            }
            result: dict[str, Any] = _tool_dispatch_sync["audit_tool_coverage"]()
    finally:
        db.close()
    return {Path(str(item["path"])).name: item for item in result["coverage"]}


def test_run_on_one_disk_is_not_credited_to_another(tmp_path: Path) -> None:
    root = _evidence(tmp_path)
    cov = _coverage(tmp_path, root, [("run_fls", {"image_path": str(root / "disk-a.dd")})])
    assert "run_fls" in cov["disk-a.dd"]["tools_run"]
    assert "run_fls" in cov["disk-b.dd"]["tools_not_run"]


def test_run_on_the_evidence_directory_covers_every_item_inside(tmp_path: Path) -> None:
    root = _evidence(tmp_path)
    cov = _coverage(tmp_path, root, [("run_plaso", {"evidence_path": str(root)})])
    assert "run_plaso" in cov["disk-a.dd"]["tools_run"]
    assert "run_plaso" in cov["disk-b.dd"]["tools_run"]


@pytest.mark.parametrize("spelling", ["relative", "parent_segments", "symlinked_directory"])
def test_other_spellings_of_the_named_path_are_matched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str
) -> None:
    root = _evidence(tmp_path)
    (tmp_path / "link").symlink_to(root, target_is_directory=True)
    monkeypatch.chdir(root)
    path = {
        "relative": "disk-b.dd",
        "parent_segments": str(root / ".." / "evidence" / "disk-b.dd"),
        "symlinked_directory": str(tmp_path / "link" / "disk-b.dd"),
    }[spelling]
    cov = _coverage(tmp_path, root, [("run_mmls", {"image_path": path})])
    assert "run_mmls" in cov["disk-b.dd"]["tools_run"]
    assert "run_mmls" in cov["disk-a.dd"]["tools_not_run"]


def test_symlink_and_real_path_calls_are_combined(tmp_path: Path) -> None:
    root = _evidence(tmp_path)
    (tmp_path / "link").symlink_to(root, target_is_directory=True)
    calls: list[tuple[str, dict[str, object]]] = [
        ("run_fls", {"image_path": str(tmp_path / "link" / "disk-a.dd")}),
        ("run_fls", {"image_path": str(root / "disk-b.dd")}),
    ]
    cov = _coverage(tmp_path, root, calls)
    assert "run_fls" in cov["disk-a.dd"]["tools_run"]
    assert "run_fls" in cov["disk-b.dd"]["tools_run"]


def test_symlinked_item_matches_a_call_on_its_target(tmp_path: Path) -> None:
    root = _evidence(tmp_path)
    store = tmp_path / "store"
    store.mkdir()
    (store / "disk-c.dd").write_bytes(b"x")
    (root / "disk-c.dd").symlink_to(store / "disk-c.dd")
    cov = _coverage(tmp_path, root, [("run_fls", {"image_path": str(store / "disk-c.dd")})])
    assert "run_fls" in cov["disk-c.dd"]["tools_run"]
    assert "run_fls" in cov["disk-a.dd"]["tools_not_run"]


def test_home_relative_input_is_expanded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "extracted" / "cov" / "evidence"
    root.mkdir(parents=True)
    _zip(root / "a.zip")
    _zip(root / "b.zip")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    cov = _extract_then_audit(tmp_path, root, "~/extracted/cov/evidence/a.zip", root / "expanded")
    assert (root / "expanded" / "note.txt").read_text() == "x"
    assert "extract_archive" in cov["a.zip"]["tools_run"]
    assert "extract_archive" in cov["b.zip"]["tools_not_run"]


def test_output_directory_is_not_an_evidence_input(tmp_path: Path) -> None:
    root = tmp_path / "extracted" / "cov" / "evidence"
    root.mkdir(parents=True)
    nested = tmp_path / "nested.zip"
    _zip(nested)
    with zipfile.ZipFile(root / "a.zip", "w") as zf:
        zf.write(nested, "nested.zip")
    cov = _extract_then_audit(tmp_path, root, str(root / "a.zip"), root / "expanded")
    assert (root / "expanded" / "nested.zip").read_bytes() == nested.read_bytes()
    assert "extract_archive" in cov["a.zip"]["tools_run"]
    assert "extract_archive" in cov["nested.zip"]["tools_not_run"]


@pytest.mark.parametrize("input_kind", ["outside_file", "missing", "null"])
def test_unmatched_explicit_input_is_not_credited_globally(
    tmp_path: Path, input_kind: str
) -> None:
    root = _evidence(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "disk-c.dd").write_bytes(b"x")
    paths = {
        "outside_file": str(outside / "disk-c.dd"),
        "missing": str(root / "missing.dd"),
        "null": "a\x00b",
    }
    cov = _coverage(tmp_path, root, [("run_fls", {"image_path": paths[input_kind]})])
    assert "run_fls" in cov["disk-a.dd"]["tools_not_run"]
    assert "run_fls" in cov["disk-b.dd"]["tools_not_run"]


def test_unsupported_home_relative_input_is_not_credited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _evidence(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    cov = _coverage(tmp_path, root, [("run_fls", {"image_path": "~/evidence/disk-a.dd"})])
    assert "run_fls" in cov["disk-a.dd"]["tools_not_run"]
    assert "run_fls" in cov["disk-b.dd"]["tools_not_run"]


def test_auxiliary_input_does_not_credit_evidence(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    for name in ("a.pcap", "b.pcap"):
        (root / name).write_bytes(b"x")
    params: dict[str, object] = {
        "pcap_path": str(root / "a.pcap"),
        "ssl_keylog_path": str(root / "b.pcap"),
    }
    cov = _coverage(tmp_path, root, [("run_pcap_analysis", params)])
    assert "run_pcap_analysis" in cov["a.pcap"]["tools_run"]
    assert "run_pcap_analysis" in cov["b.pcap"]["tools_not_run"]


@pytest.mark.parametrize(
    ("tool", "params", "filename"),
    [
        ("yara_scan_memory", {"ruleset": "builtin"}, "host-memory.mem"),
        ("query_sqlite_from_image", {"inode": 42, "query": "SELECT 1"}, "a.sqlite"),
        ("index_evtx_file", {"filename": "a.evtx", "image_path": ""}, "a.evtx"),
    ],
)
def test_implicit_input_tools_keep_name_based_coverage(
    tmp_path: Path, tool: str, params: dict[str, object], filename: str
) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / filename).write_bytes(b"x")
    cov = _coverage(tmp_path, root, [(tool, params)])
    assert tool in cov[filename]["tools_run"]


@pytest.mark.parametrize("include_implicit_call", [False, True])
def test_unmatched_explicit_input_disables_implicit_tool_fallback(
    tmp_path: Path, include_implicit_call: bool
) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    for name in ("a.evtx", "b.evtx"):
        (root / name).write_bytes(b"x")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "disk-c.dd").write_bytes(b"x")
    calls: list[tuple[str, dict[str, object]]] = [
        ("index_evtx_file", {"filename": "a.evtx", "image_path": str(outside / "disk-c.dd")}),
    ]
    if include_implicit_call:
        calls.append(("index_evtx_file", {"filename": "a.evtx", "image_path": ""}))
    cov = _coverage(tmp_path, root, calls)
    for name in ("a.evtx", "b.evtx"):
        assert "index_evtx_file" in cov[name]["tools_not_run"]


@pytest.mark.parametrize(
    "call", ["evtx_directory", "file_as_evtx_dir", "image_path_only", "no_input"]
)
def test_hayabusa_counts_only_through_an_evtx_directory(tmp_path: Path, call: str) -> None:
    root = tmp_path / "evidence"
    selected = root / "selected"
    selected.mkdir(parents=True)
    (selected / "a.evtx").write_bytes(b"x")
    (root / "b.evtx").write_bytes(b"x")
    params: dict[str, object] = {"evtx_dir": "", "image_path": ""}
    if call == "evtx_directory":
        params["evtx_dir"] = str(selected)
    elif call == "file_as_evtx_dir":
        params["evtx_dir"] = str(selected / "a.evtx")
    elif call == "image_path_only":
        params["image_path"] = str(selected / "a.evtx")
    cov = _coverage(tmp_path, root, [("run_hayabusa", params)])
    assert ("run_hayabusa" in cov["a.evtx"]["tools_run"]) is (call == "evtx_directory")
    assert "run_hayabusa" in cov["b.evtx"]["tools_not_run"]


def test_evidence_tool_policies_cover_mapped_tools_and_match_handler_signatures() -> None:
    mapped = {tool for tools in review._EVIDENCE_TOOL_MAP.values() for tool in tools}
    assert mapped == set(review._EVIDENCE_INPUT_PARAMS) | review._IMPLICIT_INPUT_TOOLS
    assert set(review._EVIDENCE_SELECTOR_PARAMS) <= review._IMPLICIT_INPUT_TOOLS
    for tool, names in review._EVIDENCE_SELECTOR_PARAMS.items():
        assert not set(names) & set(review._EVIDENCE_INPUT_PARAMS.get(tool, ())), tool
    for policies in (review._EVIDENCE_INPUT_PARAMS, review._EVIDENCE_SELECTOR_PARAMS):
        for tool, names in policies.items():
            signature = inspect.signature(_tool_dispatch_sync[tool])
            assert set(names) <= set(signature.parameters), tool
