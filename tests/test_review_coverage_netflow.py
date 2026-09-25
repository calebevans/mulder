"""audit_tool_coverage reports one item per nfcapd exporter directory.

Without the collapse the pristine loop would emit one gap list per nfcapd file (N files give N
items and 3N gaps). The map entry makes ``netflow_capture`` visible to the audit at all; the
collapse keys it on ``ev.path.parent`` and adds a ``files`` count.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.index.correlator import Correlator
from mulder.server.app import ServerContext, _tool_dispatch_sync
from mulder.server.tools.review import _EVIDENCE_TOOL_MAP
from tests.netflow_harness import yday

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netflow" / "edge-router"
_MAGIC = b"\x0c\xa5\x02\x00"
_NETFLOW_TOOLS = ["run_netflow_inventory", "run_netflow_sweep", "run_netflow_top"]


def _context(tmp_path: Path, evidence_root: Path) -> Iterator[ServerContext]:
    db = CaseDB.create(case_id="nf-review", evidence_root=str(evidence_root), db_dir=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    ctx = ServerContext(case_id="nf-review", db=db, correlator=Correlator(db=db), audit=audit)
    with patch("mulder.server.tools.review.get_ctx", return_value=ctx):
        yield ctx
    db.close()


@pytest.fixture()
def fixture_ctx(tmp_path: Path) -> Iterator[ServerContext]:
    assert _FIXTURES.is_dir(), f"missing fixture tree {_FIXTURES}"
    yield from _context(tmp_path, _FIXTURES)


def _coverage() -> dict[str, object]:
    result: dict[str, object] = _tool_dispatch_sync["audit_tool_coverage"]()
    assert result["status"] == "success"
    return result


def _netflow_items(result: dict[str, object]) -> list[dict[str, object]]:
    coverage = result["coverage"]
    assert isinstance(coverage, list)
    return [i for i in coverage if i["artifact_type"] == "netflow_capture"]


def test_tool_map_entry() -> None:
    assert _EVIDENCE_TOOL_MAP["netflow_capture"] == _NETFLOW_TOOLS


def test_fixture_tree_one_item_per_exporter_directory(fixture_ctx: ServerContext) -> None:
    result = _coverage()
    items = _netflow_items(result)

    assert len(items) == 1
    (item,) = items
    assert item["path"] == str((_FIXTURES / "2001" / "02").resolve())
    assert item["files"] == 3  # the 0-byte stray and the text nfcapd.200102035555 are not counted
    assert item["tools_run"] == []
    assert item["tools_not_run"] == _NETFLOW_TOOLS
    assert result["total_gaps"] == 3
    assert result["evidence_items"] == 1


def test_logged_netflow_call_moves_to_tools_run(fixture_ctx: ServerContext) -> None:
    fixture_ctx.audit.log_tool_call(
        tool_call_id="tc_netflow01",
        tool_name="run_netflow_sweep",
        params={"evidence_path": str(_FIXTURES / "2001" / "02"), "source": "netflow.sweep.x"},
        output_hash="blake2b:0",
        duration_ms=1.0,
    )
    result = _coverage()
    (item,) = _netflow_items(result)

    assert item["tools_run"] == ["run_netflow_sweep"]
    assert item["tools_not_run"] == ["run_netflow_inventory", "run_netflow_top"]
    assert result["total_gaps"] == 2


def test_two_exporters_two_items_other_types_unchanged(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    dirs = [root / "netflow" / name / "2001" / "02" for name in ("branch-probe", "edge-router")]
    for n, d in enumerate(dirs, start=1):
        d.mkdir(parents=True)
        for day in range(48, 48 + 4 * n - 1):
            (d / f"nfcapd.{yday(day)}0000").write_bytes(_MAGIC + b"\x00" * 60)
    (root / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    for _ in _context(tmp_path, root):
        result = _coverage()

    items = _netflow_items(result)
    assert [(i["path"], i["files"]) for i in items] == [
        (str(dirs[0].resolve()), 3),
        (str(dirs[1].resolve()), 7),
    ]
    coverage = result["coverage"]
    assert isinstance(coverage, list)
    pcap = [i for i in coverage if i["artifact_type"] == "network_capture"]
    assert len(pcap) == 1
    assert pcap[0]["path"] == str((root / "capture.pcap").resolve())
    assert "files" not in pcap[0]
    assert result["evidence_items"] == 3
    assert result["total_gaps"] == 3 + 3 + 1
