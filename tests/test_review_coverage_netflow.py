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
from mulder.models import WindowRow
from mulder.server.app import ServerContext, _tool_dispatch_sync
from mulder.server.tools.review import _EVIDENCE_TOOL_MAP
from tests.conftest import yday

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netflow" / "edge-router"
_MAGIC = b"\x0c\xa5\x02\x00"
_NETFLOW_TOOLS = ["run_netflow_analysis"]


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
    assert result["total_gaps"] == 1
    assert result["evidence_items"] == 1


def test_only_a_summary_source_for_the_directory_counts_as_run(fixture_ctx: ServerContext) -> None:
    """Coverage is per directory: the audit log alone (the tool ran somewhere, or failed) and a
    pivot's source do not cover it; a ``netflow.analysis.*`` source whose path is the directory or
    a parent of it does."""
    day_dir = str((_FIXTURES / "2001" / "02").resolve())
    fixture_ctx.audit.log_tool_call(
        tool_call_id="tc_netflow01",
        tool_name="run_netflow_analysis",
        params={"evidence_path": day_dir, "source": "netflow.analysis.x"},
        output_hash="blake2b:0",
        duration_ms=1.0,
    )
    fixture_ctx.db.register_source("netflow.sweep.x", day_dir, "blake2b:0", "nfdump", 3)
    fixture_ctx.db.register_source(
        "netflow.analysis.elsewhere", "/other/dir", "blake2b:0", "nfdump", 3
    )
    (item,) = _netflow_items(_coverage())
    assert item["tools_run"] == [] and item["tools_not_run"] == ["run_netflow_analysis"]

    # a summary whose header row was never stored (or that ended partial) still covers nothing:
    # only a stored status=success header counts
    sid = fixture_ctx.db.register_source(
        "netflow.analysis.x", str(_FIXTURES.resolve()), "blake2b:0", "nfdump", 9
    )
    (item,) = _netflow_items(_coverage())
    assert item["tools_run"] == [] and item["tools_not_run"] == ["run_netflow_analysis"]
    header = "- netflow header tool=run_netflow_analysis tool_call_id=tc_netflow01 status=success"
    fixture_ctx.db.insert_windows(sid, [WindowRow(
        source_id=sid, line_start=1, line_end=1, event_time=None, raw_text=header,
    )])  # fmt: skip
    result = _coverage()
    (item,) = _netflow_items(result)
    assert item["tools_run"] == ["run_netflow_analysis"]
    assert item["tools_not_run"] == []
    assert result["total_gaps"] == 0


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
    assert result["total_gaps"] == 1 + 1 + 1
