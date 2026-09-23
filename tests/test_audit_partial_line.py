"""An append after a torn line must stay readable by every later process."""

from __future__ import annotations

from pathlib import Path

from mulder.audit import AuditLog


def _torn_log(tmp_path: Path) -> Path:
    """A log whose writer died mid-way through its second line."""
    log_path = tmp_path / "audit.jsonl"
    AuditLog(log_path).log_tool_call("tc_00000001", "search", {}, "sha256:x")
    with open(log_path, "a") as fh:
        fh.write('{"type":"tool_call","tool_call_id":"tc_00000002","tool_na')
    return log_path


def test_entry_after_a_torn_line_survives_a_reload(tmp_path: Path) -> None:
    log_path = _torn_log(tmp_path)

    writer = AuditLog(log_path)
    writer.log_tool_call("tc_00000003", "search", {}, "sha256:y")
    assert writer.has_tool_call("tc_00000003")

    reloaded = AuditLog(log_path)
    assert reloaded.has_tool_call("tc_00000001")
    assert reloaded.has_tool_call("tc_00000003")
    # The torn entry itself is unrecoverable; it must not take a neighbour with it.
    assert not reloaded.has_tool_call("tc_00000002")


def test_intact_log_gains_no_blank_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.log_tool_call("tc_a", "search", {}, "sha256:x")
    log.log_tool_call("tc_b", "search", {}, "sha256:y")

    assert log_path.read_bytes().count(b"\n") == 2
    assert b"\n\n" not in log_path.read_bytes()
