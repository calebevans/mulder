"""run_evtx_recovery: records that survived a log clearing are indexed, marked and bounded."""

from __future__ import annotations

import inspect
import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.assets.manifest import ASSETS_BY_KEY
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.extractors.optical import OpticalError
from mulder.orchestrator import prompts
from mulder.server import app
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import tool_already_indexed
from mulder.server.tool_access import Role, get_tools_for_role
from mulder.server.tools.extract import evtx_recovery
from mulder.server.tools.extract.evtx_recovery import run_evtx_recovery

_HEADER = b"ElfFile\x00".ljust(4096, b"\x00")
_CHUNK = 65536
_SIGNATURE = b"ElfChnk\x00"
_BINARY = "/opt/evtx-dump/evtx_dump"
_T = "2024-03-01T10:00:0{}.0000000Z"


@pytest.fixture
def case(tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    return tmp_case_db


def _rec(
    rid: int,
    channel: str = "Security",
    when: str | None = None,
    eid: object = 4624,
    recovered: bool = False,
    provider: str = "Microsoft-Windows-Security-Auditing",
    **data: object,
) -> dict[str, Any]:
    """One record as evtx_dump prints it with ``-o jsonl``."""
    event = {
        "System": {
            "Provider": {"#attributes": {"Name": provider}},
            "EventID": eid,
            "TimeCreated": {"#attributes": {"SystemTime": when or _T.format(rid % 10)}},
            "EventRecordID": rid,
            "Channel": channel,
        },
        "EventData": data,
    }
    return {"recovered": True, "Event": event} if recovered else {"Event": event}


def _chunk(*records: object) -> bytes:
    """A stand-in event log chunk: signature, a record where the first one
    belongs, then the JSON lines the fake evtx_dump prints for it."""
    body = b"".join(json.dumps(r).encode() + b"\n" for r in records)
    return (_SIGNATURE.ljust(512, b"\x00") + b"\x2a\x2a\x00\x00" + body).ljust(_CHUNK, b"\x00")


def _log(path: Path, *chunks: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_HEADER + b"".join(chunks))
    return path


class _FakeEvtxDump:
    """Stands in for the evtx_dump process: prints what the test put in each chunk."""

    calls: list[list[str]] = []

    def __init__(self, cmd: list[str], **_: object) -> None:
        self.calls.append(cmd)
        data = Path(cmd[-1]).read_bytes()
        lines: list[bytes] = []
        errors: list[bytes] = []
        self.returncode = 0
        if data[:8] != b"ElfFile\x00":
            self.returncode = 1
            errors.append(b"Error: Failed to open file\n")
        else:
            body = data[4096:]
            # The real one reads whole 64 KiB chunks only.
            assert len(body) % _CHUNK == 0, "a chunk was not padded"
            for offset in range(0, len(body), _CHUNK):
                payload = body[offset + 516 : offset + _CHUNK].rstrip(b"\x00")
                lines += payload.splitlines(keepends=True)
        self.stdout = iter(lines)
        self.stderr = iter(errors)

    def wait(self) -> int:
        return self.returncode

    def poll(self) -> int:
        return self.returncode

    def kill(self) -> None:
        pass


def _recover(target: Path | str, **kwargs: Any) -> dict[str, Any]:
    _FakeEvtxDump.calls = []
    with (
        patch.object(evtx_recovery, "_evtx_dump_binary", return_value=_BINARY),
        patch("mulder.server.tools.extract.evtx_recovery.subprocess.Popen", _FakeEvtxDump),
    ):
        result: dict[str, Any] = run_evtx_recovery.__wrapped__(  # type: ignore[attr-defined]
            str(target), **kwargs
        )
    return result


def _lines(case: CaseDB, source: str) -> list[str]:
    return "".join(w.raw_text for w in case.get_windows_by_source(source)).splitlines()


def _sources(case: CaseDB) -> set[str]:
    return {s.source_name for s in case.get_sources()}


def test_recovered_records_are_indexed_per_channel_marked_and_in_time_order(
    case: CaseDB, tmp_path: Path
) -> None:
    log = _log(
        tmp_path / "Security.evtx",
        _chunk(
            _rec(12, recovered=True, TargetUserName="svc_backup"),
            _rec(11, eid={"#attributes": {"Qualifiers": 0}, "#text": 4672}, recovered=True),
            _rec(20, when="2024-03-02T08:00:00.0000000Z"),
            _rec(7, channel="System", eid=7045, recovered=True, ServiceName="PSEXESVC"),
        ),
    )

    summary = _recover(log)["results"]

    assert _FakeEvtxDump.calls == [[_BINARY, "--recover-records", "-o", "jsonl", str(log)]]
    assert summary["recovered_records"] == 3
    assert summary["earliest_recovered"] == _T.format(1)
    assert summary["latest_recovered"] == _T.format(7)
    security = summary["channels"]["security"]
    assert security["source"] == "evtx_recovered.security"
    assert security["event_ids"] == {"4672": 1, "4624": 1}
    # What is live sits beside what was recovered, so a late start is visible.
    assert (security["live_records"], security["live_earliest"]) == (
        1,
        "2024-03-02T08:00:00.0000000Z",
    )
    assert summary["live_log_cleared"] is False
    assert "does not show it did not happen" in summary["interpretation"]

    lines = _lines(case, "evtx_recovered.security")
    assert [line.split(" | ")[:3] for line in lines] == [
        [_T.format(1), "4672", "security"],
        [_T.format(2), "4624", "security"],
    ]
    assert lines[1].split(" | ", 3)[3].startswith('[recovered record 12] {"System":')
    assert "svc_backup" in lines[1]
    assert "PSEXESVC" in _lines(case, "evtx_recovered.system")[0]
    window = case.get_windows_by_source("evtx_recovered.security")[0]
    assert str(window.event_time).startswith("2024-03-01T10:00:01")
    assert _lines(case, "evtx_recovered.summary")[0].endswith(
        "3 records recovered (read 1 event log files)"
    )
    # The live record is not indexed here: index_evtx_file owns the live log.
    assert not any("record 20]" in line for line in lines)


def test_a_recovered_record_that_is_still_live_is_dropped_whichever_is_read_first(
    case: CaseDB, tmp_path: Path
) -> None:
    logs = tmp_path / "logs"
    # a-first.evtx is read before b-live.evtx: record 1's live copy comes later.
    _log(logs / "a-first.evtx", _chunk(_rec(1, recovered=True), _rec(2, recovered=True)))
    _log(logs / "b-live.evtx", _chunk(_rec(1), _rec(3), _rec(3, recovered=True)))
    # Same ID and time in another channel is another record.
    _log(logs / "c.evtx", _chunk(_rec(1, channel="System", recovered=True)))
    # The same stale record found twice is kept once.
    _log(logs / "d.evtx", _chunk(_rec(2, recovered=True)))

    summary = _recover(logs)["results"]

    assert summary["duplicates_of_live_dropped"] == 2
    assert [line.split("] ")[0][-8:] for line in _lines(case, "evtx_recovered.security")] == [
        "record 2"
    ]
    assert summary["channels"]["system"]["recovered"] == 1


def test_only_the_channels_that_matter_are_kept_unless_asked(case: CaseDB, tmp_path: Path) -> None:
    rdp = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    log = _log(
        tmp_path / "x.evtx",
        _chunk(
            _rec(1, channel="Application", recovered=True),
            _rec(2, channel=rdp, recovered=True),
            _rec(3, channel="microsoft-windows-powershell/operational", recovered=True),
            _rec(4, channel="Microsoft-Windows-Sysmon/Operational", recovered=True),
        ),
    )

    assert set(_recover(log)["results"]["channels"]) == {
        "terminalservices-localsessionmanager-operational",
        "powershell-operational",
    }
    everything = _recover(log, channels=["*"], force=True)["results"]
    assert everything["recovered_records"] == 4
    sysmon = _recover(log, channels=["*SYSMON*"], force=True)["results"]
    assert set(sysmon["channels"]) == {"sysmon-operational"}


def test_a_time_window_bounds_what_is_kept_and_a_date_covers_its_day(
    case: CaseDB, tmp_path: Path
) -> None:
    days = ["2024-02-28T23:59:59.9Z", "2024-03-01T00:00:00.0Z", "2024-03-01T23:59:59.9Z"]
    log = _log(
        tmp_path / "x.evtx",
        _chunk(*(_rec(i, when=day, recovered=True) for i, day in enumerate(days))),
    )

    one_day = _recover(log, t_start="2024-03-01", t_end="2024-03-01")["results"]
    assert (one_day["earliest_recovered"], one_day["latest_recovered"]) == (days[1], days[2])
    to_the_second = _recover(log, t_end="2024-03-01 00:00:00Z", force=True)["results"]
    assert to_the_second["recovered_records"] == 2

    bad = _recover(log, t_start="yesterday", force=True)
    assert bad["error_type"] == "invalid_argument"


def test_the_record_cap_is_per_channel_and_is_reported(case: CaseDB, tmp_path: Path) -> None:
    log = _log(
        tmp_path / "x.evtx",
        _chunk(
            *(_rec(i, recovered=True) for i in range(5)),
            _rec(1, channel="System", recovered=True),
        ),
    )

    summary = _recover(log, max_records=2)["results"]

    assert summary["channels"]["security"]["recovered"] == 2
    assert summary["channels"]["security"]["not_indexed_over_max_records"] == 3
    assert summary["channels"]["system"]["recovered"] == 1
    assert summary["truncated"] == {"records_over_max_records": 3}
    assert len(_lines(case, "evtx_recovered.security")) == 2
    assert any("truncated" in line for line in _lines(case, "evtx_recovered.summary"))
    assert _recover(log, max_records=0, force=True)["error_type"] == "invalid_argument"


def test_a_live_log_that_records_its_own_clearing_is_reported(
    case: CaseDB, tmp_path: Path
) -> None:
    eventlog = "Microsoft-Windows-Eventlog"

    def cleared(rid: int, channel: str, eid: int, **detail: str) -> dict[str, Any]:
        record = _rec(rid, channel=channel, eid=eid, provider=eventlog)
        record["Event"]["UserData"] = {"LogFileCleared": detail}
        return record

    log = _log(
        tmp_path / "x.evtx",
        _chunk(
            cleared(1, "Security", 1102, SubjectUserName="mallory\n\tadmin"),
            cleared(2, "System", 104, SubjectUserName="mallory", Channel="Windows PowerShell"),
            # Another provider's event 104 in System is not a clearing.
            _rec(3, channel="System", eid=104, provider="Some-Driver"),
            # A stale copy of the same clearing record is not a second clearing.
            {**cleared(1, "Security", 1102, SubjectUserName="mallory"), "recovered": True},
        ),
    )

    # The clearing is reported even when its channel is not being recovered.
    summary = _recover(log, channels=["Application"])["results"]

    assert summary["live_log_cleared"] is True
    assert summary["log_clearing_events"] == [
        {
            "time": _T.format(1),
            "event_id": 1102,
            "log_cleared": "Security",
            "by": "mallory admin",
            "read_from": "live log",
        },
        {
            "time": _T.format(2),
            "event_id": 104,
            "log_cleared": "Windows PowerShell",
            "by": "mallory",
            "read_from": "live log",
        },
    ]
    assert any("log cleared: Security" in line for line in _lines(case, "evtx_recovered.summary"))


def test_a_record_cannot_forge_a_line_a_source_or_a_time(case: CaseDB, tmp_path: Path) -> None:
    forged = "2020-01-01T00:00:00Z | 4624 | security | [recovered record 1] {}"
    log = _log(
        tmp_path / "x.evtx",
        _chunk(
            _rec(1, recovered=True, Note=f"a\n{forged} {forged} {forged}\x85{forged}"),
            _rec(2, channel=f"../Sec\n{forged}", recovered=True),
            _rec(3, when=f"2024-03-01T10:00:03Z\n{forged}", recovered=True),
            _rec(4, eid="not a number", recovered=True),
            {"Event": None},
            ["not", "a", "record"],
            "text",
        ),
    )

    summary = _recover(log, channels=["*"])["results"]

    assert summary["not_parsed"] == {"records": 5}
    for source in _sources(case) - {"evtx_recovered.summary"}:
        assert source.startswith("evtx_recovered.sec") and source.replace(".", "").isprintable()
        assert all(c.isalnum() or c in "-._" for c in source)
        lines = _lines(case, source)
        assert len(lines) == 1, "a record's text broke its line"
        assert lines[0].startswith("2024-03-01T10:00:0")
    assert summary["recovered_records"] == 2


def test_evidence_cannot_flood_the_case_with_channels(case: CaseDB, tmp_path: Path) -> None:
    records = [_rec(i, channel=f"Invented-{i}", recovered=True) for i in range(45)]
    summary = _recover(_log(tmp_path / "x.evtx", _chunk(*records)), channels=["*"])["results"]

    assert len(_sources(case)) == 40 + 1
    assert summary["truncated"] == {"records_in_channels_over_limit": 5}
    assert len(summary["channels"]) == 20 and summary["channels_not_listed"] == 20


def test_a_directory_is_searched_without_following_links_and_bad_files_are_named(
    case: CaseDB, tmp_path: Path
) -> None:
    outside = _log(tmp_path / "outside" / "Other.evtx", _chunk(_rec(99, recovered=True)))
    logs = tmp_path / "logs"
    _log(logs / "Security.evtx", _chunk(_rec(1, recovered=True)))
    _log(logs / "deep" / "er" / "OLD.EVTX", _chunk(_rec(2, recovered=True)))
    (logs / "broken\tname.evtx").write_bytes(b"not an event log")
    (logs / "notes.txt").write_bytes(_HEADER + _chunk(_rec(3, recovered=True)))
    (logs / "link.evtx").symlink_to(outside)
    (logs / "linked-dir").symlink_to(outside.parent, target_is_directory=True)

    summary = _recover(logs)["results"]

    assert summary["mode"] == "read 3 event log files"
    assert summary["recovered_records"] == 2
    assert summary["not_parsed"] == {"files": ["broken name.evtx"], "file_count": 1}

    empty = tmp_path / "empty"
    empty.mkdir()
    assert _recover(empty)["error_type"] == "invalid_argument"


def test_chunks_are_carved_out_of_raw_data_wherever_they_are(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = 100_000
    monkeypatch.setattr(evtx_recovery, "_SCAN_BLOCK", block)
    monkeypatch.setattr(evtx_recovery, "_BATCH_CHUNKS", 2)
    first = _chunk(_rec(1), _rec(2, recovered=True))
    second = _chunk(_rec(3))
    cut = _chunk(_rec(4), _rec(5))[: 516 + len(json.dumps(_rec(4))) + 20]
    raw = tmp_path / "evidence" / "disk.raw"
    raw.parent.mkdir()
    raw.write_bytes(
        b"\x11" * (block - 3)  # the first signature straddles two scan blocks
        + first
        + b"\x11" * 12_345
        + _SIGNATURE  # a signature with no record after it is not a chunk
        + b"\x11" * 999
        + second
        + first  # an exact copy
        + b"\x11" * 7
        + cut  # cut short by the end of the data
    )
    before = raw.read_bytes()

    summary = _recover(raw)["results"]

    assert summary["mode"].startswith("carved 3 event log chunks out of ")
    assert summary["duplicate_chunks_skipped"] == 1
    assert len(_FakeEvtxDump.calls) == 2, "three chunks in batches of two"
    assert [
        line.split(" | ", 3)[3].split("] ")[0] for line in _lines(case, "evtx_recovered.security")
    ] == [
        "[carved record 1",
        "[recovered record 2",
        "[carved record 3",
        "[carved record 4",
    ]
    assert summary["not_parsed"] == {"records": 1}, "the record the cut went through"
    # Nothing to compare with: said in the response and in the indexed summary.
    assert summary["compared_with_live_logs"] is False
    assert summary["live_log_cleared"] is None
    assert "still in the live logs" in summary["warning"]
    assert any("still in the live logs" in ln for ln in _lines(case, "evtx_recovered.summary"))
    # The evidence is read, never written, and nothing is left beside it.
    assert raw.read_bytes() == before
    assert list(raw.parent.iterdir()) == [raw]


def test_carved_records_still_in_the_extracted_live_logs_are_dropped(
    case: CaseDB, tmp_path: Path
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"\x00" * 1000 + _chunk(*(_rec(i) for i in range(1, 6))))
    extracted = tmp_path / "mulder_evtx_extract"
    _log(extracted / "Security.evtx", _chunk(_rec(1), _rec(2), _rec(3), _rec(9, recovered=True)))
    case.set_kv(f"evtx_extract_dir:{image}", str(extracted))

    # run_evtx_parser writes the manifest once every log is out. Before that
    # the directory may be half filled, so it is not used.
    early = _recover(image)["results"]
    assert early["compared_with_live_logs"] is False
    assert early["recovered_records"] == 5

    extract_and_index("Security.evtx\t1 MB\tHIGH", "evtx.manifest", str(image), "evtx-extract")
    summary = _recover(image, force=True)["results"]

    assert summary["compared_with_live_logs"] is True
    assert summary["duplicates_of_live_dropped"] == 3
    assert summary["channels"]["security"]["recovered"] == 3
    assert summary["channels"]["security"]["live_records"] == 3
    assert summary["mode"].endswith("and read 1 extracted logs")
    assert "warning" not in summary


def test_an_e01_is_carved_through_its_raw_view_and_never_copied(
    case: CaseDB, tmp_path: Path
) -> None:
    image = tmp_path / "disk.E01"
    image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00 compressed")
    flat = tmp_path / "xmount" / "disk.dd"
    flat.parent.mkdir()
    flat.write_bytes(b"\x00" * 77 + _chunk(_rec(1)))
    asked: list[str] = []

    @contextmanager
    def raw_view(path: str) -> Iterator[Path]:
        asked.append(path)
        yield flat

    with patch.object(evtx_recovery, "raw_image", raw_view):
        summary = _recover(image)["results"]

    assert asked == [str(image)]
    assert summary["recovered_records"] == 1
    assert {s.source_path for s in case.get_sources()} == {str(image)}

    def no_fuse(path: str) -> Iterator[Path]:
        raise OpticalError("xmount could not expose disk.E01")

    with patch.object(evtx_recovery, "raw_image", contextmanager(no_fuse)):
        failed = _recover(image, force=True)
    assert failed["error_type"] == "tool_failed"
    assert "xmount could not expose" in failed["error_message"]


def test_running_out_of_time_is_a_timeout_and_indexes_nothing(
    case: CaseDB, tmp_path: Path
) -> None:
    log = _log(tmp_path / "x.evtx", _chunk(_rec(1, recovered=True)))

    with patch.object(evtx_recovery, "adaptive_timeout", return_value=0):
        result = _recover(log)

    # "timeout" is what lets the job store defer and retry it under load.
    assert result["error_type"] == "timeout"
    assert _sources(case) == set()


def test_the_dump_is_streamed_from_a_real_process_and_killed_at_the_deadline(
    tmp_path: Path,
) -> None:
    lines = tmp_path / "out.jsonl"
    lines.write_text(json.dumps(_rec(1)) + "\nnot json\n" + json.dumps(_rec(2)) + "\n")
    prints = tmp_path / "prints"
    prints.write_text(
        f'#!/bin/sh\ncat "{lines}"\n'
        'echo "Failed to dump the next record." >&2\necho "Caused by: x" >&2\n'
    )
    hangs = tmp_path / "hangs"
    hangs.write_text("#!/bin/sh\nexec sleep 30\n")
    for script in (prints, hangs):
        script.chmod(0o755)
    seen: list[Any] = []

    status, unreadable = evtx_recovery._dump(
        str(prints), tmp_path / "x.evtx", time.monotonic() + 30, seen.append
    )

    assert status == 0
    assert [r["Event"]["System"]["EventRecordID"] for r in seen] == [1, 2]
    assert unreadable == 2, "one line that is not JSON, one failure evtx_dump reported"

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        evtx_recovery._dump(str(hangs), tmp_path / "x.evtx", started + 0.3, seen.append)
    assert time.monotonic() - started < 10


def test_a_path_is_recovered_once_even_when_nothing_was_found(
    case: CaseDB, tmp_path: Path
) -> None:
    log = _log(tmp_path / "Security.evtx", _chunk(_rec(1)))

    first = _recover(log)["results"]
    again = _recover(log)["results"]

    assert first["recovered_records"] == 0
    assert _sources(case) == {"evtx_recovered.summary"}
    assert again["status"] == "skipped"
    assert _FakeEvtxDump.calls == []
    assert tool_already_indexed("run_evtx_recovery", str(log)) == ["evtx_recovered.summary"]
    # Under "evtx." these would tell run_evtx_parser the live log was parsed.
    assert tool_already_indexed("run_evtx_parser", str(log)) == []


def test_the_binary_comes_from_the_asset_root_and_never_from_path(
    case: CaseDB, tmp_path: Path, asset_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """python-evtx, a mulder dependency, installs a console script called
    ``evtx_dump``. In the container image that script is what PATH finds."""
    on_path = tmp_path / "bin"
    on_path.mkdir()
    (on_path / "evtx_dump").write_text("#!/bin/sh\nexit 0\n")
    (on_path / "evtx_dump").chmod(0o755)
    monkeypatch.setenv("PATH", str(on_path))

    missing = run_evtx_recovery.__wrapped__(str(tmp_path))  # type: ignore[attr-defined]
    assert missing["error_type"] == "binary_missing"
    assert "mulder setup" in missing["suggestion"]

    installed = asset_root / "evtx-dump" / "evtx_dump"
    installed.parent.mkdir()
    installed.write_text("#!/bin/sh\nexit 0\n")
    assert evtx_recovery._evtx_dump_binary() is None, "not executable yet"
    installed.chmod(0o755)
    assert evtx_recovery._evtx_dump_binary() == str(installed)


def test_a_missing_path_is_an_error(case: CaseDB, tmp_path: Path) -> None:
    assert _recover(tmp_path / "gone.evtx")["error_type"] == "file_not_found"


def test_guidance_says_when_to_recover_and_what_recovery_does_not_show() -> None:
    prompt_dir = Path(prompts.__file__).parent
    planner = (prompt_dir / "extract_planner.md").read_text(encoding="utf-8")
    analyst = (prompt_dir / "extract_analyst.md").read_text(encoding="utf-8")

    assert "mcp__mulder__run_evtx_recovery" in get_tools_for_role(Role.EXTRACT_EXECUTOR)
    assert "mcp__mulder__run_evtx_recovery" not in get_tools_for_role(Role.EXTRACT_ANALYST)
    assert "Plan it only when there is a reason" in planner
    assert "never in the same plan\n  as run_evtx_parser" in planner
    assert "Recovering nothing does not show that nothing\nwas logged" in planner
    assert "names run_evtx_recovery (you cannot call it)" in analyst
    assert "does not show it did not happen" in analyst
    doc = " ".join((inspect.getdoc(run_evtx_recovery) or "").split())
    assert "does NOT show it did not happen" in doc


def test_the_binary_is_pinned_for_both_architectures() -> None:
    asset = ASSETS_BY_KEY["evtx-dump"]

    assert set(asset.digests) == {"amd64", "arm64"}
    # amd64 takes the static build: upstream's x86_64-gnu one needs GLIBC 2.34.
    assert asset.urls["amd64"].endswith(f"evtx_dump-v{asset.version}-x86_64-unknown-linux-musl")
    assert asset.chmod_x == ("evtx_dump",)
    # No link onto PATH, where python-evtx's script of the same name lives.
    assert asset.shims == ()
