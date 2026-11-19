"""run_hayabusa_logon_summary: who logged on, how and from where, as a bounded table.

The fake Hayabusa follows what the pinned 3.8.1 binary does (checked in the
container image): ``logon-summary -o <prefix>`` writes ``<prefix>-successful.csv``
and ``<prefix>-failed.csv`` with one row per combination and a count, and no
times. Without ``rules/config`` it prints "Cannot open file" for
``eventkey_alias.txt`` and then reports that no logon events were detected.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.server import app
from mulder.server.tools import hayabusa
from mulder.server.tools.extract import evtx as evtx_tools
from mulder.server.tools.hayabusa import run_hayabusa, run_hayabusa_logon_summary

HEADER = (
    "{kind},Event,Target Account,Target Domain,Target Computer,Logon Type,"
    "Source Account,Source Domain,Source Computer,Source IP Address"
)
SUCCESSFUL = "\n".join(
    [
        HEADER.format(kind="Successful"),
        "79,Sec 4624,SYSTEM,NT AUTHORITY,SRV01,5 - Service,SRV01$,WORKGROUP,-,-",
        "4,Sec 4624,alice,CORP,SRV01,10 - RemoteInteractive,-,-,WS07,10.0.0.7",
        "2,Sec 4624,Administrator,SRV01,SRV01,3 - Network,-,-,DESKTOP-TR62H4R,79.173.135.242",
        "1,Sec 4624,Administrator,SRV01,SRV01,4 - Batch,SRV01$,WORKGROUP,SRV01,-",
        "",
    ]
)
FAILED = "\n".join(
    [
        HEADER.format(kind="Failed"),
        "310,Sec 4625,Administrator,SRV01,SRV01,3 - Network,-,-,KALI,185.220.101.4",
        "",
    ]
)
NO_CONFIG = "[ERROR] Cannot open file. [file:rules/config/eventkey_alias.txt]\n"
# What 3.8.1 prints with --quiet --no-color: colour resets are still there.
STDOUT = (
    "\x1b[0mGenerating Logon Summary\n\n"
    "Total Event Records\x1b[0m:  653\n\n"
    "\x1b[0mFirst Timestamp\x1b[0m:  2023-03-15 07:05:04.108 +00:00\n"
    "\x1b[0mLast Timestamp\x1b[0m:  2023-03-24 12:37:15.067 +00:00\n\n"
    "\x1b[0mElapsed time: \x1b[0m00:00:00.013\n"
)

Fake = Callable[[list[str], str], "subprocess.CompletedProcess[str]"]


@pytest.fixture
def case(tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    return tmp_case_db


@pytest.fixture
def evtx_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "evtx"
    directory.mkdir()
    (directory / "Security.evtx").write_bytes(b"ElfFile\x00")
    return directory


@pytest.fixture
def binary(tmp_path: Path) -> Path:
    """A Hayabusa install with its rules/config beside the binary."""
    home = tmp_path / "hayabusa"
    (home / "rules" / "config").mkdir(parents=True)
    (home / "hayabusa").write_text("#!/bin/sh\n")
    return home / "hayabusa"


def writes(successful: str = SUCCESSFUL, failed: str = FAILED, returncode: int = 0) -> Fake:
    def fake(cmd: list[str], prefix: str) -> subprocess.CompletedProcess[str]:
        Path(f"{prefix}-successful.csv").write_text(successful)
        Path(f"{prefix}-failed.csv").write_text(failed)
        return subprocess.CompletedProcess(cmd, returncode, stdout=STDOUT, stderr="")

    return fake


def summarise(
    monkeypatch: pytest.MonkeyPatch, binary: Path, fake: Fake, **kwargs: Any
) -> tuple[Any, list[list[str]]]:
    argvs: list[list[str]] = []

    def run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        argvs.append(list(cmd))
        return fake(cmd, cmd[cmd.index("-o") + 1])

    monkeypatch.setattr(hayabusa, "_hayabusa_binary", lambda: str(binary))
    monkeypatch.setattr("mulder.server.tools.hayabusa.subprocess.run", run)
    result = run_hayabusa_logon_summary.__wrapped__(**kwargs)  # type: ignore[attr-defined]
    return result, argvs


def test_the_command_and_options_are_the_ones_the_pinned_version_takes(
    case: CaseDB, evtx_dir: Path, binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _result, (argv,) = summarise(monkeypatch, binary, writes(), evtx_dir=str(evtx_dir))

    assert argv[:4] == [str(binary), "logon-summary", "-d", str(evtx_dir)]
    assert argv[4] == "-o" and not Path(argv[5]).exists(), "the output prefix is temporary"
    assert {"--clobber", "--quiet", "--quiet-errors", "--no-color", "--UTC"} <= set(argv)
    assert argv[argv.index("--rules-config") + 1] == str(binary.parent / "rules" / "config")
    # csv-timeline options this command does not have.
    assert not {"--no-wizard", "-p", "-m"} & set(argv)


def test_totals_types_and_sourced_rows_are_returned_and_everything_is_indexed(
    case: CaseDB, evtx_dir: Path, binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, _argv = summarise(monkeypatch, binary, writes(), evtx_dir=str(evtx_dir))

    summary = result["results"]
    assert summary["source"] == "logon.summary"
    good = summary["successful"]
    assert (good["logons"], good["combinations"]) == (86, 4)
    assert good["by_logon_type"] == {
        "5 - Service": 79,
        "10 - RemoteInteractive": 4,
        "3 - Network": 2,
        "4 - Batch": 1,
    }
    # Only rows that name an address, the external one first.
    assert [
        (r["Target Account"], r["Source IP Address"], r["external"], r["count"])
        for r in good["with_source_address"]
    ] == [
        ("Administrator", "79.173.135.242", True, 2),
        ("alice", "10.0.0.7", False, 4),
    ]
    assert good["with_source_address"][0]["Source Computer"] == "DESKTOP-TR62H4R"
    bad = summary["failed"]
    assert (
        bad["logons"] == 310
        and bad["with_source_address"][0]["Source IP Address"] == "185.220.101.4"
    )
    assert "no first or last time" in summary["note"]
    assert "A logon is not a compromise" in summary["note"]
    # The only times the pinned version gives: the span of the records the counts cover.
    assert summary["log_period"] == {
        "first_timestamp": "2023-03-15 07:05:04.108 +00:00",
        "last_timestamp": "2023-03-24 12:37:15.067 +00:00",
        "event_records": "653",
    }

    (source,) = [s for s in case.get_sources() if s.source_name == "logon.summary"]
    assert source.source_path == str(evtx_dir)
    text = "".join(w.raw_text for w in case.get_windows_by_source("logon.summary"))
    assert "# successful logons" in text and "# failed logons" in text
    assert "79,Sec 4624,SYSTEM" in text and "310,Sec 4625,Administrator" in text


def test_a_long_table_is_cut_with_the_number_left_out(
    case: CaseDB, evtx_dir: Path, binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [
        f"{i + 1},Sec 4624,user{i},CORP,SRV01,3 - Network,-,-,WS{i},10.0.1.{i}" for i in range(40)
    ]
    table = "\n".join([HEADER.format(kind="Successful"), *rows, ""])

    result, _argv = summarise(
        monkeypatch, binary, writes(successful=table), evtx_dir=str(evtx_dir)
    )

    good = result["results"]["successful"]
    assert len(good["with_source_address"]) == 15
    assert good["with_source_address"][0]["count"] == 40
    assert good["with_source_address_not_listed"] == 25
    assert good["logons"] == sum(range(1, 41))


def test_missing_rules_config_is_an_error_not_zero_logons(
    case: CaseDB, evtx_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The arm64 image once shipped an empty rules directory; every log then read as empty."""
    bare = tmp_path / "bare" / "hayabusa"
    bare.parent.mkdir()
    bare.write_text("#!/bin/sh\n")

    def no_config(cmd: list[str], prefix: str) -> subprocess.CompletedProcess[str]:
        Path(f"{prefix}-successful.csv").write_text(HEADER.format(kind="Successful") + "\n")
        return subprocess.CompletedProcess(cmd, 0, stdout="No logon events", stderr=NO_CONFIG)

    result, (argv,) = summarise(monkeypatch, bare, no_config, evtx_dir=str(evtx_dir))

    assert "--rules-config" not in argv
    assert result["status"] == "error" and result["error_type"] == "asset_missing"
    assert "Nothing was examined" in result["error_message"]
    assert not [s for s in case.get_sources() if s.source_name == "logon.summary"]


def test_a_failed_or_slow_run_is_an_error(
    case: CaseDB, evtx_dir: Path, binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(cmd: list[str], _prefix: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="panicked at src/main.rs")

    def hang(cmd: list[str], _prefix: str) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd, 300)

    crashed, _argv = summarise(monkeypatch, binary, crash, evtx_dir=str(evtx_dir))
    hung, _argv = summarise(monkeypatch, binary, hang, evtx_dir=str(evtx_dir))

    assert crashed["error_type"] == "tool_failed" and "panicked" in crashed["error_message"]
    assert hung["error_type"] == "timeout"


def test_no_logon_rows_is_reported_with_the_reasons_it_can_happen(
    case: CaseDB, evtx_dir: Path, binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = writes(HEADER.format(kind="Successful") + "\n", HEADER.format(kind="Failed") + "\n")

    result, _argv = summarise(monkeypatch, binary, empty, evtx_dir=str(evtx_dir))

    summary = result["results"]
    assert summary["successful"]["logons"] == summary["failed"]["logons"] == 0
    assert "not that nobody logged on" in summary["note"]
    assert "cleared, rolled over or absent" in summary["note"]
    # Nothing is registered, so the next call reads the logs again: a log that
    # was corrupt this time must not be skipped as done from then on.
    assert summary["index"]["status"] == "not_indexed"
    assert not [s for s in case.get_sources() if s.source_name == "logon.summary"]
    _again, argvs = summarise(monkeypatch, binary, writes(), evtx_dir=str(evtx_dir))
    assert len(argvs) == 1


def test_another_image_s_logs_are_never_summarised_as_this_image_s(
    case: CaseDB, evtx_dir: Path, binary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Host A's logs are extracted, host B's are not: B must not get A's logons."""
    host_b = tmp_path / "hostB.E01"
    host_b.write_bytes(b"EVF")
    monkeypatch.setattr(evtx_tools, "_evtx_extract_dirs", {"/evidence/hostA.E01": str(evtx_dir)})
    case.set_kv("evtx_extract_dir", str(evtx_dir))
    extracted: list[str] = []

    def no_logs(image: str) -> None:
        extracted.append(image)

    monkeypatch.setattr(hayabusa, "_extract_evtx_inline", no_logs)

    result, argvs = summarise(monkeypatch, binary, writes(), image_path=str(host_b))

    assert result["status"] == "error" and "No EVTX directory found" in result["error_message"]
    assert argvs == [] and extracted == [str(host_b)], "B's own logs were looked for"
    assert not case.get_sources()
    # Without an image named, the most recent extraction is still used.
    assert hayabusa._resolve_evtx_dir(None) == str(evtx_dir)
    assert hayabusa._resolve_evtx_dir(None, image_path="/evidence/hostA.E01") == str(evtx_dir)


def test_with_an_image_and_a_directory_the_summary_is_indexed_under_the_image(
    case: CaseDB, evtx_dir: Path, binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """start_extraction_batch skips by image_path, so that is the path the source must carry."""
    image = "/evidence/hostA.E01"

    first, _argv = summarise(
        monkeypatch, binary, writes(), evtx_dir=str(evtx_dir), image_path=image
    )
    again, argvs = summarise(monkeypatch, binary, writes(), image_path=image)

    assert first["status"] == "success"
    assert [s.source_path for s in case.get_sources()] == [image]
    assert "skipped" in again["preview"] and argvs == []


def test_source_addresses_are_classified_whatever_their_family() -> None:
    rows = [
        "5,Sec 4624,alice,CORP,SRV01,10 - RemoteInteractive,-,-,WS1,2a01:4f8:c17:1234::1",
        "4,Sec 4624,bob,CORP,SRV01,3 - Network,-,-,WS2,::ffff:45.33.32.156",
        "9,Sec 4624,carol,CORP,SRV01,3 - Network,-,-,WS3,fe80::1",
        "8,Sec 4624,dave,CORP,SRV01,3 - Network,-,-,WS4,::ffff:10.0.0.5",
        "7,Sec 4624,erin,CORP,SRV01,3 - Network,-,-,WS5,LOCAL",
        "3,Sec 4624,frank,CORP,SRV01,3 - Network,-,-,WS6,45.33.32.156",
    ]
    table: Any = hayabusa._logon_table("\n".join([HEADER.format(kind="Successful"), *rows]))

    # External first, then what could not be classified, then internal; by count within each.
    assert [(r["Target Account"], r["external"]) for r in table["with_source_address"]] == [
        ("alice", True),
        ("bob", True),
        ("frank", True),
        ("erin", None),
        ("carol", False),
        ("dave", False),
    ]


def test_malformed_rows_are_not_counted_and_fields_are_cleaned() -> None:
    """A failed logon's account name is whatever the remote party typed."""
    rows = [
        "2,Sec 4625,adm\x1b[31min\x07,CORP,SRV01,3 - Network,-,-,KALI,185.220.101.4",
        "not-a-count,Sec 4625,x,CORP,SRV01,3 - Network,-,-,KALI,185.220.101.4",
        "1,short,row",
    ]
    table: Any = hayabusa._logon_table("\n".join([HEADER.format(kind="Failed"), *rows]))

    assert (table["logons"], table["combinations"]) == (2, 1)
    (row,) = table["with_source_address"]
    assert row["Target Account"] == "adm?[31min?"


def test_it_is_skipped_per_target_and_does_not_mark_the_sigma_scan_as_done(
    case: CaseDB, evtx_dir: Path, binary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, argvs = summarise(monkeypatch, binary, writes(), evtx_dir=str(evtx_dir))
    again, more = summarise(monkeypatch, binary, writes(), evtx_dir=str(evtx_dir))
    forced, forced_argvs = summarise(
        monkeypatch, binary, writes(), evtx_dir=str(evtx_dir), force=True
    )

    assert first["status"] == "success" and len(argvs) == 1
    assert "skipped" in again["preview"] and more == []
    assert len(forced_argvs) == 1

    # A second EVTX directory in the same case is its own target.
    other = tmp_path / "other"
    other.mkdir()
    (other / "Security.evtx").write_bytes(b"ElfFile\x00")
    second, second_argvs = summarise(monkeypatch, binary, writes(), evtx_dir=str(other))
    assert second["status"] == "success" and len(second_argvs) == 1

    # run_hayabusa skips when any "hayabusa." source exists; this one must not count.
    ran: list[list[str]] = []

    def sigma_scan(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        ran.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("mulder.server.tools.hayabusa.subprocess.run", sigma_scan)
    run_hayabusa.__wrapped__(str(evtx_dir))  # type: ignore[attr-defined]
    assert ran and ran[0][1] == "csv-timeline"
