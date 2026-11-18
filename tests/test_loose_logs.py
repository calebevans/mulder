"""run_loose_logs: loose log files are recognised, indexed, loaded as rows and routed.

Before this the classifier labelled such files ``log_file`` and ``log_directory`` and
nothing read them. The tool tests run on a real case database; only Zircolite is stubbed.
"""

from __future__ import annotations

import gzip
import inspect
import json
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml

from mulder import logtable
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.extractors.classifier import EvidenceClassifier, loose_log_targets
from mulder.orchestrator import prompts
from mulder.orchestrator.evidence import EvidenceContext
from mulder.orchestrator.types import PhaseResult
from mulder.server import app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.helpers import TOOL_SOURCE_PREFIXES
from mulder.server.tool_access import Role, get_tools_for_role
from mulder.server.tools import looselogs
from mulder.server.tools.logtables import log_rows, log_top
from mulder.server.tools.looselogs import run_loose_logs
from mulder.server.tools.review import _EVIDENCE_INPUT_PARAMS, _EVIDENCE_TOOL_MAP

_PROMPTS = Path(prompts.__file__).parent


def _hit(ip: str, method: str, path: str, status: int = 200, second: int = 0) -> str:
    return (
        f'{ip} - - [10/Oct/2023:13:55:{second:02d} +0000] "{method} {path} HTTP/1.1" '
        f'{status} 512 "-" "Mozilla/5.0"'
    )


_IIS = (
    "#Software: Microsoft Internet Information Services 8.5\n"
    "#Fields: date time cs-method cs-uri-stem cs-uri-query c-ip cs(User-Agent) sc-status\n"
    "2016-08-10 22:21:34 GET /joomla/agent.php - 23.22.63.114 Opera/9.02 200\n"
)
_ZEEK = (
    "#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
    "1705314153.5\tC1\t10.0.0.5\t203.0.113.9\t443\ttcp\n#close\t2024-01-15-11-00-00\n"
)
_EVE = (
    '{"timestamp":"2016-08-28T23:58:59.931869-0600","event_type":"dns","src_ip":"8.8.8.8",'
    '"dest_ip":"10.0.0.5","dns":{"type":"answer","rrname":"a.example","rdata":"203.0.113.9"}}\n'
    '{"timestamp":"2016-08-28T23:59:00.000000-0600","event_type":"alert","src_ip":"10.0.0.5",'
    '"dest_ip":"203.0.113.9","alert":{"signature":"ET TROJAN x","action":"allowed"}}\n'
)
_FIREWALL = (
    'date=2024-01-15 time=03:12:44 tz="-0800" devname=fw1 logid="0101039947" type="event" '
    'subtype="vpn" action="tunnel-up" tunneltype="ssl-web" remip=203.0.113.50 user="jsmith"\n'
    "Jan 15 2024 10:22:33 fw01 : %ASA-6-113039: Group <VPN> User <jsmith> IP <203.0.113.50> "
    "AnyConnect parent session started.\n"
)
_SYSLOG = (
    "Mar  4 12:38:02 web01 sshd[1234]: Accepted password for root from 203.0.113.9 port 5\n"
    "Mar  4 12:38:05 web01 sudo: root : TTY=pts/0 ; COMMAND=/bin/bash\n"
)
_SHELL_LOG = (
    "2025-05-06T14:10:00Z shell[288199]: [root]: chmod +x /tmp/encrypt\n"
    "2025-05-06T14:35:04Z shell[288199]: [root]: esxcli vm process kill --type=force "
    "--world-id=1\n"
    "2025-05-06T14:36:00Z shell[288199]: [root]: esxcli system settings kernel set -s "
    "execinstalledonly -v FALSE\n"
)
_HOSTD_LOG = (
    "2025-05-06T14:00:00.123Z info hostd[2099999] [Originator@6876 sub=Vimsvc.ha-eventmgr "
    "opID=esxui-1 user=root] Event 105 : SSH access has been enabled\n"
    '-->    eventTypeId = "vim.event.EventEx",\n'
    "2025-05-06T14:05:00.000Z info hostd[2099999] [Originator@6876 sub=Vimsvc.ha-eventmgr] "
    "Event 131 : User root@198.51.100.7 logged in as VMware-client/6.5.0\n"
    "2025-05-06T14:06:00.000Z verbose hostd[2099999] [Originator@6876 sub=PropertyProvider] "
    "RecordOp ASSIGN: info\n"
)


@pytest.fixture
def evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """An empty evidence directory with a real case database behind the server context."""
    root = tmp_path / "evidence"
    root.mkdir()
    db_dir = tmp_path / "db"
    db = CaseDB.create(case_id="case", evidence_root=str(root), db_dir=db_dir)
    ctx = app.ServerContext(
        case_id="case", db=db, correlator=MagicMock(), audit=AuditLog(db_dir / "case.audit.jsonl")
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    monkeypatch.setattr(app, "_cfg", app.ServerConfig(db_dir=db_dir))
    yield root
    db.close()


def _run(path: Path, force: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = run_loose_logs.__wrapped__(str(path), force)  # type: ignore[attr-defined]
    return result


def _ok(path: Path, force: bool = False) -> dict[str, Any]:
    result = _run(path, force)
    assert result["status"] == "success", result
    summary: dict[str, Any] = result["results"]
    return summary


def _lines(source: str) -> list[str]:
    """Every indexed line of *source*, in order: index 0 is line 1."""
    windows = app.get_ctx().db.get_windows_by_source(source)
    return "".join(w.raw_text for w in windows).splitlines()


def _table(name: str) -> dict[str, Any]:
    return next(t for t in logtable.tables(app.get_ctx().db) if t["table"] == name)


def _rows(table: str, **kwargs: Any) -> list[dict[str, Any]]:
    result = log_rows.__wrapped__(table, limit=200, **kwargs)  # type: ignore[attr-defined]
    assert result["status"] in ("success", "skipped"), result
    rows: list[dict[str, Any]] = result["rows"]
    return rows


def test_a_directory_of_mixed_logs_is_indexed_and_loaded(evidence: Path, tmp_path: Path) -> None:
    logs = evidence / "web01" / "logs"
    (logs / "nginx").mkdir(parents=True)
    (logs / "nginx" / "access.log").write_text(
        f"{_hit('203.0.113.9', 'GET', '/index.php?id=1')}\nnot a request line\n"
        f"{_hit('198.51.100.7', 'POST', '/login.php', 302, 5)}\n"
    )
    (logs / "u_ex160810.log").write_text(_IIS)
    (logs / "conn.log").write_text(_ZEEK)
    (logs / "eve.json").write_text(_EVE)
    (logs / "firewall.log").write_text(_FIREWALL)
    (logs / "messages").write_text(_SYSLOG)
    (logs / "notes.txt").write_text("Collected by the on-call engineer.\nSecond line.\n")
    (logs / "lastlog").write_bytes(b"\x00\x01\x02" * 400)
    (logs / "empty.log").write_text("\n\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "planted.log").write_text(_hit("192.0.2.1", "GET", "/planted"))
    (logs / "planted.log").symlink_to(outside / "planted.log")
    (logs / "planted-dir").symlink_to(outside, target_is_directory=True)

    summary = _ok(logs)

    assert summary["files_read"] == 7
    assert {name: s["files"] for name, s in summary["sources"].items()} == {
        "logs.firewall": 1,
        "logs.suricata.alert": 1,
        "logs.suricata.dns": 1,
        "logs.syslog": 1,
        "logs.text": 1,
        "logs.web": 2,
        "logs.zeek.conn": 1,
    }
    web = summary["sources"]["logs.web"]
    assert (web["log_table"], web["rows"], web["rows_not_parsed"]) == ("logs.web", 3, 1)
    assert summary["sources"]["logs.firewall"]["rows"] == 2
    # Text that nothing could parse is indexed and said to be unparsed; it gets no table.
    assert "nothing parsed" in summary["sources"]["logs.text"]["note"]
    assert "log_table" not in summary["sources"]["logs.text"]
    assert "Second line." in _lines("logs.text")
    # What was not read at all is counted, with the reason.
    assert {r: v["examples"] for r, v in summary["files_not_read"].items()} == {
        "binary": ["lastlog"],
        "empty": ["empty.log"],
        "symbolic link": ["planted-dir", "planted.log"],  # neither is followed
    }
    assert not any("/planted" in line for line in _lines("logs.web"))
    assert summary["web"]["sigma"].startswith("skipped:")  # no Zircolite in the test run
    # The firewall and syslog lines carry no zone, and syslog no year: the result says so.
    assert "logs.syslog" in summary["notes"][0] and "read as UTC" in summary["notes"][0]
    assert "logs.syslog carry no year" in summary["notes"][1]

    rows = _rows("logs.web")
    assert [(r["time"], r["src_ip"], r["action"], r["target"], r["status"]) for r in rows] == [
        ("2016-08-10T22:21:34Z", "23.22.63.114", "GET", "/joomla/agent.php", "200"),
        ("2023-10-10T13:55:00Z", "203.0.113.9", "GET", "/index.php", "200"),
        ("2023-10-10T13:55:05Z", "198.51.100.7", "POST", "/login.php", "302"),
    ]
    assert rows[1]["query"] == "id=1" and rows[1]["file"] == "nginx/access.log"
    # A row names the line of the indexed text that holds the whole event: the original
    # line, behind its UTC time.
    text = _lines("logs.web")
    assert text[0] == "-\t# file: u_ex160810.log" and "-\t# file: nginx/access.log" in text
    for row in rows:
        when, _, original = text[row["line"] - 1].partition("\t")
        assert when == row["time"] and row["target"] in original
    assert text[rows[1]["line"]] == "-\tnot a request line"
    vpn = _rows("logs.firewall", filters=[{"field": "tunnel_type", "op": "exists"}])
    assert [(r["time"], r["actor"], r["src_ip"], r["action"], r["vendor"]) for r in vpn] == [
        ("2024-01-15T10:22:33Z", "jsmith", "203.0.113.50", "session-started", "asa"),
        ("2024-01-15T11:12:44Z", "jsmith", "203.0.113.50", "tunnel-up", "fortigate"),
    ]
    assert _table("logs.zeek.conn")["first_time"] == "2024-01-15T10:22:33Z"
    assert _table("logs.suricata.dns")["first_time"] == "2016-08-29T05:58:59Z"
    assert _table("logs.syslog")["rows"] == 2


def test_a_single_file_is_read_by_itself(evidence: Path) -> None:
    (evidence / "access.log").write_text(_hit("203.0.113.9", "GET", "/"))
    (evidence / "other.log").write_text(_hit("198.51.100.7", "GET", "/other"))

    summary = _ok(evidence / "access.log")

    assert summary["files_read"] == 1
    assert _lines("logs.web")[0] == "-\t# file: access.log"
    assert [r["target"] for r in _rows("logs.web")] == ["/"]


def test_line_separators_in_a_line_do_not_shift_the_rows_after_it(evidence: Path) -> None:
    """str.splitlines, which the window builder uses, breaks on all of these. Left in a
    line they would make every later row point one line too early."""
    hostile = _hit("203.0.113.9", "GET", "/a").replace("Mozilla", "Moz\u2028il\x0cla\x85\x1e\rX")
    (evidence / "access.log").write_text(
        f"{hostile}\n{_hit('198.51.100.7', 'GET', '/b', second=1)}\n", newline=""
    )

    _ok(evidence / "access.log")

    text = _lines("logs.web")
    assert len(text) == 3  # the file line and one line per request
    second = _rows("logs.web")[1]
    assert second["target"] == "/b" and "/b" in text[second["line"] - 1]
    assert "Moz il la   X" in text[1]


def test_a_large_log_is_indexed_in_parts(evidence: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(looselogs, "_PART_LINES", 4)
    hits = [_hit("203.0.113.9", "GET", f"/page{n}", second=n) for n in range(8)]
    (evidence / "access.log").write_text("\n".join(hits))

    summary = _ok(evidence / "access.log")

    web = summary["sources"]["logs.web"]
    assert web["sources"] == "logs.web, and logs.web.2 to logs.web.3"
    assert (web["lines"], web["rows"]) == (8, 8)
    assert _lines("logs.web.2")[0] == "-\t# file: access.log (continued)"
    assert _table("logs.web")["rows"] == 8
    # Every row still names its own source and line.
    for row in _rows("logs.web"):
        assert row["target"] in _lines(row["source"])[row["line"] - 1]
    parts = {"logs.web", "logs.web.2", "logs.web.3"}
    assert {row["source"] for row in _rows("logs.web")} == parts


def test_a_second_run_is_skipped_and_a_forced_one_replaces_its_rows(evidence: Path) -> None:
    (evidence / "access.log").write_text(_hit("203.0.113.9", "GET", "/"))
    _ok(evidence / "access.log")

    again = _run(evidence / "access.log")
    assert again["results"]["status"] == "skipped"
    assert again["results"]["existing_sources"] == ["logs.web", "logs.web.webshell"]

    _ok(evidence / "access.log", force=True)
    assert _table("logs.web")["rows"] == 1


def test_overlapping_paths_are_counted_once(evidence: Path) -> None:
    """The directory is read recursively, so a file in it holds events the table has."""
    logs = evidence / "logs"
    logs.mkdir()
    (logs / "access.log").write_text(_hit("203.0.113.9", "GET", "/"))
    _ok(logs)

    inside = _ok(logs / "access.log")

    note = inside["sources"]["logs.web"]["log_table_note"]
    assert "no rows added" in note and str(logs) in note
    assert inside["sources"]["logs.web"]["rows"] == 0
    assert _table("logs.web")["rows"] == 1
    assert "webshell_candidates" not in inside["web"]  # nothing of this call's to summarise


def test_gzip_is_read_and_a_damaged_one_keeps_what_came_before(evidence: Path) -> None:
    logs = evidence / "logs"
    logs.mkdir()
    hits = "\n".join(_hit("203.0.113.9", "GET", f"/page{n}", second=n % 60) for n in range(5000))
    (logs / "access.log.1.gz").write_bytes(gzip.compress(hits.encode()))
    whole = gzip.compress(hits.replace("/page", "/cut").encode())
    (logs / "access.log.2.gz").write_bytes(whole[: len(whole) // 2])

    summary = _ok(logs)

    web = summary["sources"]["logs.web"]
    assert web["files"] == 2 and 5000 < web["rows"] < 10000
    assert web["rows_not_parsed"] >= 1  # the lost tail is in no count, and that is said
    assert summary["files_not_read"]["unreadable or damaged (EOFError)"]["examples"] == [
        "access.log.2.gz"
    ]


def test_every_limit_that_bites_is_reported(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs = evidence / "logs"
    logs.mkdir()
    long_agent = _hit("203.0.113.9", "GET", "/long").replace("Mozilla/5.0", "A" * 300)
    (logs / "a.log").write_text("\n".join([long_agent, *[_hit("203.0.113.9", "GET", "/")] * 9]))
    for name in ("b.log", "c.log", "d.log"):
        (logs / name).write_text(_hit("198.51.100.7", "GET", f"/{name}"))
    monkeypatch.setattr(looselogs, "_LINE_CHARS", 120)
    monkeypatch.setattr(looselogs, "_FILE_CHARS", 700)
    monkeypatch.setattr(looselogs, "_MAX_FILES", 3)

    summary = _ok(logs)

    assert summary["files_not_read"] == {
        "over the limit of 3 files for one call": {"files": 1, "examples": ["d.log"]},
        "read only in part (the first 0 MiB of text)": {"files": 1, "examples": ["a.log"]},
    }
    web = summary["sources"]["logs.web"]
    assert web["rows"] < 12 and web["rows_not_parsed"] == 1
    # The index holds the start of a long line; the row was parsed from all of it.
    assert "1 lines longer than 120 characters were cut" in summary["notes"][0]
    assert _lines("logs.web")[1].endswith("…")
    assert (
        _rows("logs.web", filters=[{"field": "target", "op": "eq", "value": "/long"}])[0][
            "user_agent"
        ]
        == "A" * 300
    )

    # The budget of a whole call: the first file uses it up, the others are not opened.
    monkeypatch.setattr(looselogs, "_CALL_CHARS", 100)
    capped = _ok(logs, force=True)
    assert capped["files_not_read"]["over the size limit for one call"]["examples"] == [
        "b.log",
        "c.log",
    ]


def test_a_line_longer_than_is_read_is_dropped_past_the_limit(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(looselogs, "_READ_CHARS", 200)
    first = _hit("203.0.113.9", "GET", "/first")
    (evidence / "access.log").write_text(
        f"{first}\n{'x' * 5000}\n{first.replace('first', 'last')}"
    )

    summary = _ok(evidence / "access.log")

    web = summary["sources"]["logs.web"]
    assert (web["lines"], web["rows"], web["rows_not_parsed"]) == (3, 2, 1)
    assert [r["target"] for r in _rows("logs.web")] == ["/first", "/last"]


def test_paths_outside_the_evidence_are_refused(evidence: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.log"
    outside.write_text(_hit("192.0.2.1", "GET", "/"))
    (evidence / "link.log").symlink_to(outside)

    assert _run(outside)["error_type"] == "invalid_argument"
    assert _run(evidence / "link.log")["error_type"] == "invalid_argument"
    assert _run(evidence / "missing.log")["error_type"] == "file_not_found"
    assert app.get_ctx().db.get_sources() == []


def test_nothing_but_a_regular_file_is_opened(evidence: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs on this platform")
    logs = evidence / "logs"
    logs.mkdir()
    os.mkfifo(logs / "pipe.log")  # opening it would block for ever

    result = _run(logs)

    assert result["error_type"] == "no_data"
    assert "not a regular file" in result["error_message"]


def test_web_shell_candidates_are_scripts_few_clients_post_to(evidence: Path) -> None:
    hits = [_hit(f"198.51.100.{n}", "POST", "/login.php") for n in range(1, 6)]
    hits += [
        _hit("203.0.113.9", "POST", "/uploads/cmd.php?x=1", second=10),
        _hit("203.0.113.9", "POST", "/uploads/cmd.php", second=20),
        _hit("203.0.113.10", "GET", "/uploads/cmd.php", second=30),
        _hit("203.0.113.9", "GET", "/uploads/only-get.php"),  # never posted to
        _hit("203.0.113.9", "POST", "/uploads/denied.aspx", 403),  # the POST failed
        _hit("203.0.113.9", "POST", "/api/items"),  # not a script
    ]
    (evidence / "access.log").write_text("\n".join(hits))

    summary = _ok(evidence / "access.log")

    assert summary["web"]["webshell_candidates"] == 1
    header, *candidates = _lines(summary["web"]["webshell_source"])
    assert candidates == [
        "2023-10-10T13:55:10Z\t2023-10-10T13:55:30Z\t-\t/uploads/cmd.php\tposts=2\trequests=3"
        "\tclients=203.0.113.9,203.0.113.10"
    ]
    # The caveat travels with the list.
    assert "A lead, not a verdict" in header and "only ever fetched with GET" in header


def test_an_esxi_bundle_is_read_for_its_logs_and_highlights(evidence: Path) -> None:
    bundle = evidence / "esx-esx01-2025-05-06--14.40"
    (bundle / "commands").mkdir(parents=True)
    (bundle / "etc" / "vmware").mkdir(parents=True)
    (bundle / "commands" / "esxcli_vm-process-list.txt").write_text("db01\n")
    logs = bundle / "var" / "run" / "log"
    logs.mkdir(parents=True)
    (logs / "shell.log").write_text(_SHELL_LOG)
    (logs / "hostd.0.gz").write_bytes(gzip.compress(_HOSTD_LOG.encode()))
    # Named for nothing ESXi writes, and no line says ESXi: being in the bundle does.
    (logs / "collected.log").write_text(
        "2025-05-06T14:04:00Z sshd[2100001]: Accepted password for root from 198.51.100.7 port 5\n"
    )

    summary = _ok(bundle)

    assert "commands/ and etc/" in summary["esxi_bundle"]
    assert list(summary["sources"]) == ["logs.esxi"] and summary["files_read"] == 3
    esxi = summary["sources"]["logs.esxi"]
    assert (esxi["lines"], esxi["rows"], esxi["rows_not_parsed"]) == (8, 7, 0)
    assert summary["esxi"]["by_category"] == {
        "shell_command": 1,
        "vm_power": 1,
        "exec_policy": 1,
        "ssh_shell_access": 1,
        "login": 2,
    }
    header, *found = _lines(summary["esxi"]["highlights_source"])
    assert "not that it was hostile" in header and "6 lines" in header
    # In time order, whatever file each line came from: the sequence of the intrusion.
    assert [line.split("\t")[:5] for line in found] == [
        ["2025-05-06T14:00:00Z", "ssh_shell_access", "hostd", "root", "-"],
        ["2025-05-06T14:04:00Z", "login", "sshd", "root", "198.51.100.7"],
        ["2025-05-06T14:05:00Z", "login", "hostd", "root", "198.51.100.7"],
        ["2025-05-06T14:10:00Z", "shell_command", "shell", "root", "-"],
        ["2025-05-06T14:35:04Z", "vm_power", "shell", "root", "-"],
        ["2025-05-06T14:36:00Z", "exec_policy", "shell", "root", "-"],
    ]
    assert found[3].endswith("[root]: chmod +x /tmp/encrypt")
    # The same categories are a field of the table, so they can be counted.
    top = log_top.__wrapped__(  # type: ignore[attr-defined]
        "logs.esxi",
        ["highlight", "src_ip"],
        [{"field": "highlight", "op": "eq", "value": "login"}],
    )
    assert [(r["src_ip"], r["count"]) for r in top["rows"]] == [("198.51.100.7", 2)]
    commands = _rows("logs.esxi", filters=[{"field": "program", "op": "eq", "value": "shell"}])
    assert commands[0]["action"] == "chmod +x /tmp/encrypt" and commands[0]["actor"] == "root"
    assert commands[0]["file"] == "var/run/log/shell.log"


def _sigma_tree(root: Path) -> None:
    """The two places the SigmaHQ tree keeps web server rules, and a rule that is not one."""
    generic = root / "sigma-rules" / "rules" / "web" / "webserver_generic"
    emerging = root / "sigma-rules" / "rules-emerging-threats" / "2021" / "Exploits"
    generic.mkdir(parents=True)
    emerging.mkdir(parents=True)
    (generic / "web_sql_injection_in_access_logs.yml").write_text(
        "title: SQL Injection Strings In URI\nlogsource:\n    category: webserver\n"
        "detection:\n    selection:\n        cs-method: 'GET'\n    keywords:\n"
        "        - 'UNION SELECT'\n        - '=select '\n"
        "    filter_main_status:\n        sc-status: 404\n"
        "    condition: selection and keywords and not 1 of filter_main_*\nlevel: high\n"
    )
    (emerging / "web_cve_2021_41773_apache_path_traversal.yml").write_text(
        "title: CVE-2021-41773\nlogsource:\n    category: webserver\ndetection:\n"
        "    selection:\n        cs-uri-query|contains: '/cgi-bin/.%2e/'\n"
        "    keywords:\n        '|all':\n            - 'POST'\n            - 200\n"
        "    condition: selection or keywords\nlevel: high\n"
    )
    (emerging / "web_proxy_rule.yml").write_text(
        "title: Proxy\nlogsource:\n    category: proxy\ndetection:\n"
        "    selection:\n        c-uri: 'x'\n    condition: selection\n"
    )


def test_keyword_rules_are_rewritten_so_that_they_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zircolite's SQLite backend has no full-text column: it drops a rule that is a
    list of keywords and runs the rest as if the ruleset were whole."""
    _sigma_tree(tmp_path)
    monkeypatch.setattr(looselogs, "asset_path", lambda *parts: tmp_path.joinpath(*parts))

    assert looselogs._web_rules(tmp_path / "out") == 2  # the proxy rule is not for web logs

    rules = [yaml.safe_load(p.read_text()) for p in sorted((tmp_path / "out").iterdir())]
    assert rules[0]["detection"] == {
        "selection": {"cs-method": "GET"},  # a field test is left as it was
        "keywords": {"mulder.raw|contains": ["UNION SELECT", "=select "]},
        "filter_main_status": {"sc-status": 404},
        "condition": "selection and keywords and not 1 of filter_main_*",
    }
    assert rules[1]["detection"]["selection"] == {"cs-uri-query|contains": "/cgi-bin/.%2e/"}
    # "All of these words", and a number among them: contains takes text.
    assert rules[1]["detection"]["keywords"] == {"mulder.raw|contains|all": ["POST", "200"]}


def test_sigma_matches_on_web_requests_are_indexed(
    evidence: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sigma_tree(tmp_path)
    monkeypatch.setattr(looselogs, "asset_path", lambda *parts: tmp_path.joinpath(*parts))
    monkeypatch.setattr(looselogs, "_missing_zircolite_modules", lambda: [])
    monkeypatch.setattr(looselogs, "_zircolite_script", lambda: tmp_path / "zircolite.py")
    monkeypatch.setattr(looselogs, "_PART_LINES", 2)
    scans: list[list[dict[str, Any]]] = []

    def zircolite(
        script: str, events: Path, fmt: str, rules: Path, out: Path, extra: object, config: Path
    ) -> tuple[Path, subprocess.CompletedProcess[str]]:
        seen = [json.loads(line) for line in events.read_text().splitlines()]
        scans.append(seen)
        assert len(list(rules.glob("*.yml"))) == 2 and fmt == "json"
        fields = json.loads(config.read_text())
        assert fields["alias"] == {"cs-uri": "c-uri", "cs-user-agent": "c-useragent"}
        assert set(seen[0]) <= set(fields["mappings"])
        matches = [e for e in seen if "UNION SELECT" in e["mulder.raw"]]
        results = out / "zircolite_results.json"
        results.write_text(
            json.dumps(
                [{"title": "SQL Injection Strings In URI", "id": "r1", "rule_level": "high",
                  "tags": ["attack.t1190"], "matches": matches}] if matches else []
            )
        )  # fmt: skip
        ran = "[+] Executing ruleset - 1 rules"
        return results, subprocess.CompletedProcess([], 0, stdout=ran, stderr="")

    monkeypatch.setattr(looselogs, "_run_zircolite_process", zircolite)
    (evidence / "access.log").write_text(
        "\n".join(
            [
                _hit("203.0.113.9", "GET", "/"),
                _hit("203.0.113.9", "GET", "/item.php?id=1%20UNION SELECT%201", second=1),
                _hit("198.51.100.7", "GET", "/about", second=2),
            ]
        )
    )

    web = _ok(evidence / "access.log")["web"]

    # The events are handed over in bounded parts, under the W3C names the rules use,
    # each with its original line and where that line is indexed (here the second
    # source: a part is two lines, and the first holds the file line and one request).
    assert [len(scan) for scan in scans] == [2, 1]
    assert scans[0][1] == {
        "c-ip": "203.0.113.9",
        "cs-method": "GET",
        "cs-uri-stem": "/item.php",
        "cs-uri-query": "id=1%20UNION SELECT%201",
        "cs-uri": "/item.php?id=1%20UNION SELECT%201",
        "sc-status": "200",
        "cs-user-agent": "Mozilla/5.0",
        "mulder.raw": _hit("203.0.113.9", "GET", "/item.php?id=1%20UNION SELECT%201", second=1),
        "mulder.event_time": "2023-10-10T13:55:01Z",
        "mulder.source": "logs.web.2",
        "mulder.line": 2,
    }
    assert "UNION SELECT" in _lines("logs.web.2")[1]
    assert web["sigma"] == "ok (1 of 2 rules ran; Zircolite could not convert the others)"
    assert (web["sigma_events_scanned"], web["detections"]) == (3, 1)
    assert web["rules_matched"] == {"SQL Injection Strings In URI": 1}
    header, match = _lines(web["detections_source"])
    assert "not that it succeeded" in header and "1 matches over 3 requests" in header
    assert match.startswith("2023-10-10T13:55:01Z\thigh\tSQL Injection Strings In URI\tr1")
    assert '"mulder.line":2,"mulder.source":"logs.web.2"' in match and "mulder.raw" not in match


def test_a_sigma_scan_that_cannot_run_says_so_and_the_log_is_still_loaded(
    evidence: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(looselogs, "_missing_zircolite_modules", lambda: [])
    monkeypatch.setattr(looselogs, "_zircolite_script", lambda: tmp_path / "zircolite.py")
    (evidence / "access.log").write_text(_hit("203.0.113.9", "GET", "/"))

    web = _ok(evidence / "access.log")["web"]  # no rules under the (empty) asset root

    assert web["sigma"] == "skipped: the SigmaHQ web server rules are not installed (mulder setup)"
    assert web["sigma_events_not_scanned"] == 1 and "detections_source" not in web
    assert _table("logs.web")["rows"] == 1

    _sigma_tree(tmp_path)
    monkeypatch.setattr(looselogs, "asset_path", lambda *parts: tmp_path.joinpath(*parts))

    def no_rules(*args: object) -> tuple[Path, subprocess.CompletedProcess[str]]:
        return tmp_path / "none.json", subprocess.CompletedProcess([], 0, stdout="", stderr="")

    monkeypatch.setattr(looselogs, "_run_zircolite_process", no_rules)
    web = _ok(evidence / "access.log", force=True)["web"]
    assert web["sigma"] == "error: Zircolite loaded none of the web server rules"
    assert web["sigma_events_not_scanned"] == 1


# --- Classification and routing ------------------------------------------------------


def _types(root: Path) -> dict[str, str]:
    return {
        str(c.path.relative_to(root.resolve())): c.artifact_type
        for c in EvidenceClassifier().classify(root)
    }


def _bundle(path: Path) -> Path:
    for part in ("commands", "etc/vmware", "var/run/log", "var/log/vmware"):
        (path / part).mkdir(parents=True)
    (path / "var" / "run" / "log" / "hostd.log").write_text(_HOSTD_LOG)
    (path / "commands" / "esxcli_software-vib-list.txt").write_text("VIBs\n")
    return path


def _tree(root: Path) -> Path:
    """A host with a /var/log, a directory of web logs, a sensor's output, a bundle, and
    a host directory that holds a memory image beside a note."""
    (root / "web01" / "var" / "log" / "nginx").mkdir(parents=True)
    (root / "web01" / "var" / "log" / "auth.log").write_text(_SYSLOG)
    (root / "web01" / "var" / "log" / "nginx" / "access.log").write_text(
        _hit("1.2.3.4", "GET", "/")
    )
    iis = root / "iis-export"
    iis.mkdir()
    (iis / "u_ex160810.log").write_text(_IIS)
    (iis / "u_ex160811.log").write_text(_IIS)
    (iis / "u_ex160809.log.1").write_text(_IIS)  # a rotated log
    sensor = root / "sensor"
    sensor.mkdir()
    (sensor / "eve.json").write_text(_EVE)
    (sensor / "package.json").write_text('{"name": "not a log"}')
    _bundle(root / "esx01-vm-support")
    (root / "ws-07").mkdir()
    (root / "ws-07" / "memory.raw").write_bytes(b"\x00" * 64)
    (root / "ws-07" / "collection.txt").write_text("collected with winpmem\n")
    (root / "fortigate.log").write_text(_FIREWALL)
    return root


def test_log_evidence_is_classified_without_an_item_per_file_in_a_log_directory(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path / "evidence")

    assert _types(root) == {
        # One item for the bundle and one for /var/log: what is under them is theirs.
        "esx01-vm-support": "esxi_bundle",
        "web01/var/log": "log_directory",
        "fortigate.log": "log_file",
        "iis-export/u_ex160809.log.1": "log_file",
        "iis-export/u_ex160810.log": "log_file",
        "iis-export/u_ex160811.log": "log_file",
        "sensor/eve.json": "log_file",  # Suricata's JSON, by its keys
        "ws-07/collection.txt": "log_file",
        "ws-07/memory.raw": "memory_dump",
    }
    # The evidence directory may be the bundle itself.
    assert _types(root / "esx01-vm-support") == {".": "esxi_bundle"}


def test_loose_log_files_are_read_by_directory_only_where_that_reads_nothing_else(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path / "evidence").resolve()

    targets = loose_log_targets(EvidenceClassifier().classify(root), root)

    assert {str(p.relative_to(root)): v for p, v in targets.items()} == {
        "esx01-vm-support": ("esxi_bundle", 1),
        "web01/var/log": ("log_directory", 1),
        "iis-export": ("log_file", 3),  # the directory holds only logs: one run
        "sensor": ("log_file", 1),
        # Beside a memory image, and at the top of the evidence, a run on the directory
        # would wander into other evidence: the file is read by itself.
        "ws-07/collection.txt": ("log_file", 1),
        "fortigate.log": ("log_file", 1),
    }
    # A single file given as the evidence is its own target, never its directory.
    alone = root / "fortigate.log"
    assert loose_log_targets(EvidenceClassifier().classify(alone), alone) == {
        alone: ("log_file", 1)
    }


def _context(
    root: Path, name: str, evidence_types: list[str], extracted: Path | None = None
) -> str:
    ctx = EvidenceContext(str(root), extracted_dir=extracted)
    systems = [{"name": name, "type": "Network", "evidence": evidence_types}]
    systems.append({"name": "ws-07", "type": "Windows", "evidence": ["memory_dump"]})
    ctx.identify_systems(
        PhaseResult(phase_name="catalog", messages=[]), cached_catalog_data={"systems": systems}
    )
    return ctx.build_evidence_context(name)


def test_the_planner_is_given_each_log_target_and_the_tool(tmp_path: Path) -> None:
    root = _tree(tmp_path / "evidence")

    host = _context(root, "web01", ["log_directory"])
    assert 'Log directories (type "log_directory"):' in host
    assert f"  {root / 'web01' / 'var' / 'log'}\n" in host
    assert "nginx" not in host  # not planned a second time for a directory inside
    assert 'run_loose_logs(evidence_path=<directory>) task, group "foundation"' in host

    web = _context(root, "iis-export", ["log_file"])
    assert f"  {root / 'iis-export'}  (3 files)" in web
    assert "run_loose_logs(evidence_path=<path>)" in web and "u_ex160810" not in web

    esx = _context(root, "esx01-vm-support", ["esxi_bundle"])
    assert 'ESXi support bundles (type "esxi_bundle"):' in esx
    assert f"  {root / 'esx01-vm-support'}\n" in esx and "hostd.log" not in esx

    # A device the catalog named for what it is, not for its file: the type is enough,
    # and it gets only the logs no other system's name claims.
    firewall = _context(root, "Perimeter firewall", ["log_file"])
    assert f"  {root / 'fortigate.log'}\n" in firewall
    assert "ws-07" not in firewall
    for text in (host, web, esx, firewall):
        assert "No pre-populated paths available" not in text


def test_logs_delivered_in_an_archive_are_planned_where_they_were_unpacked(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "esx01-vm-support.tgz").write_bytes(b"\x1f\x8b")
    extracted = tmp_path / "extracted"
    bundle = _bundle(extracted / "esx01-vm-support-abc123" / "esx-esx01-2025-05-06")

    text = _context(root, "esx01-vm-support", ["esxi_bundle"], extracted)

    assert f"  {bundle}\n" in text


def test_rotated_logs_are_not_planned_as_archives_nor_large_logs_as_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The planner context lists every .gz as an archive to unpack first, and every
    unpacked file over 100 MB as a memory dump. A log directory is full of the first,
    and a web server's logs are often the second: run_loose_logs reads both as they are."""
    root = _tree(tmp_path / "evidence")
    (root / "web01" / "var" / "log" / "auth.log.2.gz").write_bytes(gzip.compress(b"x\n"))
    (root / "esx01-vm-support" / "var" / "run" / "log" / "hostd.0.gz").write_bytes(b"\x1f\x8b")
    (root / "web01" / "backup.tar.gz").write_bytes(b"\x1f\x8b")  # not in a log directory
    extracted = tmp_path / "extracted"
    slot = extracted / "web01-logs-abc123"
    (slot / "var" / "log").mkdir(parents=True)
    for name in ("access.log", "var/log/messages", "var/log/messages.1.gz", "memory.bin"):
        (slot / name).write_text("x\n")
    real_stat = Path.stat

    def big(self: Path, **kwargs: Any) -> os.stat_result:
        return os.stat_result((*real_stat(self, **kwargs)[:6], 200 << 20, 0, 0, 0))

    monkeypatch.setattr(Path, "stat", big)  # every file is 200 MiB

    host = _context(root, "web01", ["log_directory"], extracted)
    esx = _context(root, "esx01-vm-support", ["esxi_bundle"], extracted)

    assert "NESTED ARCHIVES" not in esx
    archives = host.split("NESTED ARCHIVES", 1)[1].split("Log directories", 1)[0]
    assert "backup.tar.gz" in archives and "auth.log.2.gz" not in archives
    assert "messages.1.gz" not in archives
    memory = host.split("Extracted memory dumps", 1)[1].split("NESTED ARCHIVES", 1)[0]
    assert "memory.bin" in memory and "access.log" not in memory and "messages" not in memory


def test_the_coverage_audit_counts_a_run_for_the_target_it_read(tmp_path: Path) -> None:
    root = _tree(tmp_path / "evidence")
    db_dir = tmp_path / "db"
    db = CaseDB.create(case_id="cov", evidence_root=str(root), db_dir=db_dir)
    audit = AuditLog(db_dir / "cov.audit.jsonl")
    for n, target in enumerate((root / "iis-export", root / "web01" / "var" / "log" / "nginx")):
        audit.log_tool_call(
            f"tc_{n}", "run_loose_logs", {"evidence_path": str(target)}, "sha256:x"
        )
    ctx = MagicMock(db=db, audit=audit, case_id="cov")
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("mulder.server.tools.review.get_ctx", lambda: ctx)
            patch.setattr("mulder.server.tools.review.get_cfg", lambda: MagicMock(db_dir=db_dir))
            result = _tool_dispatch_sync["audit_tool_coverage"]()
    finally:
        db.close()

    logs = {
        str(Path(str(i["path"])).relative_to(root.resolve())): i
        for i in result["coverage"]
        if "run_loose_logs" in (*i["tools_run"], *i["tools_not_run"])
    }
    assert {path: item["tools_run"] for path, item in logs.items()} == {
        "iis-export": ["run_loose_logs"],
        # A run on a directory inside it did not read /var/log.
        "web01/var/log": [],
        "esx01-vm-support": [],
        "sensor": [],
        "ws-07/collection.txt": [],
        "fortigate.log": [],
    }
    assert logs["iis-export"]["files"] == 3 and "files" not in logs["sensor"]


def test_the_tool_is_wired_the_way_the_batch_and_the_audit_expect() -> None:
    assert list(inspect.signature(run_loose_logs.__wrapped__).parameters) == [  # type: ignore[attr-defined]
        "evidence_path",  # the name start_extraction_batch scopes its skip by
        "force",
    ]
    assert TOOL_SOURCE_PREFIXES["run_loose_logs"] == ["logs."]
    assert _EVIDENCE_INPUT_PARAMS["run_loose_logs"] == ("evidence_path",)
    for kind in ("log_file", "log_directory", "esxi_bundle"):
        assert _EVIDENCE_TOOL_MAP[kind] == ["run_loose_logs"]
    executor = get_tools_for_role(Role.EXTRACT_EXECUTOR)
    analyst = get_tools_for_role(Role.EXTRACT_ANALYST)
    assert any(name.endswith("run_loose_logs") for name in executor)
    assert not any(name.endswith("run_loose_logs") for name in analyst)


def test_the_prompts_say_what_these_logs_do_and_do_not_show() -> None:
    catalog = (_PROMPTS / "catalog.md").read_text()
    planner = (_PROMPTS / "extract_planner.md").read_text()
    analyst = (_PROMPTS / "extract_analyst.md").read_text()

    for kind in ('"log_file"', '"log_directory"', '"esxi_bundle"'):
        assert kind in catalog
    assert "run_loose_logs(evidence_path=<path as listed>)" in planner
    assert "which account logged in, from which address and when" in planner
    # The analyst cannot run the tool; it is told what to ask for, and what a lead is.
    assert "follow-up request that names run_loose_logs" in analyst
    for source in ("logs.web.detections", "logs.web.webshell", "logs.esxi.highlights"):
        assert source in analyst
    assert "Both are leads" in analyst
    assert 'No row is not "no login"' in analyst
    assert "submit a [COLLECT] finding naming the log" in analyst
