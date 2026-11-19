"""Loose log MCP tool: index log files and load their events into log tables.

The logs that say how an intruder got in rarely come inside a disk image: a VPN or
firewall export, a web server's access logs, Zeek or Suricata output, the logs of a
hypervisor. ``run_loose_logs`` reads such files, recognises each one's format
(``mulder.logparse``), indexes every line as text and loads what it could parse as rows
(``mulder.logtable``), which ``log_top``, ``log_histogram`` and ``log_rows`` count over.

Three sources are derived from the rows: SigmaHQ web server rule matches, a list of web
shell candidates, and the lines of an ESXi log that matter in a hypervisor ransomware
case. Each is a lead and says so in its first line.
"""

from __future__ import annotations

import gzip
import itertools
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

import yaml
from sqlalchemy import text

from mulder import logparse, logtable
from mulder.assets.paths import asset_path
from mulder.extractors.classifier import EvidenceClassifier, is_esxi_bundle, is_loose_log
from mulder.logparse import SKIP, Row
from mulder.path_policy import PathPolicyError
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.netflow.tools import _resolve_evidence
from mulder.server.tools.zircolite import (
    _NO_RULES_MARKER,
    _detection_lines,
    _missing_zircolite_modules,
    _parse_zircolite_output,
    _run_zircolite_process,
    _zircolite_script,
)

__all__ = ["run_loose_logs"]

_PREFIX = "logs."
_EXTRACTOR = "looselogs"
_WEB = "logs.web"
_ESXI = "logs.esxi"
# ponytail: a source holds at most this many lines and this many characters, so what
# waits to be loaded stays within a few hundred MB whatever the log's size or the
# length of its lines; the price is one source per 100,000 lines. Index the text in a
# stream (extract_and_index takes one string) if sources crowd.
_PART_LINES = 100_000
_PART_CHARS = 64 << 20  # of the lines and row values queued for one source
_VALUE_CHARS = 4 * logtable.MAX_VALUE_CHARS  # of one row value that a log table reads
_READ_CHARS = 65_536  # of one line that are parsed
_LINE_CHARS = 4_000  # of one line that are indexed
_FILE_CHARS = 1 << 30  # of one file that are read: a gzip bomb ends here
_CALL_CHARS = 4 << 30  # of all files in one call
_MAX_FILES = 5_000
_SNIFF_LINES = 50
_NAMED = 10  # file names the result lists per reason
_MAX_DETECTIONS = 20_000  # Sigma matches indexed; every match is counted
_MAX_HIGHLIGHTS = 50_000
_SIGMA_SECONDS = 1_800  # spent in Zircolite before the rest is left unscanned
_SHELL_CLIENTS = 3
_MAX_CANDIDATES = 100
_SCRIPT_EXTS = (
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".asp", ".aspx",
    ".ashx", ".asmx", ".jsp", ".jspx", ".cfm", ".cgi", ".pl",
)  # fmt: skip

# str.splitlines breaks on all of these, and so does the window builder: left in a
# line they would shift every later row's line number. Tabs stay (Zeek).
_BREAKS = {c: " " for c in (*range(9), *range(10, 32), 0x7F, 0x85, 0x2028, 0x2029)}

# What a web event is called for the Sigma scan: the W3C names the rules use.
_RAW, _TIME = "mulder.raw", "mulder.event_time"
_SIGMA_FIELDS = (
    "c-ip", "cs-username", "cs-method", "cs-uri-stem", "cs-uri-query",
    "sc-status", "cs-user-agent", "cs-referer", "cs-host",
    _RAW, _TIME, "mulder.source", "mulder.line",
)  # fmt: skip
# Another name rules give the user agent.
_ALIASES = {"cs-user-agent": "c-useragent"}
_NOT_A_LOG = "not a log by its name (pass the file itself to read it)"
_RULES_RAN = re.compile(r"Executing ruleset - (\d+) rules")


def _web_rules(out: Path) -> int:
    """Write the installed SigmaHQ web server rules to *out*; return how many.

    Most of the generic rules are keyword lists ("=whoami", "UNION SELECT"), matched
    anywhere in the event. Zircolite builds its SQLite backend without a full-text
    column, so it cannot convert them and would run the rest as if nothing were
    missing. A keyword list is the same test as "this field contains any of", so each
    is rewritten against the field that holds the original log line.
    """
    generic = asset_path("sigma-rules", "rules", "web", "webserver_generic")
    emerging = asset_path("sigma-rules", "rules-emerging-threats")
    paths = sorted(generic.glob("*.yml")) if generic else []
    paths += sorted(emerging.rglob("web_*.yml")) if emerging else []
    out.mkdir()
    written = 0
    for path in paths:
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        source = rule.get("logsource") if isinstance(rule, dict) else None
        if not isinstance(source, dict) or source.get("category") != "webserver":
            continue
        detection = rule.get("detection")
        for name, value in detection.items() if isinstance(detection, dict) else ():
            # A bare list is "any of these words"; {"|all": [...]} is "all of them".
            every = isinstance(value, dict) and list(value) == ["|all"]
            words = value["|all"] if every else value
            if isinstance(words, list) and words and not any(isinstance(w, dict) for w in words):
                test = f"{_RAW}|contains|all" if every else f"{_RAW}|contains"
                detection[name] = {test: [str(word) for word in words]}
        (out / f"{written:03d}.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
        written += 1
    return written


class _Sigma:
    """Runs the web server rules over web events, a part at a time.

    Zircolite holds its events in memory (about 2.6 KB each, measured), so they are
    handed over 100,000 at a time, as the text is indexed, or sooner when their lines
    are long.
    """

    def __init__(self, tmp: Path, evidence_path: str) -> None:
        self.tmp = tmp
        self.evidence_path = evidence_path
        self.events: list[str] = []
        self.chars = 0  # of the events waiting
        self.detections: list[str] = []  # as indexed lines: a match repeats its request
        self.by_rule: dict[str, int] = {}
        self.status = ""
        self.rules = self.rules_ran = self.scanned = self.unscanned = self.matches = 0
        self.spent = 0.0

    def add(self, row: Row, raw: str, source: str) -> None:
        extra = row.get("extra") or {}
        stem, query = row.get("target"), extra.get("query")
        event = {
            "c-ip": row.get("src_ip"),
            "cs-username": row.get("actor"),
            "cs-method": row.get("action"),
            "cs-uri-stem": stem,
            # The whole request target, as a proxy logs it: most of the rules look in
            # this field for a path ("/cgi-bin/.%2e/"), not only for what follows "?".
            "cs-uri-query": f"{stem}?{query}" if query else stem,
            "sc-status": row.get("status"),
            "cs-user-agent": row.get("user_agent"),
            "cs-referer": extra.get("referer"),
            "cs-host": extra.get("host"),
            _RAW: raw,
            _TIME: logtable.normalise_time(row.get("event_time")),
            "mulder.source": source,
            "mulder.line": row.get("line"),
        }
        self.events.append(json.dumps({k: v for k, v in event.items() if v not in (None, "")}))
        self.chars += len(self.events[-1])
        if len(self.events) >= _PART_LINES or self.chars >= _PART_CHARS:
            self.scan()

    def _ready(self) -> str:
        """Why the scan cannot run, or an empty string when it can."""
        missing = _missing_zircolite_modules()
        if missing or _zircolite_script() is None:
            what = f"missing {', '.join(missing)}" if missing else "Zircolite is not installed"
            return f"skipped: {what} (pipx install 'mulder-dfir[forensics]'; mulder setup)"
        self.rules = _web_rules(self.tmp / "rules")
        if not self.rules:
            return "skipped: the SigmaHQ web server rules are not installed (mulder setup)"
        return ""

    def scan(self) -> None:
        """Scan the events gathered so far."""
        events, self.events, self.chars = self.events, [], 0
        if not events:
            return
        if not self.status:
            self.status = self._ready() or "ok"
        if self.status != "ok" or self.spent > _SIGMA_SECONDS:
            self.unscanned += len(events)
            return
        work = Path(tempfile.mkdtemp(dir=self.tmp))
        (work / "events.json").write_text("\n".join(events), encoding="utf-8")
        (work / "fields.json").write_text(
            json.dumps(
                {
                    "exclusions": [],
                    "useless": [None, ""],
                    # Identity mappings: without one, Zircolite truncates a field name
                    # to its last dotted segment.
                    "mappings": {name: name for name in _SIGMA_FIELDS},
                    "alias": _ALIASES,
                    "split": {},
                }
            ),
            encoding="utf-8",
        )
        started = time.monotonic()
        try:
            results, proc = _run_zircolite_process(
                str(_zircolite_script()),
                work / "events.json",
                "json",
                self.tmp / "rules",
                work,
                (),
                work / "fields.json",
            )
            output = f"{proc.stdout or ''}{proc.stderr or ''}"
            ran = _RULES_RAN.search(output)
            if _NO_RULES_MARKER in output or not ran or not int(ran[1]):
                self.status = "error: Zircolite loaded none of the web server rules"
            elif not results.exists():
                self.status = f"error: Zircolite exited {proc.returncode} without results"
            else:
                self.rules_ran = int(ran[1])
                found = _parse_zircolite_output(results, self.evidence_path, "json")["detections"]
                for detection in found:
                    fields = detection["matched_fields"]
                    detection["timestamp"] = fields.pop(_TIME, "")
                    # The line is in the source the match names; the rest is repetition.
                    repeated = (_RAW, "OriginalLogfile", "row_id", "cs-uri-stem")
                    for key in (*repeated, *_ALIASES.values()):
                        fields.pop(key, None)
                    title = str(detection["rule_title"])
                    self.by_rule[title] = self.by_rule.get(title, 0) + 1
                self.matches += len(found)
                self.detections += _detection_lines(
                    found[: _MAX_DETECTIONS - len(self.detections)]
                )
        except subprocess.TimeoutExpired as exc:
            self.status = f"error: Zircolite timed out after {exc.timeout:.0f} seconds"
        except OSError as exc:
            self.status = f"error: {exc}"[:200]
        finally:
            self.spent += time.monotonic() - started
            shutil.rmtree(work, ignore_errors=True)
        if self.status == "ok":
            self.scanned += len(events)
        else:
            self.unscanned += len(events)

    def report(self) -> dict[str, object]:
        """Index the matches and describe the scan."""
        self.scan()
        status = self.status or "skipped: no web events"
        if status == "ok" and self.unscanned:
            status = f"stopped after {_SIGMA_SECONDS // 60} minutes: later requests not scanned"
        elif status == "ok" and self.rules_ran < self.rules:
            status = (
                f"ok ({self.rules_ran} of {self.rules} rules ran; Zircolite could not "
                "convert the others)"
            )
        entry: dict[str, object] = {"sigma": status}
        if self.unscanned:
            entry["sigma_events_not_scanned"] = self.unscanned
        if not self.scanned:
            return entry
        header = (
            f"Sigma web server rule matches in {self.evidence_path}: {self.matches} matches "
            f"over {self.scanned} requests, {self.rules_ran} of {self.rules} rules. A match "
            "shows that a request looked like an attack, not that it succeeded: read the "
            "status and what the same address did next (mulder.source and mulder.line name "
            "the request's line)."
        )
        if self.matches > len(self.detections):
            header += f" Only the first {len(self.detections)} matches are listed."
        source = f"{_WEB}.detections"
        extract_and_index(
            "\n".join([header, *sorted(self.detections)]),
            source,
            self.evidence_path,
            _EXTRACTOR,
        )
        top = sorted(self.by_rule.items(), key=lambda kv: (-kv[1], kv[0]))
        entry.update(
            sigma_events_scanned=self.scanned,
            detections=self.matches,
            rules_matched=dict(top[:20]),
            detections_source=source,
        )
        return entry


def _webshell_candidates(evidence_path: str, ids: list[int]) -> dict[str, object]:
    """Index the script paths that few clients ever asked for and that took a POST.

    One read-only statement over the web rows this call loaded. Everything in it is a
    constant or a bound parameter.
    """
    params: dict[str, object] = {"t": _WEB, "clients": _SHELL_CLIENTS, "n": _MAX_CANDIDATES}
    params.update({f"s{i}": source_id for i, source_id in enumerate(ids)})
    params.update({f"e{i}": f"%{ext}" for i, ext in enumerate(_SCRIPT_EXTS)})
    posted = "SUM(upper(action) IS 'POST' AND substr(status, 1, 1) IS '2')"
    statement = text(
        "SELECT json_extract(extra, '$.host'), target, COUNT(*), "
        f"{posted}, COUNT(DISTINCT src_ip), MIN(event_time), MAX(event_time),"
        " group_concat(DISTINCT src_ip), COUNT(*) OVER () FROM log_events"
        f" WHERE log_table = :t AND source_id IN ({', '.join(f':s{i}' for i in range(len(ids)))})"
        f" AND ({' OR '.join(f'target LIKE :e{i}' for i in range(len(_SCRIPT_EXTS)))})"
        f" GROUP BY 1, 2 HAVING {posted} > 0 AND COUNT(DISTINCT src_ip) <= :clients"
        " ORDER BY 5, 4 DESC, 2 LIMIT :n"
    )
    with get_ctx().db.engine.connect() as conn:
        found = conn.execute(statement, params).fetchall()
    total = found[0][8] if found else 0
    header = (
        f"Web shell candidates in {evidence_path}: {total} script paths (.php, .asp, .aspx, "
        f".jsp and the like) that answered a POST with a 2xx status and that at most "
        f"{_SHELL_CLIENTS} client addresses ever requested. A lead, not a verdict: an admin "
        "page or a rarely used endpoint looks the same. A shell that was only ever fetched "
        "with GET, that answered with another status, or whose path has no script extension "
        "is not listed. Read its requests in logs.web before calling it a web shell."
    )
    if total > len(found):
        header += f" Only the first {len(found)} are listed."
    lines = [
        f"{first or '-'}\t{last or '-'}\t{host or '-'}\t{path}\tposts={posts}"
        f"\trequests={requests}\tclients={clients}"
        for host, path, requests, posts, _, first, last, clients, _ in found
    ]
    source = f"{_WEB}.webshell"
    extract_and_index("\n".join([header, *lines]), source, evidence_path, _EXTRACTOR)
    return {"webshell_candidates": total, "webshell_source": source}


@dataclass
class _Table:
    """One source's lines and rows waiting to be indexed, and what it loaded so far."""

    source: str
    tabular: bool
    lines: list[str] = field(default_factory=list)
    rows: list[Row | None] = field(default_factory=list)
    chars: int = 0  # of the queued lines and row values
    file: str | None = None
    names: list[str] = field(default_factory=list)  # the sources written
    ids: list[int] = field(default_factory=list)  # of those whose rows were loaded
    examples: list[str] = field(default_factory=list)  # the first files read
    files: int = 0
    total: int = 0
    loaded: int = 0
    unparsed: int = 0
    untimed: int = 0
    naive: bool = False
    guessed_year: bool = False
    covered_by: str | None = None

    def add(self, file: str, line: str, row: Row | None) -> None:
        """Queue one line of *file*, and its row when it has one."""
        mark = "-\t" if self.tabular else ""
        if file != self.file:
            self.file = file
            self.files += 1
            self.examples += [file][: _NAMED - len(self.examples)]
            self.lines.append(f"{mark}# file: {file}")
        elif not self.lines:  # a part that continues a file names it again
            self.lines.append(f"{mark}# file: {file} (continued)")
        self.lines.append(line)
        self.chars += len(line)
        self.total += 1
        if row is None:
            self.rows.append(None)
        elif row is not SKIP:
            row["line"] = len(self.lines)
            row.setdefault("extra", {})["file"] = file
            self.rows.append(row)

    def cut(self, row: Row) -> None:
        """Cut the values of a queued *row* to what the log table reads of one, and
        count them: a request can carry 64 KiB in each of several fields."""
        for values in (row, row["extra"]):
            for key, value in values.items():
                if isinstance(value, list | dict) and key != "extra":
                    value = str(value)  # as the table would read it
                if isinstance(value, str):
                    values[key] = value[:_VALUE_CHARS]
                    self.chars += len(values[key])

    @property
    def name(self) -> str:
        """The source the queued lines will be indexed as."""
        return self.source if not self.names else f"{self.source}.{len(self.names) + 1}"

    def flush(self, evidence_path: str) -> None:
        """Index the queued lines as one source and load their rows."""
        if not self.lines:
            return
        name = self.name
        indexed = extract_and_index("\n".join(self.lines), name, evidence_path, _EXTRACTOR)
        self.names.append(name)
        rows, self.lines, self.rows, self.chars = self.rows, [], [], 0
        if not self.tabular:
            return
        source_id = int(str(indexed["source_id"]))
        # The directory is read recursively, so one evidence path can lie inside
        # another: its events are then in the table once, not twice.
        loaded = logtable.ingest(get_ctx().db, self.source, source_id, rows, nested=True)
        if "covered_by" in loaded:
            self.covered_by = str(loaded["covered_by"])
        else:
            self.ids.append(source_id)
        self.loaded += loaded["rows"]
        self.unparsed += loaded["rows_unparsed"]
        self.untimed += loaded["rows_no_time"]

    def summary(self) -> dict[str, object]:
        entry: dict[str, object] = {"files": self.files, "lines": self.total}
        if len(self.names) > 1:  # a large log is indexed in parts
            entry["sources"] = f"{self.names[0]}, and {self.names[1]} to {self.names[-1]}"
        if not self.tabular:
            entry["examples"] = self.examples
            entry["note"] = "format not recognised: indexed as text, nothing parsed; use search"
            return entry
        entry.update(log_table=self.source, rows=self.loaded, rows_not_parsed=self.unparsed)
        if self.untimed:
            entry["rows_without_time"] = self.untimed
        if self.covered_by:
            entry["log_table_note"] = (
                "no rows added: these events are already in the table from "
                f"{self.covered_by}, which contains this path"
            )
        return entry


class _Reader:
    """The lines of a text stream, bounded: by line, and by *budget* characters in all."""

    def __init__(self, stream: IO[str], budget: int) -> None:
        self.stream = stream
        self.budget = self.left = budget
        self.cut = False
        self.long = 0  # lines read only as far as is parsed

    def __iter__(self) -> Iterator[str]:
        while True:
            if self.left <= 0:
                self.cut = bool(self.stream.read(1))
                return
            line = self.stream.readline(_READ_CHARS)
            if not line:
                return
            self.left -= len(line)
            more, dropped = line, False
            # A line longer than is parsed: the rest of it is read and dropped.
            while len(more) == _READ_CHARS and not more.endswith("\n") and self.left > 0:
                more = self.stream.readline(_READ_CHARS)
                self.left -= len(more)
                dropped = dropped or bool(more.strip())
            self.long += dropped
            yield line.rstrip("\n")


def _open(path: Path) -> IO[str]:
    """*path* as text, a line ending wherever a line feed, a carriage return or both
    end it. gzip is read through; PowerShell's ">" writes UTF-16."""
    with path.open("rb") as probe:
        magic = probe.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    encoding = "utf-16" if magic in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    return path.open("r", encoding=encoding, errors="replace")


class _Run:
    """One call's state: the tables being filled and what was left out, and why."""

    def __init__(self, evidence_path: str, tmp: Path, esxi: bool) -> None:
        self.evidence_path = evidence_path
        self.esxi = esxi
        self.tables: dict[str, _Table] = {}
        self.not_read: dict[str, dict[str, Any]] = {}  # reason -> files, examples
        self.left = _CALL_CHARS
        self.read = self.cut_lines = self.long_lines = 0
        self.sigma = _Sigma(tmp, evidence_path)
        self.highlights: list[str] = []
        self.categories: dict[str, int] = {}

    def skip(self, reason: str, name: str) -> None:
        """Count a file that is not read, and keep the first few names."""
        entry = self.not_read.setdefault(reason, {"files": 0, "examples": []})
        entry["files"] += 1
        entry["examples"] += [name][: _NAMED - len(entry["examples"])]

    def file(self, path: Path, name: str, mtime: datetime | None) -> None:
        """Read one file into its tables."""
        if self.left <= 0:
            self.skip("over the size limit for one call", name)
            return
        table: _Table | None = None
        reader: _Reader | None = None
        lost = ""  # why the rest of the file is in no count
        try:
            with _open(path) as stream:
                reader = _Reader(stream, min(_FILE_CHARS, self.left))
                lines = iter(reader)
                head = list(itertools.islice(lines, _SNIFF_LINES))
                if any("\x00" in line for line in head):
                    self.skip("binary", name)
                    return
                if not any(line.strip() for line in head):
                    self.skip("empty", name)
                    return
                self.read += 1
                fmt = logparse.sniff(path.name, head, mtime, self.esxi)
                for line in itertools.chain(head, lines):
                    if line.strip():
                        table = self.line(fmt, name, line)
                if reader.cut:
                    lost = f"read only in part (the first {reader.budget >> 20} MiB of text)"
        except (OSError, EOFError, zlib.error) as exc:
            # A truncated or corrupt gzip stream fails part-way: what was read stays.
            lost = f"unreadable or damaged ({type(exc).__name__})"
        finally:
            if reader is not None:
                self.left -= reader.budget - reader.left
                self.long_lines += reader.long
        if lost:
            self.skip(lost, name)
            if table is not None and table.tabular:
                table.rows.append(None)

    def line(self, fmt: logparse.Format, name: str, line: str) -> _Table:
        """Parse *line* and queue it for the table its format names."""
        row = fmt.parse(line)
        table = self.tables.get(fmt.source)
        if table is None:
            table = self.tables[fmt.source] = _Table(fmt.source, fmt.tabular)
        table.naive |= fmt.naive
        table.guessed_year |= fmt.guessed_year
        indexed = line.translate(_BREAKS)
        if len(indexed) > _LINE_CHARS:
            indexed = f"{indexed[:_LINE_CHARS]}…"
            self.cut_lines += 1
        if fmt.tabular:
            # The event's own time leads, in one form: the index takes a window's time
            # from the first timestamp in it and reads neither Apache's nor Zeek's.
            when = logtable.normalise_time(row.get("event_time")) if row else None
            indexed = f"{when or '-'}\t{indexed}"
        table.add(name, indexed, row)
        if row:
            if fmt.source == _WEB:
                self.sigma.add(row, line, table.name)
            category = row["extra"].get("highlight")
            if category:
                self.categories[category] = self.categories.get(category, 0) + 1
                if len(self.highlights) < _MAX_HIGHLIGHTS:
                    values = (
                        category,
                        row["extra"].get("program"),
                        row.get("actor"),
                        row.get("src_ip"),
                        str(row["extra"].get("message") or "")[:1000],
                    )
                    # str.split breaks on tabs and every line separator alike.
                    columns = "\t".join(" ".join(str(v or "-").split()) for v in values)
                    self.highlights.append(f"{indexed.partition(chr(9))[0]}\t{columns}")
            table.cut(row)  # after the Sigma scan was given the whole of each value
        if len(table.lines) >= _PART_LINES or table.chars >= _PART_CHARS:
            table.flush(self.evidence_path)
        return table

    def esxi_highlights(self) -> dict[str, object]:
        """Index the ESXi lines that matter in a hypervisor ransomware case."""
        total = sum(self.categories.values())
        counts = ", ".join(f"{name} {n}" for name, n in sorted(self.categories.items()))
        header = (
            f"ESXi highlights in {self.evidence_path}: {total} lines ({counts or 'none'}). "
            "Columns: time "
            "(UTC), category, program, user, source address, message. These are pattern "
            "matches on known ESXi messages: a category says what a line is about, not that "
            "it was hostile (exec_policy and vib_install include lines that only read a "
            "setting), and a line that is not listed may still be in logs.esxi."
        )
        if total > len(self.highlights):
            header += f" Only the first {len(self.highlights)} are listed."
        source = f"{_ESXI}.highlights"
        extract_and_index(
            "\n".join([header, *sorted(self.highlights)]), source, self.evidence_path, _EXTRACTOR
        )
        return {"highlights": total, "by_category": self.categories, "highlights_source": source}


def _walk(
    tops: list[Path], root: Path, run: _Run, whole: bool
) -> Iterator[tuple[Path, str, datetime | None]]:
    """Every log file under *tops*, with its name relative to *root* and its
    modification time. Symlinks are not followed and nothing but a regular file is
    opened: a link could point anywhere, and a FIFO would block the read.

    In a log directory every file is a log, and *whole* says that *tops* lie in one or
    in a bundle. Any other directory may hold a web root or a source tree beside its
    logs: there only what the classifier takes for a log file is read, and nothing
    hidden, which is what the planner counted when it listed the directory.
    """

    def shown(path: object) -> str:
        return os.path.relpath(str(path), root).translate(_BREAKS)[:300]

    def unlisted(exc: OSError) -> None:  # os.walk would pass over it in silence
        run.skip(f"directory could not be listed ({type(exc).__name__})", shown(exc.filename))

    seen = 0
    logs: set[str] = set()  # the folders whose every file is read
    for top in tops:
        single = top.is_file()
        walk: Iterable[tuple[str, list[str], list[str]]] = (
            [(str(top.parent), [], [top.name])] if single else os.walk(top, onerror=unlisted)
        )
        for folder, folders, names in walk:
            if (
                whole
                or single
                or os.path.dirname(folder) in logs
                or EvidenceClassifier._is_log_directory(Path(folder))
            ):
                logs.add(folder)
            else:
                folders[:] = [name for name in folders if not name.startswith(".")]
            folders.sort()
            # os.walk lists a linked directory and does not enter it: say so.
            names += [name for name in folders if os.path.islink(os.path.join(folder, name))]
            for name in sorted(names):
                path = Path(folder, name)
                try:
                    info = path.lstat()
                except OSError:
                    run.skip("unreadable or damaged (OSError)", shown(path))
                    continue
                if not stat.S_ISREG(info.st_mode):
                    kind = "symbolic link" if stat.S_ISLNK(info.st_mode) else "not a regular file"
                    run.skip(kind, shown(path))
                    continue
                if folder not in logs and (name.startswith(".") or not is_loose_log(path)):
                    run.skip(_NOT_A_LOG, shown(path))
                    continue
                seen += 1
                if seen > _MAX_FILES:  # counted, so that the result says how many
                    run.skip(f"over the limit of {_MAX_FILES} files for one call", shown(path))
                    continue
                try:
                    mtime = datetime.fromtimestamp(info.st_mtime, tz=UTC)
                except (OverflowError, OSError, ValueError):
                    mtime = None  # a time outside the calendar: the file is read all the same
                yield path, shown(path), mtime


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_loose_logs(evidence_path: str, force: bool = False) -> dict[str, object]:
    """Index loose log files and load their events into log tables.

    Call on evidence of type "log_file", "log_directory" or "esxi_bundle": web server
    access logs (Apache, nginx, IIS), VPN and firewall logs (FortiGate, SonicWall,
    Cisco ASA), Zeek and Suricata logs, ESXi logs and syslog. The format of each file is
    recognised from its content; plain and gzip files are read.

    Returns, per source it wrote, the files and lines read, the rows loaded into the
    log table of the same name and the rows that could not be parsed. Every line is
    indexed as text behind its UTC time. A file whose format is not recognised is
    indexed as logs.text and nothing in it is parsed; files that were not read at all
    (binary, symbolic link, not a log by its name, over a limit) are counted in
    files_not_read with the reason.
    For web logs it also runs the SigmaHQ web server rules (logs.web.detections) and
    lists web shell candidates (logs.web.webshell); for ESXi logs it lists logins,
    shell commands, SSH or shell being enabled, virtual machines powered off, the
    execInstalledOnly setting and VIB installs (logs.esxi.highlights). Those three are
    leads to read, not findings.

    Args:
        evidence_path: A log file, or a directory read recursively: every file of a
            log directory (named log or logs, or under var/log), and elsewhere the
            files named as logs (.log, .txt, rotated .log.N, Suricata or Zeek JSON).
            For an ESXi support bundle pass the bundle directory: its var/run/log and
            var/log are read.
        force: Re-run even if this path was already indexed.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "run_loose_logs"
    params: dict[str, object] = {"evidence_path": evidence_path, "force": force}

    try:
        root = _resolve_evidence(evidence_path)
    except PathPolicyError as exc:
        return error_response(tc_id, name, params, str(exc), error_type="invalid_argument")
    if not root.exists():
        return error_response(
            tc_id, name, params, f"Path not found: {evidence_path}", error_type="file_not_found"
        )

    if not force:
        existing = sources_already_indexed([_PREFIX], evidence_path=evidence_path)
        if existing:
            skipped: dict[str, object] = {
                "status": "skipped",
                "reason": "Sources already indexed from prior extraction",
                "existing_sources": existing,
            }
            return tool_response(tc_id, name, params, skipped, None, 0.0)

    bundle = root.is_dir() and is_esxi_bundle(root)
    tops = [root]
    if bundle:
        logs = (root / "var" / "run" / "log", root / "var" / "log")
        tops = [d for d in logs if d.is_dir() and not d.is_symlink()]
    near = (root, *list(root.parents)[:4])
    inside_bundle = any(is_esxi_bundle(folder) for folder in near)
    whole = inside_bundle or any(map(EvidenceClassifier._is_log_directory, near))
    base = root if root.is_dir() else root.parent

    with tempfile.TemporaryDirectory(prefix="mulder_looselogs_") as tmpdir:
        run = _Run(evidence_path, Path(tmpdir), inside_bundle)
        for path, shown, mtime in _walk(tops, base, run, whole):
            run.file(path, shown, mtime)
        for table in run.tables.values():
            table.flush(evidence_path)
        if not run.tables:
            return error_response(
                tc_id,
                name,
                params,
                f"No readable log files in {evidence_path}"
                + (f" (not read: {', '.join(sorted(run.not_read))})" if run.not_read else ""),
                (time.monotonic() - t0) * 1000,
                error_type="no_data",
            )

        # Returned in full rather than as a preview: it is bounded, and it is where the
        # caller learns which sources and tables to use.
        summary: dict[str, object] = {"evidence_path": evidence_path, "files_read": run.read}
        if bundle:
            summary["esxi_bundle"] = (
                "read var/run/log and var/log only; the bundle's commands/ and etc/ hold "
                "command output and configuration and were not indexed"
            )
        if run.not_read:
            summary["files_not_read"] = dict(sorted(run.not_read.items()))
        summary["sources"] = {
            source: table.summary() for source, table in sorted(run.tables.items())
        }
        notes: list[str] = []
        naive = sorted(s for s, t in run.tables.items() if t.naive)
        if naive:
            notes.append(
                f"times in {', '.join(naive)} carry no UTC offset and were read as UTC: "
                "if the device kept local time they are off by its offset"
            )
        guessed = sorted(s for s, t in run.tables.items() if t.guessed_year)
        if guessed:
            notes.append(
                f"lines in {', '.join(guessed)} carry no year: it was taken from each "
                "file's modification time, which copying the file can change"
            )
        if run.cut_lines:
            notes.append(
                f"{run.cut_lines} lines longer than {_LINE_CHARS} characters were cut in "
                "the indexed text (they were parsed whole, up to 64 KiB)"
            )
        if run.long_lines:
            notes.append(
                f"{run.long_lines} lines are longer than {_READ_CHARS} characters: the "
                "rest of each was neither parsed nor indexed"
            )
        if notes:
            summary["notes"] = notes

        web = run.tables.get(_WEB)
        if web is not None:
            entry = run.sigma.report()
            if web.ids:
                entry.update(_webshell_candidates(evidence_path, web.ids))
            summary["web"] = entry
        if _ESXI in run.tables:
            summary["esxi"] = run.esxi_highlights()
        summary["hint"] = (
            "list_log_tables shows each table's fields and time range; count with "
            "log_top and log_histogram, read events with log_rows. A row's source and "
            "line say where its event is indexed: a large log is indexed in parts "
            "(logs.web, logs.web.2 and so on) and the line counts within the part. "
            "Search that exact source: a table's name alone also matches its parts and "
            "the sources derived from it."
        )

    return tool_response(tc_id, name, params, summary, None, (time.monotonic() - t0) * 1000)
