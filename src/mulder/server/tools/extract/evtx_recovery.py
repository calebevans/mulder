"""Recover Windows event log records that survived a log clearing (evtx_dump)."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
import threading
import time
import zlib
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mulder.extractors.optical import OpticalError, raw_image
from mulder.server.app import get_ctx, has_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    adaptive_timeout,
    cli_path,
    error_response,
    make_tool_call_id,
    require_binary,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = ["run_evtx_recovery"]

_NAME = "run_evtx_recovery"
# Not under "evtx.": run_evtx_parser treats any evtx.* source of a path as
# proof that the path's live logs were parsed, and would then skip them.
_PREFIX = "evtx_recovered."
_SUMMARY_SOURCE = _PREFIX + "summary"

# Channel name patterns (fnmatch, case-insensitive) recovered by default.
_DEFAULT_CHANNELS = (
    "Security",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-*",
)
_DEFAULT_MAX_RECORDS = 10_000
_MAX_RECORDS_LIMIT = 100_000
_MAX_EVTX_FILES = 2_000
# A record names its own channel, so evidence can invent as many as it likes.
_MAX_CHANNELS = 40
_MAX_RESPONSE_CHANNELS = 20
_MAX_RESPONSE_EVENT_IDS = 10
_MAX_LISTED = 20

_CHUNK_SIZE = 65536
_HEADER_SIZE = 4096
_CHUNK_MAGIC = b"ElfChnk\x00"
_RECORD_MAGIC = b"\x2a\x2a\x00\x00"
_FIRST_RECORD = 512
_SCAN_BLOCK = 16 * 1024 * 1024
_BATCH_CHUNKS = 256

# Microsoft-Windows-Eventlog writes these when a log is cleared.
_CLEARING_EVENTS = {("security", 1102), ("system", 104)}

_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}(T\d{2}(:\d{2}(:\d{2}(\.\d+)?)?)?)?")
# How evtx_dump writes a record's time. Anything else is evidence text.
_STAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?")
# str.splitlines() breaks a line on these too, and json.dumps leaves them as
# they are: a record holding one could otherwise forge an indexed line.
_LINE_BREAKS = {0x85: "\\u0085", 0x2028: "\\u2028", 0x2029: "\\u2029"}

_INTERPRETATION = (
    "Recovered records are what happened to survive in cleared or reused space: a "
    "partial remainder, not the log. A recovered record shows that event was logged. "
    "No recovered record for an event or a period does not show it did not happen."
)
_NOT_COMPARED = (
    "No extracted live logs were available to compare with, so [carved] records "
    "include any that are still in the live logs. For a disk image, run "
    "run_evtx_parser on it first, then this tool with force=True."
)


def _flat(value: object, limit: int = 120) -> str:
    """One bounded line: evidence text must not split a record or flood a response."""
    return " ".join(str(value).split())[:limit]


def _slug(channel: str) -> str:
    """``Microsoft-Windows-PowerShell/Operational`` -> ``powershell-operational``.

    The shape a live log's source name has (``evtx.powershell-operational``).
    """
    name = channel.lower().removeprefix("microsoft-windows-")[:120]
    return re.sub(r"[^a-z0-9]+", "-", name).strip("-") or "unknown"


def _time_bound(value: str | None) -> str | None:
    """Normalise a UTC time bound, or raise ValueError.

    Bounds are compared as text against the same number of leading characters
    of a record's time, so a date alone covers its whole day.
    """
    if not value:
        return None
    bound = value.strip().replace(" ", "T").rstrip("Zz")
    if not _TIME_RE.fullmatch(bound):
        raise ValueError(f"not a UTC time like 2024-03-01 or 2024-03-01T14:30:00: {value!r}")
    return bound


def _is_evtx(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(8) == b"ElfFile\x00"
    except OSError:
        return False


def _evtx_files(root: Path) -> list[Path]:
    """Regular ``*.evtx`` files under *root*.

    Symlinks are left alone: one could point outside the evidence, and
    ``os.walk`` does not descend into linked directories.
    """
    found = [
        Path(folder, name)
        for folder, _dirs, names in os.walk(root)
        for name in names
        if name.lower().endswith(".evtx")
    ]
    return sorted(p for p in found if not p.is_symlink() and p.is_file())


def _file_header() -> bytes:
    """A minimal EVTX file header, so evtx_dump reads a run of chunks as a log.

    evtx_dump counts the chunks from the file size, not from this header.
    """
    header = bytearray(_HEADER_SIZE)
    # magic, three unused 8-byte counters, header size, version 3.1, block size
    struct.pack_into("<8s24xIHHH", header, 0, b"ElfFile\x00", 128, 1, 3, _HEADER_SIZE)
    struct.pack_into("<I", header, 124, zlib.crc32(header[:120]))
    return bytes(header)


def _carved(raw: Path, out: Path, deadline: float, stats: Counter[str]) -> Iterator[Path]:
    """Yield *out* each time it holds a batch of event log chunks found in *raw*.

    A chunk is the 64 KiB after a chunk signature that is followed by a record
    where the first record belongs; an exact copy of one already taken is
    skipped. *raw* is read once, in blocks, and never copied: only the chunks
    are written, a batch at a time, and each batch replaces the last.

    ponytail: evtx_dump has this built in on its main branch (--carve, with
    bad-sector handling) but not in a release; switch when one ships it.

    Raises:
        TimeoutError: When *deadline* passes.
    """
    header = _file_header()
    seen: set[bytes] = set()
    batch: list[bytes] = []
    carry = b""
    base = 0
    with open(raw, "rb") as source:
        while block := source.read(_SCAN_BLOCK):
            if time.monotonic() > deadline:
                raise TimeoutError
            # A signature may straddle two blocks: search the last 7 bytes again.
            data = carry + block
            start = base - len(carry)
            hit = data.find(_CHUNK_MAGIC)
            while hit != -1:
                chunk = os.pread(source.fileno(), _CHUNK_SIZE, start + hit)
                if chunk[_FIRST_RECORD : _FIRST_RECORD + 4] == _RECORD_MAGIC:
                    digest = hashlib.blake2b(chunk, digest_size=16).digest()
                    if digest in seen:
                        stats["duplicate_chunks"] += 1
                    else:
                        seen.add(digest)
                        stats["chunks_carved"] += 1
                        # A chunk cut short by the end of the data is padded.
                        batch.append(chunk.ljust(_CHUNK_SIZE, b"\x00"))
                        if len(batch) == _BATCH_CHUNKS:
                            out.write_bytes(header + b"".join(batch))
                            batch.clear()
                            yield out
                hit = data.find(_CHUNK_MAGIC, hit + 1)
            carry = block[-(len(_CHUNK_MAGIC) - 1) :]
            base += len(block)
            stats["bytes_scanned"] = base
    if batch:
        out.write_bytes(header + b"".join(batch))
        yield out


def _dump(
    binary: str, evtx: Path, deadline: float, take: Callable[[Any], None]
) -> tuple[int, int]:
    """Feed every record evtx_dump reads from *evtx*, live and recovered, to *take*.

    The JSON lines are streamed, never held. Returns (exit status, records
    evtx_dump found but could not render).

    Raises:
        TimeoutError: When *deadline* passes; evtx_dump is killed.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    proc = subprocess.Popen(
        [binary, "--recover-records", "-o", "jsonl", cli_path(str(evtx))],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None and proc.stderr is not None
    failures: list[int] = []
    stderr = proc.stderr
    # Drained on its own thread so a flood of errors cannot block the pipe.
    drain = threading.Thread(
        target=lambda: failures.append(sum(ln.startswith(b"Failed to dump") for ln in stderr)),
        daemon=True,
    )
    expired = threading.Event()

    def expire() -> None:
        expired.set()
        proc.kill()

    timer = threading.Timer(remaining, expire)
    drain.start()
    timer.start()
    unreadable = 0
    try:
        for line in proc.stdout:
            try:
                record = json.loads(line)
            except ValueError:
                unreadable += 1
                continue
            take(record)
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        drain.join()
    if expired.is_set():
        raise TimeoutError
    return proc.returncode, unreadable + sum(failures)


_Row = tuple[str, int, int, str]


@dataclass
class _Recovery:
    """What one run has read so far."""

    patterns: list[str]
    t_start: str | None
    t_end: str | None
    max_records: int
    stats: Counter[str] = field(default_factory=Counter)
    # hash of (channel, record id, time) for every live record in scope
    live: set[int] = field(default_factory=set)
    # channel slug -> [count, earliest, latest] of its live records
    live_span: dict[str, list[Any]] = field(default_factory=dict)
    # channel slug -> record key -> (time, record id, event id, indexed line)
    kept: dict[str, dict[int, _Row]] = field(default_factory=dict)
    over_cap: Counter[str] = field(default_factory=Counter)
    cleared: list[dict[str, object]] = field(default_factory=list)
    live_log_cleared: bool = False

    def take(self, record: Any, carved: bool) -> None:
        """Sort one evtx_dump record into live, recovered or dropped."""
        try:
            event = record["Event"]
            system = event["System"]
            channel = system["Channel"]
            when = system["TimeCreated"]["#attributes"]["SystemTime"]
            record_id = int(system["EventRecordID"])
            event_id = system["EventID"]
            event_id = int(event_id["#text"] if isinstance(event_id, dict) else event_id)
        except (KeyError, TypeError, ValueError):
            self.stats["records_not_parsed"] += 1
            return
        if not (isinstance(channel, str) and isinstance(when, str) and _STAMP_RE.fullmatch(when)):
            self.stats["records_not_parsed"] += 1
            return

        recovered = record.get("recovered") is True
        is_live = not carved and not recovered
        name = channel.lower()
        if (name, event_id) in _CLEARING_EVENTS:
            self._note_clearing(event, system, when, event_id, is_live, recovered)

        if not any(fnmatch.fnmatchcase(name, pattern) for pattern in self.patterns):
            return
        if self.t_start and when[: len(self.t_start)] < self.t_start:
            return
        if self.t_end and when[: len(self.t_end)] > self.t_end:
            return

        # A hash, not the tuple: a large Security log has millions of records.
        key = hash((name, record_id, when))
        slug = _slug(channel)
        if is_live:
            self.live.add(key)
            span = self.live_span.get(slug)
            if span is None and len(self.live_span) < _MAX_CHANNELS:
                span = self.live_span[slug] = [0, when, when]
            if span is not None:
                span[:] = [span[0] + 1, min(span[1], when), max(span[2], when)]
            return

        rows = self.kept.get(slug)
        if rows is None:
            if len(self.kept) >= _MAX_CHANNELS:
                self.stats["records_over_channel_limit"] += 1
                return
            rows = self.kept[slug] = {}
        if key in self.live:
            self.stats["duplicates_of_live"] += 1
        elif key in rows:
            self.stats["duplicate_recovered"] += 1
        elif len(rows) >= self.max_records:
            self.over_cap[slug] += 1
        else:
            payload = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
            marker = "recovered" if recovered else "carved"
            rows[key] = (
                when,
                record_id,
                event_id,
                f"{when} | {event_id} | {slug} | [{marker} record {record_id}] "
                + payload.translate(_LINE_BREAKS),
            )

    def _note_clearing(
        self, event: Any, system: Any, when: str, event_id: int, is_live: bool, recovered: bool
    ) -> None:
        try:
            if system["Provider"]["#attributes"]["Name"] != "Microsoft-Windows-Eventlog":
                return
        except (KeyError, TypeError):
            return
        user_data = event.get("UserData")
        detail = user_data.get("LogFileCleared") if isinstance(user_data, dict) else None
        if not isinstance(detail, dict):
            detail = {}
        self.live_log_cleared = self.live_log_cleared or is_live
        if len(self.cleared) < _MAX_LISTED:
            self.cleared.append(
                {
                    "time": when,
                    "event_id": event_id,
                    "log_cleared": _flat(detail.get("Channel") or system["Channel"]),
                    "by": _flat(detail.get("SubjectUserName") or "?"),
                    "read_from": "live log"
                    if is_live
                    else "recovered record"
                    if recovered
                    else "carved record",
                }
            )

    def results(self) -> dict[str, list[_Row]]:
        """Recovered records per channel, in time order, without live duplicates."""
        final: dict[str, list[_Row]] = {}
        for slug, rows in sorted(self.kept.items()):
            # A live copy may have been read after the recovered one.
            late = [key for key in rows if key in self.live]
            self.stats["duplicates_of_live"] += len(late)
            records = sorted(row for key, row in rows.items() if key not in self.live)
            if records:
                final[slug] = records
        return final


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_evtx_recovery(
    evidence_path: str,
    channels: list[str] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    max_records: int = _DEFAULT_MAX_RECORDS,
    force: bool = False,
) -> dict[str, object]:
    """Recover Windows event log records left behind after a log was cleared.

    Call when a log was cleared (Security 1102, System 104) or starts later
    than the system was in use. Given a .evtx file or a directory of them, it
    reads the stale records still inside the files. Given any other file (a
    raw or E01 disk image, a memory dump, unallocated space), it carves event
    log chunks out of the raw bytes, which reads the whole file once; on a
    disk image call it after run_evtx_parser, whose extracted logs are used to
    drop records that are still live.

    Returns counts per channel and event ID, the earliest and latest recovered
    time, whether a live log records its own clearing, and what was cut or not
    parsed. Records are indexed per channel as evtx_recovered.<channel>, one
    per line (time | event ID | channel | event), marked [recovered] (stale
    space inside a log) or [carved] (a chunk found in raw data). Recovery is
    partial: no recovered record for an event or period does NOT show it did
    not happen.

    Args:
        evidence_path: A .evtx file, a directory of .evtx files, or a raw file
            to carve (disk image, memory dump, unallocated space).
        channels: Channel name patterns, case-insensitive, ``*`` allowed.
            Default: Security, System, PowerShell and Task Scheduler
            operational, Terminal Services. ``["*"]`` keeps every channel.
        t_start: Keep records at or after this UTC time (2024-03-01 or
            2024-03-01T14:30:00).
        t_end: Keep records at or before this UTC time.
        max_records: Most records kept per channel (default 10000).
        force: Re-run even if this path was already recovered.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path,
        "channels": channels,
        "t_start": t_start,
        "t_end": t_end,
        "max_records": max_records,
        "force": force,
    }

    def fail(message: str, error_type: str, suggestion: str | None = None) -> dict[str, object]:
        elapsed = (time.monotonic() - t0) * 1000
        return error_response(tc_id, _NAME, params, message, elapsed, error_type, suggestion)

    try:
        start, end = _time_bound(t_start), _time_bound(t_end)
    except ValueError as exc:
        return fail(str(exc), "invalid_argument")
    if not 1 <= max_records <= _MAX_RECORDS_LIMIT:
        return fail(f"max_records must be 1 to {_MAX_RECORDS_LIMIT}", "invalid_argument")
    patterns = [str(c).lower()[:200] for c in (channels or _DEFAULT_CHANNELS)][:_MAX_LISTED]

    if not force:
        existing = sources_already_indexed([_PREFIX], evidence_path=evidence_path)
        if existing:
            skipped: dict[str, object] = {
                "status": "skipped",
                "reason": "Sources already indexed from prior extraction",
                "existing_sources": existing,
            }
            return tool_response(tc_id, _NAME, params, skipped, None, 0.0)

    evtx_dump = require_binary("evtx_dump")
    if not evtx_dump:
        return fail(
            "evtx_dump not found on PATH",
            "binary_missing",
            "Run 'mulder setup' (installs evtx_dump).",
        )
    target = Path(evidence_path)
    if not target.exists():
        return fail(f"Path not found: {evidence_path}", "file_not_found")

    carving = False
    compared_with_live = True
    if target.is_dir():
        logs = _evtx_files(target)
        if not logs:
            return fail(
                f"No .evtx files under {evidence_path}. Pass a .evtx file, a directory of "
                "them, or a raw file to carve (disk image, memory dump).",
                "invalid_argument",
            )
    elif not target.is_file():
        return fail(f"Not a regular file or directory: {evidence_path}", "invalid_argument")
    elif _is_evtx(target):
        logs = [target]
    else:
        carving = True
        # run_evtx_parser's copies of this image's logs say which records are
        # live. It indexes evtx.manifest only once every log is extracted.
        logs = []
        if has_ctx() and sources_already_indexed(["evtx.manifest"], evidence_path=evidence_path):
            extracted = get_ctx().db.get_kv(f"evtx_extract_dir:{evidence_path}")
            if extracted and Path(extracted).is_dir():
                logs = _evtx_files(Path(extracted))
        compared_with_live = bool(logs)

    run = _Recovery(patterns, start, end, max_records)
    unread: list[str] = []
    deadline = t0 + adaptive_timeout(target)

    def read(evtx: Path, carved: bool) -> None:
        status, failed = _dump(evtx_dump, evtx, deadline, lambda record: run.take(record, carved))
        run.stats["records_not_parsed"] += failed
        if status != 0:
            unread.append("carved chunks" if carved else _flat(evtx.name))

    try:
        for log in logs[:_MAX_EVTX_FILES]:
            read(log, carved=False)
        if carving:
            with (
                raw_image(evidence_path) as raw,
                tempfile.TemporaryDirectory(prefix="mulder_evtx_recovery_") as tmp,
            ):
                # An E01's raw view is larger than its compressed segments.
                deadline = t0 + adaptive_timeout(raw)
                for batch in _carved(raw, Path(tmp) / "carved.evtx", deadline, run.stats):
                    read(batch, carved=True)
    except TimeoutError:
        return fail(
            f"evtx recovery of {evidence_path} ran past its time limit; nothing was indexed",
            "timeout",
        )
    except OpticalError as exc:
        return fail(f"Cannot read {evidence_path} as raw bytes: {exc}", "tool_failed")
    except OSError as exc:
        return fail(f"Cannot read {evidence_path}: {exc.strerror or exc}", "tool_failed")

    final = run.results()
    total = sum(len(records) for records in final.values())
    times = [records[i][0] for records in final.values() for i in (0, -1)]
    mode = (
        f"carved {run.stats['chunks_carved']} event log chunks out of "
        f"{run.stats['bytes_scanned']} bytes"
        + (f" and read {len(logs)} extracted logs" if logs else "")
        if carving
        else f"read {min(len(logs), _MAX_EVTX_FILES)} event log files"
    )

    per_channel: dict[str, dict[str, object]] = {}
    summary_lines = [
        f"Event log recovery of {_flat(evidence_path, 300)}: {total} records recovered ({mode})",
        "channel\trecovered\tearliest\tlatest\tlive records\tlive earliest\tlive latest",
    ]
    for slug in sorted({*final, *run.live_span}):
        records = final.get(slug, [])
        live_count, live_first, live_last = run.live_span.get(slug, [0, None, None])
        entry: dict[str, object] = {"recovered": len(records)}
        if records:
            source = _PREFIX + slug
            extract_and_index(
                "\n".join(row[3] for row in records),
                source,
                evidence_path,
                "evtx_dump",
            )
            by_id = Counter(str(row[2]) for row in records)
            entry.update(
                source=source,
                earliest=records[0][0],
                latest=records[-1][0],
                event_ids=dict(by_id.most_common(_MAX_RESPONSE_EVENT_IDS)),
            )
            if run.over_cap[slug]:
                entry["not_indexed_over_max_records"] = run.over_cap[slug]
        if live_count:
            entry.update(live_records=live_count, live_earliest=live_first, live_latest=live_last)
        per_channel[slug] = entry
        summary_lines.append(
            "\t".join(
                str(v or "-")
                for v in (
                    slug,
                    len(records),
                    entry.get("earliest"),
                    entry.get("latest"),
                    live_count,
                    live_first,
                    live_last,
                )
            )
        )

    truncated: dict[str, object] = {}
    if any(run.over_cap.values()):
        truncated["records_over_max_records"] = sum(run.over_cap.values())
    if run.stats["records_over_channel_limit"]:
        truncated["records_in_channels_over_limit"] = run.stats["records_over_channel_limit"]
    if len(logs) > _MAX_EVTX_FILES:
        truncated["evtx_files_not_read"] = len(logs) - _MAX_EVTX_FILES
    not_parsed: dict[str, object] = {}
    if run.stats["records_not_parsed"]:
        not_parsed["records"] = run.stats["records_not_parsed"]
    if unread:
        not_parsed["files"] = unread[:_MAX_LISTED]
        not_parsed["file_count"] = len(unread)

    for item in run.cleared:
        summary_lines.append(
            f"{item['time']}\tlog cleared: {item['log_cleared']} (event {item['event_id']}) "
            f"by {item['by']}; read from a {item['read_from']}"
        )
    if carving and not compared_with_live:
        summary_lines.append(_NOT_COMPARED)
    for label, value in (("truncated", truncated), ("not parsed", not_parsed)):
        if value:
            summary_lines.append(f"{label}: {json.dumps(value)}")
    summary_lines.append(_INTERPRETATION)
    extract_and_index("\n".join(summary_lines), _SUMMARY_SOURCE, evidence_path, "evtx_dump")

    shown = sorted(per_channel, key=lambda s: (-int(str(per_channel[s]["recovered"])), s))
    summary: dict[str, object] = {
        "evidence_path": evidence_path,
        "mode": mode,
        "recovered_records": total,
        "earliest_recovered": min(times, default=None),
        "latest_recovered": max(times, default=None),
        "channels": {slug: per_channel[slug] for slug in shown[:_MAX_RESPONSE_CHANNELS]},
        "channels_not_listed": max(len(shown) - _MAX_RESPONSE_CHANNELS, 0),
        # None: no live log was read, so there was nothing to find one in.
        "live_log_cleared": run.live_log_cleared if logs else None,
        "log_clearing_events": run.cleared,
        "duplicates_of_live_dropped": run.stats["duplicates_of_live"],
        "truncated": truncated,
        "not_parsed": not_parsed,
        "summary_source": _SUMMARY_SOURCE,
        "interpretation": _INTERPRETATION,
    }
    if carving:
        summary["duplicate_chunks_skipped"] = run.stats["duplicate_chunks"]
        summary["compared_with_live_logs"] = compared_with_live
        if not compared_with_live:
            summary["warning"] = _NOT_COMPARED
    # Returned in full: it is bounded, and the counts are what the caller acts on.
    return tool_response(tc_id, _NAME, params, summary, None, (time.monotonic() - t0) * 1000)
