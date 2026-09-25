"""NetFlow (nfdump ``nfcapd.*``) MCP tools.

Six tools answer the common network-forensics questions over nfdump 1.7 capture files:
inventory, ranked top-N, one-host profile, many-to-many sweep detection,
one-pair timeline/beacon statistics and a bounded generic query.  Every
call validates its arguments (``core.py``), resolves ``evidence_path``
through ``mulder.path_policy``, admits files by magic only, stages them
into a private symlink directory, runs nfdump as an argv list under
``prlimit --as`` behind a two-slot semaphore, and indexes one ``WindowRow``
per emitted line (own ``event_time`` each) under a deterministic
``netflow.<kind>.<id>`` source.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import signal
import subprocess
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from mulder.models import WindowRow
from mulder.path_policy import PathPolicyError, resolve_allowed_path
from mulder.server.app import get_cfg, get_ctx, has_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    TOOL_SOURCE_PREFIXES,
    current_batch_id,
    error_response,
    hash_output,
    make_tool_call_id,
    require_binary,
    sources_already_indexed,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.netflow import core
from mulder.server.tools.netflow.core import NetflowArgError

__all__ = [
    "run_netflow_host_profile",
    "run_netflow_inventory",
    "run_netflow_pair_timeline",
    "run_netflow_query",
    "run_netflow_sweep",
    "run_netflow_top",
]

logger = logging.getLogger(__name__)

# Inventory is the only tool with a batch-skippable prefix: per-invocation
# sources (top/profile/sweep/pair/query) carry a parameter hash in their
# name and must never be skipped by a broad prefix.
TOOL_SOURCE_PREFIXES.update({"run_netflow_inventory": ["netflow.inventory."]})

_NFDUMP_SLOTS = threading.BoundedSemaphore(core.NFDUMP_SLOT_COUNT)
_STDERR_PREVIEW = 500
_EXECUTORS = Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR
_SERIALISE_NOTE = "calls on one directory serialise (2 nfdump slots per server)"
_MEMORY_SUGGESTION = (
    "nfdump exceeded its 4 GiB memory limit: narrow t_start/t_end or the filter (a single "
    "'src ip'/'dst ip' rather than a net), or aggregate on fewer keys"
)

# One lock per base source name: identical calls running concurrently (run_parallel, two JobStore
# workers, a resubmitted batch) would otherwise all pass the sources_already_indexed check and
# register the same netflow.<kind>.<hid> name several times.  The lock is held from the name
# check through registration, so the second identical call waits, re-checks and returns the
# existing "skipped" envelope without spending an nfdump slot; different parameter sets have
# different names and still run in parallel.
_NAME_LOCKS: dict[str, threading.Lock] = {}
_NAME_LOCKS_GUARD = threading.Lock()


@contextmanager
def _name_lock(base: str) -> Iterator[None]:
    """Serialise every call that would register ``base`` or a ``<name>-r<k>`` re-run of it."""
    with _NAME_LOCKS_GUARD:
        lock = _NAME_LOCKS.setdefault(base, threading.Lock())
    with lock:
        yield


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


@dataclass
class NfRun:
    """A completed nfdump invocation that may be parsed."""

    stdout: str
    stderr: str
    returncode: int
    argv: list[str]
    elapsed_s: float
    slot_wait_s: float
    warnings: list[str]


@dataclass
class NfFailure:
    """An nfdump invocation that must become an ``error_response``."""

    error_type: str
    error: str
    suggestion: str | None
    argv: list[str]
    elapsed_s: float
    slot_wait_s: float


def _example_filters() -> str:
    return "; ".join(f"'{e}'" for e in core.EXAMPLE_FILTERS)


def _run_nfdump(
    read: Sequence[str],
    mode: Sequence[str],
    fmt: str | None,
    filter_expr: str | None,
    timeout: int,
) -> NfRun | NfFailure:
    """Run one nfdump command (argv list, ``TZ=UTC``, 4 GiB ``RLIMIT_AS`` and no core dumps
    via prlimit).

    Slot waiting counts against the same ``timeout`` budget.  ``fmt=None``
    runs a bare command (``-I``) without ``-N -6 -q -o`` and without a filter.
    Outcomes: ANY stderr line at rc 0 that is not in
    ``core.STDERR_BENIGN_PREFIXES`` is a failure, because nfdump 1.7.10 stops or
    hollows out a ``-R`` walk silently (rc 0) on a truncated or block-corrupt
    file and prints nothing on stderr in a healthy run.
    """
    binary = require_binary(core.NFDUMP_BINARY) or require_binary("nfdump")
    if not binary:
        return NfFailure(
            "binary_missing",
            "nfdump not found (/opt/nfdump/bin/nfdump or PATH)",
            "install nfdump >= 1.7 (the container image ships it in /opt/nfdump)",
            [],
            0.0,
            0.0,
        )
    prlimit = require_binary(core.PRLIMIT_BINARY) or require_binary("prlimit")
    if not prlimit:
        return NfFailure(
            "binary_missing",
            "prlimit (util-linux) not found; refusing to run nfdump without an RLIMIT_AS cap",
            None,
            [],
            0.0,
            0.0,
        )
    cmd: list[str] = [
        prlimit, f"--as={core.NFDUMP_RLIMIT_AS}", f"--core={core.NFDUMP_RLIMIT_CORE}", "--",
        binary, *read, *mode,
    ]  # fmt: skip
    if fmt is not None:
        cmd += ["-N", "-6", "-q", "-o", fmt, "--", filter_expr or "any"]
    t0 = time.monotonic()
    deadline = t0 + timeout
    if not _NFDUMP_SLOTS.acquire(timeout=timeout):
        waited = time.monotonic() - t0
        return NfFailure(
            "timeout",
            f"waited {waited:.0f}s for an nfdump slot ({core.NFDUMP_SLOT_COUNT} per server)",
            "retry; calls on the same directory serialise",
            cmd,
            waited,
            waited,
        )
    slot_wait_s = time.monotonic() - t0
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",  # nfdump echoes bad filter bytes; a decode error must not escape
            timeout=max(1.0, deadline - time.monotonic()),
            check=False,
            env={**os.environ, "TZ": "UTC"},
        )
    except subprocess.TimeoutExpired:
        return NfFailure(
            "timeout",
            f"nfdump timed out after {timeout}s",
            "narrow t_start/t_end or the filter; calls on one directory serialise (2 slots)",
            cmd,
            time.monotonic() - t0,
            slot_wait_s,
        )
    except OSError as exc:
        return NfFailure(
            "os_error", f"failed to execute nfdump: {exc}", None, cmd, time.monotonic() - t0,
            slot_wait_s,
        )  # fmt: skip
    finally:
        _NFDUMP_SLOTS.release()
    elapsed = time.monotonic() - t0
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    rc = proc.returncode
    if rc == 254:
        lines = [ln for ln in stdout.splitlines() if ln.strip()]
        first = lines[0] if lines else "nfdump rejected the filter"
        return NfFailure(
            "invalid_argument",
            f"nfdump filter error: {first.strip()}",
            f"fix the nfdump filter syntax; examples: {_example_filters()}",
            cmd,
            elapsed,
            slot_wait_s,
        )
    if rc != 0:
        detail = (stderr[:_STDERR_PREVIEW] or stdout[:_STDERR_PREVIEW]).strip()
        # Out of memory under RLIMIT_AS: rc 255 (pthread_create under a small cap), death by
        # SIGABRT from the flowHash_resize assertion under the 4 GiB cap (subprocess reports a
        # signal as a negative rc; 134 is the shell's rendering), or an allocation message.
        if rc == 255 or rc < 0 or rc == 134 or core.MEMORY_FAIL_RE.search(stderr):
            if rc < 0:
                try:
                    signame = signal.Signals(-rc).name
                except ValueError:
                    signame = f"signal {-rc}"
                what = f"nfdump killed by {signame} (likely hit its 4 GiB memory limit)"
            elif rc == 134:
                what = "nfdump aborted (SIGABRT, likely hit its 4 GiB memory limit)"
            else:
                what = f"nfdump exited {rc}"
            return NfFailure(
                "tool_failed",
                f"{what}: {detail}" if detail else what,
                _MEMORY_SUGGESTION,
                cmd,
                elapsed,
                slot_wait_s,
            )
        return NfFailure(
            "tool_failed", f"nfdump exited {rc}: {detail}", None, cmd, elapsed, slot_wait_s
        )
    bad_lines = [
        ln.strip()
        for ln in stderr.splitlines()
        if ln.strip() and not ln.strip().startswith(core.STDERR_BENIGN_PREFIXES)
    ]
    if bad_lines:
        # nfdump 1.7.10 reports a truncated file ("appendix offset error"), a corrupt block
        # ("Unknown block type", "Corrupt data file", "DataBlock count error") or a read error
        # on stderr and STILL exits 0 after stopping or skipping part of the walk; the result
        # would be a silent undercount with files_scanned claiming the whole set was read.
        known = [ln for ln in bad_lines if core.STDERR_FAIL_RE.search(ln)]
        return NfFailure(
            "tool_failed",
            "nfdump reported a damaged or unreadable input file: "
            + "\n".join(known or bad_lines)[:_STDERR_PREVIEW],
            "a staged file is truncated, block-corrupt or unreadable (this includes transient "
            "read errors) and nfdump stops its walk silently: see "
            "files_excluded / warnings, point evidence_path at the good files or a single "
            "file, then retry",
            cmd,
            elapsed,
            slot_wait_s,
        )
    if len(stdout) > core.MAX_STDOUT_BYTES:
        return NfFailure(
            "tool_failed", "output too large; narrow the query", None, cmd, elapsed, slot_wait_s
        )
    return NfRun(stdout, stderr, rc, cmd, elapsed, slot_wait_s, [])


# ---------------------------------------------------------------------------
# Shared plumbing: path policy, discovery, naming, indexing, envelope
# ---------------------------------------------------------------------------


def _resolve_evidence(evidence_path: str) -> Path:
    """Resolve ``evidence_path`` inside the case evidence root or the case DB directory."""
    if "\x00" in evidence_path:
        # Path.resolve() raises ValueError on an embedded NUL, which would escape the tool.
        raise PathPolicyError("evidence_path contains a NUL character")
    if not Path(evidence_path).is_absolute():
        raise PathPolicyError("evidence_path must be absolute")
    cfg = get_cfg()
    ctx = get_ctx()
    roots = [Path(cfg.db_dir)]
    meta = ctx.db.get_case_metadata()
    if meta and meta.evidence_root:
        roots.append(Path(meta.evidence_root))
    return resolve_allowed_path(Path(evidence_path), roots)


@dataclass
class _Prep:
    """Everything a tool knows before nfdump runs."""

    tool: str
    tc_id: str
    t0: float
    params: dict[str, object]
    resolved: Path
    files: list[core.NfFile]
    excluded: list[core.Excluded]
    ts: datetime | None
    te: datetime | None
    selected: list[core.NfFile]
    warnings: list[str] = field(default_factory=list)
    runs: list[NfRun] = field(default_factory=list)

    @property
    def excluded_json(self) -> list[dict[str, object]]:
        """``files_excluded`` (capped)."""
        return [e.as_dict() for e in self.excluded[: core.MAX_EXCLUDED_LISTED]]

    def elapsed_ms(self) -> float:
        """Wall time since the tool started."""
        return (time.monotonic() - self.t0) * 1000


def _error(
    tool: str,
    tc_id: str,
    params: Mapping[str, object],
    t0: float,
    error_type: str,
    error: str,
    suggestion: str | None = None,
    extra: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Audited ``error_response`` plus tool-specific extras (argv, timings, exclusions)."""
    resp = error_response(
        tc_id,
        tool,
        params,
        error,
        (time.monotonic() - t0) * 1000,
        error_type=error_type,
        suggestion=suggestion,
    )
    resp["tool"] = tool
    if extra:
        resp.update(extra)
    return resp


def _invalid(
    tool: str, tc_id: str, params: Mapping[str, object], t0: float, exc: NetflowArgError
) -> dict[str, object]:
    return _error(tool, tc_id, params, t0, "invalid_argument", str(exc), exc.suggestion)


def _prepare(
    tool: str,
    tc_id: str,
    t0: float,
    params: dict[str, object],
    evidence_path: str,
    t_start: str | None,
    t_end: str | None,
) -> _Prep | dict[str, object]:
    """Window parsing, path policy, discovery and day selection shared by every tool."""
    if not has_ctx():
        return _error(
            tool, tc_id, params, t0, "no_case_loaded",
            "no case is loaded", "call scan_evidence or open_case first",
        )  # fmt: skip
    try:
        ts, te = core.parse_window(t_start, t_end)
    except NetflowArgError as exc:
        return _invalid(tool, tc_id, params, t0, exc)
    try:
        resolved = _resolve_evidence(evidence_path)
    except ValueError as exc:  # PathPolicyError subclasses ValueError; Path.resolve raises it too
        return _error(
            tool, tc_id, params, t0, "invalid_argument", str(exc),
            "evidence_path must be an absolute path inside the case evidence root",
        )  # fmt: skip
    if not resolved.exists():
        return _error(
            tool, tc_id, params, t0, "file_not_found", f"evidence_path not found: {resolved}"
        )
    files, excluded = core.discover(resolved)
    if not files:
        return _error(
            tool,
            tc_id,
            params,
            t0,
            "file_not_found",
            f"no nfcapd files under {resolved}",
            "point evidence_path at a directory of nfdump nfcapd.* files (or one such file)",
            {
                "evidence_path": str(resolved),
                "files_excluded": [e.as_dict() for e in excluded[: core.MAX_EXCLUDED_LISTED]],
            },
        )
    if len(files) > core.MAX_FILES:
        return _error(
            tool,
            tc_id,
            params,
            t0,
            "invalid_argument",
            f"{len(files)} nfcapd files under {resolved} exceed the {core.MAX_FILES} file limit",
            "point evidence_path at a subdirectory",
        )
    selected = core.select(files, ts, te)
    prep = _Prep(tool, tc_id, t0, params, resolved, files, excluded, ts, te, selected)
    if len(excluded) > core.MAX_EXCLUDED_LISTED:
        prep.warnings.append(_excluded_note(len(excluded)))
    if not selected:
        prep.warnings.append(
            "no nfcapd file is dated within the window (with the 1-day lookbehind / 8-day "
            "lookahead); nothing was read"
        )
    return prep


def _excluded_note(count: int) -> str:
    return f"{count} entries excluded; first {core.MAX_EXCLUDED_LISTED} listed"


def _run_extra(
    prep: _Prep, argv: Sequence[str], elapsed_s: float, slot_wait_s: float
) -> dict[str, object]:
    return {
        "nfdump_argv": list(argv),
        "slot_wait_s": round(slot_wait_s, 3),
        "elapsed_s": round(elapsed_s, 3),
        "evidence_path": str(prep.resolved),
        "files_scanned": len(prep.selected),
        "file_range": core.file_range(prep.selected),
        "files_excluded": prep.excluded_json,
    }


def _run(
    prep: _Prep,
    read: Sequence[str],
    mode: Sequence[str],
    fmt: str | None,
    filter_expr: str | None,
    timeout: int | None = None,
) -> NfRun | dict[str, object]:
    """Run nfdump for ``prep``; a failure is returned as a finished error response."""
    res = _run_nfdump(read, mode, fmt, filter_expr, timeout or core.timeout_for(prep.selected))
    if isinstance(res, NfFailure):
        return _error(
            prep.tool,
            prep.tc_id,
            prep.params,
            prep.t0,
            res.error_type,
            res.error,
            res.suggestion,
            _run_extra(prep, res.argv, res.elapsed_s, res.slot_wait_s),
        )
    prep.runs.append(res)
    prep.warnings.extend(res.warnings)
    return res


@dataclass
class _Named:
    """The source name a run will register under, and what it supersedes."""

    name: str
    supersedes: str | None


def _name_or_skip(prep: _Prep, base: str, force: bool) -> _Named | dict[str, object]:
    """Deterministic source naming with exact idempotency.

    An existing source under ``base`` (or a ``<name>-r<k>`` re-run of it) for the same
    resolved path skips the call unless ``force``; ``force`` registers
    ``<name>-r<k>`` with ``k = 1 + number of earlier re-runs`` (the hyphen keeps
    ``get_raw_output(base)`` from matching it while ``search(source=...)``
    prefixes still span every run).
    """
    existing = sources_already_indexed([base], evidence_path=str(prep.resolved))
    if not existing:
        return _Named(base, None)
    ctx = get_ctx()
    runs = [
        s
        for s in ctx.db.get_sources()
        if s.source_path == str(prep.resolved)
        and (s.source_name == base or s.source_name.startswith(base + "-r"))
        and not s.source_name.endswith(".manifest")
    ]
    latest = max(runs, key=lambda s: s.source_id) if runs else None
    if not force:
        name = latest.source_name if latest else base
        line_count = latest.line_count if latest else 0
        resp: dict[str, object] = {
            "tool_call_id": prep.tc_id,
            "status": "skipped",
            "tool": prep.tool,
            "source": name,
            "source_name": name,
            "line_count": line_count,
            "windows_indexed": 0,
            "existing_sources": sorted(set(existing)),
            "evidence_path": str(prep.resolved),
            "hint": f"get_raw_output('{name}') for the rows, or force=True to re-run",
        }
        ctx.audit.log_tool_call(
            tool_call_id=prep.tc_id,
            tool_name=prep.tool,
            params={**prep.params, "source": name},
            output_hash=hash_output(resp),
            duration_ms=prep.elapsed_ms(),
            batch_id=current_batch_id.get(),
        )
        return resp
    k = 1 + sum(1 for s in runs if s.source_name.startswith(base + "-r"))
    return _Named(f"{base}-r{k}", latest.source_name if latest else base)


def _index_rows(
    source_name: str, source_path: str, rows: Sequence[tuple[str | None, str]]
) -> tuple[int, int]:
    """Register ``source_name`` and insert one ``WindowRow`` per line (own ``event_time``)."""
    ctx = get_ctx()
    text = "\n".join(t for _, t in rows)
    h = "blake2b:" + hashlib.blake2b(text.encode(), digest_size=32).hexdigest()
    sid = ctx.db.register_source(source_name, source_path, h, core.EXTRACTOR, len(rows))
    batch = [
        WindowRow(source_id=sid, line_start=i, line_end=i, event_time=et, raw_text=t)
        for i, (et, t) in enumerate(rows, 1)
    ]
    for k in range(0, len(batch), core.INSERT_BATCH):
        ctx.db.insert_windows(sid, batch[k : k + core.INSERT_BATCH])
    return sid, len(rows)


def _header_text(
    prep: _Prep,
    filter_applied: str | None,
    fields: Sequence[tuple[str, object]],
    rows: int,
    truncated: bool,
    supersedes: str | None,
) -> str:
    """Line 1 of every non-empty source: in-DB provenance carrying the originating call id."""
    fr = core.file_range(prep.selected)
    parts = [
        f"tool={prep.tool}",
        f"tool_call_id={prep.tc_id}",
        f"evidence_path={prep.resolved}",
        f"files={len(prep.selected)}",
        "file_range=" + ("..".join(fr) if fr else "none"),
        f"window={core.window_label(prep.ts, prep.te)}",
        f'filter="{filter_applied or "any"}"',
    ]
    parts += [f"{k}={core.num(v) if isinstance(v, (int, float)) else v}" for k, v in fields]
    parts += [f"rows={rows}", f"truncated={'true' if truncated else 'false'}"]
    if supersedes:
        parts.append(f"supersedes={supersedes}")
    return "- netflow header " + " ".join(parts)


def _subnet_regex(ip: str) -> str:
    """A regex example for the /24 of an IPv4 ``ip`` (an RFC 5737 placeholder otherwise)."""
    octets = str(ip).split(".")
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        return "\\.".join(octets[:3]) + "\\.\\d+"
    return "192\\.0\\.2\\.\\d+"


def _cite_hint(name: str, tc_id: str, ip: str, port: object, ts: str, te: str, extra: str) -> str:
    return (
        f"Rows are indexed one per line under source '{name}' (line = line_start); line 1 is a "
        f"header carrying this tool_call_id ({tc_id}). To cite: evidence_refs = the tool_call_id "
        f"of the search/get_timeline/get_raw_output call that surfaced the row "
        f"(get_raw_output('{name}', limit=1) also shows this call's id); sources = the exact "
        f"source name; quote src/dst/dport/first values. Search: search(query='\"{ip}\"', "
        f"source='netflow'), search(query='\"dport={port}\"', source='netflow', "
        f"t_start='{ts}', t_end='{te}'), search(query=r'{_subnet_regex(ip)}', regex=True, "
        f"source='netflow'); get_timeline(t_start='{ts}', t_end='{te}') merges these rows with "
        f"other sources. All times UTC, T-separated. {extra}"
    ).strip()


def _finish(
    prep: _Prep,
    named: _Named,
    data_rows: Sequence[core.Row],
    *,
    filter_applied: str | None,
    params_effective: Mapping[str, object],
    header_fields: Sequence[tuple[str, object]],
    summary: Mapping[str, object],
    truncated: bool,
    rows_dropped: int,
    max_inline_rows: int,
    hint_extra: str,
    extra: Mapping[str, object] | None = None,
    manifest: Sequence[core.Row] | None = None,
) -> dict[str, object]:
    """Index the rows, build the hand-made envelope and write the audit entry."""
    rows = list(data_rows)
    if len(rows) > core.MAX_INDEX_ROWS:
        rows = rows[: core.MAX_INDEX_ROWS]
        truncated = True
        prep.warnings.append(f"indexed rows capped at {core.MAX_INDEX_ROWS}")
    name = named.name
    source_path = str(prep.resolved)
    status = "success"
    manifest_name: str | None = None
    manifest_lines = 0
    if rows:
        header = _header_text(
            prep, filter_applied, header_fields, len(rows), truncated, named.supersedes
        )
        lines: list[tuple[str | None, str]] = [(None, header)]
        lines += [(r.event_time, r.text()) for r in rows]
        sid, indexed = _index_rows(name, source_path, lines)
    else:
        empty = extract_and_index("", name, source_path, core.EXTRACTOR)
        sid = int(str(empty.get("source_id", 0)))
        indexed = 0
        status = "indexed_empty"
    if manifest:
        manifest_name = f"{name}.manifest"
        mhdr = _header_text(prep, filter_applied, header_fields, len(manifest), False, None)
        mlines: list[tuple[str | None, str]] = [(None, mhdr)]
        mlines += [(r.event_time, r.text()) for r in manifest]
        _, manifest_lines = _index_rows(manifest_name, source_path, mlines)
    last_run = prep.runs[-1] if prep.runs else None
    first_ip = "192.0.2.10"
    first_port: object = 445
    ts_hint = f"{prep.ts:%Y-%m-%dT%H:%M:%S}" if prep.ts else "2001-02-03T04:05:00"
    te_hint = f"{prep.te:%Y-%m-%dT%H:%M:%S}" if prep.te else "2001-02-03T04:05:20"
    for r in rows:
        d = dict(r.fields)
        ip = d.get("src") or d.get("ip") or d.get("value") or d.get("host")
        if isinstance(ip, str) and "." in ip and "/" not in ip:
            first_ip = ip
        port = d.get("dport") or d.get("port")
        if isinstance(port, int):
            first_port = port
        if r.event_time and not prep.ts:
            ts_hint = r.event_time
            te_hint = r.event_time[:11] + "23:59:59"
        break
    inline = [{"line": i + 2, **r.as_dict()} for i, r in enumerate(rows[:max_inline_rows])]
    resp: dict[str, object] = {
        "tool_call_id": prep.tc_id,
        "status": status,
        "tool": prep.tool,
        "source": name,
        "source_name": name,
        "source_id": sid,
        "windows_indexed": indexed,
        "line_count": indexed,
        "evidence_path": source_path,
        "files_scanned": len(prep.selected),
        "file_range": core.file_range(prep.selected),
        "files_excluded": prep.excluded_json,
        "window": {
            "t_start": f"{prep.ts:%Y-%m-%dT%H:%M:%S}" if prep.ts else None,
            "t_end": f"{prep.te:%Y-%m-%dT%H:%M:%S}" if prep.te else None,
        },
        "filter_applied": filter_applied,
        "nfdump_argv": list(last_run.argv) if last_run else None,
        "params_effective": dict(params_effective),
        "row_count": len(rows),
        "truncated": truncated,
        "rows_dropped": rows_dropped,
        "rows": inline,
        "summary": dict(summary),
        "elapsed_s": round((time.monotonic() - prep.t0), 3),
        "slot_wait_s": round(sum(r.slot_wait_s for r in prep.runs), 3),
        "warnings": list(dict.fromkeys(prep.warnings)),
        "note": None,
        "hint": _cite_hint(name, prep.tc_id, first_ip, first_port, ts_hint, te_hint, hint_extra),
    }
    if len(prep.excluded) > core.MAX_EXCLUDED_LISTED:
        resp["note"] = _excluded_note(len(prep.excluded))
    if manifest_name:
        resp["manifest_source"] = manifest_name
        resp["manifest_line_count"] = manifest_lines
    if status == "indexed_empty":
        resp["hint"] = (
            f"No rows matched; an empty source '{name}' was registered so the call is on record. "
            "Widen t_start/t_end or relax the filter and re-run with force=True. " + hint_extra
        )
    if extra:
        resp.update(extra)
    ctx = get_ctx()
    ctx.audit.log_tool_call(
        tool_call_id=prep.tc_id,
        tool_name=prep.tool,
        params={**prep.params, "source": name},
        output_hash=hash_output(resp),
        duration_ms=prep.elapsed_ms(),
        batch_id=current_batch_id.get(),
    )
    return resp


def _effective_hash_params(eff: Mapping[str, object]) -> dict[str, object]:
    """Parameters that shape the indexed rows (inline count and force never do)."""
    return {k: v for k, v in eff.items() if k not in ("max_inline_rows", "force")}


def _window_eff(prep: _Prep) -> dict[str, object]:
    """The parsed window in the seconds ``T`` form that ``window_clause`` sends to nfdump, so
    ``'2001-02-03 12:00:00'``, ``'...T12:00:00Z'`` and ``'...T12:00:00.000'`` share one source id
    and ``params_effective`` echoes the canonical spelling."""
    return {
        "t_start": f"{prep.ts:%Y-%m-%dT%H:%M:%S}" if prep.ts else None,
        "t_end": f"{prep.te:%Y-%m-%dT%H:%M:%S}" if prep.te else None,
    }


# ---------------------------------------------------------------------------
# run_netflow_inventory
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_netflow_inventory(
    evidence_path: str,
    top_n: int = 50,
    max_inline_rows: int = 20,
    force: bool = False,
) -> dict[str, object]:
    """Inventory a directory of nfdump nfcapd NetFlow files: exporter identity, data window,
    per-file manifest, top talkers, top services, top byte sources/destinations and a /24
    segment matrix.
    Call once per NetFlow directory (independent of the other run_netflow_* tools; slow: three
    passes over every file; can take many minutes on large directories; calls on one directory
    serialise).
    Returns bounded ranked rows inline and indexes them under netflow.inventory.<id> (per-file
    rows under netflow.inventory.<id>.manifest).

    Args:
        evidence_path: Absolute path of the nfcapd directory (or one nfcapd file) inside the
            case evidence root; spell it identically on every call.
        top_n: Rows per ranked table (clamped 5..100).
        max_inline_rows: Rows returned inline (0..100; every row is in the DB).
        force: Re-run even if netflow.inventory.<id> already exists (registers <id>-r<k>).
    """
    tool = "run_netflow_inventory"
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path,
        "top_n": top_n,
        "max_inline_rows": max_inline_rows,
        "force": force,
    }
    try:
        top_n_e = core.clamp(top_n, 5, 100)
        inline = core.clamp(max_inline_rows, 0, core.MAX_INLINE_ROWS)
    except NetflowArgError as exc:
        return _invalid(tool, tc_id, params, t0, exc)
    prep = _prepare(tool, tc_id, t0, params, evidence_path, None, None)
    if isinstance(prep, dict):
        return prep
    hid = core.source_hid(tool, str(prep.resolved), {})
    base = f"netflow.inventory.{hid}"
    with _name_lock(base):
        named = _name_or_skip(prep, base, force)
        if isinstance(named, dict):
            return named
        eff: dict[str, object] = {"top_n": top_n_e, "max_inline_rows": inline}

        # Pass A: per-file -I (cheap, sequential, warms the page cache).
        passes: dict[str, float] = {}
        argv_passes: dict[str, list[str]] = {}
        info: dict[Path, dict[str, int | str]] = {}
        staged: list[core.NfFile] = []
        budget_a = core.timeout_for(prep.selected)
        deadline_a = time.monotonic() + budget_a
        ta = time.monotonic()
        for f in prep.selected:
            remaining = int(deadline_a - time.monotonic())
            if remaining < 1:
                return _error(
                    tool, tc_id, params, t0, "timeout",
                    f"pass I exceeded {budget_a}s over {len(prep.selected)} files",
                    "retry (deferrable); the page cache is now warmer",
                    _run_extra(prep, argv_passes.get("I", []), time.monotonic() - t0, 0.0),
                )  # fmt: skip
            per_file = min(remaining, core.timeout_for([f]))
            res = _run_nfdump(["-I", "-r", str(f.path)], [], None, None, per_file)
            if isinstance(res, NfFailure):
                if res.error_type == "timeout":
                    return _error(
                        tool, tc_id, params, t0, "timeout", res.error, res.suggestion,
                        _run_extra(prep, res.argv, res.elapsed_s, res.slot_wait_s),
                    )  # fmt: skip
                if res.error_type in ("binary_missing", "os_error"):
                    return _error(
                        tool, tc_id, params, t0, res.error_type, res.error, res.suggestion,
                        _run_extra(prep, res.argv, res.elapsed_s, res.slot_wait_s),
                    )  # fmt: skip
                first_line = res.error.splitlines()[0] if res.error else "unknown"
                prep.excluded.append(core.Excluded(str(f.path), f"nfdump -I failed: {first_line}"))
                continue
            argv_passes.setdefault("I", list(res.argv))
            prep.runs.append(res)
            info[f.path] = core.parse_dash_i(res.stdout)
            staged.append(f)
        passes["I"] = round(time.monotonic() - ta, 3)
        if not staged:
            return _error(
                tool, tc_id, params, t0, "file_not_found",
                f"no readable nfcapd files under {prep.resolved}",
                "every candidate failed nfdump -I; see files_excluded",
                {"evidence_path": str(prep.resolved), "files_excluded": prep.excluded_json},
            )  # fmt: skip
        prep.selected = staged

        def _i(d: Mapping[str, int | str], key: str) -> int:
            v = d.get(key, 0)
            return v if isinstance(v, int) else 0

        with core.stage(staged) as read:
            tb = time.monotonic()
            stat_mode = [
                "-s", "ip/flows", "-s", "dstport:p/flows", "-s", "srcip/bytes",
                "-s", "dstip/bytes", "-n", str(top_n_e),
            ]  # fmt: skip
            stat_run = _run(prep, read, stat_mode, core.STAT_FMT, "any")
            if isinstance(stat_run, dict):
                return stat_run
            passes["stat"] = round(time.monotonic() - tb, 3)
            argv_passes["stat"] = list(stat_run.argv)
            tc = time.monotonic()
            seg_mode = ["-A", core.SEG_AGG_KEYS, "-s", "record/flows", "-n", str(top_n_e)]
            seg_run = _run(prep, read, seg_mode, core.SEG_FMT, "any")
            if isinstance(seg_run, dict):
                return seg_run
            passes["segment"] = round(time.monotonic() - tc, 3)
            argv_passes["segment"] = list(seg_run.argv)

        stats = core.parse_stat_csv(stat_run.stdout, [True, False, True, True])
        seg = core.parse_flow_csv(seg_run.stdout)
        prep.warnings.extend(stats.warnings + seg.warnings)
        while len(stats.tables) < 4:
            stats.tables.append(core.StatTable())

        idents = sorted({str(d.get("Ident", "")) for d in info.values() if d.get("Ident")})
        exporter = ",".join(idents) if idents else "unknown"
        total = {k: sum(_i(d, k) for d in info.values()) for k in (
            "Flows", "Flows_tcp", "Flows_udp", "Flows_icmp", "Flows_other", "Packets", "Bytes",
        )}  # fmt: skip
        firsts = [
            _i(d, "First") + _i(d, "msec_first") / 1000.0 for d in info.values() if _i(d, "First")
        ]
        lasts = [
            _i(d, "Last") + _i(d, "msec_last") / 1000.0 for d in info.values() if _i(d, "Last")
        ]
        first_e = min(firsts) if firsts else None
        last_e = max(lasts) if lasts else None
        rows: list[core.Row] = [
            core.Row(
                "summary",
                core.iso_s(first_e) if first_e is not None else None,
                [
                    ("exporter", exporter),
                    ("files", len(staged)),
                    ("flows", total["Flows"]),
                    ("tcp_flows", total["Flows_tcp"]),
                    ("udp_flows", total["Flows_udp"]),
                    ("icmp_flows", total["Flows_icmp"]),
                    ("other_flows", total["Flows_other"]),
                    ("packets", total["Packets"]),
                    ("bytes", total["Bytes"]),
                    ("first", core.iso_ms(first_e) if first_e is not None else "-"),
                    ("last", core.iso_ms(last_e) if last_e is not None else "-"),
                    ("dir", str(prep.resolved)),
                ],
            )  # fmt: skip
        ]
        for rank, r in enumerate(stats.tables[0].rows, 1):
            rows.append(core.Row("talker", r.ts, [
                ("rank", rank), ("ip", r.val), ("flows", r.fl), ("flows_pct", r.flP),
                ("packets", r.pkt), ("bytes", r.byt), ("bytes_pct", r.bytP), ("first", r.ts),
                ("last", r.te),
            ]))  # fmt: skip
        for rank, r in enumerate(stats.tables[1].rows, 1):
            rows.append(core.Row("service", r.ts, [
                ("rank", rank), ("proto", r.proto), ("port", r.val), ("flows", r.fl),
                ("flows_pct", r.flP), ("bytes", r.byt), ("first", r.ts), ("last", r.te),
            ]))  # fmt: skip
        for kind, table in (("src_bytes", stats.tables[2]), ("dst_bytes", stats.tables[3])):
            for rank, r in enumerate(table.rows, 1):
                rows.append(core.Row(kind, r.ts, [
                    ("rank", rank), ("ip", r.val), ("bytes", r.byt), ("bytes_pct", r.bytP),
                    ("flows", r.fl), ("first", r.ts), ("last", r.te),
                ]))  # fmt: skip
        for s in seg.rows:
            rows.append(core.Row("segment", core.iso_s(s.first), [
                ("src_net", f"{s.sa}/24"), ("dst_net", f"{s.da}/24"),
                ("flows", s.fl if s.fl is not None else 0), ("packets", s.pkt), ("bytes", s.byt),
                ("first", core.iso_ms(s.first)), ("last", core.iso_ms(s.last)),
            ]))  # fmt: skip
        manifest: list[core.Row] = []
        for f in staged:
            d = info.get(f.path, {})
            fields: list[tuple[str, object]] = [
                ("name", f.path.name), ("size", f.size), ("flows", _i(d, "Flows")),
                ("first", core.iso_s(_i(d, "First")) if _i(d, "First") else "-"),
                ("last", core.iso_s(_i(d, "Last")) if _i(d, "Last") else "-"),
                ("ident", str(d.get("Ident", "unknown"))),
                ("seq_failures", _i(d, "Sequence failures")),
            ]  # fmt: skip
            if f.path.name.lower().startswith("nfcapd.current"):
                fields.append(("note", "live-collector-temp-file-read-via-staging"))
            manifest.append(core.Row("file", None, fields))
        summary: dict[str, object] = {
            "exporter": exporter,
            "files": len(staged),
            "flows": total["Flows"],
            "tcp_flows": total["Flows_tcp"],
            "udp_flows": total["Flows_udp"],
            "icmp_flows": total["Flows_icmp"],
            "other_flows": total["Flows_other"],
            "packets": total["Packets"],
            "bytes": total["Bytes"],
            "first": core.iso_ms(first_e) if first_e is not None else None,
            "last": core.iso_ms(last_e) if last_e is not None else None,
            "talkers": len(stats.tables[0].rows),
            "services": len(stats.tables[1].rows),
            "segments": len(seg.rows),
        }
        return _finish(
            prep,
            named,
            rows,
            filter_applied="any",
            params_effective=eff,
            header_fields=[("top_n", top_n_e)],
            summary=summary,
            truncated=False,
            rows_dropped=stats.dropped + seg.dropped,
            max_inline_rows=inline,
            hint_extra=(
                "Row kinds: summary, talker, service, src_bytes, dst_bytes, segment; per-file "
                "rows are under the .manifest source (bookkeeping, no event_time). talker rows "
                "count each flow once per endpoint (as source and as destination), so their "
                "flows/bytes and *_pct add up to more than the totals and can exceed 100%; "
                "src_bytes/dst_bytes are one-sided. flows=/bytes= sum every exporter record, and "
                "an exporter can emit one flow more than once. Follow up with run_netflow_sweep, "
                "run_netflow_top(direction='egress') and run_netflow_host_profile."
            ),
            extra={"passes": passes, "nfdump_argv_passes": argv_passes},
            manifest=manifest,
        )


# ---------------------------------------------------------------------------
# run_netflow_top
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(_EXECUTORS)
def run_netflow_top(
    evidence_path: str,
    stat: str = "dstip",
    order: str = "flows",
    n: int = 25,
    filter: str = "any",  # noqa: A002
    direction: str = "any",
    internal_nets: list[str] | None = None,
    protocol_split: bool = False,
    t_start: str | None = None,
    t_end: str | None = None,
    max_inline_rows: int = 20,
    force: bool = False,
) -> dict[str, object]:
    """Rank the top-N values of one NetFlow field (stat: srcip, dstip, ip, srcport, dstport, port)
    by order flows, packets, bytes, pps, bps or bpp with percent-of-total, optionally restricted
    by an nfdump filter, a UTC time window (t_start/t_end, 'YYYY-MM-DDTHH:MM:SS', flows active
    in the window) and a direction (egress/ingress/internal relative to internal_nets).
    Use for top external destinations, internal hosts making direct outbound web connections,
    and unusual ports.
    Returns <= n ranked rows (max_inline_rows inline) indexed under netflow.top.<id>; calls on
    one directory serialise.

    Args:
        evidence_path: Absolute nfcapd directory (or file) inside the case evidence root.
        stat: Field to rank: srcip, dstip, ip, srcport, dstport or port. ip and port count each
            flow once per endpoint (as source and as destination), so their flows/bytes and
            *_pct add up to more than the totals and can exceed 100%; use srcip/dstip
            (srcport/dstport) for shares that add up to 100%.
        order: flows, packets, bytes, pps, bps or bpp.
        n: Rows to keep (clamped 1..200).
        filter: nfdump filter expression (whitelisted tokens), default "any".
        direction: any, egress, ingress or internal (relative to internal_nets).
        internal_nets: Up to 8 CIDRs (default RFC1918).
        protocol_split: Split each value by transport protocol (nfdump ':p').
        t_start: UTC window start 'YYYY-MM-DDTHH:MM:SS' (optional, open-ended).
        t_end: UTC window end (optional, open-ended).
        max_inline_rows: Rows returned inline (0..100).
        force: Re-run even if this exact query is already indexed.
    """
    tool = "run_netflow_top"
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path, "stat": stat, "order": order, "n": n, "filter": filter,
        "direction": direction, "internal_nets": internal_nets, "protocol_split": protocol_split,
        "t_start": t_start, "t_end": t_end, "max_inline_rows": max_inline_rows, "force": force,
    }  # fmt: skip
    try:
        stat_e = core.validate_choice(stat, core.STAT_KEYS, "stat")
        order_e = core.validate_choice(order, core.STAT_ORDER, "order")
        n_e = core.clamp(n, 1, 200)
        direction_e = core.validate_choice(direction, core.DIRECTIONS, "direction")
        nets = core.validate_internal_nets(internal_nets)
        filt = core.validate_filter(filter)
        inline = core.clamp(max_inline_rows, 0, core.MAX_INLINE_ROWS)
    except NetflowArgError as exc:
        return _invalid(tool, tc_id, params, t0, exc)
    prep = _prepare(tool, tc_id, t0, params, evidence_path, t_start, t_end)
    if isinstance(prep, dict):
        return prep
    eff: dict[str, object] = {
        "stat": stat_e, "order": order_e, "n": n_e, "filter": core.canonical_filter(filt),
        "direction": direction_e, "internal_nets": nets, "protocol_split": bool(protocol_split),
        **_window_eff(prep), "max_inline_rows": inline,
    }  # fmt: skip
    hid = core.source_hid(tool, str(prep.resolved), _effective_hash_params(eff))
    base = f"netflow.top.{hid}"
    with _name_lock(base):
        named = _name_or_skip(prep, base, force)
        if isinstance(named, dict):
            return named
        full_filter = core.combine_filter(
            filt, core.net_clause(direction_e, nets), core.window_clause(prep.ts, prep.te)
        )
        stat_arg = f"{stat_e}{':p' if protocol_split else ''}/{order_e}"
        rows: list[core.Row] = []
        dropped = 0
        if prep.selected:
            with core.stage(prep.selected) as read:
                run = _run(
                    prep, read, ["-s", stat_arg, "-n", str(n_e)], core.STAT_FMT, full_filter
                )
            if isinstance(run, dict):
                return run
            parsed = core.parse_stat_csv(run.stdout, [core.stat_ip_valued(stat_e)])
            prep.warnings.extend(parsed.warnings)
            dropped = parsed.dropped
            table = parsed.tables[0] if parsed.tables else core.StatTable()
            rows = [core.top_row(r, i, stat_e, order_e) for i, r in enumerate(table.rows[:n_e], 1)]
        return _finish(
            prep,
            named,
            rows,
            filter_applied=full_filter,
            params_effective=eff,
            header_fields=[
                ("stat", stat_e),
                ("order", order_e),
                ("n", n_e),
                ("direction", direction_e),
            ],  # fmt: skip
            summary={"rows": len(rows), "stat": stat_e, "order": order_e},
            truncated=False,
            rows_dropped=dropped,
            max_inline_rows=inline,
            hint_extra=(
                "flows=/packets=/bytes= sum every exporter record (an exporter can emit one flow "
                "more than once), so treat them as record counts and upper bounds, not "
                "connection counts. "
                "stat=ip/port rows count each flow once per endpoint, so their shares can exceed "
                "100% in total. Pivot on a value with run_netflow_host_profile(host=...) or "
                "run_netflow_pair_timeline(src=..., dst=...)."
            ),
        )


# ---------------------------------------------------------------------------
# run_netflow_host_profile
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(_EXECUTORS)
def run_netflow_host_profile(
    evidence_path: str,
    host: str,
    n: int = 20,
    internal_nets: list[str] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    max_inline_rows: int = 20,
    force: bool = False,
) -> dict[str, object]:
    """Profile one IP address (host) from NetFlow: outbound peers and services it uses, inbound
    peers and services it offers, exact byte/flow totals per direction, first/last seen and how
    many of the listed top-n peers are external to internal_nets (external_peers counts only the
    ranked peer rows, not every peer of the host).
    Use to characterise a suspect or victim host before pivoting with run_netflow_pair_timeline.
    Returns <= 6*n ranked rows plus a summary, indexed under netflow.profile.<id>; a host with no
    records is indexed_empty; calls on one directory serialise.

    Args:
        evidence_path: Absolute nfcapd directory (or file) inside the case evidence root.
        host: The IP address to profile.
        n: Rows per ranked table (clamped 5..100).
        internal_nets: Up to 8 CIDRs considered internal (default RFC1918).
        t_start: UTC window start 'YYYY-MM-DDTHH:MM:SS' (optional).
        t_end: UTC window end (optional).
        max_inline_rows: Rows returned inline (0..100).
        force: Re-run even if this exact profile is already indexed.
    """
    tool = "run_netflow_host_profile"
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path, "host": host, "n": n, "internal_nets": internal_nets,
        "t_start": t_start, "t_end": t_end, "max_inline_rows": max_inline_rows, "force": force,
    }  # fmt: skip
    try:
        host_e = core.validate_ip(host, "host")
        n_e = core.clamp(n, 5, 100)
        nets = core.validate_internal_nets(internal_nets)
        inline = core.clamp(max_inline_rows, 0, core.MAX_INLINE_ROWS)
    except NetflowArgError as exc:
        return _invalid(tool, tc_id, params, t0, exc)
    prep = _prepare(tool, tc_id, t0, params, evidence_path, t_start, t_end)
    if isinstance(prep, dict):
        return prep
    eff: dict[str, object] = {
        "host": host_e, "n": n_e, "internal_nets": nets, **_window_eff(prep),
        "max_inline_rows": inline,
    }  # fmt: skip
    hid = core.source_hid(tool, str(prep.resolved), _effective_hash_params(eff))
    base = f"netflow.profile.{hid}"
    with _name_lock(base):
        named = _name_or_skip(prep, base, force)
        if isinstance(named, dict):
            return named
        window = core.window_clause(prep.ts, prep.te)
        out_filter = core.combine_filter(f"src ip {host_e}", window)
        in_filter = core.combine_filter(f"dst ip {host_e}", window)
        rows: list[core.Row] = []
        dropped = 0
        passes: dict[str, float] = {}
        argv_passes: dict[str, list[str]] = {}
        summary: dict[str, object] = {"host": host_e}
        if prep.selected:
            # Table 0 of each pass is the host itself (the filter pins it, so `-s srcip/flows`
            # or `-s dstip/flows` has exactly one row with flP=100.0): its fl/byt/ts/te are the
            # EXACT direction totals and first/last.  Back-computing the total from a one-decimal
            # share of the top dstport row is inexact (it can be off by several percent).
            with core.stage(prep.selected) as read:
                ta = time.monotonic()
                out_mode = [
                    "-s", "srcip/flows", "-s", "dstport:p/flows", "-s", "dstip/flows",
                    "-s", "dstip/bytes", "-n", str(n_e),
                ]  # fmt: skip
                out_run = _run(prep, read, out_mode, core.STAT_FMT, out_filter)
                if isinstance(out_run, dict):
                    return out_run
                passes["out"] = round(time.monotonic() - ta, 3)
                argv_passes["out"] = list(out_run.argv)
                tb = time.monotonic()
                in_mode = [
                    "-s", "dstip/flows", "-s", "dstport:p/flows", "-s", "srcip/flows",
                    "-s", "srcip/bytes", "-n", str(n_e),
                ]  # fmt: skip
                in_run = _run(prep, read, in_mode, core.STAT_FMT, in_filter)
                if isinstance(in_run, dict):
                    return in_run
                passes["in"] = round(time.monotonic() - tb, 3)
                argv_passes["in"] = list(in_run.argv)
            out_p = core.parse_stat_csv(out_run.stdout, [True, False, True, True])
            in_p = core.parse_stat_csv(in_run.stdout, [True, False, True, True])
            prep.warnings.extend(out_p.warnings + in_p.warnings)
            dropped = out_p.dropped + in_p.dropped
            for p in (out_p, in_p):
                while len(p.tables) < 4:
                    p.tables.append(core.StatTable())
            internal = [ipaddress.ip_network(x) for x in nets]

            def _external(ip: str) -> bool:
                addr = ipaddress.ip_address(ip)
                return not any(addr in net for net in internal)

            totals: dict[str, int] = {}
            exact_rows: list[core.StatRow] = []
            for label, p in (("out", out_p), ("in", in_p)):
                exact = p.tables[0].rows
                totals[f"{label}_flows"] = exact[0].fl if exact else 0
                totals[f"{label}_bytes"] = exact[0].byt if exact else 0
                exact_rows += exact
            all_rows = [r for p in (out_p, in_p) for t in p.tables[1:] for r in t.rows]
            first = min((r.ts for r in exact_rows), default=None)
            last = max((r.te for r in exact_rows), default=None)
            peers: list[str] = []
            for p in (out_p, in_p):
                for t in p.tables[2:]:
                    for r in t.rows:
                        if r.val not in peers:
                            peers.append(r.val)
            ext = [ip for ip in peers if _external(ip)]
            summary.update(
                {
                    **totals,
                    "first": first,
                    "last": last,
                    "external_peers": len(ext),
                    "external_peers_scope": f"top{n_e}_peer_tables",
                    "external_peer_ips": ext[: core.MAX_TARGETS_LISTED],
                    "out_services": len(out_p.tables[1].rows),
                    "in_services": len(in_p.tables[1].rows),
                }
            )
            if all_rows or exact_rows:
                rows.append(core.Row("profile", first, [
                    ("host", host_e), ("kind", "summary"), ("out_flows", totals["out_flows"]),
                    ("out_bytes", totals["out_bytes"]), ("in_flows", totals["in_flows"]),
                    ("in_bytes", totals["in_bytes"]), ("first", first or "-"),
                    ("last", last or "-"), ("external_peers", len(ext)),
                    ("external_peers_scope", f"top{n_e}_peer_tables"),
                    ("external_peer_ips", tuple(ext[:core.MAX_TARGETS_LISTED]) if ext else "none"),
                ]))  # fmt: skip
            kinds = (
                ("out_service", out_p.tables[1], True), ("out_peer_flows", out_p.tables[2], False),
                ("out_peer_bytes", out_p.tables[3], False), ("in_service", in_p.tables[1], True),
                ("in_peer_flows", in_p.tables[2], False), ("in_peer_bytes", in_p.tables[3], False),
            )  # fmt: skip
            for kind, table, is_port in kinds:
                for rank, r in enumerate(table.rows[:n_e], 1):
                    rows.append(core.profile_row(r, rank, host_e, kind, is_port))
        return _finish(
            prep,
            named,
            rows,
            filter_applied=f"{out_filter} | {in_filter}",
            params_effective=eff,
            header_fields=[("host", host_e), ("n", n_e)],
            summary=summary,
            truncated=False,
            rows_dropped=dropped,
            max_inline_rows=inline,
            hint_extra=(
                "Row kinds: summary, out_service, out_peer_flows, out_peer_bytes, in_service, "
                "in_peer_flows, in_peer_bytes. out_flows/out_bytes/in_flows/in_bytes and "
                "first/last are exact per-direction totals. external_peers counts external IPs "
                "among the top-n peer rows only (union of the four peer tables), not every peer "
                "of the host: raise n or use run_netflow_top for totals. Pivot on an external "
                "peer with run_netflow_pair_timeline(src=host, dst=peer, dport=port)."
            ),
            extra={"passes": passes, "nfdump_argv_passes": argv_passes},
        )


# ---------------------------------------------------------------------------
# run_netflow_sweep
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(_EXECUTORS)
def run_netflow_sweep(
    evidence_path: str,
    ports: list[int] | None = None,
    min_targets: int = 3,
    n: int = 25,
    syn_only: bool = False,
    burst_window_s: int = 60,
    internal_nets: list[str] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    max_inline_rows: int = 20,
    force: bool = False,
) -> dict[str, object]:
    """Detect internal lateral-movement sweeps and scans in NetFlow: for every (source IP,
    destination port) count distinct internal targets, flows, SYN-only flows and the largest
    burst of new targets within burst_window_s.
    Default ports 22,135,139,445,3389,5985,5986; syn_only=True keeps only unanswered SYN probes
    (scanning/dead hosts).
    Returns <= n (source, port) rows ranked by distinct targets, indexed under netflow.sweep.<id>;
    the top row's targets_list names the hosts touched; calls on one directory serialise.

    Args:
        evidence_path: Absolute nfcapd directory (or file) inside the case evidence root.
        ports: Up to 16 destination ports to watch (default the lateral-movement set).
        min_targets: Minimum distinct targets for a (source, port) to be reported (2..1000).
        n: Rows to keep (clamped 1..100).
        syn_only: Keep only flows with SYN set and ACK clear.
        burst_window_s: Sliding window for the burst statistic (1..3600 s).
        internal_nets: Up to 8 CIDRs considered internal (default RFC1918).
        t_start: UTC window start 'YYYY-MM-DDTHH:MM:SS' (optional).
        t_end: UTC window end (optional).
        max_inline_rows: Rows returned inline (0..100).
        force: Re-run even if this exact sweep is already indexed.
    """
    tool = "run_netflow_sweep"
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path, "ports": ports, "min_targets": min_targets, "n": n,
        "syn_only": syn_only, "burst_window_s": burst_window_s, "internal_nets": internal_nets,
        "t_start": t_start, "t_end": t_end, "max_inline_rows": max_inline_rows, "force": force,
    }  # fmt: skip
    try:
        port_list = list(core.DEFAULT_SWEEP_PORTS) if not ports else list(ports)
        if len(port_list) > core.MAX_SWEEP_PORTS:
            raise NetflowArgError(f"ports has more than {core.MAX_SWEEP_PORTS} entries")
        ports_e = sorted({core.validate_port(p, "ports entry") for p in port_list})
        min_targets_e = core.clamp(min_targets, 2, 1000)
        n_e = core.clamp(n, 1, 100)
        burst_e = core.clamp(burst_window_s, 1, 3600)
        nets = core.validate_internal_nets(internal_nets)
        inline = core.clamp(max_inline_rows, 0, core.MAX_INLINE_ROWS)
    except NetflowArgError as exc:
        return _invalid(tool, tc_id, params, t0, exc)
    prep = _prepare(tool, tc_id, t0, params, evidence_path, t_start, t_end)
    if isinstance(prep, dict):
        return prep
    eff: dict[str, object] = {
        "ports": ports_e, "min_targets": min_targets_e, "n": n_e, "syn_only": bool(syn_only),
        "burst_window_s": burst_e, "internal_nets": nets, **_window_eff(prep),
        "max_inline_rows": inline,
    }  # fmt: skip
    hid = core.source_hid(tool, str(prep.resolved), _effective_hash_params(eff))
    base = f"netflow.sweep.{hid}"
    with _name_lock(base):
        named = _name_or_skip(prep, base, force)
        if isinstance(named, dict):
            return named
        clauses = ["proto tcp and flags S"]
        if syn_only:
            clauses.append("not flags A")
        clauses.append("dst port in [ " + " ".join(str(p) for p in ports_e) + " ]")
        clauses.append("(" + " or ".join(f"src net {x}" for x in nets) + ")")
        clauses.append("(" + " or ".join(f"dst net {x}" for x in nets) + ")")
        window = core.window_clause(prep.ts, prep.te)
        if window:
            clauses.append(window)
        full_filter = " and ".join(clauses)
        rows: list[core.Row] = []
        dropped = 0
        summary: dict[str, object] = {"groups_total": 0, "tuples": 0, "tuple_cap_hit": False}
        if prep.selected:
            mode = [
                "-A", "srcip,dstip,dstport,flags", "-s", "record/flows",
                "-n", str(core.SWEEP_TUPLE_CAP),
            ]  # fmt: skip
            fmt = "csv:%tsr,%ter,%sa,%da,%dp,%flg,%pkt,%byt,%fl"
            with core.stage(prep.selected) as read:
                run = _run(prep, read, mode, fmt, full_filter)
            if isinstance(run, dict):
                return run
            parsed = core.parse_flow_csv(run.stdout)
            prep.warnings.extend(parsed.warnings)
            dropped = parsed.dropped
            cap_hit = len(parsed.rows) >= core.SWEEP_TUPLE_CAP
            if cap_hit:
                prep.warnings.append(
                    f"aggregation returned the {core.SWEEP_TUPLE_CAP}-tuple cap; narrow the window"
                )
            groups = core.sweep_groups(parsed.rows, min_targets_e, burst_e)
            rows = [g.row(burst_e) for g in groups[:n_e]]
            summary = {
                "groups_total": len(groups),
                "tuples": len(parsed.rows),
                "tuple_cap_hit": cap_hit,
                "top": (
                    {
                        "src": groups[0].src,
                        "dport": groups[0].dport,
                        "targets": groups[0].targets,
                        "burst_targets": groups[0].burst_targets,
                        "burst_start": core.iso_ms(groups[0].burst_start),
                    }
                    if groups
                    else None
                ),  # fmt: skip
            }
        return _finish(
            prep,
            named,
            rows,
            filter_applied=full_filter,
            params_effective=eff,
            header_fields=[
                ("ports", ",".join(str(p) for p in ports_e)),
                ("min_targets", min_targets_e),
                ("n", n_e),
                ("syn_only", "true" if syn_only else "false"),
                ("burst_window_s", burst_e),
            ],  # fmt: skip
            summary=summary,
            truncated=(
                bool(summary.get("groups_total", 0)) and int(str(summary["groups_total"])) > n_e
            ),
            rows_dropped=dropped,
            max_inline_rows=inline,
            hint_extra=(
                "targets= and burst_targets= are the lateral-movement signal; flows= counts "
                "exporter records (an exporter can emit one flow more than once: a record "
                "count, not a connection count). Confirm a row with run_netflow_query(filter="
                "'src ip <src> and dst port <dport>', aggregate=['srcip','dstip','dstport'], "
                "t_start=..., t_end=...) and pivot with run_netflow_host_profile(host=<src>)."
            ),
        )


# ---------------------------------------------------------------------------
# run_netflow_pair_timeline
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(_EXECUTORS)
def run_netflow_pair_timeline(
    evidence_path: str,
    src: str,
    dst: str,
    dport: int | None = None,
    proto: str = "any",
    both_directions: bool = False,
    max_records: int = 20000,
    index_records: int = 200,
    t_start: str | None = None,
    t_end: str | None = None,
    max_inline_rows: int = 20,
    force: bool = False,
) -> dict[str, object]:
    """Pull every flow record between two IPs (src, dst; optionally one destination port dport)
    and characterise the relationship: first/last seen, sessions over 1 h, longest and
    lowest-rate session, distinct source ports, TCP flag mix, SYN-only retries, inter-arrival
    statistics (beaconing/periodicity) and flow-size uniformity (fixed-size beacons).
    Use after run_netflow_top / run_netflow_sweep / run_netflow_host_profile point at a
    suspicious pair.
    records= drops only byte-identical exporter copies; records_distinct=/bytes_distinct= also
    collapse re-exports of one flow (same 5-tuple, first/last within 2 ms, different counters):
    cite those for session counts and volumes. With both_directions=True records=/bytes= count
    both legs (records_out/records_in, bytes_out/bytes_in split them) while sessions, intervals,
    source ports and SYN retries are computed on the src->dst leg only.
    Indexes one summary row plus up to index_records flow rows under netflow.pair.<id> (a pair
    with no records is indexed_empty); calls on one directory serialise.

    Args:
        evidence_path: Absolute nfcapd directory (or file) inside the case evidence root.
        src: Source IP address.
        dst: Destination IP address.
        dport: Destination port (1..65535) or None for all ports.
        proto: any, tcp, udp or icmp.
        both_directions: Also match dst->src records (with dport, the reply leg matches
            'src port dport').
        max_records: Records read before truncation (100..50000; file order).
        index_records: Flow rows indexed after the summary row (0..500).
        t_start: UTC window start 'YYYY-MM-DDTHH:MM:SS' (optional).
        t_end: UTC window end (optional).
        max_inline_rows: Rows returned inline (0..100).
        force: Re-run even if this exact pair query is already indexed.
    """
    tool = "run_netflow_pair_timeline"
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path, "src": src, "dst": dst, "dport": dport, "proto": proto,
        "both_directions": both_directions, "max_records": max_records,
        "index_records": index_records, "t_start": t_start, "t_end": t_end,
        "max_inline_rows": max_inline_rows, "force": force,
    }  # fmt: skip
    try:
        src_e = core.validate_ip(src, "src")
        dst_e = core.validate_ip(dst, "dst")
        dport_e = core.validate_port(dport, "dport") if dport is not None else None
        proto_e = core.validate_choice(proto, core.PROTOS, "proto")
        max_records_e = core.clamp(max_records, 100, 50_000)
        index_records_e = core.clamp(index_records, 0, core.MAX_INDEX_ROWS)
        inline = core.clamp(max_inline_rows, 0, core.MAX_INLINE_ROWS)
    except NetflowArgError as exc:
        return _invalid(tool, tc_id, params, t0, exc)
    prep = _prepare(tool, tc_id, t0, params, evidence_path, t_start, t_end)
    if isinstance(prep, dict):
        return prep
    eff: dict[str, object] = {
        "src": src_e, "dst": dst_e, "dport": dport_e, "proto": proto_e,
        "both_directions": bool(both_directions), "max_records": max_records_e,
        "index_records": index_records_e, **_window_eff(prep), "max_inline_rows": inline,
    }  # fmt: skip
    hid = core.source_hid(tool, str(prep.resolved), _effective_hash_params(eff))
    base = f"netflow.pair.{hid}"
    with _name_lock(base):
        named = _name_or_skip(prep, base, force)
        if isinstance(named, dict):
            return named
        # The port clause goes on each leg: a reply record carries dport as its SOURCE port, so a
        # top-level `and dst port P` would silently drop the whole reverse leg.
        fwd = f"src ip {src_e} and dst ip {dst_e}"
        rev = f"src ip {dst_e} and dst ip {src_e}"
        if dport_e is not None:
            fwd += f" and dst port {dport_e}"
            rev += f" and src port {dport_e}"
        clauses = [f"(({fwd}) or ({rev}))" if both_directions else fwd]
        if proto_e != "any":
            clauses.append(f"proto {proto_e}")
        window = core.window_clause(prep.ts, prep.te)
        if window:
            clauses.append(window)
        full_filter = " and ".join(clauses)
        rows: list[core.Row] = []
        dropped = 0
        truncated = False
        summary: dict[str, object] = {}
        if prep.selected:
            with core.stage(prep.selected) as read:
                run = _run(prep, read, ["-c", str(max_records_e + 1)], core.RAW_FMT, full_filter)
            if isinstance(run, dict):
                return run
            parsed = core.parse_flow_csv(run.stdout)
            prep.warnings.extend(parsed.warnings)
            dropped = parsed.dropped
            raw = parsed.rows
            if len(raw) > max_records_e:
                truncated = True
                raw = raw[:max_records_e]
            st = core.pair_stats(raw, truncated, src_e)
            summary = st.as_dict()
            if st.records > 0:
                # No records -> no summary row: the source is indexed_empty, never a
                # data row without an event_time.
                rows.append(
                    core.pair_summary_row(st, src_e, dst_e, dport_e, bool(both_directions))
                )
                deduped, _ = core.dedupe_flows(raw)
                flow_cap = min(index_records_e, core.MAX_INDEX_ROWS - 1)
                rows += [core.flow_row(r) for r in deduped[:flow_cap]]
                if len(deduped) > flow_cap:
                    prep.warnings.append(
                        f"{len(deduped)} unique records; {flow_cap} flow rows indexed after the "
                        "summary (raise index_records or narrow the window for the rest)"
                    )
        hint_extra = (
            "Line 2 is the pair summary (hints= names detected behaviours); later lines are flow "
            "records in chronological order. records= drops only byte-identical exporter copies; "
            "an exporter can also re-export a flow with slightly different timestamps (within "
            "the 2 ms tolerance) or different counters, so cite records_distinct= / "
            "bytes_distinct= for session counts and volumes (records_raw counts every "
            "exporter record). distinct_days counts UTC days on which a record started; "
            "active_days counts every day a record was active."
        )
        if both_directions:
            hint_extra += (
                " both_directions=true: records=/bytes= count both legs (records_out/"
                "records_in, bytes_out/bytes_in split them); sessions, intervals, source ports "
                "and SYN retries are computed on the src->dst leg only."
            )
        if truncated:
            hint_extra += (
                " truncated=true: the record set is a file-order prefix, so hints_partial=true "
                "and the periodicity/size hints are omitted; narrow t_start/t_end (or add dport) "
                "and re-run for periodicity statistics."
            )
        return _finish(
            prep,
            named,
            rows,
            filter_applied=full_filter,
            params_effective=eff,
            header_fields=[
                ("src", src_e),
                ("dst", dst_e),
                ("dport", dport_e if dport_e else "any"),
                ("proto", proto_e),
                ("both_directions", "true" if both_directions else "false"),
                ("max_records", max_records_e),
                ("index_records", index_records_e),
            ],  # fmt: skip
            summary=summary,
            truncated=truncated,
            rows_dropped=dropped,
            max_inline_rows=inline,
            hint_extra=hint_extra,
            extra={
                "records_raw": summary.get("records_raw", 0),
                "records": summary.get("records", 0),
                "hints": summary.get("hints", []),
                "hints_partial": summary.get("hints_partial", truncated),
            },
        )


# ---------------------------------------------------------------------------
# run_netflow_query
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(_EXECUTORS)
def run_netflow_query(
    evidence_path: str,
    filter: str = "any",  # noqa: A002
    aggregate: list[str] | None = None,
    order: str = "tstart",
    limit: int = 100,
    direction: str = "any",
    internal_nets: list[str] | None = None,
    t_start: str | None = None,
    t_end: str | None = None,
    max_inline_rows: int = 20,
    force: bool = False,
) -> dict[str, object]:
    """Run a bounded nfdump query over NetFlow: an nfdump filter (e.g. "src ip 192.0.2.10 and
    dst port 445"), an optional UTC window (t_start/t_end 'YYYY-MM-DDTHH:MM:SS', flows active in
    the window), an optional direction, and either raw flow records (order tstart/tend/duration =
    first `limit` matches in file order then sorted; bytes/packets/bps/bpp/pps = true top-N) or
    rows aggregated by proto/srcip/dstip/srcport/dstport/flags/srcip4/N/dstip4/N ranked by
    flows/bytes/packets/bps/bpp/pps.
    Use for time-window pivots around a known event and for any question the other run_netflow_*
    tools do not answer. flows=, packets= and bytes= (raw or aggregated) sum every exporter
    record; an exporter can emit a flow twice (same 5-tuple and first/last, sometimes with
    different packet/byte counters; run_netflow_pair_timeline's near_copies_collapsed= shows
    the ratio for one pair) and aggregation does NOT remove the copies. Count connections as
    distinct (proto,src,sport,dst,dport,first seen) and treat byte totals as upper bounds;
    run_netflow_pair_timeline reports records_distinct=/bytes_distinct= for one pair.
    Memory rule: order bytes/packets/bps/bpp/pps without aggregate, or aggregates with srcport or
    both srcip and dstip (srcip4/N and dstip4/N with N >= 25 count as srcip/dstip), need a filter
    (any/ipv4/ipv6 alone do not count) or a window of <= 3 files (nfdump keeps every distinct
    key in memory). truncated=true means narrow or aggregate. Indexes <= limit rows under
    netflow.query.<id>; calls on one directory serialise.

    Args:
        evidence_path: Absolute nfcapd directory (or file) inside the case evidence root.
        filter: nfdump filter expression (whitelisted tokens), default "any". For long-lived
            sessions add 'duration > 3600000' (milliseconds) rather than relying on order=duration.
        aggregate: None for raw records, or 1..5 keys from proto, srcip, dstip, srcport, dstport,
            flags, srcip4/N, dstip4/N.
        order: Raw: tstart, tend, duration, bytes, packets, bps, bpp, pps. Aggregated: flows,
            bytes, packets, bps, bpp, pps (a left-over "tstart" becomes flows).
        limit: Rows to return and index (1..500).
        direction: any, egress, ingress or internal (relative to internal_nets).
        internal_nets: Up to 8 CIDRs (default RFC1918).
        t_start: UTC window start 'YYYY-MM-DDTHH:MM:SS' (optional).
        t_end: UTC window end (optional).
        max_inline_rows: Rows returned inline (0..100).
        force: Re-run even if this exact query is already indexed.
    """
    tool = "run_netflow_query"
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path, "filter": filter, "aggregate": aggregate, "order": order,
        "limit": limit, "direction": direction, "internal_nets": internal_nets,
        "t_start": t_start, "t_end": t_end, "max_inline_rows": max_inline_rows, "force": force,
    }  # fmt: skip
    try:
        filt = core.validate_filter(filter)
        keys = core.validate_agg_keys(aggregate)
        order_l = str(order).strip().lower()
        if keys is None:
            order_e = core.validate_choice(order_l, frozenset(core.RAW_ORDER), "order")
        else:
            order_e = (
                "flows"
                if order_l == "tstart"
                else core.validate_choice(order_l, core.STAT_ORDER, "order (aggregated)")
            )
        limit_e = core.clamp(limit, 1, core.MAX_INDEX_ROWS)
        direction_e = core.validate_choice(direction, core.DIRECTIONS, "direction")
        nets = core.validate_internal_nets(internal_nets)
        inline = core.clamp(max_inline_rows, 0, core.MAX_INLINE_ROWS)
    except NetflowArgError as exc:
        return _invalid(tool, tc_id, params, t0, exc)
    prep = _prepare(tool, tc_id, t0, params, evidence_path, t_start, t_end)
    if isinstance(prep, dict):
        return prep
    heavy = core.is_heavy_query(keys, order_e) and len(prep.selected) > core.HEAVY_MAX_FILES
    if heavy and core.is_unrestrictive_filter(filt):
        what = f"aggregate={','.join(keys)}" if keys else f"order={order_e}"
        return _error(
            tool, tc_id, params, t0, "invalid_argument",
            f"{what} over {len(prep.selected)} files needs a filter (any/ipv4/ipv6 alone do not "
            f"narrow it) or a window selecting <= {core.HEAVY_MAX_FILES} files (nfdump keeps "
            "every distinct key in memory)",
            "add t_start/t_end or a filter such as 'src net 192.0.2.0/24'",
            {"evidence_path": str(prep.resolved), "files_scanned": len(prep.selected)},
        )  # fmt: skip
    eff: dict[str, object] = {
        "filter": core.canonical_filter(filt), "aggregate": keys, "order": order_e,
        "limit": limit_e, "direction": direction_e, "internal_nets": nets, **_window_eff(prep),
        "max_inline_rows": inline,
    }  # fmt: skip
    hid = core.source_hid(tool, str(prep.resolved), _effective_hash_params(eff))
    base = f"netflow.query.{hid}"
    with _name_lock(base):
        named = _name_or_skip(prep, base, force)
        if isinstance(named, dict):
            return named
        full_filter = core.combine_filter(
            filt, core.net_clause(direction_e, nets), core.window_clause(prep.ts, prep.te)
        )
        if keys is None:
            if order_e in ("tstart", "tend", "duration"):
                mode = ["-O", order_e, "-c", str(limit_e + 1)]
            else:
                mode = ["-s", f"record/{order_e}", "-n", str(limit_e + 1)]
            fmt = core.RAW_FMT
        else:
            mode = ["-A", ",".join(keys), "-s", f"record/{order_e}", "-n", str(limit_e + 1)]
            fmt = core.agg_format(keys)
        rows: list[core.Row] = []
        dropped = 0
        truncated = False
        if prep.selected:
            with core.stage(prep.selected) as read:
                run = _run(prep, read, mode, fmt, full_filter)
            if isinstance(run, dict):
                return run
            parsed = core.parse_flow_csv(run.stdout)
            prep.warnings.extend(parsed.warnings)
            dropped = parsed.dropped
            recs = parsed.rows
            if len(recs) > limit_e:
                truncated = True
                recs = recs[:limit_e]
            if keys is None:
                recs = core.sort_flows(recs, order_e)
                rows = [core.flow_row(r) for r in recs]
            else:
                rows = [core.agg_row(r, keys) for r in recs]
        hint_extra = (
            "flows=/packets=/bytes= sum every exporter record (aggregated rows too) and an "
            "exporter can emit one flow more than once, so cite them as record counts and volume "
            "upper bounds, not connection counts; raw rows are individual records."
        )
        if truncated:
            hint_extra += f" truncated=true: more than {limit_e} rows matched" + (
                " (raw tstart/tend/duration order returns the first matches in file order): "
                "narrow t_start/t_end or the filter, or aggregate."
                if keys is None
                else ": narrow the filter/window or raise limit (<= 500)."
            )
        return _finish(
            prep,
            named,
            rows,
            filter_applied=full_filter,
            params_effective=eff,
            header_fields=[
                ("aggregate", ",".join(keys) if keys else "none"),
                ("order", order_e),
                ("limit", limit_e),
                ("direction", direction_e),
            ],  # fmt: skip
            summary={"rows": len(rows), "mode": "aggregated" if keys else "raw", "order": order_e},
            truncated=truncated,
            rows_dropped=dropped,
            max_inline_rows=inline,
            hint_extra=hint_extra,
        )
