"""Append-only JSONL audit log for a case investigation."""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import threading
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

from mulder.models import (
    AuditSummary,
    ProvenanceChain,
    SourceProvenance,
    ToolCallEntry,
)

if TYPE_CHECKING:
    from mulder.db import CaseDB

logger = logging.getLogger(__name__)

_COST_PER_MTOK_INPUT = 3.0
_COST_PER_MTOK_OUTPUT = 15.0
_MIN_OUTPUT_TOKEN_ESTIMATE = 100

_AUDIT_SCHEMA = "mulder.audit"
_AUDIT_VERSION = 1
_HASH_PREFIX = "sha256:"
_GENESIS_HASH = _HASH_PREFIX + hashlib.sha256(b"mulder.audit:v1:genesis").hexdigest()
_CHAIN_FIELDS = frozenset({"schema", "version", "sequence", "previous_hash", "entry_hash"})

AuditIntegrityStatus = Literal[
    "empty",
    "verified",
    "verified_with_legacy_anchor",
    "legacy_unverified",
    "invalid",
]


@dataclass(frozen=True)
class AuditIntegrityResult:
    """Result of checking one audit file's complete JSONL event chain.

    ``ok`` means no structural or cryptographic error was observed.  Callers
    that require tamper evidence must additionally require ``status`` to be
    ``verified`` or ``verified_with_legacy_anchor``; a parseable legacy log is
    intentionally reported as unverified rather than corrupt.  Like any
    unsealed hash chain, this verifies the entries present in the file but
    cannot prove that a suffix was not removed without an externally retained
    head or the case manifest added by a later receipt layer.
    """

    ok: bool
    status: AuditIntegrityStatus
    entries_checked: int
    legacy_entries: int
    head_hash: str | None = None
    first_error_line: int | None = None
    first_error_sequence: int | None = None
    error_code: str | None = None
    message: str = ""
    expected: object | None = None
    actual: object | None = None

    @property
    def cryptographically_verified(self) -> bool:
        """Whether the file has a stored chain head covering all present entries."""
        return self.status in {"verified", "verified_with_legacy_anchor"}


@dataclass(frozen=True)
class _AuditScan:
    """Internal scan output used both by verification and append recovery."""

    result: AuditIntegrityResult
    entries: tuple[dict[str, object], ...]
    append_hash: str
    next_sequence: int
    parse_errors: int
    native_entries: int


def _canonical_json(value: object) -> bytes:
    """Serialize a JSON value into the stable byte representation we commit."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(data: bytes) -> str:
    return _HASH_PREFIX + hashlib.sha256(data).hexdigest()


def _entry_hash(entry: Mapping[str, object]) -> str:
    """Hash a native entry, excluding the self-referential ``entry_hash``."""
    payload = {key: value for key, value in entry.items() if key != "entry_hash"}
    return _digest(b"mulder.audit:v1:entry\0" + _canonical_json(payload))


def _legacy_hash(previous_hash: str, entry: Mapping[str, object]) -> str:
    """Build a deterministic anchor over a parseable legacy prefix."""
    return _digest(
        b"mulder.audit:v1:legacy\0"
        + previous_hash.encode("ascii")
        + b"\0"
        + _canonical_json(entry)
    )


def _invalid_result(
    *,
    entries_checked: int,
    legacy_entries: int,
    line_number: int,
    sequence: int | None,
    error_code: str,
    message: str,
    expected: object | None = None,
    actual: object | None = None,
) -> AuditIntegrityResult:
    return AuditIntegrityResult(
        ok=False,
        status="invalid",
        entries_checked=entries_checked,
        legacy_entries=legacy_entries,
        first_error_line=line_number,
        first_error_sequence=sequence,
        error_code=error_code,
        message=message,
        expected=expected,
        actual=actual,
    )


def _scan_audit_file(log_path: Path) -> _AuditScan:
    """Parse and verify ``log_path``, retaining the first broken-link detail."""
    if not log_path.exists():
        result = AuditIntegrityResult(
            ok=True,
            status="empty",
            entries_checked=0,
            legacy_entries=0,
            message="Audit log is empty.",
        )
        return _AuditScan(result, (), _GENESIS_HASH, 1, 0, 0)

    entries: list[dict[str, object]] = []
    rolling_hash = _GENESIS_HASH
    stored_head: str | None = None
    event_count = 0
    entries_checked = 0
    legacy_entries = 0
    native_entries = 0
    parse_errors = 0
    first_error: AuditIntegrityResult | None = None
    saw_native = False

    with open(log_path, "rb") as fh:
        for line_number, raw_line in enumerate(fh, start=1):
            try:
                stripped = raw_line.decode("utf-8").strip()
                if not stripped:
                    continue
                parsed = json.loads(stripped)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                parse_errors += 1
                if first_error is None:
                    first_error = _invalid_result(
                        entries_checked=entries_checked,
                        legacy_entries=legacy_entries,
                        line_number=line_number,
                        sequence=event_count + 1,
                        error_code="invalid_json",
                        message=f"Line {line_number} is not valid JSON: {exc}",
                    )
                continue

            if not isinstance(parsed, dict):
                if first_error is None:
                    first_error = _invalid_result(
                        entries_checked=entries_checked,
                        legacy_entries=legacy_entries,
                        line_number=line_number,
                        sequence=event_count + 1,
                        error_code="entry_not_object",
                        message=f"Line {line_number} is a JSON value, not an audit object.",
                        expected="object",
                        actual=type(parsed).__name__,
                    )
                continue

            entry = cast(dict[str, object], parsed)
            entries.append(entry)
            event_count += 1
            is_native = any(field in entry for field in _CHAIN_FIELDS)

            if first_error is not None:
                continue

            if not is_native:
                if saw_native:
                    first_error = _invalid_result(
                        entries_checked=entries_checked,
                        legacy_entries=legacy_entries,
                        line_number=line_number,
                        sequence=event_count,
                        error_code="legacy_after_chain",
                        message="An unchained legacy entry appears after the native chain began.",
                    )
                    continue
                try:
                    rolling_hash = _legacy_hash(rolling_hash, entry)
                except (TypeError, ValueError) as exc:
                    first_error = _invalid_result(
                        entries_checked=entries_checked,
                        legacy_entries=legacy_entries,
                        line_number=line_number,
                        sequence=event_count,
                        error_code="noncanonical_legacy_entry",
                        message=f"Legacy entry cannot be canonically encoded: {exc}",
                    )
                    continue
                legacy_entries += 1
                entries_checked += 1
                continue

            saw_native = True
            native_entries += 1
            sequence_value = entry.get("sequence")
            sequence = sequence_value if type(sequence_value) is int else None

            required_fields = _CHAIN_FIELDS.difference(entry)
            if required_fields:
                first_error = _invalid_result(
                    entries_checked=entries_checked,
                    legacy_entries=legacy_entries,
                    line_number=line_number,
                    sequence=sequence,
                    error_code="missing_chain_field",
                    message=f"Native entry is missing chain fields: {sorted(required_fields)}",
                    expected=sorted(_CHAIN_FIELDS),
                    actual=sorted(_CHAIN_FIELDS.intersection(entry)),
                )
                continue
            if entry.get("schema") != _AUDIT_SCHEMA:
                first_error = _invalid_result(
                    entries_checked=entries_checked,
                    legacy_entries=legacy_entries,
                    line_number=line_number,
                    sequence=sequence,
                    error_code="unsupported_schema",
                    message="Native entry uses an unsupported audit schema.",
                    expected=_AUDIT_SCHEMA,
                    actual=entry.get("schema"),
                )
                continue
            if type(entry.get("version")) is not int or entry.get("version") != _AUDIT_VERSION:
                first_error = _invalid_result(
                    entries_checked=entries_checked,
                    legacy_entries=legacy_entries,
                    line_number=line_number,
                    sequence=sequence,
                    error_code="unsupported_version",
                    message="Native entry uses an unsupported audit schema version.",
                    expected=_AUDIT_VERSION,
                    actual=entry.get("version"),
                )
                continue
            if sequence != event_count:
                first_error = _invalid_result(
                    entries_checked=entries_checked,
                    legacy_entries=legacy_entries,
                    line_number=line_number,
                    sequence=sequence,
                    error_code="sequence_mismatch",
                    message="Audit event sequence is not contiguous.",
                    expected=event_count,
                    actual=sequence_value,
                )
                continue

            legacy_marker = entry.get("legacy_prefix_entries")
            if native_entries == 1 and legacy_entries:
                if legacy_marker != legacy_entries:
                    first_error = _invalid_result(
                        entries_checked=entries_checked,
                        legacy_entries=legacy_entries,
                        line_number=line_number,
                        sequence=sequence,
                        error_code="legacy_anchor_mismatch",
                        message="First native entry does not declare its full legacy prefix.",
                        expected=legacy_entries,
                        actual=legacy_marker,
                    )
                    continue
            elif legacy_marker is not None:
                first_error = _invalid_result(
                    entries_checked=entries_checked,
                    legacy_entries=legacy_entries,
                    line_number=line_number,
                    sequence=sequence,
                    error_code="unexpected_legacy_anchor",
                    message=(
                        "Only a first native entry following legacy records may declare an anchor."
                    ),
                    expected=None,
                    actual=legacy_marker,
                )
                continue

            previous_hash = entry.get("previous_hash")
            if previous_hash != rolling_hash:
                first_error = _invalid_result(
                    entries_checked=entries_checked,
                    legacy_entries=legacy_entries,
                    line_number=line_number,
                    sequence=sequence,
                    error_code="previous_hash_mismatch",
                    message="Audit entry does not link to the preceding event.",
                    expected=rolling_hash,
                    actual=previous_hash,
                )
                continue
            try:
                expected_hash = _entry_hash(entry)
            except (TypeError, ValueError) as exc:
                first_error = _invalid_result(
                    entries_checked=entries_checked,
                    legacy_entries=legacy_entries,
                    line_number=line_number,
                    sequence=sequence,
                    error_code="noncanonical_entry",
                    message=f"Native entry cannot be canonically encoded: {exc}",
                )
                continue
            actual_hash = entry.get("entry_hash")
            if actual_hash != expected_hash:
                first_error = _invalid_result(
                    entries_checked=entries_checked,
                    legacy_entries=legacy_entries,
                    line_number=line_number,
                    sequence=sequence,
                    error_code="entry_hash_mismatch",
                    message="Audit entry content does not match its committed hash.",
                    expected=expected_hash,
                    actual=actual_hash,
                )
                continue

            rolling_hash = expected_hash
            stored_head = expected_hash
            entries_checked += 1

    if first_error is not None:
        return _AuditScan(
            first_error,
            tuple(entries),
            rolling_hash,
            event_count + 1,
            parse_errors,
            native_entries,
        )
    if event_count == 0:
        result = AuditIntegrityResult(
            ok=True,
            status="empty",
            entries_checked=0,
            legacy_entries=0,
            message="Audit log is empty.",
        )
    elif not saw_native:
        result = AuditIntegrityResult(
            ok=True,
            status="legacy_unverified",
            entries_checked=entries_checked,
            legacy_entries=legacy_entries,
            message="Legacy entries are readable but have no stored integrity chain.",
        )
    else:
        status: AuditIntegrityStatus = (
            "verified_with_legacy_anchor" if legacy_entries else "verified"
        )
        result = AuditIntegrityResult(
            ok=True,
            status=status,
            entries_checked=entries_checked,
            legacy_entries=legacy_entries,
            head_hash=stored_head,
            message=(
                "The native chain commits the canonical legacy prefix and all native entries."
                if legacy_entries
                else "Every audit entry is covered by the native integrity chain."
            ),
        )
    return _AuditScan(
        result,
        tuple(entries),
        rolling_hash,
        event_count + 1,
        parse_errors,
        native_entries,
    )


class AuditLog:
    """Append-only JSONL audit log for a case investigation.

    Each ``log_tool_call`` invocation appends a single JSON line and records
    the ``tool_call_id`` in an in-memory index for fast validation by
    ``submit_finding`` and provenance chain resolution.
    """

    def __init__(self, log_path: Path) -> None:
        """Open or create an audit log at ``log_path`` and load existing entries."""
        self._log_path = Path(log_path)
        self._lock = threading.Lock()
        self._tool_call_ids: set[str] = set()
        self._tool_calls: dict[str, dict[str, object]] = {}
        self._finding_entries: dict[str, dict[str, object]] = {}
        self._total_tool_calls: int = 0
        self._total_findings: int = 0
        self._total_duration_ms: float = 0.0
        self._tool_call_counts: dict[str, int] = defaultdict(int)
        self._tool_durations: dict[str, float] = defaultdict(float)
        self._estimated_input_tokens: int = 0
        self._estimated_output_tokens: int = 0
        self._timestamps: list[str] = []
        self._append_hash = _GENESIS_HASH
        self._next_sequence = 1
        self._legacy_entries = 0
        self._native_entries = 0
        self._append_blocked_reason: str | None = None
        self._file_fingerprint: tuple[int, int, int, int] | None = None
        self._load_existing()

    def _reset_indexes(self) -> None:
        """Reset derived state before reloading a file changed by another writer."""
        self._tool_call_ids.clear()
        self._tool_calls.clear()
        self._finding_entries.clear()
        self._total_tool_calls = 0
        self._total_findings = 0
        self._total_duration_ms = 0.0
        self._tool_call_counts.clear()
        self._tool_durations.clear()
        self._estimated_input_tokens = 0
        self._estimated_output_tokens = 0
        self._timestamps.clear()

    def _fingerprint(self) -> tuple[int, int, int, int] | None:
        try:
            stat = self._log_path.stat()
        except FileNotFoundError:
            return None
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def _load_existing(self) -> None:
        """Populate in-memory indexes from an existing JSONL file."""
        scan = _scan_audit_file(self._log_path)
        self._append_hash = scan.append_hash
        self._next_sequence = scan.next_sequence
        self._legacy_entries = scan.result.legacy_entries
        self._native_entries = scan.native_entries
        self._append_blocked_reason = None if scan.result.ok else scan.result.message
        for entry in scan.entries:
            self._index_entry(entry)
        if scan.parse_errors > 0:
            logger.warning(
                "Audit log %s: %d lines failed to parse (possible corruption)",
                self._log_path,
                scan.parse_errors,
            )
        if not scan.result.ok:
            logger.warning(
                "Audit log %s failed integrity verification at line %s: %s",
                self._log_path,
                scan.result.first_error_line,
                scan.result.message,
            )
        self._file_fingerprint = self._fingerprint()

    def verify_integrity(self) -> AuditIntegrityResult:
        """Verify the complete file and return the first broken-link diagnostic.

        This method never mutates or repairs the log.  ``legacy_unverified`` is
        a compatibility state, not a cryptographic success.  Once a native
        event is appended to a legacy log, its first link canonically commits
        the entire parseable legacy prefix as it exists at that transition.
        Detecting removal of a complete final suffix requires an external head
        commitment or sealed case manifest and is deliberately out of scope.
        """
        return _scan_audit_file(self._log_path).result

    def _index_entry(self, entry: dict[str, object]) -> None:
        """Index a parsed audit entry by type and update summary accumulators."""
        ts = entry.get("timestamp")
        if isinstance(ts, str) and ts:
            self._timestamps.append(ts)

        entry_type = entry.get("type")
        if entry_type == "tool_call" and "tool_call_id" in entry:
            tcid = entry["tool_call_id"]
            if not isinstance(tcid, str):
                return
            self._tool_call_ids.add(tcid)
            self._tool_calls[tcid] = entry
            tool_name = entry.get("tool_name", "unknown")
            if isinstance(tool_name, str) and tool_name != "run_parallel":
                self._total_tool_calls += 1
                dur = entry.get("duration_ms", 0)
                dur_f = float(dur) if isinstance(dur, int | float) else 0.0
                self._tool_call_counts[tool_name] += 1
                self._tool_durations[tool_name] += dur_f
                self._total_duration_ms += dur_f
                params_str = json.dumps(entry.get("params", {}))
                self._estimated_input_tokens += len(params_str) // 4
                self._estimated_output_tokens += max(
                    len(params_str) // 2, _MIN_OUTPUT_TOKEN_ESTIMATE
                )
        elif entry_type == "finding" and "finding_id" in entry:
            fid = entry["finding_id"]
            if not isinstance(fid, str):
                return
            self._finding_entries[fid] = entry
            self._total_findings += 1

    def _append(self, entry: dict[str, object]) -> None:
        """Append ``entry`` to the JSONL log file and update in-memory indexes."""
        with self._lock:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a+", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    if self._fingerprint() != self._file_fingerprint:
                        self._reset_indexes()
                        self._load_existing()
                    if self._append_blocked_reason is not None:
                        raise RuntimeError(
                            "Refusing to append to an invalid audit log: "
                            f"{self._append_blocked_reason}"
                        )
                    reserved = _CHAIN_FIELDS.intersection(entry)
                    if reserved:
                        raise ValueError(
                            f"Audit event may not set reserved chain fields: {sorted(reserved)}"
                        )

                    chained_entry = dict(entry)
                    chained_entry.update(
                        {
                            "schema": _AUDIT_SCHEMA,
                            "version": _AUDIT_VERSION,
                            "sequence": self._next_sequence,
                            "previous_hash": self._append_hash,
                        }
                    )
                    if self._native_entries == 0 and self._legacy_entries:
                        chained_entry["legacy_prefix_entries"] = self._legacy_entries
                    chained_entry["entry_hash"] = _entry_hash(chained_entry)
                    serialized = _canonical_json(chained_entry).decode("utf-8")

                    fh.write(serialized + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                    self._append_hash = cast(str, chained_entry["entry_hash"])
                    self._next_sequence += 1
                    self._native_entries += 1
                    self._index_entry(chained_entry)
                    stat = os.fstat(fh.fileno())
                    self._file_fingerprint = (
                        stat.st_dev,
                        stat.st_ino,
                        stat.st_size,
                        stat.st_mtime_ns,
                    )
                finally:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def log_tool_call(
        self,
        tool_call_id: str,
        tool_name: str,
        params: Mapping[str, object],
        output_hash: str,
        duration_ms: float = 0,
        sub_calls: list[str] | None = None,
        batch_id: str | None = None,
    ) -> None:
        """Record a tool invocation as one JSONL line and index ``tool_call_id``."""
        entry: dict[str, object] = {
            "type": "tool_call",
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "params": dict(params),
            "output_hash": output_hash,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if sub_calls is not None:
            entry["sub_calls"] = sub_calls
        if batch_id is not None:
            entry["batch_id"] = batch_id
        self._append(entry)

    def has_tool_call(self, tool_call_id: str) -> bool:
        """Return True if ``tool_call_id`` appears in this audit log."""
        return tool_call_id in self._tool_call_ids

    @property
    def tool_call_ids(self) -> set[str]:
        """All tool call IDs indexed from the log (copy of the internal set)."""
        return set(self._tool_call_ids)

    def log_ingestion_step(
        self,
        source_name: str,
        source_path: str,
        source_hash: str,
        extractor: str,
        window_count: int,
        duration_ms: float,
    ) -> None:
        """Record a source ingestion step (extractor run and window count)."""
        entry: dict[str, object] = {
            "type": "ingestion",
            "source_name": source_name,
            "source_path": source_path,
            "source_hash": source_hash,
            "extractor": extractor,
            "window_count": window_count,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._append(entry)

    def log_finding_submission(
        self,
        finding_id: str,
        evidence_refs: list[str],
    ) -> None:
        """Record a finding submission and its evidence tool-call references."""
        entry: dict[str, object] = {
            "type": "finding",
            "finding_id": finding_id,
            "evidence_refs": evidence_refs,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._append(entry)

    def get_provenance_chain(self, finding_id: str, db: CaseDB) -> ProvenanceChain:
        """Trace a finding back through tool calls to original evidence files."""
        finding_entry = self._finding_entries.get(finding_id)
        if finding_entry is None:
            raise KeyError(f"No finding with id '{finding_id}' in the audit log")

        raw_refs = finding_entry.get("evidence_refs", [])
        if isinstance(raw_refs, list):
            evidence_refs = [x for x in raw_refs if isinstance(x, str)]
        else:
            evidence_refs = []
        tool_calls, queried_source_names = self._resolve_tool_calls(evidence_refs)
        sources = self._resolve_sources(queried_source_names, db)

        return ProvenanceChain(
            finding_id=finding_id,
            tool_calls=tool_calls,
            sources=sources,
        )

    def _resolve_tool_calls(
        self, evidence_refs: list[str]
    ) -> tuple[list[ToolCallEntry], set[str]]:
        """Map ``evidence_refs`` to ``ToolCallEntry`` rows and collect source names."""
        tool_calls: list[ToolCallEntry] = []
        source_names: set[str] = set()

        for ref in evidence_refs:
            tc = self._tool_calls.get(ref)
            if tc is None:
                continue
            tcid_o = tc.get("tool_call_id", "")
            tname_o = tc.get("tool_name", "")
            params_o = tc.get("params", {})
            outh_o = tc.get("output_hash", "")
            ts_o = tc.get("timestamp", "")
            dur_o = tc.get("duration_ms", 0)
            params: dict[str, object] = (
                cast(dict[str, object], params_o) if isinstance(params_o, dict) else {}
            )
            dur_f = float(dur_o) if isinstance(dur_o, int | float) else 0.0
            bid_o = tc.get("batch_id")
            tool_calls.append(
                ToolCallEntry(
                    tool_call_id=tcid_o if isinstance(tcid_o, str) else "",
                    tool_name=tname_o if isinstance(tname_o, str) else "",
                    params=params,
                    output_hash=outh_o if isinstance(outh_o, str) else "",
                    timestamp=ts_o if isinstance(ts_o, str) else "",
                    duration_ms=dur_f,
                    batch_id=bid_o if isinstance(bid_o, str) else None,
                )
            )
            source_names.update(self._extract_source_names(params))

        return tool_calls, source_names

    @staticmethod
    def _extract_source_names(params: dict[str, object]) -> set[str]:
        """Collect source identifiers from tool ``params`` (keys, channel, lists)."""
        names: set[str] = set()
        for key in ("source", "source_name"):
            val = params.get(key)
            if isinstance(val, str):
                names.add(val)
        channel = params.get("channel")
        if channel is not None:
            names.add(f"evtx.{channel}")
        sources_list = params.get("sources")
        if isinstance(sources_list, list):
            names.update(x for x in sources_list if isinstance(x, str))
        return names

    @staticmethod
    def _resolve_sources(queried_names: set[str], db: CaseDB) -> list[SourceProvenance]:
        """Look up ``SourceProvenance`` rows in the case DB for ``queried_names``."""
        db_sources = {s.source_name: s for s in db.get_sources()}
        return [
            SourceProvenance(
                source_name=src.source_name,
                source_path=src.source_path,
                source_hash=src.source_hash,
                extractor=src.extractor,
            )
            for name in sorted(queried_names)
            if (src := db_sources.get(name)) is not None
        ]

    def summary(self) -> AuditSummary:
        """Compute aggregate statistics from in-memory accumulators."""
        if not self._timestamps and self._total_tool_calls == 0:
            return AuditSummary(
                total_tool_calls=0,
                total_findings=0,
                tool_call_counts={},
                total_duration_ms=0.0,
                first_timestamp="",
                last_timestamp="",
            )

        cost_per_mtok_in = _COST_PER_MTOK_INPUT
        cost_per_mtok_out = _COST_PER_MTOK_OUTPUT
        estimated_cost = (
            self._estimated_input_tokens / 1_000_000 * cost_per_mtok_in
            + self._estimated_output_tokens / 1_000_000 * cost_per_mtok_out
        )

        wall_clock_ms = self._total_duration_ms
        if len(self._timestamps) >= 2:
            try:
                t0 = datetime.fromisoformat(self._timestamps[0])
                t1 = datetime.fromisoformat(self._timestamps[-1])
                wall_clock_ms = (t1 - t0).total_seconds() * 1000
            except (ValueError, TypeError):
                pass

        return AuditSummary(
            total_tool_calls=self._total_tool_calls,
            total_findings=self._total_findings,
            tool_call_counts=dict(self._tool_call_counts),
            tool_durations=dict(self._tool_durations),
            total_duration_ms=self._total_duration_ms,
            wall_clock_ms=wall_clock_ms,
            first_timestamp=self._timestamps[0] if self._timestamps else "",
            last_timestamp=self._timestamps[-1] if self._timestamps else "",
            estimated_input_tokens=self._estimated_input_tokens,
            estimated_output_tokens=self._estimated_output_tokens,
            estimated_cost_usd=round(estimated_cost, 4),
        )
