"""Append-only JSONL audit log for a case investigation."""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import threading
from collections import defaultdict
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, TYPE_CHECKING, Literal, cast

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
class AuditFileSnapshot:
    """One locked audit-file observation and its semantic verification result."""

    integrity: AuditIntegrityResult
    entries: tuple[dict[str, object], ...]
    sha256: str
    size_bytes: int


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


@contextmanager
def _audit_read_handle(
    log_path: Path,
    locked_handle: IO[bytes] | None,
) -> Iterator[IO[bytes]]:
    """Yield the caller's locked descriptor or own a fresh read descriptor."""
    if locked_handle is not None:
        yield locked_handle
        return
    with open(log_path, "rb") as handle:
        yield handle


def _scan_audit_file(
    log_path: Path,
    *,
    locked_handle: IO[bytes] | None = None,
) -> _AuditScan:
    """Parse and verify ``log_path``, retaining the first broken-link detail."""
    if locked_handle is None and not log_path.exists():
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

    with _audit_read_handle(log_path, locked_handle) as fh:
        if locked_handle is not None:
            fh.seek(0)
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


@contextmanager
def _shared_file_lock(log_path: Path) -> Iterator[IO[bytes] | None]:
    """Hold a cooperative read lock while a caller scans an existing log."""
    try:
        fh = open(log_path, "rb")  # noqa: SIM115 - owned by the context below
    except FileNotFoundError:
        yield None
        return
    with fh:
        locked_stat = os.fstat(fh.fileno())
        fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
        try:
            yield fh
            try:
                current_stat = log_path.stat()
            except FileNotFoundError as exc:
                raise RuntimeError("Audit log was removed while being verified") from exc
            if (current_stat.st_dev, current_stat.st_ino) != (
                locked_stat.st_dev,
                locked_stat.st_ino,
            ):
                raise RuntimeError("Audit log was replaced while being verified")
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


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

    def _load_existing(
        self,
        *,
        writer_lock_held: bool = False,
        locked_handle: IO[bytes] | None = None,
    ) -> None:
        """Populate in-memory indexes from an existing JSONL file."""
        if writer_lock_held:
            scan = _scan_audit_file(self._log_path, locked_handle=locked_handle)
        else:
            with _shared_file_lock(self._log_path) as shared_handle:
                scan = _scan_audit_file(
                    self._log_path,
                    locked_handle=shared_handle,
                )
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
        with _shared_file_lock(self._log_path) as shared_handle:
            return _scan_audit_file(
                self._log_path,
                locked_handle=shared_handle,
            ).result

    def read_verified_snapshot(
        self,
    ) -> tuple[AuditIntegrityResult, tuple[dict[str, object], ...]]:
        """Return integrity and entries from one cooperatively locked scan.

        Consumers that bind semantics to an entry must not verify the file and
        reopen it later: a replacement between those operations would create a
        time-of-check/time-of-use gap.  This method keeps both observations in
        the same shared-lock snapshot.
        """
        snapshot = self.read_verified_file_snapshot()
        return snapshot.integrity, snapshot.entries

    def read_verified_file_snapshot(self) -> AuditFileSnapshot:
        """Hash and verify the exact same cooperatively locked audit bytes."""
        with self.hold_verified_file_snapshot() as snapshot:
            return snapshot

    @contextmanager
    def hold_verified_file_snapshot(self) -> Iterator[AuditFileSnapshot]:
        """Yield one verified snapshot while preventing cooperative appends."""
        with _shared_file_lock(self._log_path) as shared_handle:
            scan = _scan_audit_file(
                self._log_path,
                locked_handle=shared_handle,
            )
            digest = hashlib.sha256()
            size = 0
            if shared_handle is not None:
                shared_handle.seek(0)
                while chunk := shared_handle.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
            yield AuditFileSnapshot(
                integrity=scan.result,
                entries=scan.entries,
                sha256=_HASH_PREFIX + digest.hexdigest(),
                size_bytes=size,
            )

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

    def _append(
        self,
        entry: dict[str, object],
        *,
        bind_previous_as: str | None = None,
    ) -> dict[str, object]:
        """Append ``entry`` and return the exact chained record written to disk."""
        with self._lock:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a+", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    descriptor_stat = os.fstat(fh.fileno())
                    current_stat = self._log_path.stat()
                    if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (
                        current_stat.st_dev,
                        current_stat.st_ino,
                    ):
                        raise RuntimeError("Audit log was replaced during append")
                    if self._fingerprint() != self._file_fingerprint:
                        self._reset_indexes()
                        self._load_existing(
                            writer_lock_held=True,
                            locked_handle=cast(IO[bytes], fh.buffer),
                        )
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
                    if bind_previous_as is not None:
                        if bind_previous_as in chained_entry:
                            raise ValueError(
                                f"Audit event may not set {bind_previous_as}; it is chain-bound"
                            )
                        chained_entry[bind_previous_as] = self._append_hash
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
        return chained_entry

    def log_run_event(
        self,
        case_id: str,
        event: Mapping[str, object],
    ) -> dict[str, object]:
        """Append one typed review-console run event to the audit chain.

        The review event schema is owned by :mod:`mulder.review.events`; this
        low-level method only supplies the audit timestamp and durable chain
        sequence.  Callers cannot override audit or event envelope fields.
        """
        reserved = _CHAIN_FIELDS.union({"type", "timestamp", "case_id"})
        collision = reserved.intersection(event)
        if collision:
            raise ValueError(f"Run event may not set reserved fields: {sorted(collision)}")
        return self._append(
            {
                "type": "run_event",
                "case_id": case_id,
                **dict(event),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def log_checkpoint_event(
        self,
        case_id: str,
        event: Mapping[str, object],
    ) -> dict[str, object]:
        """Append one restart checkpoint proposal to the case audit chain.

        The run ledger is operational and mutable.  This audit entry binds the
        phase identity, exact input, and result digest to tamper-evident case
        state so a forged SQLite row cannot be accepted during resume.  The
        proposal is not completion by itself: only an exact, committed SQLite
        row that cites its entry hash completes the checkpoint.
        """
        reserved = _CHAIN_FIELDS.union(
            {
                "type",
                "timestamp",
                "case_id",
                "checkpoint_state",
                "result_parent_audit_head",
            }
        )
        collision = reserved.intersection(event)
        if collision:
            raise ValueError(
                f"Checkpoint event may not set reserved fields: {sorted(collision)}"
            )
        return self._append(
            {
                "type": "run_checkpoint",
                "checkpoint_state": "proposed",
                "case_id": case_id,
                **dict(event),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            bind_previous_as="result_parent_audit_head",
        )

    def read_run_event_entries(
        self,
        *,
        after_sequence: int = 0,
        limit: int = 1000,
    ) -> tuple[AuditIntegrityResult, tuple[dict[str, object], ...], int, int]:
        """Read a stable bounded page of native run-event audit entries.

        Returns the complete audit integrity result, selected entries, the
        highest native run-event sequence currently present, and the number of
        legacy run-event entries skipped because they have no durable ID.
        """
        if after_sequence < 0:
            raise ValueError("after_sequence must be non-negative")
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with _shared_file_lock(self._log_path) as shared_handle:
            scan = _scan_audit_file(
                self._log_path,
                locked_handle=shared_handle,
            )
        selected: list[dict[str, object]] = []
        high_watermark = 0
        skipped_legacy = 0
        for entry in scan.entries:
            if entry.get("type") != "run_event":
                continue
            sequence = entry.get("sequence")
            if type(sequence) is not int:
                skipped_legacy += 1
                continue
            high_watermark = max(high_watermark, sequence)
            if sequence > after_sequence and len(selected) < limit:
                selected.append(entry)
        return scan.result, tuple(selected), high_watermark, skipped_legacy

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

    def tool_call_source_names(self, tool_call_id: str) -> set[str]:
        """Return server-recorded sources whose output the call exposed."""
        entry = self._tool_calls.get(tool_call_id)
        if entry is None:
            return set()
        params = entry.get("params")
        if not isinstance(params, dict):
            return set()
        return self._extract_source_names(cast(dict[str, object], params))

    def tool_call_window_ids(self, tool_call_id: str) -> set[int]:
        """Return immutable window IDs actually exposed by one audited call."""
        entry = self._tool_calls.get(tool_call_id)
        if entry is None:
            return set()
        params = entry.get("params")
        if not isinstance(params, dict):
            return set()
        values = params.get("returned_window_ids")
        if not isinstance(values, list):
            return set()
        return {value for value in values if type(value) is int and value > 0}

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

    def log_execution_decision(self, event: Mapping[str, object]) -> None:
        """Record one centralized command policy decision and terminal state."""
        entry = {"type": "execution_policy", **dict(event)}
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
        plugin = params.get("plugin")
        if isinstance(plugin, str) and plugin:
            short = plugin.rsplit(".", 1)[-1].casefold()
            names.add(f"volatility.{short}")
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
