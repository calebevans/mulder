"""Durable run handles, phase checkpoints, cancellation, and health forecasts.

This module is the persistence boundary for restartable orchestration.  It
stores only operational state; findings and evidence remain authoritative in
the case database and audit chain.  A checkpoint is reusable only when its
input digest matches and its audit head is still present in a verified chain.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Literal, cast
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from mulder.audit import AuditLog
from mulder.orchestrator.types import PhaseResult

RUN_STATE_SCHEMA: Literal["mulder.run-state"] = "mulder.run-state"
RUN_STATE_VERSION: Literal[1] = 1
RUN_CHECKPOINT_VERSION: Literal[2] = 2
RunProfile = Literal["quick", "full"]
RunStatus = Literal[
    "running",
    "cancel_requested",
    "awaiting_review",
    "cancelled",
    "completed",
    "failed",
]


class RunStateError(ValueError):
    """Raised when a run handle or checkpoint is inconsistent."""


class RunCancelled(RunStateError):
    """Raised at a cooperative boundary after cancellation is requested."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)


class RunProfileSpec(_FrozenModel):
    """Persisted meaning of a quick or full run."""

    name: RunProfile
    coverage_ceiling: Literal["sampled", "evidence_bounded"]
    budget_multiplier: float = Field(gt=0, le=1)
    description: str


PROFILES: Mapping[RunProfile, RunProfileSpec] = {
    "quick": RunProfileSpec(
        name="quick",
        coverage_ceiling="sampled",
        budget_multiplier=0.35,
        description=(
            "Triage profile. Results remain sampled/partial and cannot represent full coverage."
        ),
    ),
    "full": RunProfileSpec(
        name="full",
        coverage_ceiling="evidence_bounded",
        budget_multiplier=1.0,
        description=(
            "Complete configured workflow. Full coverage still requires "
            "affirmative coverage records."
        ),
    ),
}


class HealthForecast(_FrozenModel):
    """Conservative pre-run capacity forecast, never a completion claim."""

    profile: RunProfile
    evidence_files: int = Field(ge=0)
    evidence_bytes: int = Field(ge=0)
    required_working_bytes: int = Field(ge=0)
    free_disk_bytes: int = Field(ge=0)
    available_memory_bytes: int = Field(ge=0)
    estimated_minutes_low: int = Field(ge=0)
    estimated_minutes_high: int = Field(ge=0)
    ready: bool
    warnings: tuple[str, ...]
    basis: Literal["size_heuristic_v1"] = "size_heuristic_v1"


class RunHandle(_FrozenModel):
    """Stable user-facing handle for one resumable run."""

    run_id: str
    case_id: str
    profile: RunProfile
    coverage_ceiling: Literal["sampled", "evidence_bounded"]
    input_digest: str
    contract_digest: str
    approval_required: bool
    generation: int = Field(ge=1)
    status: RunStatus
    cancel_requested: bool
    created_at: str
    updated_at: str
    completed_steps: tuple[str, ...]


class PhaseCheckpoint(_FrozenModel):
    """One completed phase attempt bound to input and audit position."""

    attempt_id: str
    run_id: str
    step_key: str
    phase_name: str
    attempt_number: int = Field(ge=1)
    run_generation: int = Field(ge=1)
    input_digest: str
    audit_head_before: str
    audit_head_after: str
    result_digest: str
    checkpoint_event_hash: str
    result: dict[str, object]
    started_at: str
    completed_at: str


_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    profile TEXT NOT NULL CHECK(profile IN ('quick','full')),
    coverage_ceiling TEXT NOT NULL CHECK(coverage_ceiling IN ('sampled','evidence_bounded')),
    input_digest TEXT NOT NULL,
    contract_digest TEXT NOT NULL,
    approval_required INTEGER NOT NULL DEFAULT 0 CHECK(approval_required IN (0,1)),
    generation INTEGER NOT NULL DEFAULT 1 CHECK(generation > 0),
    status TEXT NOT NULL CHECK(status IN
        ('running','cancel_requested','awaiting_review','cancelled','completed','failed')),
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS phase_attempts (
    attempt_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    step_key TEXT NOT NULL,
    phase_name TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK(attempt_number > 0),
    run_generation INTEGER NOT NULL CHECK(run_generation > 0),
    input_digest TEXT NOT NULL,
    audit_head_before TEXT NOT NULL,
    audit_head_after TEXT,
    result_digest TEXT,
    checkpoint_event_hash TEXT,
    status TEXT NOT NULL CHECK(status IN ('running','completed','interrupted')),
    result_json TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(run_id, step_key, attempt_number)
);
CREATE INDEX IF NOT EXISTS ix_phase_attempts_run_step
    ON phase_attempts(run_id, step_key, attempt_number);
CREATE TABLE IF NOT EXISTS run_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS run_events_no_update
    BEFORE UPDATE ON run_events BEGIN SELECT RAISE(ABORT, 'run events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS run_events_no_delete
    BEFORE DELETE ON run_events BEGIN SELECT RAISE(ABORT, 'run events are append-only'); END;
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_value(domain: str, value: object) -> str:
    """Return a domain-separated stable digest for checkpoint inputs."""
    return "sha256:" + hashlib.sha256(
        domain.encode("utf-8") + b"\0" + _canonical_json(value)
    ).hexdigest()


def evidence_identity(path: Path) -> str:
    """Fingerprint an un-ingested path inventory for restart safety.

    This is a change detector, not a chain-of-custody content commitment.
    Content-addressed intake manifests should be preferred when available.
    """
    root = Path(path).expanduser().resolve(strict=True)
    if root.is_file():
        stat_result = root.stat()
        inventory: object = {
            "kind": "file",
            "path": str(root),
            "size": stat_result.st_size,
            "mtime_ns": stat_result.st_mtime_ns,
        }
    else:
        entries: list[tuple[str, int, int]] = []
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = sorted(directories)
            for name in sorted(files):
                candidate = current_path / name
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                stat_result = candidate.stat()
                entries.append(
                    (
                        candidate.relative_to(root).as_posix(),
                        stat_result.st_size,
                        stat_result.st_mtime_ns,
                    )
                )
        inventory = {"kind": "directory", "path": str(root), "entries": entries}
    return digest_value("mulder.evidence-inventory:v1", inventory)


def _evidence_size(path: Path) -> tuple[int, int, tuple[str, ...]]:
    root = Path(path).expanduser().resolve(strict=True)
    warnings: list[str] = []
    if root.is_file():
        if zipfile.is_zipfile(root):
            try:
                with zipfile.ZipFile(root) as archive:
                    members = [item for item in archive.infolist() if not item.is_dir()]
                return len(members), sum(item.file_size for item in members), ()
            except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                warnings.append(f"archive inventory could not be read: {exc}")
        return 1, root.stat().st_size, tuple(warnings)
    count = 0
    total = 0
    def walk_error(exc: OSError) -> None:
        warnings.append(f"unreadable directory excluded: {exc.filename or root}")

    for current, directories, files in os.walk(
        root,
        followlinks=False,
        onerror=walk_error,
    ):
        current_path = Path(current)
        for name in directories:
            if (current_path / name).is_symlink():
                warnings.append(f"symlink directory excluded: {(current_path / name).name}")
        for name in files:
            candidate = current_path / name
            if candidate.is_symlink():
                warnings.append(f"symlink file excluded: {candidate.name}")
                continue
            try:
                total += candidate.stat().st_size
                count += 1
            except OSError:
                warnings.append(f"unreadable entry excluded: {candidate.name}")
    return count, total, tuple(sorted(set(warnings)))


def _disk_probe_path(planned_path: Path) -> tuple[Path, str | None]:
    """Resolve a planned output directory to an existing filesystem anchor.

    Forecasting is read-only, so a destination that does not exist is measured
    on its nearest existing directory ancestor and reported as an assumption.
    """
    planned = Path(planned_path).expanduser().resolve(strict=False)
    if planned.exists():
        if not planned.is_dir():
            raise RunStateError(f"working path is not a directory: {planned}")
        return planned, None
    probe = planned
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    if not probe.is_dir():
        raise RunStateError(
            f"working path has a non-directory ancestor: {planned} (blocked by {probe})"
        )
    return (
        probe,
        f"planned working path {planned} does not exist; "
        f"disk capacity measured on ancestor {probe}",
    )


def forecast_health(
    evidence_path: Path,
    profile: RunProfile,
    *,
    working_paths: Sequence[Path] = (),
    free_disk_bytes: int | None = None,
    available_memory_bytes: int | None = None,
) -> HealthForecast:
    """Forecast disk/memory/time bounds before starting a run."""
    if profile not in PROFILES:
        raise RunStateError(f"unsupported run profile: {profile!r}")
    files, size, scan_warnings = _evidence_size(evidence_path)
    capacity_warnings: list[str] = []
    if free_disk_bytes is None:
        if working_paths:
            probes = tuple(_disk_probe_path(item) for item in working_paths)
            disk_paths = tuple(probe for probe, _warning in probes)
            capacity_warnings.extend(
                warning for _probe, warning in probes if warning is not None
            )
        else:
            # Direct API callers retain the historical evidence-volume fallback.
            disk_paths = (Path(evidence_path).expanduser().resolve(strict=True),)
        free_disk = min(shutil.disk_usage(item).free for item in disk_paths)
    else:
        free_disk = free_disk_bytes
    if available_memory_bytes is None:
        try:
            import psutil

            available_memory = int(psutil.virtual_memory().available)
        except ImportError:
            available_memory = 0
    else:
        available_memory = available_memory_bytes
    multiplier = 0.45 if profile == "quick" else 1.5
    required = max(256 << 20, int(size * multiplier))
    warnings = [*scan_warnings, *capacity_warnings]
    if free_disk < required:
        warnings.append("insufficient free disk for the conservative working-set estimate")
    if not available_memory:
        warnings.append("available memory could not be determined")
    elif available_memory < 512 << 20:
        warnings.append("less than 512 MiB memory is currently available")
    mib = max(1, size // (1 << 20))
    low = max(1, mib // (900 if profile == "quick" else 450))
    high = max(low + 1, low * (3 if profile == "quick" else 5))
    return HealthForecast(
        profile=profile,
        evidence_files=files,
        evidence_bytes=size,
        required_working_bytes=required,
        free_disk_bytes=max(0, free_disk),
        available_memory_bytes=max(0, available_memory),
        estimated_minutes_low=low,
        estimated_minutes_high=high,
        ready=(
            free_disk >= required
            and available_memory >= 512 << 20
            and not any("unreadable" in item for item in warnings)
        ),
        warnings=tuple(warnings),
    )


def _result_mapping(result: PhaseResult) -> dict[str, object]:
    gate: object = result.gate_result
    if is_dataclass(gate) and not isinstance(gate, type):
        gate = asdict(gate)
    elif not isinstance(gate, (dict, list, str, int, float, bool, type(None))):
        gate = str(gate)
    return {
        "phase_name": result.phase_name,
        "success": result.success,
        "messages": list(result.messages),
        "tool_names": list(result.tool_names),
        "turns_used": result.turns_used,
        "session_id": result.session_id,
        "gate_result": gate,
        "plans_executed": result.plans_executed,
        "follow_ups_used": result.follow_ups_used,
        "context_exhausted": result.context_exhausted,
        "batch_ids": sorted(result.batch_ids),
    }


def _phase_result(raw: Mapping[str, object]) -> PhaseResult:
    def strings(name: str) -> list[str]:
        value = raw.get(name, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise RunStateError(f"checkpoint {name} is invalid")
        return cast(list[str], value)

    phase_name = raw.get("phase_name")
    if not isinstance(phase_name, str):
        raise RunStateError("checkpoint phase_name is invalid")

    def integer(name: str) -> int:
        value = raw.get(name, 0)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise RunStateError(f"checkpoint {name} is invalid")
        return value

    return PhaseResult(
        phase_name=phase_name,
        success=raw.get("success") is True,
        messages=strings("messages"),
        tool_names=strings("tool_names"),
        turns_used=integer("turns_used"),
        session_id=str(raw.get("session_id", "")),
        gate_result=raw.get("gate_result"),
        plans_executed=integer("plans_executed"),
        follow_ups_used=integer("follow_ups_used"),
        context_exhausted=raw.get("context_exhausted") is True,
        batch_ids=set(strings("batch_ids")),
    )


@contextmanager
def _ledger_file_lock(
    path: Path,
    *,
    exclusive: bool,
    nonblocking: bool = False,
) -> Iterator[IO[bytes]]:
    """Hold an advisory process lock on an existing run ledger."""
    ledger_path = Path(path).expanduser().resolve(strict=False)
    try:
        handle = ledger_path.open("rb")
    except OSError as exc:
        raise RunStateError(f"run ledger is unavailable: {ledger_path}: {exc}") from exc
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    if nonblocking:
        operation |= fcntl.LOCK_NB
    try:
        try:
            fcntl.flock(handle.fileno(), operation)
        except BlockingIOError as exc:
            raise RunStateError(
                "run has active tool invocations; retry resume after they finish"
            ) from exc
        yield handle
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _assert_active_lease_row(
    case_id: str,
    ledger_path: Path,
    run_id: str,
    generation: int,
) -> None:
    """Validate one active generation without mutating or migrating the ledger."""
    if generation < 1:
        raise RunStateError("run generation must be positive")
    try:
        with sqlite3.connect(ledger_path, timeout=30) as connection:
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute(
                "SELECT case_id,status,cancel_requested,generation FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
    except sqlite3.DatabaseError as exc:
        raise RunStateError(f"run ledger is invalid: {exc}") from exc
    if row is None or row[0] != case_id:
        raise RunStateError(f"run handle not found for case: {run_id}")
    if row[3] != generation:
        raise RunStateError("run lease was superseded by another process")
    if row[2] or row[1] in {"cancel_requested", "cancelled"}:
        raise RunCancelled(f"run cancellation requested: {run_id}")
    if row[1] != "running":
        raise RunStateError(f"run is not active: {row[1]}")


@contextmanager
def hold_active_run_lease(
    case_id: str,
    ledger_path: Path,
    run_id: str,
    generation: int,
) -> Iterator[None]:
    """Fence one MCP tool invocation against concurrent run takeover.

    A resumer must acquire an exclusive lock before incrementing the
    generation.  Tool calls hold a shared lock from the final generation check
    through the complete invocation, so a takeover can never pass an in-flight
    write boundary.
    """
    if not case_id or Path(case_id).name != case_id or case_id in {".", ".."}:
        raise RunStateError("case_id must be one safe path segment")
    if not run_id or Path(run_id).name != run_id or run_id in {".", ".."}:
        raise RunStateError("run_id must be one safe path segment")
    resolved = Path(ledger_path).expanduser().resolve(strict=False)
    with _ledger_file_lock(resolved, exclusive=False):
        _assert_active_lease_row(case_id, resolved, run_id, generation)
        yield


@contextmanager
def hold_run_ledger_snapshot(ledger_path: Path) -> Iterator[None]:
    """Prevent Mulder run-ledger and summary mutations during case publication."""
    resolved = Path(ledger_path).expanduser().resolve(strict=False)
    with _ledger_file_lock(resolved, exclusive=True):
        yield


class RunLedger:
    """Own durable run identity, cooperative cancellation, and checkpoints."""

    def __init__(self, case_id: str, path: Path, audit_path: Path) -> None:
        if not case_id or Path(case_id).name != case_id or case_id in {".", ".."}:
            raise RunStateError("case_id must be one safe path segment")
        self.case_id = case_id
        self.path = Path(path).expanduser().resolve(strict=False)
        self.audit_path = Path(audit_path).expanduser().resolve(strict=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect(configure_journal=True) as connection:
            connection.executescript(_SCHEMA)

    def _connect(self, *, configure_journal: bool = False) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        if configure_journal:
            connection.execute("PRAGMA journal_mode=DELETE")
        return connection

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        run_id: str,
        kind: str,
        actor: str,
        detail: Mapping[str, object],
    ) -> None:
        connection.execute(
            "INSERT INTO run_events(event_id,run_id,kind,actor,detail,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                f"run-event-{uuid4().hex}",
                run_id,
                kind,
                actor,
                _canonical_json(dict(detail)).decode("utf-8"),
                _now(),
            ),
        )

    def open_run(
        self,
        *,
        profile: RunProfile,
        input_digest: str,
        contract_digest: str | None = None,
        approval_required: bool = False,
        allow_awaiting_review_resume: bool = False,
        run_id: str | None = None,
        resume: bool = False,
    ) -> RunHandle:
        """Create a run or resume the exact existing input/profile."""
        spec = PROFILES.get(profile)
        if spec is None:
            raise RunStateError(f"unsupported run profile: {profile!r}")
        selected_id = run_id or f"run-{uuid4().hex}"
        selected_contract = contract_digest or digest_value(
            "mulder.run-contract:v1",
            {"profile": profile, "input_digest": input_digest},
        )
        if Path(selected_id).name != selected_id or selected_id in {"", ".", ".."}:
            raise RunStateError("run_id must be one safe path segment")
        now = _now()
        takeover_guard = (
            _ledger_file_lock(self.path, exclusive=True, nonblocking=True)
            if resume
            else _ledger_file_lock(self.path, exclusive=False)
        )
        with takeover_guard:  # noqa: SIM117 - lock must outlive SQLite commit
            with self._connect() as connection:  # noqa: SIM117
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM runs WHERE run_id=?", (selected_id,)
                ).fetchone()
                if row is None:
                    if resume:
                        raise RunStateError(f"run handle not found: {selected_id}")
                    connection.execute(
                        "INSERT INTO runs(run_id,case_id,profile,coverage_ceiling,input_digest,"
                        "contract_digest,approval_required,generation,status,cancel_requested,"
                        "created_at,updated_at) VALUES(?,?,?,?,?,?,?,1,'running',0,?,?)",
                        (
                            selected_id,
                            self.case_id,
                            profile,
                            spec.coverage_ceiling,
                            input_digest,
                            selected_contract,
                            int(approval_required),
                            now,
                            now,
                        ),
                    )
                    self._event(connection, selected_id, "created", "orchestrator", {})
                else:
                    if not resume:
                        raise RunStateError(f"run handle already exists: {selected_id}")
                    if (
                        row["case_id"] != self.case_id
                        or row["profile"] != profile
                        or row["input_digest"] != input_digest
                        or row["contract_digest"] != selected_contract
                        or bool(row["approval_required"]) != approval_required
                    ):
                        raise RunStateError(
                            "resume handle does not bind this case, profile, input, "
                            "and run contract"
                        )
                    if row["cancel_requested"]:
                        raise RunCancelled("run was cancelled before resume")
                    status = cast(str, row["status"])
                    if status == "awaiting_review":
                        if not approval_required or not allow_awaiting_review_resume:
                            raise RunStateError(
                                "awaiting-review run requires an explicit approved-report resume"
                            )
                    elif status != "running":
                        raise RunStateError(f"{status} run cannot be resumed")
                    connection.execute(
                        "UPDATE runs SET status='running',generation=generation+1,updated_at=? "
                        "WHERE run_id=?",
                        (now, selected_id),
                    )
                    self._event(connection, selected_id, "resumed", "orchestrator", {})
        return self.status(selected_id)

    def status(self, run_id: str) -> RunHandle:
        """Read a run handle and its ordered, audit-verified completed steps."""
        with self._connect() as connection:
            connection.execute("BEGIN")
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None or row["case_id"] != self.case_id:
                raise RunStateError(f"run handle not found for case: {run_id}")
            completed_rows = connection.execute(
                "SELECT * FROM phase_attempts WHERE run_id=? AND status='completed' "
                "ORDER BY rowid",
                (run_id,),
            ).fetchall()
        ordered_steps: list[str] = []
        for completed_row in completed_rows:
            self._validated_checkpoint_result(completed_row)
            step_key = cast(str, completed_row["step_key"])
            if step_key not in ordered_steps:
                ordered_steps.append(step_key)
        steps = tuple(ordered_steps)
        return RunHandle(
            run_id=row["run_id"],
            case_id=row["case_id"],
            profile=cast(RunProfile, row["profile"]),
            coverage_ceiling=row["coverage_ceiling"],
            input_digest=row["input_digest"],
            contract_digest=row["contract_digest"],
            approval_required=bool(row["approval_required"]),
            generation=row["generation"],
            status=row["status"],
            cancel_requested=bool(row["cancel_requested"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            completed_steps=steps,
        )

    def request_cancel(self, run_id: str, *, requested_by: str) -> RunHandle:
        """Persist a cooperative cancellation request; never kill a process."""
        if not requested_by.strip():
            raise RunStateError("requested_by is required")
        with _ledger_file_lock(self.path, exclusive=False):
            return self._request_cancel_unlocked(run_id, requested_by=requested_by)

    def _request_cancel_unlocked(self, run_id: str, *, requested_by: str) -> RunHandle:
        """Persist cancellation while the caller holds the publication guard."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT case_id,status,cancel_requested FROM runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if row is None or row["case_id"] != self.case_id:
                raise RunStateError(f"run handle not found for case: {run_id}")
            if row["status"] not in {"running", "cancel_requested"}:
                raise RunStateError(f"{row['status']} run cannot be cancelled")
            if not row["cancel_requested"]:
                connection.execute(
                    "UPDATE runs SET status='cancel_requested',cancel_requested=1,updated_at=? "
                    "WHERE run_id=?",
                    (_now(), run_id),
                )
                self._event(connection, run_id, "cancel_requested", requested_by.strip(), {})
        return self.status(run_id)

    def assert_active(self, run_id: str, *, generation: int) -> None:
        """Raise at a safe cooperative boundary when cancellation was requested."""
        handle = self.status(run_id)
        if handle.generation != generation:
            raise RunStateError("run lease was superseded by another process")
        if handle.cancel_requested or handle.status in {"cancel_requested", "cancelled"}:
            raise RunCancelled(f"run cancellation requested: {run_id}")
        if handle.status != "running":
            raise RunStateError(f"run is not active: {handle.status}")

    def _verified_head(self) -> str:
        integrity = AuditLog(self.audit_path).verify_integrity()
        if not integrity.ok or not integrity.cryptographically_verified or not integrity.head_hash:
            raise RunStateError("checkpoint requires a verified non-empty native audit chain")
        return integrity.head_hash

    def _checkpoint_event_matches(
        self,
        digest: str,
        expected: Mapping[str, object],
    ) -> bool:
        """Verify an exact semantic checkpoint envelope in the native audit chain."""
        integrity, entries = AuditLog(self.audit_path).read_verified_snapshot()
        if not integrity.ok or not integrity.cryptographically_verified:
            return False
        prior_hashes: set[str] = set()
        event: Mapping[str, object] | None = None
        for raw in entries:
            entry_hash = raw.get("entry_hash")
            if entry_hash == digest:
                event = raw
                break
            if isinstance(entry_hash, str):
                prior_hashes.add(entry_hash)
        if event is None:
            return False
        phase_start = event.get("phase_start_audit_head")
        result_parent = event.get("result_parent_audit_head")
        return (
            all(event.get(key) == value for key, value in expected.items())
            and isinstance(phase_start, str)
            and phase_start in prior_hashes
            and isinstance(result_parent, str)
            and result_parent in prior_hashes
            and event.get("previous_hash") == result_parent
        )

    def _validated_checkpoint_result(self, row: sqlite3.Row) -> PhaseResult:
        """Validate the audit/ledger conjunction for one completed attempt."""
        if row["status"] != "completed":
            raise RunStateError(f"phase attempt is not completed: {row['attempt_id']}")
        try:
            result = json.loads(row["result_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise RunStateError(
                f"checkpoint result is invalid: {row['step_key']}"
            ) from exc
        if not isinstance(result, dict):
            raise RunStateError(f"checkpoint result is not an object: {row['step_key']}")
        result_digest = digest_value("mulder.phase-result:v1", result)
        checkpoint_hash = row["checkpoint_event_hash"]
        if (
            row["result_digest"] != result_digest
            or not isinstance(checkpoint_hash, str)
            or row["audit_head_after"] != checkpoint_hash
            or not self._checkpoint_event_matches(
                checkpoint_hash,
                {
                    "type": "run_checkpoint",
                    "checkpoint_state": "proposed",
                    "case_id": self.case_id,
                    "checkpoint_schema": "mulder.run-checkpoint",
                    "checkpoint_version": RUN_CHECKPOINT_VERSION,
                    "attempt_id": row["attempt_id"],
                    "attempt_number": row["attempt_number"],
                    "run_id": row["run_id"],
                    "step_key": row["step_key"],
                    "phase_name": row["phase_name"],
                    "input_digest": row["input_digest"],
                    "result_digest": result_digest,
                    "phase_start_audit_head": row["audit_head_before"],
                    "run_generation": row["run_generation"],
                },
            )
        ):
            raise RunStateError(
                f"checkpoint audit envelope is absent or invalid: {row['step_key']}"
            )
        return _phase_result(cast(Mapping[str, object], result))

    def resume_phase(
        self,
        run_id: str,
        *,
        generation: int,
        step_key: str,
        input_digest: str,
    ) -> PhaseResult | None:
        """Return the last exact completed result when its audit head remains valid."""
        self.assert_active(run_id, generation=generation)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM phase_attempts WHERE run_id=? AND step_key=? "
                "ORDER BY attempt_number DESC LIMIT 1",
                (run_id, step_key),
            ).fetchone()
        if row is None or row["status"] != "completed" or row["input_digest"] != input_digest:
            return None
        return self._validated_checkpoint_result(row)

    def begin_phase(
        self,
        run_id: str,
        *,
        generation: int,
        step_key: str,
        phase_name: str,
        input_digest: str,
    ) -> str:
        """Open a new attempt after marking abandoned running attempts interrupted."""
        with _ledger_file_lock(self.path, exclusive=False):
            return self._begin_phase_unlocked(
                run_id,
                generation=generation,
                step_key=step_key,
                phase_name=phase_name,
                input_digest=input_digest,
            )

    def _begin_phase_unlocked(
        self,
        run_id: str,
        *,
        generation: int,
        step_key: str,
        phase_name: str,
        input_digest: str,
    ) -> str:
        """Open an attempt while the caller holds the publication guard."""
        audit_head = self._verified_head()
        attempt_id = f"attempt-{uuid4().hex}"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = connection.execute(
                "SELECT case_id,status,cancel_requested,generation FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if run is None or run["case_id"] != self.case_id:
                raise RunStateError(f"run handle not found for case: {run_id}")
            if run["cancel_requested"] or run["status"] == "cancel_requested":
                raise RunCancelled(f"run cancellation requested: {run_id}")
            if run["generation"] != generation:
                raise RunStateError("run lease was superseded by another process")
            if run["status"] != "running":
                raise RunStateError(f"run is not active: {run['status']}")
            connection.execute(
                "UPDATE phase_attempts SET status='interrupted',completed_at=? "
                "WHERE run_id=? AND step_key=? AND status='running'",
                (_now(), run_id, step_key),
            )
            number = int(
                connection.execute(
                    "SELECT COALESCE(MAX(attempt_number),0)+1 FROM phase_attempts "
                    "WHERE run_id=? AND step_key=?",
                    (run_id, step_key),
                ).fetchone()[0]
            )
            connection.execute(
                "INSERT INTO phase_attempts(attempt_id,run_id,step_key,phase_name,"
                "attempt_number,run_generation,input_digest,audit_head_before,status,started_at) "
                "VALUES(?,?,?,?,?,?,?,?,'running',?)",
                (
                    attempt_id,
                    run_id,
                    step_key,
                    phase_name,
                    number,
                    generation,
                    input_digest,
                    audit_head,
                    _now(),
                ),
            )
            self._event(
                connection,
                run_id,
                "phase_started",
                "orchestrator",
                {"attempt_id": attempt_id, "step_key": step_key},
            )
        return attempt_id

    def complete_phase(
        self,
        attempt_id: str,
        result: PhaseResult,
        *,
        generation: int,
    ) -> PhaseCheckpoint:
        """Checkpoint only after every leased tool-side effect has ended."""
        with _ledger_file_lock(
            self.path,
            exclusive=True,
            nonblocking=True,
        ):
            return self._complete_phase_unlocked(
                attempt_id,
                result,
                generation=generation,
            )

    def _complete_phase_unlocked(
        self,
        attempt_id: str,
        result: PhaseResult,
        *,
        generation: int,
    ) -> PhaseCheckpoint:
        """Commit a successful result through an audit-proposal/ledger conjunction."""
        if not result.success:
            raise RunStateError("only a successful phase result may become a checkpoint")
        result_json = _canonical_json(_result_mapping(result)).decode("utf-8")
        result_mapping = cast(dict[str, object], json.loads(result_json))
        result_digest = digest_value("mulder.phase-result:v1", result_mapping)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT p.*,r.case_id,r.status AS run_status,r.cancel_requested,"
                "r.generation AS current_generation "
                "FROM phase_attempts p JOIN runs r ON r.run_id=p.run_id "
                "WHERE p.attempt_id=?",
                (attempt_id,),
            ).fetchone()
        if row is None or row["status"] != "running":
            raise RunStateError(f"running phase attempt not found: {attempt_id}")
        if row["case_id"] != self.case_id:
            raise RunStateError("phase attempt belongs to another case")
        if row["phase_name"] != result.phase_name:
            raise RunStateError("phase result does not match its running attempt")
        if row["cancel_requested"] or row["run_status"] == "cancel_requested":
            raise RunCancelled(f"run cancellation requested: {row['run_id']}")
        if row["run_generation"] != generation or row["current_generation"] != generation:
            raise RunStateError("run lease was superseded by another process")
        if row["run_status"] != "running":
            raise RunStateError(f"run is not active: {row['run_status']}")
        event = AuditLog(self.audit_path).log_checkpoint_event(
            self.case_id,
            {
                "checkpoint_schema": "mulder.run-checkpoint",
                "checkpoint_version": RUN_CHECKPOINT_VERSION,
                "attempt_id": attempt_id,
                "attempt_number": row["attempt_number"],
                "run_id": row["run_id"],
                "step_key": row["step_key"],
                "phase_name": row["phase_name"],
                "input_digest": row["input_digest"],
                "result_digest": result_digest,
                "phase_start_audit_head": row["audit_head_before"],
                "run_generation": generation,
            },
        )
        checkpoint_hash = event.get("entry_hash")
        if not isinstance(checkpoint_hash, str):
            raise RunStateError("audit checkpoint did not return a native entry hash")
        completed = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT p.*,r.case_id,r.status AS run_status,r.cancel_requested,"
                "r.generation AS current_generation "
                "FROM phase_attempts p JOIN runs r ON r.run_id=p.run_id "
                "WHERE p.attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if row is None or row["status"] != "running":
                raise RunStateError(f"running phase attempt not found: {attempt_id}")
            if row["phase_name"] != result.phase_name:
                raise RunStateError("phase result does not match its running attempt")
            if row["cancel_requested"] or row["run_status"] == "cancel_requested":
                raise RunCancelled(f"run cancellation requested: {row['run_id']}")
            if (
                row["run_generation"] != generation
                or row["current_generation"] != generation
            ):
                raise RunStateError("run lease was superseded by another process")
            if row["run_status"] != "running":
                raise RunStateError(f"run is not active: {row['run_status']}")
            connection.execute(
                "UPDATE phase_attempts SET status='completed',audit_head_after=?,"
                "result_digest=?,checkpoint_event_hash=?,result_json=?,completed_at=? "
                "WHERE attempt_id=?",
                (
                    checkpoint_hash,
                    result_digest,
                    checkpoint_hash,
                    result_json,
                    completed,
                    attempt_id,
                ),
            )
            self._event(
                connection,
                row["run_id"],
                "phase_completed",
                "orchestrator",
                {
                    "attempt_id": attempt_id,
                    "step_key": row["step_key"],
                    "checkpoint_event_hash": checkpoint_hash,
                    "result_digest": result_digest,
                },
            )
        return PhaseCheckpoint(
            attempt_id=attempt_id,
            run_id=row["run_id"],
            step_key=row["step_key"],
            phase_name=row["phase_name"],
            attempt_number=row["attempt_number"],
            run_generation=row["run_generation"],
            input_digest=row["input_digest"],
            audit_head_before=row["audit_head_before"],
            audit_head_after=checkpoint_hash,
            result_digest=result_digest,
            checkpoint_event_hash=checkpoint_hash,
            result=result_mapping,
            started_at=row["started_at"],
            completed_at=completed,
        )

    def finish(
        self,
        run_id: str,
        status: Literal["awaiting_review", "completed", "failed", "cancelled"],
        *,
        generation: int,
    ) -> RunHandle:
        """Persist terminal state only after all leased tool bodies have exited."""
        with _ledger_file_lock(  # noqa: SIM117 - lock covers the nested DB commit
            self.path,
            exclusive=True,
            nonblocking=True,
        ):
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT case_id,status,cancel_requested,generation FROM runs "
                    "WHERE run_id=?",
                    (run_id,),
                ).fetchone()
                if row is None or row["case_id"] != self.case_id:
                    raise RunStateError(f"run handle not found for case: {run_id}")
                if row["generation"] != generation:
                    raise RunStateError("run lease was superseded by another process")
                current = cast(str, row["status"])
                allowed = {
                    "running": {"awaiting_review", "completed", "failed"},
                    "cancel_requested": {"cancelled"},
                }
                if status not in allowed.get(current, set()):
                    raise RunStateError(f"invalid run transition: {current} -> {status}")
                connection.execute(
                    "UPDATE runs SET status=?,updated_at=? WHERE run_id=?",
                    (status, _now(), run_id),
                )
                self._event(connection, run_id, status, "orchestrator", {})
        return self.status(run_id)

    def write_summary(self, run_id: str, output: Path) -> Path:
        """Publish one coherent summary without racing takeover or completion."""
        with _ledger_file_lock(self.path, exclusive=False):
            return self._write_summary_locked(run_id, output)

    def _write_summary_locked(self, run_id: str, output: Path) -> Path:
        """Atomically write a receipt-friendly JSON view of the run handle."""
        handle = self.status(run_id)
        payload = {
            "schema": RUN_STATE_SCHEMA,
            "version": RUN_STATE_VERSION,
            **handle.model_dump(mode="json"),
            "ledger": self.path.name,
        }
        content = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        output = Path(output).expanduser().resolve(strict=False)
        if output.parent != self.path.parent:
            raise RunStateError("run summary must be written beside the run ledger")
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=output.parent, prefix=f".{output.name}.", delete=False
            ) as handle_file:
                temporary = Path(handle_file.name)
                handle_file.write(content)
                handle_file.flush()
                os.fsync(handle_file.fileno())
            os.replace(temporary, output)
        except BaseException:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise
        return output


__all__ = [
    "HealthForecast",
    "PROFILES",
    "PhaseCheckpoint",
    "RUN_CHECKPOINT_VERSION",
    "RUN_STATE_SCHEMA",
    "RUN_STATE_VERSION",
    "RunCancelled",
    "RunHandle",
    "RunLedger",
    "RunProfile",
    "RunProfileSpec",
    "RunStateError",
    "digest_value",
    "evidence_identity",
    "forecast_health",
    "hold_active_run_lease",
    "hold_run_ledger_snapshot",
]
