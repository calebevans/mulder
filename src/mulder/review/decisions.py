"""Append-only analyst review and state-bound approval workflow.

The case database remains authoritative. Review actions are immutable events;
approval is valid only for the exact claim/evidence snapshot reviewed and an
audit-chain head that is still present in the current verified chain.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from mulder.audit import AuditLog

ReviewEventKind = Literal["accept", "reject", "comment", "follow_up"]
ApprovalDecisionKind = Literal["approve", "reject"]
ApprovalState = Literal["not_requested", "awaiting_review", "approved", "rejected", "stale"]


class ReviewWorkflowError(ValueError):
    """Raised when review state is invalid, stale, or unavailable."""


@dataclass(frozen=True)
class ReviewEvent:
    sequence: int
    event_id: str
    case_id: str
    kind: ReviewEventKind
    subject_type: str
    subject_id: str
    reviewer: str
    comment: str
    created_at: str


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    case_id: str
    claim_set_digest: str
    audit_head_digest: str
    requested_by: str
    created_at: str


@dataclass(frozen=True)
class ApprovalDecision:
    decision_id: str
    request_id: str
    decision: ApprovalDecisionKind
    reviewer: str
    comment: str
    claim_set_digest: str
    audit_head_digest: str
    created_at: str


@dataclass(frozen=True)
class ApprovalStatus:
    state: ApprovalState
    claim_set_digest: str
    audit_head_digest: str
    request: ApprovalRequest | None = None
    decision: ApprovalDecision | None = None
    reason: str = ""

    def as_mapping(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible view for CLIs and receipts."""
        return {
            "state": self.state,
            "claim_set_digest": self.claim_set_digest,
            "audit_head_digest": self.audit_head_digest,
            "request": asdict(self.request) if self.request is not None else None,
            "decision": asdict(self.decision) if self.decision is not None else None,
            "reason": self.reason,
        }


_SCHEMA = """
CREATE TABLE IF NOT EXISTS review_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('accept','reject','comment','follow_up')),
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    comment TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_review_events_case_sequence
    ON review_events(case_id, sequence);
CREATE TABLE IF NOT EXISTS approval_requests (
    request_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    claim_set_digest TEXT NOT NULL,
    audit_head_digest TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_approval_requests_case_created
    ON approval_requests(case_id, created_at, request_id);
CREATE TABLE IF NOT EXISTS approval_decisions (
    decision_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES approval_requests(request_id),
    decision TEXT NOT NULL CHECK (decision IN ('approve','reject')),
    reviewer TEXT NOT NULL,
    comment TEXT NOT NULL,
    claim_set_digest TEXT NOT NULL,
    audit_head_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS review_events_no_update
    BEFORE UPDATE ON review_events BEGIN SELECT RAISE(ABORT, 'review events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS review_events_no_delete
    BEFORE DELETE ON review_events BEGIN SELECT RAISE(ABORT, 'review events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS approval_requests_no_update
    BEFORE UPDATE ON approval_requests BEGIN
    SELECT RAISE(ABORT, 'approval requests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS approval_requests_no_delete
    BEFORE DELETE ON approval_requests BEGIN
    SELECT RAISE(ABORT, 'approval requests are append-only'); END;
CREATE TRIGGER IF NOT EXISTS approval_decisions_no_update
    BEFORE UPDATE ON approval_decisions BEGIN
    SELECT RAISE(ABORT, 'approval decisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS approval_decisions_no_delete
    BEFORE DELETE ON approval_decisions BEGIN
    SELECT RAISE(ABORT, 'approval decisions are append-only'); END;
"""


def _canonical_digest(domain: bytes, payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(domain + b"\0" + encoded).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _commit_and_checkpoint(connection: sqlite3.Connection) -> None:
    """Commit review state and remove WAL bytes before receipt snapshots."""
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")


class ReviewWorkflow:
    """Own schema, events, snapshot commitments, and approval validation."""

    def __init__(self, case_id: str, db_dir: Path) -> None:
        if not case_id or Path(case_id).name != case_id:
            raise ReviewWorkflowError("case_id must be one non-empty path segment")
        self.case_id = case_id
        self.db_dir = Path(db_dir).expanduser().resolve(strict=False)
        self.db_path = self.db_dir / f"{case_id}.db"
        self.audit_path = self.db_dir / f"{case_id}.audit.jsonl"
        if not self.db_path.is_file():
            raise ReviewWorkflowError(f"Case database not found: {self.db_path}")
        if not self.audit_path.is_file():
            raise ReviewWorkflowError(f"Case audit log not found: {self.audit_path}")

    def initialize(self) -> None:
        """Create additive review tables and immutable-row triggers."""
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            row = connection.execute(
                "SELECT 1 FROM case_metadata WHERE case_id = ?", (self.case_id,)
            ).fetchone()
            if row is None:
                raise ReviewWorkflowError(f"Case {self.case_id!r} is not in the database")
            connection.executescript(_SCHEMA)
            _commit_and_checkpoint(connection)

    def append_event(
        self,
        kind: ReviewEventKind,
        *,
        subject_type: str,
        subject_id: str,
        reviewer: str,
        comment: str = "",
    ) -> ReviewEvent:
        """Append one accept/reject/comment/follow-up event."""
        if kind not in {"accept", "reject", "comment", "follow_up"}:
            raise ReviewWorkflowError(f"Unsupported review event kind: {kind!r}")
        values = {
            "event_id": f"review-{uuid4().hex}",
            "case_id": self.case_id,
            "kind": kind,
            "subject_type": subject_type.strip(),
            "subject_id": subject_id.strip(),
            "reviewer": reviewer.strip(),
            "comment": comment,
            "created_at": _now(),
        }
        if not values["subject_type"] or not values["subject_id"] or not values["reviewer"]:
            raise ReviewWorkflowError("subject_type, subject_id, and reviewer are required")
        self.initialize()
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.execute(
                "INSERT INTO review_events "
                "(event_id,case_id,kind,subject_type,subject_id,reviewer,comment,created_at) "
                "VALUES (:event_id,:case_id,:kind,:subject_type,:subject_id,"
                ":reviewer,:comment,:created_at)",
                values,
            )
            sequence = cursor.lastrowid
            _commit_and_checkpoint(connection)
        if sequence is None:
            raise ReviewWorkflowError("SQLite did not return a review event sequence")
        return ReviewEvent(sequence=int(sequence), **values)  # type: ignore[arg-type]

    def events(self, *, after_sequence: int = 0, limit: int = 200) -> tuple[ReviewEvent, ...]:
        """Read a stable bounded event page for restart/replay consumers."""
        if after_sequence < 0 or limit < 1 or limit > 1000:
            raise ReviewWorkflowError("after_sequence must be >= 0 and limit must be 1..1000")
        if not self._has_table("review_events"):
            return ()
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT sequence,event_id,case_id,kind,subject_type,subject_id,"
                "reviewer,comment,created_at "
                "FROM review_events WHERE case_id=? AND sequence>? ORDER BY sequence LIMIT ?",
                (self.case_id, after_sequence, limit),
            ).fetchall()
        return tuple(ReviewEvent(**dict(row)) for row in rows)

    def snapshot_digests(self) -> tuple[str, str]:
        """Commit active findings/claims/anchors/verifications and audit head."""
        for suffix in ("-wal", "-journal"):
            sidecar = Path(str(self.db_path) + suffix)
            if sidecar.is_file() and sidecar.stat().st_size:
                raise ReviewWorkflowError(
                    f"Approval requires a quiescent database ({sidecar.name} is non-empty)"
                )
        claim_digest = self._claim_set_digest()
        integrity = AuditLog(self.audit_path).verify_integrity()
        if (
            not integrity.ok
            or not integrity.cryptographically_verified
            or integrity.head_hash is None
        ):
            raise ReviewWorkflowError(
                "Approval requires a cryptographically verified non-empty audit chain"
            )
        return claim_digest, integrity.head_hash

    def request_approval(self, *, requested_by: str) -> ApprovalRequest:
        """Create or return the request for the exact current case snapshot."""
        if not requested_by.strip():
            raise ReviewWorkflowError("requested_by is required")
        self.initialize()
        claim_digest, audit_head = self.snapshot_digests()
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            existing = connection.execute(
                "SELECT r.*,d.decision FROM approval_requests r "
                "LEFT JOIN approval_decisions d ON d.request_id=r.request_id "
                "WHERE r.case_id=? AND r.claim_set_digest=? AND r.audit_head_digest=? "
                "ORDER BY r.created_at DESC,r.request_id DESC LIMIT 1",
                (self.case_id, claim_digest, audit_head),
            ).fetchone()
            if existing is not None:
                if existing["decision"] == "reject":
                    raise ReviewWorkflowError(
                        "Rejected case state must change before requesting review again"
                    )
                return ApprovalRequest(
                    request_id=existing["request_id"],
                    case_id=existing["case_id"],
                    claim_set_digest=existing["claim_set_digest"],
                    audit_head_digest=existing["audit_head_digest"],
                    requested_by=existing["requested_by"],
                    created_at=existing["created_at"],
                )
            request = ApprovalRequest(
                request_id=f"approval-request-{uuid4().hex}",
                case_id=self.case_id,
                claim_set_digest=claim_digest,
                audit_head_digest=audit_head,
                requested_by=requested_by.strip(),
                created_at=_now(),
            )
            connection.execute(
                "INSERT INTO approval_requests "
                "(request_id,case_id,claim_set_digest,audit_head_digest,requested_by,created_at) "
                "VALUES (:request_id,:case_id,:claim_set_digest,:audit_head_digest,"
                ":requested_by,:created_at)",
                asdict(request),
            )
            _commit_and_checkpoint(connection)
        return request

    def decide(
        self,
        request_id: str,
        decision: ApprovalDecisionKind,
        *,
        reviewer: str,
        comment: str = "",
    ) -> ApprovalDecision:
        """Append one state-bound approve/reject decision."""
        if decision not in {"approve", "reject"}:
            raise ReviewWorkflowError(f"Unsupported approval decision: {decision!r}")
        if not reviewer.strip():
            raise ReviewWorkflowError("reviewer is required")
        self.initialize()
        claim_digest, audit_head = self.snapshot_digests()
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            raw = connection.execute(
                "SELECT * FROM approval_requests WHERE request_id=? AND case_id=?",
                (request_id, self.case_id),
            ).fetchone()
            if raw is None:
                raise ReviewWorkflowError(f"Approval request not found: {request_id}")
            request = ApprovalRequest(**dict(raw))
            if request.claim_set_digest != claim_digest or request.audit_head_digest != audit_head:
                raise ReviewWorkflowError(
                    "Approval request is stale: claims or audit head changed after review"
                )
            result = ApprovalDecision(
                decision_id=f"approval-decision-{uuid4().hex}",
                request_id=request.request_id,
                decision=decision,
                reviewer=reviewer.strip(),
                comment=comment,
                claim_set_digest=claim_digest,
                audit_head_digest=audit_head,
                created_at=_now(),
            )
            try:
                connection.execute(
                    "INSERT INTO approval_decisions "
                    "(decision_id,request_id,decision,reviewer,comment,claim_set_digest,"
                    "audit_head_digest,created_at) VALUES (:decision_id,:request_id,"
                    ":decision,:reviewer,:comment,:claim_set_digest,"
                    ":audit_head_digest,:created_at)",
                    asdict(result),
                )
                _commit_and_checkpoint(connection)
            except sqlite3.IntegrityError as exc:
                raise ReviewWorkflowError("Approval request already has a decision") from exc
        return result

    def status(self) -> ApprovalStatus:
        """Return conservative current approval state without mutating rows."""
        claim_digest, audit_head = self.snapshot_digests()
        if not self._has_table("approval_requests"):
            return ApprovalStatus("not_requested", claim_digest, audit_head)
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT r.*,d.decision_id,d.decision,d.reviewer,d.comment,"
                "d.created_at AS decision_created_at,d.claim_set_digest AS decision_claim_digest,"
                "d.audit_head_digest AS decision_audit_head "
                "FROM approval_requests r LEFT JOIN approval_decisions d "
                "ON d.request_id=r.request_id "
                "WHERE r.case_id=? ORDER BY r.created_at DESC,r.request_id DESC LIMIT 1",
                (self.case_id,),
            ).fetchone()
        if row is None:
            return ApprovalStatus("not_requested", claim_digest, audit_head)
        request = ApprovalRequest(
            request_id=row["request_id"],
            case_id=row["case_id"],
            claim_set_digest=row["claim_set_digest"],
            audit_head_digest=row["audit_head_digest"],
            requested_by=row["requested_by"],
            created_at=row["created_at"],
        )
        decision = (
            ApprovalDecision(
                decision_id=row["decision_id"],
                request_id=row["request_id"],
                decision=row["decision"],
                reviewer=row["reviewer"],
                comment=row["comment"],
                claim_set_digest=row["decision_claim_digest"],
                audit_head_digest=row["decision_audit_head"],
                created_at=row["decision_created_at"],
            )
            if row["decision_id"] is not None
            else None
        )
        if request.claim_set_digest != claim_digest:
            return ApprovalStatus(
                "stale", claim_digest, audit_head, request, decision, "claim_set_changed"
            )
        if not self._audit_contains(request.audit_head_digest):
            return ApprovalStatus(
                "stale", claim_digest, audit_head, request, decision, "approved_audit_head_absent"
            )
        if decision is None:
            return ApprovalStatus("awaiting_review", claim_digest, audit_head, request)
        state: ApprovalState = "approved" if decision.decision == "approve" else "rejected"
        return ApprovalStatus(state, claim_digest, audit_head, request, decision)

    def require_approved_state(self) -> ApprovalStatus:
        """Return a current approval or raise with an actionable state."""
        status = self.status()
        if status.state != "approved":
            raise ReviewWorkflowError(f"Case is not approved for this state: {status.state}")
        return status

    def _claim_set_digest(self) -> str:
        with sqlite3.connect(
            f"file:{self.db_path}?mode=ro&immutable=1", uri=True
        ) as connection:
            connection.row_factory = sqlite3.Row
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "claims" not in tables or "evidence_anchors" not in tables:
                raise ReviewWorkflowError("Approval requires native atomic claims and anchors")
            payload: dict[str, object] = {}
            queries = {
                "findings": (
                    "SELECT * FROM findings WHERE case_id=? AND COALESCE(is_deleted,0)=0 "
                    "ORDER BY finding_id",
                    (self.case_id,),
                ),
                "claims": (
                    "SELECT c.* FROM claims c JOIN findings f ON f.finding_id=c.finding_id "
                    "WHERE f.case_id=? AND COALESCE(f.is_deleted,0)=0 "
                    "ORDER BY c.finding_id,c.ordinal,c.claim_id",
                    (self.case_id,),
                ),
                "anchors": (
                    "SELECT a.* FROM evidence_anchors a JOIN claims c ON c.claim_id=a.claim_id "
                    "JOIN findings f ON f.finding_id=c.finding_id "
                    "WHERE f.case_id=? AND COALESCE(f.is_deleted,0)=0 "
                    "ORDER BY a.claim_id,a.anchor_id",
                    (self.case_id,),
                ),
            }
            if "claim_verifications" in tables:
                queries["verifications"] = (
                    "SELECT v.* FROM claim_verifications v JOIN claims c ON c.claim_id=v.claim_id "
                    "JOIN findings f ON f.finding_id=c.finding_id "
                    "WHERE f.case_id=? AND COALESCE(f.is_deleted,0)=0 "
                    "ORDER BY v.claim_id,v.verified_at,v.verification_id",
                    (self.case_id,),
                )
            for name, (sql, params) in queries.items():
                payload[name] = [dict(row) for row in connection.execute(sql, params).fetchall()]
        return _canonical_digest(b"mulder.review.claim-set:v1", payload)

    def _audit_contains(self, digest: str) -> bool:
        integrity = AuditLog(self.audit_path).verify_integrity()
        if not integrity.ok or not integrity.cryptographically_verified:
            return False
        try:
            with self.audit_path.open("r", encoding="utf-8") as handle:
                return any(
                    json.loads(line).get("entry_hash") == digest
                    for line in handle
                    if line.strip()
                )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False

    def _has_table(self, table_name: str) -> bool:
        with sqlite3.connect(
            f"file:{self.db_path}?mode=ro&immutable=1", uri=True
        ) as connection:
            row = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
            ).fetchone()
        return row is not None
