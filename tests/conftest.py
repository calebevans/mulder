"""Shared fixtures for the Mulder test suite."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.models import Finding


@pytest.fixture()
def tmp_case_db(tmp_path: Path) -> Generator[CaseDB]:
    """Create a throwaway CaseDB backed by a temp directory."""
    db = CaseDB.create(case_id="test-case", evidence_root="/evidence", db_dir=tmp_path)
    yield db
    db.close()


@pytest.fixture()
def tmp_audit_log(tmp_path: Path) -> AuditLog:
    """Create an AuditLog pointed at a temp JSONL file."""
    return AuditLog(tmp_path / "test.audit.jsonl")


@pytest.fixture()
def sample_finding() -> Finding:
    """A minimal valid Finding for reuse across tests."""
    return Finding(
        finding_id="f-001",
        case_id="test-case",
        title="Suspicious process",
        description="spinlock.exe spawned from cmd.exe via 192.168.1.10:4444",
        severity="high",
        confidence="confirmed",
        evidence_refs=["tc_aabbccdd"],
        sources=["volatility.pslist"],
        mitre_attack_ids=["T1059.001"],
        event_time_start="2025-01-15T08:00:00Z",
        event_time_end="2025-01-15T09:00:00Z",
        submitted_at="2025-01-15T12:00:00Z",
    )
