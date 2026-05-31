"""Shared fixtures for the Mulder test suite."""

from __future__ import annotations

import sys
from collections.abc import Generator
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.models import Finding


def _install_sdk_stub() -> None:
    """Install a claude_agent_sdk stub for orchestrator tests."""
    if "claude_agent_sdk" in sys.modules:
        return
    sdk = ModuleType("claude_agent_sdk")
    sdk.ClaudeAgentOptions = MagicMock  # type: ignore[attr-defined]
    sdk.query = MagicMock  # type: ignore[attr-defined]

    types_mod = ModuleType("claude_agent_sdk.types")
    types_mod.AssistantMessage = MagicMock  # type: ignore[attr-defined]
    types_mod.ResultMessage = MagicMock  # type: ignore[attr-defined]
    types_mod.TextBlock = MagicMock  # type: ignore[attr-defined]
    types_mod.ToolUseBlock = MagicMock  # type: ignore[attr-defined]

    sys.modules["claude_agent_sdk"] = sdk
    sys.modules["claude_agent_sdk.types"] = types_mod


_install_sdk_stub()


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
