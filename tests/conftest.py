"""Shared fixtures for the Mulder test suite."""

from __future__ import annotations

import sys
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.models import Finding
from mulder.orchestrator.gates import reset_gate_failure_counters


def _install_sdk_stub() -> None:
    """Install a claude_agent_sdk stub for orchestrator tests."""
    if "claude_agent_sdk" in sys.modules:
        return
    sdk = ModuleType("claude_agent_sdk")
    sdk.ClaudeAgentOptions = MagicMock  # type: ignore[attr-defined]
    sdk.query = MagicMock  # type: ignore[attr-defined]

    types_mod = ModuleType("claude_agent_sdk.types")

    @dataclass
    class HookMatcher:
        matcher: str | None = None
        hooks: list[object] = field(default_factory=list)
        timeout: float | None = None

    types_mod.AssistantMessage = MagicMock  # type: ignore[attr-defined]
    types_mod.HookMatcher = HookMatcher  # type: ignore[attr-defined]
    types_mod.ResultMessage = MagicMock  # type: ignore[attr-defined]
    types_mod.TextBlock = MagicMock  # type: ignore[attr-defined]
    types_mod.ToolUseBlock = MagicMock  # type: ignore[attr-defined]

    sys.modules["claude_agent_sdk"] = sdk
    sys.modules["claude_agent_sdk.types"] = types_mod


_install_sdk_stub()


@pytest.fixture(scope="session", autouse=True)
def _hermetic_asset_root(tmp_path_factory: pytest.TempPathFactory) -> Generator[None]:
    """Point every asset lookup at an empty tmp dir for the whole session.

    ``MULDER_ASSET_ROOT`` is exclusive (SPEC/setup/01-spec.md §1.2), so this
    makes the suite independent of the developer's ``/opt`` *and* of whatever
    their own ``mulder setup`` installed.  Session-scoped, so it cannot use the
    function-scoped ``monkeypatch`` fixture without a ``ScopeMismatch``.
    """
    from mulder.assets.paths import reset_asset_caches

    mp = pytest.MonkeyPatch()
    mp.setenv("MULDER_ASSET_ROOT", str(tmp_path_factory.mktemp("empty-assets")))
    reset_asset_caches()
    yield
    mp.undo()
    reset_asset_caches()


@pytest.fixture(scope="session", autouse=True)
def _no_network(_hermetic_asset_root: None) -> Generator[None]:
    """Fail loudly on any real socket connect or httpx request.

    ``mulder setup``'s fetcher is injectable so tests can substitute a local
    one; this is the belt-and-braces layer that catches a regression which
    bypasses the injection and would otherwise download gigabytes in CI.
    """
    import socket

    import httpx

    def _blocked(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("test attempted network I/O")

    mp = pytest.MonkeyPatch()
    mp.setattr(socket.socket, "connect", _blocked)
    mp.setattr(httpx.Client, "send", _blocked)
    mp.setattr(httpx.AsyncClient, "send", _blocked)
    yield
    mp.undo()


@pytest.fixture()
def asset_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    """Pin ``MULDER_ASSET_ROOT`` to a tmp dir and flush every dependent cache."""
    from mulder.assets.paths import reset_asset_caches

    root = tmp_path / "assets"
    root.mkdir()
    monkeypatch.setenv("MULDER_ASSET_ROOT", str(root))
    reset_asset_caches()
    yield root
    reset_asset_caches()


@pytest.fixture(autouse=True)
def _reset_gate_counters() -> None:
    """Reset module-level gate failure counters between tests."""
    reset_gate_failure_counters()


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
