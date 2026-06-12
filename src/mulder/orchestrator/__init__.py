"""Multi-pass forensic investigation orchestrator using the Claude Agent SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mulder.orchestrator.errors import AuthenticationError, ModelNotAvailableError
    from mulder.orchestrator.evidence import EvidenceContext, ServerBridge
    from mulder.orchestrator.log_tailer import LogTailer
    from mulder.orchestrator.roles import RoleRunner
    from mulder.orchestrator.runner import Orchestrator
    from mulder.orchestrator.session import SessionExecutor

__all__ = [
    "AuthenticationError",
    "EvidenceContext",
    "LogTailer",
    "ModelNotAvailableError",
    "Orchestrator",
    "RoleRunner",
    "ServerBridge",
    "SessionExecutor",
]


def __getattr__(name: str) -> object:
    """Lazy-load public symbols to avoid import-order issues with SDK stubs."""
    if name in ("AuthenticationError", "ModelNotAvailableError"):
        from mulder.orchestrator.errors import (
            AuthenticationError,
            ModelNotAvailableError,
        )

        return AuthenticationError if name == "AuthenticationError" else ModelNotAvailableError
    if name == "Orchestrator":
        from mulder.orchestrator.runner import Orchestrator

        return Orchestrator
    if name == "SessionExecutor":
        from mulder.orchestrator.session import SessionExecutor

        return SessionExecutor
    if name == "RoleRunner":
        from mulder.orchestrator.roles import RoleRunner

        return RoleRunner
    if name in ("EvidenceContext", "ServerBridge"):
        from mulder.orchestrator.evidence import EvidenceContext, ServerBridge

        return EvidenceContext if name == "EvidenceContext" else ServerBridge
    if name == "LogTailer":
        from mulder.orchestrator.log_tailer import LogTailer

        return LogTailer
    raise AttributeError(f"module 'mulder.orchestrator' has no attribute {name!r}")
