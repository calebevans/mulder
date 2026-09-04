"""Policy-enforced subprocess execution.

Callers describe intent with :class:`CommandRequest`; the runner resolves the
executable, asks one policy object for a decision, and records that decision
before starting a child process.  Tool modules should depend on this package
rather than constructing a second execution policy of their own.
"""

from mulder.execution.policy import (
    CommandPolicy,
    CommandRequest,
    NetworkClass,
    PathAccess,
    PathArgument,
    PolicyDecision,
)
from mulder.execution.runner import (
    BubblewrapNetworkIsolationBackend,
    CommandResult,
    CommandRunner,
    ExecutionAuditEvent,
    ExecutionStatus,
    NetworkIsolationBackend,
    NetworkIsolationPlan,
)

__all__ = [
    "BubblewrapNetworkIsolationBackend",
    "CommandPolicy",
    "CommandRequest",
    "CommandResult",
    "CommandRunner",
    "ExecutionAuditEvent",
    "ExecutionStatus",
    "NetworkClass",
    "NetworkIsolationBackend",
    "NetworkIsolationPlan",
    "PathAccess",
    "PathArgument",
    "PolicyDecision",
]
