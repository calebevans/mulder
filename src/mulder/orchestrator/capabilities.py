"""Agent identities and capability authorization for MCP sessions.

This module is the single policy seam between pipeline roles and the tools
handed to a model session.  Phase declarations remain the source of requested
tools; identities independently constrain what each seat is allowed to do.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from mulder.server.tool_access import Role, get_registered_tool_roles


class Capability(str, Enum):
    """Security-relevant effects available to an agent identity."""

    CASE_READ = "case-read"
    FORENSIC_EXECUTION = "forensic-execution"
    CASE_MUTATION = "case-mutation"
    JOB_CONTROL = "job-control"
    PUBLICATION = "publication"
    VERIFICATION = "verification"


@dataclass(frozen=True)
class AgentIdentity:
    """Stable identity and explicit authority for one pipeline seat."""

    name: str
    role: Role
    capabilities: frozenset[Capability]


class CapabilityViolation(ValueError):
    """Raised before SDK startup when a tool exceeds an identity's authority."""


_MUTATION_TOOLS = frozenset(
    {
        "bookmark_window",
        "delete_finding",
        "deduplicate_findings",
        "record_claim_verification",
        "record_coverage",
        "submit_finding",
        "submit_narrative",
        "track_progress",
        "update_finding",
        "withdraw_finding",
    }
)
_JOB_TOOLS = frozenset(
    {
        "check_extraction_status",
        "get_completed_results",
        "run_parallel",
        "start_extraction_batch",
        "wait",
        "wait_all",
    }
)
_PUBLICATION_TOOLS = frozenset({"finalize_report"})


def tool_capability(tool_name: str, declared_roles: Role) -> Capability:
    """Classify a registered tool by its strongest security-relevant effect."""
    prefix = "mcp__mulder__"
    name = tool_name[len(prefix) :] if tool_name.startswith(prefix) else tool_name
    if name in _PUBLICATION_TOOLS:
        return Capability.PUBLICATION
    if name in _MUTATION_TOOLS:
        return Capability.CASE_MUTATION
    if name in _JOB_TOOLS:
        return Capability.JOB_CONTROL

    # Extraction-only tools launch or control forensic parsers.  Tools shared
    # with analyst/correlation roles are read/query operations over stored data.
    if declared_roles == Role.EXTRACT_EXECUTOR:
        return Capability.FORENSIC_EXECUTION
    return Capability.CASE_READ


def authorize_tool_list(identity: AgentIdentity, requested: list[str]) -> list[str]:
    """Validate and return a deterministic tool allowlist for an identity.

    Authorization requires both the existing decorator role declaration and
    the independent effect capability. Unknown tools and undeclared role/tool
    combinations are rejected before provider options are constructed.
    """
    authorized: set[str] = set()
    for tool_name in requested:
        roles = get_registered_tool_roles(tool_name)
        if roles is None:
            raise CapabilityViolation(
                f"identity {identity.name!r} requested unknown tool {tool_name!r}"
            )
        if not identity.role & roles:
            raise CapabilityViolation(
                f"identity {identity.name!r} is not assigned role for {tool_name!r}"
            )
        required = tool_capability(tool_name, roles)
        if required not in identity.capabilities:
            raise CapabilityViolation(
                f"identity {identity.name!r} lacks {required.value!r} for {tool_name!r}"
            )
        authorized.add(tool_name)
    return sorted(authorized)


_READ = frozenset({Capability.CASE_READ})
_READ_MUTATE = frozenset({Capability.CASE_READ, Capability.CASE_MUTATION})

IDENTITIES: dict[tuple[str, str], AgentIdentity] = {
    ("catalog", "single"): AgentIdentity(
        "catalog", Role.CATALOG, _READ | {Capability.JOB_CONTROL}
    ),
    ("extraction", "planner"): AgentIdentity("extraction-planner", Role.EXTRACT_PLANNER, _READ),
    ("extraction", "executor"): AgentIdentity(
        "extraction-executor",
        Role.EXTRACT_EXECUTOR,
        _READ | {Capability.FORENSIC_EXECUTION, Capability.JOB_CONTROL},
    ),
    ("extraction", "analyst"): AgentIdentity(
        "extraction-analyst", Role.EXTRACT_ANALYST, _READ_MUTATE
    ),
    ("cross_system", "planner"): AgentIdentity("cross-planner", Role.CROSS_PLANNER, _READ),
    ("cross_system", "executor"): AgentIdentity(
        "cross-executor", Role.CROSS_EXECUTOR, _READ_MUTATE | {Capability.JOB_CONTROL}
    ),
    ("cross_system", "analyst"): AgentIdentity(
        "cross-analyst", Role.CROSS_ANALYST, _READ_MUTATE
    ),
    ("alternative_narrative", "planner"): AgentIdentity(
        "narrative-planner", Role.NARRATIVE_PLANNER, _READ
    ),
    ("alternative_narrative", "executor"): AgentIdentity(
        "narrative-executor",
        Role.NARRATIVE_EXECUTOR,
        _READ_MUTATE | {Capability.JOB_CONTROL},
    ),
    ("alternative_narrative", "analyst"): AgentIdentity(
        "narrative-analyst", Role.NARRATIVE_ANALYST, _READ_MUTATE
    ),
    ("report", "single"): AgentIdentity(
        "report", Role.REPORT, _READ | {Capability.CASE_MUTATION, Capability.PUBLICATION}
    ),
}

UTILITY_IDENTITY = AgentIdentity(
    "batch-wait-utility", Role.EXTRACT_EXECUTOR, _READ | {Capability.JOB_CONTROL}
)
JSON_REPAIR_IDENTITY = AgentIdentity("json-repair", Role(0), frozenset())
VERIFIER_IDENTITY = AgentIdentity(
    "deterministic-verifier", Role(0), frozenset({Capability.VERIFICATION})
)


def identity_for_phase(phase_name: str, seat: str) -> AgentIdentity:
    """Resolve the declared identity for a phase seat, failing closed."""
    if phase_name.startswith("pack."):
        template = IDENTITIES.get(("extraction", seat))
        if template is None:
            raise CapabilityViolation(f"no pack identity declared for seat {seat!r}")
        return AgentIdentity(
            name=f"{phase_name}-{seat}",
            role=template.role,
            capabilities=template.capabilities,
        )
    try:
        return IDENTITIES[(phase_name, seat)]
    except KeyError as exc:
        raise CapabilityViolation(f"no identity declared for {phase_name!r}/{seat!r}") from exc
