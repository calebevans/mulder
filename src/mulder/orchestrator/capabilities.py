"""Agent identities and capability authorization for MCP sessions.

This module is the single policy seam between pipeline roles and the tools
handed to a model session.  Phase declarations remain the source of requested
tools; identities independently constrain what each seat is allowed to do.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from mulder.server.tool_access import (
    Role,
    get_registered_tool_effect,
    get_registered_tool_effect_set,
    get_registered_tool_roles,
)


class Capability(str, Enum):
    """Security-relevant effects available to an agent identity."""

    CASE_READ = "case-read"
    FORENSIC_EXECUTION = "forensic-execution"
    CASE_WRITE = "case-mutation"
    CASE_MUTATION = "case-mutation"  # Backwards-compatible symbolic alias.
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


DELEGATION_SECRET_ENV = "MULDER_TOOL_DELEGATION_SECRET"
DELEGATION_GRANT_ENV = "MULDER_TOOL_DELEGATION_GRANT"
_DELEGATION_VERSION = 1


def tool_capability(tool_name: str) -> Capability:
    """Return the registered tool's sole effect for legacy callers."""
    effects = get_registered_tool_effect(tool_name)
    if effects is None or len(effects) != 1:
        raise CapabilityViolation(f"tool {tool_name!r} does not have exactly one effect")
    effect = next(iter(effects))
    return Capability(effect.value)


def tool_capabilities(tool_name: str) -> frozenset[Capability]:
    """Return all security-relevant effects declared by a registered tool."""
    effects = get_registered_tool_effect_set(tool_name)
    if effects is None:
        raise CapabilityViolation(f"unknown tool effect for {tool_name!r}")
    return frozenset(Capability(effect.value) for effect in effects)


def authorize_tool(identity: AgentIdentity, tool_name: str) -> None:
    """Authorize one direct or nested tool against role and capabilities."""
    roles = get_registered_tool_roles(tool_name)
    if roles is None:
        raise CapabilityViolation(
            f"identity {identity.name!r} requested unknown tool {tool_name!r}"
        )
    if not identity.role & roles:
        raise CapabilityViolation(
            f"identity {identity.name!r} is not assigned role for {tool_name!r}"
        )
    required = tool_capabilities(tool_name)
    missing = required - identity.capabilities
    if missing:
        raise CapabilityViolation(
            f"identity {identity.name!r} lacks effects "
            f"{sorted(capability.value for capability in missing)!r} for {tool_name!r}"
        )


def authorize_tool_list(identity: AgentIdentity, requested: list[str]) -> list[str]:
    """Validate and return a deterministic tool allowlist for an identity.

    Authorization requires both the existing decorator role declaration and
    the independent effect capability. Unknown tools and undeclared role/tool
    combinations are rejected before provider options are constructed.
    """
    authorized: set[str] = set()
    for tool_name in requested:
        authorize_tool(identity, tool_name)
        authorized.add(tool_name)
    return sorted(authorized)


def create_delegation_grant(identity: AgentIdentity, secret: str) -> str:
    """Sign one session-scoped identity for server-side nested dispatch."""
    if not secret:
        raise ValueError("delegation secret must not be empty")
    payload = json.dumps(
        {
            "capabilities": sorted(capability.value for capability in identity.capabilities),
            "name": identity.name,
            "role": identity.role.value,
            "version": _DELEGATION_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = hmac.new(secret.encode("utf-8"), encoded, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded.decode('ascii')}.{encoded_signature}"


def identity_from_delegation_grant(grant: str, secret: str) -> AgentIdentity:
    """Verify a session grant and reconstruct its immutable initiating identity."""
    try:
        encoded, encoded_signature = grant.split(".", maxsplit=1)
        signature = _decode_urlsafe(encoded_signature)
        expected = hmac.new(
            secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature mismatch")
        payload = json.loads(_decode_urlsafe(encoded).decode("utf-8"))
        if payload.get("version") != _DELEGATION_VERSION:
            raise ValueError("unsupported version")
        capabilities = frozenset(Capability(value) for value in payload["capabilities"])
        return AgentIdentity(
            name=str(payload["name"]),
            role=Role(int(payload["role"])),
            capabilities=capabilities,
        )
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise CapabilityViolation("invalid nested-tool delegation grant") from exc


def identity_from_bound_environment(
    environment: Mapping[str, str] | None = None,
) -> AgentIdentity | None:
    """Verify the identity bound to an MCP server process, when configured.

    An entirely unbound environment preserves standalone administrative use.
    A partially bound environment is always a configuration error and fails
    closed before any registered tool body runs.
    """
    values = os.environ if environment is None else environment
    secret = values.get(DELEGATION_SECRET_ENV, "")
    grant = values.get(DELEGATION_GRANT_ENV, "")
    if not secret and not grant:
        return None
    if not secret or not grant:
        raise CapabilityViolation("incomplete MCP session identity binding")
    return identity_from_delegation_grant(grant, secret)


def _decode_urlsafe(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


_READ = frozenset({Capability.CASE_READ})
_READ_MUTATE = frozenset({Capability.CASE_READ, Capability.CASE_WRITE})

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
        "extraction-analyst",
        Role.EXTRACT_ANALYST,
        _READ_MUTATE | {Capability.FORENSIC_EXECUTION},
    ),
    ("cross_system", "planner"): AgentIdentity("cross-planner", Role.CROSS_PLANNER, _READ),
    ("cross_system", "executor"): AgentIdentity(
        "cross-executor",
        Role.CROSS_EXECUTOR,
        _READ_MUTATE | {Capability.FORENSIC_EXECUTION, Capability.JOB_CONTROL},
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
        "report", Role.REPORT, _READ | {Capability.CASE_WRITE, Capability.PUBLICATION}
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
