"""Declarative tool-role access registry for the Mulder MCP surface.

Tools self-declare which pipeline roles may invoke them via the
``@tool_access`` decorator. The ``get_tools_for_role`` function
builds allowlists at import time so ``phases.py`` never needs manual
tool list maintenance.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Flag, auto
from typing import TypeVar

F = TypeVar("F", bound=Callable[..., object])


class Role(Flag):
    """Pipeline roles that can invoke MCP tools."""

    CATALOG = auto()
    EXTRACT_PLANNER = auto()
    EXTRACT_EXECUTOR = auto()
    EXTRACT_ANALYST = auto()
    CROSS_PLANNER = auto()
    CROSS_EXECUTOR = auto()
    CROSS_ANALYST = auto()
    NARRATIVE_PLANNER = auto()
    NARRATIVE_EXECUTOR = auto()
    NARRATIVE_ANALYST = auto()
    REPORT = auto()


PLANNERS = Role.EXTRACT_PLANNER | Role.CROSS_PLANNER | Role.NARRATIVE_PLANNER
EXECUTORS = Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR
ANALYSTS = Role.EXTRACT_ANALYST | Role.CROSS_ANALYST | Role.NARRATIVE_ANALYST
ALL_ROLES = Role.CATALOG | PLANNERS | EXECUTORS | ANALYSTS | Role.REPORT

_registry: dict[str, Role] = {}


def tool_access(*roles: Role) -> Callable[[F], F]:
    """Declare which pipeline roles may call this tool.

    Place this decorator BELOW ``@mcp.tool()`` so it runs first
    and registers the function before FastMCP wraps it.

    Example::

        @mcp.tool()
        @tool_access(EXECUTORS)
        def run_volatility(...):
            ...
    """
    combined = Role(0)
    for r in roles:
        combined |= r

    def decorator(fn: F) -> F:
        _registry[fn.__name__] = combined
        return fn

    return decorator


def get_tools_for_role(role: Role) -> list[str]:
    """Return sorted MCP tool names accessible by a given role."""
    return sorted(f"mcp__mulder__{name}" for name, allowed in _registry.items() if role & allowed)
