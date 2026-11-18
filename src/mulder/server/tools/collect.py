"""MCP tool: collect cloud audit logs during an investigation, when the user allows it."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from mulder import collect as collector
from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.helpers import error_response, make_tool_call_id, tool_response
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.cloudlogs import run_cloud_audit_logs

__all__ = ["collect_cloud_audit_logs"]

logger = logging.getLogger(__name__)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def collect_cloud_audit_logs(
    provider: str,
    start: str | None = None,
    end: str | None = None,
    days: int = 30,
) -> dict[str, object]:
    """Fetch and index cloud audit logs for a time window, using read-only credentials.

    Call when the case concerns a cloud or source-hosting account that the
    investigator configured live collection for, and its audit log is not
    already among the evidence. Only works when the investigator has enabled it; otherwise it
    returns an error and the missing log should be recorded as a [COLLECT]
    finding. Which organizations and projects are read is fixed by the
    investigator's configuration and cannot be chosen here.

    Returns, per configured organization or project, the event count, whether
    the collection was complete, warnings, and the cloudlog.* sources the
    events were indexed into (the same as run_cloud_audit_logs).

    Args:
        provider: "github" or "gcp".
        start: Start of the window, ISO 8601. Default: *days* before *end*.
        end: End of the window, ISO 8601. Default: now.
        days: Window length when *start* is not given.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "collect_cloud_audit_logs"
    params: dict[str, object] = {"provider": provider, "start": start, "end": end, "days": days}

    scopes = collector.targets().get(provider, [])
    if not collector.agent_collection_enabled() or not scopes:
        return error_response(
            tc_id,
            name,
            params,
            f"Live collection of {provider} audit logs is not enabled for this investigation",
            error_type="not_enabled",
            suggestion=(
                "Do not retry. Record the missing log as a [COLLECT] finding so the "
                "investigator can export it."
            ),
        )
    try:
        since, until = collector.window(start, end, days)
    except collector.CollectError as exc:
        return error_response(tc_id, name, params, str(exc), error_type="invalid_argument")

    # Under the case, never in the evidence directory: evidence is not written to.
    root = Path(get_cfg().db_dir) / "collected" / get_ctx().case_id
    collected: dict[str, object] = {}
    for scope in scopes:
        dest = root / f"{provider}-{scope}-{since:%Y%m%dT%H%M%SZ}-{until:%Y%m%dT%H%M%SZ}"
        if dest.is_dir() and any(dest.glob("*.jsonl")):
            collected[scope] = {"status": "already collected", "path": str(dest)}
            continue
        try:
            done = collector.collect(provider, scope, since, until, dest)
        except collector.CollectError as exc:
            collected[scope] = {"status": "error", "error": str(exc)}
            continue
        indexed = run_cloud_audit_logs.__wrapped__(str(dest))  # type: ignore[attr-defined]
        collected[scope] = {
            "status": "collected" if done.complete else "partial",
            "events": done.events,
            "window": f"{done.start} to {done.end}",
            "sha256": done.sha256,
            "warnings": done.warnings,
            "path": str(dest),
            "indexed": indexed.get("results", indexed),
        }

    elapsed = (time.monotonic() - t0) * 1000
    if all(isinstance(v, dict) and v.get("status") == "error" for v in collected.values()):
        why = "; ".join(str(v.get("error")) for v in collected.values() if isinstance(v, dict))
        return error_response(tc_id, name, params, why[:600], elapsed, error_type="tool_failed")
    return tool_response(
        tc_id, name, params, {"provider": provider, "scopes": collected}, None, elapsed
    )
