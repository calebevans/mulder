"""Explicit local-only MCP adapter for sealed Linux live-state acquisition."""

from __future__ import annotations

import time
from pathlib import Path

from mulder.linux_live import (
    CollectionResult,
    LinuxCheck,
    LinuxCollectionRequest,
    LinuxCollectionScope,
    collect_linux_live_state,
)
from mulder.models import CoverageKey, CoverageMetadata, ToolOutcome, ToolOutcomeStatus
from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.helpers import error_response, make_tool_call_id, tool_response
from mulder.server.tool_access import Role, tool_access

__all__ = ["collect_linux_live_state_bundle"]


def _aggregate_outcome(result_statuses: list[str], result: CollectionResult) -> ToolOutcome:
    """Conservatively summarize per-check coverage without strengthening it."""
    coverages = result.manifest.coverage
    if result_statuses and all(status == "failed" for status in result_statuses):
        status = ToolOutcomeStatus.FAILED
    elif any(status in {"failed", "partial"} for status in result_statuses):
        status = ToolOutcomeStatus.PARTIAL
    elif result_statuses and all(status == "empty" for status in result_statuses):
        status = ToolOutcomeStatus.SUCCESS_EMPTY
    else:
        status = ToolOutcomeStatus.SUCCESS_NONEMPTY
    limited = [coverage.check.value for coverage in coverages if coverage.status != "success"]
    reason = f"limited checks: {', '.join(limited)}" if limited else None
    return ToolOutcome(
        status=status,
        coverage=CoverageMetadata(
            bytes_examined=sum(item.bytes_examined for item in coverages),
            bytes_total=(
                None
                if any(item.errors or not item.totals_known for item in coverages)
                else sum(item.bytes_discovered for item in coverages)
            ),
            rows_examined=sum(item.files_examined for item in coverages),
            rows_total=(
                None
                if any(item.errors for item in coverages)
                else sum(item.files_discovered for item in coverages)
            ),
            truncation_reason=reason if status is ToolOutcomeStatus.PARTIAL else None,
            tool_version=result.manifest.collector.collector_version,
            parser_version=result.manifest.collector.parser_versions["linux-filesystem"],
        ),
        reason=reason,
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def collect_linux_live_state_bundle(
    host_id: str,
    checks: list[str],
    bundle_name: str,
    max_files_per_check: int = 2_000,
    max_bytes_per_file: int = 2 * 1024 * 1024,
    max_total_bytes: int = 64 * 1024 * 1024,
) -> dict[str, object]:
    """Collect typed state from the current Linux host into a sealed bundle.

    This is the only live-acquisition endpoint.  It requires a loaded case,
    requires the caller to name the current host and exact built-in checks, and
    writes only below that server's case directory.  It cannot accept a shell
    command, executable, SSH target, arbitrary input path, or output path.

    Args:
        host_id: Exact local hostname being authorized and recorded.
        checks: One or more built-in Linux check IDs.
        bundle_name: Safe filename stem below ``<db-dir>/live-bundles``.
        max_files_per_check: Hard per-check file bound.
        max_bytes_per_file: Hard prefix bound for any one source file.
        max_total_bytes: Hard aggregate source-content bound.
    """
    ctx = get_ctx()
    cfg = get_cfg()
    tc_id = make_tool_call_id()
    started = time.monotonic()
    params: dict[str, object] = {
        "host_id": host_id,
        "checks": checks,
        "bundle_name": bundle_name,
        "max_files_per_check": max_files_per_check,
        "max_bytes_per_file": max_bytes_per_file,
        "max_total_bytes": max_total_bytes,
    }
    try:
        typed_checks = tuple(LinuxCheck(check) for check in checks)
        request = LinuxCollectionRequest(
            host_id=host_id,
            checks=typed_checks,
            bundle_name=bundle_name,
            max_files_per_check=max_files_per_check,
            max_bytes_per_file=max_bytes_per_file,
            max_total_bytes=max_total_bytes,
        )
        scope = LinuxCollectionScope.for_local_host(
            output_root=(Path(cfg.db_dir) / "live-bundles").absolute()
        )
        result = collect_linux_live_state(scope, request)
    except (OSError, ValueError) as exc:
        return error_response(
            tc_id,
            "collect_linux_live_state_bundle",
            params,
            str(exc),
            (time.monotonic() - started) * 1000,
            error_type="scope_denied",
            outcome_status=ToolOutcomeStatus.FAILED,
        )

    statuses: list[str] = []
    for coverage in result.manifest.coverage:
        statuses.append(coverage.status)
        ctx.db.record_coverage(
            CoverageKey(
                system_name=host_id,
                evidence_domain="linux_live",
                check_name=coverage.check.value,
            ),
            coverage.tool_outcome(),
            source_name=str(result.bundle_path),
            tool_call_id=tc_id,
        )
    outcome = _aggregate_outcome(statuses, result)
    return tool_response(
        tc_id,
        "collect_linux_live_state_bundle",
        params,
        {
            "bundle_path": str(result.bundle_path),
            "bundle_sha256": result.bundle_sha256,
            "host_id": result.manifest.scope.host_id,
            "checks": [
                {
                    "check": coverage.check.value,
                    "status": coverage.status,
                    "files_examined": coverage.files_examined,
                    "files_discovered": coverage.files_discovered,
                    "reason": coverage.reason,
                }
                for coverage in result.manifest.coverage
            ],
            "seal": result.manifest.seal.model_dump(mode="json"),
        },
        elapsed_ms=(time.monotonic() - started) * 1000,
        outcome=outcome,
    )
