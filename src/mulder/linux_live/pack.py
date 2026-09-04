"""Contract-shaped descriptor for the Linux live specialist pack.

PR 7.1's registry is developed on a separate integration line.  Returning
strict inert data here avoids copying or conditionally importing that contract;
the integration commit can validate this mapping with ``DomainPackManifest``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mulder import __version__
from mulder.linux_live.collector import (
    ALL_LINUX_CHECKS,
    LINUX_LIVE_COLLECTOR_VERSION,
    logical_paths_for,
)


def linux_live_pack_fixture_root() -> Path:
    """Return the packaged fixture root used by domain-pack preflight."""
    return Path(__file__).with_name("fixtures")


def linux_live_pack_descriptor() -> dict[str, Any]:
    """Return deterministic inert data accepted by PR 7.1's v1 contract."""
    return {
        "schema": "mulder.domain-pack",
        "schema_version": 1,
        "support_version": "1.0",
        "pack_id": "linux.live-state",
        "pack_version": "1.0.0",
        "title": "Linux live-state acquisition and review",
        "supported_mulder_versions": [__version__],
        "supported_core_schema_versions": [1],
        "classifiers": [
            {
                "classifier_id": "linux-live-bundle",
                "artifact_type": "linux_live_bundle",
                "path_kind": "file",
                "extensions": [".mlive"],
                "name_globs": [],
                "path_globs": [],
            }
        ],
        "tool_bindings": [
            {
                "binding_id": "collect-local-state",
                "tool_name": "collect_linux_live_state_bundle",
                "roles": ["executor"],
                "parser_id": "mulder-linux-live-collector",
            }
        ],
        "parser_support": [
            {
                "parser_id": "mulder-linux-live-collector",
                "supported_versions": [LINUX_LIVE_COLLECTOR_VERSION],
            }
        ],
        "required_capabilities": ["forensic.local-live-read"],
        "hunts": [
            {
                "hunt_id": check.value,
                "title": f"Review Linux {check.value.replace('_', ' ')} state",
                "artifact_types": ["linux_live_bundle"],
                "tool_binding_ids": ["collect-local-state"],
                "required_capability_ids": ["forensic.local-live-read"],
                "gate_ids": [f"{check.value}-coverage-recorded"],
                "questions": [
                    f"What does the acquired {check.value} state support within coverage?"
                ],
                "planner_instructions": (
                    f"Request only the {check.value} typed check for the scoped local host."
                ),
                "executor_instructions": (
                    "Preserve the bundle seal and exact per-check coverage outcome."
                ),
                "analyst_instructions": (
                    "Limit conclusions to captured paths and treat partial/failed as gaps. "
                    f"Declared paths: {', '.join(logical_paths_for(check))}."
                ),
                "max_retries": 1,
                "max_follow_ups": 1,
            }
            for check in ALL_LINUX_CHECKS
        ],
        "gates": [
            {
                "gate_id": f"{check.value}-coverage-recorded",
                "required_tool_binding_ids": ["collect-local-state"],
                "require_all": True,
            }
            for check in ALL_LINUX_CHECKS
        ],
        "fixtures": [
            {
                "fixture_id": "minimal-auth-log",
                "path": "minimal-auth.txt",
                "sha256": "ba80baf5a4321ac5b0ad2398788c52472f9bd34ad8d872dd3905b6230f3d7058",
                "size_bytes": 82,
            }
        ],
        "benchmark_expectations": [
            {
                "expectation_id": f"{check.value}-typed-coverage",
                "fixture_id": "minimal-auth-log",
                "hunt_id": check.value,
                "acceptable_statuses": [
                    "SUCCESS_NONEMPTY",
                    "SUCCESS_EMPTY",
                    "PARTIAL",
                    "FAILED",
                ],
                "required_gate_ids": [f"{check.value}-coverage-recorded"],
            }
            for check in ALL_LINUX_CHECKS
        ],
        "receipt_replay": {
            "schema_version": 1,
            "receipt_namespace": "linux.live-state",
            "replay_mode": "version_matched",
            "deterministic": True,
            "records_fixture_digests": True,
            "records_parser_versions": True,
            "records_tool_bindings": True,
        },
    }
