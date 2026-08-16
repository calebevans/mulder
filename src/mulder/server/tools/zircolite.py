"""Zircolite MCP tool for Linux Sigma detection on Auditd/Sysmon logs."""

from __future__ import annotations

import importlib.util
import json
import logging
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Literal

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "run_zircolite",
]

logger = logging.getLogger(__name__)

_ZIRCOLITE_TIMEOUT = 600
_ZIRCOLITE_SCRIPT = "/opt/zircolite/zircolite.py"
_DEFAULT_LINUX_RULES = "/opt/zircolite/rules/linux/"

# Zircolite 2.20.0's unguarded top-level third-party imports, i.e. the modules
# without which zircolite.py cannot start at all.  Every other import in
# Zircolite (aiohttp, evtx, lxml, requests, elasticsearch, pysigma, yaml,
# jinja2) sits inside a try/except feeding its own ImportErrorHandler and is
# optional.  Inside the container these come from the Dockerfile's pip install;
# under ``pipx install mulder-dfir`` they come from the ``forensics`` extra.
# Keep this list short: a missing entry only weakens the preflight, an extra
# entry blocks a working install.
_ZIRCOLITE_MODULES = ("orjson", "xxhash", "colorama", "tqdm")

_FORMAT_FLAGS: dict[str, list[str]] = {
    "auditd": ["--auditd"],
    "sysmon_linux": ["--sysmon4linux"],
    "json": ["--jsononly"],
    "evtx": [],
}

_LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]


def _missing_zircolite_modules() -> list[str]:
    """Return Zircolite dependencies not importable from mulder's interpreter."""
    return [m for m in _ZIRCOLITE_MODULES if importlib.util.find_spec(m) is None]


def _run_zircolite_process(
    events_path: Path,
    log_format: str,
    ruleset_path: Path,
    output_dir: Path,
) -> Path:
    """Execute Zircolite against event logs.

    Args:
        events_path: Path to input log file(s).
        log_format: Log format identifier.
        ruleset_path: Path to the Sigma ruleset directory.
        output_dir: Output directory for results.

    Returns:
        Path to the JSON results file.

    Raises:
        subprocess.TimeoutExpired: If Zircolite exceeds the timeout.
    """
    output_file = output_dir / "zircolite_results.json"
    format_flags = _FORMAT_FLAGS.get(log_format, [])

    cmd = [
        sys.executable,
        _ZIRCOLITE_SCRIPT,
        "--events",
        str(events_path),
        "--ruleset",
        str(ruleset_path),
        "--json",
        "--outfile",
        str(output_file),
        *format_flags,
    ]

    subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_ZIRCOLITE_TIMEOUT,
        check=False,
    )
    return output_file


def _build_detection_timeline(
    detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a chronological timeline from detections.

    Args:
        detections: List of detection dicts with timestamps.

    Returns:
        Sorted list of timeline entries.
    """
    timeline: list[dict[str, Any]] = []
    for d in detections:
        ts = d.get("timestamp", "")
        if ts:
            timeline.append(
                {
                    "timestamp": ts,
                    "rule_title": d.get("rule_title", ""),
                    "rule_level": d.get("rule_level", ""),
                }
            )
    return sorted(timeline, key=lambda x: x.get("timestamp", ""))


def _parse_zircolite_output(
    results_path: Path,
    events_path: str,
    log_format: str,
    level_filter: str | None = None,
) -> dict[str, Any]:
    """Parse Zircolite JSON output into structured results.

    Args:
        results_path: Path to the Zircolite JSON output file.
        events_path: Original events path for reference.
        log_format: Log format used.
        level_filter: Minimum level to include.

    Returns:
        Dict with filtered and structured detections.
    """
    if not results_path.exists():
        return {
            "events_path": events_path,
            "log_format": log_format,
            "detections": [],
            "total_detections": 0,
            "total_events_processed": 0,
            "level_counts": {},
            "mitre_coverage": {},
            "timeline": [],
        }

    try:
        raw_results = json.loads(results_path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {
            "events_path": events_path,
            "log_format": log_format,
            "detections": [],
            "total_detections": 0,
            "total_events_processed": 0,
            "level_counts": {},
            "mitre_coverage": {},
            "timeline": [],
        }

    if not isinstance(raw_results, list):
        raw_results = [raw_results] if raw_results else []

    min_idx = (
        _LEVEL_ORDER.index(level_filter) if level_filter and level_filter in _LEVEL_ORDER else 0
    )

    detections: list[dict[str, Any]] = []
    level_counts: dict[str, int] = {}
    mitre_coverage: dict[str, list[str]] = {}

    for entry in raw_results:
        level = entry.get("rule_level", "informational")
        level_counts[level] = level_counts.get(level, 0) + 1

        level_idx = _LEVEL_ORDER.index(level) if level in _LEVEL_ORDER else 0
        if level_idx < min_idx:
            continue

        mitre_refs = entry.get("rule_mitre", [])
        if isinstance(mitre_refs, list):
            for ref in mitre_refs:
                if isinstance(ref, dict):
                    tactic = ref.get("tactic", "unknown")
                    technique = ref.get("technique", "")
                    if tactic not in mitre_coverage:
                        mitre_coverage[tactic] = []
                    if technique and technique not in mitre_coverage[tactic]:
                        mitre_coverage[tactic].append(technique)

        mitre_attack: list[str] = []
        if isinstance(mitre_refs, list):
            for r in mitre_refs:
                if isinstance(r, dict):
                    mitre_attack.append(f"{r.get('technique', '')} ({r.get('tactic', '')})")

        detections.append(
            {
                "timestamp": entry.get("timestamp", ""),
                "rule_title": entry.get("rule_title", ""),
                "rule_id": entry.get("rule_id", ""),
                "rule_level": level,
                "rule_description": entry.get("rule_description", ""),
                "mitre_attack": mitre_attack,
                "matched_fields": entry.get("matched_fields", {}),
                "count": entry.get("count", 1),
            }
        )

    timeline = _build_detection_timeline(detections)

    return {
        "events_path": events_path,
        "log_format": log_format,
        "detections": detections[:500],
        "total_detections": len(detections),
        "total_events_processed": sum(level_counts.values()),
        "level_counts": level_counts,
        "mitre_coverage": mitre_coverage,
        "timeline": timeline[:200],
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_zircolite(
    events_path: str,
    log_format: Literal["auditd", "sysmon_linux", "json", "evtx"] = "auditd",
    ruleset_path: str | None = None,
    sigma_level_filter: Literal["informational", "low", "medium", "high", "critical"]
    | None = "medium",
    force: bool = False,
) -> dict[str, object]:
    """Apply Sigma detection rules to Linux logs using Zircolite.

    Evaluates Sigma rules against Auditd, Sysmon for Linux, or
    JSON-formatted event logs. Fills the Linux detection gap that
    Windows-only tools (Hayabusa, Chainsaw) cannot address.

    Args:
        events_path: Path to the log file or directory of log files
            to analyze.
        log_format: Format of the input logs. "auditd" for Linux
            Audit daemon logs, "sysmon_linux" for Sysmon for Linux
            JSON output, "json" for generic JSON event streams,
            "evtx" for Windows EVTX (fallback use case).
        ruleset_path: Path to a custom ruleset directory. If None,
            uses the bundled Linux Sigma rules at
            /opt/zircolite/rules/linux/.
        sigma_level_filter: Minimum Sigma rule level to include in
            results. Rules below this level are excluded. Set None
            to include all levels.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "events_path": events_path,
        "log_format": log_format,
        "ruleset_path": ruleset_path,
        "sigma_level_filter": sigma_level_filter,
        "force": force,
    }

    if not force:
        existing = sources_already_indexed(["zircolite."], evidence_path=events_path)
        if existing:
            return tool_response(
                tc_id,
                "run_zircolite",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "zircolite",
                0.0,
            )

    missing = _missing_zircolite_modules()
    if missing:
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Zircolite dependencies not importable: {', '.join(missing)}",
            error_type="binary_missing",
            suggestion=(
                "Install the forensics extra: pipx install 'mulder-dfir[forensics]' "
                "(or: pipx inject mulder-dfir " + " ".join(missing) + ")"
            ),
        )

    if not Path(_ZIRCOLITE_SCRIPT).exists():
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Zircolite script not found: {_ZIRCOLITE_SCRIPT}",
            error_type="binary_missing",
            suggestion=(
                "Install Zircolite: git clone"
                " https://github.com/wagga40/Zircolite.git /opt/zircolite"
            ),
        )

    if not Path(events_path).exists():
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Path not found: {events_path}",
            error_type="file_not_found",
        )

    effective_ruleset = Path(ruleset_path) if ruleset_path else Path(_DEFAULT_LINUX_RULES)
    if not effective_ruleset.exists():
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Ruleset path not found: {effective_ruleset}",
            error_type="file_not_found",
        )

    if log_format not in _FORMAT_FLAGS:
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Invalid log_format: {log_format}. Valid: {list(_FORMAT_FLAGS.keys())}",
            error_type="invalid_argument",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_zircolite_") as tmpdir:
        output_dir = Path(tmpdir)
        try:
            results_path = _run_zircolite_process(
                Path(events_path),
                log_format,
                effective_ruleset,
                output_dir,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_zircolite",
                params,
                f"Zircolite timed out after {_ZIRCOLITE_TIMEOUT}s",
                (time.monotonic() - t0) * 1000,
                error_type="timeout",
            )
        except OSError as exc:
            return error_response(
                tc_id,
                "run_zircolite",
                params,
                f"Failed to execute Zircolite: {exc}",
                (time.monotonic() - t0) * 1000,
                error_type="os_error",
            )

        result = _parse_zircolite_output(results_path, events_path, log_format, sigma_level_filter)

        text_parts = [
            f"Zircolite {log_format} analysis of {events_path}",
            f"Total detections: {result['total_detections']}",
            f"Events processed: {result['total_events_processed']}",
        ]
        for level, count in result.get("level_counts", {}).items():
            text_parts.append(f"  {level}: {count}")
        if result.get("mitre_coverage"):
            text_parts.append("MITRE coverage:")
            for tactic, techniques in result["mitre_coverage"].items():
                text_parts.append(f"  {tactic}: {', '.join(techniques[:5])}")

        summary = extract_and_index(
            "\n".join(text_parts), "zircolite.detections", events_path, "zircolite"
        )
        summary.update(result)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_zircolite", params, summary, "zircolite.detections", elapsed)
