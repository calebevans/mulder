"""Chainsaw MCP tool for Windows EVTX, MFT, and SRUM analysis."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Literal

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    require_binary,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "run_chainsaw",
]

logger = logging.getLogger(__name__)

_CHAINSAW_TIMEOUT = 600
_CHAINSAW_BINARY = "/usr/local/bin/chainsaw"
_DEFAULT_SIGMA_RULES = "/opt/sigma-rules/rules/windows/"


def _run_chainsaw_hunt(
    evidence_path: Path,
    sigma_rules_path: Path,
    output_dir: Path,
    time_start: str | None = None,
    time_end: str | None = None,
    timeout: int = _CHAINSAW_TIMEOUT,
) -> Path:
    """Execute Chainsaw in hunt mode against EVTX files.

    Args:
        evidence_path: Directory containing .evtx files.
        sigma_rules_path: Path to Sigma rules directory.
        output_dir: Output directory for results.
        time_start: Optional time range start (ISO 8601).
        time_end: Optional time range end (ISO 8601).
        timeout: Subprocess timeout in seconds.

    Returns:
        Path to the JSON results file.

    Raises:
        subprocess.TimeoutExpired: If Chainsaw exceeds the timeout.
    """
    output_file = output_dir / "chainsaw_hunt.json"
    cmd = [
        _CHAINSAW_BINARY,
        "hunt",
        str(evidence_path),
        "-s",
        str(sigma_rules_path),
        "--json",
        "--output",
        str(output_file),
    ]
    if time_start:
        cmd.extend(["--from", time_start])
    if time_end:
        cmd.extend(["--to", time_end])

    subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return output_file


def _run_chainsaw_search(
    evidence_path: Path,
    search_term: str,
    output_dir: Path,
    time_start: str | None = None,
    time_end: str | None = None,
    timeout: int = _CHAINSAW_TIMEOUT,
) -> Path:
    """Execute Chainsaw in search mode against EVTX files.

    Args:
        evidence_path: Directory containing .evtx files.
        search_term: Keyword or regex to search for.
        output_dir: Output directory for results.
        time_start: Optional time range start.
        time_end: Optional time range end.
        timeout: Subprocess timeout in seconds.

    Returns:
        Path to the JSON results file.

    Raises:
        subprocess.TimeoutExpired: If Chainsaw exceeds the timeout.
    """
    output_file = output_dir / "chainsaw_search.json"
    cmd = [
        _CHAINSAW_BINARY,
        "search",
        search_term,
        str(evidence_path),
        "--json",
        "--output",
        str(output_file),
    ]
    if time_start:
        cmd.extend(["--from", time_start])
    if time_end:
        cmd.extend(["--to", time_end])

    subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return output_file


def _run_chainsaw_srum(
    srum_path: Path, output_dir: Path, timeout: int = _CHAINSAW_TIMEOUT
) -> Path:
    """Execute Chainsaw SRUM parsing mode.

    Args:
        srum_path: Path to the SRUDB.dat file.
        output_dir: Output directory for results.
        timeout: Subprocess timeout in seconds.

    Returns:
        Path to the JSON results file.

    Raises:
        subprocess.TimeoutExpired: If Chainsaw exceeds the timeout.
    """
    output_file = output_dir / "chainsaw_srum.json"
    cmd = [
        _CHAINSAW_BINARY,
        "analyse",
        "srum",
        str(srum_path),
        "--json",
        "--output",
        str(output_file),
    ]
    subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return output_file


def _run_chainsaw_timeline(
    evidence_path: Path,
    output_dir: Path,
    time_start: str | None = None,
    time_end: str | None = None,
    timeout: int = _CHAINSAW_TIMEOUT,
) -> Path:
    """Execute Chainsaw in dump/timeline mode against EVTX files.

    Args:
        evidence_path: Directory containing .evtx files.
        output_dir: Output directory for results.
        time_start: Optional time range start.
        time_end: Optional time range end.
        timeout: Subprocess timeout in seconds.

    Returns:
        Path to the JSON results file.

    Raises:
        subprocess.TimeoutExpired: If Chainsaw exceeds the timeout.
    """
    output_file = output_dir / "chainsaw_timeline.json"
    cmd = [
        _CHAINSAW_BINARY,
        "dump",
        str(evidence_path),
        "--json",
        "--output",
        str(output_file),
    ]
    if time_start:
        cmd.extend(["--from", time_start])
    if time_end:
        cmd.extend(["--to", time_end])

    subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return output_file


def _parse_chainsaw_hunt_results(results_path: Path) -> dict[str, Any]:
    """Parse Chainsaw hunt mode JSON output.

    Args:
        results_path: Path to the JSON results file.

    Returns:
        Dict with detections, severity counts, and MITRE mappings.
    """
    if not results_path.exists():
        return {"detections": [], "total_findings": 0, "severity_counts": {}}

    try:
        raw = json.loads(results_path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {"detections": [], "total_findings": 0, "severity_counts": {}}

    if not isinstance(raw, list):
        raw = [raw] if raw else []

    detections: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {}
    mitre_techniques: set[str] = set()

    for entry in raw:
        level = entry.get("level", entry.get("rule_level", "informational"))
        severity_counts[level] = severity_counts.get(level, 0) + 1

        mitre = entry.get("mitre", entry.get("tags", []))
        if isinstance(mitre, list):
            for t in mitre:
                if isinstance(t, str) and t.startswith("attack."):
                    mitre_techniques.add(t)

        detections.append(
            {
                "timestamp": entry.get("timestamp", ""),
                "rule_name": entry.get("name", entry.get("rule_title", "")),
                "rule_level": level,
                "source": entry.get("source", ""),
                "event_id": entry.get("event_id", 0),
                "computer": entry.get("computer", entry.get("system", {}).get("computer", "")),
                "channel": entry.get("channel", ""),
                "sigma_id": entry.get("sigma_id", entry.get("rule_id", "")),
                "mitre_attack": mitre if isinstance(mitre, list) else [],
                "event_data": entry.get("event_data", entry.get("document", {})),
            }
        )

    return {
        "detections": detections[:500],
        "total_findings": len(detections),
        "severity_counts": severity_counts,
        "mitre_techniques": sorted(mitre_techniques),
    }


def _parse_chainsaw_srum_results(results_path: Path) -> dict[str, Any]:
    """Parse Chainsaw SRUM JSON output.

    Args:
        results_path: Path to the JSON results file.

    Returns:
        Dict with SRUM entries and summary statistics.
    """
    if not results_path.exists():
        return {"srum_entries": [], "total_entries": 0}

    try:
        raw = json.loads(results_path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {"srum_entries": [], "total_entries": 0}

    if not isinstance(raw, list):
        raw = [raw] if raw else []

    entries: list[dict[str, Any]] = []
    for entry in raw:
        entries.append(
            {
                "timestamp": entry.get("timestamp", ""),
                "application": entry.get("application", entry.get("app", "")),
                "user_sid": entry.get("user_sid", entry.get("user", "")),
                "bytes_sent": entry.get("bytes_sent", 0),
                "bytes_received": entry.get("bytes_received", 0),
            }
        )

    return {
        "srum_entries": entries[:500],
        "total_entries": len(entries),
    }


def _parse_chainsaw_timeline_results(results_path: Path) -> dict[str, Any]:
    """Parse Chainsaw timeline/dump JSON output.

    Args:
        results_path: Path to the JSON results file.

    Returns:
        Dict with timeline entries.
    """
    if not results_path.exists():
        return {"timeline_entries": [], "total_entries": 0}

    try:
        raw = json.loads(results_path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {"timeline_entries": [], "total_entries": 0}

    if not isinstance(raw, list):
        raw = [raw] if raw else []

    return {
        "timeline_entries": raw[:1000],
        "total_entries": len(raw),
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_chainsaw(
    evidence_path: str,
    mode: Literal["hunt", "search", "srum", "timeline"] = "hunt",
    sigma_rules_path: str = _DEFAULT_SIGMA_RULES,
    search_term: str | None = None,
    time_range_start: str | None = None,
    time_range_end: str | None = None,
    force: bool = False,
) -> dict[str, object]:
    """Analyze Windows artifacts using Chainsaw with Sigma rules.

    Runs Chainsaw against EVTX logs, MFT records, or SRUM databases
    to detect suspicious activity via Sigma rules and built-in logic.
    Complements Hayabusa with SRUM support and an independent Sigma
    implementation.

    Args:
        evidence_path: Path to the evidence directory containing EVTX
            files, or path to a specific SRUM database file.
        mode: Analysis mode. "hunt" applies Sigma rules to EVTX files,
            "search" finds specific strings/patterns in EVTX, "srum"
            parses the SRUM database for process resource usage,
            "timeline" dumps all events chronologically.
        sigma_rules_path: Path to the Sigma rules directory.
        search_term: Required when mode="search". The keyword or
            regex pattern to search for in EVTX records.
        time_range_start: Optional ISO 8601 timestamp to filter results
            (inclusive start).
        time_range_end: Optional ISO 8601 timestamp to filter results
            (inclusive end).
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path,
        "mode": mode,
        "sigma_rules_path": sigma_rules_path,
        "search_term": search_term,
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
        "force": force,
    }

    if not force:
        existing = sources_already_indexed(["chainsaw."], evidence_path=evidence_path)
        if existing:
            return tool_response(
                tc_id,
                "run_chainsaw",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "chainsaw",
                0.0,
            )

    if not require_binary("chainsaw") and not Path(_CHAINSAW_BINARY).exists():
        return error_response(
            tc_id,
            "run_chainsaw",
            params,
            "chainsaw not found on PATH",
            error_type="binary_missing",
            suggestion="Install Chainsaw from https://github.com/WithSecureLabs/chainsaw",
        )

    if not Path(evidence_path).exists():
        return error_response(
            tc_id,
            "run_chainsaw",
            params,
            f"Path not found: {evidence_path}",
            error_type="file_not_found",
        )

    if mode == "search" and not search_term:
        return error_response(
            tc_id,
            "run_chainsaw",
            params,
            "search_term is required when mode='search'",
            error_type="invalid_argument",
        )

    timeout = adaptive_timeout(evidence_path, base=_CHAINSAW_TIMEOUT)
    with tempfile.TemporaryDirectory(prefix="mulder_chainsaw_") as tmpdir:
        output_dir = Path(tmpdir)
        try:
            if mode == "hunt":
                results_path = _run_chainsaw_hunt(
                    Path(evidence_path),
                    Path(sigma_rules_path),
                    output_dir,
                    time_range_start,
                    time_range_end,
                    timeout=timeout,
                )
                result = _parse_chainsaw_hunt_results(results_path)
                source_name = "chainsaw.hunt"
            elif mode == "search":
                assert search_term is not None
                results_path = _run_chainsaw_search(
                    Path(evidence_path),
                    search_term,
                    output_dir,
                    time_range_start,
                    time_range_end,
                    timeout=timeout,
                )
                result = _parse_chainsaw_hunt_results(results_path)
                source_name = "chainsaw.search"
            elif mode == "srum":
                results_path = _run_chainsaw_srum(Path(evidence_path), output_dir, timeout=timeout)
                result = _parse_chainsaw_srum_results(results_path)
                source_name = "chainsaw.srum"
            else:
                results_path = _run_chainsaw_timeline(
                    Path(evidence_path),
                    output_dir,
                    time_range_start,
                    time_range_end,
                    timeout=timeout,
                )
                result = _parse_chainsaw_timeline_results(results_path)
                source_name = "chainsaw.timeline"

        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_chainsaw",
                params,
                f"Chainsaw timed out in {mode} mode after {timeout}s",
                (time.monotonic() - t0) * 1000,
                error_type="timeout",
            )
        except OSError as exc:
            return error_response(
                tc_id,
                "run_chainsaw",
                params,
                f"Failed to execute Chainsaw: {exc}",
                (time.monotonic() - t0) * 1000,
                error_type="os_error",
            )

        text_parts = [f"Chainsaw {mode} analysis of {evidence_path}"]
        if mode in ("hunt", "search"):
            text_parts.append(f"Total findings: {result.get('total_findings', 0)}")
            for level, count in result.get("severity_counts", {}).items():
                text_parts.append(f"  {level}: {count}")
        elif mode == "srum":
            text_parts.append(f"SRUM entries: {result.get('total_entries', 0)}")
        else:
            text_parts.append(f"Timeline entries: {result.get('total_entries', 0)}")

        summary = extract_and_index("\n".join(text_parts), source_name, evidence_path, "chainsaw")
        summary.update(result)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_chainsaw", params, summary, source_name, elapsed)
