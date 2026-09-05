"""Chainsaw MCP tool for Windows EVTX, MFT, and SRUM analysis."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Literal

from mulder.assets.paths import asset_display_path, asset_path, asset_search_summary
from mulder.patterns import DISK_IMAGE_EXTS
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index, format_records
from mulder.server.helpers import (
    adaptive_timeout,
    classify_tool_exit,
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

# How many records the tool response carries back. The index is not bounded by
# this: the records are indexed first and truncated only for the response.
_MAX_DETECTIONS = 500
_MAX_TIMELINE = 1000

# Field order for the indexed lines. Timestamp first, so per-window timestamp
# extraction picks up the record's own time rather than whatever appears first.
_DETECTION_FIELDS = (
    "timestamp",
    "rule_level",
    "rule_name",
    "computer",
    "channel",
    "event_id",
    "sigma_id",
    "mitre_attack",
    "source",
    "event_data",
)
_SRUM_FIELDS = (
    "timestamp",
    "application",
    "user_sid",
    "bytes_sent",
    "bytes_received",
)


def _chainsaw_binary() -> str | None:
    """Resolve the chainsaw executable: PATH first, asset root second.

    PATH wins so a SIFT/apt/cargo install keeps being used.  The resolved value
    is also what gets exec'd -- gating on ``which`` and then exec'ing a
    hardcoded ``/usr/local/bin/chainsaw`` is what made a ``~/.local/bin``
    install report ``os_error`` instead of ``binary_missing`` and silently
    never run.
    """
    found = require_binary("chainsaw")
    if found:
        return found
    candidate = asset_path("chainsaw", "chainsaw")
    if candidate is not None and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def _default_sigma_rules() -> Path:
    """The Sigma rules directory ``mulder setup`` provisions for hunt mode."""
    return asset_display_path("sigma-rules", "rules", "windows")


def _default_chainsaw_mapping() -> Path:
    """The Sigma-to-EVTX field mapping chainsaw requires for ``hunt -s``.

    ``chainsaw hunt`` treats ``--mapping`` as *required* whenever Sigma rules
    are supplied; the file ships in chainsaw's own ``mappings/`` directory,
    which ``mulder setup`` fetches alongside the binary.
    """
    return asset_display_path("chainsaw", "mappings", "sigma-event-logs-all.yml")


def _resolve_evtx_evidence(evidence_path: str) -> str:
    """Resolve a disk image path to its EVTX extraction directory.

    If *evidence_path* is already a directory, returns it unchanged.
    If it is a disk image, looks up the extraction directory from the
    in-memory cache (``_evtx_extract_dirs``) and the DB ``kv_store``,
    mirroring the cross-process fallback used in ``run_hayabusa`` and
    ``index_evtx_file``.

    Args:
        evidence_path: Path to an EVTX directory or disk image.

    Returns:
        Resolved directory path, or the original *evidence_path* if
        no extraction directory is found.
    """
    ep = Path(evidence_path)
    if ep.is_dir():
        return evidence_path
    if ep.suffix.lower() not in DISK_IMAGE_EXTS:
        return evidence_path

    from mulder.server.tools.extract.evtx import _evtx_extract_dirs

    if evidence_path in _evtx_extract_dirs:
        d = _evtx_extract_dirs[evidence_path]
        if Path(d).is_dir():
            return d

    for d in reversed(list(_evtx_extract_dirs.values())):
        if Path(d).is_dir():
            return d

    try:
        ctx = get_ctx()
        db_dir = ctx.db.get_kv(f"evtx_extract_dir:{evidence_path}")
        if db_dir and Path(db_dir).is_dir():
            return db_dir
        db_dir = ctx.db.get_kv("evtx_extract_dir") or ""
        if db_dir and Path(db_dir).is_dir():
            return db_dir
    except Exception:
        logger.debug("Failed to read evtx_extract_dir from DB kv_store", exc_info=True)

    return evidence_path


def _run_chainsaw_hunt(
    binary: str,
    evidence_path: Path,
    sigma_rules_path: Path,
    mapping_path: Path,
    output_dir: Path,
    time_start: str | None = None,
    time_end: str | None = None,
    timeout: int = _CHAINSAW_TIMEOUT,
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    """Execute Chainsaw in hunt mode against EVTX files.

    Args:
        binary: Resolved Chainsaw executable.
        evidence_path: Directory containing .evtx files.
        sigma_rules_path: Path to Sigma rules directory.
        mapping_path: Path to the chainsaw Sigma field-mapping file.
        output_dir: Output directory for results.
        time_start: Optional time range start (ISO 8601).
        time_end: Optional time range end (ISO 8601).
        timeout: Subprocess timeout in seconds.

    Returns:
        ``(results_path, completed_process)``. The caller must inspect the
        process: chainsaw exits non-zero on an unusable argument or rule set
        and writes nothing, which is otherwise indistinguishable from a run
        that legitimately found no detections.

    Raises:
        subprocess.TimeoutExpired: If Chainsaw exceeds the timeout.
    """
    output_file = output_dir / "chainsaw_hunt.json"
    cmd = [
        binary,
        "hunt",
        str(evidence_path),
        "-s",
        str(sigma_rules_path),
        "--mapping",
        str(mapping_path),
        "--json",
        "--output",
        str(output_file),
    ]
    if time_start:
        cmd.extend(["--from", time_start])
    if time_end:
        cmd.extend(["--to", time_end])

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return output_file, proc


def _run_chainsaw_search(
    binary: str,
    evidence_path: Path,
    search_term: str,
    output_dir: Path,
    time_start: str | None = None,
    time_end: str | None = None,
    timeout: int = _CHAINSAW_TIMEOUT,
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    """Execute Chainsaw in search mode against EVTX files.

    Args:
        binary: Resolved Chainsaw executable.
        evidence_path: Directory containing .evtx files.
        search_term: Keyword or regex to search for.
        output_dir: Output directory for results.
        time_start: Optional time range start.
        time_end: Optional time range end.
        timeout: Subprocess timeout in seconds.

    Returns:
        ``(results_path, completed_process)``. The caller must inspect the
        process: chainsaw exits non-zero on an unusable argument or rule set
        and writes nothing, which is otherwise indistinguishable from a run
        that legitimately found no detections.

    Raises:
        subprocess.TimeoutExpired: If Chainsaw exceeds the timeout.
    """
    output_file = output_dir / "chainsaw_search.json"
    cmd = [
        binary,
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

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return output_file, proc


def _run_chainsaw_srum(
    binary: str,
    srum_path: Path,
    software_hive: Path,
    output_dir: Path,
    timeout: int = _CHAINSAW_TIMEOUT,
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    """Execute Chainsaw SRUM parsing mode.

    Args:
        binary: Resolved Chainsaw executable.
        srum_path: Path to the SRUDB.dat file.
        software_hive: Path to the SOFTWARE registry hive (required by chainsaw).
        output_dir: Output directory for results.
        timeout: Subprocess timeout in seconds.

    Returns:
        ``(results_path, completed_process)``. The caller must inspect the
        process: chainsaw exits non-zero on an unusable argument or rule set
        and writes nothing, which is otherwise indistinguishable from a run
        that legitimately found no detections.

    Raises:
        subprocess.TimeoutExpired: If Chainsaw exceeds the timeout.
    """
    output_file = output_dir / "chainsaw_srum.json"
    cmd = [
        binary,
        "analyse",
        "srum",
        str(srum_path),
        "--software",
        str(software_hive),
        "--output",
        str(output_file),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return output_file, proc


def _run_chainsaw_timeline(
    binary: str,
    evidence_path: Path,
    output_dir: Path,
    timeout: int = _CHAINSAW_TIMEOUT,
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    """Execute Chainsaw in dump/timeline mode against EVTX files.

    Args:
        binary: Resolved Chainsaw executable.
        evidence_path: Directory containing .evtx files.
        output_dir: Output directory for results.
        timeout: Subprocess timeout in seconds.

    Returns:
        ``(results_path, completed_process)``. The caller must inspect the
        process: chainsaw exits non-zero on an unusable argument or rule set
        and writes nothing, which is otherwise indistinguishable from a run
        that legitimately found no detections.

    Raises:
        subprocess.TimeoutExpired: If Chainsaw exceeds the timeout.
    """
    output_file = output_dir / "chainsaw_timeline.json"
    cmd = [
        binary,
        "dump",
        str(evidence_path),
        "--json",
        "--output",
        str(output_file),
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return output_file, proc


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
        # Not truncated here: the caller indexes these and then truncates for
        # the response, so the case database sees every detection.
        "detections": detections,
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
        "srum_entries": entries,
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
        "timeline_entries": raw,
        "total_entries": len(raw),
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_chainsaw(
    evidence_path: str,
    mode: Literal["hunt", "search", "srum", "timeline"] = "hunt",
    sigma_rules_path: str = "",
    search_term: str | None = None,
    software_hive: str = "",
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
        sigma_rules_path: Path to the Sigma rules directory. Empty
            resolves to the rules installed by 'mulder setup'.
        search_term: Required when mode="search". The keyword or
            regex pattern to search for in EVTX records.
        software_hive: Required when mode="srum". Path to the SOFTWARE
            registry hive extracted from the same host as the SRUM
            database; chainsaw needs it to resolve application IDs.
        time_range_start: Optional ISO 8601 timestamp to filter results
            (inclusive start). Not supported in "timeline" mode.
        time_range_end: Optional ISO 8601 timestamp to filter results
            (inclusive end). Not supported in "timeline" mode.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path,
        "mode": mode,
        "sigma_rules_path": sigma_rules_path,
        "search_term": search_term,
        "software_hive": software_hive,
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

    binary = _chainsaw_binary()
    if binary is None:
        return error_response(
            tc_id,
            "run_chainsaw",
            params,
            f"chainsaw not found on PATH or under {asset_search_summary('chainsaw', 'chainsaw')}",
            error_type="binary_missing",
            suggestion=(
                "Run 'mulder setup' (installs Chainsaw 2.16.0), or install it "
                "from https://github.com/WithSecureLabs/chainsaw"
            ),
        )

    if mode in ("hunt", "search", "timeline"):
        evidence_path = _resolve_evtx_evidence(evidence_path)

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

    if mode == "srum" and not software_hive:
        return error_response(
            tc_id,
            "run_chainsaw",
            params,
            "software_hive is required when mode='srum': chainsaw needs the "
            "SOFTWARE registry hive to resolve SRUM application IDs",
            error_type="invalid_argument",
        )

    if mode == "timeline" and (time_range_start or time_range_end):
        return error_response(
            tc_id,
            "run_chainsaw",
            params,
            "chainsaw dump has no time-range filter; use mode='search' or "
            "filter the returned timeline instead",
            error_type="invalid_argument",
        )

    rules = Path(sigma_rules_path) if sigma_rules_path else _default_sigma_rules()
    mapping = _default_chainsaw_mapping()
    if mode == "hunt" and not mapping.exists():
        return error_response(
            tc_id,
            "run_chainsaw",
            params,
            f"chainsaw Sigma mapping not found at {mapping}. Run 'mulder setup' "
            "to provision chainsaw's mappings/ directory.",
            error_type="asset_missing",
        )

    timeout = adaptive_timeout(evidence_path, base=_CHAINSAW_TIMEOUT)
    with tempfile.TemporaryDirectory(prefix="mulder_chainsaw_") as tmpdir:
        output_dir = Path(tmpdir)
        try:
            if mode == "hunt":
                results_path, proc = _run_chainsaw_hunt(
                    binary,
                    Path(evidence_path),
                    rules,
                    mapping,
                    output_dir,
                    time_range_start,
                    time_range_end,
                    timeout=timeout,
                )
                result = _parse_chainsaw_hunt_results(results_path)
                source_name = "chainsaw.hunt"
            elif mode == "search":
                assert search_term is not None
                results_path, proc = _run_chainsaw_search(
                    binary,
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
                results_path, proc = _run_chainsaw_srum(
                    binary,
                    Path(evidence_path),
                    Path(software_hive),
                    output_dir,
                    timeout=timeout,
                )
                result = _parse_chainsaw_srum_results(results_path)
                source_name = "chainsaw.srum"
            else:
                results_path, proc = _run_chainsaw_timeline(
                    binary,
                    Path(evidence_path),
                    output_dir,
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

        verdict, message = classify_tool_exit(
            proc, "chainsaw", produced_output=results_path.exists()
        )
        if verdict == "failed":
            return error_response(
                tc_id,
                "run_chainsaw",
                params,
                message,
                (time.monotonic() - t0) * 1000,
                error_type="tool_failed",
            )

        text_parts = [f"Chainsaw {mode} analysis of {evidence_path}"]
        if mode in ("hunt", "search"):
            text_parts.append(f"Total findings: {result.get('total_findings', 0)}")
            for level, count in result.get("severity_counts", {}).items():
                text_parts.append(f"  {level}: {count}")
            records_key, record_cap = "detections", _MAX_DETECTIONS
            fields: tuple[str, ...] | None = _DETECTION_FIELDS
        elif mode == "srum":
            text_parts.append(f"SRUM entries: {result.get('total_entries', 0)}")
            records_key, record_cap = "srum_entries", _MAX_DETECTIONS
            fields = _SRUM_FIELDS
        else:
            text_parts.append(f"Timeline entries: {result.get('total_entries', 0)}")
            records_key, record_cap = "timeline_entries", _MAX_TIMELINE
            fields = None

        # Index the detections themselves. Indexing only the counts above is
        # why a hunt that found 412 things left nothing searchable behind.
        records = result.get(records_key, [])
        text_parts.extend(format_records(records, fields))

        summary = extract_and_index("\n".join(text_parts), source_name, evidence_path, "chainsaw")

        # The response stays bounded; the index does not.
        result[records_key] = records[:record_cap]
        summary.update(result)

    elapsed = (time.monotonic() - t0) * 1000
    response = tool_response(tc_id, "run_chainsaw", params, summary, source_name, elapsed)
    if verdict == "partial":
        response["warning"] = message
    return response
