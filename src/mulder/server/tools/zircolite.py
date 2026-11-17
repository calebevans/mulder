"""Zircolite MCP tool for Linux Sigma detection on Auditd/Sysmon logs."""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mulder.assets.paths import asset_display_path, asset_path, asset_search_summary
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
_STDERR_PREVIEW_CHARS = 500
_ZIRCOLITE_DIRNAME = "zircolite"


def _zircolite_script() -> Path | None:
    """The Zircolite entry point, or None if it is not installed."""
    return asset_path(_ZIRCOLITE_DIRNAME, "zircolite.py")


def _default_linux_rules() -> Path:
    """The Linux Sigma rules ``mulder setup`` copies in beside Zircolite."""
    return asset_display_path(_ZIRCOLITE_DIRNAME, "rules", "linux")


# ``import name -> PyPI distribution`` for what Zircolite 2.20.0 needs to do
# the job run_zircolite asks of it.  The first four are its unguarded top-level
# imports, without which zircolite.py cannot start.  pySigma and its SQLite
# backend are imported inside a try/except, so Zircolite starts without them,
# but it then cannot compile a Sigma YAML ruleset: it logs "No rules to
# execute", exits 0 and writes no results, which reads as a clean scan.  Every
# ruleset mulder ships is Sigma YAML, so they are required here.  Inside the
# container these come from the Dockerfile's pip install; under ``pipx install
# mulder-dfir`` they come from the ``forensics`` extra.
_ZIRCOLITE_MODULES = {
    "orjson": "orjson",
    "xxhash": "xxhash",
    "colorama": "colorama",
    "tqdm": "tqdm",
    "sigma": "pysigma",
    "sigma.backends.sqlite": "pysigma-backend-sqlite",
    # Sysmon-for-Linux events are XML inside syslog lines. Without lxml
    # Zircolite swallows the parse error for every event and scans nothing.
    "lxml": "lxml",
}

# What Zircolite logs, while still exiting 0, when a ruleset compiled to nothing.
_NO_RULES_MARKER = "No rules to execute"

_FORMAT_FLAGS: dict[str, list[str]] = {
    "auditd": ["--auditd"],
    "sysmon_linux": ["--sysmon4linux"],
    "json": ["--jsononly"],
    "evtx": [],
}

_LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]

# Sigma tags under "attack." also name groups (g0032) and software (s0002).
_ATTACK_TACTICS = frozenset(
    {
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    }
)

# Where a matched event keeps its time, by input format: auditd (set by
# Zircolite), then Sysmon's two fields.
_TIME_FIELDS = ("timestamp", "UtcTime", "SystemTime")


def _event_time(match: dict[str, Any]) -> object:
    """A matched event's time; epoch numbers become ISO 8601 UTC.

    Logs such as GitHub's audit log carry epoch milliseconds, which the index
    cannot place on a timeline.
    """
    value = next((match[k] for k in _TIME_FIELDS if match.get(k) not in (None, "")), "")
    if isinstance(value, bool) or not isinstance(value, int | float):
        return value
    seconds = value / 1000 if value > 1e11 else value
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return value


# How many detections the tool response carries back. The index is not bounded
# by this: every detection is indexed, and the list is truncated only for the
# response, which tool_response reduces to a preview anyway.
_MAX_RESPONSE_DETECTIONS = 500

# Field order for the indexed lines. Timestamp first, so the per-window
# timestamp extraction in extract_and_index picks up the detection's own time
# rather than the first timestamp that happens to appear in the window.
_DETECTION_FIELDS = (
    "timestamp",
    "rule_level",
    "rule_title",
    "rule_id",
    "mitre_attack",
    "rule_description",
    "matched_fields",
)

# matched_fields carries the whole matched event. Long enough to keep the
# fields an analyst searches for (process image, command line, user), short
# enough that one detection cannot fill a 4096-character index window.
_FIELD_CHARS = 2000


def _detection_field(value: object) -> str:
    """Render one detection field as a single-line, bounded string."""
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, bool | int | float):
        text = str(value)
    else:
        text = json.dumps(value, default=str, separators=(",", ":"), sort_keys=True)
    return text.replace("\t", " ").replace("\r", " ").replace("\n", " ")[:_FIELD_CHARS]


def _detection_lines(detections: list[dict[str, Any]]) -> list[str]:
    """Render detections as one tab-separated line each, for indexing.

    ``extract_and_index`` stores exactly the text it is handed, so handing it a
    count stored a count. One line per detection matters twice over: the window
    builder splits on line boundaries, so no detection is cut in half, and
    timestamp extraction runs per window rather than finding a single timestamp
    for a whole summary.
    """
    return [
        "\t".join(_detection_field(d.get(name)) for name in _DETECTION_FIELDS) for d in detections
    ]


def _missing_zircolite_modules() -> list[str]:
    """Return the PyPI names of Zircolite dependencies mulder's interpreter lacks."""
    missing: list[str] = []
    for module, distribution in _ZIRCOLITE_MODULES.items():
        try:
            found = importlib.util.find_spec(module) is not None
        except ModuleNotFoundError:  # the parent package of a dotted name is absent
            found = False
        if not found:
            missing.append(distribution)
    return missing


def _run_zircolite_process(
    script: str,
    events_path: Path,
    log_format: str,
    ruleset_path: Path,
    output_dir: Path,
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    """Execute Zircolite against event logs.

    Args:
        script: Resolved path to ``zircolite.py``.
        events_path: Path to input log file(s).
        log_format: Log format identifier.
        ruleset_path: Path to the Sigma ruleset directory.
        output_dir: Output directory for results.

    Returns:
        Tuple of (path to the JSON results file, the completed process). The
        caller needs the process to tell a genuinely empty ruleset match from a
        Zircolite run that never produced results.

    Raises:
        subprocess.TimeoutExpired: If Zircolite exceeds the timeout.
    """
    output_file = output_dir / "zircolite_results.json"
    format_flags = _FORMAT_FLAGS.get(log_format, [])

    # Zircolite resolves its field mappings, log file and scratch directory
    # against the working directory.  Name the mappings explicitly and run in
    # the output directory, or it exits 1 ("Cannot find mapping file") whenever
    # mulder was not started from Zircolite's own checkout.
    cmd = [
        sys.executable,
        str(Path(script).resolve()),
        "--events",
        str(events_path.resolve()),
        "--ruleset",
        str(ruleset_path.resolve()),
        "--outfile",
        str(output_file),
        "--config",
        str(Path(script).resolve().parent / "config" / "fieldMappings.json"),
        *format_flags,
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_ZIRCOLITE_TIMEOUT,
        check=False,
        cwd=output_dir,
        # Zircolite renders auditd epochs in the host's local time.
        env={**os.environ, "TZ": "UTC"},
    )
    return output_file, proc


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
        if ts not in ("", None):
            timeline.append(
                {
                    "timestamp": ts,
                    "rule_title": d.get("rule_title", ""),
                    "rule_level": d.get("rule_level", ""),
                }
            )
    return sorted(timeline, key=lambda x: str(x.get("timestamp", "")))


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
    tactics: set[str] = set()
    techniques: set[str] = set()

    # Zircolite writes one object per rule that fired, carrying every event the
    # rule matched: {"title", "id", "description", "rule_level", "tags",
    # "count", "matches": [...]}.  One detection per matched event, so each
    # keeps its own timestamp.  The array is padded with an empty object.
    for entry in raw_results:
        if not isinstance(entry, dict) or not entry.get("title"):
            continue
        level = str(entry.get("rule_level") or "informational")
        level_idx = _LEVEL_ORDER.index(level) if level in _LEVEL_ORDER else 0
        # Sigma tags: "attack.t1059.004" is a technique, "attack.execution" a tactic.
        mitre_attack = [
            name.upper() if name[:1] == "t" and name[1:2].isdigit() else name
            for tag in entry.get("tags") or []
            if (name := str(tag).removeprefix("attack.")) != str(tag)
        ]

        matches = [m for m in entry.get("matches") or [] if isinstance(m, dict)]
        for match in matches or [{}]:
            # Counted before the filter, so the caller can see what it hid.
            level_counts[level] = level_counts.get(level, 0) + 1
            if level_idx < min_idx:
                continue
            # Coverage describes the detections reported, not the ones filtered out.
            techniques.update(n for n in mitre_attack if n[:1] == "T" and n[1:2].isdigit())
            tactics.update(n for n in mitre_attack if n in _ATTACK_TACTICS)
            detections.append(
                {
                    "timestamp": _event_time(match),
                    "rule_title": entry.get("title", ""),
                    "rule_id": entry.get("id", ""),
                    "rule_level": level,
                    "rule_description": entry.get("description", ""),
                    "mitre_attack": mitre_attack,
                    "matched_fields": match,
                }
            )

    mitre_coverage = {"tactics": sorted(tactics), "techniques": sorted(techniques)}

    timeline = _build_detection_timeline(detections)

    return {
        "events_path": events_path,
        "log_format": log_format,
        # Not truncated here: run_zircolite indexes every detection before
        # bounding the list for the response.
        "detections": detections,
        "total_detections": len(detections),
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
            uses the Linux Sigma rules installed alongside Zircolite by
            'mulder setup'.
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

    script = _zircolite_script()
    if script is None:
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            "Zircolite script not found under any of: "
            f"{asset_search_summary(_ZIRCOLITE_DIRNAME, 'zircolite.py')}",
            error_type="binary_missing",
            suggestion="Run 'mulder setup' (installs Zircolite 2.20.0 and its Linux Sigma rules).",
        )

    if not Path(events_path).exists():
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Path not found: {events_path}",
            error_type="file_not_found",
        )

    effective_ruleset = Path(ruleset_path) if ruleset_path else _default_linux_rules()
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
            results_path, proc = _run_zircolite_process(
                str(script),
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

        if _NO_RULES_MARKER in f"{proc.stdout or ''}{proc.stderr or ''}":
            return error_response(
                tc_id,
                "run_zircolite",
                params,
                f"Zircolite loaded no rules from {effective_ruleset}, so nothing was scanned",
                (time.monotonic() - t0) * 1000,
                error_type="tool_failed",
                suggestion="Point ruleset_path at Sigma YAML rules or a Zircolite JSON ruleset.",
            )

        # Zircolite writes a results file even when nothing matched, so a
        # missing one means it never got as far as scanning, whatever it exited.
        if not results_path.exists():
            # The tail: Zircolite opens with a banner and ends with the cause.
            detail = ((proc.stderr or "").strip() or (proc.stdout or "").strip())[
                -_STDERR_PREVIEW_CHARS:
            ]
            return error_response(
                tc_id,
                "run_zircolite",
                params,
                f"Zircolite exited {proc.returncode} and wrote no results file: {detail}",
                (time.monotonic() - t0) * 1000,
                error_type="tool_failed",
            )

        result = _parse_zircolite_output(results_path, events_path, log_format, sigma_level_filter)

        text_parts = [
            f"Zircolite {log_format} analysis of {events_path}",
            f"Total detections: {result['total_detections']}",
        ]
        for level, count in result.get("level_counts", {}).items():
            text_parts.append(f"  {level}: {count}")
        for kind, names in result["mitre_coverage"].items():
            if names:
                text_parts.append(f"MITRE {kind}: {', '.join(names)}")

        # Index the detections themselves, not just how many there were: the
        # source is called "zircolite.detections", so a search over the case
        # must be able to find a rule title, a MITRE technique or a matched
        # field, none of which the header lines above contain.
        detections: list[dict[str, Any]] = result["detections"]
        text_parts.extend(_detection_lines(detections))

        summary = extract_and_index(
            "\n".join(text_parts), "zircolite.detections", events_path, "zircolite"
        )

        # The index holds every detection; the response stays bounded.
        result["detections"] = detections[:_MAX_RESPONSE_DETECTIONS]
        summary.update(result)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_zircolite", params, summary, "zircolite.detections", elapsed)
