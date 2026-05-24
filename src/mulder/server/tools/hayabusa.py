"""Hayabusa MCP tools for Sigma-rule-based EVTX detection.

Runs Hayabusa against extracted EVTX files and indexes the resulting
detection alerts into the case database.  All tools are read-only
with respect to evidence files.
"""

from __future__ import annotations

import csv
import io
import logging
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path

from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    _PREVIEW_CHAR_LIMIT,
    error_response,
    hash_output,
    make_tool_call_id,
)

logger = logging.getLogger(__name__)

_HAYABUSA_BIN = "/opt/hayabusa/hayabusa"
_HAYABUSA_TIMEOUT = 300
_VALID_SEVERITIES = ("informational", "low", "medium", "high", "critical")


def _resolve_evtx_dir(evtx_dir: str | None, image_path: str | None = None) -> str | None:
    """Return a valid EVTX directory path, or None.

    Checks *evtx_dir* first, then looks up *image_path* in the
    per-image extraction dict, and finally falls back to the most
    recently extracted directory.
    """
    if evtx_dir and Path(evtx_dir).is_dir():
        return evtx_dir

    from mulder.server.tools.extract.evtx import _evtx_extract_dirs

    if image_path and image_path in _evtx_extract_dirs:
        d = _evtx_extract_dirs[image_path]
        if Path(d).is_dir():
            return d
    if _evtx_extract_dirs:
        d = next(reversed(_evtx_extract_dirs.values()))
        if Path(d).is_dir():
            return d

    return None


@mcp.tool()
def run_hayabusa(
    evtx_dir: str = "",
    min_severity: str = "medium",
    image_path: str = "",
) -> dict[str, object]:
    """Scan EVTX files with Hayabusa against 3,700+ Sigma detection rules.

    Runs the Hayabusa Sigma rule engine against all ``.evtx`` files in a
    directory.  Returns detection alerts with severity levels and MITRE
    ATT&CK technique mappings.  Results are indexed into the case DB as
    ``hayabusa.alerts`` for subsequent searching.

    Run this **immediately after** ``run_evtx_parser`` for each disk
    image to get a prioritised list of suspicious events before manual
    EVTX analysis.  Each ``run_evtx_parser`` call stores its extracted
    EVTX directory keyed by image path, so pass *image_path* to target
    a specific extraction when multiple images have been processed.

    Args:
        evtx_dir: Directory containing ``.evtx`` files.  If empty, falls
            back to the directory created by ``run_evtx_parser``.
        min_severity: Minimum alert severity to include.  One of
            ``"informational"``, ``"low"``, ``"medium"`` (default),
            ``"high"``, ``"critical"``.
        image_path: Path to the disk image whose extracted EVTX directory
            should be used.  Only needed when *evtx_dir* is empty and
            multiple images have been processed.  Matches the path
            previously passed to ``run_evtx_parser``.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"evtx_dir": evtx_dir, "min_severity": min_severity, "image_path": image_path}
    tool_name = "run_hayabusa"

    if not shutil.which("hayabusa") and not Path(_HAYABUSA_BIN).exists():
        return error_response(
            tc_id,
            tool_name,
            params,
            f"Hayabusa binary not found. Ensure it is installed at {_HAYABUSA_BIN} or on PATH.",
            elapsed_ms=(time.monotonic() - t0) * 1000,
        )

    resolved_dir = _resolve_evtx_dir(evtx_dir or None, image_path=image_path or None)
    if not resolved_dir:
        return error_response(
            tc_id,
            tool_name,
            params,
            "No EVTX directory found. Run run_evtx_parser on a disk image "
            "first, or provide an explicit evtx_dir path.",
            elapsed_ms=(time.monotonic() - t0) * 1000,
        )

    evtx_files = list(Path(resolved_dir).rglob("*.evtx"))
    if not evtx_files:
        return error_response(
            tc_id,
            tool_name,
            params,
            f"No .evtx files found in {resolved_dir}",
            elapsed_ms=(time.monotonic() - t0) * 1000,
        )

    severity = min_severity.lower()
    if severity not in _VALID_SEVERITIES:
        severity = "medium"

    hayabusa_bin = (
        _HAYABUSA_BIN
        if Path(_HAYABUSA_BIN).exists()
        else shutil.which("hayabusa") or _HAYABUSA_BIN
    )

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        hayabusa_bin,
        "csv-timeline",
        "-d",
        resolved_dir,
        "-o",
        out_path,
        "-p",
        "super-verbose",
        "--no-wizard",
        "-m",
        severity,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_HAYABUSA_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            tool_name,
            params,
            f"Hayabusa timed out after {_HAYABUSA_TIMEOUT}s",
            elapsed_ms=(time.monotonic() - t0) * 1000,
        )

    if proc.returncode != 0 and not Path(out_path).exists():
        stderr_preview = (proc.stderr or "")[:_PREVIEW_CHAR_LIMIT]
        return error_response(
            tc_id,
            tool_name,
            params,
            f"Hayabusa exited {proc.returncode}: {stderr_preview}",
            elapsed_ms=(time.monotonic() - t0) * 1000,
        )

    try:
        csv_text = Path(out_path).read_text(errors="replace")
    except OSError:
        csv_text = ""
    finally:
        Path(out_path).unlink(missing_ok=True)

    if not csv_text.strip():
        elapsed = (time.monotonic() - t0) * 1000
        result: dict[str, object] = {
            "total_alerts": 0,
            "by_severity": {},
            "top_rules": [],
            "mitre_techniques": [],
            "evtx_dir": resolved_dir,
            "evtx_file_count": len(evtx_files),
        }
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name=tool_name,
            params=params,
            output_hash=hash_output(result),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "success",
            "results": result,
            "source": "hayabusa.alerts",
        }

    alerts = _parse_hayabusa_csv(csv_text)

    index_result = extract_and_index(
        raw_output=csv_text,
        source_name="hayabusa.alerts",
        source_path=resolved_dir,
        extractor_name="hayabusa",
    )

    severity_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    techniques: set[str] = set()

    for alert in alerts:
        sev = alert.get("Level", "unknown").lower()
        severity_counts[sev] += 1

        rule = alert.get("RuleTitle", "")
        if rule:
            rule_counts[rule] += 1

        mitre = alert.get("MitreAttack", "") or alert.get("MITRE ATT&CK", "")
        if mitre:
            for part in mitre.split(","):
                tid = part.strip()
                if tid:
                    techniques.add(tid)

    top_rules = [{"rule": name, "count": count} for name, count in rule_counts.most_common(10)]

    elapsed = (time.monotonic() - t0) * 1000
    result = {
        "total_alerts": len(alerts),
        "by_severity": dict(severity_counts),
        "top_rules": top_rules,
        "mitre_techniques": sorted(techniques),
        "evtx_dir": resolved_dir,
        "evtx_file_count": len(evtx_files),
        "index": index_result,
    }

    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=tool_name,
        params=params,
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": result,
        "source": "hayabusa.alerts",
    }


def _parse_hayabusa_csv(csv_text: str) -> list[dict[str, str]]:
    """Parse Hayabusa CSV output into a list of alert dicts."""
    reader = csv.DictReader(io.StringIO(csv_text))
    alerts: list[dict[str, str]] = []
    for row in reader:
        alerts.append(dict(row))
    return alerts
