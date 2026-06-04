"""Hayabusa MCP tools for Sigma-rule EVTX detection.

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

from mulder.patterns import DISK_IMAGE_EXTS
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    _PREVIEW_CHAR_LIMIT,
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

logger = logging.getLogger(__name__)

_HAYABUSA_BIN = "/opt/hayabusa/hayabusa"
_HAYABUSA_TIMEOUT = 300
_VALID_SEVERITIES = ("informational", "low", "medium", "high", "critical")


def _dir_has_evtx(directory: str) -> bool:
    """Return True if *directory* contains at least one ``.evtx`` file."""
    return next(Path(directory).rglob("*.evtx"), None) is not None


def _resolve_evtx_dir(evtx_dir: str | None, image_path: str | None = None) -> str | None:
    """Return a valid EVTX directory path, or None.

    Each candidate is validated to contain at least one ``.evtx`` file
    before being accepted, so stale or empty extraction directories are
    skipped automatically.

    Resolution order:
    1. Explicit *evtx_dir* if it exists and contains EVTX files.
    2. Prior extraction from ``run_evtx_parser`` keyed by *image_path*
       (in-memory cache).
    3. Any prior extraction directory (newest first) that still has files
       (in-memory cache).
    4. DB ``kv_store`` fallback (``evtx_extract_dir:{image_path}`` then
       ``evtx_extract_dir``), for cross-process persistence when the
       server restarts between orchestrator phases.
    5. Inline EVTX extraction from *image_path* using the same TSK +
       carved-EVTX strategy as ``run_evtx_parser``.

    Args:
        evtx_dir: Explicit directory containing ``.evtx`` files.
        image_path: Disk image path; used for lookup or inline extraction.

    Returns:
        Path to a directory containing EVTX files, or None.
    """
    if evtx_dir and Path(evtx_dir).is_dir() and _dir_has_evtx(evtx_dir):
        return evtx_dir

    from mulder.server.tools.extract.evtx import _evtx_extract_dirs

    if image_path and image_path in _evtx_extract_dirs:
        d = _evtx_extract_dirs[image_path]
        if Path(d).is_dir() and _dir_has_evtx(d):
            return d

    for d in reversed(list(_evtx_extract_dirs.values())):
        if Path(d).is_dir() and _dir_has_evtx(d):
            return d

    try:
        ctx = get_ctx()
        if image_path:
            db_dir = ctx.db.get_kv(f"evtx_extract_dir:{image_path}")
            if db_dir and Path(db_dir).is_dir() and _dir_has_evtx(db_dir):
                return db_dir
        db_dir = ctx.db.get_kv("evtx_extract_dir") or ""
        if db_dir and Path(db_dir).is_dir() and _dir_has_evtx(db_dir):
            return db_dir
    except Exception:
        logger.debug("Failed to read evtx_extract_dir from DB kv_store", exc_info=True)

    if (
        image_path
        and Path(image_path).exists()
        and Path(image_path).suffix.lower() in DISK_IMAGE_EXTS
    ):
        return _extract_evtx_inline(image_path)

    return None


def _extract_evtx_inline(image_path: str) -> str | None:
    """Extract EVTX files from a disk image for Hayabusa analysis.

    Uses the same two-stage strategy as ``run_evtx_parser``: TSK
    icat extraction first, then a bulk_extractor carved-EVTX fallback.
    The extracted directory is registered in ``_evtx_extract_dirs`` so
    subsequent tools can reuse it.

    Args:
        image_path: Path to a disk image (E01, raw, dd).

    Returns:
        Path to the extraction directory, or None if no EVTX files found.
    """
    from mulder.server.tools.extract.evtx import (
        _evtx_extract_dirs,
        _extract_evtx_from_image,
        _find_carved_evtx,
    )

    logger.info(
        "Hayabusa: no prior EVTX extraction found; extracting inline from %s",
        image_path,
    )
    extract_dir = tempfile.mkdtemp(prefix="mulder_hayabusa_evtx_")
    evtx_files = _extract_evtx_from_image(image_path, extract_dir)
    if not evtx_files:
        evtx_files = _find_carved_evtx(extract_dir)
    if evtx_files:
        _evtx_extract_dirs[image_path] = extract_dir
        logger.info(
            "Hayabusa: extracted %d EVTX files from %s",
            len(evtx_files),
            image_path,
        )
        return extract_dir

    shutil.rmtree(extract_dir, ignore_errors=True)
    return None


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_hayabusa(
    evtx_dir: str = "",
    min_severity: str = "medium",
    image_path: str = "",
    force: bool = False,
) -> dict[str, object]:
    """Detect threats in EVTX files using 3,700+ Sigma rules via Hayabusa.

    Call immediately after run_evtx_parser to get a prioritized list of
    suspicious events with MITRE ATT&CK technique mappings. Automatically
    locates the EVTX extraction directory from the prior run_evtx_parser
    call. If no prior extraction exists and image_path is a disk image,
    extracts EVTX files inline.

    Indexes as ``hayabusa.alerts``; returns severity breakdown, top rules,
    and MITRE technique IDs. Use search(source='hayabusa.alerts') for
    detailed alert inspection.

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
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {
        "evtx_dir": evtx_dir,
        "min_severity": min_severity,
        "image_path": image_path,
        "force": force,
    }

    if not force:
        hayabusa_evidence = evtx_dir or image_path
        existing = sources_already_indexed(["hayabusa."], evidence_path=hayabusa_evidence or None)
        if existing:
            return tool_response(
                tc_id,
                "run_hayabusa",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "hayabusa.alerts",
                0.0,
            )
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

    timeout = adaptive_timeout(image_path or resolved_dir, base=_HAYABUSA_TIMEOUT)
    try:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                tool_name,
                params,
                f"Hayabusa timed out after {timeout}s",
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
        return tool_response(
            tc_id,
            tool_name,
            params,
            {
                "total_alerts": 0,
                "by_severity": {},
                "top_rules": [],
                "mitre_techniques": [],
                "evtx_dir": resolved_dir,
                "evtx_file_count": len(evtx_files),
            },
            "hayabusa.alerts",
            elapsed,
        )

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
    result: dict[str, object] = {
        "total_alerts": len(alerts),
        "by_severity": dict(severity_counts),
        "top_rules": top_rules,
        "mitre_techniques": sorted(techniques),
        "evtx_dir": resolved_dir,
        "evtx_file_count": len(evtx_files),
        "index": index_result,
    }

    return tool_response(tc_id, tool_name, params, result, "hayabusa.alerts", elapsed)


def _parse_hayabusa_csv(csv_text: str) -> list[dict[str, str]]:
    """Parse Hayabusa CSV output into a list of alert dicts."""
    reader = csv.DictReader(io.StringIO(csv_text))
    alerts: list[dict[str, str]] = []
    for row in reader:
        alerts.append(dict(row))
    return alerts
