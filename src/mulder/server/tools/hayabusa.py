"""Hayabusa MCP tools for Sigma-rule EVTX detection.

Runs Hayabusa against extracted EVTX files and indexes the resulting
detection alerts into the case database.  All tools are read-only
with respect to evidence files.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path

from mulder.assets.paths import asset_path, asset_search_summary
from mulder.patterns import DISK_IMAGE_EXTS, is_external_ip
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

_HAYABUSA_DIRNAME = "hayabusa"
_HAYABUSA_TIMEOUT = 300


def _hayabusa_binary() -> str | None:
    """Resolve the Hayabusa executable: asset root first, then PATH.

    Asset root wins because the image and ``mulder setup`` both install a
    version-matched binary there, while a stray PATH entry may be anything.
    """
    candidate = asset_path(_HAYABUSA_DIRNAME, "hayabusa")
    if candidate is not None and os.access(candidate, os.X_OK):
        return str(candidate)
    return shutil.which("hayabusa")


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
    3. Without *image_path* only: any prior extraction directory (newest
       first) that still has files (in-memory cache).
    4. DB ``kv_store`` fallback (``evtx_extract_dir:{image_path}``, or
       ``evtx_extract_dir`` without *image_path*), for cross-process
       persistence when the server restarts between orchestrator phases.
    5. Inline EVTX extraction from *image_path* using the same TSK +
       carved-EVTX strategy as ``run_evtx_parser``.

    With *image_path* given, another image's directory is never returned:
    its logs would be reported, and indexed, as this image's.

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

    if not image_path:
        for d in reversed(list(_evtx_extract_dirs.values())):
            if Path(d).is_dir() and _dir_has_evtx(d):
                return d

    try:
        key = f"evtx_extract_dir:{image_path}" if image_path else "evtx_extract_dir"
        db_dir = get_ctx().db.get_kv(key) or ""
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

    hayabusa_bin = _hayabusa_binary()
    if hayabusa_bin is None:
        return error_response(
            tc_id,
            tool_name,
            params,
            "Hayabusa binary not found on PATH or under "
            f"{asset_search_summary(_HAYABUSA_DIRNAME, 'hayabusa')}. Run 'mulder setup'.",
            elapsed_ms=(time.monotonic() - t0) * 1000,
            error_type="binary_missing",
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

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        hayabusa_bin,
        "csv-timeline",
        "-d",
        resolved_dir,
        "-o",
        out_path,
        # out_path is pre-created above by NamedTemporaryFile, and Hayabusa
        # refuses to write over an existing file unless --clobber is given:
        # it prints "The file ... already exists" to stderr, writes nothing,
        # and still exits 0. Without this flag no scan ever runs.
        "--clobber",
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

        try:
            csv_text = Path(out_path).read_text(errors="replace")
        except OSError:
            csv_text = ""

        # The output path is pre-created above, so "the file exists" says
        # nothing about whether Hayabusa ran. Gate on content instead: a
        # non-zero exit that wrote no timeline produced no evidence, and
        # must not be reported as a scan that found nothing. Conjunctive on
        # purpose -- Hayabusa exits non-zero on an unreadable EVTX after
        # having already written detections for the rest, and those are kept.
        if proc.returncode != 0 and not csv_text.strip():
            detail = ((proc.stderr or "").strip() or (proc.stdout or "").strip())[
                :_PREVIEW_CHAR_LIMIT
            ]
            return error_response(
                tc_id,
                tool_name,
                params,
                f"Hayabusa exited {proc.returncode} and wrote no timeline: {detail}",
                elapsed_ms=(time.monotonic() - t0) * 1000,
                error_type="tool_failed",
            )
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


# ---------------------------------------------------------------------------
# Logon summary
# ---------------------------------------------------------------------------

# Not under "hayabusa.": run_hayabusa and the batch submitter treat any source
# with that prefix as the Sigma scan already done.
_LOGON_SOURCE = "logon.summary"
_LOGON_TOOL = "run_hayabusa_logon_summary"
_LOGON_ROWS_SHOWN = 15
_LOGON_COLUMNS = (
    "Target Account",
    "Target Domain",
    "Target Computer",
    "Logon Type",
    "Source Computer",
    "Source IP Address",
)
_LOGON_NOTE = (
    "Each row counts one combination of account, logon type and source over the whole "
    "log; Hayabusa 3.8.1 gives no first or last time per row (log_period is the span of "
    "all event records read), so search the Security log (events 4624, 4625) for when. "
    "A logon is not a compromise: type 5 and 0 are the "
    "machine's own services, and type 3 or 10 from an address the organisation does not "
    "use is a lead to check against the account's normal sources. external is null when "
    "the source is not an address that could be classified. No rows means no logon "
    "events in the logs that were read, not that nobody logged on: the Security log may "
    "be cleared, rolled over or absent."
)
# Account and computer names come from the event log, and a failed logon's
# account name is whatever the remote party typed.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Hayabusa 3.8.1 prints these three lines on stdout, with colour resets
# between the label and the colon even under --no-color.
_PERIOD_RE = re.compile(
    r"(First Timestamp|Last Timestamp|Total Event Records)[^:\n]*:\s*([0-9][0-9 :.+-]{0,40})"
)


def _is_external(address: str) -> bool | None:
    """Whether a logon's source address is public; None when it cannot be classified."""
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is None:
            return ip.is_global
        ip = ip.ipv4_mapped
    return is_external_ip(str(ip))


def _logon_table(csv_text: str) -> dict[str, object]:
    """Summarise one of Hayabusa's logon CSVs: totals, by type, and rows naming a source."""
    rows = [r for r in csv.reader(io.StringIO(csv_text)) if r]
    table: dict[str, object] = {
        "logons": 0,
        "combinations": 0,
        "by_logon_type": {},
        "with_source_address": [],
    }
    if len(rows) < 2 or not all(c in rows[0] for c in _LOGON_COLUMNS):
        return table
    header = rows[0]
    idx = {c: header.index(c) for c in _LOGON_COLUMNS}
    by_type: Counter[str] = Counter()
    combinations = 0
    sourced: list[tuple[int, int, dict[str, object]]] = []
    for row in rows[1:]:
        if len(row) != len(header) or not row[0].isdigit():
            continue
        row = [_CONTROL_RE.sub("?", cell)[:_PREVIEW_CHAR_LIMIT] for cell in row]
        count = int(row[0])
        combinations += 1
        by_type[row[idx["Logon Type"]]] += count
        address = row[idx["Source IP Address"]]
        if address not in ("", "-"):
            external = _is_external(address)
            fields: dict[str, object] = {"count": count, "external": external}
            fields.update({c: row[i] for c, i in idx.items()})
            # External first, then what could not be classified, then internal.
            rank = {True: 0, None: 1, False: 2}[external]
            sourced.append((rank, count, fields))
    sourced.sort(key=lambda s: (s[0], -s[1]))
    table.update(
        logons=sum(by_type.values()),
        combinations=combinations,
        by_logon_type=dict(by_type.most_common()),
        with_source_address=[fields for _e, _c, fields in sourced[:_LOGON_ROWS_SHOWN]],
    )
    if len(sourced) > _LOGON_ROWS_SHOWN:
        table["with_source_address_not_listed"] = len(sourced) - _LOGON_ROWS_SHOWN
    return table


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_hayabusa_logon_summary(
    evtx_dir: str = "",
    image_path: str = "",
    force: bool = False,
) -> dict[str, object]:
    """Summarise successful and failed Windows logons from EVTX files using Hayabusa.

    Call after run_evtx_parser on a Windows image, alongside run_hayabusa. It
    answers who logged on, how (logon type) and from which computer and
    address, with a count per combination, which Sigma alerts do not give.

    Indexes the full tables as ``logon.summary`` and returns totals, counts
    by logon type and the rows that name a source address, external addresses
    first. Counts cover the whole log (``log_period``) and carry no times of
    their own. A logon is not a compromise, and no rows is not no logons: the
    Security log may have been cleared or rolled over.

    Args:
        evtx_dir: Directory containing ``.evtx`` files. If empty, falls back
            to the directory created by ``run_evtx_parser``.
        image_path: Path to the disk image whose extracted EVTX directory
            should be used (as passed to ``run_evtx_parser``).
        force: Re-run even if the summary is already indexed.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"evtx_dir": evtx_dir, "image_path": image_path, "force": force}

    def _error(message: str, error_type: str = "unknown") -> dict[str, object]:
        elapsed = (time.monotonic() - t0) * 1000
        return error_response(tc_id, _LOGON_TOOL, params, message, elapsed, error_type=error_type)

    target = image_path or evtx_dir
    if not force:
        existing = sources_already_indexed([_LOGON_SOURCE], evidence_path=target or None)
        if existing:
            return tool_response(
                tc_id,
                _LOGON_TOOL,
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                _LOGON_SOURCE,
                0.0,
            )

    hayabusa_bin = _hayabusa_binary()
    if hayabusa_bin is None:
        return _error(
            "Hayabusa binary not found on PATH or under "
            f"{asset_search_summary(_HAYABUSA_DIRNAME, 'hayabusa')}. Run 'mulder setup'.",
            "binary_missing",
        )
    resolved_dir = _resolve_evtx_dir(evtx_dir or None, image_path=image_path or None)
    if not resolved_dir:
        return _error(
            "No EVTX directory found. Run run_evtx_parser on a disk image "
            "first, or provide an explicit evtx_dir path."
        )

    with tempfile.TemporaryDirectory(prefix="mulder_hayabusa_logon_") as tmpdir:
        prefix = str(Path(tmpdir) / "logon")
        # Verified against Hayabusa 3.8.1: -o is a prefix and the command writes
        # <prefix>-successful.csv and <prefix>-failed.csv. --quiet-errors keeps
        # it from writing ./logs/errorlog-*.log into the working directory.
        cmd = [hayabusa_bin, "logon-summary", "-d", resolved_dir, "-o", prefix]
        cmd += ["--clobber", "--quiet", "--quiet-errors", "--no-color", "--UTC"]
        # Without rules/config (eventkey_alias.txt) Hayabusa reads no logon
        # fields and reports "No logon events were detected" on any log.
        config = Path(hayabusa_bin).resolve().parent / "rules" / "config"
        if config.is_dir():
            cmd += ["--rules-config", str(config)]
        timeout = adaptive_timeout(image_path or resolved_dir, base=_HAYABUSA_TIMEOUT)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired:
            return _error(f"Hayabusa timed out after {timeout}s", "timeout")
        output = (proc.stdout or "") + (proc.stderr or "")
        if "eventkey_alias.txt" in output:
            return _error(
                "Hayabusa could not open rules/config/eventkey_alias.txt, so it cannot read "
                "logon events: the rules directory beside its binary is missing or empty. "
                "Nothing was examined.",
                "asset_missing",
            )
        tables: dict[str, str] = {}
        for kind in ("successful", "failed"):
            try:
                tables[kind] = Path(f"{prefix}-{kind}.csv").read_text(errors="replace")
            except OSError:
                tables[kind] = ""
    if proc.returncode != 0 and not any(t.strip() for t in tables.values()):
        detail = output.strip()[:_PREVIEW_CHAR_LIMIT]
        return _error(
            f"Hayabusa exited {proc.returncode} and wrote no summary: {detail}", "tool_failed"
        )

    summaries = {kind: _logon_table(table) for kind, table in tables.items()}
    result: dict[str, object] = {
        "source": _LOGON_SOURCE,
        **summaries,
        "evtx_dir": resolved_dir,
        "note": _LOGON_NOTE,
    }
    period = {label: value.strip() for label, value in _PERIOD_RE.findall(proc.stdout or "")}
    if period:
        result["log_period"] = {
            "first_timestamp": period.get("First Timestamp"),
            "last_timestamp": period.get("Last Timestamp"),
            "event_records": period.get("Total Event Records"),
        }
    if any(summary["combinations"] for summary in summaries.values()):
        text = "".join(
            f"# {kind} logons: count per account, logon type and source (no times)\n{table}\n"
            for kind, table in tables.items()
            if table.strip()
        )
        result["index"] = extract_and_index(
            text, _LOGON_SOURCE, target or resolved_dir, "hayabusa"
        )
    else:
        # Nothing is registered, so a later call reads the logs again instead
        # of being skipped as done on a log that could not be read this time.
        result["index"] = {"status": "not_indexed", "reason": "no logon rows"}
    return tool_response(tc_id, _LOGON_TOOL, params, result, None, (time.monotonic() - t0) * 1000)
