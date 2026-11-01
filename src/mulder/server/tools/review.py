"""MCP tools for post-investigation self-correction.

These tools help the agent identify its own blind spots before
finalizing a report: evidence that was indexed but never cited in
a finding, and applicable forensic tools that were never invoked.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections import defaultdict
from pathlib import Path

from mulder.db import CaseDB
from mulder.extractors.classifier import ClassifierConfig, EvidenceClassifier
from mulder.patterns import (
    EMAIL_RE,
    IP_RE,
    UNIX_PATH_RE,
    WIN_PATH_RE,
    classify_ip,
    source_is_cited,
)
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import hash_output, make_tool_call_id
from mulder.server.tool_access import ANALYSTS, Role, tool_access
from mulder.server.tools.findings import _evaluate_finalize_gates

logger = logging.getLogger(__name__)

_EVIDENCE_TOOL_MAP: dict[str, list[str]] = {
    "memory_dump": [
        "run_volatility",
        "run_volatility_batch",
        "yara_scan_memory",
    ],
    "disk_image": [
        "run_fls",
        "run_bulk_extractor",
        "run_mmls",
        "yara_scan_files",
        "run_plaso",
        "detect_steganography",
        "run_optical_listing",
    ],
    "network_capture": [
        "run_pcap_analysis",
    ],
    "netflow_capture": [
        "run_netflow_analysis",
    ],
    "evtx": [
        "run_evtx_parser",
        "run_hayabusa",
        "index_evtx_file",
    ],
    "compressed_archive": [
        "extract_archive",
    ],
    "sqlite_database": [
        "query_sqlite_from_image",
    ],
    "phone_dump": [
        "run_fls",
        "run_bulk_extractor",
    ],
    "phone_database": [
        "query_sqlite_from_image",
    ],
    "ios_backup": [
        "run_fls",
        "run_bulk_extractor",
    ],
}

# Parameters that name the evidence a mapped tool reads. Output locations
# such as extract_to and auxiliary inputs such as ssl_keylog_path are left
# out, so a call is credited only to the evidence it was run on.
_EVIDENCE_INPUT_PARAMS: dict[str, tuple[str, ...]] = {
    "run_netflow_analysis": ("evidence_path",),
    "run_volatility": ("memory_path",),
    "run_volatility_batch": ("memory_path",),
    "run_fls": ("image_path",),
    "run_bulk_extractor": ("image_path",),
    "run_mmls": ("image_path",),
    "yara_scan_files": ("target_path",),
    "run_plaso": ("evidence_path",),
    "detect_steganography": ("target_path",),
    "run_optical_listing": ("image_path",),
    "run_pcap_analysis": ("pcap_path",),
    "run_evtx_parser": ("evtx_path",),
    "run_hayabusa": ("evtx_dir",),
    "index_evtx_file": (),
    "extract_archive": ("archive_path",),
}

# index_evtx_file's image_path names the source image of a prior extraction,
# not the EVTX file that was read. It blocks name-based fallback without
# crediting paths that happen to share its spelling.
_EVIDENCE_SELECTOR_PARAMS: dict[str, tuple[str, ...]] = {
    "index_evtx_file": ("image_path",),
}

# These tools can find evidence from case metadata or prior extractions.
# Preserve name-based coverage only when none of a tool's logged calls
# supplies an explicit evidence-input path or source-image selector.
# An unmatched target must never enable this fallback.
_IMPLICIT_INPUT_TOOLS = frozenset(
    {
        "yara_scan_memory",
        "query_sqlite_from_image",
        "index_evtx_file",
    }
)

_MAX_SAMPLE_WINDOWS = 3
_MAX_SAMPLE_TEXT_LEN = 300


def _get_source_samples(db: CaseDB, source_name: str) -> list[str]:
    """Return truncated text samples from the first few windows of a source."""
    windows = db.get_windows_by_source(source_name)
    samples: list[str] = []
    for w in windows[:_MAX_SAMPLE_WINDOWS]:
        text = w.raw_text
        if len(text) > _MAX_SAMPLE_TEXT_LEN:
            text = text[:_MAX_SAMPLE_TEXT_LEN] + "..."
        samples.append(text)
    return samples


def _path_forms(value: str | Path, *, expand_user: bool = False) -> set[Path]:
    """A path as written (made absolute) and its resolved form.

    The audit log keeps tool arguments as the model passed them, while the
    evidence list holds paths under the resolved evidence root, so either
    side may name a symlink. Expand ``~`` only for inputs whose tool does so.
    """
    path = Path(value)
    try:
        if expand_user:
            path = path.expanduser()
        path = path.absolute()
        return {path, path.resolve()}
    except (OSError, RuntimeError, ValueError):
        return {path.absolute()}


@mcp.tool()
@tool_access(Role.NARRATIVE_PLANNER | Role.NARRATIVE_ANALYST | Role.REPORT)
def audit_evidence_coverage() -> dict[str, object]:
    """Identify indexed evidence sources not cited by any submitted finding.

    Call before finalize_report to catch blind spots. Requires at least
    some findings to have been submitted for meaningful results.

    Returns uncited sources grouped by extractor, with content samples.
    Review each uncited source with search() to verify nothing relevant
    was overlooked.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    sources = ctx.db.get_sources()
    findings = ctx.db.get_findings()

    finding_sources: set[str] = set()
    for f in findings:
        finding_sources.update(f.sources)

    cited: list[dict[str, object]] = []
    uncited: list[dict[str, object]] = []

    for src in sources:
        entry: dict[str, object] = {
            "source_name": src.source_name,
            "extractor": src.extractor,
            "line_count": src.line_count,
        }

        if source_is_cited(src.source_name, finding_sources):
            cited.append(entry)
        else:
            if src.line_count > 0:
                entry["samples"] = _get_source_samples(ctx.db, src.source_name)
            uncited.append(entry)

    by_extractor: dict[str, list[dict[str, object]]] = defaultdict(list)
    for u in uncited:
        by_extractor[str(u["extractor"])].append(u)

    total = len(sources)
    coverage_pct = round(len(cited) / total * 100, 1) if total else 100.0

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "total_sources": total,
        "cited_count": len(cited),
        "uncited_count": len(uncited),
        "coverage_pct": coverage_pct,
        "uncited_sources": dict(by_extractor),
        "hint": (
            "Review each uncited source. For sources with content, use "
            "search(query, source=source_name) to check for relevant evidence. "
            "Either submit a finding or document why the source is not relevant."
        ),
    }

    if invalid := ctx.db.get_invalid_findings():
        result["invalid_findings"] = invalid
    if coverage_pct < 50:
        result["warning"] = (
            f"Only {coverage_pct:.0f}% of sources are cited by findings. "
            f"Review uncited sources with content for relevant evidence. "
            f"Not every source needs a finding, but sources with significant "
            f"content should be reviewed."
        )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="audit_evidence_coverage",
        params={},
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


@mcp.tool()
@tool_access(Role.NARRATIVE_PLANNER | Role.NARRATIVE_ANALYST | Role.REPORT)
def audit_tool_coverage() -> dict[str, object]:
    """Report applicable forensic tools that were never invoked during the investigation.

    Call before finalize_report to ensure no applicable analysis was
    skipped. Re-classifies the evidence directory and compares applicable
    tools against the audit log. A call counts for an evidence item only
    when one of the tool's evidence-input parameters names that item or a
    directory holding it; a path that matches no item counts for none.
    Tools that can pick their input themselves count by name only while
    none of their calls names an input path or a source image.

    Returns per-evidence-item tool coverage with tools_run and
    tools_not_run lists, plus total_gaps count.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    case_metadata = ctx.db.get_case_metadata()
    evidence_root = Path(case_metadata.evidence_root)

    if not evidence_root.exists():
        result: dict[str, object] = {
            "tool_call_id": tc_id,
            "status": "error",
            "error": f"Evidence path no longer accessible: {evidence_root}",
        }
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="audit_tool_coverage",
            params={},
            output_hash=hash_output(result),
            duration_ms=elapsed,
        )
        return result

    classifier = EvidenceClassifier(ClassifierConfig())
    classified = classifier.classify(evidence_root)

    evidence = [
        form
        for ev in classified
        if ev.artifact_type in _EVIDENCE_TOOL_MAP
        for form in _path_forms(ev.path)
    ]
    targets: dict[str, set[Path]] = defaultdict(set)
    tools_with_explicit_targets: set[str] = set()
    for entry in ctx.audit.tool_call_entries():
        params = entry.get("params")
        tool_name = str(entry.get("tool_name"))
        hits = targets[tool_name]
        if not isinstance(params, dict):
            continue
        for key in _EVIDENCE_SELECTOR_PARAMS.get(tool_name, ()):
            value = params.get(key)
            if isinstance(value, str) and value:
                tools_with_explicit_targets.add(tool_name)
        for key in _EVIDENCE_INPUT_PARAMS.get(tool_name, ()):
            value = params.get(key)
            if isinstance(value, str) and value:
                tools_with_explicit_targets.add(tool_name)
                # Hayabusa ignores an evtx_dir that is not a directory.
                if tool_name == "run_hayabusa" and not os.path.isdir(value):
                    continue
                for path in _path_forms(value, expand_user=tool_name == "extract_archive"):
                    if any(e.is_relative_to(path) for e in evidence):
                        hits.add(path)

    items: list[dict[str, object]] = []
    total_gaps = 0

    # nfcapd files are classified one by one; report their exporter directory once, and count
    # run_netflow_analysis as run for a directory only when a COMPLETED summary source exists
    # for that directory (or a parent the extractor was pointed at): its header row stored with
    # status=success, so neither a partial run nor a summary whose rows were never written counts
    analysis_paths = {
        s.source_path
        for s in ctx.db.get_sources()
        if s.source_name.startswith("netflow.analysis.")
        and any(
            " status=success" in str(w.raw_text)
            for w in ctx.db.get_windows_by_source(s.source_name)[:1]
        )
    }
    netflow_dirs: dict[str, int] = {}
    for ev in classified:
        if ev.artifact_type == "netflow_capture":
            parent = str(ev.path.parent)
            netflow_dirs[parent] = netflow_dirs.get(parent, 0) + 1

    seen_netflow_dirs: set[str] = set()
    for ev in classified:
        applicable = _EVIDENCE_TOOL_MAP.get(ev.artifact_type, [])
        if not applicable:
            continue

        item_path = str(ev.path)
        files: int | None = None
        if ev.artifact_type == "netflow_capture":
            item_path = str(ev.path.parent)
            if item_path in seen_netflow_dirs:
                continue
            seen_netflow_dirs.add(item_path)
            files = netflow_dirs[item_path]
            covered = any(
                item_path == p or item_path.startswith(p.rstrip("/") + "/") for p in analysis_paths
            )
            run = list(applicable) if covered else []
        else:
            forms = _path_forms(ev.path)
            run = [
                t
                for t in applicable
                if t in targets
                and (
                    (t in _IMPLICIT_INPUT_TOOLS and t not in tools_with_explicit_targets)
                    or any(f.is_relative_to(p) for f in forms for p in targets[t])
                )
            ]
        not_run = [t for t in applicable if t not in run]
        total_gaps += len(not_run)

        item: dict[str, object] = {
            "path": item_path,
            "artifact_type": ev.artifact_type,
            "tools_run": run,
            "tools_not_run": not_run,
        }
        if files is not None:
            item["files"] = files
        items.append(item)

    result = {
        "tool_call_id": tc_id,
        "status": "success",
        "evidence_items": len(items),
        "total_gaps": total_gaps,
        "coverage": items,
        "hint": (
            "For each tool in tools_not_run, either run the tool now or "
            "document why it was skipped (not applicable, covered by an "
            "equivalent tool, etc.)."
        ),
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="audit_tool_coverage",
        params={},
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


@mcp.tool()
@tool_access(Role.NARRATIVE_PLANNER | Role.NARRATIVE_ANALYST | Role.REPORT, unthrottled=True)
def check_finalize_readiness() -> dict[str, object]:
    """Check whether the investigation meets all finalize_report requirements.

    Returns a detailed checklist of all gates that finalize_report will
    enforce, with pass/fail status for each. Call this before
    finalize_report to identify remaining work.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    findings = ctx.db.get_findings()
    case_metadata = ctx.db.get_case_metadata()
    sources = ctx.db.get_sources()
    audit_summary = ctx.audit.summary()

    gate_results = _evaluate_finalize_gates(findings, case_metadata, sources, audit_summary)
    all_passed = all(g["passed"] for g in gate_results)

    if all_passed:
        action = "All gates pass. You may call finalize_report."
    else:
        failing = [str(g["name"]) for g in gate_results if not g["passed"]]
        action = f"Fix failing gate(s) before calling finalize_report: {failing}"

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "ready_to_finalize": all_passed,
        "gates": gate_results,
        "action": action,
    }
    if invalid := ctx.db.get_invalid_findings():
        result["invalid_findings"] = invalid
        result["action"] = (
            f"{action} Also fix invalid finding(s) excluded from the report "
            f"{[i['finding_id'] for i in invalid]}: update_finding with valid "
            "evidence_refs, or delete_finding."
        )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="check_finalize_readiness",
        params={},
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


@mcp.tool()
@tool_access(ANALYSTS)
def track_progress(
    system_name: str,
    tools_completed: list[str],
    questions_addressed: list[str],
    notes: str = "",
) -> dict[str, object]:
    """Record investigation progress for a specific system.

    Call this after completing analysis of each system to track which
    tools were run and which investigation questions were addressed.
    Progress records persist in the database and survive context
    compaction.

    Args:
        system_name: Name of the system or evidence source analyzed.
        tools_completed: List of tool names that were run.
        questions_addressed: List of investigation questions covered.
        notes: Optional free-text notes about this analysis step.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    ctx.db.record_progress(system_name, tools_completed, questions_addressed, notes)
    summary = ctx.db.get_progress_summary()

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "accepted",
        "system_name": system_name,
        "progress_summary": summary,
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="track_progress",
        params={
            "system_name": system_name,
            "tools_completed": tools_completed,
            "questions_addressed": questions_addressed,
        },
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


@mcp.tool()
@tool_access(
    Role.EXTRACT_ANALYST
    | Role.CROSS_PLANNER
    | Role.CROSS_ANALYST
    | Role.NARRATIVE_PLANNER
    | Role.NARRATIVE_ANALYST
    | Role.REPORT,
    unthrottled=True,
)
def get_investigation_summary() -> dict[str, object]:
    """Return a compact progress dashboard for the current investigation.

    Call periodically during analysis to stay oriented, or after context
    compaction to recover overall investigation state. No prerequisites.

    Returns sources indexed, findings by severity, finalize readiness
    gates, and a remaining_work checklist of outstanding tasks.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    sources = ctx.db.get_sources()
    findings = ctx.db.get_findings()

    extractors_used: set[str] = set()
    for s in sources:
        extractors_used.add(s.extractor)

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    has_mitre = sum(1 for f in findings if f.mitre_attack_ids)
    has_negative = sum(1 for f in findings if f.title.startswith("[NEGATIVE]"))
    has_timestamps = sum(1 for f in findings if f.event_time_start)

    batch_info: dict[str, object] = {
        "note": "Use check_extraction_status(batch_id) for details",
    }

    case_metadata = ctx.db.get_case_metadata()
    audit_summary = ctx.audit.summary()

    gate_results = _evaluate_finalize_gates(findings, case_metadata, sources, audit_summary)
    all_passed = all(g["passed"] for g in gate_results)
    blockers: list[str] = [f"{g['name']}: {g['detail']}" for g in gate_results if not g["passed"]]

    remaining_work: list[str] = []
    non_negative = [f for f in findings if not f.title.startswith("[NEGATIVE]")]
    if any(not f.event_time_start for f in non_negative):
        remaining_work.append("Add timestamps to non-negative findings missing event_time_start")
    if not (case_metadata.narrative and case_metadata.narrative.strip()):
        remaining_work.append("Submit investigation narrative via submit_narrative")
    tool_counts = audit_summary.tool_call_counts
    if "audit_evidence_coverage" not in tool_counts:
        remaining_work.append("Run audit_evidence_coverage to check for uncited sources")
    if "audit_tool_coverage" not in tool_counts:
        remaining_work.append("Run audit_tool_coverage to verify all applicable tools were used")
    invalid = ctx.db.get_invalid_findings()
    if invalid:
        remaining_work.append(
            f"Fix invalid finding(s) {[i['finding_id'] for i in invalid]} with "
            "update_finding (valid evidence_refs) or delete_finding"
        )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_investigation_summary",
        params={},
        output_hash=hash_output({}),
        duration_ms=elapsed,
    )

    return {
        "tool_call_id": tc_id,
        "status": "success",
        "sources_indexed": len(sources),
        "unique_source_types": sorted(extractors_used),
        "findings_submitted": len(findings),
        "findings_by_severity": severity_counts,
        "findings_with_mitre_ids": has_mitre,
        "findings_with_timestamps": has_timestamps,
        "negative_findings": has_negative,
        "extraction_batches": batch_info,
        "remaining_work": remaining_work,
        "ready_to_finalize": all_passed,
        "finalize_blockers": blockers if blockers else "none",
        "elapsed_ms": round(elapsed, 1),
        **({"invalid_findings": invalid} if invalid else {}),
    }


_URL_RE = re.compile(r"https?://[^\s\"'>]+")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_USER_RE = re.compile(r"\b(?:NT AUTHORITY|BUILTIN)\\[\w$]+\b|\b[\w]+\\[\w$]+\b")

_NOISE_DOMAINS = frozenset({"microsoft.com", "windows.com", "windowsupdate.com"})


@mcp.tool()
@tool_access(Role.CROSS_ANALYST | Role.NARRATIVE_ANALYST | Role.REPORT)
def get_ioc_summary() -> dict[str, object]:
    """Extract and deduplicate IOCs from findings and bulk_extractor data.

    Scans all submitted findings for IP addresses, domains, email
    addresses, file paths, and user accounts. Also checks bulk_extractor
    outputs (bulk.email, bulk.url, bulk.domain) if indexed. Returns
    categorized, deduplicated IOC lists. Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    findings = ctx.db.get_findings()
    sources = ctx.db.get_sources()

    ips: set[str] = set()
    emails: set[str] = set()
    domains: set[str] = set()
    file_paths: set[str] = set()
    user_accounts: set[str] = set()

    for f in findings:
        text_blob = f"{f.title}\n{f.description}"
        ips.update(IP_RE.findall(text_blob))
        emails.update(EMAIL_RE.findall(text_blob))
        file_paths.update(WIN_PATH_RE.findall(text_blob))
        file_paths.update(UNIX_PATH_RE.findall(text_blob))
        user_accounts.update(_USER_RE.findall(text_blob))
        for url in _URL_RE.findall(text_blob):
            match = re.match(r"https?://([^/:]+)", url)
            if match:
                domains.add(match.group(1).lower())

    bulk_sources = {s.source_name for s in sources}
    _BULK_LIMIT = 200

    if "bulk.email" in bulk_sources:
        windows = ctx.db.get_windows_by_source("bulk.email")
        for w in windows[:_BULK_LIMIT]:
            emails.update(EMAIL_RE.findall(w.raw_text))

    if "bulk.url" in bulk_sources:
        windows = ctx.db.get_windows_by_source("bulk.url")
        for w in windows[:_BULK_LIMIT]:
            for url in _URL_RE.findall(w.raw_text):
                match = re.match(r"https?://([^/:]+)", url)
                if match:
                    domains.add(match.group(1).lower())

    if "bulk.domain" in bulk_sources:
        windows = ctx.db.get_windows_by_source("bulk.domain")
        for w in windows[:_BULK_LIMIT]:
            domains.update(_DOMAIN_RE.findall(w.raw_text))

    public_ips = sorted(ip for ip in ips if classify_ip(ip) == "public")
    private_ips = sorted(ip for ip in ips if classify_ip(ip) != "public")
    filtered_domains = sorted(d for d in domains if d not in _NOISE_DOMAINS and "." in d)

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "ip_addresses": {
            "public": public_ips,
            "private": private_ips,
        },
        "domains": filtered_domains,
        "email_addresses": sorted(emails),
        "file_paths": sorted(file_paths),
        "user_accounts": sorted(user_accounts),
        "total_unique_iocs": (
            len(public_ips)
            + len(private_ips)
            + len(filtered_domains)
            + len(emails)
            + len(file_paths)
            + len(user_accounts)
        ),
    }
    if invalid := ctx.db.get_invalid_findings():
        result["invalid_findings"] = invalid

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_ioc_summary",
        params={},
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    result["elapsed_ms"] = round(elapsed, 1)
    return result
