"""MCP tools for post-investigation self-correction.

These tools help the agent identify its own blind spots before
finalizing a report: evidence that was indexed but never cited in
a finding, and applicable forensic tools that were never invoked.
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from pathlib import Path

from mulder.extractors.classifier import ClassifierConfig, EvidenceClassifier
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import hash_output, make_tool_call_id

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
    ],
    "network_capture": [
        "run_pcap_analysis",
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

_MAX_SAMPLE_WINDOWS = 3
_MAX_SAMPLE_TEXT_LEN = 300


def _get_source_samples(db: object, source_name: str) -> list[str]:
    """Return truncated text samples from the first few windows of a source."""
    windows = db.get_windows_by_source(source_name)  # type: ignore[attr-defined]
    samples: list[str] = []
    for w in windows[:_MAX_SAMPLE_WINDOWS]:
        text = w.raw_text
        if len(text) > _MAX_SAMPLE_TEXT_LEN:
            text = text[:_MAX_SAMPLE_TEXT_LEN] + "..."
        samples.append(text)
    return samples


def _source_is_cited(source_name: str, finding_sources: set[str]) -> bool:
    """Check if a source is cited by any finding using substring matching.

    Findings cite shorthand like ``"bulk.email (carry-tablet)"`` while
    DB sources are stored as ``"bulk.email"``, so we match if the
    source_name appears as a substring of any finding source string,
    or vice versa.
    """
    return any(source_name in fs or fs in source_name for fs in finding_sources)


@mcp.tool()
def audit_evidence_coverage() -> dict[str, object]:
    """Identify indexed evidence sources not cited by any finding.

    Returns a list of sources that were extracted and indexed but never
    referenced in a submitted finding.  Each uncited source includes a
    sample of its content so you can assess whether it contains relevant
    evidence that was overlooked.

    Run this before ``finalize_report()`` to catch blind spots.
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

        if _source_is_cited(src.source_name, finding_sources):
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
def audit_tool_coverage() -> dict[str, object]:
    """Report applicable forensic tools that were never invoked.

    Re-classifies the evidence directory and compares the applicable
    tools for each artifact type against the tools actually invoked
    (from the audit log).  Returns per-item coverage and a list of gaps.

    Run this before ``finalize_report()`` to ensure no applicable
    analysis was skipped.
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

    audit_summary = ctx.audit.summary()
    tools_invoked = set(audit_summary.tool_call_counts.keys())

    items: list[dict[str, object]] = []
    total_gaps = 0

    for ev in classified:
        applicable = _EVIDENCE_TOOL_MAP.get(ev.artifact_type, [])
        if not applicable:
            continue

        run = [t for t in applicable if t in tools_invoked]
        not_run = [t for t in applicable if t not in tools_invoked]
        total_gaps += len(not_run)

        items.append(
            {
                "path": str(ev.path),
                "artifact_type": ev.artifact_type,
                "tools_run": run,
                "tools_not_run": not_run,
            }
        )

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
def get_investigation_summary() -> dict[str, object]:
    """Return a compact progress dashboard for the current investigation.

    Shows systems analyzed, findings by severity, extraction batch
    status, and investigation question coverage. Call this periodically
    to stay oriented during long investigations. Read-only.
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
        "elapsed_ms": round(elapsed, 1),
    }


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_URL_RE = re.compile(r"https?://[^\s\"'>]+")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_WIN_PATH_RE = re.compile(r"[A-Z]:\\[^\s\"'<>|]+", re.IGNORECASE)
_UNIX_PATH_RE = re.compile(r"/(?:usr|etc|tmp|var|home|opt|root)/[^\s\"'<>|]+")
_USER_RE = re.compile(r"\b(?:NT AUTHORITY|BUILTIN)\\[\w$]+\b|\b[\w]+\\[\w$]+\b")

_PRIVATE_IP_PREFIXES = ("10.", "127.", "169.254.", "192.168.")
_NOISE_DOMAINS = frozenset({"microsoft.com", "windows.com", "windowsupdate.com"})


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP is in a private or loopback range."""
    if any(ip.startswith(p) for p in _PRIVATE_IP_PREFIXES):
        return True
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "172":
        second = int(parts[1])
        if 16 <= second <= 31:
            return True
    return False


@mcp.tool()
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
        ips.update(_IP_RE.findall(text_blob))
        emails.update(_EMAIL_RE.findall(text_blob))
        file_paths.update(_WIN_PATH_RE.findall(text_blob))
        file_paths.update(_UNIX_PATH_RE.findall(text_blob))
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
            emails.update(_EMAIL_RE.findall(w.raw_text))

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

    public_ips = sorted(ip for ip in ips if not _is_private_ip(ip))
    private_ips = sorted(ip for ip in ips if _is_private_ip(ip))
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
