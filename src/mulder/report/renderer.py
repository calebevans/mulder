"""Jinja2 report renderer for Mulder investigation reports."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jinja2
import markdown

from mulder.models import AuditSummary, CaseMetadataRow, Finding, SourceRow

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IP_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d+)\b")
_PORT_RE = re.compile(r"\bport\s+(\d+)\b", re.IGNORECASE)
_PATH_RE = re.compile(
    r"(?:C:\\[A-Za-z]|/(?:usr|var|etc|home|root|Windows|Users|System(?:/Library)?))"
    r"[^\s,\"'`*:]+[^\s,\"'`*:.)]"
)
_HASH_RE = re.compile(r"\b(?:SHA1|SHA256|MD5)[:\s]+([a-fA-F0-9]{32,64})\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
_PRIVATE_RANGES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
)


def _is_external_ip(ip: str) -> bool:
    """Return True if *ip* is not covered by common private IPv4 prefixes."""
    return not any(ip.startswith(p) for p in _PRIVATE_RANGES)


def _extract_iocs(
    findings: list[Finding],
) -> tuple[
    list[dict[str, str]],
    list[dict[str, str]],
    list[dict[str, str]],
]:
    """Extract network, file, and email IOCs from finding descriptions.

    Returns ``(network_iocs, file_iocs, email_iocs)``, deduplicated across
    findings with the first occurrence's context kept.
    """
    network_iocs: list[dict[str, str]] = []
    file_iocs: list[dict[str, str]] = []
    email_iocs: list[dict[str, str]] = []
    seen_ip: set[str] = set()
    seen_port: set[str] = set()
    seen_file: set[str] = set()
    seen_email: set[str] = set()

    for f in findings:
        text = f.description

        for m in _IP_PORT_RE.finditer(text):
            ip, port = m.group(1), m.group(2)
            if ip in _SKIP_IPS:
                continue
            if ip not in seen_ip:
                seen_ip.add(ip)
                ioc_type = "External IP" if _is_external_ip(ip) else "Internal IP"
                network_iocs.append({"type": ioc_type, "value": ip, "context": f.title[:80]})
            port_key = f"TCP {port}"
            if port_key not in seen_port:
                seen_port.add(port_key)
                network_iocs.append({"type": "Port", "value": port_key, "context": f.title[:80]})

        for m in _IP_RE.finditer(text):
            ip = m.group()
            if ip in _SKIP_IPS or ip in seen_ip:
                continue
            seen_ip.add(ip)
            ioc_type = "External IP" if _is_external_ip(ip) else "Internal IP"
            network_iocs.append({"type": ioc_type, "value": ip, "context": f.title[:80]})

        for m in _PORT_RE.finditer(text):
            port_key = f"TCP {m.group(1)}"
            if port_key not in seen_port:
                seen_port.add(port_key)
                network_iocs.append({"type": "Port", "value": port_key, "context": f.title[:80]})

        for m in _PATH_RE.finditer(text):
            val = m.group().rstrip(".)]}")
            if len(val) < 8 or val in seen_file:
                continue
            seen_file.add(val)
            file_iocs.append({"type": "Path", "value": val, "context": f.title[:80]})

        for m in _HASH_RE.finditer(text):
            val = m.group(1)
            if val not in seen_file:
                seen_file.add(val)
                hash_type = "SHA256" if len(val) == 64 else "SHA1" if len(val) == 40 else "MD5"
                file_iocs.append({"type": hash_type, "value": val, "context": f.title[:80]})

        for m in _EMAIL_RE.finditer(text):
            addr = m.group().lower()
            if addr not in seen_email:
                seen_email.add(addr)
                email_iocs.append({"type": "Email", "value": addr, "context": f.title[:80]})

    return network_iocs, file_iocs, email_iocs


def _parse_audit_log(audit_log_path: Path | str) -> list[dict[str, Any]]:
    """Parse the JSONL audit log into a list of dicts for template use."""
    path = Path(audit_log_path)
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _build_provenance_chains(
    findings: Sequence[Finding | dict[str, Any]],
    audit_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """For each finding, resolve evidence_refs to their audit log entries."""
    tc_index: dict[str, dict[str, Any]] = {}
    for entry in audit_entries:
        if entry.get("type") == "tool_call":
            tc_index[entry["tool_call_id"]] = entry

    chains: list[dict[str, Any]] = []
    for f in findings:
        refs = f.evidence_refs if hasattr(f, "evidence_refs") else f.get("evidence_refs", [])
        fid = f.finding_id if hasattr(f, "finding_id") else f.get("finding_id", "")
        title = f.title if hasattr(f, "title") else f.get("title", "")
        resolved: list[dict[str, Any]] = []
        for ref in refs:
            if ref in tc_index:
                entry = tc_index[ref]
                resolved.append(
                    {
                        "tool_call_id": ref,
                        "tool_name": entry.get("tool_name", ""),
                        "timestamp": entry.get("timestamp", ""),
                        "duration_ms": entry.get("duration_ms", 0),
                        "params": entry.get("params", {}),
                        "output_hash": entry.get("output_hash", ""),
                    }
                )
            else:
                resolved.append(
                    {
                        "tool_call_id": ref,
                        "tool_name": "unknown",
                        "timestamp": "",
                        "duration_ms": 0,
                        "params": {},
                        "output_hash": "",
                    }
                )
        chains.append({"finding_id": fid, "title": title, "evidence": resolved})
    return chains


def _format_duration(total_duration_ms: float) -> str:
    """Convert milliseconds to a human-readable hours/minutes string."""
    hours = total_duration_ms / 3_600_000
    if hours >= 1:
        return f"{hours:.1f} hours"
    mins = total_duration_ms / 60_000
    return f"{mins:.0f} minutes"


def _classify_sources(
    sources_list: Sequence[SourceRow | dict[str, Any]] | None,
) -> tuple[int, int, int]:
    """Classify sources into memory dumps, disk images, and other counts."""
    mem, disk, other = 0, 0, 0
    if not sources_list:
        return mem, disk, other
    for s in sources_list:
        name = s.source_name if hasattr(s, "source_name") else s.get("source_name", "")
        ext = s.extractor if hasattr(s, "extractor") else s.get("extractor", "")
        lower_name = (name + " " + ext).lower()
        if any(k in lower_name for k in ("memory", "volatility", ".img", ".vmem", ".dmp")):
            mem += 1
        elif any(k in lower_name for k in ("tsk", "disk", ".e01", ".dd", "bulk", "sleuthkit")):
            disk += 1
        else:
            other += 1
    return mem, disk, other


def _timeline_date_range(
    timeline_findings: Sequence[Finding | dict[str, Any]],
) -> tuple[str, str]:
    """Return (earliest_date, latest_date) from timeline findings as YYYY-MM-DD."""
    starts: list[str] = []
    ends: list[str] = []
    for f in timeline_findings:
        ts = f.event_time_start if hasattr(f, "event_time_start") else f.get("event_time_start")
        te = f.event_time_end if hasattr(f, "event_time_end") else f.get("event_time_end")
        if ts:
            starts.append(ts)
        if te:
            ends.append(te)
    all_ts = starts + ends
    if not all_ts:
        return "", ""
    earliest = min(all_ts)[:10]
    latest = max(all_ts)[:10]
    return earliest, latest


def _get_attr(obj: Any, attr: str, default: Any = "") -> Any:
    """Read *attr* from an object or dict, falling back to *default*."""
    return getattr(obj, attr) if hasattr(obj, attr) else obj.get(attr, default)


def _build_executive_summary(
    case_id: str,
    finding_count: int,
    critical_count: int,
    high_count: int,
    sources_count: int,
    total_tool_calls: int,
    total_duration_ms: float,
    critical_findings: Sequence[Finding | dict[str, Any]],
    timeline_findings: Sequence[Finding | dict[str, Any]] | None = None,
    confirmed_count: int = 0,
    inference_count: int = 0,
    negative_count: int = 0,
    sources_list: Sequence[SourceRow | dict[str, Any]] | None = None,
    evidence_integrity_status: str = "",
    tool_call_counts: dict[str, int] | None = None,
) -> str:
    """Generate a multi-paragraph HTML executive summary."""
    duration_str = _format_duration(total_duration_ms)
    mem_count, disk_count, other_count = _classify_sources(sources_list)

    # -- Para 1: Case overview --
    scope_parts: list[str] = []
    if mem_count:
        scope_parts.append(f"{mem_count} memory{'s' if mem_count != 1 else ''}")
    if disk_count:
        scope_parts.append(f"{disk_count} disk")
    if other_count:
        scope_parts.append(f"{other_count} other")
    scope_str = " (" + ", ".join(scope_parts) + ")" if scope_parts else ""

    p1 = (
        f"This automated investigation of case <strong>{case_id}</strong> "
        f"analyzed <strong>{sources_count}</strong> evidence sources{scope_str} "
        f"over <strong>{duration_str}</strong> of processing, "
        f"executing <strong>{total_tool_calls}</strong> tool calls. "
        f"The analysis identified <strong>{finding_count}</strong> findings"
    )
    sev_parts: list[str] = []
    if critical_count:
        sev_parts.append(f"<strong>{critical_count} critical</strong>")
    if high_count:
        sev_parts.append(f"<strong>{high_count} high</strong>")
    if sev_parts:
        p1 += ", including " + " and ".join(sev_parts) + " severity items"
    p1 += "."
    if confirmed_count or inference_count:
        p1 += (
            f" Of these, <strong>{confirmed_count}</strong> were corroborated "
            f"by multiple sources (confirmed) and <strong>{inference_count}</strong> "
            f"remain single-source inferences."
        )

    # -- Para 2: Attack narrative from timeline --
    p2 = ""
    tl = list(timeline_findings or [])
    if tl:
        earliest, latest = _timeline_date_range(tl)
        date_span = (
            f"from <strong>{earliest}</strong> to <strong>{latest}</strong>"
            if earliest != latest
            else f"on <strong>{earliest}</strong>"
        )
        p2 = f"The attack timeline spans {date_span}. "
        first_event = _get_attr(tl[0], "title")
        p2 += f"The earliest observed activity was <em>{first_event}</em>"
        first_ts = _get_attr(tl[0], "event_time_start")
        if first_ts:
            p2 += f" ({first_ts[:19]})"
        p2 += ". "

        crit_tl = [f for f in tl if _get_attr(f, "severity") == "critical"]
        if len(crit_tl) > 1:
            mid_titles = [_get_attr(f, "title") for f in crit_tl[1:4]]
            p2 += (
                "The investigation subsequently uncovered "
                + "; ".join(f"<em>{t}</em>" for t in mid_titles)
                + ". "
            )

        last_event = _get_attr(tl[-1], "title")
        if len(tl) > 1 and last_event != first_event:
            p2 += f"The most recent activity was <em>{last_event}</em>"
            last_ts = _get_attr(tl[-1], "event_time_start")
            if last_ts:
                p2 += f" ({last_ts[:19]})"
            p2 += "."

    # -- Para 3: Key threat summary --
    p3 = ""
    if critical_findings:
        p3 = "Key threats identified: "
        threat_items = []
        for f in critical_findings[:5]:
            title = _get_attr(f, "title")
            threat_items.append(f"<strong>{title}</strong>")
        p3 += "; ".join(threat_items) + "."
    if negative_count:
        p3 += (
            f" Additionally, <strong>{negative_count}</strong> "
            f"{'hypothesis was' if negative_count == 1 else 'hypotheses were'} "
            f"explicitly tested and ruled out, demonstrating investigative rigour."
        )

    # -- Para 4: Methodology --
    p4 = ""
    if tool_call_counts:
        top_tools = sorted(tool_call_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        tool_str = ", ".join(f"{name} ({count})" for name, count in top_tools)
        p4 = f"Primary analysis tools: {tool_str}."
    if evidence_integrity_status == "hashes_recorded":
        label = "SHA-256 hashes recorded for all evidence files at ingestion."
        p4 += f" {label}" if p4 else label

    paras = [p for p in (p1, p2, p3, p4) if p]
    return "</p><p>".join(paras)


def _build_executive_summary_md(
    case_id: str,
    finding_count: int,
    critical_count: int,
    high_count: int,
    sources_count: int,
    total_tool_calls: int,
    total_duration_ms: float,
    critical_findings: Sequence[Finding | dict[str, Any]],
    timeline_findings: Sequence[Finding | dict[str, Any]] | None = None,
    confirmed_count: int = 0,
    inference_count: int = 0,
    negative_count: int = 0,
    sources_list: Sequence[SourceRow | dict[str, Any]] | None = None,
    evidence_integrity_status: str = "",
    tool_call_counts: dict[str, int] | None = None,
) -> str:
    """Generate a multi-paragraph plaintext/markdown executive summary."""
    duration_str = _format_duration(total_duration_ms)
    mem_count, disk_count, other_count = _classify_sources(sources_list)

    scope_parts: list[str] = []
    if mem_count:
        scope_parts.append(f"{mem_count} memory")
    if disk_count:
        scope_parts.append(f"{disk_count} disk")
    if other_count:
        scope_parts.append(f"{other_count} other")
    scope_str = " (" + ", ".join(scope_parts) + ")" if scope_parts else ""

    p1 = (
        f"This automated investigation of case **{case_id}** "
        f"analyzed **{sources_count}** evidence sources{scope_str} "
        f"over **{duration_str}** of processing, "
        f"executing **{total_tool_calls}** tool calls. "
        f"The analysis identified **{finding_count}** findings"
    )
    sev_parts: list[str] = []
    if critical_count:
        sev_parts.append(f"**{critical_count} critical**")
    if high_count:
        sev_parts.append(f"**{high_count} high**")
    if sev_parts:
        p1 += ", including " + " and ".join(sev_parts) + " severity items"
    p1 += "."
    if confirmed_count or inference_count:
        p1 += (
            f" Of these, **{confirmed_count}** were corroborated "
            f"by multiple sources (confirmed) and **{inference_count}** "
            f"remain single-source inferences."
        )

    p2 = ""
    tl = list(timeline_findings or [])
    if tl:
        earliest, latest = _timeline_date_range(tl)
        date_span = (
            f"from **{earliest}** to **{latest}**" if earliest != latest else f"on **{earliest}**"
        )
        p2 = f"The attack timeline spans {date_span}. "
        first_event = _get_attr(tl[0], "title")
        p2 += f'The earliest observed activity was "{first_event}"'
        first_ts = _get_attr(tl[0], "event_time_start")
        if first_ts:
            p2 += f" ({first_ts[:19]})"
        p2 += ". "

        crit_tl = [f for f in tl if _get_attr(f, "severity") == "critical"]
        if len(crit_tl) > 1:
            mid_titles = [_get_attr(f, "title") for f in crit_tl[1:4]]
            p2 += (
                "The investigation subsequently uncovered "
                + "; ".join(f'"{t}"' for t in mid_titles)
                + ". "
            )

        last_event = _get_attr(tl[-1], "title")
        if len(tl) > 1 and last_event != first_event:
            p2 += f'The most recent activity was "{last_event}"'
            last_ts = _get_attr(tl[-1], "event_time_start")
            if last_ts:
                p2 += f" ({last_ts[:19]})"
            p2 += "."

    p3 = ""
    if critical_findings:
        p3 = "Key threats identified: "
        threat_items = []
        for f in critical_findings[:5]:
            title = _get_attr(f, "title")
            threat_items.append(f"**{title}**")
        p3 += "; ".join(threat_items) + "."
    if negative_count:
        p3 += (
            f" Additionally, **{negative_count}** "
            f"{'hypothesis was' if negative_count == 1 else 'hypotheses were'} "
            f"explicitly tested and ruled out, demonstrating investigative rigour."
        )

    p4 = ""
    if tool_call_counts:
        top_tools = sorted(tool_call_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        tool_str = ", ".join(f"{name} ({count})" for name, count in top_tools)
        p4 = f"Primary analysis tools: {tool_str}."
    if evidence_integrity_status == "hashes_recorded":
        label = "SHA-256 hashes recorded for all evidence files at ingestion."
        p4 += f" {label}" if p4 else label

    paras = [p for p in (p1, p2, p3, p4) if p]
    return "\n\n".join(paras)


def _build_related_findings(
    findings: Sequence[Finding | dict[str, Any]],
) -> dict[str, list[str]]:
    """Map each finding_id to IDs of findings sharing evidence refs."""
    ref_to_fids: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        fid = f.finding_id if hasattr(f, "finding_id") else f.get("finding_id", "")
        refs = f.evidence_refs if hasattr(f, "evidence_refs") else f.get("evidence_refs", [])
        for ref in refs:
            ref_to_fids[ref].append(fid)

    related: dict[str, list[str]] = defaultdict(list)
    for fids in ref_to_fids.values():
        if len(fids) > 1:
            for fid in fids:
                for other in fids:
                    if other != fid and other not in related[fid]:
                        related[fid].append(other)
    return dict(related)


def _build_related_titles(
    findings: Sequence[Finding | dict[str, Any]],
    related_findings: dict[str, list[str]],
) -> dict[str, list[dict[str, str]]]:
    """Precompute related finding titles so the template avoids O(n^2) loops."""
    title_map: dict[str, str] = {}
    for f in findings:
        fid = f.finding_id if hasattr(f, "finding_id") else f.get("finding_id", "")
        title = f.title if hasattr(f, "title") else f.get("title", "")
        title_map[fid] = title

    result: dict[str, list[dict[str, str]]] = {}
    for fid, related_ids in related_findings.items():
        result[fid] = [
            {"finding_id": rid, "title": title_map.get(rid, rid)} for rid in related_ids
        ]
    return result


def _build_mitre_techniques(
    findings: Sequence[Finding | dict[str, Any]],
) -> list[dict[str, Any]]:
    """Aggregate MITRE ATT&CK technique IDs across all findings."""
    tech_map: dict[str, list[dict[str, str]]] = defaultdict(list)
    for f in findings:
        fid = f.finding_id if hasattr(f, "finding_id") else f.get("finding_id", "")
        title = f.title if hasattr(f, "title") else f.get("title", "")
        attack_ids = (
            f.mitre_attack_ids if hasattr(f, "mitre_attack_ids") else f.get("mitre_attack_ids", [])
        )
        for tid in attack_ids:
            tech_map[tid].append({"finding_id": fid, "title": title})

    result: list[dict[str, Any]] = []
    for tid in sorted(tech_map):
        result.append(
            {
                "id": tid,
                "url": _attack_id_to_url(tid),
                "finding_count": len(tech_map[tid]),
                "findings": tech_map[tid],
            }
        )
    return result


def _attack_id_to_url(tid: str) -> str:
    """Convert ``T1059.001`` to ``https://attack.mitre.org/techniques/T1059/001/``."""
    parts = tid.split(".")
    path = "/".join(parts)
    return f"https://attack.mitre.org/techniques/{path}/"


def _filesizeformat(value: int | float) -> str:
    """Format a byte count as a human-readable file size."""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def _compute_integrity_status(integrity: list[dict[str, object]] | None) -> str:
    """Derive an overall integrity status string from evidence registry."""
    if not integrity:
        return "no_evidence_registered"
    return "hashes_recorded"


class ReportRenderer:
    """Renders validated findings into markdown and HTML investigation reports."""

    def __init__(self) -> None:
        """Configure Jinja to load package templates.

        ``autoescape=False`` preserves markdown until HTML conversion.
        """
        self._env = jinja2.Environment(
            loader=jinja2.PackageLoader("mulder", "report/templates"),
            autoescape=False,
            keep_trailing_newline=True,
        )
        self._env.filters["attack_url"] = _attack_id_to_url
        self._env.filters["basename"] = lambda p: Path(str(p)).name
        self._env.filters["filesizeformat"] = _filesizeformat

    def _build_context(
        self,
        case_metadata: CaseMetadataRow,
        findings: list[Finding],
        audit_summary: AuditSummary,
        audit_log_path: Path | str,
        audit_entries: list[dict[str, Any]] | None = None,
        sources_list: list[SourceRow] | None = None,
        evidence_integrity: list[dict[str, object]] | None = None,
        source_windows: dict[str, list[dict[str, Any]]] | None = None,
    ) -> dict[str, Any]:
        """Assemble template variables from case metadata, findings, audit trail, and sources."""
        _NEG_PREFIX = "[NEGATIVE]"
        positive_findings = [f for f in findings if not f.title.startswith(_NEG_PREFIX)]
        negative_findings = [f for f in findings if f.title.startswith(_NEG_PREFIX)]

        sorted_findings = sorted(
            positive_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
        )
        confirmed = sum(1 for f in positive_findings if f.confidence == "confirmed")
        inference = sum(1 for f in positive_findings if f.confidence == "inference")
        critical_count = sum(1 for f in positive_findings if f.severity == "critical")
        high_count = sum(1 for f in positive_findings if f.severity == "high")
        medium_count = sum(1 for f in positive_findings if f.severity == "medium")
        low_count = sum(1 for f in positive_findings if f.severity == "low")
        info_count = sum(1 for f in positive_findings if f.severity == "info")

        critical_findings = [f for f in sorted_findings if f.severity == "critical"]
        timeline_findings = sorted(
            [f for f in sorted_findings if f.event_time_start],
            key=lambda f: f.event_time_start or "",
        )

        all_sources = set()
        for f in findings:
            all_sources.update(f.sources)

        network_iocs, file_iocs, email_iocs = _extract_iocs(findings)

        if audit_entries is None:
            audit_entries = _parse_audit_log(audit_log_path)

        tool_call_entries = [
            e
            for e in audit_entries
            if e.get("type") == "tool_call" and e.get("tool_name") != "run_parallel"
        ]

        provenance_chains = _build_provenance_chains(sorted_findings, audit_entries)

        sources_data: list[dict[str, Any]] = []
        if sources_list:
            for s in sources_list:
                d = s.model_dump() if hasattr(s, "model_dump") else vars(s)
                referencing = [
                    f.title
                    for f in findings
                    if s.source_name in f.sources
                    or any(s.source_name.startswith(src) for src in f.sources)
                ]
                d["referencing_findings"] = referencing
                sources_data.append(d)

        _summary_kwargs: dict[str, Any] = dict(
            case_id=case_metadata.case_id,
            finding_count=len(positive_findings),
            critical_count=critical_count,
            high_count=high_count,
            sources_count=len(all_sources),
            total_tool_calls=audit_summary.total_tool_calls,
            total_duration_ms=audit_summary.total_duration_ms,
            critical_findings=critical_findings,
            timeline_findings=timeline_findings,
            confirmed_count=confirmed,
            inference_count=inference,
            negative_count=len(negative_findings),
            sources_list=sources_list,
            evidence_integrity_status=_compute_integrity_status(evidence_integrity),
            tool_call_counts=audit_summary.tool_call_counts,
        )
        executive_summary = _build_executive_summary(**_summary_kwargs)
        executive_summary_md = _build_executive_summary_md(**_summary_kwargs)

        related_findings = _build_related_findings(sorted_findings)
        related_titles = _build_related_titles(sorted_findings, related_findings)
        mitre_techniques = _build_mitre_techniques(positive_findings)

        return {
            "case_id": case_metadata.case_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence_root": case_metadata.evidence_root,
            "finding_count": len(positive_findings),
            "negative_findings": negative_findings,
            "negative_count": len(negative_findings),
            "confirmed_count": confirmed,
            "inference_count": inference,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "info_count": info_count,
            "findings": sorted_findings,
            "critical_findings": critical_findings,
            "timeline_findings": timeline_findings,
            "sources": sorted(all_sources),
            "network_iocs": network_iocs,
            "file_iocs": file_iocs,
            "email_iocs": email_iocs,
            "total_tool_calls": audit_summary.total_tool_calls,
            "audit_log_path": str(audit_log_path),
            "audit_entries": tool_call_entries,
            "provenance_chains": provenance_chains,
            "sources_list": sources_data,
            "tool_call_counts": audit_summary.tool_call_counts,
            "tool_durations": audit_summary.tool_durations,
            "total_duration_ms": audit_summary.total_duration_ms,
            "first_timestamp": audit_summary.first_timestamp,
            "last_timestamp": audit_summary.last_timestamp,
            "executive_summary": executive_summary,
            "executive_summary_md": executive_summary_md,
            "related_findings": related_findings,
            "estimated_input_tokens": audit_summary.estimated_input_tokens,
            "estimated_output_tokens": audit_summary.estimated_output_tokens,
            "estimated_cost_usd": audit_summary.estimated_cost_usd,
            "evidence_integrity": evidence_integrity or [],
            "evidence_integrity_status": _compute_integrity_status(evidence_integrity),
            "related_titles": related_titles,
            "mitre_techniques": mitre_techniques,
            "source_windows": source_windows or {},
        }

    def render(
        self,
        case_metadata: CaseMetadataRow,
        findings: list[Finding],
        audit_summary: AuditSummary,
        audit_log_path: Path | str,
        audit_entries: list[dict[str, Any]] | None = None,
        sources_list: list[SourceRow] | None = None,
        evidence_integrity: list[dict[str, object]] | None = None,
    ) -> str:
        """Render the markdown report template (``report.md.j2``) to a string."""
        ctx = self._build_context(
            case_metadata,
            findings,
            audit_summary,
            audit_log_path,
            audit_entries=audit_entries,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
        )
        template = self._env.get_template("report.md.j2")
        return template.render(**ctx)

    def render_html(
        self,
        case_metadata: CaseMetadataRow,
        findings: list[Finding],
        audit_summary: AuditSummary,
        audit_log_path: Path | str,
        audit_entries: list[dict[str, Any]] | None = None,
        sources_list: list[SourceRow] | None = None,
        evidence_integrity: list[dict[str, object]] | None = None,
        source_windows: dict[str, list[dict[str, Any]]] | None = None,
    ) -> str:
        """Render the HTML report with markdown descriptions converted to HTML."""
        ctx = self._build_context(
            case_metadata,
            findings,
            audit_summary,
            audit_log_path,
            audit_entries=audit_entries,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
            source_windows=source_windows,
        )

        md_extensions = ["fenced_code", "tables", "nl2br"]
        html_findings = []
        for f in ctx["findings"]:
            fd = f.model_dump() if hasattr(f, "model_dump") else vars(f)
            fd["description_html"] = markdown.markdown(
                fd.get("description", ""), extensions=md_extensions
            )
            html_findings.append(SimpleNamespace(**fd))
        ctx["findings"] = html_findings

        for f in ctx.get("critical_findings", []):
            if not hasattr(f, "description_html"):
                fd = f.model_dump() if hasattr(f, "model_dump") else vars(f)
                fd["description_html"] = ""
                ctx["critical_findings"] = [
                    SimpleNamespace(**g.model_dump(), description_html="")
                    if hasattr(g, "model_dump")
                    else g
                    for g in ctx["critical_findings"]
                ]
                break

        for f in ctx.get("timeline_findings", []):
            if not hasattr(f, "description_html"):
                ctx["timeline_findings"] = [
                    SimpleNamespace(**g.model_dump(), description_html="")
                    if hasattr(g, "model_dump")
                    else g
                    for g in ctx["timeline_findings"]
                ]
                break

        template = self._env.get_template("report.html.j2")
        return template.render(**ctx)
