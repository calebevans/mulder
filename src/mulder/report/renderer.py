"""Jinja2 report renderer for Mulder investigation reports."""

from __future__ import annotations

import functools
import json
import logging
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
from mulder.patterns import (
    EMAIL_RE,
    IP_RE,
    SEVERITY_ORDER,
    classify_ip,
    format_token_count,
    is_external_ip,
)

logger = logging.getLogger(__name__)


def _normalize_finding(f: Finding | dict[str, Any]) -> Finding:
    """Convert a dict to a Finding, or return as-is if already a Finding."""
    if isinstance(f, Finding):
        return f
    return Finding(**f)


def _normalize_source(s: SourceRow | dict[str, Any]) -> SourceRow:
    """Convert a dict to a SourceRow, or return as-is if already a SourceRow."""
    if isinstance(s, SourceRow):
        return s
    return SourceRow(**s)


_SEVERITY_ORDER = SEVERITY_ORDER

_ATTACK_TACTICS_PATH = Path(__file__).resolve().parent / "data" / "attack_tactics.json"

_IP_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d+)\b")
_PORT_RE = re.compile(r"\bport\s+(\d+)\b", re.IGNORECASE)
_PATH_RE = re.compile(
    r"(?:C:\\[A-Za-z]|/(?:usr|var|etc|home|root|Windows|Users|System(?:/Library)?))"
    r"[^\s,\"'`*:]+[^\s,\"'`*:.)]"
)
_HASH_RE = re.compile(r"\b(?:SHA1|SHA256|MD5)[:\s]+([a-fA-F0-9]{32,64})\b")
_FILE_EXT_AFTER_EMAIL = re.compile(
    r"\.(ost|tmp|xml|json|log|bak|dat|db|cfg|old|pst|eml|msg|mbox|csv|txt|ini)$",
    re.IGNORECASE,
)
_SKIP_IP_CATEGORIES = frozenset({"loopback", "reserved", "link_local"})
_NON_IOC_IPS = frozenset({"0.0.0.0", "255.255.255.255"})


_FALSE_POSITIVE_RE = re.compile(r"false\s+positive", re.IGNORECASE)
_IOC_EXCLUDED_SEVERITIES = frozenset({"low", "info"})


def _filter_ioc_eligible(findings: list[Finding]) -> list[Finding]:
    """Exclude findings that should not contribute IOCs to the appendix.

    Filters out findings at LOW/INFO severity and findings whose title or
    description explicitly documents a false positive, since their artifacts
    are not actionable indicators of compromise.

    Args:
        findings: All positive findings from the case.

    Returns:
        Subset of findings eligible for IOC extraction.
    """
    eligible: list[Finding] = []
    for f in findings:
        if f.severity in _IOC_EXCLUDED_SEVERITIES:
            continue
        if _FALSE_POSITIVE_RE.search(f.title) or _FALSE_POSITIVE_RE.search(f.description):
            continue
        eligible.append(f)
    return eligible


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
            if ip in _NON_IOC_IPS or classify_ip(ip) in _SKIP_IP_CATEGORIES:
                continue
            if ip not in seen_ip:
                seen_ip.add(ip)
                ioc_type = "External IP" if is_external_ip(ip) else "Internal IP"
                network_iocs.append({"type": ioc_type, "value": ip, "context": f.title[:80]})
            port_key = f"TCP {port}"
            if port_key not in seen_port:
                seen_port.add(port_key)
                network_iocs.append({"type": "Port", "value": port_key, "context": f.title[:80]})

        for m in IP_RE.finditer(text):
            ip = m.group()
            if ip in _NON_IOC_IPS or classify_ip(ip) in _SKIP_IP_CATEGORIES or ip in seen_ip:
                continue
            seen_ip.add(ip)
            ioc_type = "External IP" if is_external_ip(ip) else "Internal IP"
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

        for m in EMAIL_RE.finditer(text):
            addr = m.group().lower()
            after = text[m.end() : m.end() + 5]
            if after and after[0] == ".":
                continue
            if _FILE_EXT_AFTER_EMAIL.search(addr):
                continue
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
    findings: Sequence[Finding],
    audit_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """For each finding, resolve evidence_refs to their audit log entries."""
    tc_index: dict[str, dict[str, Any]] = {}
    for entry in audit_entries:
        if entry.get("type") == "tool_call":
            tc_index[entry["tool_call_id"]] = entry

    chains: list[dict[str, Any]] = []
    for f in findings:
        resolved: list[dict[str, Any]] = []
        for ref in f.evidence_refs:
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
        chains.append({"finding_id": f.finding_id, "title": f.title, "evidence": resolved})
    return chains


def _format_duration(total_duration_ms: float) -> str:
    """Convert milliseconds to a human-readable hours/minutes string."""
    hours = total_duration_ms / 3_600_000
    if hours >= 1:
        return f"{hours:.1f} hours"
    mins = total_duration_ms / 60_000
    return f"{mins:.0f} minutes"


def _classify_sources(
    sources_list: Sequence[SourceRow] | None,
) -> tuple[int, int, int]:
    """Classify sources into memory dumps, disk images, and other counts."""
    mem, disk, other = 0, 0, 0
    if not sources_list:
        return mem, disk, other
    for s in sources_list:
        lower_name = (s.source_name + " " + s.extractor).lower()
        if any(k in lower_name for k in ("memory", "volatility", ".img", ".vmem", ".dmp")):
            mem += 1
        elif any(k in lower_name for k in ("tsk", "disk", ".e01", ".dd", "bulk", "sleuthkit")):
            disk += 1
        else:
            other += 1
    return mem, disk, other


def _timeline_date_range(
    timeline_findings: Sequence[Finding],
) -> tuple[str, str]:
    """Return (earliest_date, latest_date) from timeline findings as YYYY-MM-DD."""
    starts: list[str] = []
    ends: list[str] = []
    for f in timeline_findings:
        if f.event_time_start:
            starts.append(f.event_time_start)
        if f.event_time_end:
            ends.append(f.event_time_end)
    all_ts = starts + ends
    if not all_ts:
        return "", ""
    earliest = min(all_ts)[:10]
    latest = max(all_ts)[:10]
    return earliest, latest


def _build_executive_summary(
    case_id: str,
    finding_count: int,
    critical_count: int,
    high_count: int,
    sources_count: int,
    total_tool_calls: int,
    total_duration_ms: float,
    critical_findings: Sequence[Finding],
    timeline_findings: Sequence[Finding] | None = None,
    confirmed_count: int = 0,
    inference_count: int = 0,
    negative_count: int = 0,
    sources_list: Sequence[SourceRow] | None = None,
    evidence_integrity_status: str = "",
    tool_call_counts: dict[str, int] | None = None,
) -> str:
    """Generate a structured HTML executive summary.

    The HTML report already renders stat cards below the summary, so
    this focuses on the narrative and key threats rather than repeating
    raw numbers.
    """
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

    sev_parts: list[str] = []
    if critical_count:
        sev_parts.append(f"{critical_count} critical")
    if high_count:
        sev_parts.append(f"{high_count} high")
    sev_str = " (" + ", ".join(sev_parts) + ")" if sev_parts else ""

    sections: list[str] = []

    def _pill(icon: str, label: str, value: str) -> str:
        return (
            f'<div class="exec-pill">'
            f'<span class="ep-icon">{icon}</span>'
            f'<span class="ep-val">{value}</span> {label}'
            f"</div>"
        )

    pills = [
        _pill("\U0001f4c2", f"sources{scope_str}", str(sources_count)),
        _pill("\U0001f50d", "tool calls", str(total_tool_calls)),
        _pill("\u23f1\ufe0f", "elapsed", duration_str),
        _pill("\U0001f6a8", f"findings{sev_str}", str(finding_count)),
        _pill("\u2705", "confirmed", str(confirmed_count)),
        _pill("\U0001f914", "inference", str(inference_count)),
    ]
    if negative_count:
        noun = "hypothesis" if negative_count == 1 else "hypotheses"
        pills.append(_pill("\u274c", f"{noun} ruled out", str(negative_count)))
    if evidence_integrity_status == "hashes_recorded":
        pills.append(_pill("\U0001f512", "SHA-256 hashes", "\u2713"))
    sections.append('<div class="exec-meta">' + "".join(pills) + "</div>")

    tl = list(timeline_findings or [])
    if tl:
        earliest, latest = _timeline_date_range(tl)
        if earliest and latest:
            first_event = tl[0].title
            first_ts = tl[0].event_time_start
            narrative = f"The attack timeline spans <strong>{earliest}</strong>"
            if earliest != latest:
                narrative += f" to <strong>{latest}</strong>"
            narrative += f". The earliest activity was <em>{first_event}</em>"
            if first_ts:
                narrative += f" ({first_ts[:10]})"
            narrative += "."

            crit_tl = [f for f in tl if f.severity == "critical"]
            if len(crit_tl) > 1:
                mid_titles = [f.title for f in crit_tl[1:4]]
                narrative += (
                    " The investigation subsequently uncovered "
                    + "; ".join(f"<em>{t}</em>" for t in mid_titles)
                    + "."
                )

            last_event = tl[-1].title
            if len(tl) > 1 and last_event != first_event:
                last_ts = tl[-1].event_time_start
                narrative += f" The most recent activity was <em>{last_event}</em>"
                if last_ts:
                    narrative += f" ({last_ts[:10]})"
                narrative += "."
            sections.append(f"<p>{narrative}</p>")

    if critical_findings:
        items = "".join(f"<li>{f.title}</li>" for f in critical_findings[:5])
        sections.append(
            f'<div class="exec-threats"><strong>Key Threats</strong><ul>{items}</ul></div>'
        )

    return "\n".join(sections)


_KILL_CHAIN_PHASES: list[tuple[str, tuple[str, ...]]] = [
    (
        "Initial Access / Deployment",
        (
            "deploy",
            "install",
            "initial",
            "implant",
            "malware",
            "backdoor",
            "dropper",
            "staging",
            "staged",
        ),
    ),
    (
        "Persistence",
        (
            "persist",
            "service",
            "registry",
            "run key",
            "auto-start",
            "scheduled task",
            "startup",
            "boot",
        ),
    ),
    (
        "Lateral Movement",
        (
            "lateral",
            "winrm",
            "rdp",
            "smb",
            "psexec",
            "wmi",
            "remote",
            "spread",
            "pivot",
        ),
    ),
    (
        "Command and Control",
        (
            "c2",
            "c&c",
            "beacon",
            "callback",
            "lariat",
            "meterpreter",
            "metasploit",
            "cobalt",
            "empire",
            "powershell cradle",
            "download cradle",
            "shell",
        ),
    ),
    (
        "Credential Access",
        (
            "credential",
            "skeleton key",
            "mimikatz",
            "password",
            "kerberos",
            "ntlm",
            "lsass",
            "sam",
            "hash",
        ),
    ),
    (
        "Defense Evasion / Anti-Forensics",
        (
            "evasion",
            "masquerad",
            "injection",
            "inject",
            "log clear",
            "log clearing",
            "anti-forensic",
            "fake",
            "disguise",
            "obfuscat",
        ),
    ),
    (
        "Discovery / Collection",
        (
            "discovery",
            "scan",
            "enumerat",
            "recon",
            "exfiltrat",
            "collection",
            "staging",
        ),
    ),
]


def _build_kill_chain_summary(
    timeline_findings: Sequence[Finding],
) -> list[tuple[str, list[Finding]]]:
    """Group timeline findings into kill chain phases by keyword matching.

    Args:
        timeline_findings: Chronologically sorted findings with timestamps.

    Returns:
        List of (phase_name, findings) tuples, ordered by kill chain
        progression. Only phases with matching findings are included.
    """
    assigned: set[str] = set()
    result: list[tuple[str, list[Finding]]] = []

    for phase_name, keywords in _KILL_CHAIN_PHASES:
        matches: list[Finding] = []
        for f in timeline_findings:
            if f.finding_id in assigned:
                continue
            text = (f.title + " " + f.description).lower()
            if any(kw in text for kw in keywords):
                matches.append(f)
                assigned.add(f.finding_id)
        if matches:
            result.append((phase_name, matches))

    # Catch unassigned findings under "Other Activity"
    unassigned = [f for f in timeline_findings if f.finding_id not in assigned]
    if unassigned:
        result.append(("Other Activity", unassigned))

    return result


def _phase_time_range(findings: Sequence[Finding]) -> str:
    """Format the time range for a group of findings.

    Args:
        findings: Findings in a single kill chain phase.

    Returns:
        Formatted date range string like "2018-06-04 to 2018-09-07".
    """
    starts = [f.event_time_start[:10] for f in findings if f.event_time_start]
    if not starts:
        return "unknown"
    earliest = min(starts)
    latest = max(starts)
    return earliest if earliest == latest else f"{earliest} to {latest}"


def _build_executive_summary_md(
    case_id: str,
    finding_count: int,
    critical_count: int,
    high_count: int,
    sources_count: int,
    total_tool_calls: int,
    total_duration_ms: float,
    critical_findings: Sequence[Finding],
    timeline_findings: Sequence[Finding] | None = None,
    confirmed_count: int = 0,
    inference_count: int = 0,
    negative_count: int = 0,
    sources_list: Sequence[SourceRow] | None = None,
    evidence_integrity_status: str = "",
    tool_call_counts: dict[str, int] | None = None,
) -> str:
    """Generate a structured markdown executive summary."""
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

    lines: list[str] = []

    effective_sources = sources_count
    if scope_parts:
        effective_sources = mem_count + disk_count + other_count

    lines.append(
        f"**Scope:** {effective_sources} evidence sources{scope_str} "
        f"| {total_tool_calls} tool calls | {duration_str}"
    )

    sev_parts: list[str] = []
    if critical_count:
        sev_parts.append(f"{critical_count} critical")
    if high_count:
        sev_parts.append(f"{high_count} high")
    sev_str = " (" + ", ".join(sev_parts) + ")" if sev_parts else ""

    results_line = f"**Results:** {finding_count} findings{sev_str}"
    results_line += f" | {confirmed_count} confirmed, {inference_count} inference"
    if negative_count:
        results_line += (
            f" | {negative_count} "
            f"{'hypothesis' if negative_count == 1 else 'hypotheses'} ruled out"
        )
    lines.append(results_line)

    tl = list(timeline_findings or [])
    if tl:
        earliest, latest = _timeline_date_range(tl)
        if earliest and latest:
            span = earliest if earliest == latest else f"{earliest} to {latest}"
            lines.append(f"**Timeline:** {span}")

    if critical_findings:
        lines.append("")
        lines.append("**Key Threats:**")
        for f in critical_findings[:5]:
            lines.append(f"- {f.title}")

    if tl:
        lifecycle = _build_kill_chain_summary(tl)
        if lifecycle:
            lines.append("")
            lines.append("**Attack Lifecycle:**")
            for phase_name, phase_findings in lifecycle:
                ts_range = _phase_time_range(phase_findings)
                count = len(phase_findings)
                sample = phase_findings[0].title
                if count == 1:
                    lines.append(f"- **{phase_name}** ({ts_range}): {sample}")
                else:
                    lines.append(
                        f"- **{phase_name}** ({ts_range}): {sample} (+{count - 1} related)"
                    )

    tool_parts: list[str] = []
    if tool_call_counts:
        top_tools = sorted(tool_call_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        tool_str = ", ".join(f"{name} ({count})" for name, count in top_tools)
        tool_parts.append(tool_str)
    if evidence_integrity_status == "hashes_recorded":
        tool_parts.append("SHA-256 hashes recorded for all evidence")
    if tool_parts:
        lines.append("")
        lines.append("**Tools:** " + ". ".join(tool_parts) + ".")

    return "\n".join(lines)


def _build_related_findings(
    findings: Sequence[Finding],
) -> dict[str, list[str]]:
    """Map each finding_id to IDs of findings sharing evidence refs."""
    ref_to_fids: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        for ref in f.evidence_refs:
            ref_to_fids[ref].add(f.finding_id)

    related: dict[str, set[str]] = defaultdict(set)
    for fids in ref_to_fids.values():
        if len(fids) > 1:
            for fid in fids:
                related[fid].update(fids - {fid})
    return {fid: sorted(others) for fid, others in related.items()}


def _build_related_titles(
    findings: Sequence[Finding],
    related_findings: dict[str, list[str]],
) -> dict[str, list[dict[str, str]]]:
    """Precompute related finding titles so the template avoids O(n^2) loops."""
    title_map: dict[str, str] = {f.finding_id: f.title for f in findings}

    result: dict[str, list[dict[str, str]]] = {}
    for fid, related_ids in related_findings.items():
        result[fid] = [
            {"finding_id": rid, "title": title_map.get(rid, rid)} for rid in related_ids
        ]
    return result


def _build_mitre_techniques(
    findings: Sequence[Finding],
    attack_data: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Aggregate MITRE ATT&CK technique IDs across all findings."""
    tech_map: dict[str, list[dict[str, str]]] = defaultdict(list)
    for f in findings:
        for tid in f.mitre_attack_ids:
            tech_map[tid].append({"finding_id": f.finding_id, "title": f.title})

    tech_lookup = attack_data.get("techniques", {}) if attack_data else {}

    result: list[dict[str, Any]] = []
    for tid in sorted(tech_map):
        name = ""
        info = tech_lookup.get(tid) or tech_lookup.get(tid.split(".")[0])
        if info:
            name = info.get("name", "")
        result.append(
            {
                "id": tid,
                "name": name,
                "url": _attack_id_to_url(tid),
                "finding_count": len(tech_map[tid]),
                "findings": tech_map[tid],
            }
        )
    return result


@functools.lru_cache(maxsize=1)
def _load_attack_tactics() -> dict[str, Any] | None:
    """Load the pre-extracted ATT&CK tactic mapping from package data.

    Returns ``None`` when the data file is missing (e.g. bare PyPI install
    without the extraction step).
    """
    if not _ATTACK_TACTICS_PATH.exists():
        logger.debug(
            "ATT&CK tactic data not found at %s; skipping tactic grouping", _ATTACK_TACTICS_PATH
        )
        return None
    try:
        data: dict[str, Any] = json.loads(_ATTACK_TACTICS_PATH.read_text(encoding="utf-8"))
        return data
    except Exception:
        logger.warning("Failed to parse %s", _ATTACK_TACTICS_PATH, exc_info=True)
        return None


def _build_mitre_tactic_groups(
    mitre_techniques: list[dict[str, Any]],
    attack_data: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Group techniques by ATT&CK tactic using pre-extracted STIX data.

    Returns ``(all_tactics, active_tactic_groups)`` where *all_tactics* is
    the full ordered tactic list (each with an ``active`` flag and counts),
    and *active_tactic_groups* contains only tactics that have findings,
    each with a ``techniques`` list attached.
    """
    tech_lookup = attack_data.get("techniques", {})

    tactic_techs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tactic_findings: dict[str, int] = defaultdict(int)

    for tech in mitre_techniques:
        tid = tech["id"]
        parent_tid = tid.split(".")[0]
        info = tech_lookup.get(tid) or tech_lookup.get(parent_tid)
        if info and info.get("tactics"):
            for tactic_id in info["tactics"]:
                tactic_techs[tactic_id].append(tech)
                tactic_findings[tactic_id] += tech["finding_count"]
        else:
            tactic_techs["_unknown"].append(tech)
            tactic_findings["_unknown"] += tech["finding_count"]

    ordered_tactics = sorted(attack_data.get("tactics", []), key=lambda t: t.get("order", 99))

    all_tactics: list[dict[str, Any]] = []
    active_groups: list[dict[str, Any]] = []

    for tactic in ordered_tactics:
        tid = tactic["id"]
        is_active = tid in tactic_techs
        entry = {
            "id": tid,
            "name": tactic["name"],
            "shortname": tactic.get("shortname", ""),
            "order": tactic.get("order", 99),
            "active": is_active,
            "technique_count": len(tactic_techs.get(tid, [])),
            "finding_count": tactic_findings.get(tid, 0),
        }
        all_tactics.append(entry)
        if is_active:
            active_groups.append(
                {
                    **entry,
                    "techniques": tactic_techs[tid],
                }
            )

    if "_unknown" in tactic_techs:
        unknown = {
            "id": "_unknown",
            "name": "Other",
            "shortname": "other",
            "order": 999,
            "active": True,
            "technique_count": len(tactic_techs["_unknown"]),
            "finding_count": tactic_findings["_unknown"],
            "techniques": tactic_techs["_unknown"],
        }
        active_groups.append(unknown)

    return all_tactics, active_groups


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


def _clean_finding_description(text: str) -> str:
    """Normalize escape sequences in finding descriptions.

    Fixes literal backslash-n sequences and double-escaped hex codes
    that appear when model output is serialized through JSON twice.

    Args:
        text: Raw finding description text.

    Returns:
        Cleaned text with proper escape sequences.
    """
    cleaned = text.replace("\\n", "\n")
    cleaned = cleaned.replace("\\\\x", "\\x")
    return cleaned


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
        self._env.filters["tokformat"] = format_token_count

    @staticmethod
    def _render_narrative_template(narrative: str, ctx: dict[str, Any]) -> str:
        """Render narrative text as a Jinja2 template with context variables.

        Treats the narrative as a Jinja2 template string, injecting
        authoritative numeric values from the report context. Falls back
        to the raw narrative if rendering fails (e.g., no placeholders
        or a syntax error).

        Args:
            narrative: Raw narrative text, potentially containing Jinja2
                template variables like ``{{finding_count}}``.
            ctx: Report context dictionary providing template variables.

        Returns:
            Rendered narrative string, or the original if rendering fails.
        """
        if not narrative:
            return narrative
        try:
            env = jinja2.Environment(undefined=jinja2.Undefined)
            template = env.from_string(narrative)
            return template.render(**ctx)
        except Exception:
            return narrative

    def build_context(
        self,
        case_metadata: CaseMetadataRow,
        findings: Sequence[Finding | dict[str, Any]],
        audit_summary: AuditSummary,
        audit_log_path: Path | str,
        audit_entries: list[dict[str, Any]] | None = None,
        sources_list: Sequence[SourceRow | dict[str, Any]] | None = None,
        evidence_integrity: list[dict[str, object]] | None = None,
        source_windows: dict[str, list[dict[str, Any]]] | None = None,
    ) -> dict[str, Any]:
        """Assemble template variables from case metadata, findings, audit trail, and sources.

        Args:
            case_metadata: Row from the case metadata table.
            findings: Validated findings or dicts to include in the report.
            audit_summary: Aggregated audit trail statistics.
            audit_log_path: Path to the JSONL audit log.
            audit_entries: Pre-parsed audit entries; parsed from file if None.
            sources_list: Evidence source rows for the source table.
            evidence_integrity: Evidence registry entries with file hashes.
            source_windows: Per-source raw text windows for the HTML report.

        Returns:
            Dict of template variables ready for Jinja2 rendering.
        """
        normalized_findings: list[Finding] = [_normalize_finding(f) for f in findings]
        normalized_sources: list[SourceRow] | None = (
            [_normalize_source(s) for s in sources_list] if sources_list else None
        )
        _NEG_PREFIX = "[NEGATIVE]"
        positive_findings = [f for f in normalized_findings if not f.title.startswith(_NEG_PREFIX)]
        negative_findings = [f for f in normalized_findings if f.title.startswith(_NEG_PREFIX)]

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

        all_sources: set[str] = set()
        for f in normalized_findings:
            all_sources.update(f.sources)

        ioc_eligible_findings = _filter_ioc_eligible(positive_findings)
        network_iocs, file_iocs, email_iocs = _extract_iocs(ioc_eligible_findings)

        if audit_entries is None:
            audit_entries = _parse_audit_log(audit_log_path)

        tool_call_entries = [
            e
            for e in audit_entries
            if e.get("type") == "tool_call" and e.get("tool_name") != "run_parallel"
        ]

        provenance_chains = _build_provenance_chains(sorted_findings, audit_entries)

        sources_data: list[dict[str, Any]] = []
        if normalized_sources:
            for s in normalized_sources:
                d = s.model_dump()
                referencing = [
                    f.title
                    for f in normalized_findings
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
            total_duration_ms=audit_summary.wall_clock_ms or audit_summary.total_duration_ms,
            critical_findings=critical_findings,
            timeline_findings=timeline_findings,
            confirmed_count=confirmed,
            inference_count=inference,
            negative_count=len(negative_findings),
            sources_list=normalized_sources,
            evidence_integrity_status=_compute_integrity_status(evidence_integrity),
            tool_call_counts=audit_summary.tool_call_counts,
        )
        executive_summary = _build_executive_summary(**_summary_kwargs)
        executive_summary_md = _build_executive_summary_md(**_summary_kwargs)

        related_findings = _build_related_findings(sorted_findings)
        related_titles = _build_related_titles(sorted_findings, related_findings)
        attack_data = _load_attack_tactics()
        mitre_techniques = _build_mitre_techniques(positive_findings, attack_data)
        if attack_data and mitre_techniques:
            all_tactics, active_tactic_groups = _build_mitre_tactic_groups(
                mitre_techniques, attack_data
            )
        else:
            all_tactics, active_tactic_groups = [], []

        ctx: dict[str, Any] = {
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
            "sources_count": len(all_sources),
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
            "evidence_integrity": evidence_integrity or [],
            "evidence_integrity_status": _compute_integrity_status(evidence_integrity),
            "related_titles": related_titles,
            "mitre_techniques": mitre_techniques,
            "mitre_all_tactics": all_tactics,
            "mitre_tactic_groups": active_tactic_groups,
            "source_windows": source_windows or {},
            "model_token_breakdown": self._load_model_usage(
                Path(audit_log_path).parent, case_metadata.case_id
            ),
        }

        rendered_narrative = self._render_narrative_template(case_metadata.narrative or "", ctx)
        ctx["narrative"] = rendered_narrative
        ctx["narrative_html"] = (
            markdown.markdown(
                rendered_narrative,
                extensions=["fenced_code", "tables", "nl2br"],
            )
            if rendered_narrative
            else ""
        )

        return ctx

    @staticmethod
    def _load_model_usage(db_dir: Path, case_id: str) -> list[dict[str, Any]]:
        """Load per-model token usage from the orchestrator sidecar file.

        Args:
            db_dir: Directory containing case files.
            case_id: Case identifier.

        Returns:
            List of dicts with model, input, and output keys, or empty
            list if the sidecar file does not exist.
        """
        usage_path = db_dir / f"{case_id}.model_usage.json"
        if not usage_path.exists():
            return []
        try:
            data = json.loads(usage_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return [
                    {
                        "model": entry.get("model", "unknown"),
                        "input": entry.get("input_tokens", 0),
                        "output": entry.get("output_tokens", 0),
                    }
                    for entry in data
                    if isinstance(entry, dict)
                ]
        except (json.JSONDecodeError, OSError):
            pass
        return []

    def _render_markdown(self, ctx: dict[str, Any]) -> str:
        """Render the markdown report from a pre-built context.

        Args:
            ctx: Template context dict from ``build_context``.

        Returns:
            Rendered markdown report string.
        """
        template = self._env.get_template("report.md.j2")
        return template.render(**ctx)

    @staticmethod
    def _build_print_css(case_id: str) -> str:
        """Build CSS print overrides for PDF generation.

        Forces a light color scheme, adds page margins, and injects
        case ID and confidentiality headers into every page.

        Args:
            case_id: Case identifier for the page header.

        Returns:
            CSS string with @page rules and theme overrides.
        """
        return f"""
            @page {{
                size: A4;
                margin: 2.5cm 2cm;
                @top-left {{
                    content: "Case: {case_id}";
                    font-size: 8pt;
                    color: #666;
                }}
                @top-right {{
                    content: "CONFIDENTIAL";
                    font-size: 8pt;
                    color: #cc0000;
                    font-weight: bold;
                }}
                @bottom-center {{
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 8pt;
                    color: #666;
                }}
            }}
            @page :first {{
                @top-left {{ content: none; }}
                @top-right {{ content: none; }}
            }}
            body {{
                background: #ffffff !important;
                color: #1a1a1a !important;
            }}
            .dark-theme, [data-theme="dark"] {{
                background: #ffffff !important;
                color: #1a1a1a !important;
            }}
            pre, code {{
                background: #f5f5f5 !important;
                color: #333 !important;
            }}
            table {{
                page-break-inside: avoid;
            }}
            h1, h2, h3 {{
                page-break-after: avoid;
            }}
        """

    def _render_pdf(self, html_text: str, case_id: str) -> bytes | None:
        """Render an HTML report string to PDF bytes.

        Uses weasyprint to convert the self-contained HTML report to a
        print-ready PDF with headers, footers, and page numbers. Returns
        None if weasyprint is not installed.

        Args:
            html_text: Complete HTML report string.
            case_id: Case identifier for page headers.

        Returns:
            PDF content as bytes, or None if weasyprint is unavailable.
        """
        try:
            import weasyprint
        except ImportError:
            logger.warning(
                "weasyprint not installed; skipping PDF generation. "
                "Install with: pip install 'mulder-mcp[pdf]'"
            )
            return None

        print_css = self._build_print_css(case_id)
        html_doc = weasyprint.HTML(string=html_text)
        css_override = weasyprint.CSS(string=print_css)
        pdf_bytes: bytes = html_doc.write_pdf(stylesheets=[css_override])
        return pdf_bytes

    def _render_html(self, ctx: dict[str, Any]) -> str:
        """Render the HTML report from a pre-built context.

        Converts markdown in finding descriptions to HTML before rendering
        the HTML template. Mutates ``ctx["findings"]``,
        ``ctx["critical_findings"]``, and ``ctx["timeline_findings"]``
        in-place with ``SimpleNamespace`` wrappers.

        Args:
            ctx: Template context dict from ``build_context``.

        Returns:
            Rendered HTML report string.
        """
        md_extensions = ["fenced_code", "tables", "nl2br"]
        html_findings = []
        for f in ctx["findings"]:
            fd = f.model_dump()
            cleaned_desc = _clean_finding_description(fd.get("description", ""))
            fd["description_html"] = markdown.markdown(cleaned_desc, extensions=md_extensions)
            html_findings.append(SimpleNamespace(**fd))
        ctx["findings"] = html_findings

        for f in ctx.get("critical_findings", []):
            if not hasattr(f, "description_html"):
                ctx["critical_findings"] = [
                    SimpleNamespace(**g.model_dump(), description_html="")
                    for g in ctx["critical_findings"]
                ]
                break

        for f in ctx.get("timeline_findings", []):
            if not hasattr(f, "description_html"):
                ctx["timeline_findings"] = [
                    SimpleNamespace(**g.model_dump(), description_html="")
                    for g in ctx["timeline_findings"]
                ]
                break

        template = self._env.get_template("report.html.j2")
        return template.render(**ctx)

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
        """Render the markdown report template (``report.md.j2``) to a string.

        Convenience wrapper that builds context and renders markdown in
        one call. Use ``render_all`` when both formats are needed.

        Args:
            case_metadata: Row from the case metadata table.
            findings: Validated findings to include in the report.
            audit_summary: Aggregated audit trail statistics.
            audit_log_path: Path to the JSONL audit log.
            audit_entries: Pre-parsed audit entries; parsed from file if None.
            sources_list: Evidence source rows for the source table.
            evidence_integrity: Evidence registry entries with file hashes.

        Returns:
            Rendered markdown report string.
        """
        ctx = self.build_context(
            case_metadata,
            findings,
            audit_summary,
            audit_log_path,
            audit_entries=audit_entries,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
        )
        return self._render_markdown(ctx)

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
        """Render the HTML report with markdown descriptions converted to HTML.

        Convenience wrapper that builds context and renders HTML in one
        call. Use ``render_all`` when both formats are needed.

        Args:
            case_metadata: Row from the case metadata table.
            findings: Validated findings to include in the report.
            audit_summary: Aggregated audit trail statistics.
            audit_log_path: Path to the JSONL audit log.
            audit_entries: Pre-parsed audit entries; parsed from file if None.
            sources_list: Evidence source rows for the source table.
            evidence_integrity: Evidence registry entries with file hashes.
            source_windows: Per-source raw text windows for the HTML report.

        Returns:
            Rendered HTML report string.
        """
        ctx = self.build_context(
            case_metadata,
            findings,
            audit_summary,
            audit_log_path,
            audit_entries=audit_entries,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
            source_windows=source_windows,
        )
        return self._render_html(ctx)

    def render_all(
        self,
        case_metadata: CaseMetadataRow,
        findings: list[Finding],
        audit_summary: AuditSummary,
        audit_log_path: Path | str,
        audit_entries: list[dict[str, Any]] | None = None,
        sources_list: list[SourceRow] | None = None,
        evidence_integrity: list[dict[str, object]] | None = None,
        source_windows: dict[str, list[dict[str, Any]]] | None = None,
        generate_pdf: bool = True,
    ) -> tuple[str, str, bytes | None]:
        """Render markdown, HTML, and optionally PDF reports.

        Avoids the cost of building the template context twice when both
        output formats are needed. Markdown is rendered first from the
        unmodified context; HTML rendering then augments the context with
        converted description HTML.

        Args:
            case_metadata: Row from the case metadata table.
            findings: Validated findings to include in the report.
            audit_summary: Aggregated audit trail statistics.
            audit_log_path: Path to the JSONL audit log.
            audit_entries: Pre-parsed audit entries; parsed from file if None.
            sources_list: Evidence source rows for the source table.
            evidence_integrity: Evidence registry entries with file hashes.
            source_windows: Per-source raw text windows for the HTML report.
            generate_pdf: Attempt PDF generation if weasyprint is available.

        Returns:
            Tuple of (markdown_text, html_text, pdf_bytes_or_none).
        """
        ctx = self.build_context(
            case_metadata,
            findings,
            audit_summary,
            audit_log_path,
            audit_entries=audit_entries,
            sources_list=sources_list,
            evidence_integrity=evidence_integrity,
            source_windows=source_windows,
        )
        md_text = self._render_markdown(ctx)
        html_text = self._render_html(dict(ctx))

        pdf_bytes: bytes | None = None
        if generate_pdf:
            pdf_bytes = self._render_pdf(html_text, case_metadata.case_id)

        return md_text, html_text, pdf_bytes
