"""Defense evasion, execution chains, recovery, and PCAP correlation composite MCP tools."""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from mulder.models import WindowRow
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    _HINT_CHAR_LIMIT,
    _PREVIEW_CHAR_LIMIT,
    extract_module_names,
    extract_pid,
    extract_pids_from_windows,
    hash_output,
    make_tool_call_id,
    slim_window,
)
from mulder.server.tools_composite_core import (
    _IP_RE,
    _PORT_RE,
    _SRC_CMDLINE,
    _SRC_DLLLIST,
    _SRC_EVTX_SECURITY,
    _SRC_EVTX_SYSTEM,
    _SRC_EZ_AMCACHE,
    _SRC_EZ_EVTX_SECURITY,
    _SRC_EZ_MFT,
    _SRC_EZ_PREFETCH,
    _SRC_EZ_SHIMCACHE,
    _SRC_EZ_USNJRNL,
    _SRC_MODSCAN,
    _SRC_MODULES,
    _SRC_NETSCAN,
    _SRC_PCAP_CONVERSATIONS,
    _SRC_PCAP_DNS,
    _SRC_PCAP_HTTP,
    _SRC_PLASO,
    _SRC_PSLIST,
    _SRC_PSSCAN,
    _SRC_PSTREE,
    _SRC_TSK_FILELIST,
    _UNUSUAL_DLL_PATHS,
    _build_pid_metadata,
    _check_missing_sources,
    _extract_exe_name,
    _extract_process_name,
    _keyword_sub_query,
    _query_source,
    _source_exists,
    _strip_source_windows,
)

__all__ = [
    "find_defense_evasion",
    "reconstruct_execution_chains",
    "assess_recovery",
    "correlate_pcap_with_host",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SECURITY_PROCESSES: set[str] = {
    "msmpeng.exe",
    "msseces.exe",
    "savservice.exe",
    "ccsvchst.exe",
    "avp.exe",
    "avgnt.exe",
    "bdagent.exe",
    "ekrn.exe",
    "mbam.exe",
    "mbamservice.exe",
    "sfc.exe",
    "windefend",
    "sense.exe",
    "mpcmdrun.exe",
    "nissrv.exe",
    "carbonblack",
    "cbdefense",
    "crowdstrike",
    "csfalconservice.exe",
    "taniumclient.exe",
    "sentinelagent.exe",
    "cyoptics.exe",
}

_SYSTEM_PARENTS: set[str] = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "svchost.exe",
    "explorer.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "dwm.exe",
}

_SECURE_DELETE_TOOLS: set[str] = {
    "sdelete.exe",
    "sdelete64.exe",
    "eraser.exe",
    "cipher.exe",
    "bleachbit.exe",
    "bcwipe.exe",
    "ccleaner.exe",
    "ccleaner64.exe",
    "dban",
    "shred",
}

# ---------------------------------------------------------------------------
# Defense evasion helpers
# ---------------------------------------------------------------------------


def _check_timestomping(
    indicators: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Search UsnJrnl and MFT for timestamp discrepancy indicators."""
    usnjrnl_wins, tc_usn = _keyword_sub_query(
        "timestamp modification created renamed file entry discrepancy",
        "find_defense_evasion",
        source_name=_SRC_EZ_USNJRNL,
        k=20,
    )
    sub_call_ids.append(tc_usn)

    mft_wins, tc_mft = _keyword_sub_query(
        "standard information filename attribute timestamp mismatch created",
        "find_defense_evasion",
        source_name=_SRC_EZ_MFT,
        k=20,
    )
    sub_call_ids.append(tc_mft)

    for w in usnjrnl_wins + mft_wins:
        text_lower = w.raw_text.lower()
        if any(kw in text_lower for kw in ("timestamp", "stomp", "mismatch", "modified")):
            indicators.append(
                {
                    "type": "potential_timestomping",
                    "source": w.raw_text[:20],
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
                    "source_window": slim_window(w),
                }
            )


def _check_log_clearing(
    indicators: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Detect Event IDs 104 (system log cleared) and 1102 (security log cleared)."""
    clear_wins, tc_clear = _keyword_sub_query(
        "event log cleared event 104 1102 audit log cleared",
        "find_defense_evasion",
        source_name=_SRC_EVTX_SECURITY,
        k=20,
    )
    sub_call_ids.append(tc_clear)

    sys_clear_wins, tc_sys = _keyword_sub_query(
        "event log cleared event 104 system log cleared",
        "find_defense_evasion",
        source_name=_SRC_EVTX_SYSTEM,
        k=10,
    )
    sub_call_ids.append(tc_sys)

    for w in clear_wins + sys_clear_wins:
        text = w.raw_text
        if "104" in text or "1102" in text or "cleared" in text.lower():
            indicators.append(
                {
                    "type": "log_clearing",
                    "event_time": w.event_time,
                    "evidence_text": text.strip()[:_PREVIEW_CHAR_LIMIT],
                    "source_window": slim_window(w),
                }
            )


def _check_hidden_processes_defense(
    indicators: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Detect hidden processes by comparing psscan vs pslist."""
    if not _source_exists(_SRC_PSSCAN) or not _source_exists(_SRC_PSLIST):
        return
    psscan_wins, tc_ps = _query_source(_SRC_PSSCAN, "find_defense_evasion")
    sub_call_ids.append(tc_ps)
    pslist_wins, tc_pl = _query_source(_SRC_PSLIST, "find_defense_evasion")
    sub_call_ids.append(tc_pl)

    psscan_pids = extract_pids_from_windows(psscan_wins)
    pslist_pids = extract_pids_from_windows(pslist_wins)
    hidden = set(psscan_pids) - set(pslist_pids)

    for pid in sorted(hidden):
        all_wins = [slim_window(w) for w in psscan_pids[pid]]
        indicators.append(
            {
                "type": "hidden_process",
                "pid": pid,
                "source": _SRC_PSSCAN,
                "source_windows": all_wins[:5],
                "window_count": len(all_wins),
            }
        )


def _check_hidden_kernel_modules(
    indicators: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Detect hidden kernel modules by comparing modscan vs modules."""
    if not _source_exists(_SRC_MODULES) or not _source_exists(_SRC_MODSCAN):
        return
    modules_wins, tc_mod = _query_source(_SRC_MODULES, "find_defense_evasion")
    sub_call_ids.append(tc_mod)
    modscan_wins, tc_ms = _query_source(_SRC_MODSCAN, "find_defense_evasion")
    sub_call_ids.append(tc_ms)

    linked = extract_module_names(modules_wins)
    scanned = extract_module_names(modscan_wins)
    hidden = set(scanned) - set(linked)

    for name in sorted(hidden):
        all_wins = [slim_window(w) for w in scanned[name]]
        indicators.append(
            {
                "type": "hidden_kernel_module",
                "module_name": name,
                "source": _SRC_MODSCAN,
                "source_windows": all_wins[:5],
                "window_count": len(all_wins),
            }
        )


def _check_disabled_security(
    indicators: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Detect termination of security/AV/EDR processes."""
    sec_wins, tc_sec = _keyword_sub_query(
        "taskkill process terminated antivirus security defender disable stop",
        "find_defense_evasion",
        source_name=_SRC_PLASO,
        k=20,
    )
    sub_call_ids.append(tc_sec)

    for w in sec_wins:
        text_lower = w.raw_text.lower()
        matched = next(
            (proc for proc in _SECURITY_PROCESSES if proc in text_lower),
            None,
        )
        if matched is not None or "taskkill" in text_lower:
            indicators.append(
                {
                    "type": "disabled_security",
                    "matched_process": matched,
                    "source": _SRC_PLASO,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
                    "source_window": slim_window(w),
                }
            )

    if _source_exists(_SRC_CMDLINE):
        cmd_wins, tc_cmd = _query_source(_SRC_CMDLINE, "find_defense_evasion")
        sub_call_ids.append(tc_cmd)
        for w in cmd_wins:
            text_lower = w.raw_text.lower()
            if "taskkill" not in text_lower and "stop-service" not in text_lower:
                continue
            matched = next(
                (proc for proc in _SECURITY_PROCESSES if proc in text_lower),
                None,
            )
            if matched is not None:
                indicators.append(
                    {
                        "type": "disabled_security",
                        "matched_process": matched,
                        "source": "volatility.cmdline",
                        "event_time": w.event_time,
                        "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
                        "source_window": slim_window(w),
                    }
                )


# ---------------------------------------------------------------------------
# Execution chains helpers
# ---------------------------------------------------------------------------


def _build_process_graph(
    pstree_wins: list[WindowRow],
    cmdline_pids: dict[int, list[WindowRow]],
    netscan_pids: dict[int, list[WindowRow]],
    dlllist_pids: dict[int, list[WindowRow]] | None,
    malfind_pids: dict[int, list[WindowRow]],
) -> dict[int, dict[str, Any]]:
    """Build a per-PID node dict with children, cmdline, net, DLL info."""
    flat_cmdline_wins = [w for ws in cmdline_pids.values() for w in ws]
    parent_map, pid_names = _build_pid_metadata(pstree_wins, flat_cmdline_wins)
    nodes: dict[int, dict[str, Any]] = {}

    all_pids = set(pid_names.keys())
    for pid in all_pids:
        name = pid_names.get(pid, "unknown")
        cmdline = " ".join(w.raw_text.strip() for w in cmdline_pids.get(pid, []))
        connections = [w.raw_text.strip() for w in netscan_pids.get(pid, [])]
        dll_anomalies: list[str] = []
        if dlllist_pids and pid in dlllist_pids:
            for w in dlllist_pids[pid]:
                path_lower = w.raw_text.lower()
                if any(pat in path_lower for pat in _UNUSUAL_DLL_PATHS):
                    dll_anomalies.append(w.raw_text.strip()[:_HINT_CHAR_LIMIT])

        nodes[pid] = {
            "pid": pid,
            "name": name,
            "parent_pid": parent_map.get(pid),
            "parent_name": pid_names.get(parent_map.get(pid, -1), "unknown"),
            "cmdline": cmdline[:_PREVIEW_CHAR_LIMIT],
            "network_connections": connections[:10],
            "dll_anomalies": dll_anomalies[:5],
            "malfind_hit": pid in malfind_pids,
            "children": [],
        }

    for pid, node in nodes.items():
        ppid = node["parent_pid"]
        if ppid and ppid in nodes:
            nodes[ppid]["children"].append(pid)

    return nodes


def _extract_chains(nodes: dict[int, dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Identify chain roots and walk their trees."""
    chains: list[list[dict[str, Any]]] = []
    for pid, node in nodes.items():
        parent_name = node["parent_name"].lower()
        if parent_name in _SYSTEM_PARENTS and node["name"].lower() not in _SYSTEM_PARENTS:
            chain = _walk_chain(nodes, pid)
            if (
                len(chain) > 1
                or node["malfind_hit"]
                or node["network_connections"]
                or node["dll_anomalies"]
            ):
                chains.append(chain)
    chains.sort(
        key=lambda c: sum(1 for n in c if n["malfind_hit"] or n["network_connections"]),
        reverse=True,
    )
    return chains


def _walk_chain(nodes: dict[int, dict[str, Any]], root_pid: int) -> list[dict[str, Any]]:
    """BFS walk from root_pid through children."""
    chain: list[dict[str, Any]] = []
    queue: deque[int] = deque([root_pid])
    visited: set[int] = set()
    while queue:
        pid = queue.popleft()
        if pid in visited:
            continue
        visited.add(pid)
        node = nodes.get(pid)
        if not node:
            continue
        chain.append(node)
        queue.extend(node.get("children", []))
    return chain


# ---------------------------------------------------------------------------
# PCAP correlation helpers
# ---------------------------------------------------------------------------


def _extract_pcap_indicators(
    pcap_sources: list[str],
    caller_name: str,
    sub_call_ids: list[str],
) -> tuple[set[str], set[int]]:
    """Extract unique IP addresses and ports from PCAP source windows.

    Args:
        pcap_sources: Source names to query (e.g. pcap.conversations, pcap.dns).
        caller_name: Tool name for audit trail.
        sub_call_ids: Mutable list; appended with IDs from sub-queries.

    Returns:
        Tuple of (IP address set, port number set) extracted from all PCAP windows.
    """
    pcap_ips: set[str] = set()
    pcap_ports: set[int] = set()
    ip_re = _IP_RE
    port_re = _PORT_RE

    for pcap_src in pcap_sources:
        if not _source_exists(pcap_src):
            continue
        wins, tc_id = _query_source(pcap_src, caller_name)
        sub_call_ids.append(tc_id)
        for w in wins:
            for m in ip_re.finditer(w.raw_text):
                pcap_ips.add(m.group())
            for m in port_re.finditer(w.raw_text):
                pcap_ports.add(int(m.group(1)))

    return pcap_ips, pcap_ports


def _correlate_with_netscan(
    pcap_ips: set[str],
    pcap_ports: set[int],
    caller_name: str,
    sub_call_ids: list[str],
) -> list[dict[str, Any]]:
    """Match PCAP IP indicators against Volatility netscan connections.

    Args:
        pcap_ips: Set of IP addresses observed in PCAP data.
        pcap_ports: Set of port numbers observed in PCAP data.
        caller_name: Tool name for audit trail.
        sub_call_ids: Mutable list; appended with IDs from sub-queries.

    Returns:
        List of correlation dicts for each netscan entry with overlapping IPs.
    """
    correlations: list[dict[str, Any]] = []
    if not _source_exists(_SRC_NETSCAN):
        return correlations

    netscan_wins, tc_net = _query_source(_SRC_NETSCAN, caller_name)
    sub_call_ids.append(tc_net)
    ip_re = _IP_RE

    for w in netscan_wins:
        netscan_ips = {m.group() for m in ip_re.finditer(w.raw_text)}
        overlap = netscan_ips & pcap_ips
        if overlap:
            pid = extract_pid(w.raw_text)
            proc_name = _extract_process_name(w.raw_text)
            correlations.append(
                {
                    "type": "pcap_netscan_ip_match",
                    "matched_ips": sorted(overlap),
                    "pid": pid,
                    "process": proc_name,
                    "netscan_text": w.raw_text.strip()[:300],
                }
            )

    return correlations


# ---------------------------------------------------------------------------
# Recovery assessment helpers
# ---------------------------------------------------------------------------


def _collect_deleted_files(sub_call_ids: list[str]) -> int:
    """Query TSK filelist and return the count of deleted file entries.

    Deleted entries are identified by the ``* `` marker prefix in the
    raw text produced by ``fls``.
    """
    deleted_wins, tc = _query_source(_SRC_TSK_FILELIST, "assess_recovery")
    sub_call_ids.append(tc)
    return len([w for w in deleted_wins if "* " in w.raw_text])


def _collect_secure_delete_hits(
    sub_call_ids: list[str],
) -> list[dict[str, Any]]:
    """Detect secure-delete tool execution and log clearing as anti-forensics indicators.

    Searches execution artifact sources (prefetch, amcache, shimcache)
    for known secure-delete utilities and event log sources for log
    clearing events (Event IDs 104, 1102).
    """
    anti_forensics: list[dict[str, Any]] = []

    for src in (_SRC_EZ_PREFETCH, _SRC_EZ_AMCACHE, _SRC_EZ_SHIMCACHE):
        if not _source_exists(src):
            continue
        wins, tc = _query_source(src, "assess_recovery")
        sub_call_ids.append(tc)
        for w in wins:
            text_lower = w.raw_text.lower()
            matched = next(
                (tool for tool in _SECURE_DELETE_TOOLS if tool in text_lower),
                None,
            )
            if matched:
                anti_forensics.append(
                    {
                        "type": "secure_delete_tool",
                        "tool": matched,
                        "source": src,
                        "evidence_text": w.raw_text.strip()[:300],
                    }
                )

    for evtx_src in (_SRC_EVTX_SECURITY, _SRC_EVTX_SYSTEM):
        if not _source_exists(evtx_src):
            continue
        evtx_wins, tc = _keyword_sub_query(
            "log cleared event 104 1102 audit log cleared wiped",
            "assess_recovery",
            source_name=evtx_src,
            k=10,
        )
        sub_call_ids.append(tc)
        for w in evtx_wins:
            text = w.raw_text
            if "104" in text or "1102" in text or "cleared" in text.lower():
                anti_forensics.append(
                    {
                        "type": "log_clearing",
                        "source": evtx_src,
                        "event_time": w.event_time,
                        "evidence_text": text.strip()[:300],
                    }
                )

    return anti_forensics


def _collect_usn_deletion_hits(
    sub_call_ids: list[str],
) -> list[dict[str, Any]]:
    """Scan USN journal for file deletion activity.

    Performs a keyword sub-query for FILE_DELETE / CLOSE entries and
    returns matching evidence snippets.
    """
    if not _source_exists(_SRC_EZ_USNJRNL):
        return []

    usn_wins, tc = _keyword_sub_query(
        "FILE_DELETE CLOSE rename delete",
        "assess_recovery",
        source_name=_SRC_EZ_USNJRNL,
        k=30,
    )
    sub_call_ids.append(tc)

    deletions: list[dict[str, Any]] = []
    for w in usn_wins:
        text_lower = w.raw_text.lower()
        if "delete" in text_lower or "close" in text_lower:
            deletions.append(
                {
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:_HINT_CHAR_LIMIT],
                }
            )

    return deletions


def _build_recovery_assessment(
    total_deleted: int,
    anti_forensics: list[dict[str, Any]],
    usnjrnl_deletions: list[dict[str, Any]],
) -> dict[str, object]:
    """Build the final recovery assessment from collected evidence sections.

    Combines deleted file counts, anti-forensics indicators, and USN
    journal deletion samples into a single scored assessment dict.
    """
    evidence_gaps: list[str] = []
    if anti_forensics:
        evidence_gaps.append(
            "Secure delete tools detected -- some deleted files may be unrecoverable"
        )
    if any(item.get("type") == "log_clearing" for item in anti_forensics):
        evidence_gaps.append("Event log clearing detected -- some log evidence has been destroyed")

    return {
        "total_deleted_files": total_deleted,
        "anti_forensics_detected": anti_forensics,
        "anti_forensics_count": len(anti_forensics),
        "usnjrnl_deletions_sampled": usnjrnl_deletions[:20],
        "evidence_gaps": evidence_gaps,
    }


# ---------------------------------------------------------------------------
# MCP tool handlers
# ---------------------------------------------------------------------------


@mcp.tool()
def find_defense_evasion() -> dict[str, object]:
    """Detect defense evasion techniques across memory, filesystem, and event logs.

    Checks for timestomping (UsnJrnl vs MFT timestamp discrepancies),
    log clearing (Event IDs 104 and 1102), hidden processes (psscan vs
    pslist diff), hidden kernel modules (modscan vs modules diff), and
    disabled security tools (AV/EDR process termination patterns).
    Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []
    indicators: list[dict[str, Any]] = []

    _check_timestomping(indicators, sub_call_ids)
    _check_log_clearing(indicators, sub_call_ids)
    _check_hidden_processes_defense(indicators, sub_call_ids)
    _check_hidden_kernel_modules(indicators, sub_call_ids)
    _check_disabled_security(indicators, sub_call_ids)

    missing = _check_missing_sources(
        [
            ("volatility.psscan", "run_volatility('psscan', '<memory_path>')"),
            ("volatility.pslist", "run_volatility('pslist', '<memory_path>')"),
            ("volatility.modules", "run_volatility('modules', '<memory_path>')"),
            ("evtx.security", "run_evtx_parser('<evtx_path>')"),
            ("ez.usnjrnl", "run_mft_parser('<image_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_defense_evasion",
        params={},
        output_hash=hash_output(indicators),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _strip_source_windows(indicators)
    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": indicators,
        "source": None,
        "result_count": len(indicators),
    }
    if missing:
        result["missing_sources"] = missing
    return result


@mcp.tool()
def reconstruct_execution_chains() -> dict[str, object]:
    """Reconstruct parent-child process execution chains from memory forensics.

    Builds a directed graph from Volatility pstree/pslist data, attaches
    command lines, network connections, DLL anomalies, and malfind hits
    to each node, then identifies chains rooted at system processes that
    spawn suspicious children.  Correlates with prefetch/amcache/shimcache
    when available.  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    pstree_wins, tc1 = _query_source(_SRC_PSTREE, "reconstruct_execution_chains")
    sub_call_ids.append(tc1)
    cmdline_wins, tc2 = _query_source(_SRC_CMDLINE, "reconstruct_execution_chains")
    sub_call_ids.append(tc2)
    netscan_wins, tc3 = _query_source(_SRC_NETSCAN, "reconstruct_execution_chains")
    sub_call_ids.append(tc3)
    malfind_wins, tc4 = _query_source("volatility.malfind", "reconstruct_execution_chains")
    sub_call_ids.append(tc4)

    dlllist_wins: list[WindowRow] = []
    if _source_exists(_SRC_DLLLIST):
        dlllist_wins, tc_dll = _query_source(_SRC_DLLLIST, "reconstruct_execution_chains")
        sub_call_ids.append(tc_dll)

    cmdline_pids = extract_pids_from_windows(cmdline_wins)
    netscan_pids = extract_pids_from_windows(netscan_wins)
    malfind_pids = extract_pids_from_windows(malfind_wins)
    dlllist_pids = extract_pids_from_windows(dlllist_wins) if dlllist_wins else None

    nodes = _build_process_graph(
        pstree_wins, cmdline_pids, netscan_pids, dlllist_pids, malfind_pids
    )
    chains = _extract_chains(nodes)

    prefetch_data: dict[str, dict[str, Any]] = {}
    if _source_exists(_SRC_EZ_PREFETCH):
        pf_wins, tc_pf = _query_source(_SRC_EZ_PREFETCH, "reconstruct_execution_chains")
        sub_call_ids.append(tc_pf)
        for w in pf_wins:
            exe = _extract_exe_name(w.raw_text)
            if exe and exe not in prefetch_data:
                prefetch_data[exe] = {
                    "event_time": w.event_time,
                    "text": w.raw_text[:_HINT_CHAR_LIMIT],
                }

    for chain in chains:
        for node in chain:
            exe_lower = node["name"].lower()
            if exe_lower in prefetch_data:
                node["prefetch_first_run"] = prefetch_data[exe_lower].get("event_time")

    missing = _check_missing_sources(
        [
            ("volatility.pstree", "run_volatility('pstree', '<memory_path>')"),
            ("volatility.cmdline", "run_volatility('cmdline', '<memory_path>')"),
            ("volatility.netscan", "run_volatility('netscan', '<memory_path>')"),
            ("volatility.malfind", "run_volatility('malfind', '<memory_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="reconstruct_execution_chains",
        params={},
        output_hash=hash_output(chains),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _strip_source_windows(chains)
    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": chains,
        "source": None,
        "result_count": len(chains),
    }
    if missing:
        result["missing_sources"] = missing
    return result


@mcp.tool()
def assess_recovery() -> dict[str, object]:
    """Assess evidence recoverability by cross-referencing deleted files,
    carving results, and anti-forensics indicators.

    Queries deleted file listings, checks for secure-delete tool
    execution evidence, looks for log clearing events, and produces
    a structured recovery assessment.  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    total_deleted = _collect_deleted_files(sub_call_ids)
    anti_forensics = _collect_secure_delete_hits(sub_call_ids)
    usnjrnl_deletions = _collect_usn_deletion_hits(sub_call_ids)
    assessment = _build_recovery_assessment(total_deleted, anti_forensics, usnjrnl_deletions)

    missing = _check_missing_sources(
        [
            ("tsk.filelist", "run_fls('<image_path>')"),
            ("ez.prefetch", "run_prefetch_parser('<image_path>')"),
            ("ez.usnjrnl", "parse_usn_journal('<image_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="assess_recovery",
        params={},
        output_hash=hash_output(assessment),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _strip_source_windows(assessment.get("anti_forensics_detected", []))
    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": assessment,
        "source": None,
        "result_count": 1,
    }
    if missing:
        result["missing_sources"] = missing
    return result


@mcp.tool()
def correlate_pcap_with_host(
    t_start: str | None = None,
    t_end: str | None = None,
) -> dict[str, object]:
    """Cross-reference PCAP network events with host artifacts.

    Matches IPs and ports from PCAP conversations/DNS with Volatility
    netscan connections, correlates PCAP timestamps with event log and
    prefetch data to link network activity to host processes.  Read-only.

    Args:
        t_start: Optional ISO-8601 start time for correlation window.
        t_end: Optional ISO-8601 end time for correlation window.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    pcap_ips, pcap_ports = _extract_pcap_indicators(
        [_SRC_PCAP_CONVERSATIONS, _SRC_PCAP_DNS, _SRC_PCAP_HTTP],
        "correlate_pcap_with_host",
        sub_call_ids,
    )

    correlations = _correlate_with_netscan(
        pcap_ips, pcap_ports, "correlate_pcap_with_host", sub_call_ids
    )

    if t_start and t_end:
        evtx_src = (
            _SRC_EZ_EVTX_SECURITY if _source_exists(_SRC_EZ_EVTX_SECURITY) else _SRC_EVTX_SECURITY
        )
        if _source_exists(evtx_src):
            evtx_wins, tc_evtx = _keyword_sub_query(
                f"logon event network connection {t_start}",
                "correlate_pcap_with_host",
                source_name=evtx_src,
                k=15,
            )
            sub_call_ids.append(tc_evtx)
            for w in evtx_wins:
                evtx_ips = {m.group() for m in _IP_RE.finditer(w.raw_text)}
                overlap = evtx_ips & pcap_ips
                if overlap:
                    correlations.append(
                        {
                            "type": "pcap_evtx_ip_match",
                            "matched_ips": sorted(overlap),
                            "event_time": w.event_time,
                            "evidence_text": w.raw_text.strip()[:300],
                        }
                    )

    missing = _check_missing_sources(
        [
            ("pcap.conversations", "run_pcap_analysis('<pcap_path>', mode='conversations')"),
            ("volatility.netscan", "run_volatility('netscan', '<memory_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="correlate_pcap_with_host",
        params={"t_start": t_start, "t_end": t_end},
        output_hash=hash_output(correlations),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _strip_source_windows(correlations)
    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": correlations,
        "source": None,
        "result_count": len(correlations),
    }
    if missing:
        result["missing_sources"] = missing
    return result
