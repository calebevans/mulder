"""Composite MCP tools that join results from multiple evidence sources.

These higher-level tools combine artifacts from different forensic sources
(memory, event logs, registry, timeline) into single coherent answers.
Every tool is read-only -- evidence integrity is enforced by API design.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from uuid import uuid4

from mulder.models import WindowRow
from mulder.server.app import get_ctx, mcp

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

_LOLBINS: set[str] = {
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wmic.exe",
    "msbuild.exe",
    "cscript.exe",
    "wscript.exe",
    "powershell.exe",
    "cmd.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "installutil.exe",
    "cmstp.exe",
}

_ENCODED_PS_PATTERNS: list[str] = [
    "-enc ",
    "-encodedcommand ",
    "frombase64string",
    "-e ",
    "iex(",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "net.webclient",
    "bitstransfer",
]

_PERSISTENCE_KEYS: list[str] = [
    "\\Run\\",
    "\\RunOnce\\",
    "\\RunServices\\",
    "\\Userinit",
    "\\Shell",
    "AppInit_DLLs",
    "\\Winlogon\\",
    "\\Explorer\\Shell Folders",
    "WMI",
    "\\Services\\",
    "\\CurrentVersion\\Image File Execution",
]

_LATERAL_PORTS: set[int] = {445, 3389, 5985, 5986, 135}

_CORRELATION_WINDOW_SECONDS = 30

_SRC_NETSCAN = "volatility.netscan"
_SRC_PLASO = "plaso.timeline"
_SRC_EVTX_SECURITY = "evtx.security"
_SRC_EVTX_SYSTEM = "evtx.system"

# PID extraction: matches a column of digits that looks like a PID
# in Volatility tab-separated output (typically 2nd or 3rd column).
_PID_RE = re.compile(r"(?:^|\t)(\d{1,6})(?:\t|$)", re.MULTILINE)

# Port extraction from netscan output (e.g. "192.168.1.1:445" or ":3389")
_PORT_RE = re.compile(r":(\d{1,5})(?:\s|$)")

# Process name extraction (first non-empty tab-separated column that looks like a name)
_PROC_NAME_RE = re.compile(r"^([^\t]+\.exe)", re.MULTILINE | re.IGNORECASE)

# Parent PID: Volatility pslist/pstree put PPID in the column after PID
_PPID_RE = re.compile(r"(?:^|\t)(\d{1,6})\t(\d{1,6})(?:\t|$)", re.MULTILINE)

# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _make_tool_call_id() -> str:
    return f"tc_{uuid4().hex[:8]}"


def _hash_output(output: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(output, sort_keys=True, default=str).encode()).hexdigest()
    )


def _query_source(
    source_name: str,
    tool_name: str,
) -> tuple[list[WindowRow], str]:
    """Fetch all windows for a source, log as a sub-call, return (windows, tool_call_id)."""
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(source_name)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=f"{tool_name}._query({source_name})",
        params={"source_name": source_name},
        output_hash=_hash_output({"count": len(windows)}),
        duration_ms=elapsed,
    )
    return windows, tc_id


def _semantic_sub_query(
    query: str,
    tool_name: str,
    source_name: str | None = None,
    k: int = 20,
) -> tuple[list[WindowRow], str]:
    """Run a semantic search as a logged sub-call, return (windows, tool_call_id)."""
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    scored = ctx.query_engine.semantic_search(query, k=k, source_name=source_name)
    windows = [s.window for s in scored]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=f"{tool_name}._search({source_name or 'all'})",
        params={"query": query, "source": source_name, "k": k},
        output_hash=_hash_output({"count": len(windows)}),
        duration_ms=elapsed,
    )
    return windows, tc_id


def extract_pid(text: str) -> int | None:
    """Parse the first PID value from a Volatility output line."""
    m = _PID_RE.search(text)
    if m:
        val = int(m.group(1))
        if val > 0:
            return val
    return None


def _extract_pids_from_windows(windows: list[WindowRow]) -> dict[int, list[WindowRow]]:
    """Group windows by the PID found in their text."""
    pid_map: dict[int, list[WindowRow]] = defaultdict(list)
    for w in windows:
        pid = extract_pid(w.raw_text)
        if pid is not None:
            pid_map[pid].append(w)
    return dict(pid_map)


def _extract_process_name(text: str) -> str:
    """Best-effort extraction of a process name from Volatility output."""
    m = _PROC_NAME_RE.search(text)
    return m.group(1).strip() if m else "unknown"


def _extract_ports(text: str) -> list[int]:
    """Extract port numbers from netscan output text."""
    return [int(m.group(1)) for m in _PORT_RE.finditer(text)]


def _has_encoded_powershell(cmdline: str) -> bool:
    lower = cmdline.lower()
    return any(pat in lower for pat in _ENCODED_PS_PATTERNS)


def _is_lolbin(proc_name: str) -> bool:
    return proc_name.lower() in _LOLBINS


def _parse_event_time(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


_SUSPICIOUS_PARENTS: set[str] = {
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
}
_SUSPICIOUS_CHILDREN: set[str] = {
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}


def _build_pid_metadata(
    pstree_wins: list[WindowRow],
    cmdline_wins: list[WindowRow],
) -> tuple[dict[int, int], dict[int, str]]:
    """Extract parent-PID mapping and PID-to-name mapping from Volatility output."""
    parent_map: dict[int, int] = {}
    pid_names: dict[int, str] = {}
    for w in pstree_wins:
        m = _PPID_RE.search(w.raw_text)
        if m:
            parent_map[int(m.group(1))] = int(m.group(2))
        pid = extract_pid(w.raw_text)
        if pid is not None:
            pid_names[pid] = _extract_process_name(w.raw_text)
    for w in cmdline_wins:
        pid = extract_pid(w.raw_text)
        if pid is not None and pid not in pid_names:
            pid_names[pid] = _extract_process_name(w.raw_text)
    return parent_map, pid_names


def _analyze_pid(
    pid: int,
    *,
    pid_names: dict[int, str],
    parent_map: dict[int, int],
    malfind_pids: dict[int, list[WindowRow]],
    cmdline_pids: dict[int, list[WindowRow]],
    netscan_pids: dict[int, list[WindowRow]],
    pstree_pids: dict[int, list[WindowRow]],
) -> dict | None:
    """Evaluate a single PID for suspicion indicators. Returns None if benign."""
    reasons: list[str] = []
    source_windows: list[dict] = []
    connections: list[str] = []
    name = pid_names.get(pid, "unknown")
    parent_pid = parent_map.get(pid)
    parent_name = pid_names.get(parent_pid, "unknown") if parent_pid else "unknown"

    if pid in malfind_pids:
        reasons.append("malfind_injection")
        source_windows.extend(w.model_dump() for w in malfind_pids[pid])

    if pid in cmdline_pids:
        cmdline_text = " ".join(w.raw_text for w in cmdline_pids[pid])
        if _has_encoded_powershell(cmdline_text):
            reasons.append("encoded_powershell")
        source_windows.extend(w.model_dump() for w in cmdline_pids[pid])

    if _is_lolbin(name):
        reasons.append("lolbin_execution")

    if pid in netscan_pids:
        for w in netscan_pids[pid]:
            connections.append(w.raw_text.strip())
        if _netscan_has_external(netscan_pids[pid]):
            reasons.append("external_network_connection")
        source_windows.extend(w.model_dump() for w in netscan_pids[pid])

    if parent_name.lower() in _SUSPICIOUS_PARENTS and name.lower() in _SUSPICIOUS_CHILDREN:
        reasons.append("suspicious_parent")

    if pid in pstree_pids:
        source_windows.extend(w.model_dump() for w in pstree_pids[pid])

    if not reasons:
        return None

    return {
        "pid": pid,
        "name": name,
        "parent_pid": parent_pid,
        "parent_name": parent_name,
        "cmdline": " ".join(w.raw_text.strip() for w in cmdline_pids.get(pid, [])),
        "malfind_hit": pid in malfind_pids,
        "network_connections": connections,
        "suspicion_reasons": reasons,
        "source_windows": source_windows,
    }


def _netscan_has_external(windows: list[WindowRow]) -> bool:
    """Check if any netscan window shows a connection on a non-standard high port."""
    for w in windows:
        ports = _extract_ports(w.raw_text)
        if any(p not in _LATERAL_PORTS and p > 1024 for p in ports):
            return True
    return False


# ------------------------------------------------------------------
# Tool: find_suspicious_processes
# ------------------------------------------------------------------


@mcp.tool()
def find_suspicious_processes() -> dict:
    """Identify suspicious processes by cross-referencing memory forensics artifacts.

    Joins data from Volatility malfind (code injection), cmdline (command
    arguments), netscan (network connections), and pstree (parent-child
    relationships).  Flags processes exhibiting indicators like code
    injection, encoded PowerShell, LOLBin usage, or unexpected parents
    with external network connections.  Read-only.
    """
    ctx = get_ctx()
    composite_id = _make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    malfind_wins, tc1 = _query_source("volatility.malfind", "find_suspicious_processes")
    sub_call_ids.append(tc1)

    cmdline_wins, tc2 = _query_source("volatility.cmdline", "find_suspicious_processes")
    sub_call_ids.append(tc2)

    netscan_wins, tc3 = _query_source(_SRC_NETSCAN, "find_suspicious_processes")
    sub_call_ids.append(tc3)

    pstree_wins, tc4 = _query_source("volatility.pstree", "find_suspicious_processes")
    sub_call_ids.append(tc4)

    malfind_pids = _extract_pids_from_windows(malfind_wins)
    cmdline_pids = _extract_pids_from_windows(cmdline_wins)
    netscan_pids = _extract_pids_from_windows(netscan_wins)
    pstree_pids = _extract_pids_from_windows(pstree_wins)

    all_pids = set(malfind_pids) | set(cmdline_pids) | set(netscan_pids) | set(pstree_pids)
    parent_map, pid_names = _build_pid_metadata(pstree_wins, cmdline_wins)

    suspicious: list[dict] = []
    for pid in sorted(all_pids):
        entry = _analyze_pid(
            pid,
            pid_names=pid_names,
            parent_map=parent_map,
            malfind_pids=malfind_pids,
            cmdline_pids=cmdline_pids,
            netscan_pids=netscan_pids,
            pstree_pids=pstree_pids,
        )
        if entry is not None:
            suspicious.append(entry)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_suspicious_processes",
        params={},
        output_hash=_hash_output(suspicious),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    return {
        "tool_call_id": composite_id,
        "results": suspicious,
        "source": None,
        "result_count": len(suspicious),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Persistence helpers
# ------------------------------------------------------------------


def _collect_registry_persistence(
    mechanisms: list[dict],
    sub_call_ids: list[str],
) -> None:
    for reg_source in ("registry.system", "registry.software"):
        wins, tc_id = _query_source(reg_source, "find_persistence_mechanisms")
        sub_call_ids.append(tc_id)
        for w in wins:
            text_lower = w.raw_text.lower()
            matched_key = next(
                (key for key in _PERSISTENCE_KEYS if key.lower() in text_lower),
                None,
            )
            if matched_key is not None:
                mechanisms.append(
                    {
                        "type": "registry_autorun",
                        "key_pattern": matched_key,
                        "source": reg_source,
                        "evidence_text": w.raw_text.strip()[:500],
                        "source_window": w.model_dump(),
                    }
                )


def _collect_service_persistence(
    mechanisms: list[dict],
    sub_call_ids: list[str],
) -> None:
    svcscan_wins, tc_svc = _query_source("volatility.svcscan", "find_persistence_mechanisms")
    sub_call_ids.append(tc_svc)
    for w in svcscan_wins:
        mechanisms.append(
            {
                "type": "installed_service",
                "source": "volatility.svcscan",
                "evidence_text": w.raw_text.strip()[:500],
                "source_window": w.model_dump(),
            }
        )


def _collect_evtx_service_installs(
    mechanisms: list[dict],
    sub_call_ids: list[str],
) -> None:
    evtx_wins, tc_evtx = _semantic_sub_query(
        "service installation event 7045 new service installed",
        "find_persistence_mechanisms",
        source_name=_SRC_EVTX_SYSTEM,
        k=20,
    )
    sub_call_ids.append(tc_evtx)
    for w in evtx_wins:
        if "7045" in w.raw_text or "service" in w.raw_text.lower():
            mechanisms.append(
                {
                    "type": "service_install_event",
                    "source": _SRC_EVTX_SYSTEM,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": w.model_dump(),
                }
            )


def _collect_startup_dir_modifications(
    mechanisms: list[dict],
    sub_call_ids: list[str],
) -> None:
    plaso_wins, tc_plaso = _semantic_sub_query(
        "startup directory autorun modification programs startup folder",
        "find_persistence_mechanisms",
        source_name=_SRC_PLASO,
        k=20,
    )
    sub_call_ids.append(tc_plaso)
    for w in plaso_wins:
        text_lower = w.raw_text.lower()
        if "startup" in text_lower or "autorun" in text_lower or "run\\" in text_lower:
            mechanisms.append(
                {
                    "type": "startup_directory_modification",
                    "source": _SRC_PLASO,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": w.model_dump(),
                }
            )


# ------------------------------------------------------------------
# Tool: find_persistence_mechanisms
# ------------------------------------------------------------------


@mcp.tool()
def find_persistence_mechanisms() -> dict:
    """Detect persistence mechanisms across registry, services, event logs, and timeline.

    Searches Windows registry hives for known autorun keys (Run, RunOnce,
    Userinit, AppInit_DLLs, etc.), cross-references with Volatility service
    scan output, checks event logs for service installation events (Event
    ID 7045), and inspects the Plaso timeline for modifications to startup
    directories.  Read-only.
    """
    ctx = get_ctx()
    composite_id = _make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []
    mechanisms: list[dict] = []

    _collect_registry_persistence(mechanisms, sub_call_ids)
    _collect_service_persistence(mechanisms, sub_call_ids)
    _collect_evtx_service_installs(mechanisms, sub_call_ids)
    _collect_startup_dir_modifications(mechanisms, sub_call_ids)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_persistence_mechanisms",
        params={},
        output_hash=_hash_output(mechanisms),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    return {
        "tool_call_id": composite_id,
        "results": mechanisms,
        "source": None,
        "result_count": len(mechanisms),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Lateral movement helpers
# ------------------------------------------------------------------

_LOGON_EVENT_TYPES = ("network_logon", "failed_logon", "explicit_credentials")


def _classify_logon_windows(
    logon_wins: list[WindowRow],
    failed_wins: list[WindowRow],
    cred_wins: list[WindowRow],
) -> list[dict]:
    """Classify security event log windows into typed indicator dicts."""
    indicators: list[dict] = []
    for w in logon_wins:
        text_lower = w.raw_text.lower()
        if "4624" not in w.raw_text and "logon" not in text_lower:
            continue
        logon_type = "network" if ("type 3" in text_lower or "type 10" in text_lower) else "other"
        indicators.append(
            {
                "type": "network_logon",
                "logon_type": logon_type,
                "source": _SRC_EVTX_SECURITY,
                "event_time": w.event_time,
                "evidence_text": w.raw_text.strip()[:500],
                "source_window": w.model_dump(),
            }
        )
    for w in failed_wins:
        text_lower = w.raw_text.lower()
        if "4625" in w.raw_text or "fail" in text_lower:
            indicators.append(
                {
                    "type": "failed_logon",
                    "source": _SRC_EVTX_SECURITY,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": w.model_dump(),
                }
            )
    for w in cred_wins:
        text_lower = w.raw_text.lower()
        if "4648" in w.raw_text or "credential" in text_lower or "runas" in text_lower:
            indicators.append(
                {
                    "type": "explicit_credentials",
                    "source": _SRC_EVTX_SECURITY,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": w.model_dump(),
                }
            )
    return indicators


def _collect_netscan_lateral(
    netscan_wins: list[WindowRow],
) -> tuple[list[dict], list[dict]]:
    """Filter netscan windows for lateral movement ports. Returns (indicators, connections)."""
    indicators: list[dict] = []
    for w in netscan_wins:
        matching_ports = [p for p in _extract_ports(w.raw_text) if p in _LATERAL_PORTS]
        if matching_ports:
            entry = {
                "type": "lateral_movement_port",
                "ports": matching_ports,
                "source": _SRC_NETSCAN,
                "event_time": w.event_time,
                "evidence_text": w.raw_text.strip()[:500],
                "source_window": w.model_dump(),
            }
            indicators.append(entry)
    return indicators, list(indicators)


def _collect_rdp_artifacts(rdp_wins: list[WindowRow]) -> list[dict]:
    indicators: list[dict] = []
    for w in rdp_wins:
        text_lower = w.raw_text.lower()
        if "rdp" in text_lower or "remote desktop" in text_lower or "bitmap" in text_lower:
            indicators.append(
                {
                    "type": "rdp_artifact",
                    "source": _SRC_PLASO,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": w.model_dump(),
                }
            )
    return indicators


def _correlate_by_timestamp(
    indicators: list[dict],
    lateral_connections: list[dict],
) -> list[dict]:
    """Find logon events within 30 seconds of a lateral-movement network connection."""
    logon_times = [
        (_parse_event_time(ind["event_time"]), ind)
        for ind in indicators
        if ind["type"] in _LOGON_EVENT_TYPES and ind.get("event_time")
    ]
    net_times = [
        (_parse_event_time(ind["event_time"]), ind)
        for ind in lateral_connections
        if ind.get("event_time")
    ]
    delta = timedelta(seconds=_CORRELATION_WINDOW_SECONDS)
    correlations: list[dict] = []
    for lt, logon_ind in logon_times:
        if lt is None:
            continue
        for nt, net_ind in net_times:
            if nt is None:
                continue
            if abs(lt - nt) <= delta:
                correlations.append(
                    {
                        "type": "temporal_correlation",
                        "logon_event": logon_ind["type"],
                        "network_port": net_ind.get("ports"),
                        "time_delta_seconds": abs((lt - nt).total_seconds()),
                        "logon_time": logon_ind["event_time"],
                        "connection_time": net_ind["event_time"],
                    }
                )
    return correlations


# ------------------------------------------------------------------
# Tool: find_lateral_movement_indicators
# ------------------------------------------------------------------


@mcp.tool()
def find_lateral_movement_indicators() -> dict:
    """Detect lateral movement by correlating logon events, network connections, and RDP artifacts.

    Searches Windows Security event log for network logons (Event ID 4624
    Type 3/10), failed logons (4625), and explicit credential use (4648).
    Cross-references with Volatility netscan for connections on SMB (445),
    RDP (3389), WinRM (5985/5986), and RPC (135) ports.  Checks the Plaso
    timeline for RDP bitmap cache and related artifacts.  Events are
    correlated by timestamp proximity (30-second window).  Read-only.
    """
    ctx = get_ctx()
    composite_id = _make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    logon_wins, tc_logon = _semantic_sub_query(
        "successful logon type 3 network logon event 4624 remote",
        "find_lateral_movement_indicators",
        source_name=_SRC_EVTX_SECURITY,
        k=20,
    )
    sub_call_ids.append(tc_logon)

    failed_wins, tc_failed = _semantic_sub_query(
        "failed logon event 4625 authentication failure brute force",
        "find_lateral_movement_indicators",
        source_name=_SRC_EVTX_SECURITY,
        k=20,
    )
    sub_call_ids.append(tc_failed)

    cred_wins, tc_cred = _semantic_sub_query(
        "explicit credentials logon event 4648 pass the hash runas",
        "find_lateral_movement_indicators",
        source_name=_SRC_EVTX_SECURITY,
        k=20,
    )
    sub_call_ids.append(tc_cred)

    indicators = _classify_logon_windows(logon_wins, failed_wins, cred_wins)

    netscan_wins, tc_net = _query_source(_SRC_NETSCAN, "find_lateral_movement_indicators")
    sub_call_ids.append(tc_net)
    net_indicators, lateral_connections = _collect_netscan_lateral(netscan_wins)
    indicators.extend(net_indicators)

    rdp_wins, tc_rdp = _semantic_sub_query(
        "RDP remote desktop bitmap cache default.rdp connection",
        "find_lateral_movement_indicators",
        source_name=_SRC_PLASO,
        k=20,
    )
    sub_call_ids.append(tc_rdp)
    indicators.extend(_collect_rdp_artifacts(rdp_wins))

    correlations = _correlate_by_timestamp(indicators, lateral_connections)
    indicators.extend(correlations)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_lateral_movement_indicators",
        params={},
        output_hash=_hash_output(indicators),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    return {
        "tool_call_id": composite_id,
        "results": indicators,
        "source": None,
        "result_count": len(indicators),
        "reduced": False,
        "reduction_ratio": None,
    }
