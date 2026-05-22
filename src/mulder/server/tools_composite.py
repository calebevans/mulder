"""Composite MCP tools that join results from multiple evidence sources.

These higher-level tools combine artifacts from different forensic sources
(memory, event logs, registry, timeline) into single coherent answers.
Every tool is read-only -- evidence integrity is enforced by API design.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

from mulder.models import SourceRow, WindowRow
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import hash_output, make_tool_call_id, slim_window


def _strip_source_windows(items: list[Any] | Any) -> None:
    """Remove ``source_windows`` / ``source_window`` from result dicts in-place.

    Handles nested lists (e.g., execution chains = list of list of dicts).
    The agent can retrieve evidence via ``search()`` when needed.
    """
    if not isinstance(items, list):
        return
    for item in items:
        if isinstance(item, dict):
            item.pop("source_windows", None)
            item.pop("source_window", None)
        elif isinstance(item, list):
            _strip_source_windows(item)


_EXE_POWERSHELL = "powershell.exe"
_EXE_CMD = "cmd.exe"

_LOLBINS: set[str] = {
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wmic.exe",
    "msbuild.exe",
    "cscript.exe",
    "wscript.exe",
    _EXE_POWERSHELL,
    _EXE_CMD,
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
_SRC_PSSCAN = "volatility.psscan"
_SRC_PSLIST = "volatility.pslist"
_SRC_ENVARS = "volatility.envars"
_SRC_PRIVS = "volatility.privs"
_SRC_CMDLINE = "volatility.cmdline"
_SRC_PSTREE = "volatility.pstree"
_SRC_DLLLIST = "volatility.dlllist"
_SRC_MODULES = "volatility.modules"
_SRC_MODSCAN = "volatility.modscan"
_SRC_PLASO = "plaso.timeline"
_SRC_EVTX_SECURITY = "evtx.security"
_SRC_EVTX_SYSTEM = "evtx.system"
_SRC_EZ_SHIMCACHE = "ez.shimcache"
_SRC_EZ_AMCACHE = "ez.amcache"
_SRC_EZ_PREFETCH = "ez.prefetch"
_SRC_EZ_EVTX_SECURITY = "ez.evtx.security"
_SRC_EZ_SRUM = "ez.srum"
_SRC_EZ_USNJRNL = "ez.usnjrnl"
_SRC_EZ_MFT = "ez.mft"
_SRC_EZ_JUMPLISTS = "ez.jumplists"
_SRC_EZ_LNKFILES = "ez.lnkfiles"
_SRC_TSK_FILELIST = "tsk.filelist"
_SRC_BULK_URL = "bulk.url"
_SRC_BULK_EMAIL = "bulk.email"
_SRC_BULK_DOMAIN = "bulk.domain"
_SRC_PCAP_CONVERSATIONS = "pcap.conversations"
_SRC_PCAP_DNS = "pcap.dns"
_SRC_PCAP_HTTP = "pcap.http"

_DANGEROUS_PRIVILEGES: set[str] = {"sedebugprivilege", "setcbprivilege"}

_UNUSUAL_DLL_PATHS: tuple[str, ...] = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\recycle",
)

_PERSISTENCE_EXECUTABLES: set[str] = {
    "schtasks.exe",
    "reg.exe",
    "sc.exe",
    "at.exe",
    "wmic.exe",
    "msiexec.exe",
    _EXE_POWERSHELL,
    _EXE_CMD,
    "bitsadmin.exe",
}

_STARTUP_PATH_PATTERNS: tuple[str, ...] = (
    "\\startup\\",
    "\\start menu\\programs\\startup\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
)

_EXFIL_SERVICES: tuple[str, ...] = (
    "mega.nz",
    "pastebin.com",
    "paste.ee",
    "dropbox.com",
    "drive.google.com",
    "docs.google.com",
    "wetransfer.com",
    "sendspace.com",
    "mediafire.com",
    "anonfiles.com",
    "file.io",
    "transfer.sh",
    "gofile.io",
    "catbox.moe",
    "temp.sh",
    "discord.com/api/webhooks",
    "telegram.org",
    "api.telegram.org",
)

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

_MODULE_NAME_RE = re.compile(r"^([^\t]+\.sys)", re.MULTILINE | re.IGNORECASE)

# PID extraction: matches a column of digits that looks like a PID
# in Volatility tab-separated output (typically 2nd or 3rd column).
_PID_RE = re.compile(r"(?:^|\t)(\d{1,6})(?:\t|$)", re.MULTILINE)

# Port extraction from netscan output (e.g. "192.168.1.1:445" or ":3389")
_PORT_RE = re.compile(r":(\d{1,5})(?:\s|$)")

# IPv4 address extraction
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Process name extraction (first non-empty tab-separated column that looks like a name)
_PROC_NAME_RE = re.compile(r"^([^\t]+\.exe)", re.MULTILINE | re.IGNORECASE)

# Parent PID: Volatility pslist/pstree put PPID in the column after PID
_PPID_RE = re.compile(r"(?:^|\t)(\d{1,6})\t(\d{1,6})(?:\t|$)", re.MULTILINE)


_sources_cache: list[SourceRow] | None = None
_sources_cache_case_id: str | None = None


def _get_cached_sources() -> list[SourceRow]:
    """Return cached sources for the current case, refreshing if case changed."""
    global _sources_cache, _sources_cache_case_id
    ctx = get_ctx()
    if _sources_cache is None or _sources_cache_case_id != ctx.case_id:
        _sources_cache = ctx.db.get_sources()
        _sources_cache_case_id = ctx.case_id
    return _sources_cache


def _source_exists(source_prefix: str) -> bool:
    """Return True if any indexed source matches *source_prefix* exactly or as a prefix."""
    return any(
        s.source_name == source_prefix or s.source_name.startswith(source_prefix + ".")
        for s in _get_cached_sources()
    )


def _find_matching_sources(source_prefix: str) -> list[str]:
    """Return all source names that match *source_prefix* exactly or as a prefix."""
    return [
        s.source_name
        for s in _get_cached_sources()
        if s.source_name == source_prefix or s.source_name.startswith(source_prefix + ".")
    ]


_NETWORK_SOURCE_ALTERNATIVES = ("volatility.netscan", "volatility.connscan", "volatility.sockscan")


def _check_missing_sources(
    required: list[tuple[str, str]],
) -> list[dict[str, str]]:
    """Return a list of missing sources with suggested extraction commands.

    *required* is a list of ``(source_name, suggested_command)`` pairs.
    Only returns entries for sources not yet indexed.  Uses prefix
    matching so ``volatility.netscan.host1`` satisfies ``volatility.netscan``.

    Network sources (netscan/connscan/sockscan) are treated as
    interchangeable -- having any one satisfies the requirement.
    """
    missing = []
    for src, cmd in required:
        if src in _NETWORK_SOURCE_ALTERNATIVES:
            if not any(_source_exists(alt) for alt in _NETWORK_SOURCE_ALTERNATIVES):
                missing.append({"source": src, "suggestion": cmd})
        elif not _source_exists(src):
            missing.append({"source": src, "suggestion": cmd})
    return missing


_SEVERITY_WEIGHTS = {
    "malfind_injection": 10,
    "suspicious_network": 8,
    "hidden_process": 9,
    "suspicious_cmdline": 7,
    "unusual_parent": 6,
    "suspicious_dll_path": 5,
    "suspicious_environment": 4,
}


def _score_and_sort_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Score composite results by severity signals and sort most anomalous first."""
    for item in results:
        reasons = item.get("reasons", [])
        score = sum(_SEVERITY_WEIGHTS.get(r, 3) for r in reasons)
        item["anomaly_score"] = score
    results.sort(key=lambda x: x.get("anomaly_score", 0), reverse=True)
    return results


def _query_source(
    source_name: str,
    tool_name: str,
) -> tuple[list[WindowRow], str]:
    """Fetch all windows for a source (prefix-matched), log as a sub-call.

    Uses prefix matching so ``volatility.malfind`` retrieves data from
    ``volatility.malfind``, ``volatility.malfind.host1``, etc.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    matched = _find_matching_sources(source_name)
    windows = ctx.db.get_windows_by_source_prefix(source_name)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=f"{tool_name}._query({source_name})",
        params={"source_name": source_name, "matched_sources": matched},
        output_hash=hash_output({"count": len(windows)}),
        duration_ms=elapsed,
    )
    return windows, tc_id


def _keyword_sub_query(
    query: str,
    tool_name: str,
    source_name: str | None = None,
    k: int = 20,
) -> tuple[list[WindowRow], str]:
    """Run a keyword search as a logged sub-call, return (windows, tool_call_id).

    Searches raw_text for *query* as a case-insensitive substring.
    Falls back to searching all sources when the requested source doesn't
    exist in the case database.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    effective_source = source_name if source_name and _source_exists(source_name) else None
    results = ctx.db.search_windows(query, source_name=effective_source, max_results=k)
    windows = [w for w, _sname in results]

    actual_label = effective_source or "all"
    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=f"{tool_name}._search({actual_label})",
        params={"query": query, "source": effective_source, "max_results": k},
        output_hash=hash_output({"count": len(windows)}),
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
    """Return True if *cmdline* contains encoded/obfuscated PowerShell patterns."""
    lower = cmdline.lower()
    return any(pat in lower for pat in _ENCODED_PS_PATTERNS)


def _is_lolbin(proc_name: str) -> bool:
    """Return True if *proc_name* is a known living-off-the-land binary."""
    return proc_name.lower() in _LOLBINS


def _parse_event_time(ts: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string, returning None on failure."""
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
    _EXE_CMD,
    _EXE_POWERSHELL,
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


def _check_hidden_process(
    pid: int,
    pslist_pids: dict[int, list[WindowRow]] | None,
    psscan_pids: dict[int, list[WindowRow]] | None,
    reasons: list[str],
    source_windows: list[dict[str, Any]],
) -> None:
    """Flag PID if present in psscan but missing from pslist (unlinked/hidden)."""
    if psscan_pids is None or pslist_pids is None:
        return
    if pid in psscan_pids and pid not in pslist_pids:
        reasons.append("hidden_process")
        source_windows.extend(slim_window(w) for w in psscan_pids[pid])


def _check_dangerous_privileges(
    pid: int,
    privs_pids: dict[int, list[WindowRow]] | None,
    reasons: list[str],
    source_windows: list[dict[str, Any]],
) -> None:
    """Flag PID holding SeDebugPrivilege or SeTcbPrivilege."""
    if privs_pids is None or pid not in privs_pids:
        return
    priv_text = " ".join(w.raw_text.lower() for w in privs_pids[pid])
    if any(priv in priv_text for priv in _DANGEROUS_PRIVILEGES):
        reasons.append("dangerous_privilege")
        source_windows.extend(slim_window(w) for w in privs_pids[pid])


def _check_suspicious_environment(
    pid: int,
    envars_pids: dict[int, list[WindowRow]] | None,
    reasons: list[str],
    source_windows: list[dict[str, Any]],
) -> None:
    """Flag PID with anomalous environment variables (e.g. overridden COMSPEC)."""
    if envars_pids is None or pid not in envars_pids:
        return
    env_text = " ".join(w.raw_text.lower() for w in envars_pids[pid])
    if "comspec" in env_text or ("temp" in env_text and "\\appdata\\" not in env_text):
        reasons.append("suspicious_environment")
        source_windows.extend(slim_window(w) for w in envars_pids[pid])


def _check_dll_anomalies(
    pid: int,
    dlllist_pids: dict[int, list[WindowRow]] | None,
    reasons: list[str],
    source_windows: list[dict[str, Any]],
) -> None:
    """Flag PID loading DLLs from unusual filesystem locations."""
    if dlllist_pids is None or pid not in dlllist_pids:
        return
    for w in dlllist_pids[pid]:
        path_lower = w.raw_text.lower()
        if any(pat in path_lower for pat in _UNUSUAL_DLL_PATHS):
            reasons.append("unusual_dll_path")
            source_windows.extend(slim_window(w) for w in dlllist_pids[pid])
            return


def _analyze_pid(
    pid: int,
    *,
    pid_names: dict[int, str],
    parent_map: dict[int, int],
    malfind_pids: dict[int, list[WindowRow]],
    cmdline_pids: dict[int, list[WindowRow]],
    netscan_pids: dict[int, list[WindowRow]],
    pstree_pids: dict[int, list[WindowRow]],
    pslist_pids: dict[int, list[WindowRow]] | None = None,
    psscan_pids: dict[int, list[WindowRow]] | None = None,
    privs_pids: dict[int, list[WindowRow]] | None = None,
    envars_pids: dict[int, list[WindowRow]] | None = None,
    dlllist_pids: dict[int, list[WindowRow]] | None = None,
) -> dict[str, Any] | None:
    """Evaluate a single PID for suspicion indicators. Returns None if benign."""
    reasons: list[str] = []
    source_windows: list[dict[str, Any]] = []
    connections: list[str] = []
    name = pid_names.get(pid, "unknown")
    parent_pid = parent_map.get(pid)
    parent_name = pid_names.get(parent_pid, "unknown") if parent_pid else "unknown"

    _check_hidden_process(pid, pslist_pids, psscan_pids, reasons, source_windows)

    if pid in malfind_pids:
        reasons.append("malfind_injection")
        source_windows.extend(slim_window(w) for w in malfind_pids[pid])

    if pid in cmdline_pids:
        cmdline_text = " ".join(w.raw_text for w in cmdline_pids[pid])
        if _has_encoded_powershell(cmdline_text):
            reasons.append("encoded_powershell")
        source_windows.extend(slim_window(w) for w in cmdline_pids[pid])

    if _is_lolbin(name):
        reasons.append("lolbin_execution")

    if pid in netscan_pids:
        for w in netscan_pids[pid]:
            connections.append(w.raw_text.strip())
        if _netscan_has_external(netscan_pids[pid]):
            reasons.append("external_network_connection")
        source_windows.extend(slim_window(w) for w in netscan_pids[pid])

    if parent_name.lower() in _SUSPICIOUS_PARENTS and name.lower() in _SUSPICIOUS_CHILDREN:
        reasons.append("suspicious_parent")

    _check_dangerous_privileges(pid, privs_pids, reasons, source_windows)
    _check_suspicious_environment(pid, envars_pids, reasons, source_windows)
    _check_dll_anomalies(pid, dlllist_pids, reasons, source_windows)

    if pid in pstree_pids:
        source_windows.extend(slim_window(w) for w in pstree_pids[pid])

    if not reasons:
        return None

    cmdline_full = " ".join(w.raw_text.strip() for w in cmdline_pids.get(pid, []))
    cmdline_out = (cmdline_full[:300] + "...") if len(cmdline_full) > 300 else cmdline_full
    capped_conns = [c[:200] for c in connections[:5]]

    return {
        "pid": pid,
        "name": name,
        "parent_pid": parent_pid,
        "parent_name": parent_name,
        "cmdline": cmdline_out,
        "malfind_hit": pid in malfind_pids,
        "network_connections": capped_conns,
        "suspicion_reasons": reasons,
        "source_windows": source_windows,
        "window_count": len(source_windows),
    }


def _netscan_has_external(windows: list[WindowRow]) -> bool:
    """Check if any netscan window shows a connection on a non-standard high port."""
    for w in windows:
        ports = _extract_ports(w.raw_text)
        if any(p not in _LATERAL_PORTS and p > 1024 for p in ports):
            return True
    return False


@mcp.tool()
def find_suspicious_processes() -> dict[str, object]:
    """Identify suspicious processes by cross-referencing memory forensics artifacts.

    Joins data from Volatility malfind (code injection), cmdline (command
    arguments), netscan (network connections), pstree (parent-child
    relationships), psscan (hidden process detection), privs (privilege
    escalation), envars (environment anomalies), and dlllist (DLLs loaded
    from unusual filesystem paths).  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    malfind_wins, tc1 = _query_source("volatility.malfind", "find_suspicious_processes")
    sub_call_ids.append(tc1)

    cmdline_wins, tc2 = _query_source(_SRC_CMDLINE, "find_suspicious_processes")
    sub_call_ids.append(tc2)

    netscan_wins, tc3 = _query_source(_SRC_NETSCAN, "find_suspicious_processes")
    sub_call_ids.append(tc3)

    pstree_wins, tc4 = _query_source(_SRC_PSTREE, "find_suspicious_processes")
    sub_call_ids.append(tc4)

    pslist_wins: list[WindowRow] = []
    psscan_wins: list[WindowRow] = []
    if _source_exists(_SRC_PSSCAN):
        psscan_wins, tc_ps = _query_source(_SRC_PSSCAN, "find_suspicious_processes")
        sub_call_ids.append(tc_ps)
        pslist_wins, tc_pl = _query_source(_SRC_PSLIST, "find_suspicious_processes")
        sub_call_ids.append(tc_pl)

    privs_wins: list[WindowRow] = []
    if _source_exists(_SRC_PRIVS):
        privs_wins, tc_priv = _query_source(_SRC_PRIVS, "find_suspicious_processes")
        sub_call_ids.append(tc_priv)

    envars_wins: list[WindowRow] = []
    if _source_exists(_SRC_ENVARS):
        envars_wins, tc_env = _query_source(_SRC_ENVARS, "find_suspicious_processes")
        sub_call_ids.append(tc_env)

    dlllist_wins: list[WindowRow] = []
    if _source_exists(_SRC_DLLLIST):
        dlllist_wins, tc_dll = _query_source(_SRC_DLLLIST, "find_suspicious_processes")
        sub_call_ids.append(tc_dll)

    malfind_pids = _extract_pids_from_windows(malfind_wins)
    cmdline_pids = _extract_pids_from_windows(cmdline_wins)
    netscan_pids = _extract_pids_from_windows(netscan_wins)
    pstree_pids = _extract_pids_from_windows(pstree_wins)

    pslist_pids = _extract_pids_from_windows(pslist_wins) if pslist_wins else None
    psscan_pids = _extract_pids_from_windows(psscan_wins) if psscan_wins else None
    privs_pids = _extract_pids_from_windows(privs_wins) if privs_wins else None
    envars_pids = _extract_pids_from_windows(envars_wins) if envars_wins else None
    dlllist_pids = _extract_pids_from_windows(dlllist_wins) if dlllist_wins else None

    all_pids = set(malfind_pids) | set(cmdline_pids) | set(netscan_pids) | set(pstree_pids)
    if psscan_pids:
        all_pids |= set(psscan_pids)
    parent_map, pid_names = _build_pid_metadata(pstree_wins, cmdline_wins)

    suspicious: list[dict[str, Any]] = []
    for pid in sorted(all_pids):
        entry = _analyze_pid(
            pid,
            pid_names=pid_names,
            parent_map=parent_map,
            malfind_pids=malfind_pids,
            cmdline_pids=cmdline_pids,
            netscan_pids=netscan_pids,
            pstree_pids=pstree_pids,
            pslist_pids=pslist_pids,
            psscan_pids=psscan_pids,
            privs_pids=privs_pids,
            envars_pids=envars_pids,
            dlllist_pids=dlllist_pids,
        )
        if entry is not None:
            suspicious.append(entry)

    missing = _check_missing_sources(
        [
            ("volatility.malfind", "run_volatility('malfind', '<memory_path>')"),
            ("volatility.cmdline", "run_volatility('cmdline', '<memory_path>')"),
            ("volatility.netscan", "run_volatility('netscan', '<memory_path>')"),
            ("volatility.pstree", "run_volatility('pstree', '<memory_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_suspicious_processes",
        params={},
        output_hash=hash_output(suspicious),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _score_and_sort_results(suspicious)
    _strip_source_windows(suspicious)

    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": suspicious,
        "source": None,
        "result_count": len(suspicious),
    }
    if missing:
        result["missing_sources"] = missing
    return result


def _collect_registry_persistence(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Scan SYSTEM and SOFTWARE registry hives for known autorun key patterns."""
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
                        "source_window": slim_window(w),
                    }
                )


def _collect_service_persistence(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Collect installed services from Volatility svcscan output."""
    svcscan_wins, tc_svc = _query_source("volatility.svcscan", "find_persistence_mechanisms")
    sub_call_ids.append(tc_svc)
    for w in svcscan_wins:
        mechanisms.append(
            {
                "type": "installed_service",
                "source": "volatility.svcscan",
                "evidence_text": w.raw_text.strip()[:500],
                "source_window": slim_window(w),
            }
        )


def _collect_evtx_service_installs(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Search system EVTX for service installation events (Event ID 7045)."""
    evtx_wins, tc_evtx = _keyword_sub_query(
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
                    "source_window": slim_window(w),
                }
            )


def _collect_startup_dir_modifications(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Search Plaso timeline for modifications to startup directories."""
    plaso_wins, tc_plaso = _keyword_sub_query(
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
                    "source_window": slim_window(w),
                }
            )


def _collect_ez_execution_persistence(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Query EZ shimcache/amcache/prefetch for persistence-related executables."""
    ez_sources = [
        (_SRC_EZ_SHIMCACHE, "shimcache_persistence"),
        (_SRC_EZ_AMCACHE, "amcache_persistence"),
        (_SRC_EZ_PREFETCH, "prefetch_persistence"),
    ]
    for src, mech_type in ez_sources:
        if not _source_exists(src):
            continue
        wins, tc_id = _query_source(src, "find_persistence_mechanisms")
        sub_call_ids.append(tc_id)
        for w in wins:
            text_lower = w.raw_text.lower()
            matched_exe = next(
                (exe for exe in _PERSISTENCE_EXECUTABLES if exe in text_lower),
                None,
            )
            if matched_exe is not None:
                mechanisms.append(
                    {
                        "type": mech_type,
                        "executable": matched_exe,
                        "source": src,
                        "evidence_text": w.raw_text.strip()[:500],
                        "source_window": slim_window(w),
                    }
                )


def _collect_scheduled_task_persistence(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Search EVTX for scheduled task creation/modification events."""
    evtx_wins, tc_evtx = _keyword_sub_query(
        "scheduled task created modified event 106 140 4698 schtasks",
        "find_persistence_mechanisms",
        source_name=_SRC_EVTX_SYSTEM,
        k=20,
    )
    sub_call_ids.append(tc_evtx)
    for w in evtx_wins:
        text = w.raw_text
        if any(eid in text for eid in ("106", "140", "4698")) or "schtask" in text.lower():
            mechanisms.append(
                {
                    "type": "scheduled_task",
                    "source": _SRC_EVTX_SYSTEM,
                    "evidence_text": text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )


def _collect_startup_files(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Check TSK file listing for files placed in startup directories."""
    if not _source_exists(_SRC_TSK_FILELIST):
        return
    wins, tc_id = _query_source(_SRC_TSK_FILELIST, "find_persistence_mechanisms")
    sub_call_ids.append(tc_id)
    for w in wins:
        text_lower = w.raw_text.lower()
        if any(pat in text_lower for pat in _STARTUP_PATH_PATTERNS):
            mechanisms.append(
                {
                    "type": "startup_directory_file",
                    "source": _SRC_TSK_FILELIST,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )


@mcp.tool()
def find_persistence_mechanisms() -> dict[str, object]:
    """Detect persistence mechanisms across registry, services, event logs, and timeline.

    Searches Windows registry hives for known autorun keys (Run, RunOnce,
    Userinit, AppInit_DLLs, etc.), cross-references with Volatility service
    scan output, checks event logs for service installation and scheduled
    task events, queries EZ Tools shimcache/amcache/prefetch for execution
    of persistence-related tools, and inspects TSK file listings and the
    Plaso timeline for modifications to startup directories.  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []
    mechanisms: list[dict[str, Any]] = []

    _collect_registry_persistence(mechanisms, sub_call_ids)
    _collect_service_persistence(mechanisms, sub_call_ids)
    _collect_evtx_service_installs(mechanisms, sub_call_ids)
    _collect_startup_dir_modifications(mechanisms, sub_call_ids)
    _collect_ez_execution_persistence(mechanisms, sub_call_ids)
    _collect_scheduled_task_persistence(mechanisms, sub_call_ids)
    _collect_startup_files(mechanisms, sub_call_ids)

    missing = _check_missing_sources(
        [
            ("volatility.svcscan", "run_volatility('svcscan', '<memory_path>')"),
            ("registry.system", "run_registry_parser('<image_path>', hive='SYSTEM')"),
            ("registry.software", "run_registry_parser('<image_path>', hive='SOFTWARE')"),
            ("ez.shimcache", "run_shimcache_parser('<image_path>')"),
            ("ez.amcache", "run_amcache_parser('<image_path>')"),
            ("ez.prefetch", "run_prefetch_parser('<image_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_persistence_mechanisms",
        params={},
        output_hash=hash_output(mechanisms),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _strip_source_windows(mechanisms)
    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": mechanisms,
        "source": None,
        "result_count": len(mechanisms),
    }
    if missing:
        result["missing_sources"] = missing
    return result


_LOGON_EVENT_TYPES = ("network_logon", "failed_logon", "explicit_credentials")


def _classify_logon_windows(
    logon_wins: list[WindowRow],
    failed_wins: list[WindowRow],
    cred_wins: list[WindowRow],
) -> list[dict[str, Any]]:
    """Classify security event log windows into typed indicator dicts."""
    indicators: list[dict[str, Any]] = []
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
                "source_window": slim_window(w),
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
                    "source_window": slim_window(w),
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
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _collect_netscan_lateral(
    netscan_wins: list[WindowRow],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Filter netscan windows for lateral movement ports. Returns (indicators, connections)."""
    indicators: list[dict[str, Any]] = []
    for w in netscan_wins:
        matching_ports = [p for p in _extract_ports(w.raw_text) if p in _LATERAL_PORTS]
        if matching_ports:
            entry = {
                "type": "lateral_movement_port",
                "ports": matching_ports,
                "source": _SRC_NETSCAN,
                "event_time": w.event_time,
                "evidence_text": w.raw_text.strip()[:500],
                "source_window": slim_window(w),
            }
            indicators.append(entry)
    return indicators, list(indicators)


def _collect_rdp_artifacts(
    rdp_wins: list[WindowRow],
    sub_call_ids: list[str],
) -> list[dict[str, Any]]:
    """Gather RDP artifacts from Plaso, EZ EVTX, and TerminalServices events."""
    indicators: list[dict[str, Any]] = []
    for w in rdp_wins:
        text_lower = w.raw_text.lower()
        if "rdp" in text_lower or "remote desktop" in text_lower or "bitmap" in text_lower:
            indicators.append(
                {
                    "type": "rdp_artifact",
                    "source": _SRC_PLASO,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )

    if _source_exists(_SRC_EZ_EVTX_SECURITY):
        rdp_evtx, tc_rdp_ez = _keyword_sub_query(
            "logon type 10 remote interactive RDP RemoteInteractive",
            "find_lateral_movement_indicators",
            source_name=_SRC_EZ_EVTX_SECURITY,
            k=20,
        )
        sub_call_ids.append(tc_rdp_ez)
        for w in rdp_evtx:
            text_lower = w.raw_text.lower()
            if "type 10" in text_lower or "remoteinteractive" in text_lower:
                indicators.append(
                    {
                        "type": "rdp_logon",
                        "source": _SRC_EZ_EVTX_SECURITY,
                        "event_time": w.event_time,
                        "evidence_text": w.raw_text.strip()[:500],
                        "source_window": slim_window(w),
                    }
                )

    ts_wins, tc_ts = _keyword_sub_query(
        "TerminalServices session reconnection RDP disconnect event",
        "find_lateral_movement_indicators",
        source_name=_SRC_EVTX_SYSTEM,
        k=10,
    )
    sub_call_ids.append(tc_ts)
    for w in ts_wins:
        text_lower = w.raw_text.lower()
        if "terminalservices" in text_lower or "remote desktop" in text_lower:
            indicators.append(
                {
                    "type": "rdp_terminal_services",
                    "source": _SRC_EVTX_SYSTEM,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )

    return indicators


def _collect_winrm_indicators(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Detect WinRM connection events (Event IDs 91, 168, 169)."""
    indicators: list[dict[str, Any]] = []
    winrm_wins, tc_winrm = _keyword_sub_query(
        "WinRM WSMan event 91 168 169 remote management connection",
        "find_lateral_movement_indicators",
        source_name=_SRC_EVTX_SYSTEM,
        k=20,
    )
    sub_call_ids.append(tc_winrm)
    for w in winrm_wins:
        text = w.raw_text
        text_lower = text.lower()
        if any(eid in text for eid in ("91", "168", "169")) or "winrm" in text_lower:
            indicators.append(
                {
                    "type": "winrm_connection",
                    "source": _SRC_EVTX_SYSTEM,
                    "event_time": w.event_time,
                    "evidence_text": text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _collect_srum_network_anomalies(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Flag SRUM entries with high byte counts or unusual process network usage."""
    if not _source_exists(_SRC_EZ_SRUM):
        return []
    indicators: list[dict[str, Any]] = []
    srum_wins, tc_srum = _query_source(_SRC_EZ_SRUM, "find_lateral_movement_indicators")
    sub_call_ids.append(tc_srum)
    for w in srum_wins:
        text_lower = w.raw_text.lower()
        has_high_bytes = any(
            kw in text_lower for kw in ("bytessent", "bytes_sent", "bytesrecvd", "bytes_recv")
        )
        has_unusual_proc = any(proc in text_lower for proc in ("powershell", "cmd", "wscript"))
        if has_high_bytes and has_unusual_proc:
            indicators.append(
                {
                    "type": "srum_network_anomaly",
                    "source": _SRC_EZ_SRUM,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _collect_pcap_lateral(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Check pcap.conversations for connections on lateral-movement ports."""
    if not _source_exists(_SRC_PCAP_CONVERSATIONS):
        return []
    indicators: list[dict[str, Any]] = []
    wins, tc_id = _query_source(_SRC_PCAP_CONVERSATIONS, "find_lateral_movement_indicators")
    sub_call_ids.append(tc_id)
    for w in wins:
        matching_ports = [p for p in _extract_ports(w.raw_text) if p in _LATERAL_PORTS]
        if matching_ports:
            indicators.append(
                {
                    "type": "pcap_lateral_movement_port",
                    "ports": matching_ports,
                    "source": _SRC_PCAP_CONVERSATIONS,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _collect_pcap_exfil_dns(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Check pcap.dns for queries to known exfiltration/C2 services."""
    if not _source_exists(_SRC_PCAP_DNS):
        return []
    indicators: list[dict[str, Any]] = []
    wins, tc_id = _query_source(_SRC_PCAP_DNS, "find_data_exfiltration_indicators")
    sub_call_ids.append(tc_id)
    for w in wins:
        text_lower = w.raw_text.lower()
        matched_svc = next(
            (svc for svc in _EXFIL_SERVICES if svc.split("/")[0] in text_lower),
            None,
        )
        if matched_svc is not None:
            indicators.append(
                {
                    "type": "pcap_exfil_dns",
                    "domain": matched_svc,
                    "source": _SRC_PCAP_DNS,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _collect_pcap_exfil_http(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Check pcap.http for requests to known exfiltration/upload services."""
    if not _source_exists(_SRC_PCAP_HTTP):
        return []
    indicators: list[dict[str, Any]] = []
    wins, tc_id = _query_source(_SRC_PCAP_HTTP, "find_data_exfiltration_indicators")
    sub_call_ids.append(tc_id)
    for w in wins:
        text_lower = w.raw_text.lower()
        matched_svc = next(
            (svc for svc in _EXFIL_SERVICES if svc.split("/")[0] in text_lower),
            None,
        )
        if matched_svc is not None:
            indicators.append(
                {
                    "type": "pcap_exfil_http",
                    "service": matched_svc,
                    "source": _SRC_PCAP_HTTP,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _correlate_by_timestamp(
    indicators: list[dict[str, Any]],
    lateral_connections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
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
    correlations: list[dict[str, Any]] = []
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


@mcp.tool()
def find_lateral_movement_indicators() -> dict[str, object]:
    """Detect lateral movement by correlating logon events, network connections, and RDP artifacts.

    Searches Windows Security event log (raw and structured EZ EVTX) for
    network logons (Event ID 4624 Type 3/10), failed logons (4625), and
    explicit credential use (4648).  Cross-references with Volatility
    netscan for connections on SMB (445), RDP (3389), WinRM (5985/5986),
    and RPC (135) ports.  Detects WinRM events (91, 168, 169), checks
    the Plaso timeline and EVTX for RDP artifacts, and queries SRUM for
    network usage anomalies.  Events are correlated by timestamp
    proximity (30-second window).  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    evtx_sec_source = (
        _SRC_EZ_EVTX_SECURITY if _source_exists(_SRC_EZ_EVTX_SECURITY) else _SRC_EVTX_SECURITY
    )

    logon_wins, tc_logon = _keyword_sub_query(
        "successful logon type 3 network logon event 4624 remote",
        "find_lateral_movement_indicators",
        source_name=evtx_sec_source,
        k=20,
    )
    sub_call_ids.append(tc_logon)

    failed_wins, tc_failed = _keyword_sub_query(
        "failed logon event 4625 authentication failure brute force",
        "find_lateral_movement_indicators",
        source_name=evtx_sec_source,
        k=20,
    )
    sub_call_ids.append(tc_failed)

    cred_wins, tc_cred = _keyword_sub_query(
        "explicit credentials logon event 4648 pass the hash runas",
        "find_lateral_movement_indicators",
        source_name=evtx_sec_source,
        k=20,
    )
    sub_call_ids.append(tc_cred)

    indicators = _classify_logon_windows(logon_wins, failed_wins, cred_wins)

    netscan_wins, tc_net = _query_source(_SRC_NETSCAN, "find_lateral_movement_indicators")
    sub_call_ids.append(tc_net)
    net_indicators, lateral_connections = _collect_netscan_lateral(netscan_wins)
    indicators.extend(net_indicators)

    rdp_wins, tc_rdp = _keyword_sub_query(
        "RDP remote desktop bitmap cache default.rdp connection",
        "find_lateral_movement_indicators",
        source_name=_SRC_PLASO,
        k=20,
    )
    sub_call_ids.append(tc_rdp)
    indicators.extend(_collect_rdp_artifacts(rdp_wins, sub_call_ids))

    indicators.extend(_collect_winrm_indicators(sub_call_ids))
    indicators.extend(_collect_srum_network_anomalies(sub_call_ids))
    indicators.extend(_collect_pcap_lateral(sub_call_ids))

    correlations = _correlate_by_timestamp(indicators, lateral_connections)
    indicators.extend(correlations)

    missing = _check_missing_sources(
        [
            ("volatility.netscan", "run_volatility('netscan', '<memory_path>')"),
            ("evtx.security", "run_evtx_parser('<evtx_path>')"),
            ("plaso.timeline", "run_plaso('<evidence_path>')"),
            ("pcap.conversations", "run_pcap_analysis('<pcap_path>', mode='conversations')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_lateral_movement_indicators",
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


def _collect_exfil_urls(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Check bulk.url for references to known upload/exfiltration services."""
    if not _source_exists(_SRC_BULK_URL):
        return []
    indicators: list[dict[str, Any]] = []
    wins, tc_id = _query_source(_SRC_BULK_URL, "find_data_exfiltration_indicators")
    sub_call_ids.append(tc_id)
    for w in wins:
        text_lower = w.raw_text.lower()
        matched_svc = next(
            (svc for svc in _EXFIL_SERVICES if svc in text_lower),
            None,
        )
        if matched_svc is not None:
            indicators.append(
                {
                    "type": "exfil_upload_service",
                    "service": matched_svc,
                    "source": _SRC_BULK_URL,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _collect_exfil_emails(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Flag external email addresses from bulk.email."""
    if not _source_exists(_SRC_BULK_EMAIL):
        return []
    indicators: list[dict[str, Any]] = []
    wins, tc_id = _query_source(_SRC_BULK_EMAIL, "find_data_exfiltration_indicators")
    sub_call_ids.append(tc_id)
    for w in wins:
        if "@" in w.raw_text:
            indicators.append(
                {
                    "type": "exfil_email",
                    "source": _SRC_BULK_EMAIL,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _collect_exfil_domains(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Check bulk.domain for known C2 / exfiltration domain patterns."""
    if not _source_exists(_SRC_BULK_DOMAIN):
        return []
    indicators: list[dict[str, Any]] = []
    wins, tc_id = _query_source(_SRC_BULK_DOMAIN, "find_data_exfiltration_indicators")
    sub_call_ids.append(tc_id)
    for w in wins:
        text_lower = w.raw_text.lower()
        matched_svc = next(
            (svc for svc in _EXFIL_SERVICES if svc.split("/")[0] in text_lower),
            None,
        )
        if matched_svc is not None:
            indicators.append(
                {
                    "type": "exfil_domain",
                    "domain": matched_svc,
                    "source": _SRC_BULK_DOMAIN,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _collect_high_port_connections(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Flag netscan connections on high ports that are not standard services."""
    _STANDARD_PORTS: set[int] = {
        80,
        443,
        53,
        25,
        110,
        143,
        993,
        995,
        587,
        22,
        21,
        23,
        *_LATERAL_PORTS,
    }
    indicators: list[dict[str, Any]] = []
    if not _source_exists(_SRC_NETSCAN):
        return indicators
    wins, tc_id = _query_source(_SRC_NETSCAN, "find_data_exfiltration_indicators")
    sub_call_ids.append(tc_id)
    for w in wins:
        ports = _extract_ports(w.raw_text)
        unusual = [p for p in ports if p > 1024 and p not in _STANDARD_PORTS]
        if unusual:
            indicators.append(
                {
                    "type": "high_port_connection",
                    "ports": unusual,
                    "source": _SRC_NETSCAN,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


def _collect_large_file_access(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Semantic search the Plaso timeline for large file access patterns."""
    indicators: list[dict[str, Any]] = []
    plaso_wins, tc_id = _keyword_sub_query(
        "large file copy archive zip rar 7z transfer staging compress",
        "find_data_exfiltration_indicators",
        source_name=_SRC_PLASO,
        k=20,
    )
    sub_call_ids.append(tc_id)
    for w in plaso_wins:
        text_lower = w.raw_text.lower()
        if any(kw in text_lower for kw in (".zip", ".rar", ".7z", ".tar", "staging", "archive")):
            indicators.append(
                {
                    "type": "large_file_access",
                    "source": _SRC_PLASO,
                    "event_time": w.event_time,
                    "evidence_text": w.raw_text.strip()[:500],
                    "source_window": slim_window(w),
                }
            )
    return indicators


@mcp.tool()
def find_data_exfiltration_indicators() -> dict[str, object]:
    """Detect potential data exfiltration by correlating network, URL, and file access artifacts.

    Checks bulk_extractor URLs for known upload/exfil services (Mega,
    Pastebin, Dropbox, etc.), flags external email addresses, scans
    domains for C2 patterns, detects high-port network connections from
    memory, and searches the Plaso timeline for large file staging or
    archive creation.  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []
    indicators: list[dict[str, Any]] = []

    indicators.extend(_collect_exfil_urls(sub_call_ids))
    indicators.extend(_collect_exfil_emails(sub_call_ids))
    indicators.extend(_collect_exfil_domains(sub_call_ids))
    indicators.extend(_collect_high_port_connections(sub_call_ids))
    indicators.extend(_collect_large_file_access(sub_call_ids))
    indicators.extend(_collect_pcap_exfil_dns(sub_call_ids))
    indicators.extend(_collect_pcap_exfil_http(sub_call_ids))

    missing = _check_missing_sources(
        [
            ("bulk.url", "run_bulk_extractor('<image_path>', features=['url'])"),
            ("bulk.email", "run_bulk_extractor('<image_path>', features=['email'])"),
            ("volatility.netscan", "run_volatility('netscan', '<memory_path>')"),
            ("plaso.timeline", "run_plaso('<evidence_path>')"),
            ("pcap.dns", "run_pcap_analysis('<pcap_path>', mode='dns')"),
            ("pcap.http", "run_pcap_analysis('<pcap_path>', mode='http')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_data_exfiltration_indicators",
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


def _extract_exe_name(text: str) -> str | None:
    """Best-effort extraction of an executable name from artifact text."""
    m = _PROC_NAME_RE.search(text)
    return m.group(1).strip().lower() if m else None


def _accumulate_exe_evidence(
    exe_evidence: dict[str, dict[str, Any]],
    windows: list[WindowRow],
    label: str,
    include_times: bool = True,
) -> None:
    """Merge windows into the exe_evidence map keyed by executable name."""
    for w in windows:
        exe_name = _extract_exe_name(w.raw_text)
        if exe_name is None:
            continue
        if exe_name not in exe_evidence:
            exe_evidence[exe_name] = {
                "executable": exe_name,
                "sources": [],
                "source_windows": [],
                "event_times": [],
            }
        entry = exe_evidence[exe_name]
        if label not in entry["sources"]:
            entry["sources"].append(label)
        entry["source_windows"].append(slim_window(w))
        entry["_total_window_count"] = entry.get("_total_window_count", 0) + 1
        if include_times and w.event_time:
            entry["event_times"].append(w.event_time)


@mcp.tool()
def find_execution_evidence() -> dict[str, object]:
    """Build a unified execution evidence view from multiple artifact sources.

    Joins EZ Tools prefetch (run times), amcache (install/execution with
    hashes), shimcache (file existence evidence), jump lists (user file
    access), LNK files (shortcut execution), and the Volatility process
    tree (processes running at capture time).  Each entry lists which
    sources corroborate the execution.  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    exe_evidence: dict[str, dict[str, Any]] = {}

    source_configs = [
        (_SRC_EZ_PREFETCH, "prefetch"),
        (_SRC_EZ_AMCACHE, "amcache"),
        (_SRC_EZ_SHIMCACHE, "shimcache"),
        (_SRC_EZ_JUMPLISTS, "jumplists"),
        (_SRC_EZ_LNKFILES, "lnkfiles"),
    ]

    for src, label in source_configs:
        if not _source_exists(src):
            continue
        wins, tc_id = _query_source(src, "find_execution_evidence")
        sub_call_ids.append(tc_id)
        _accumulate_exe_evidence(exe_evidence, wins, label)

    if _source_exists(_SRC_PSTREE):
        pstree_wins, tc_pt = _query_source(_SRC_PSTREE, "find_execution_evidence")
        sub_call_ids.append(tc_pt)
        _accumulate_exe_evidence(exe_evidence, pstree_wins, "memory_pstree", include_times=False)

    _MAX_EXE_WINDOWS = 10
    for entry in exe_evidence.values():
        total = entry.pop("_total_window_count", len(entry["source_windows"]))
        entry["window_count"] = total
        if len(entry["source_windows"]) > _MAX_EXE_WINDOWS:
            entry["source_windows"] = entry["source_windows"][:_MAX_EXE_WINDOWS]
            entry["truncated"] = True

    results = sorted(
        exe_evidence.values(),
        key=lambda e: len(e["sources"]),
        reverse=True,
    )

    missing = _check_missing_sources(
        [
            ("ez.prefetch", "run_prefetch_parser('<image_path>')"),
            ("ez.amcache", "run_amcache_parser('<image_path>')"),
            ("ez.shimcache", "run_shimcache_parser('<image_path>')"),
            ("volatility.pstree", "run_volatility('pstree', '<memory_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="find_execution_evidence",
        params={},
        output_hash=hash_output(results),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _strip_source_windows(results)
    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": results,
        "source": None,
        "result_count": len(results),
    }
    if missing:
        result["missing_sources"] = missing
    return result


def _extract_module_names(windows: list[WindowRow]) -> dict[str, list[WindowRow]]:
    """Group windows by the kernel module name found in their text."""
    mod_map: dict[str, list[WindowRow]] = defaultdict(list)
    for w in windows:
        m = _MODULE_NAME_RE.search(w.raw_text)
        if m:
            name = m.group(1).strip().lower()
            mod_map[name].append(w)
    return dict(mod_map)


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
                    "evidence_text": w.raw_text.strip()[:500],
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
                    "evidence_text": text.strip()[:500],
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

    psscan_pids = _extract_pids_from_windows(psscan_wins)
    pslist_pids = _extract_pids_from_windows(pslist_wins)
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

    linked = _extract_module_names(modules_wins)
    scanned = _extract_module_names(modscan_wins)
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
                    "evidence_text": w.raw_text.strip()[:500],
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
                        "evidence_text": w.raw_text.strip()[:500],
                        "source_window": slim_window(w),
                    }
                )


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
                    dll_anomalies.append(w.raw_text.strip()[:200])

        nodes[pid] = {
            "pid": pid,
            "name": name,
            "parent_pid": parent_map.get(pid),
            "parent_name": pid_names.get(parent_map.get(pid, -1), "unknown"),
            "cmdline": cmdline[:500],
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

    cmdline_pids = _extract_pids_from_windows(cmdline_wins)
    netscan_pids = _extract_pids_from_windows(netscan_wins)
    malfind_pids = _extract_pids_from_windows(malfind_wins)
    dlllist_pids = _extract_pids_from_windows(dlllist_wins) if dlllist_wins else None

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
                prefetch_data[exe] = {"event_time": w.event_time, "text": w.raw_text[:200]}

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

    deleted_wins, tc_del = _query_source(_SRC_TSK_FILELIST, "assess_recovery")
    sub_call_ids.append(tc_del)
    deleted_files = [w for w in deleted_wins if "* " in w.raw_text]
    total_deleted = len(deleted_files)

    anti_forensics: list[dict[str, Any]] = []

    for src in (_SRC_EZ_PREFETCH, _SRC_EZ_AMCACHE, _SRC_EZ_SHIMCACHE):
        if not _source_exists(src):
            continue
        wins, tc_id = _query_source(src, "assess_recovery")
        sub_call_ids.append(tc_id)
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

    log_clearing: list[dict[str, Any]] = []
    for evtx_src in (_SRC_EVTX_SECURITY, _SRC_EVTX_SYSTEM):
        if not _source_exists(evtx_src):
            continue
        evtx_wins, tc_evtx = _keyword_sub_query(
            "log cleared event 104 1102 audit log cleared wiped",
            "assess_recovery",
            source_name=evtx_src,
            k=10,
        )
        sub_call_ids.append(tc_evtx)
        for w in evtx_wins:
            text = w.raw_text
            if "104" in text or "1102" in text or "cleared" in text.lower():
                log_clearing.append(
                    {
                        "type": "log_clearing",
                        "source": evtx_src,
                        "event_time": w.event_time,
                        "evidence_text": text.strip()[:300],
                    }
                )
    anti_forensics.extend(log_clearing)

    usnjrnl_deletions: list[dict[str, Any]] = []
    if _source_exists(_SRC_EZ_USNJRNL):
        usn_wins, tc_usn = _keyword_sub_query(
            "FILE_DELETE CLOSE rename delete",
            "assess_recovery",
            source_name=_SRC_EZ_USNJRNL,
            k=30,
        )
        sub_call_ids.append(tc_usn)
        for w in usn_wins:
            text_lower = w.raw_text.lower()
            if "delete" in text_lower or "close" in text_lower:
                usnjrnl_deletions.append(
                    {
                        "event_time": w.event_time,
                        "evidence_text": w.raw_text.strip()[:200],
                    }
                )

    evidence_gaps: list[str] = []
    if anti_forensics:
        evidence_gaps.append(
            "Secure delete tools detected -- some deleted files may be unrecoverable"
        )
    if log_clearing:
        evidence_gaps.append("Event log clearing detected -- some log evidence has been destroyed")

    assessment: dict[str, object] = {
        "total_deleted_files": total_deleted,
        "anti_forensics_detected": anti_forensics,
        "anti_forensics_count": len(anti_forensics),
        "usnjrnl_deletions_sampled": usnjrnl_deletions[:20],
        "evidence_gaps": evidence_gaps,
    }

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
    """Cross-reference PCAP network events with host-based artifacts.

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
    correlations: list[dict[str, Any]] = []

    pcap_ips: set[str] = set()
    pcap_ports: set[int] = set()

    ip_re = _IP_RE
    port_re = _PORT_RE

    for pcap_src in (_SRC_PCAP_CONVERSATIONS, _SRC_PCAP_DNS, _SRC_PCAP_HTTP):
        if not _source_exists(pcap_src):
            continue
        wins, tc_id = _query_source(pcap_src, "correlate_pcap_with_host")
        sub_call_ids.append(tc_id)
        for w in wins:
            for m in ip_re.finditer(w.raw_text):
                pcap_ips.add(m.group())
            for m in port_re.finditer(w.raw_text):
                pcap_ports.add(int(m.group(1)))

    if _source_exists(_SRC_NETSCAN):
        netscan_wins, tc_net = _query_source(_SRC_NETSCAN, "correlate_pcap_with_host")
        sub_call_ids.append(tc_net)
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
                evtx_ips = {m.group() for m in ip_re.finditer(w.raw_text)}
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


_EXE_NAME_RE = re.compile(r"(\S+\.exe)", re.IGNORECASE)
_RUN_COUNT_RE = re.compile(r"run\s*count[:\s]+(\d+)", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b([a-fA-F0-9]{40})\b")

_UNUSUAL_EXE_PATHS: tuple[str, ...] = (
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\recycle",
    "\\programdata\\",
)


@mcp.tool()
def analyze_execution_timeline() -> dict[str, object]:
    """Build a unified execution timeline from prefetch, amcache, and shimcache.

    Merges per-executable evidence from EZ Tools to show first/last
    seen times, run counts, SHA1 hashes, and flags anomalies like
    single-execution tools, unusual paths, and executables with
    amcache entries but no prefetch (possible cleanup).  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []

    exe_data: dict[str, dict[str, Any]] = {}

    def _merge_exe(name: str, source: str, event_time: str | None, text: str) -> None:
        """Upsert an executable entry, updating first/last seen times."""
        key = name.lower()
        if key not in exe_data:
            exe_data[key] = {
                "executable": name,
                "sources": [],
                "first_seen": None,
                "last_seen": None,
                "run_count": None,
                "sha1": None,
                "anomaly_flags": [],
                "evidence_snippets": [],
            }
        entry = exe_data[key]
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if event_time:
            if entry["first_seen"] is None or event_time < entry["first_seen"]:
                entry["first_seen"] = event_time
            if entry["last_seen"] is None or event_time > entry["last_seen"]:
                entry["last_seen"] = event_time
        entry["evidence_snippets"].append(text[:150])

    if _source_exists(_SRC_EZ_PREFETCH):
        pf_wins, tc_pf = _query_source(_SRC_EZ_PREFETCH, "analyze_execution_timeline")
        sub_call_ids.append(tc_pf)
        for w in pf_wins:
            m = _EXE_NAME_RE.search(w.raw_text)
            if not m:
                continue
            exe_name = m.group(1)
            _merge_exe(exe_name, "prefetch", w.event_time, w.raw_text)
            rc = _RUN_COUNT_RE.search(w.raw_text)
            if rc:
                key = exe_name.lower()
                if key in exe_data:
                    exe_data[key]["run_count"] = int(rc.group(1))

    if _source_exists(_SRC_EZ_AMCACHE):
        am_wins, tc_am = _query_source(_SRC_EZ_AMCACHE, "analyze_execution_timeline")
        sub_call_ids.append(tc_am)
        for w in am_wins:
            m = _EXE_NAME_RE.search(w.raw_text)
            if not m:
                continue
            exe_name = m.group(1)
            _merge_exe(exe_name, "amcache", w.event_time, w.raw_text)
            sha = _SHA1_RE.search(w.raw_text)
            if sha:
                key = exe_name.lower()
                if key in exe_data:
                    exe_data[key]["sha1"] = sha.group(1)

    if _source_exists(_SRC_EZ_SHIMCACHE):
        sc_wins, tc_sc = _query_source(_SRC_EZ_SHIMCACHE, "analyze_execution_timeline")
        sub_call_ids.append(tc_sc)
        for w in sc_wins:
            m = _EXE_NAME_RE.search(w.raw_text)
            if not m:
                continue
            _merge_exe(m.group(1), "shimcache", w.event_time, w.raw_text)

    for key, entry in exe_data.items():
        if entry["run_count"] == 1:
            entry["anomaly_flags"].append("single_execution")
        if any(pat in key for pat in _UNUSUAL_EXE_PATHS):
            entry["anomaly_flags"].append("unusual_path")
        if "amcache" in entry["sources"] and "prefetch" not in entry["sources"]:
            entry["anomaly_flags"].append("amcache_only_no_prefetch")
        entry["evidence_snippets"] = entry["evidence_snippets"][:3]

    results = sorted(
        exe_data.values(),
        key=lambda e: (len(e["anomaly_flags"]), len(e["sources"])),
        reverse=True,
    )

    missing = _check_missing_sources(
        [
            ("ez.prefetch", "run_prefetch_parser('<image_path>')"),
            ("ez.amcache", "run_amcache_parser('<image_path>')"),
            ("ez.shimcache", "run_shimcache_parser('<image_path>')"),
        ]
    )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=composite_id,
        tool_name="analyze_execution_timeline",
        params={},
        output_hash=hash_output(results),
        duration_ms=elapsed,
        sub_calls=sub_call_ids,
    )
    _strip_source_windows(results)
    result: dict[str, object] = {
        "tool_call_id": composite_id,
        "status": "success",
        "results": results,
        "source": None,
        "result_count": len(results),
    }
    if missing:
        result["missing_sources"] = missing
    return result
