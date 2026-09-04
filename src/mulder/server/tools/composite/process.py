"""Process anomaly detection composite MCP tool."""

from __future__ import annotations

import time
from typing import Any

from mulder.models import WindowRow
from mulder.patterns import SUSPICIOUS_PATHS
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    _HINT_CHAR_LIMIT,
    extract_pids_from_windows,
    make_tool_call_id,
    project_window_collection,
    project_window_evidence,
    slim_window,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.composite.core import (
    _EXE_CMD,
    _EXE_POWERSHELL,
    _LATERAL_PORTS,
    _SRC_CMDLINE,
    _SRC_DLLLIST,
    _SRC_ENVARS,
    _SRC_NETSCAN,
    _SRC_PRIVS,
    _SRC_PSLIST,
    _SRC_PSSCAN,
    _SRC_PSTREE,
    _build_pid_metadata,
    _check_missing_sources,
    _extract_ports,
    _query_source,
    _score_and_sort_results,
    _source_exists,
    finalize_composite_result,
)

__all__ = ["find_suspicious_processes"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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

_DANGEROUS_PRIVILEGES: set[str] = {"sedebugprivilege", "setcbprivilege"}

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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_encoded_powershell(cmdline: str) -> bool:
    """Return True if *cmdline* contains encoded/obfuscated PowerShell patterns."""
    lower = cmdline.lower()
    return any(pat in lower for pat in _ENCODED_PS_PATTERNS)


def _is_lolbin(proc_name: str) -> bool:
    """Return True if *proc_name* is a known living-off-the-land binary."""
    return proc_name.lower() in _LOLBINS


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
        if any(pat in path_lower for pat in SUSPICIOUS_PATHS):
            reasons.append("unusual_dll_path")
            source_windows.extend(slim_window(w) for w in dlllist_pids[pid])
            return


def _netscan_has_external(windows: list[WindowRow]) -> bool:
    """Check if any netscan window shows a connection on a non-standard high port."""
    for w in windows:
        ports = _extract_ports(w.raw_text)
        if any(p not in _LATERAL_PORTS and p > 1024 for p in ports):
            return True
    return False


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

    cmdline_windows = cmdline_pids.get(pid, [])
    capped_conns = [
        project_window_evidence(
            window,
            _SRC_NETSCAN,
            max_characters=_HINT_CHAR_LIMIT,
            content_key="connection",
        )
        for window in netscan_pids.get(pid, [])[:5]
    ]

    return {
        "pid": pid,
        "name": name,
        "parent_pid": parent_pid,
        "parent_name": parent_name,
        **project_window_collection(
            cmdline_windows,
            _SRC_CMDLINE,
            max_characters=300,
            content_key="cmdline",
            separator=" ",
        ),
        "malfind_hit": pid in malfind_pids,
        "network_connections": capped_conns,
        "suspicion_reasons": reasons,
        "source_windows": source_windows,
        "window_count": len(source_windows),
    }


def _collect_process_sources(
    sub_call_ids: list[str],
) -> dict[str, list[WindowRow]]:
    """Query all process-related Volatility sources for suspicious process analysis.

    Queries malfind, cmdline, netscan, pstree and conditionally psscan,
    pslist, privs, envars, and dlllist.  Appends tool-call IDs to
    *sub_call_ids* for audit tracking.

    Returns:
        Dict keyed by short source name mapping to the queried window rows.
    """
    sources: dict[str, list[WindowRow]] = {}

    sources["malfind"], tc = _query_source("volatility.malfind", "find_suspicious_processes")
    sub_call_ids.append(tc)

    sources["cmdline"], tc = _query_source(_SRC_CMDLINE, "find_suspicious_processes")
    sub_call_ids.append(tc)

    sources["netscan"], tc = _query_source(_SRC_NETSCAN, "find_suspicious_processes")
    sub_call_ids.append(tc)

    sources["pstree"], tc = _query_source(_SRC_PSTREE, "find_suspicious_processes")
    sub_call_ids.append(tc)

    sources["pslist"] = []
    sources["psscan"] = []
    if _source_exists(_SRC_PSSCAN):
        sources["psscan"], tc = _query_source(_SRC_PSSCAN, "find_suspicious_processes")
        sub_call_ids.append(tc)
        sources["pslist"], tc = _query_source(_SRC_PSLIST, "find_suspicious_processes")
        sub_call_ids.append(tc)

    sources["privs"] = []
    if _source_exists(_SRC_PRIVS):
        sources["privs"], tc = _query_source(_SRC_PRIVS, "find_suspicious_processes")
        sub_call_ids.append(tc)

    sources["envars"] = []
    if _source_exists(_SRC_ENVARS):
        sources["envars"], tc = _query_source(_SRC_ENVARS, "find_suspicious_processes")
        sub_call_ids.append(tc)

    sources["dlllist"] = []
    if _source_exists(_SRC_DLLLIST):
        sources["dlllist"], tc = _query_source(_SRC_DLLLIST, "find_suspicious_processes")
        sub_call_ids.append(tc)

    return sources


def _build_candidate_pids(sources: dict[str, list[WindowRow]]) -> set[int]:
    """Assemble the set of all candidate PIDs from queried process sources.

    Unions PIDs found across malfind, cmdline, netscan, pstree, and
    (when available) psscan.
    """
    all_pids: set[int] = set()
    for key in ("malfind", "cmdline", "netscan", "pstree"):
        all_pids |= set(extract_pids_from_windows(sources[key]))

    if sources["psscan"]:
        all_pids |= set(extract_pids_from_windows(sources["psscan"]))

    return all_pids


def _evaluate_and_score_pids(
    candidate_pids: set[int],
    sources: dict[str, list[WindowRow]],
) -> list[dict[str, Any]]:
    """Evaluate each candidate PID for suspicion indicators.

    Extracts per-source PID indexes, builds process metadata, then
    calls ``_analyze_pid`` for every candidate.  Only entries with at
    least one suspicion reason are included in the returned list.
    """
    parent_map, pid_names = _build_pid_metadata(sources["pstree"], sources["cmdline"])

    malfind_pids = extract_pids_from_windows(sources["malfind"])
    cmdline_pids = extract_pids_from_windows(sources["cmdline"])
    netscan_pids = extract_pids_from_windows(sources["netscan"])
    pstree_pids = extract_pids_from_windows(sources["pstree"])
    pslist_pids = extract_pids_from_windows(sources["pslist"]) if sources["pslist"] else None
    psscan_pids = extract_pids_from_windows(sources["psscan"]) if sources["psscan"] else None
    privs_pids = extract_pids_from_windows(sources["privs"]) if sources["privs"] else None
    envars_pids = extract_pids_from_windows(sources["envars"]) if sources["envars"] else None
    dlllist_pids = extract_pids_from_windows(sources["dlllist"]) if sources["dlllist"] else None

    suspicious: list[dict[str, Any]] = []
    for pid in sorted(candidate_pids):
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

    return suspicious


# ---------------------------------------------------------------------------
# MCP tool handler
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR)
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

    sources = _collect_process_sources(sub_call_ids)
    candidate_pids = _build_candidate_pids(sources)
    suspicious = _evaluate_and_score_pids(candidate_pids, sources)

    missing = _check_missing_sources(
        [
            ("volatility.malfind", "run_volatility('malfind', '<memory_path>')"),
            ("volatility.cmdline", "run_volatility('cmdline', '<memory_path>')"),
            ("volatility.netscan", "run_volatility('netscan', '<memory_path>')"),
            ("volatility.pstree", "run_volatility('pstree', '<memory_path>')"),
        ]
    )

    _score_and_sort_results(suspicious)

    return finalize_composite_result(
        ctx=ctx,
        composite_id=composite_id,
        tool_name="find_suspicious_processes",
        results=suspicious,
        coverage_sources=[
            "volatility.malfind",
            _SRC_CMDLINE,
            _SRC_NETSCAN,
            _SRC_PSTREE,
            _SRC_PSSCAN,
            _SRC_PSLIST,
            _SRC_PRIVS,
            _SRC_ENVARS,
            _SRC_DLLLIST,
        ],
        missing=missing,
        sub_call_ids=sub_call_ids,
        t0=t0,
    )
