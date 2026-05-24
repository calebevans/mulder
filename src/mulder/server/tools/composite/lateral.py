"""Lateral movement detection composite MCP tool."""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

from mulder.models import WindowRow
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    _PREVIEW_CHAR_LIMIT,
    hash_output,
    make_tool_call_id,
    slim_window,
)
from mulder.server.tools.composite.core import (
    _LATERAL_PORTS,
    _SRC_EVTX_SECURITY,
    _SRC_EVTX_SYSTEM,
    _SRC_EZ_EVTX_SECURITY,
    _SRC_EZ_SRUM,
    _SRC_NETSCAN,
    _SRC_PCAP_CONVERSATIONS,
    _SRC_PLASO,
    _check_missing_sources,
    _extract_ports,
    _keyword_sub_query,
    _parse_event_time,
    _query_source,
    _source_exists,
    _strip_source_windows,
)

__all__ = ["find_lateral_movement_indicators"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CORRELATION_WINDOW_SECONDS = 30

_LOGON_EVENT_TYPES = ("network_logon", "failed_logon", "explicit_credentials")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
                "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                        "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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


# ---------------------------------------------------------------------------
# MCP tool handler
# ---------------------------------------------------------------------------


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
