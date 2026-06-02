"""Data exfiltration detection composite MCP tool."""

from __future__ import annotations

import time
from typing import Any

from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    _PREVIEW_CHAR_LIMIT,
    make_tool_call_id,
    slim_window,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.composite.core import (
    _LATERAL_PORTS,
    _SRC_BULK_DOMAIN,
    _SRC_BULK_EMAIL,
    _SRC_BULK_URL,
    _SRC_NETSCAN,
    _SRC_PCAP_DNS,
    _SRC_PCAP_HTTP,
    _SRC_PLASO,
    _check_missing_sources,
    _extract_ports,
    _keyword_sub_query,
    _query_source,
    _source_exists,
    finalize_composite_result,
)

__all__ = ["find_data_exfiltration_indicators"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
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
                    "evidence_text": w.raw_text.strip()[:_PREVIEW_CHAR_LIMIT],
                    "source_window": slim_window(w),
                }
            )
    return indicators


# ---------------------------------------------------------------------------
# MCP tool handler
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR)
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

    return finalize_composite_result(
        ctx=ctx,
        composite_id=composite_id,
        tool_name="find_data_exfiltration_indicators",
        results=indicators,
        coverage_sources=[
            _SRC_BULK_URL,
            _SRC_BULK_EMAIL,
            _SRC_BULK_DOMAIN,
            _SRC_NETSCAN,
            _SRC_PLASO,
            _SRC_PCAP_DNS,
            _SRC_PCAP_HTTP,
        ],
        missing=missing,
        sub_call_ids=sub_call_ids,
        t0=t0,
    )
