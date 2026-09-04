"""Data exfiltration detection composite MCP tool."""

from __future__ import annotations

import re
import time
from typing import Any

from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    make_tool_call_id,
    project_window_evidence,
    slim_window,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.composite.core import (
    _LATERAL_PORTS,
    _SRC_BULK_DOMAIN,
    _SRC_BULK_EMAIL,
    _SRC_BULK_URL,
    _SRC_EZ_MFT,
    _SRC_NETSCAN,
    _SRC_PCAP_DNS,
    _SRC_PCAP_HTTP,
    _SRC_PLASO,
    _SRC_TSK_FILELIST,
    _check_missing_sources,
    _extract_ports,
    _keyword_sub_query,
    _query_source,
    _source_exists,
    finalize_composite_result,
)

__all__ = ["find_data_exfiltration_indicators", "find_file_staging"]

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
                    **project_window_evidence(
                        w, _SRC_BULK_URL, content_key="evidence_text"
                    ),
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
                    **project_window_evidence(
                        w, _SRC_BULK_EMAIL, content_key="evidence_text"
                    ),
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
                    **project_window_evidence(
                        w, _SRC_BULK_DOMAIN, content_key="evidence_text"
                    ),
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
                    **project_window_evidence(w, _SRC_NETSCAN, content_key="evidence_text"),
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
                    **project_window_evidence(w, _SRC_PLASO, content_key="evidence_text"),
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
                    **project_window_evidence(w, _SRC_PCAP_DNS, content_key="evidence_text"),
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
                    **project_window_evidence(w, _SRC_PCAP_HTTP, content_key="evidence_text"),
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


# ---------------------------------------------------------------------------
# File staging detection
# ---------------------------------------------------------------------------

_ARCHIVE_EXTENSIONS: tuple[str, ...] = (
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".tar.gz",
    ".tgz",
    ".cab",
    ".bz2",
)

_SUSPICIOUS_PATH_FRAGMENTS: tuple[str, ...] = (
    "\\temp\\",
    "\\tmp\\",
    "/temp/",
    "/tmp/",
    "\\downloads\\",
    "/downloads/",
    "\\recycle",
    "$recycle.bin",
    "\\appdata\\local\\temp",
    "\\windows\\temp",
)

_LARGE_FILE_THRESHOLD_BYTES = 50 * 1024 * 1024  # 50 MB


def _collect_staging_archives(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Find recently created archive files in filesystem listings."""
    indicators: list[dict[str, Any]] = []

    for source in (_SRC_TSK_FILELIST, _SRC_EZ_MFT):
        if not _source_exists(source):
            continue
        wins, tc_id = _keyword_sub_query(
            ".zip .rar .7z .tar .gz .cab .tgz",
            "find_file_staging",
            source_name=source,
            k=50,
        )
        sub_call_ids.append(tc_id)
        for w in wins:
            text_lower = w.raw_text.lower()
            if any(ext in text_lower for ext in _ARCHIVE_EXTENSIONS):
                indicators.append(
                    {
                        "type": "archive_file",
                        "source": source,
                        "event_time": w.event_time,
                        **project_window_evidence(w, source, content_key="evidence_text"),
                        "source_window": slim_window(w),
                    }
                )
    return indicators


def _collect_suspicious_location_archives(
    sub_call_ids: list[str],
) -> list[dict[str, Any]]:
    """Find archives in suspicious staging directories."""
    indicators: list[dict[str, Any]] = []

    for source in (_SRC_TSK_FILELIST, _SRC_EZ_MFT):
        if not _source_exists(source):
            continue
        wins, tc_id = _query_source(source, "find_file_staging")
        sub_call_ids.append(tc_id)
        for w in wins:
            text_lower = w.raw_text.lower()
            has_archive = any(ext in text_lower for ext in _ARCHIVE_EXTENSIONS)
            in_suspicious_path = any(frag in text_lower for frag in _SUSPICIOUS_PATH_FRAGMENTS)
            if has_archive and in_suspicious_path:
                indicators.append(
                    {
                        "type": "archive_in_suspicious_location",
                        "source": source,
                        "event_time": w.event_time,
                        **project_window_evidence(w, source, content_key="evidence_text"),
                        "source_window": slim_window(w),
                    }
                )
    return indicators


def _collect_large_file_staging(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Identify large files in the MFT that may indicate bulk data staging.

    Searches for size indicators in MFT entries; MFTECmd CSV output
    includes a FileSize column.
    """
    indicators: list[dict[str, Any]] = []
    if not _source_exists(_SRC_EZ_MFT):
        return indicators

    wins, tc_id = _keyword_sub_query(
        "archive staging compress backup dump export",
        "find_file_staging",
        source_name=_SRC_EZ_MFT,
        k=30,
    )
    sub_call_ids.append(tc_id)
    size_re = re.compile(r"(?:FileSize|size)[:\t,]\s*(\d+)", re.IGNORECASE)
    for w in wins:
        m = size_re.search(w.raw_text)
        if m:
            size = int(m.group(1))
            if size >= _LARGE_FILE_THRESHOLD_BYTES:
                indicators.append(
                    {
                        "type": "large_file_staging",
                        "file_size_bytes": size,
                        "source": _SRC_EZ_MFT,
                        "event_time": w.event_time,
                        **project_window_evidence(w, _SRC_EZ_MFT, content_key="evidence_text"),
                        "source_window": slim_window(w),
                    }
                )
    return indicators


def _collect_created_then_deleted(sub_call_ids: list[str]) -> list[dict[str, Any]]:
    """Find archives that were created and quickly deleted (exfil then cleanup)."""
    indicators: list[dict[str, Any]] = []
    if not _source_exists(_SRC_EZ_MFT):
        return indicators

    wins, tc_id = _keyword_sub_query(
        "deleted .zip .rar .7z .tar InUse:False",
        "find_file_staging",
        source_name=_SRC_EZ_MFT,
        k=30,
    )
    sub_call_ids.append(tc_id)
    for w in wins:
        text_lower = w.raw_text.lower()
        has_archive = any(ext in text_lower for ext in _ARCHIVE_EXTENSIONS)
        has_deletion = any(kw in text_lower for kw in ("inuse:false", "deleted", "isinuse,false"))
        if has_archive and has_deletion:
            indicators.append(
                {
                    "type": "archive_created_then_deleted",
                    "source": _SRC_EZ_MFT,
                    "event_time": w.event_time,
                    **project_window_evidence(w, _SRC_EZ_MFT, content_key="evidence_text"),
                    "source_window": slim_window(w),
                }
            )
    return indicators


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR | Role.EXTRACT_ANALYST | Role.NARRATIVE_EXECUTOR)
def find_file_staging() -> dict[str, object]:
    """Detect signs of data staging and exfiltration preparation in filesystem data.

    Searches indexed filesystem sources (tsk.filelist, ez.mft) for:
    - Recently created archive files (.zip, .rar, .7z, .tar, .gz)
    - Archives in suspicious locations (temp dirs, Downloads, Recycle Bin)
    - Large files that may indicate bulk data collection
    - Archives that were created then deleted (exfiltrated then cleaned up)

    Complements find_data_exfiltration_indicators by focusing on host
    filesystem artifacts rather than network traffic.  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []
    indicators: list[dict[str, Any]] = []

    indicators.extend(_collect_staging_archives(sub_call_ids))
    indicators.extend(_collect_suspicious_location_archives(sub_call_ids))
    indicators.extend(_collect_large_file_staging(sub_call_ids))
    indicators.extend(_collect_created_then_deleted(sub_call_ids))

    missing = _check_missing_sources(
        [
            ("tsk.filelist", "run_fls('<image_path>')"),
            ("ez.mft", "run_ez_tool('MFTECmd', '<image_path>')"),
        ]
    )

    return finalize_composite_result(
        ctx=ctx,
        composite_id=composite_id,
        tool_name="find_file_staging",
        results=indicators,
        coverage_sources=[_SRC_TSK_FILELIST, _SRC_EZ_MFT],
        missing=missing,
        sub_call_ids=sub_call_ids,
        t0=t0,
    )
