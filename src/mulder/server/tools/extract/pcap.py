"""Network capture (PCAP) analysis MCP tools."""

from __future__ import annotations

import json
import logging
import math
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mulder.execution import safe_subprocess as subprocess
from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    require_binary,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "run_pcap_analysis",
    "run_suricata",
    "run_zeek_analysis",
]

logger = logging.getLogger(__name__)

_PCAP_TIMEOUT = 600
_STDERR_PREVIEW_LIMIT = 500


def _timeout_partial_output(exc: subprocess.TimeoutExpired, label: str) -> str:
    """Extract any partial output captured before a subprocess timeout.

    Args:
        exc: The TimeoutExpired exception (may carry partial stdout).
        label: Human-readable label for the timed-out operation.

    Returns:
        Partial output with a truncation notice, or a plain timeout message.
    """
    raw = exc.stdout
    partial = ""
    if isinstance(raw, str):
        partial = raw.strip()
    elif isinstance(raw, bytes):
        partial = raw.decode(errors="replace").strip()
    if partial:
        return f"{partial}\n\n[TRUNCATED: {label} timed out]"
    return f"{label} timed out"


def _tshark_output_or_error(proc: subprocess.CompletedProcess[str]) -> str:
    """Return tshark stdout, surfacing stderr when stdout is empty and tshark failed.

    Corrupt or truncated PCAP files cause tshark to exit non-zero with
    diagnostic messages on stderr.  Without this check those errors are
    silently swallowed, producing empty results.

    Args:
        proc: Completed tshark process.

    Returns:
        The stdout text, or a bracketed error description when tshark
        failed with no usable output.
    """
    output = proc.stdout.strip()
    if output:
        return output
    if proc.returncode != 0:
        err = proc.stderr.strip()[:_STDERR_PREVIEW_LIMIT] if proc.stderr else "unknown error"
        return f"[tshark error (exit {proc.returncode}): {err}]"
    return ""


_PCAP_MODES = {
    "summary",
    "conversations",
    "dns",
    "http",
    "smtp",
    "tls",
    "beaconing",
    "tunneling",
    "custom",
    "all",
}


def _run_tshark(
    args: list[str],
    pcap_path: str,
    timeout: int = _PCAP_TIMEOUT,
    ssl_keylog_path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run tshark with the given args against a PCAP file.

    Handles OSError (e.g. binary removed at runtime) by returning a
    synthetic CompletedProcess with returncode=-1 and the error in
    stderr, preventing unhandled exceptions from cascading.
    """
    ssl_args: list[str] = []
    if ssl_keylog_path and Path(ssl_keylog_path).exists():
        ssl_args = ["-o", f"tls.keylog_file:{ssl_keylog_path}"]
    cmd = ["tshark", *ssl_args, "-r", pcap_path, *args]
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except OSError as exc:
        logger.error("Failed to execute tshark: %s", exc)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=-1,
            stdout="",
            stderr=f"Failed to execute tshark: {exc}",
        )


def _pcap_summary(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Capture statistics via capinfos + protocol hierarchy via tshark."""
    parts: list[str] = []

    capinfos = require_binary("capinfos")
    if capinfos:
        try:
            ci_proc = subprocess.run(
                [capinfos, pcap_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if ci_proc.stdout.strip():
                parts.append("=== Capture Info ===\n" + ci_proc.stdout.strip())
            elif ci_proc.returncode != 0 and ci_proc.stderr:
                parts.append(f"capinfos failed: {ci_proc.stderr.strip()[:_STDERR_PREVIEW_LIMIT]}")
        except subprocess.TimeoutExpired as exc:
            parts.append(_timeout_partial_output(exc, "capinfos"))
        except OSError as exc:
            parts.append(f"capinfos execution failed: {exc}")

    try:
        proc = _run_tshark(
            ["-q", "-z", "io,phs", "-c", str(max_packets)],
            pcap_path,
            timeout=120,
            ssl_keylog_path=ssl_keylog_path,
        )
        output = _tshark_output_or_error(proc)
        if output:
            parts.append("=== Protocol Hierarchy ===\n" + output)
    except subprocess.TimeoutExpired as exc:
        parts.append(_timeout_partial_output(exc, "tshark protocol hierarchy"))

    return "\n\n".join(parts)


def _pcap_conversations(
    pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None
) -> str:
    """IP and TCP conversation tables."""
    timeout = adaptive_timeout(pcap_path)
    parts: list[str] = []
    for conv_type in ("ip", "tcp"):
        try:
            proc = _run_tshark(
                ["-q", "-z", f"conv,{conv_type}", "-c", str(max_packets)],
                pcap_path,
                timeout=timeout,
                ssl_keylog_path=ssl_keylog_path,
            )
            output = _tshark_output_or_error(proc)
            if output:
                parts.append(f"=== {conv_type.upper()} Conversations ===\n" + output)
        except subprocess.TimeoutExpired as exc:
            parts.append(_timeout_partial_output(exc, f"tshark {conv_type} conversations"))
    return "\n\n".join(parts)


def _pcap_dns(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Extract DNS queries and responses."""
    try:
        proc = _run_tshark(
            [
                "-Y",
                "dns",
                "-T",
                "fields",
                "-e",
                "frame.time",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "dns.qry.name",
                "-e",
                "dns.resp.addr",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            timeout=adaptive_timeout(pcap_path),
            ssl_keylog_path=ssl_keylog_path,
        )
        return _tshark_output_or_error(proc)
    except subprocess.TimeoutExpired as exc:
        return _timeout_partial_output(exc, "tshark DNS extraction")


def _pcap_http(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Extract HTTP requests and responses."""
    try:
        proc = _run_tshark(
            [
                "-Y",
                "http",
                "-T",
                "fields",
                "-e",
                "frame.time",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "http.request.method",
                "-e",
                "http.request.uri",
                "-e",
                "http.host",
                "-e",
                "http.response.code",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            timeout=adaptive_timeout(pcap_path),
            ssl_keylog_path=ssl_keylog_path,
        )
        return _tshark_output_or_error(proc)
    except subprocess.TimeoutExpired as exc:
        return _timeout_partial_output(exc, "tshark HTTP extraction")


def _pcap_smtp(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Extract SMTP email transactions (sender, recipient, subject)."""
    try:
        proc = _run_tshark(
            [
                "-Y",
                "smtp",
                "-T",
                "fields",
                "-e",
                "frame.time",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "smtp.req.parameter",
                "-e",
                "smtp.response.parameter",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            timeout=adaptive_timeout(pcap_path),
            ssl_keylog_path=ssl_keylog_path,
        )
        return _tshark_output_or_error(proc)
    except subprocess.TimeoutExpired as exc:
        return _timeout_partial_output(exc, "tshark SMTP extraction")


def _pcap_tls(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Extract TLS handshake info (server names, certificate subjects)."""
    try:
        proc = _run_tshark(
            [
                "-Y",
                "tls.handshake.type == 1 || tls.handshake.type == 11",
                "-T",
                "fields",
                "-e",
                "frame.time",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "tls.handshake.extensions_server_name",
                "-e",
                "x509ce.dNSName",
                "-e",
                "x509sat.uTF8String",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            timeout=adaptive_timeout(pcap_path),
            ssl_keylog_path=ssl_keylog_path,
        )
        return _tshark_output_or_error(proc)
    except subprocess.TimeoutExpired as exc:
        return _timeout_partial_output(exc, "tshark TLS extraction")


def _pcap_custom(
    pcap_path: str, display_filter: str, max_packets: int, ssl_keylog_path: str | None = None
) -> str:
    """Apply a custom tshark display filter."""
    try:
        proc = _run_tshark(
            ["-Y", display_filter, "-c", str(max_packets)],
            pcap_path,
            timeout=adaptive_timeout(pcap_path),
            ssl_keylog_path=ssl_keylog_path,
        )
        return _tshark_output_or_error(proc)
    except subprocess.TimeoutExpired as exc:
        return _timeout_partial_output(exc, f"tshark custom filter '{display_filter}'")


def _pcap_beaconing(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Detect C2 beaconing by analyzing inter-arrival timing per destination."""
    try:
        proc = _run_tshark(
            [
                "-T",
                "fields",
                "-e",
                "frame.time_epoch",
                "-e",
                "ip.dst",
                "-e",
                "tcp.dstport",
                "-e",
                "udp.dstport",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            timeout=adaptive_timeout(pcap_path),
            ssl_keylog_path=ssl_keylog_path,
        )
    except subprocess.TimeoutExpired as exc:
        return _timeout_partial_output(exc, "tshark beaconing extraction")

    output = _tshark_output_or_error(proc)
    if output.startswith("[tshark error"):
        return output

    lines = output.splitlines()
    if len(lines) < 2:
        return "No packets found for beaconing analysis"

    dest_times: dict[str, list[float]] = {}
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            epoch = float(parts[0])
        except (ValueError, IndexError):
            continue
        dst_ip = parts[1]
        dst_port = parts[2] or parts[3] if len(parts) > 3 else parts[2]
        if not dst_ip or not dst_port:
            continue
        key = f"{dst_ip}:{dst_port}"
        dest_times.setdefault(key, []).append(epoch)

    results: list[str] = ["BEACONING ANALYSIS", "=" * 50, ""]
    flagged = 0
    for dest, times in sorted(dest_times.items(), key=lambda x: len(x[1]), reverse=True):
        if len(times) < 5:
            continue
        times.sort()
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 0.1:
            continue
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        cov = stddev / mean_interval if mean_interval > 0 else 999

        if cov < 0.3 and len(times) >= 10:
            flagged += 1
            results.append(
                f"** POTENTIAL BEACON: {dest} **\n"
                f"  Connections: {len(times)}, Interval: {mean_interval:.1f}s, "
                f"StdDev: {stddev:.1f}s, CoV: {cov:.3f}"
            )
        elif cov < 0.5 and len(times) >= 20:
            flagged += 1
            results.append(
                f"POSSIBLE BEACON: {dest}\n"
                f"  Connections: {len(times)}, Interval: {mean_interval:.1f}s, "
                f"StdDev: {stddev:.1f}s, CoV: {cov:.3f}"
            )

    results.insert(
        2, f"Destinations analyzed: {len(dest_times)}, Potential beacons flagged: {flagged}\n"
    )
    return "\n".join(results)


def _collect_dns_tunnel_stats(dns_lines: list[str]) -> dict[str, dict[str, Any]]:
    """Parse DNS query lines and accumulate per-domain statistics.

    Args:
        dns_lines: Raw tshark output lines (with header) from DNS query extraction.

    Returns:
        Mapping of base domain to stats dict containing query_count,
        subdomain_lengths, and unique subdomains.
    """
    domain_stats: dict[str, dict[str, Any]] = {}
    if len(dns_lines) <= 1:
        return domain_stats

    for line in dns_lines[1:]:
        parts = line.split("\t")
        if not parts or not parts[0]:
            continue
        qname = parts[0].strip().lower()
        labels = qname.split(".")
        if len(labels) < 2:
            continue
        base_domain = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""
        if base_domain not in domain_stats:
            domain_stats[base_domain] = {
                "query_count": 0,
                "subdomain_lengths": [],
                "subdomains": set(),
            }
        domain_stats[base_domain]["query_count"] += 1
        if subdomain:
            domain_stats[base_domain]["subdomain_lengths"].append(len(subdomain))
            domain_stats[base_domain]["subdomains"].add(subdomain)

    return domain_stats


def _score_dns_tunnel_candidates(
    domain_stats: dict[str, dict[str, Any]],
) -> list[str]:
    """Score domains for DNS tunneling suspicion using entropy and length heuristics.

    Args:
        domain_stats: Per-domain statistics from _collect_dns_tunnel_stats.

    Returns:
        List of formatted strings describing flagged domains.
    """
    flagged_lines: list[str] = []
    for domain, stats in sorted(
        domain_stats.items(), key=lambda x: x[1]["query_count"], reverse=True
    ):
        lengths = stats["subdomain_lengths"]
        if not lengths or stats["query_count"] < 10:
            continue
        avg_len = sum(lengths) / len(lengths)
        freq: dict[str, int] = {}
        all_chars = "".join(stats["subdomains"])
        for c in all_chars:
            freq[c] = freq.get(c, 0) + 1
        total = len(all_chars) or 1
        entropy = -sum(
            (count / total) * math.log2(count / total) for count in freq.values() if count > 0
        )

        suspicious = False
        reasons: list[str] = []
        if avg_len > 20:
            suspicious = True
            reasons.append(f"long subdomains (avg {avg_len:.0f} chars)")
        if entropy > 3.5:
            suspicious = True
            reasons.append(f"high entropy ({entropy:.2f} bits)")
        if stats["query_count"] > 100 and len(stats["subdomains"]) > 50:
            suspicious = True
            reasons.append(f"high unique subdomain count ({len(stats['subdomains'])})")

        if suspicious:
            flagged_lines.append(
                f"** POTENTIAL DNS TUNNEL: {domain} **\n"
                f"  Queries: {stats['query_count']}, "
                f"Unique subdomains: {len(stats['subdomains'])}, "
                f"Avg label len: {avg_len:.0f}, Entropy: {entropy:.2f}\n"
                f"  Reasons: {', '.join(reasons)}"
            )

    return flagged_lines


def _collect_icmp_payload_signals(
    pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None
) -> list[str]:
    """Detect ICMP packets with unusually large payloads indicating covert channels.

    Args:
        pcap_path: Path to the PCAP file.
        max_packets: Maximum packets to process.
        ssl_keylog_path: Optional SSL keylog file path.

    Returns:
        List of formatted output lines describing ICMP findings.
    """
    output_parts: list[str] = []
    try:
        icmp_proc = _run_tshark(
            [
                "-Y",
                "icmp && data.len > 64",
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "data.len",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            timeout=adaptive_timeout(pcap_path),
            ssl_keylog_path=ssl_keylog_path,
        )
        icmp_output = _tshark_output_or_error(icmp_proc)
        if icmp_output.startswith("[tshark error"):
            output_parts.append(f"\nICMP analysis: {icmp_output}")
        else:
            icmp_lines = icmp_output.splitlines()
            if len(icmp_lines) > 1:
                output_parts.append(
                    f"\nICMP large-payload packets (data > 64 bytes): {len(icmp_lines) - 1}"
                )
                for line in icmp_lines[1:6]:
                    output_parts.append(f"  {line}")
                if len(icmp_lines) > 6:
                    output_parts.append(f"  ... and {len(icmp_lines) - 6} more")
    except subprocess.TimeoutExpired as exc:
        output_parts.append(f"\n{_timeout_partial_output(exc, 'ICMP analysis')}")

    return output_parts


def _pcap_tunneling(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Detect DNS tunneling and ICMP covert channels."""
    output_parts: list[str] = ["DNS TUNNELING / COVERT CHANNEL ANALYSIS", "=" * 50, ""]

    try:
        proc = _run_tshark(
            [
                "-Y",
                "dns.qry.name",
                "-T",
                "fields",
                "-e",
                "dns.qry.name",
                "-e",
                "dns.qry.type",
                "-e",
                "frame.time",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            timeout=adaptive_timeout(pcap_path),
            ssl_keylog_path=ssl_keylog_path,
        )
        output = _tshark_output_or_error(proc)
        dns_lines = output.splitlines() if output and not output.startswith("[tshark") else []
    except subprocess.TimeoutExpired:
        dns_lines = []
        output_parts.append("DNS extraction timed out; tunnel analysis may be incomplete")

    domain_stats = _collect_dns_tunnel_stats(dns_lines)
    flagged_lines = _score_dns_tunnel_candidates(domain_stats)
    output_parts.extend(flagged_lines)

    output_parts.append(
        f"\nDomains analyzed: {len(domain_stats)}, DNS tunneling suspects: {len(flagged_lines)}"
    )

    output_parts.extend(_collect_icmp_payload_signals(pcap_path, max_packets, ssl_keylog_path))

    return "\n".join(output_parts)


def _validate_pcap_params(
    mode: str,
    pcap_path: str,
    display_filter: str | None,
    ssl_keylog_path: str | None,
    tc_id: str,
    params: dict[str, object],
) -> dict[str, object] | None:
    """Validate inputs for PCAP analysis.

    Args:
        mode: Requested analysis mode.
        pcap_path: Path to the PCAP file.
        display_filter: Optional Wireshark display filter.
        ssl_keylog_path: Optional SSL keylog file path.
        tc_id: Tool call identifier for error responses.
        params: Parameters dict for error responses.

    Returns:
        An error response dict if validation fails, None if all inputs are valid.
    """
    if mode not in _PCAP_MODES:
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            f"Unknown mode '{mode}'. Valid modes: {sorted(_PCAP_MODES)}",
            error_type="invalid_argument",
        )

    if not Path(pcap_path).exists():
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            f"File not found: {pcap_path}",
            error_type="file_not_found",
        )

    if not require_binary("tshark"):
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            "tshark not found on PATH",
            error_type="binary_missing",
            suggestion="Install tshark: apt-get install tshark",
        )

    if mode == "custom" and not display_filter:
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            "display_filter is required when mode='custom'",
            error_type="invalid_argument",
        )

    if ssl_keylog_path and not Path(ssl_keylog_path).exists():
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            f"SSL keylog file not found: {ssl_keylog_path}",
            error_type="file_not_found",
        )

    return None


def _run_pcap_mode(
    mode: str,
    pcap_path: str,
    max_packets: int,
    ssl_keylog_path: str | None,
    display_filter: str | None,
) -> tuple[str, str]:
    """Dispatch a single PCAP analysis mode and return its output.

    Args:
        mode: The analysis mode to run.
        pcap_path: Path to the PCAP file.
        max_packets: Maximum packets to process.
        ssl_keylog_path: Optional SSL keylog file path.
        display_filter: Display filter (used only for "custom" mode).

    Returns:
        A tuple of (source_name, output_text) for the executed mode.
    """
    mode_map: dict[str, tuple[str, Callable[[], str]]] = {
        "summary": (
            "pcap.summary",
            lambda: _pcap_summary(pcap_path, max_packets, ssl_keylog_path),
        ),
        "conversations": (
            "pcap.conversations",
            lambda: _pcap_conversations(pcap_path, max_packets, ssl_keylog_path),
        ),
        "dns": ("pcap.dns", lambda: _pcap_dns(pcap_path, max_packets, ssl_keylog_path)),
        "http": ("pcap.http", lambda: _pcap_http(pcap_path, max_packets, ssl_keylog_path)),
        "smtp": ("pcap.smtp", lambda: _pcap_smtp(pcap_path, max_packets, ssl_keylog_path)),
        "tls": ("pcap.tls", lambda: _pcap_tls(pcap_path, max_packets, ssl_keylog_path)),
        "beaconing": (
            "pcap.beaconing",
            lambda: _pcap_beaconing(pcap_path, max_packets, ssl_keylog_path),
        ),
        "tunneling": (
            "pcap.tunneling",
            lambda: _pcap_tunneling(pcap_path, max_packets, ssl_keylog_path),
        ),
    }

    if mode == "custom":
        assert display_filter is not None
        return "pcap.filtered", _pcap_custom(
            pcap_path, display_filter, max_packets, ssl_keylog_path
        )

    source_name, fn = mode_map[mode]
    return source_name, fn()


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_pcap_analysis(
    pcap_path: str,
    mode: str = "summary",
    display_filter: str | None = None,
    max_packets: int = 10000,
    ssl_keylog_path: str | None = None,
) -> dict[str, object]:
    """Analyze a PCAP or PCAPng network capture file using tshark.

    Extracts network conversations, DNS queries, HTTP traffic, protocol
    statistics, or applies a custom Wireshark display filter.  Results
    are indexed into the case database.

    Args:
        pcap_path: Path to the .pcap or .pcapng file.
        mode: Analysis mode.  One of:
            - "summary": capture stats + protocol hierarchy
            - "conversations": IP and TCP conversation tables
            - "dns": DNS queries and responses
            - "http": HTTP requests and responses
            - "beaconing": detect C2 beaconing via inter-arrival timing
            - "tunneling": detect DNS tunneling and ICMP covert channels
            - "custom": apply display_filter (required for this mode)
            - "all": run all modes (summary through tunneling)
        display_filter: Wireshark display filter (required when mode="custom",
            e.g. "ip.addr == 10.0.0.5 && tcp.port == 4444").
        max_packets: Maximum packets to process (default 10000).  Caps
            tshark's -c flag to prevent unbounded output on large captures.
        ssl_keylog_path: Optional path to an NSS key log file (SSLKEYLOGFILE
            format) for decrypting TLS traffic.  When provided, tshark uses
            it to decrypt encrypted sessions, revealing HTTP, SMTP, and other
            application-layer data inside TLS.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "pcap_path": pcap_path,
        "mode": mode,
        "display_filter": display_filter,
        "max_packets": max_packets,
        "ssl_keylog_path": ssl_keylog_path,
    }

    validation_error = _validate_pcap_params(
        mode, pcap_path, display_filter, ssl_keylog_path, tc_id, params
    )
    if validation_error is not None:
        return validation_error

    if mode == "all":
        modes_to_run = [
            "summary",
            "conversations",
            "dns",
            "http",
            "smtp",
            "tls",
            "beaconing",
            "tunneling",
        ]
    elif mode == "custom":
        modes_to_run = ["custom"]
    else:
        modes_to_run = [mode]

    results: list[object] = []
    for m in modes_to_run:
        try:
            source_name, output = _run_pcap_mode(
                m, pcap_path, max_packets, ssl_keylog_path, display_filter
            )
        except Exception as exc:
            logger.exception("PCAP mode '%s' failed unexpectedly", m)
            results.append(
                {
                    "source_name": f"pcap.{m}",
                    "status": "error",
                    "mode": m,
                    "error_message": str(exc)[:300],
                }
            )
            continue

        if output:
            summary = extract_and_index(output, source_name, pcap_path, "tshark")
            results.append(summary)
        else:
            results.append(
                {
                    "source_name": source_name,
                    "status": "no_output",
                    "mode": m,
                }
            )

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_pcap_analysis", params, results, "pcap", elapsed)


# ---------------------------------------------------------------------------
# Zeek network analysis
# ---------------------------------------------------------------------------

_ZEEK_TIMEOUT = 600
_ZEEK_BINARY = "/opt/zeek/bin/zeek"


def _run_zeek(
    binary: str,
    pcap_path: Path,
    output_dir: Path,
    generate_files: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Execute Zeek against a PCAP file.

    Args:
        binary: Resolved zeek executable.
        pcap_path: Path to the input PCAP.
        output_dir: Directory for Zeek log output.
        generate_files: Whether to enable file extraction.

    Returns:
        The completed process result.

    Raises:
        subprocess.TimeoutExpired: If Zeek exceeds the timeout.
    """
    cmd = [
        binary,
        "-C",
        "-r",
        str(pcap_path),
        "LogAscii::use_json=T",
    ]
    if generate_files:
        cmd.append("FileExtract::prefix=extracted_files/")

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=adaptive_timeout(pcap_path, base=_ZEEK_TIMEOUT),
        cwd=str(output_dir),
        check=False,
    )


def _extract_notable(log_type: str, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract forensically notable entries from a Zeek log.

    Applies log-type-specific heuristics to surface interesting records
    (long connections, large transfers, known-bad ports, suspicious DNS
    queries, etc.).

    Args:
        log_type: The Zeek log type (conn, dns, http, etc.).
        records: Parsed JSON records from the log.

    Returns:
        Filtered list of notable records.
    """
    notable: list[dict[str, Any]] = []

    match log_type:
        case "conn":
            for r in records:
                duration = r.get("duration", 0)
                if duration and duration > 3600:
                    notable.append(r)
                orig_bytes = r.get("orig_bytes", 0) or 0
                resp_bytes = r.get("resp_bytes", 0) or 0
                if orig_bytes + resp_bytes > 10_000_000:
                    notable.append(r)
        case "dns":
            for r in records:
                query = r.get("query", "")
                if len(query) > 60:
                    notable.append(r)
                qtype = r.get("qtype_name", "")
                if qtype in ("TXT", "NULL", "MX") and "...." in query:
                    notable.append(r)
        case "http":
            for r in records:
                status = r.get("status_code", 200)
                if status and status >= 400:
                    notable.append(r)
                user_agent = r.get("user_agent", "")
                if not user_agent or len(user_agent) < 10:
                    notable.append(r)
        case "ssl":
            for r in records:
                if r.get("validation_status") != "ok":
                    notable.append(r)
                ja3 = r.get("ja3")
                if ja3:
                    notable.append(r)
        case "notice":
            notable = list(records)

    return notable


def _parse_zeek_logs(
    output_dir: Path,
    protocols: list[str] | None,
) -> dict[str, Any]:
    """Parse Zeek JSON log files into structured results.

    Args:
        output_dir: Directory containing Zeek JSON logs.
        protocols: Optional protocol filter list.

    Returns:
        Dict with summaries and extracted intelligence per log type.
    """
    log_summaries: list[dict[str, Any]] = []
    all_dns_queries: list[dict[str, str]] = []
    all_http_requests: list[dict[str, str]] = []
    all_ssl_certs: list[dict[str, str]] = []
    all_notices: list[dict[str, str]] = []
    total_connections = 0
    protocols_detected: list[str] = []
    external_ips: set[str] = set()
    files_extracted: list[str] = []

    log_files = sorted(output_dir.glob("*.log"))

    for log_file in log_files:
        log_type = log_file.stem
        if protocols and log_type not in protocols:
            continue

        records: list[dict[str, Any]] = []
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        if not records:
            continue

        protocols_detected.append(log_type)
        notable = _extract_notable(log_type, records)

        log_summaries.append(
            {
                "log_type": log_type,
                "record_count": len(records),
                "file_path": str(log_file),
                "notable_count": len(notable),
            }
        )

        if log_type == "conn":
            total_connections = len(records)
            for r in records:
                dest_ip = r.get("id.resp_h", "")
                if dest_ip and not dest_ip.startswith(("10.", "192.168.", "172.")):
                    external_ips.add(dest_ip)

        elif log_type == "dns":
            for r in records[:100]:
                all_dns_queries.append(
                    {
                        "query": r.get("query", ""),
                        "qtype": r.get("qtype_name", ""),
                        "response": str(r.get("answers", "")),
                    }
                )

        elif log_type == "http":
            for r in records[:100]:
                all_http_requests.append(
                    {
                        "method": r.get("method", ""),
                        "host": r.get("host", ""),
                        "uri": r.get("uri", ""),
                        "status_code": str(r.get("status_code", "")),
                        "user_agent": r.get("user_agent", ""),
                    }
                )

        elif log_type == "ssl":
            for r in records[:100]:
                all_ssl_certs.append(
                    {
                        "server_name": r.get("server_name", ""),
                        "subject": r.get("subject", ""),
                        "issuer": r.get("issuer", ""),
                        "ja3": r.get("ja3", ""),
                        "validation_status": r.get("validation_status", ""),
                    }
                )

        elif log_type == "notice":
            for r in records[:50]:
                all_notices.append(
                    {
                        "note": r.get("note", ""),
                        "msg": r.get("msg", ""),
                    }
                )

    extracted_dir = output_dir / "extracted_files"
    if extracted_dir.exists():
        files_extracted = [f.name for f in extracted_dir.iterdir() if f.is_file()]

    return {
        "log_summaries": log_summaries,
        "total_connections": total_connections,
        "protocols_detected": protocols_detected,
        "dns_queries": all_dns_queries[:50],
        "http_requests": all_http_requests[:50],
        "ssl_certificates": all_ssl_certs[:50],
        "notices": all_notices[:50],
        "files_extracted": files_extracted[:50],
        "unique_external_ips": sorted(external_ips)[:100],
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_zeek_analysis(
    pcap_path: str,
    protocols: list[str] | None = None,
    generate_files: bool = True,
) -> dict[str, object]:
    """Analyze a PCAP using Zeek for protocol-aware log generation.

    Runs Zeek against a packet capture to produce structured logs for
    all detected protocols. Logs are correlated via unique session IDs
    (UIDs) enabling cross-protocol analysis.

    Args:
        pcap_path: Absolute path to the PCAP file.
        protocols: Optional list of protocols to focus on. If None,
            all detected protocols are included. Valid values include:
            "conn", "dns", "http", "ssl", "smtp", "ftp", "ssh", "smb",
            "files", "notice".
        generate_files: Whether to extract transferred files into a
            files/ subdirectory for further analysis.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "pcap_path": pcap_path,
        "protocols": protocols,
        "generate_files": generate_files,
    }

    # Keep the answer: the container's /opt prefix and a distro /usr/bin/zeek
    # are both legitimate, and exec'ing a different one than the gate accepted
    # surfaces as an opaque "[Errno 2]" instead of "zeek is not installed".
    zeek_bin = require_binary(_ZEEK_BINARY) or require_binary("zeek")
    if not zeek_bin:
        return error_response(
            tc_id,
            "run_zeek_analysis",
            params,
            "zeek not found on PATH",
            error_type="binary_missing",
            suggestion="Install Zeek: sudo apt install zeek",
        )

    if not Path(pcap_path).exists():
        return error_response(
            tc_id,
            "run_zeek_analysis",
            params,
            f"File not found: {pcap_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_zeek_") as tmpdir:
        output_dir = Path(tmpdir)
        try:
            _run_zeek(zeek_bin, Path(pcap_path), output_dir, generate_files)
        except subprocess.TimeoutExpired:
            log_files = list(output_dir.glob("*.log"))
            if log_files:
                result = _parse_zeek_logs(output_dir, protocols)
                result["timed_out"] = True
                text_parts = [f"Zeek (partial): {len(log_files)} log files generated"]
                for s in result.get("log_summaries", []):
                    text_parts.append(f"  {s['log_type']}: {s['record_count']} records")
                summary = extract_and_index(
                    "\n".join(text_parts), "zeek.partial", pcap_path, "zeek"
                )
                summary.update(result)
                elapsed = (time.monotonic() - t0) * 1000
                return tool_response(
                    tc_id, "run_zeek_analysis", params, summary, "zeek.partial", elapsed
                )
            return error_response(
                tc_id,
                "run_zeek_analysis",
                params,
                "Zeek timed out with no output",
                (time.monotonic() - t0) * 1000,
                error_type="timeout",
            )
        except OSError as exc:
            return error_response(
                tc_id,
                "run_zeek_analysis",
                params,
                f"Failed to execute Zeek: {exc}",
                (time.monotonic() - t0) * 1000,
                error_type="os_error",
            )

        result = _parse_zeek_logs(output_dir, protocols)

        text_parts = []
        for s in result.get("log_summaries", []):
            source_name = f"zeek.{s['log_type']}"
            log_path = Path(s["file_path"])
            if log_path.exists():
                log_content = log_path.read_text(errors="replace")[:50000]
                if log_content.strip():
                    extract_and_index(log_content, source_name, pcap_path, "zeek")
            text_parts.append(f"{s['log_type']}: {s['record_count']} records")

        summary_text = f"Zeek analysis of {pcap_path}\n" + "\n".join(text_parts)
        summary = extract_and_index(summary_text, "zeek.summary", pcap_path, "zeek")
        summary.update(result)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_zeek_analysis", params, summary, "zeek.summary", elapsed)


# ---------------------------------------------------------------------------
# Suricata IDS analysis
# ---------------------------------------------------------------------------

_SURICATA_TIMEOUT = 600
_SURICATA_BINARY = "/usr/bin/suricata"
_SURICATA_CONFIG = "/etc/suricata/suricata.yaml"
_ET_RULES_DIR = "/etc/suricata/rules"


def _suricata_binary() -> str | None:
    """Resolve the suricata executable, PATH first.

    A source install lands in /usr/local/bin and several distros ship it in
    /usr/sbin, so the PATH hit -- not the hardcoded literal -- is what has to
    reach subprocess.run.  The literal stays as the last-resort fallback for
    the image, which symlinks the arm64 source build to /usr/bin/suricata.
    """
    return require_binary("suricata") or (
        _SURICATA_BINARY if Path(_SURICATA_BINARY).exists() else None
    )


def _run_suricata_process(binary: str, pcap_path: Path, output_dir: Path) -> Path:
    """Execute Suricata in offline PCAP replay mode.

    Args:
        binary: Resolved suricata executable.
        pcap_path: Path to the input PCAP.
        output_dir: Directory for EVE JSON output.

    Returns:
        Path to the generated eve.json file.

    Raises:
        subprocess.TimeoutExpired: If Suricata exceeds the timeout.
    """
    eve_path = output_dir / "eve.json"

    cmd = [
        binary,
        "-r",
        str(pcap_path),
        "-l",
        str(output_dir),
        "-c",
        _SURICATA_CONFIG,
        "--set",
        f"default-rule-path={_ET_RULES_DIR}",
        "--set",
        "outputs.1.eve-log.filename=eve.json",
    ]

    subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=adaptive_timeout(pcap_path, base=_SURICATA_TIMEOUT),
        check=False,
    )

    return eve_path


def _parse_eve_json(
    eve_path: Path,
    severity_threshold: int = 3,
) -> dict[str, Any]:
    """Parse Suricata EVE JSON output into structured results.

    Args:
        eve_path: Path to the eve.json file.
        severity_threshold: Include alerts at or below this severity
            (1 = critical only, 3 = includes medium).

    Returns:
        Dict with alerts, statistics, and MITRE mappings.
    """
    alerts: list[dict[str, Any]] = []
    severity_counts: dict[int, int] = {}
    signature_counts: dict[str, int] = {}
    source_ips: set[str] = set()
    dest_ips: set[str] = set()
    categories: dict[str, int] = {}
    mitre_techniques: dict[str, list[str]] = {}

    if not eve_path.exists():
        return {
            "alerts": [],
            "statistics": {
                "total_alerts": 0,
                "unique_signatures": 0,
                "severity_counts": {},
                "top_signatures": [],
                "affected_source_ips": [],
                "affected_dest_ips": [],
                "categories": {},
            },
            "mitre_techniques": {},
            "timeline": [],
        }

    with open(eve_path) as f:
        for line in f:
            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert_data = event.get("alert", {})
            severity = alert_data.get("severity", 3)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            sig_name = alert_data.get("signature", "")
            signature_counts[sig_name] = signature_counts.get(sig_name, 0) + 1

            category = alert_data.get("category", "")
            categories[category] = categories.get(category, 0) + 1

            src_ip = event.get("src_ip", "")
            dst_ip = event.get("dest_ip", "")
            if src_ip:
                source_ips.add(src_ip)
            if dst_ip:
                dest_ips.add(dst_ip)

            metadata = alert_data.get("metadata", {})
            mitre = metadata.get("mitre_technique_id", [])
            if isinstance(mitre, str):
                mitre = [mitre]
            for tech_id in mitre:
                if tech_id not in mitre_techniques:
                    mitre_techniques[tech_id] = []
                if sig_name not in mitre_techniques[tech_id]:
                    mitre_techniques[tech_id].append(sig_name)

            if severity > severity_threshold:
                continue

            alerts.append(
                {
                    "timestamp": event.get("timestamp", ""),
                    "signature_id": alert_data.get("signature_id", 0),
                    "signature": sig_name,
                    "category": category,
                    "severity": severity,
                    "source_ip": src_ip,
                    "source_port": event.get("src_port", 0),
                    "dest_ip": dst_ip,
                    "dest_port": event.get("dest_port", 0),
                    "protocol": event.get("proto", ""),
                    "mitre_attack": mitre,
                    "payload_printable": event.get("payload_printable", ""),
                }
            )

    top_sigs = sorted(signature_counts.items(), key=lambda x: x[1], reverse=True)[:20]

    return {
        "alerts": alerts[:200],
        "statistics": {
            "total_alerts": sum(severity_counts.values()),
            "unique_signatures": len(signature_counts),
            "severity_counts": severity_counts,
            "top_signatures": top_sigs,
            "affected_source_ips": sorted(source_ips)[:50],
            "affected_dest_ips": sorted(dest_ips)[:50],
            "categories": categories,
        },
        "mitre_techniques": mitre_techniques,
        "timeline": [
            {"timestamp": a["timestamp"], "signature": a["signature"], "severity": a["severity"]}
            for a in alerts[:100]
        ],
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_suricata(
    pcap_path: str,
    alert_severity_threshold: int = 3,
) -> dict[str, object]:
    """Replay PCAP against Suricata IDS rules to detect known threats.

    Runs the Suricata engine in offline mode against a packet capture
    using the Emerging Threats Open ruleset. Produces structured alerts
    with severity, MITRE ATT&CK mappings, and affected hosts.

    Args:
        pcap_path: Absolute path to the PCAP file.
        alert_severity_threshold: Maximum severity level to include
            (1=highest severity only, 3=include medium and above).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "pcap_path": pcap_path,
        "alert_severity_threshold": alert_severity_threshold,
    }

    suricata_bin = _suricata_binary()
    if suricata_bin is None:
        return error_response(
            tc_id,
            "run_suricata",
            params,
            "suricata not found on PATH",
            error_type="binary_missing",
            suggestion=(
                "Install Suricata: sudo add-apt-repository ppa:oisf/suricata-stable"
                " && sudo apt install suricata && sudo suricata-update"
            ),
        )

    if not Path(pcap_path).exists():
        return error_response(
            tc_id,
            "run_suricata",
            params,
            f"File not found: {pcap_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_suricata_") as tmpdir:
        output_dir = Path(tmpdir)
        try:
            eve_path = _run_suricata_process(suricata_bin, Path(pcap_path), output_dir)
        except subprocess.TimeoutExpired:
            eve_path = output_dir / "eve.json"
            if eve_path.exists():
                result = _parse_eve_json(eve_path, alert_severity_threshold)
                result["timed_out"] = True
                alert_count = result["statistics"]["total_alerts"]
                summary_text = f"Suricata (partial, timed out): {alert_count} alerts detected"
                summary = extract_and_index(
                    summary_text, "suricata.partial", pcap_path, "suricata"
                )
                summary.update(result)
                elapsed = (time.monotonic() - t0) * 1000
                return tool_response(
                    tc_id, "run_suricata", params, summary, "suricata.partial", elapsed
                )
            return error_response(
                tc_id,
                "run_suricata",
                params,
                "Suricata timed out with no output",
                (time.monotonic() - t0) * 1000,
                error_type="timeout",
            )
        except OSError as exc:
            return error_response(
                tc_id,
                "run_suricata",
                params,
                f"Failed to execute Suricata: {exc}",
                (time.monotonic() - t0) * 1000,
                error_type="os_error",
            )

        result = _parse_eve_json(eve_path, alert_severity_threshold)

        stats = result["statistics"]
        text_parts = [
            f"Suricata analysis of {pcap_path}",
            f"Total alerts: {stats['total_alerts']}",
            f"Unique signatures: {stats['unique_signatures']}",
            f"Affected source IPs: {len(stats['affected_source_ips'])}",
            f"Affected dest IPs: {len(stats['affected_dest_ips'])}",
        ]
        for sig, count in stats.get("top_signatures", [])[:10]:
            text_parts.append(f"  {sig}: {count} hits")

        summary = extract_and_index(
            "\n".join(text_parts), "suricata.alerts", pcap_path, "suricata"
        )
        summary.update(result)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_suricata", params, summary, "suricata.alerts", elapsed)
