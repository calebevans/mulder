"""Network capture (PCAP) analysis MCP tools."""

from __future__ import annotations

import logging
import math
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import error_response, make_tool_call_id, tool_response

__all__ = [
    "run_pcap_analysis",
]

logger = logging.getLogger(__name__)

_PCAP_TIMEOUT = 600

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


def _require_binary(name: str) -> str | None:
    """Return the binary path if found, else None."""
    return shutil.which(name)


def _run_tshark(
    args: list[str],
    pcap_path: str,
    timeout: int = _PCAP_TIMEOUT,
    ssl_keylog_path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run tshark with the given args against a PCAP file."""
    ssl_args: list[str] = []
    if ssl_keylog_path and Path(ssl_keylog_path).exists():
        ssl_args = ["-o", f"tls.keylog_file:{ssl_keylog_path}"]
    cmd = ["tshark", *ssl_args, "-r", pcap_path, *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _pcap_summary(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Capture statistics via capinfos + protocol hierarchy via tshark."""
    parts: list[str] = []

    capinfos = _require_binary("capinfos")
    if capinfos:
        try:
            proc = subprocess.run(
                [capinfos, pcap_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.stdout.strip():
                parts.append("=== Capture Info ===\n" + proc.stdout.strip())
        except subprocess.TimeoutExpired:
            parts.append("capinfos timed out")

    try:
        proc = _run_tshark(
            ["-q", "-z", "io,phs", "-c", str(max_packets)],
            pcap_path,
            timeout=120,
            ssl_keylog_path=ssl_keylog_path,
        )
        if proc.stdout.strip():
            parts.append("=== Protocol Hierarchy ===\n" + proc.stdout.strip())
    except subprocess.TimeoutExpired:
        parts.append("tshark protocol hierarchy timed out")

    return "\n\n".join(parts)


def _pcap_conversations(
    pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None
) -> str:
    """IP and TCP conversation tables."""
    parts: list[str] = []
    for conv_type in ("ip", "tcp"):
        try:
            proc = _run_tshark(
                ["-q", "-z", f"conv,{conv_type}", "-c", str(max_packets)],
                pcap_path,
                ssl_keylog_path=ssl_keylog_path,
            )
            if proc.stdout.strip():
                parts.append(f"=== {conv_type.upper()} Conversations ===\n" + proc.stdout.strip())
        except subprocess.TimeoutExpired:
            parts.append(f"tshark {conv_type} conversations timed out")
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
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "tshark DNS extraction timed out"


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
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "tshark HTTP extraction timed out"


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
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "tshark SMTP extraction timed out"


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
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "tshark TLS extraction timed out"


def _pcap_custom(
    pcap_path: str, display_filter: str, max_packets: int, ssl_keylog_path: str | None = None
) -> str:
    """Apply a custom tshark display filter."""
    try:
        proc = _run_tshark(
            ["-Y", display_filter, "-c", str(max_packets)],
            pcap_path,
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"tshark custom filter '{display_filter}' timed out"


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
            ssl_keylog_path=ssl_keylog_path,
        )
    except subprocess.TimeoutExpired:
        return "tshark beaconing extraction timed out"

    lines = proc.stdout.strip().splitlines()
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
            ssl_keylog_path=ssl_keylog_path,
        )
        dns_lines = proc.stdout.strip().splitlines()
    except subprocess.TimeoutExpired:
        dns_lines = []

    domain_stats: dict[str, dict[str, Any]] = {}
    if len(dns_lines) > 1:
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

    flagged_dns = 0
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
            flagged_dns += 1
            output_parts.append(
                f"** POTENTIAL DNS TUNNEL: {domain} **\n"
                f"  Queries: {stats['query_count']}, "
                f"Unique subdomains: {len(stats['subdomains'])}, "
                f"Avg label len: {avg_len:.0f}, Entropy: {entropy:.2f}\n"
                f"  Reasons: {', '.join(reasons)}"
            )

    output_parts.append(
        f"\nDomains analyzed: {len(domain_stats)}, DNS tunneling suspects: {flagged_dns}"
    )

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
            ssl_keylog_path=ssl_keylog_path,
        )
        icmp_lines = icmp_proc.stdout.strip().splitlines()
        if len(icmp_lines) > 1:
            output_parts.append(
                f"\nICMP large-payload packets (data > 64 bytes): {len(icmp_lines) - 1}"
            )
            for line in icmp_lines[1:6]:
                output_parts.append(f"  {line}")
            if len(icmp_lines) > 6:
                output_parts.append(f"  ... and {len(icmp_lines) - 6} more")
    except subprocess.TimeoutExpired:
        output_parts.append("\nICMP analysis timed out")

    return "\n".join(output_parts)


@mcp.tool()
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
    params = {
        "pcap_path": pcap_path,
        "mode": mode,
        "display_filter": display_filter,
        "max_packets": max_packets,
        "ssl_keylog_path": ssl_keylog_path,
    }

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

    if not _require_binary("tshark"):
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

    _ssl = ssl_keylog_path
    results: list[object] = []

    mode_map: dict[str, tuple[str, Callable[[], str]]] = {
        "summary": ("pcap.summary", lambda: _pcap_summary(pcap_path, max_packets, _ssl)),
        "conversations": (
            "pcap.conversations",
            lambda: _pcap_conversations(pcap_path, max_packets, _ssl),
        ),
        "dns": ("pcap.dns", lambda: _pcap_dns(pcap_path, max_packets, _ssl)),
        "http": ("pcap.http", lambda: _pcap_http(pcap_path, max_packets, _ssl)),
        "smtp": ("pcap.smtp", lambda: _pcap_smtp(pcap_path, max_packets, _ssl)),
        "tls": ("pcap.tls", lambda: _pcap_tls(pcap_path, max_packets, _ssl)),
        "beaconing": ("pcap.beaconing", lambda: _pcap_beaconing(pcap_path, max_packets, _ssl)),
        "tunneling": ("pcap.tunneling", lambda: _pcap_tunneling(pcap_path, max_packets, _ssl)),
    }

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

    for m in modes_to_run:
        if m == "custom":
            assert display_filter is not None
            output = _pcap_custom(pcap_path, display_filter, max_packets, _ssl)
            source_name = "pcap.filtered"
        else:
            source_name, fn = mode_map[m]
            output = fn()

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
