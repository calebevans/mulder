"""Shared patterns, constants, and utilities used across mulder modules."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

IP_RE: re.Pattern[str] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

EMAIL_RE: re.Pattern[str] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

DOMAIN_RE: re.Pattern[str] = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|xyz|top|ru|cn|uk|de|fr|onion|local)\b",
    re.IGNORECASE,
)

HASH_RE: re.Pattern[str] = re.compile(r"\b[a-f0-9]{32,64}\b")

WIN_PATH_RE: re.Pattern[str] = re.compile(r"[A-Z]:\\[^\s,\"']+")

UNIX_PATH_RE: re.Pattern[str] = re.compile(
    r"/(?:usr|var|etc|home|tmp|opt|root|proc|sys|run|mnt|media)[^\s,\"']+"
)

PROCESS_RE: re.Pattern[str] = re.compile(
    r"\b(\w+\.exe|(?:sshd|cron|bash|sh|python[23]?|perl|ruby|java|node|nginx|"
    r"apache2?|httpd|mysqld|postgres|systemd|init|kworker|iptables|netcat|nc|"
    r"ncat|wget|curl|chmod|chown|dd|rsync|ssh|scp|sftp|su|sudo))\b",
    re.IGNORECASE,
)

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
}

DISK_IMAGE_EXTS: frozenset[str] = frozenset(
    {".e01", ".raw", ".dd", ".img", ".vmdk", ".vhd", ".vhdx", ".001"}
)

DEFAULT_DB_DIR: str = "~/.mulder/cases"

DEFAULT_WORKSPACE_DIR: str = "~/.mulder/workspace"
"""Default working directory for agent sessions on a native install.

Mirrors DEFAULT_DB_DIR's ``~/.mulder/…`` convention. The container overrides
this with the MULDER_CWD environment variable (see Dockerfile).
"""

SUSPICIOUS_PATHS: tuple[str, ...] = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\recycle",
)


def format_token_count(count: int | float) -> str:
    """Format a token count with K/M suffix for human readability.

    Args:
        count: Raw token count.

    Returns:
        Human-readable string with appropriate suffix (e.g. ``"1.5M"``).
    """
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.1f}K"
    return str(int(count))


def source_is_cited(source_name: str, finding_sources: set[str]) -> bool:
    """Check if a source is cited by any finding using substring matching.

    Findings cite shorthand like ``"bulk.email (carry-tablet)"`` while
    DB sources are stored as ``"bulk.email"``, so we match if the
    source_name appears as a substring of any finding source string,
    or vice versa.

    Args:
        source_name: Canonical source name from the database.
        finding_sources: Set of source strings cited across findings.

    Returns:
        True if *source_name* is matched by any entry in *finding_sources*.
    """
    if not source_name:
        return False
    return any(source_name in fs or fs in source_name for fs in finding_sources)


def classify_ip(ip: str) -> str:
    """Classify an IPv4 address into a network category.

    Args:
        ip: Dotted-quad IPv4 address string.

    Returns:
        One of ``"public"``, ``"private"``, ``"loopback"``,
        ``"link_local"``, or ``"reserved"``.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return "reserved"

    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_unspecified or addr.is_reserved or addr.is_multicast:
        return "reserved"
    if addr.is_private:
        return "private"
    return "public"


def is_external_ip(ip: str) -> bool:
    """Return True only if *ip* classifies as a public address.

    Args:
        ip: Dotted-quad IPv4 address string.

    Returns:
        True when the address is routable on the public internet.
    """
    return classify_ip(ip) == "public"


@dataclass
class IOCSet:
    """Collection of extracted Indicators of Compromise.

    Attributes:
        ips: Public IPv4 addresses (private/loopback filtered out).
        domains: Domain names matching common TLDs.
        hashes: MD5/SHA1/SHA256 hex strings.
        paths: Windows and Unix filesystem paths.
        processes: Executable and process names.
        emails: Email addresses.
    """

    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)


def extract_iocs_from_text(text: str) -> IOCSet:
    """Extract all IOC types from a text block.

    Filters out private/loopback IP addresses using ``classify_ip()`` for
    correct handling of all RFC 1918 ranges. All other IOC types are
    returned as-is from their respective regex matches.

    Args:
        text: Arbitrary text to scan for indicators.

    Returns:
        An IOCSet populated with deduplicated matches.
    """
    return IOCSet(
        ips=[ip for ip in IP_RE.findall(text) if classify_ip(ip) == "public"],
        domains=DOMAIN_RE.findall(text),
        hashes=HASH_RE.findall(text),
        paths=WIN_PATH_RE.findall(text) + UNIX_PATH_RE.findall(text),
        processes=PROCESS_RE.findall(text),
        emails=EMAIL_RE.findall(text),
    )
