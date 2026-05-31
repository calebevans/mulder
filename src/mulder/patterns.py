"""Shared patterns, constants, and utilities used across mulder modules."""

from __future__ import annotations

import ipaddress
import re

IP_RE: re.Pattern[str] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

EMAIL_RE: re.Pattern[str] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

DEFAULT_DB_DIR: str = "~/.mulder/cases"

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
