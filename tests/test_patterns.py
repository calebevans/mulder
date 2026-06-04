"""Tests for mulder.patterns shared utilities."""

from __future__ import annotations

from mulder.patterns import (
    EMAIL_RE,
    IP_RE,
    classify_ip,
    format_token_count,
    is_external_ip,
    source_is_cited,
)


class TestClassifyIp:
    """Tests for classify_ip covering all five categories."""

    def test_loopback_127_0_0_1(self) -> None:
        assert classify_ip("127.0.0.1") == "loopback"

    def test_loopback_127_255_255_255(self) -> None:
        assert classify_ip("127.255.255.255") == "loopback"

    def test_private_10_network(self) -> None:
        assert classify_ip("10.0.0.1") == "private"
        assert classify_ip("10.255.255.255") == "private"

    def test_private_172_16_range(self) -> None:
        assert classify_ip("172.16.0.1") == "private"
        assert classify_ip("172.31.255.255") == "private"

    def test_private_192_168(self) -> None:
        assert classify_ip("192.168.0.1") == "private"
        assert classify_ip("192.168.255.255") == "private"

    def test_link_local(self) -> None:
        assert classify_ip("169.254.0.1") == "link_local"
        assert classify_ip("169.254.255.255") == "link_local"

    def test_reserved_0_0_0_0(self) -> None:
        assert classify_ip("0.0.0.0") == "reserved"

    def test_reserved_255_255_255_255(self) -> None:
        assert classify_ip("255.255.255.255") == "reserved"

    def test_reserved_multicast(self) -> None:
        assert classify_ip("224.0.0.1") == "reserved"

    def test_public_8_8_8_8(self) -> None:
        assert classify_ip("8.8.8.8") == "public"

    def test_public_1_1_1_1(self) -> None:
        assert classify_ip("1.1.1.1") == "public"

    def test_invalid_ip_returns_reserved(self) -> None:
        assert classify_ip("not.an.ip.address") == "reserved"
        assert classify_ip("999.999.999.999") == "reserved"

    def test_172_15_is_public(self) -> None:
        """172.15.x.x is NOT private (private range starts at 172.16)."""
        assert classify_ip("172.15.0.1") == "public"

    def test_172_32_is_public(self) -> None:
        """172.32.x.x is NOT private (private range ends at 172.31)."""
        assert classify_ip("172.32.0.1") == "public"


class TestIsExternalIp:
    """Tests for the is_external_ip convenience wrapper."""

    def test_public_returns_true(self) -> None:
        assert is_external_ip("8.8.8.8") is True

    def test_private_returns_false(self) -> None:
        assert is_external_ip("10.0.0.1") is False

    def test_loopback_returns_false(self) -> None:
        assert is_external_ip("127.0.0.1") is False

    def test_reserved_returns_false(self) -> None:
        assert is_external_ip("0.0.0.0") is False

    def test_link_local_returns_false(self) -> None:
        assert is_external_ip("169.254.1.1") is False


class TestSourceIsCited:
    """Tests for source_is_cited edge cases."""

    def test_exact_match(self) -> None:
        assert source_is_cited("bulk.email", {"bulk.email"}) is True

    def test_substring_match_source_in_finding(self) -> None:
        assert source_is_cited("bulk.email", {"bulk.email (carry-tablet)"}) is True

    def test_substring_match_finding_in_source(self) -> None:
        assert source_is_cited("bulk.email.host1", {"bulk.email"}) is True

    def test_no_match(self) -> None:
        assert source_is_cited("pcap.dns", {"bulk.email", "evtx.security"}) is False

    def test_empty_finding_sources(self) -> None:
        assert source_is_cited("bulk.email", set()) is False

    def test_empty_source_name(self) -> None:
        assert source_is_cited("", {"bulk.email"}) is False

    def test_partial_name_no_match(self) -> None:
        assert source_is_cited("bulk.emai", {"pcap.dns"}) is False


class TestFormatTokenCount:
    """Tests for format_token_count boundaries."""

    def test_below_thousand(self) -> None:
        assert format_token_count(500) == "500"
        assert format_token_count(0) == "0"
        assert format_token_count(999) == "999"

    def test_exactly_thousand(self) -> None:
        assert format_token_count(1000) == "1.0K"

    def test_thousands(self) -> None:
        assert format_token_count(1500) == "1.5K"
        assert format_token_count(50_000) == "50.0K"

    def test_exactly_million(self) -> None:
        assert format_token_count(1_000_000) == "1.0M"

    def test_millions(self) -> None:
        assert format_token_count(2_500_000) == "2.5M"

    def test_float_input(self) -> None:
        assert format_token_count(1500.0) == "1.5K"
        assert format_token_count(500.7) == "500"


class TestEmailRegex:
    """Tests for EMAIL_RE, including the fixed [A-Za-z] bug."""

    def test_matches_valid_email(self) -> None:
        assert EMAIL_RE.search("user@example.com") is not None

    def test_matches_email_with_plus(self) -> None:
        assert EMAIL_RE.search("user+tag@example.com") is not None

    def test_matches_email_with_dots(self) -> None:
        assert EMAIL_RE.search("first.last@sub.domain.org") is not None

    def test_does_not_match_pipe_in_tld(self) -> None:
        """The old buggy regex [A-Z|a-z] would match literal '|' in TLDs."""
        match = EMAIL_RE.search("user@example.|om")
        assert match is None or "|" not in match.group()

    def test_does_not_match_bare_pipe(self) -> None:
        assert EMAIL_RE.fullmatch("user@host.|") is None

    def test_tld_minimum_length(self) -> None:
        assert EMAIL_RE.search("user@example.c") is None


class TestIpRegex:
    """Tests for IP_RE compiled regex."""

    def test_matches_valid_ip(self) -> None:
        assert IP_RE.search("Address is 192.168.1.1 here") is not None

    def test_extracts_ip(self) -> None:
        m = IP_RE.search("Connect to 10.0.0.5 on port 80")
        assert m is not None
        assert m.group() == "10.0.0.5"

    def test_multiple_ips(self) -> None:
        text = "From 10.0.0.1 to 10.0.0.2"
        assert len(IP_RE.findall(text)) == 2
