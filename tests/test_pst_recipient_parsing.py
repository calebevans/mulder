"""Recipient parsing must respect RFC 5322 quoting, not split on every comma.

``_parse_recipients`` did ``raw.split(",")``. A display name may legitimately
contain a comma -- ``"Doe, John" <john@example.com>`` is the form Outlook
emits for a Last, First contact -- so the header

    "Doe, John" <john@example.com>, jane@example.com

was split into three entries, two of which are not addresses at all. The
recipient list shown to the examiner was wrong, and a search for
``john@example.com`` had to match a mangled fragment to succeed.
"""

from __future__ import annotations

from mulder.server.tools.email import _parse_recipients


def test_a_quoted_comma_does_not_split_a_recipient() -> None:
    """The Last, First display name Outlook emits."""
    parsed = _parse_recipients('"Doe, John" <john@example.com>, jane@example.com')

    assert parsed == ["Doe, John <john@example.com>", "jane@example.com"]


def test_every_address_survives_a_quoted_comma() -> None:
    """The count itself was wrong: two recipients became three entries."""
    parsed = _parse_recipients('"Doe, John" <john@example.com>, jane@example.com')

    assert len(parsed) == 2


def test_a_bare_address_is_unchanged() -> None:
    """Narrowness: the common case must be untouched."""
    assert _parse_recipients("a@example.com, b@example.com") == [
        "a@example.com",
        "b@example.com",
    ]


def test_an_unquoted_display_name_is_kept() -> None:
    """Narrowness: names without commas still render as Name <addr>."""
    assert _parse_recipients("Jane Roe <jane@example.com>") == ["Jane Roe <jane@example.com>"]


def test_an_empty_header_is_an_empty_list() -> None:
    """Narrowness: absent To/Cc must not produce a phantom recipient."""
    assert _parse_recipients("") == []


def test_surrounding_whitespace_is_stripped() -> None:
    """Narrowness: the old implementation stripped, and so must this one."""
    assert _parse_recipients("  a@example.com ,  b@example.com  ") == [
        "a@example.com",
        "b@example.com",
    ]
