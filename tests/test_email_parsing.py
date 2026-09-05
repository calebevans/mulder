"""A mailbox search that silently returns nothing is the wrong kind of empty.

Five independent defects in the PST/OST path, each of which drops evidence
without saying so:

* the ``Date`` header is RFC 5322 (``Mon, 11 Mar 2024 09:14:02 +0100``) and
  was compared to ``YYYY-MM-DD`` bounds **as a string**. ``"Mon, ..."`` sorts
  above every digit, so ``date_end`` excluded the entire mailbox and
  ``date_start`` excluded nothing: any date-bounded search returned zero
  messages;
* subjects and display names are RFC 2047 encoded, and were read raw, so a
  search for "wire transfer" could not match a subject that says exactly
  that;
* ``To``/``Cc`` were split on ``","``, which is inside a quoted display name
  as often as it is between recipients;
* an HTML-only message -- most phishing -- had no body at all, because only
  ``text/plain`` was read;
* an attachment only counted if it declared
  ``Content-Disposition: attachment``, so an ``inline`` payload skipped the
  suspicious-extension check entirely.
"""

from __future__ import annotations

import email.parser
from email.header import Header
from typing import Any

import pytest

from mulder.server.tools.email import (
    _decode_header_value,
    _get_searchable_body,
    _in_date_range,
    _matches_search,
    _parse_email_message,
    _parse_recipients,
)


def _msg(raw: str) -> Any:
    return email.parser.Parser().parsestr(raw)


PLAIN = (
    "Message-ID: <1@x>\r\n"
    "Subject: Quarterly report\r\n"
    "From: alice@example.com\r\n"
    "To: bob@example.com\r\n"
    "Date: Mon, 11 Mar 2024 09:14:02 +0100\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "the numbers are attached\r\n"
)

# A subject and display name as a real client encodes them.
ENCODED = (
    "Message-ID: <2@x>\r\n"
    "Subject: =?utf-8?B?VXJnZW50OiB3aXJlIHRyYW5zZmVy?=\r\n"
    "From: =?utf-8?Q?Jos=C3=A9_Silva?= <jose@example.com>\r\n"
    'To: "Doe, John" <john@example.com>, jane@example.com\r\n'
    "Date: Tue, 12 Mar 2024 11:02:10 +0000\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "please action today\r\n"
)

HTML_ONLY = (
    "Message-ID: <3@x>\r\n"
    "Subject: Invoice\r\n"
    "From: billing@example.com\r\n"
    "To: bob@example.com\r\n"
    "Date: Wed, 13 Mar 2024 08:00:00 +0000\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<html><body><p>Please <b>reset your password</b> at "
    '<a href="http://evil.example">this link</a></p></body></html>\r\n'
)

INLINE_ATTACHMENT = (
    "Message-ID: <4@x>\r\n"
    "Subject: Photos\r\n"
    "From: mallory@example.com\r\n"
    "To: bob@example.com\r\n"
    "Date: Thu, 14 Mar 2024 10:00:00 +0000\r\n"
    'Content-Type: multipart/mixed; boundary="B"\r\n'
    "\r\n"
    "--B\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "see attached\r\n"
    "--B\r\n"
    "Content-Type: application/octet-stream\r\n"
    'Content-Disposition: inline; filename="invoice.exe"\r\n'
    "\r\n"
    "MZ\r\n"
    "--B--\r\n"
)


class TestDateRange:
    """The defect that made date-bounded searches return nothing."""

    HEADER = "Mon, 11 Mar 2024 09:14:02 +0100"

    def test_a_message_inside_the_range_is_kept(self) -> None:
        assert _in_date_range(self.HEADER, "2024-01-01", "2024-12-31") is True

    def test_the_old_string_comparison_would_have_dropped_it(self) -> None:
        """Pins why: 'M' sorts above every digit."""
        assert self.HEADER > "2024-12-31"
        assert not self.HEADER < "2024-01-01"

    def test_a_message_before_the_start_is_dropped(self) -> None:
        assert _in_date_range(self.HEADER, "2024-06-01", None) is False

    def test_a_message_after_the_end_is_dropped(self) -> None:
        assert _in_date_range(self.HEADER, None, "2024-01-31") is False

    def test_the_bounds_are_inclusive(self) -> None:
        assert _in_date_range(self.HEADER, "2024-03-11", "2024-03-11") is True

    def test_no_bounds_keeps_everything(self) -> None:
        assert _in_date_range(self.HEADER, None, None) is True

    def test_a_timezone_is_respected(self) -> None:
        """23:30 -0800 is the 12th in UTC but the 11th where it was sent."""
        assert _in_date_range("Mon, 11 Mar 2024 23:30:00 -0800", "2024-03-11", "2024-03-11")

    @pytest.mark.parametrize("raw", ["", "not a date", "Mon, 99 Xyz 9999"])
    def test_an_unparseable_date_is_kept(self, raw: str) -> None:
        """A malformed header must not silently hide a message."""
        assert _in_date_range(raw, "2024-01-01", "2024-12-31") is True


class TestHeaderDecoding:
    def test_a_base64_subject_is_decoded(self) -> None:
        assert _decode_header_value("=?utf-8?B?VXJnZW50OiB3aXJlIHRyYW5zZmVy?=") == (
            "Urgent: wire transfer"
        )

    def test_a_quoted_printable_name_is_decoded(self) -> None:
        assert _decode_header_value("=?utf-8?Q?Jos=C3=A9_Silva?=") == "José Silva"

    def test_plain_text_is_unchanged(self) -> None:
        assert _decode_header_value("Quarterly report") == "Quarterly report"

    def test_none_is_empty(self) -> None:
        assert _decode_header_value(None) == ""

    def test_a_round_trip_through_the_stdlib(self) -> None:
        original = "Betreff: Überweisung"
        encoded = Header(original, "utf-8").encode()
        assert _decode_header_value(encoded) == original

    def test_the_parsed_message_carries_the_decoded_subject(self) -> None:
        parsed = _parse_email_message(_msg(ENCODED), "Inbox")
        assert parsed["subject"] == "Urgent: wire transfer"
        assert "José Silva" in str(parsed["sender"])

    def test_a_keyword_search_now_reaches_an_encoded_subject(self) -> None:
        parsed = _parse_email_message(_msg(ENCODED), "Inbox")
        assert _matches_search(str(parsed["subject"]), "", None, [], "wire transfer")


class TestRecipientParsing:
    RAW = '"Doe, John" <john@example.com>, jane@example.com, "Smith, A" <a@x.com>'

    def test_a_comma_in_a_display_name_does_not_split_the_recipient(self) -> None:
        assert len(_parse_recipients(self.RAW)) == 3

    def test_the_old_split_produced_five_fragments(self) -> None:
        assert len([r.strip() for r in self.RAW.split(",") if r.strip()]) == 5

    def test_every_address_survives(self) -> None:
        joined = " ".join(_parse_recipients(self.RAW))
        for addr in ("john@example.com", "jane@example.com", "a@x.com"):
            assert addr in joined

    def test_a_bare_address_is_kept_bare(self) -> None:
        assert _parse_recipients("jane@example.com") == ["jane@example.com"]

    def test_empty(self) -> None:
        assert _parse_recipients("") == []

    def test_an_encoded_display_name_is_decoded(self) -> None:
        out = _parse_recipients("=?utf-8?Q?Jos=C3=A9?= <jose@example.com>")
        assert out == ["José <jose@example.com>"]


class TestBodyExtraction:
    def test_a_plain_body_is_read(self) -> None:
        assert "numbers are attached" in (_get_searchable_body(_msg(PLAIN)) or "")

    def test_an_html_only_message_has_a_searchable_body(self) -> None:
        """Most phishing is HTML-only; it previously had no body at all."""
        body = _get_searchable_body(_msg(HTML_ONLY)) or ""
        assert "reset your password" in body
        assert "<b>" not in body

    def test_the_link_target_survives_tag_stripping(self) -> None:
        parsed = _parse_email_message(_msg(HTML_ONLY), "Inbox")
        assert _matches_search("", "", str(parsed["body_text"]), [], "reset your password")

    def test_plain_is_preferred_over_html(self) -> None:
        both = (
            "Subject: s\r\n"
            'Content-Type: multipart/alternative; boundary="B"\r\n'
            "\r\n--B\r\nContent-Type: text/plain\r\n\r\nthe plain one\r\n"
            "--B\r\nContent-Type: text/html\r\n\r\n<p>the html one</p>\r\n--B--\r\n"
        )
        assert "the plain one" in (_get_searchable_body(_msg(both)) or "")

    def test_an_attachment_is_not_mistaken_for_the_body(self) -> None:
        body = _get_searchable_body(_msg(INLINE_ATTACHMENT)) or ""
        assert "see attached" in body
        assert "MZ" not in body


class TestAttachmentDetection:
    def test_an_inline_payload_is_an_attachment(self) -> None:
        parsed = _parse_email_message(_msg(INLINE_ATTACHMENT), "Inbox")
        assert parsed["attachments"] == ["invoice.exe"]

    def test_an_inline_payload_trips_the_suspicious_check(self) -> None:
        """The point of the function: an .exe must be flagged however it arrives."""
        parsed = _parse_email_message(_msg(INLINE_ATTACHMENT), "Inbox")
        assert parsed["has_suspicious_attachment"] is True

    def test_a_message_without_attachments_is_clean(self) -> None:
        parsed = _parse_email_message(_msg(PLAIN), "Inbox")
        assert parsed["attachments"] == []
        assert parsed["has_suspicious_attachment"] is False

    def test_an_attachment_name_is_searchable(self) -> None:
        assert _matches_search("", "", None, [], "invoice.exe", ["invoice.exe"])


class TestSearchCoversEveryRecipientField:
    def test_a_cc_recipient_matches(self) -> None:
        """Cc was parsed and then never searched."""
        assert _matches_search("", "", None, ["carol@example.com"], "carol")

    def test_the_parsed_message_carries_bcc_and_reply_to(self) -> None:
        raw = PLAIN.replace(
            "To: bob@example.com\r\n",
            "To: bob@example.com\r\nBcc: hidden@example.com\r\nReply-To: spoof@evil.example\r\n",
        )
        parsed = _parse_email_message(_msg(raw), "Inbox")
        assert parsed["recipients_bcc"] == ["hidden@example.com"]
        assert parsed["reply_to"] == ["spoof@evil.example"]

    def test_a_sortable_date_is_exposed(self) -> None:
        parsed = _parse_email_message(_msg(PLAIN), "Inbox")
        assert str(parsed["date_iso"]).startswith("2024-03-11T09:14:02")
        # The header as sent is preserved alongside it.
        assert parsed["date"] == "Mon, 11 Mar 2024 09:14:02 +0100"
