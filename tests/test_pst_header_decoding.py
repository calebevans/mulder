"""RFC 2047 headers must be decoded before they are searched or reported.

``Subject`` and ``From`` were read straight off the message. A non-ASCII
header arrives encoded -- ``=?utf-8?B?V2lyZSB0cmFuc2ZlciByZXF1ZXN0?=`` -- so
the report showed base64 to the examiner and a keyword search for the words
it actually contains could never match.

Any sender can choose this encoding for a pure-ASCII subject, so it is also
a trivial way to hide a subject line from a keyword search.
"""

from __future__ import annotations

import email as email_lib
from base64 import b64encode
from pathlib import Path
from typing import Any

from mulder.server.tools.email import _parse_email_message, _parse_extracted_emails


def _encoded(text: str) -> str:
    return "=?utf-8?B?" + b64encode(text.encode("utf-8")).decode("ascii") + "?="


def _message(subject: str, sender: str) -> email_lib.message.Message:
    raw = (
        f"From: {sender}\n"
        "To: cfo@example.com\n"
        f"Subject: {subject}\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "body\n"
    )
    return email_lib.message_from_string(raw)


def test_an_encoded_subject_is_decoded() -> None:
    parsed = _parse_email_message(
        _message(_encoded("Wire transfer request"), "a@example.com"), "Inbox"
    )

    assert parsed["subject"] == "Wire transfer request"


def test_an_encoded_sender_name_is_decoded() -> None:
    parsed = _parse_email_message(
        _message("Plain", f"{_encoded('Ünter Müller')} <u@example.com>"), "Inbox"
    )

    assert "Ünter Müller" in str(parsed["sender"])


def test_a_keyword_search_finds_an_encoded_subject(tmp_path: Path) -> None:
    """The forensic consequence: the subject was unsearchable."""
    folder = tmp_path / "Inbox"
    folder.mkdir()
    (folder / "m.eml").write_text(
        "From: attacker@example.com\n"
        "To: cfo@example.com\n"
        f"Subject: {_encoded('Wire transfer request')}\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "body\n",
        encoding="utf-8",
    )

    result: dict[str, Any] = _parse_extracted_emails(
        tmp_path, "/evidence/mail.pst", search_term="wire transfer"
    )

    assert result["total_emails"] == 1


def test_a_plain_subject_is_unchanged() -> None:
    """Narrowness: an ASCII subject must pass through untouched."""
    parsed = _parse_email_message(_message("Quarterly report", "a@example.com"), "Inbox")

    assert parsed["subject"] == "Quarterly report"


def test_a_missing_subject_still_reads_no_subject() -> None:
    """Narrowness: the existing placeholder is preserved."""
    raw = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "body\n"
    )
    parsed = _parse_email_message(email_lib.message_from_string(raw), "Inbox")

    assert parsed["subject"] == "(no subject)"


def test_an_undecodable_header_falls_back_to_the_raw_value() -> None:
    """A malformed encoded-word must not lose the header entirely."""
    parsed = _parse_email_message(
        _message("=?utf-8?B?!!!not-base64!!!?=", "a@example.com"), "Inbox"
    )

    assert str(parsed["subject"]).strip() != ""
