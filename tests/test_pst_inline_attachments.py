"""An attachment is anything carrying a filename, not only a declared one.

``_parse_email_message`` collected a part only when it declared
``Content-Disposition: attachment``. A payload delivered as ``inline``, or
with no disposition header at all, was therefore invisible -- it appeared in
neither ``attachments`` nor, more seriously, the ``has_suspicious_attachment``
check, which is the security purpose of that function.

Both shapes are ordinary: ``inline`` is what mail clients emit for anything
they might render, and a bare ``Content-Type`` with a ``name`` parameter is
what several older senders produce.
"""

from __future__ import annotations

import email as email_lib

from mulder.server.tools.email import _parse_email_message


def _message(disposition_header: str) -> email_lib.message.Message:
    """A two-part message whose second part carries an .exe filename."""
    raw = (
        "From: attacker@example.com\n"
        "To: victim@example.com\n"
        "Subject: Invoice\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        'Content-Type: multipart/mixed; boundary="B"\n'
        "\n"
        "--B\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "see attached\n"
        "--B\n"
        'Content-Type: application/octet-stream; name="invoice.exe"\n'
        f"{disposition_header}"
        "\n"
        "payload\n"
        "--B--\n"
    )
    return email_lib.message_from_string(raw)


def test_an_inline_payload_is_detected() -> None:
    """`inline` is the disposition a client uses for anything it may render."""
    parsed = _parse_email_message(_message("Content-Disposition: inline\n"), "Inbox")

    assert parsed["attachments"] == ["invoice.exe"]


def test_an_inline_payload_trips_the_suspicious_check() -> None:
    """The security consequence: the .exe check never saw the .exe."""
    parsed = _parse_email_message(_message("Content-Disposition: inline\n"), "Inbox")

    assert parsed["has_suspicious_attachment"] is True


def test_a_payload_with_no_disposition_header_is_detected() -> None:
    """A bare Content-Type with a name= parameter is still an attachment."""
    parsed = _parse_email_message(_message(""), "Inbox")

    assert parsed["attachments"] == ["invoice.exe"]
    assert parsed["has_suspicious_attachment"] is True


def test_a_declared_attachment_still_works() -> None:
    """Narrowness: the case that already worked is unchanged."""
    parsed = _parse_email_message(
        _message('Content-Disposition: attachment; filename="invoice.exe"\n'), "Inbox"
    )

    assert parsed["attachments"] == ["invoice.exe"]
    assert parsed["has_suspicious_attachment"] is True


def test_a_plain_message_has_no_attachments() -> None:
    """Narrowness: a body-only message must not gain a phantom attachment."""
    raw = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: Plain\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "hello\n"
    )
    parsed = _parse_email_message(email_lib.message_from_string(raw), "Inbox")

    assert parsed["attachments"] == []
    assert parsed["has_suspicious_attachment"] is False


def test_an_alternative_body_part_is_not_an_attachment() -> None:
    """Narrowness: multipart/alternative parts carry no filename, so neither
    the HTML nor the plain body may be counted as an attachment."""
    raw = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: Both\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        'Content-Type: multipart/alternative; boundary="B"\n'
        "\n"
        "--B\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "plain\n"
        "--B\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<p>html</p>\n"
        "--B--\n"
    )
    parsed = _parse_email_message(email_lib.message_from_string(raw), "Inbox")

    assert parsed["attachments"] == []


def test_a_benign_inline_image_is_listed_but_not_suspicious() -> None:
    """An inline image is a real attachment; it is not a suspicious one."""
    raw = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: Signature\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        'Content-Type: multipart/related; boundary="B"\n'
        "\n"
        "--B\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<p>hi</p>\n"
        "--B\n"
        'Content-Type: image/png; name="logo.png"\n'
        "Content-Disposition: inline\n"
        "\n"
        "binary\n"
        "--B--\n"
    )
    parsed = _parse_email_message(email_lib.message_from_string(raw), "Inbox")

    assert parsed["attachments"] == ["logo.png"]
    assert parsed["has_suspicious_attachment"] is False
