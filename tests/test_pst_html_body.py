"""An HTML-only message must still have a searchable, indexable body.

``_parse_email_message`` set ``body_text`` from ``_get_body(msg, "text/plain")``
alone. Most phishing is sent as ``text/html`` only, so those messages had
``body_text: None``: a ``search_term`` naming a phrase in the body could never
match them, and none of their content reached the case DB.

``_get_body`` had a second defect -- for a multipart message it walked every
part including nested containers and attachments, and it raised ``LookupError``
outright on a charset the platform does not know, losing the body entirely.
"""

from __future__ import annotations

import email as email_lib
from pathlib import Path
from typing import Any

from mulder.server.tools.email import _parse_email_message, _parse_extracted_emails

_PHISH_HTML = (
    "<html><head><style>p{color:red}</style></head><body>"
    "<p>Please action this <b>wire&nbsp;transfer</b> today.</p>"
    "<script>var x=1;</script>"
    "</body></html>"
)


def _html_only_message() -> email_lib.message.Message:
    raw = (
        "From: attacker@example.com\n"
        "To: cfo@example.com\n"
        "Subject: Invoice\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n" + _PHISH_HTML + "\n"
    )
    return email_lib.message_from_string(raw)


def _write_html_only(folder: Path, name: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(
        "From: attacker@example.com\n"
        "To: cfo@example.com\n"
        "Subject: Invoice\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n" + _PHISH_HTML + "\n",
        encoding="utf-8",
    )


def test_an_html_only_message_has_a_body(tmp_path: Path) -> None:
    parsed = _parse_email_message(_html_only_message(), "Inbox")

    body = parsed["body_text"]
    assert body is not None, "an HTML-only message was left with no body at all"
    assert "wire transfer" in str(body)


def test_markup_is_stripped_not_indexed(tmp_path: Path) -> None:
    """Tags, scripts and styles are not evidence and must not reach the case."""
    parsed = _parse_email_message(_html_only_message(), "Inbox")
    body = str(parsed["body_text"])

    assert "<p>" not in body
    assert "var x=1" not in body
    assert "color:red" not in body


def test_a_keyword_search_finds_an_html_only_message(tmp_path: Path) -> None:
    """The forensic consequence: the message was invisible to search."""
    _write_html_only(tmp_path / "Inbox", "phish.eml")

    result: dict[str, Any] = _parse_extracted_emails(
        tmp_path, "/evidence/mail.pst", search_term="wire transfer"
    )

    assert result["total_emails"] == 1


def test_plain_text_still_wins_over_html(tmp_path: Path) -> None:
    """Narrowness: a multipart/alternative message keeps its text/plain part."""
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
        "the plain part\n"
        "--B\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<p>the html part</p>\n"
        "--B--\n"
    )
    parsed = _parse_email_message(email_lib.message_from_string(raw), "Inbox")

    assert str(parsed["body_text"]).strip() == "the plain part"


def test_a_text_attachment_is_not_mistaken_for_the_body() -> None:
    """An attached .txt is evidence, but it is not the message body."""
    raw = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: With attachment\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        'Content-Type: multipart/mixed; boundary="B"\n'
        "\n"
        "--B\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<p>real body</p>\n"
        "--B\n"
        "Content-Type: text/plain; charset=utf-8\n"
        'Content-Disposition: attachment; filename="notes.txt"\n'
        "\n"
        "attached notes\n"
        "--B--\n"
    )
    parsed = _parse_email_message(email_lib.message_from_string(raw), "Inbox")
    body = str(parsed["body_text"])

    assert "real body" in body
    assert "attached notes" not in body


def test_an_unknown_charset_does_not_lose_the_body() -> None:
    """``LookupError`` on an exotic charset previously discarded the body."""
    raw = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: Odd charset\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        "Content-Type: text/plain; charset=x-not-a-real-charset\n"
        "\n"
        "still readable\n"
    )
    parsed = _parse_email_message(email_lib.message_from_string(raw), "Inbox")

    assert "still readable" in str(parsed["body_text"])


def test_a_plain_text_message_is_unchanged(tmp_path: Path) -> None:
    """Narrowness: the ordinary case must behave exactly as before."""
    folder = tmp_path / "Inbox"
    folder.mkdir()
    (folder / "plain.eml").write_text(
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: Plain\n"
        "Date: Mon, 11 Mar 2024 09:14:02 +0100\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "hello world\n",
        encoding="utf-8",
    )

    result = _parse_extracted_emails(tmp_path, "/evidence/mail.pst")
    emails = result["emails"]
    assert isinstance(emails, list)

    assert str(emails[0]["body_text"]).strip() == "hello world"
