"""A PST keyword search must look at every field it parses.

``_parse_extracted_emails`` parsed ``Cc`` into ``recipients_cc`` and then
passed only ``recipients_to`` to ``_matches_search``. Searching for an address
that was copied rather than addressed silently returned nothing, even though
the parser had the address in hand.

Attachment filenames were likewise collected and never searched, so looking
for a named payload -- ``invoice.exe`` -- found no message that carried it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mulder.server.tools.email import _parse_extracted_emails


def _write(folder: Path, name: str, *, cc: str = "", attachment: str = "") -> None:
    folder.mkdir(parents=True, exist_ok=True)
    headers = [
        "From: sender@example.com",
        "To: recipient@example.com",
        f"Subject: {name.removesuffix('.eml')}",
        "Date: Mon, 11 Mar 2024 09:14:02 +0100",
    ]
    if cc:
        headers.append(f"Cc: {cc}")

    if attachment:
        headers.append('Content-Type: multipart/mixed; boundary="B"')
        body = (
            "\n--B\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "see attached\n"
            "--B\n"
            "Content-Type: application/octet-stream\n"
            f'Content-Disposition: attachment; filename="{attachment}"\n'
            "\n"
            "payload\n"
            "--B--\n"
        )
    else:
        headers.append("Content-Type: text/plain; charset=utf-8")
        body = "\nordinary body\n"

    (folder / name).write_text("\n".join(headers) + "\n" + body, encoding="utf-8")


@pytest.fixture
def mailbox(tmp_path: Path) -> Path:
    folder = tmp_path / "Inbox"
    _write(folder, "copied.eml", cc="legal@example.com")
    _write(folder, "payload.eml", attachment="invoice.exe")
    _write(folder, "plain.eml")
    return tmp_path


def _subjects(result: dict[str, Any]) -> list[str]:
    emails = result["emails"]
    assert isinstance(emails, list)
    return sorted(str(e["subject"]) for e in emails)


def test_a_copied_recipient_is_searchable(mailbox: Path) -> None:
    """``Cc`` was parsed into the result and then never searched."""
    result = _parse_extracted_emails(
        mailbox, "/evidence/mail.pst", search_term="legal@example.com"
    )

    assert _subjects(result) == ["copied"]


def test_an_attachment_name_is_searchable(mailbox: Path) -> None:
    """Looking for a named payload is how an analyst pivots on one."""
    result = _parse_extracted_emails(mailbox, "/evidence/mail.pst", search_term="invoice.exe")

    assert _subjects(result) == ["payload"]


def test_an_addressed_recipient_still_matches(mailbox: Path) -> None:
    """Narrowness: the To field kept working."""
    result = _parse_extracted_emails(
        mailbox, "/evidence/mail.pst", search_term="recipient@example.com"
    )

    assert _subjects(result) == ["copied", "payload", "plain"]


def test_the_subject_still_matches(mailbox: Path) -> None:
    """Narrowness: subject search is unchanged."""
    result = _parse_extracted_emails(mailbox, "/evidence/mail.pst", search_term="plain")

    assert _subjects(result) == ["plain"]


def test_a_term_matching_nothing_still_matches_nothing(mailbox: Path) -> None:
    """Narrowness: widening the search must not make it match everything."""
    result = _parse_extracted_emails(
        mailbox, "/evidence/mail.pst", search_term="no-such-term-anywhere"
    )

    assert _subjects(result) == []


def test_no_search_term_returns_everything(mailbox: Path) -> None:
    """Narrowness: unfiltered behaviour is untouched."""
    result = _parse_extracted_emails(mailbox, "/evidence/mail.pst")

    assert _subjects(result) == ["copied", "payload", "plain"]
