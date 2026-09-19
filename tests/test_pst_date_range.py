"""A date-bounded PST search must not discard the entire mailbox.

``_parse_extracted_emails`` compared the RFC 5322 ``Date`` header against the
``YYYY-MM-DD`` bounds as a plain string::

    if date_end and date_val and date_val > date_end:
        continue

``"Mon, 11 Mar 2024 09:14:02 +0100" > "2024-12-31"`` is ``True`` -- ``M`` (77)
sorts above every digit (48-57) -- and every RFC 5322 date begins with a
weekday name. So ``date_range_end`` dropped every message ever sent, and
``date_range_start`` dropped none, in both cases silently.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mulder.server.tools.email import _parse_extracted_emails

_MESSAGES = {
    "2019.eml": "Tue, 15 Jan 2019 09:14:02 +0000",
    "2022.eml": "Wed, 11 May 2022 17:02:41 +0200",
    "2024.eml": "Mon, 11 Mar 2024 09:14:02 +0100",
}


def _write(path: Path, date_header: str, subject: str) -> None:
    path.write_text(
        "From: sender@example.com\n"
        "To: recipient@example.com\n"
        f"Subject: {subject}\n"
        f"Date: {date_header}\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "body text\n",
        encoding="utf-8",
    )


@pytest.fixture
def mailbox(tmp_path: Path) -> Path:
    """Three messages, one per year, in a readpst-style output tree."""
    folder = tmp_path / "Inbox"
    folder.mkdir()
    for name, header in _MESSAGES.items():
        _write(folder / name, header, name.removesuffix(".eml"))
    return tmp_path


def _subjects(result: dict[str, Any]) -> list[str]:
    emails = result["emails"]
    assert isinstance(emails, list)
    return sorted(str(e["subject"]) for e in emails)


def test_an_end_bound_does_not_discard_the_whole_mailbox(mailbox: Path) -> None:
    """The headline failure: every RFC 5322 date sorts above every ISO bound."""
    result = _parse_extracted_emails(mailbox, "/evidence/mail.pst", date_end="2024-12-31")

    assert _subjects(result) == ["2019", "2022", "2024"]
    assert result["total_emails"] == 3


def test_an_end_bound_still_excludes_later_messages(mailbox: Path) -> None:
    """Pins that the filter is fixed, not merely disabled."""
    result = _parse_extracted_emails(mailbox, "/evidence/mail.pst", date_end="2022-12-31")

    assert _subjects(result) == ["2019", "2022"]


def test_a_start_bound_actually_filters(mailbox: Path) -> None:
    """``date_start`` previously excluded nothing at all."""
    result = _parse_extracted_emails(mailbox, "/evidence/mail.pst", date_start="2022-01-01")

    assert _subjects(result) == ["2022", "2024"]


def test_both_bounds_select_the_middle_message(mailbox: Path) -> None:
    result = _parse_extracted_emails(
        mailbox,
        "/evidence/mail.pst",
        date_start="2022-01-01",
        date_end="2022-12-31",
    )

    assert _subjects(result) == ["2022"]


def test_an_unparseable_date_is_kept_not_hidden(tmp_path: Path) -> None:
    """A malformed header must not silently remove evidence from the case.

    Excluding it would let a forged or broken ``Date`` hide a message from
    every date-bounded search, which is the opposite of what an examiner needs.
    """
    folder = tmp_path / "Inbox"
    folder.mkdir()
    _write(folder / "broken.eml", "not a date at all", "malformed")

    result = _parse_extracted_emails(tmp_path, "/evidence/mail.pst", date_end="2024-12-31")

    assert _subjects(result) == ["malformed"]


def test_no_bounds_returns_everything(mailbox: Path) -> None:
    """Narrowness: with no date filter the fix changes nothing."""
    result = _parse_extracted_emails(mailbox, "/evidence/mail.pst")

    assert _subjects(result) == ["2019", "2022", "2024"]
