"""Email forensics MCP tools: PST/OST parsing via readpst."""

from __future__ import annotations

import email as email_lib
import email.parser
import logging
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    require_binary,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "parse_pst",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_READPST_TIMEOUT = 600
_READPST_BINARY = "/usr/bin/readpst"

_SUSPICIOUS_EXTENSIONS: set[str] = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".wsf",
    ".hta",
    ".lnk",
    ".pif",
    ".msi",
    ".jar",
    ".com",
}

_VALID_PST_SUFFIXES: set[str] = {".pst", ".ost"}

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTML_WS_RE = re.compile(r"[ \t]*\n[ \t]*")


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _decode_header_value(raw: str | None) -> str:
    """Decode an RFC 2047 header into text.

    Subjects and display names arrive as ``=?utf-8?B?...?=``. Reading them
    raw means a keyword search for "wire transfer" cannot match a subject
    that says "wire transfer", and the report shows base64.
    """
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except (UnicodeDecodeError, LookupError, ValueError):
        return raw


def _parse_recipients(raw: str) -> list[str]:
    """Parse a To/Cc header into individual addresses.

    Splitting on "," is wrong: a display name may legitimately contain one.
    ``"Doe, John" <john@example.com>, jane@example.com`` split that way
    yields ``'"Doe'``, ``'John" <john@example.com>'`` and
    ``'jane@example.com'`` -- two of the three are not addresses at all, so
    recipient search and address IOC extraction both miss them.

    Args:
        raw: Raw To/CC header value.

    Returns:
        One entry per recipient, ``Display Name <addr>`` when a name is
        present and the bare address otherwise.
    """
    if not raw:
        return []
    out: list[str] = []
    for name, addr in getaddresses([raw]):
        display = _decode_header_value(name)
        if addr and display:
            out.append(f"{display} <{addr}>")
        elif addr:
            out.append(addr)
        elif display:
            out.append(display)
    return out


def _recipient_addresses(recipients: list[str]) -> list[str]:
    """The bare addresses out of ``_parse_recipients`` output."""
    return [addr for _name, addr in getaddresses(recipients) if addr]


def _get_body(
    msg: email_lib.message.Message,
    content_type: str,
) -> str | None:
    """Extract the first body part matching the given content type.

    Args:
        msg: Parsed email message.
        content_type: MIME type to match (e.g. "text/plain").

    Returns:
        Body text or None if no matching part found.
    """
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() != content_type:
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="replace")
            except LookupError:
                return payload.decode("utf-8", errors="replace")
    return None


def _html_to_text(html: str) -> str:
    """Strip tags from an HTML body so its words are searchable."""
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    text = _HTML_TAG_RE.sub(" ", text)
    for entity, char in (
        ("&nbsp;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", '"'),
        ("&#39;", "'"),
    ):
        text = text.replace(entity, char)
    return _HTML_WS_RE.sub("\n", text).strip()


def _get_searchable_body(msg: email_lib.message.Message) -> str | None:
    """The message body as text, whatever it was sent as.

    ``text/plain`` when present, otherwise ``text/html`` with the tags
    stripped. An HTML-only message -- most phishing -- previously had no
    body at all, so no keyword could match it and nothing was indexed.
    """
    plain = _get_body(msg, "text/plain")
    if plain and plain.strip():
        return plain
    html = _get_body(msg, "text/html")
    if html and html.strip():
        return _html_to_text(html)
    return plain or html


def _message_date(raw: str | None) -> datetime | None:
    """Parse an RFC 5322 ``Date`` header into an aware datetime."""
    if not raw:
        return None
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _in_date_range(raw: str | None, start: str | None, end: str | None) -> bool:
    """Whether a message's ``Date`` falls within an inclusive YYYY-MM-DD range.

    The header is RFC 5322 -- ``Mon, 11 Mar 2024 09:14:02 +0100`` -- and was
    previously compared to the bounds as a string. ``"Mon, ..." > "2024-12-31"``
    is true for every message ever sent, because ``M`` sorts above any digit,
    so ``date_end`` discarded the entire mailbox and ``date_start`` discarded
    nothing. Any date-bounded search returned zero results.

    A message whose date is missing or unparseable is kept, so a malformed
    header cannot silently hide evidence.
    """
    if not start and not end:
        return True
    when = _message_date(raw)
    if when is None:
        return True
    day = when.date()
    if start:
        try:
            if day < datetime.strptime(start, "%Y-%m-%d").date():
                return False
        except ValueError:
            pass
    if end:
        try:
            if day > datetime.strptime(end, "%Y-%m-%d").date():
                return False
        except ValueError:
            pass
    return True


def _matches_search(
    subject: str,
    sender: str,
    body: str | None,
    recipients: list[str],
    search_term: str,
    attachments: list[str] | None = None,
) -> bool:
    """Check whether an email matches the search keyword.

    Args:
        subject: Email subject line, already RFC 2047 decoded.
        sender: Sender address.
        body: Body text (may be None).
        recipients: Every recipient -- To *and* Cc. Cc was parsed and then
            never searched, so a search naming a copied recipient missed
            the message.
        search_term: Keyword to search for (case insensitive).
        attachments: Attachment filenames, which is how an analyst looks
            for a named payload.

    Returns:
        True if the term appears in any searchable field.
    """
    term = search_term.lower()
    if term in subject.lower():
        return True
    if term in sender.lower():
        return True
    if body and term in body.lower():
        return True
    if any(term in r.lower() for r in recipients):
        return True
    return any(term in a.lower() for a in attachments or [])


def _parse_email_message(
    msg: email_lib.message.Message,
    folder: str,
) -> dict[str, object]:
    """Parse a single email.message.Message into structured form.

    Args:
        msg: Parsed email message object.
        folder: Folder name this message belongs to.

    Returns:
        Dict with extracted email fields.
    """
    attachments: list[str] = []
    has_suspicious = False

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        # An attachment is anything carrying a filename, not only what
        # declares `Content-Disposition: attachment`. Malicious payloads
        # arrive as `inline` or with no disposition header at all, and both
        # were previously invisible -- including to the suspicious-extension
        # check, which is the point of this function.
        if disposition == "attachment" or filename:
            name = _decode_header_value(filename) or "unnamed"
            attachments.append(name)
            if Path(name).suffix.lower() in _SUSPICIOUS_EXTENSIONS:
                has_suspicious = True

    when = _message_date(msg.get("Date"))

    return {
        "message_id": msg.get("Message-ID"),
        "subject": _decode_header_value(msg.get("Subject")) or "(no subject)",
        "sender": _decode_header_value(msg.get("From")),
        "recipients_to": _parse_recipients(msg.get("To", "")),
        "recipients_cc": _parse_recipients(msg.get("Cc", "")),
        "recipients_bcc": _parse_recipients(msg.get("Bcc", "")),
        "reply_to": _parse_recipients(msg.get("Reply-To", "")),
        "date": msg.get("Date"),
        # A sortable, comparable form alongside the header as sent.
        "date_iso": when.isoformat() if when else None,
        "body_text": _get_searchable_body(msg),
        "attachments": attachments,
        "folder": folder,
        "importance": msg.get("Importance", "normal"),
        "has_suspicious_attachment": has_suspicious,
    }


def _parse_extracted_emails(
    output_dir: Path,
    file_path: str,
    date_start: str | None = None,
    date_end: str | None = None,
    search_term: str | None = None,
) -> dict[str, object]:
    """Parse extracted .eml files into structured results.

    Walks the readpst output directory, parses each .eml file,
    applies date and keyword filters, and identifies suspicious
    messages.

    Args:
        output_dir: Directory containing extracted .eml files.
        file_path: Original PST file path for reference.
        date_start: Optional start date filter (YYYY-MM-DD).
        date_end: Optional end date filter (YYYY-MM-DD).
        search_term: Optional keyword filter.

    Returns:
        Dict with filtered and categorized messages.
    """
    emails: list[dict[str, object]] = []
    folder_structure: dict[str, int] = {}
    attachment_paths: list[str] = []
    suspicious_findings: list[str] = []

    parser = email.parser.Parser()

    for eml_file in sorted(output_dir.rglob("*.eml")):
        folder = eml_file.parent.name
        folder_structure[folder] = folder_structure.get(folder, 0) + 1

        try:
            with open(eml_file, encoding="utf-8", errors="replace") as f:
                msg = parser.parse(f)
        except OSError:
            logger.warning("Failed to read .eml file: %s", eml_file)
            continue

        parsed = _parse_email_message(msg, folder)

        if not _in_date_range(str(parsed.get("date") or ""), date_start, date_end):
            continue

        if search_term:
            subject = str(parsed.get("subject", ""))
            sender = str(parsed.get("sender", ""))
            body_val = parsed.get("body_text")
            body_str = str(body_val) if body_val is not None else None
            recipients: list[str] = []
            for key in ("recipients_to", "recipients_cc", "recipients_bcc"):
                val = parsed.get(key)
                if isinstance(val, list):
                    recipients.extend(str(r) for r in val)
            att_names = parsed.get("attachments")
            att_list = [str(a) for a in att_names] if isinstance(att_names, list) else []
            if not _matches_search(subject, sender, body_str, recipients, search_term, att_list):
                continue

        if parsed.get("has_suspicious_attachment"):
            suspicious_findings.append(
                f"Suspicious attachment in: {parsed.get('subject', '(unknown)')}"
            )

        att_val = parsed.get("attachments")
        if isinstance(att_val, list):
            attachment_paths.extend(str(a) for a in att_val)

        emails.append(parsed)

    return {
        "file_path": file_path,
        "total_emails": len(emails),
        "total_attachments": len(attachment_paths),
        "folder_structure": folder_structure,
        "emails": emails,
        "attachment_paths": attachment_paths,
        "date_range": [date_start, date_end],
        "suspicious_findings": suspicious_findings,
    }


# ---------------------------------------------------------------------------
# MCP Tool: parse_pst
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def parse_pst(
    case_id: str,
    file_path: str,
    extract_attachments: bool = True,
    date_range_start: str | None = None,
    date_range_end: str | None = None,
    search_term: str | None = None,
) -> dict[str, object]:
    """Parse Outlook PST/OST files for forensic email analysis.

    Extracts emails, contacts, calendar items, and attachments from
    Microsoft Outlook data files. Supports filtering by date range
    and keyword search across message content.

    Args:
        case_id: Active case identifier.
        file_path: Absolute path to the PST or OST file.
        extract_attachments: Whether to extract file attachments
            to disk for further analysis.
        date_range_start: Optional ISO 8601 date to filter emails
            (inclusive start). Format: "YYYY-MM-DD".
        date_range_end: Optional ISO 8601 date to filter emails
            (inclusive end). Format: "YYYY-MM-DD".
        search_term: Optional keyword to filter messages. Matches
            against subject, body, sender, and recipient fields.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "case_id": case_id,
        "file_path": file_path,
        "extract_attachments": extract_attachments,
        "date_range_start": date_range_start,
        "date_range_end": date_range_end,
        "search_term": search_term,
    }

    readpst = require_binary("readpst")
    if not readpst and not Path(_READPST_BINARY).exists():
        return error_response(
            tc_id,
            "parse_pst",
            params,
            "readpst not found on PATH",
            error_type="binary_missing",
            suggestion="Install pst-utils: apt-get install pst-utils",
        )
    readpst_bin = readpst or _READPST_BINARY

    target = Path(file_path)
    if not target.exists():
        return error_response(
            tc_id,
            "parse_pst",
            params,
            f"File not found: {file_path}",
            error_type="file_not_found",
        )

    if target.suffix.lower() not in _VALID_PST_SUFFIXES:
        return error_response(
            tc_id,
            "parse_pst",
            params,
            f"Expected .pst or .ost file, got: {target.suffix}",
            error_type="invalid_input",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_pst_") as tmpdir:
        output_dir = Path(tmpdir)
        cmd = [
            readpst_bin,
            "-e",
            "-D",
            "-b",
            "-o",
            str(output_dir),
        ]
        if extract_attachments:
            cmd.append("-S")

        cmd.append(str(target))

        pst_timeout = adaptive_timeout(file_path, base=_READPST_TIMEOUT)
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=pst_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "parse_pst",
                params,
                f"readpst timed out after {pst_timeout}s (large PST file?)",
                (time.monotonic() - t0) * 1000,
                error_type="timeout",
            )
        except OSError as exc:
            return error_response(
                tc_id,
                "parse_pst",
                params,
                f"Failed to execute readpst: {exc}",
                (time.monotonic() - t0) * 1000,
            )

        result = _parse_extracted_emails(
            output_dir,
            file_path,
            date_start=date_range_start,
            date_end=date_range_end,
            search_term=search_term,
        )

    index_parts: list[str] = [f"PST Analysis: {file_path}"]
    email_list = result.get("emails")
    if isinstance(email_list, list):
        for em in email_list:
            if isinstance(em, dict):
                index_parts.append(
                    f"From: {em.get('sender', '')} | "
                    f"Subject: {em.get('subject', '')} | "
                    f"Date: {em.get('date', '')}"
                )
    index_text = "\n".join(index_parts)

    summary = extract_and_index(index_text, "pst.emails", file_path, "readpst")
    summary.update(result)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "parse_pst", params, summary, "pst.emails", elapsed)
