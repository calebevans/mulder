"""Email forensics MCP tools: PST/OST parsing via readpst."""

from __future__ import annotations

import email as email_lib
import email.parser
import logging
import subprocess
import tempfile
import time
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


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_recipients(raw: str) -> list[str]:
    """Parse a comma-separated recipient string into individual addresses.

    Args:
        raw: Raw To/CC header value.

    Returns:
        List of individual email addresses or display names.
    """
    if not raw:
        return []
    return [r.strip() for r in raw.split(",") if r.strip()]


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
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == content_type:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
    else:
        if msg.get_content_type() == content_type:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                charset = msg.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
    return None


def _matches_search(
    subject: str,
    sender: str,
    body: str | None,
    recipients: list[str],
    search_term: str,
) -> bool:
    """Check whether an email matches the search keyword.

    Args:
        subject: Email subject line.
        sender: Sender address.
        body: Plain text body (may be None).
        recipients: List of recipient addresses.
        search_term: Keyword to search for (case insensitive).

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
    return any(term in r.lower() for r in recipients)


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
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "unnamed"
            attachments.append(filename)
            ext = Path(filename).suffix.lower()
            if ext in _SUSPICIOUS_EXTENSIONS:
                has_suspicious = True

    return {
        "message_id": msg.get("Message-ID"),
        "subject": msg.get("Subject", "(no subject)"),
        "sender": msg.get("From", ""),
        "recipients_to": _parse_recipients(msg.get("To", "")),
        "recipients_cc": _parse_recipients(msg.get("Cc", "")),
        "date": msg.get("Date"),
        "body_text": _get_body(msg, "text/plain"),
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

        date_val = str(parsed.get("date") or "")
        if date_start and date_val and date_val < date_start:
            continue
        if date_end and date_val and date_val > date_end:
            continue

        if search_term:
            subject = str(parsed.get("subject", ""))
            sender = str(parsed.get("sender", ""))
            body_val = parsed.get("body_text")
            body_str = str(body_val) if body_val is not None else None
            to_val = parsed.get("recipients_to")
            to_list = [str(r) for r in to_val] if isinstance(to_val, list) else []
            if not _matches_search(subject, sender, body_str, to_list, search_term):
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
