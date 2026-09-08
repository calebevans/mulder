"""``analyze_pdf`` advertised URL and embedded-file extraction it never did.

The tool signature accepts ``extract_urls`` and ``extract_embedded``, the
docstring documents them ("Whether to extract URLs from the PDF", "Whether to
list embedded files and streams"), and both are echoed into the audited
``params``. But the result was built as::

    summary["urls"] = []
    summary["embedded_files"] = []

with no code path anywhere that populated either. A PDF carrying a link to an
attacker-controlled host and an embedded ``evil.exe`` came back reporting no
URLs and no embedded files -- and because nothing was produced, nothing was
indexed either, so ``search()`` over the case could never surface them.

These tests drive the public ``analyze_pdf`` entry point and stub the wrapped
tools at ``subprocess.run``, so they exercise observable output rather than
private helpers. The fixture below is verbatim stdout from pdf-parser 0.7.11
run against a minimal PDF built for this test: one ``/URI`` link action and
one ``/Filespec`` naming ``evil.exe``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.documents import analyze_pdf

# Verbatim pdf-parser 0.7.11 output for the crafted PDF.
REAL_PARSER_DUMP = """\
PDF Comment '%PDF-1.4\\n'

obj 1 0
 Type: /Catalog
 Referencing: 2 0 R, 6 0 R

  <<
    /Type /Catalog
    /Pages 2 0 R
    /Names
      <<
        /EmbeddedFiles 6 0 R
      >>
  >>


obj 4 0
 Type: /Annot
 Referencing: 5 0 R

  <<
    /Type /Annot
    /Subtype /Link
    /A 5 0 R
  >>


obj 5 0
 Type: /Action
 Referencing:

  <<
    /Type /Action
    /S /URI
    /URI (http://malicious.example.com/payload)
  >>


obj 6 0
 Type:
 Referencing: 7 0 R

  <<
    /Names [(evil.exe) 7 0 R]
  >>


obj 7 0
 Type: /Filespec
 Referencing: 8 0 R

  <<
    /Type /Filespec
    /F (evil.exe)
    /UF (evil.exe)
    /EF
      <<
        /F 8 0 R
      >>
  >>


obj 8 0
 Type: /EmbeddedFile
 Referencing:
 Contains stream

  <<
    /Type /EmbeddedFile
    /Length 4
  >>


PDF Comment '%%EOF\\n'
"""

# A clean one-page document: no actions, no attachments.
BENIGN_PARSER_DUMP = """\
PDF Comment '%PDF-1.4\\n'

obj 1 0
 Type: /Catalog
 Referencing: 2 0 R

  <<
    /Type /Catalog
    /Pages 2 0 R
  >>


obj 3 0
 Type: /Page
 Referencing: 2 0 R

  <<
    /Type /Page
    /Parent 2 0 R
  >>


PDF Comment '%%EOF\\n'
"""


@pytest.fixture
def pdf(tmp_path: Path) -> Path:
    """A file that passes analyze_pdf's existence and extension checks."""
    target = tmp_path / "invoice.pdf"
    target.write_bytes(b"%PDF-1.4\n%%EOF\n")
    return target


def _analyze(pdf: Path, dump: str, **kwargs: Any) -> tuple[dict[str, Any], str]:
    """Run analyze_pdf with pdf-parser stubbed at the subprocess boundary.

    ``_run_pdfid`` is stubbed to report no indicators, so the JavaScript
    extractor stays gated off and every remaining subprocess call is
    pdf-parser. Returns the response and the text handed to the indexer.
    """
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kw: object) -> dict[str, object]:
        indexed.append(raw)
        return {}

    def _fake_run(*args: object, **kw: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=dump, stderr="")

    with (
        patch("mulder.server.tools.documents._pdfid_script", return_value=Path("pdfid.py")),
        patch("mulder.server.tools.documents._pdf_parser_script", return_value=Path("pp.py")),
        patch("mulder.server.tools.documents._run_pdfid", return_value=[]),
        patch("mulder.server.tools.documents.subprocess.run", side_effect=_fake_run),
        patch("mulder.server.tools.documents.extract_and_index", side_effect=_record),
    ):
        result = analyze_pdf.__wrapped__(  # type: ignore[attr-defined]
            "case-1", str(pdf), **kwargs
        )
    return result, "\n".join(indexed)


def test_a_uri_link_action_reaches_the_analyst(pdf: Path) -> None:
    """The link a reader would follow must appear in the report."""
    result, indexed = _analyze(pdf, REAL_PARSER_DUMP)

    assert result["status"] == "success"
    assert "http://malicious.example.com/payload" in str(result["preview"])
    # analyze_pdf sets `source`, so tool_response returns a compact preview and
    # the case DB is how this is reached later -- it must be indexed too.
    assert "http://malicious.example.com/payload" in indexed


def test_an_embedded_executable_reaches_the_analyst(pdf: Path) -> None:
    result, indexed = _analyze(pdf, REAL_PARSER_DUMP)

    assert "evil.exe" in str(result["preview"])
    assert "evil.exe" in indexed


def test_an_embedded_executable_is_flagged_suspicious(pdf: Path) -> None:
    """Listing an attachment is not enough; an .exe must be marked."""
    result, _indexed = _analyze(pdf, REAL_PARSER_DUMP)

    preview = str(result["preview"])
    assert '"filename": "evil.exe"' in preview
    assert '"suspicious": true' in preview


def test_the_same_attachment_is_not_reported_twice(pdf: Path) -> None:
    """/F and /UF both name the attachment; it is one file, not two."""
    _result, indexed = _analyze(pdf, REAL_PARSER_DUMP)

    assert indexed.count("Embedded file in object 7: evil.exe") == 1


def test_a_benign_document_yields_no_urls_or_attachments(pdf: Path) -> None:
    """Pins the fix's narrowness: no false positives on a clean PDF.

    A detector that flags ordinary documents is as useless as one that misses
    malicious ones.
    """
    _result, indexed = _analyze(pdf, BENIGN_PARSER_DUMP)

    assert "URL in object" not in indexed
    assert "Embedded file in object" not in indexed


def test_a_harmless_attachment_is_reported_but_not_flagged(pdf: Path) -> None:
    """An embedded .txt is still listed, just not marked suspicious."""
    dump = REAL_PARSER_DUMP.replace("evil.exe", "notes.txt")
    result, indexed = _analyze(pdf, dump)

    assert "notes.txt" in indexed
    assert '"suspicious": false' in str(result["preview"])


def test_the_parameters_still_switch_the_work_off(pdf: Path) -> None:
    """extract_urls / extract_embedded must remain honest in both directions.

    They were previously ignored; having implemented them, passing False must
    actually suppress the work rather than merely blanking the result.
    """
    _result, indexed = _analyze(pdf, REAL_PARSER_DUMP, extract_urls=False, extract_embedded=False)

    assert "malicious.example.com" not in indexed
    assert "evil.exe" not in indexed
