"""The PDF analyser was defeated by the evasion it exists to detect.

``pdfid`` reports hex-obfuscated keyword occurrences as ``total(obfuscated)``::

     /JS                    2(1)
     /JavaScript            2(1)

``int("2(1)")`` raises, and the count parser turned that into ``0``. A PDF
that writes ``/J#61vaScript`` instead of ``/JavaScript`` -- which is the
entire point of the technique -- was therefore reported as containing **no**
JavaScript at all, and the obfuscation itself, a strong signal on its own,
was never surfaced.

Separately, ``analyze_pdf`` accepted ``extract_urls`` and ``extract_embedded``,
echoed both into the audited parameters and documented them, then returned
hardcoded empty lists.

The pdfid fixtures below are verbatim output from pdfid 0.2.10.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

import mulder.server.tools.documents as doc
from mulder.server.tools.documents import (
    _extract_pdf_embedded_files,
    _extract_pdf_urls,
    _extract_pdfid_count,
    _parse_pdfid_obfuscated_count,
    _run_pdfid,
)

# Verbatim `pdfid.py evil.pdf` output, where evil.pdf carries one plain and
# one hex-obfuscated JavaScript action.
PDFID_OBFUSCATED = """PDFiD 0.2.10 evil.pdf
 PDF Header: %PDF-1.4
 obj                    5
 endobj                 5
 stream                 0
 endstream              0
 xref                   0
 trailer                1
 startxref              1
 /Page                  1
 /Encrypt               0
 /ObjStm                0
 /JS                    2(1)
 /JavaScript            2(1)
 /AA                    0
 /OpenAction            1
 /AcroForm              0
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          0
 /XFA                   0
 /Colors > 2^24         0
"""


class TestPdfidCountParsing:
    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            (" /JS                    2(1)", 2),
            (" /JavaScript            2(1)", 2),
            (" /OpenAction            1", 1),
            (" /Launch                0", 0),
            (" /EmbeddedFile          17(17)", 17),
            (" /AA                    0(0)", 0),
        ],
    )
    def test_counts(self, line: str, expected: int) -> None:
        assert _extract_pdfid_count(line) == expected

    def test_the_old_parser_returned_zero_for_the_obfuscated_form(self) -> None:
        """Pins the premise: this is what int() did with '2(1)'."""
        with pytest.raises(ValueError):
            int("2(1)")

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            (" /JS                    2(1)", 1),
            (" /JavaScript            5(3)", 3),
            (" /OpenAction            1", 0),
            (" /Launch                0", 0),
        ],
    )
    def test_obfuscated_counts(self, line: str, expected: int) -> None:
        assert _parse_pdfid_obfuscated_count(line) == expected

    def test_a_malformed_line_is_zero(self) -> None:
        assert _extract_pdfid_count("garbage") == 0
        assert _parse_pdfid_obfuscated_count("garbage") == 0


class TestObfuscatedJavaScriptIsReported:
    @staticmethod
    def _indicators(output: str) -> list[dict[str, object]]:
        import subprocess

        from mulder.server.tools import documents as doc

        proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")
        with (
            patch.object(doc, "_pdfid_script", return_value=Path("/fake/pdfid.py")),
            patch.object(doc.subprocess, "run", return_value=proc),
        ):
            return _run_pdfid(Path("/evidence/evil.pdf"))

    def test_the_javascript_is_no_longer_invisible(self) -> None:
        """On main this keyword produced no indicator at all."""
        found = {i["keyword"]: i for i in self._indicators(PDFID_OBFUSCATED)}
        assert "/JavaScript" in found
        assert found["/JavaScript"]["count"] == 2

    def test_the_obfuscation_is_reported_as_its_own_signal(self) -> None:
        found = {i["keyword"]: i for i in self._indicators(PDFID_OBFUSCATED)}
        assert found["/JS"]["obfuscated_count"] == 1
        assert found["/JS"]["risk_level"] == "high"
        assert "evasion" in str(found["/JS"]["description"])

    def test_an_unobfuscated_keyword_carries_no_such_flag(self) -> None:
        found = {i["keyword"]: i for i in self._indicators(PDFID_OBFUSCATED)}
        assert "obfuscated_count" not in found["/OpenAction"]

    def test_zero_counts_produce_no_indicator(self) -> None:
        found = {i["keyword"] for i in self._indicators(PDFID_OBFUSCATED)}
        assert "/Launch" not in found
        assert "/JBIG2Decode" not in found


# pdf-parser object dumps, in the shape pdf-parser.py --raw emits.
URI_DUMP = """obj 5 0
 Type: /Action
 Referencing:

  << /Type /Action /S /URI /URI (http://evil.example/payload) >>

"""

FILESPEC_DUMP = """obj 8 0
 Type: /Filespec
 Referencing: 9 0 R

  << /Type /Filespec /F (dropper.exe) /UF (dropper.exe) /EF << /F 9 0 R >> >>

"""


class TestUrlExtraction:
    @staticmethod
    def _urls(dump: str) -> list[dict[str, object]]:
        from mulder.server.tools import documents as doc

        with patch.object(doc, "_run_pdf_parser", return_value=dump):
            return _extract_pdf_urls(Path("/evidence/x.pdf"))

    def test_a_uri_action_is_found(self) -> None:
        """The way a PDF reaches a phishing page with no JavaScript at all."""
        urls = {u["url"] for u in self._urls(URI_DUMP)}
        assert "http://evil.example/payload" in urls

    def test_a_url_is_reported_once(self) -> None:
        assert len(self._urls(URI_DUMP)) == 1

    def test_no_urls_in_a_clean_dump(self) -> None:
        assert self._urls("obj 1 0\n << /Type /Catalog >>\n") == []


class TestEmbeddedFileExtraction:
    @staticmethod
    def _files(dump: str) -> list[dict[str, object]]:
        from mulder.server.tools import documents as doc

        with patch.object(doc, "_run_pdf_parser", return_value=dump):
            return _extract_pdf_embedded_files(Path("/evidence/x.pdf"))

    def test_an_embedded_executable_is_listed(self) -> None:
        files = self._files(FILESPEC_DUMP)
        assert [f["filename"] for f in files] == ["dropper.exe"]

    def test_an_embedded_executable_is_flagged(self) -> None:
        assert self._files(FILESPEC_DUMP)[0]["suspicious"] is True

    def test_a_benign_attachment_is_not_flagged(self) -> None:
        dump = FILESPEC_DUMP.replace("dropper.exe", "report.pdf")
        assert "suspicious" not in self._files(dump)[0]

    def test_nothing_embedded(self) -> None:
        assert self._files("obj 1 0\n << /Type /Catalog >>\n") == []


class TestAnalyzePdfHonoursTheFlags:
    """Both parameters were accepted, documented, and then ignored.

    ``summary["urls"]`` and ``summary["embedded_files"]`` were assigned a
    literal ``[]`` regardless of what the caller asked for or what the file
    contained.
    """

    @staticmethod
    def _analyze(tmp_path: Path, **kwargs: object) -> dict[str, object]:
        from mulder.server.tools import documents as doc

        pdf = tmp_path / "sample.pdf"
        pdf.write_bytes(b"%PDF-1.4\n%%EOF\n")

        def fake_parser(_path: Path, *args: str) -> str:
            if "/URI" in args or "/Annot" in args:
                return URI_DUMP
            if "/Filespec" in args or "/EmbeddedFile" in args:
                return FILESPEC_DUMP
            return ""

        captured: dict[str, object] = {}

        def capture_response(
            tc_id: str, tool_name: str, params: object, results: object, *a: object
        ) -> dict[str, object]:
            if isinstance(results, dict):
                captured.update(results)
            return {"status": "success"}

        with (
            patch.object(doc, "_pdfid_script", return_value=Path("/fake/pdfid.py")),
            patch.object(doc, "_run_pdfid", return_value=[]),
            patch.object(doc, "_extract_pdf_javascript", return_value=[]),
            patch.object(doc, "_run_pdf_parser", side_effect=fake_parser),
            patch.object(doc, "extract_and_index", return_value={}),
            patch.object(doc, "tool_response", capture_response),
        ):
            doc.analyze_pdf.__wrapped__(  # type: ignore[attr-defined]
                "case-1", str(pdf), **kwargs
            )
        return captured

    def test_urls_are_returned_when_asked_for(self, tmp_path: Path) -> None:
        result = self._analyze(tmp_path, extract_urls=True, extract_embedded=False)
        urls = [u["url"] for u in result["urls"]]  # type: ignore[index,union-attr]
        assert "http://evil.example/payload" in urls

    def test_embedded_files_are_returned_when_asked_for(self, tmp_path: Path) -> None:
        result = self._analyze(tmp_path, extract_urls=False, extract_embedded=True)
        names = [f["filename"] for f in result["embedded_files"]]  # type: ignore[index,union-attr]
        assert names == ["dropper.exe"]

    def test_the_flags_still_switch_the_work_off(self, tmp_path: Path) -> None:
        result = self._analyze(tmp_path, extract_urls=False, extract_embedded=False)
        assert result["urls"] == []
        assert result["embedded_files"] == []


# --- JavaScript extraction ------------------------------------------------
#
# `pdf-parser --type` selects on an indirect object's /Type entry. A PDF's
# JavaScript lives in an action dictionary -- /Type /Action, /S /JavaScript --
# so `--type /JS` matches no object in any PDF and the extractor always
# returned nothing. Verified against DidierStevensSuite pdf-parser: on a PDF
# containing `app.alert(1)`, `--type /JS --filter` prints zero bytes while
# `--search javascript` prints the action.

LITERAL_JS_OBJECT = """obj 4 0
 Type: /Action
 Referencing:

  <<
    /Type /Action
    /S /JavaScript
    /JS '(app.alert\\(1\\))'
  >>

"""
"""Verbatim `pdf-parser --search javascript --filter` output for an inline script."""

INDIRECT_JS_OBJECT = """obj 4 0
 Type: /Action
 Referencing: 5 0 R

  <<
    /Type /Action
    /S /JavaScript
    /JS 5 0 R
  >>

"""
"""Verbatim output for the shape a real maldoc uses: a compressed JS stream."""

INDIRECT_JS_STREAM = """obj 5 0
 Type:
 Referencing:
 Contains stream

  <<
    /Length 38
    /Filter /FlateDecode
  >>

 b"app.alert('indirect-js-here');"
"""
"""Verbatim `--object 5 --filter --raw` output: the decoded stream payload."""


class TestJavaScriptExtraction:
    def test_the_search_is_not_a_type_selector(self, tmp_path: Path) -> None:
        """The invocation itself is the bug; pin what is actually run."""
        calls: list[tuple[str, ...]] = []

        def fake_parser(_path: Path, *args: str) -> str:
            calls.append(args)
            return ""

        with patch.object(doc, "_run_pdf_parser", side_effect=fake_parser):
            doc._extract_pdf_javascript(tmp_path / "x.pdf")

        assert calls, "the parser was never invoked"
        assert all("--type" not in a for a in calls)
        assert ("--search", "javascript", "--filter") in calls

    def test_an_inline_script_is_extracted(self, tmp_path: Path) -> None:
        with patch.object(doc, "_run_pdf_parser", return_value=LITERAL_JS_OBJECT):
            scripts = doc._extract_pdf_javascript(tmp_path / "x.pdf")

        assert len(scripts) == 1
        assert scripts[0]["object_id"] == 4
        assert scripts[0]["code"] == "app.alert(1)"

    def test_an_escaped_parenthesis_does_not_truncate_the_script(self, tmp_path: Path) -> None:
        """`app.alert(1)` is the common case, and a PDF writes `(` as `\\(`.

        Stopping at the first `)` would yield `app.alert(1` and lose whatever
        followed -- including the part an analyst is reading the script for.
        """
        with patch.object(doc, "_run_pdf_parser", return_value=LITERAL_JS_OBJECT):
            scripts = doc._extract_pdf_javascript(tmp_path / "x.pdf")

        assert scripts[0]["code"].endswith(")")

    def test_an_indirect_stream_reference_is_followed(self, tmp_path: Path) -> None:
        """`/JS 5 0 R` -- the code is in another object, usually compressed."""
        seen: list[tuple[str, ...]] = []

        def fake_parser(_path: Path, *args: str) -> str:
            seen.append(args)
            if "--object" in args:
                return INDIRECT_JS_STREAM
            return INDIRECT_JS_OBJECT

        with patch.object(doc, "_run_pdf_parser", side_effect=fake_parser):
            scripts = doc._extract_pdf_javascript(tmp_path / "x.pdf")

        assert ("--object", "5", "--filter", "--raw") in seen
        assert len(scripts) == 1
        assert scripts[0]["code"] == "app.alert('indirect-js-here');"

    def test_an_object_carrying_no_script_is_not_reported(self, tmp_path: Path) -> None:
        """`--search javascript` also matches a /Names /JavaScript tree."""
        names_tree = "obj 9 0\n  <<\n    /Names [(n) 4 0 R]\n  >>\n"
        with patch.object(doc, "_run_pdf_parser", return_value=names_tree):
            assert doc._extract_pdf_javascript(tmp_path / "x.pdf") == []

    def test_a_hex_obfuscated_action_is_still_found(self, tmp_path: Path) -> None:
        """`/J#61vaScript` must not defeat the extractor as it defeated the count.

        pdf-parser canonicalizes hex-escaped names before printing, so the dump
        for an obfuscated action is byte-identical to the dump for a plain one
        and `--search javascript` matches both. Verified against the real tool
        on a PDF whose *only* JavaScript action is written `/S /J#61vaScript`:
        the raw file contains no literal `/JavaScript` at all, and pdf-parser
        still prints `/S /JavaScript`, which is the fixture below.

        This is asserted rather than assumed because the PR's other half exists
        precisely because that evasion defeated the keyword count.
        """
        with patch.object(doc, "_run_pdf_parser", return_value=LITERAL_JS_OBJECT):
            scripts = doc._extract_pdf_javascript(tmp_path / "obfuscated.pdf")

        assert len(scripts) == 1
        assert scripts[0]["code"] == "app.alert(1)"

    def test_the_extracted_script_is_analysed(self, tmp_path: Path) -> None:
        """Extraction must feed the obfuscation and suspicious-function checks."""
        with patch.object(doc, "_run_pdf_parser", return_value=LITERAL_JS_OBJECT):
            scripts = doc._extract_pdf_javascript(tmp_path / "x.pdf")

        assert "is_obfuscated" in scripts[0]
        assert "suspicious_functions" in scripts[0]
