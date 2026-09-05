"""A document analysis that did not run must not be reported as a clean document.

Three ways ``analyze_office_document`` and ``analyze_pdf`` said "clean" about a
file they had not actually examined:

* **olevba.** The wrapper guarded only "non-zero exit *and* no stdout". Run
  against a file it cannot read, olevba exits 3 and still prints a perfectly
  valid JSON document -- one whose entry is ``{"type": "error", ...}``. It
  parses, it carries no ``macros`` and no ``analysis``, so the wrapper returned
  ``([], [], False)`` and ``_assess_office_risk`` scored the document
  ``clean``. Unparseable JSON took the same path via a ``logger.warning``.

  The exit code cannot carry this decision on its own: olevba's
  ``RETURN_WARNINGS`` is **1**, so a non-zero status is how a *successful*
  analysis reports that it found something. The failure is recognised from
  olevba's own output instead.

* **pdfid.** ``_run_pdfid`` never looked at ``returncode``. A pdfid that
  crashed printed a traceback, matched no keyword lines, and produced an empty
  indicator list -- identical to a PDF containing nothing risky.

* **msodde.** A failure was recorded with ``logger.warning`` only, while the
  response still carried ``dde_links: []``. The consuming agent could not tell
  "no DDE links in this document" from "DDE analysis did not run".

And one wrong verdict: ``_assess_office_risk`` was computed from VBA alone and
short-circuited to ``clean`` whenever ``has_vba`` was false. A DDE maldoc
carries no VBA at all -- that is the entire technique -- so a real
``DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"`` document was reported
clean, and its command never reached the case index either.

The olevba and msodde fixtures here are copied verbatim from oletools 0.60.2.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import mulder.server.tools.documents as doc
from mulder.server.tools.documents import (
    _analyze_macros_olevba,
    _assess_office_risk,
    _parse_msodde_output,
    _run_pdfid,
)

# Verbatim `python -m oletools.msodde --json dde.docx` output for a document
# whose only content is a DDEAUTO field.
MSODDE_DDEAUTO_JSON = json.dumps(
    [
        {
            "msg": "msodde 0.60.2 - http://decalage.info/python/oletools",
            "level": "WARNING",
            "type": "msg",
        },
        {"msg": "Opening file: dde.docx", "level": "WARNING", "type": "msg"},
        {"msg": "DDE Links:", "level": "WARNING", "type": "msg"},
        {
            "msg": ' DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" ',
            "level": "WARNING",
            "type": "dde-link",
        },
    ]
)

# Verbatim `python -m oletools.olevba --json /nope/missing.doc` output, exit 3.
OLEVBA_ERROR_JSON = json.dumps(
    [
        {
            "script_name": "olevba",
            "version": "0.60.2",
            "url": "http://decalage.info/python/oletools",
            "type": "MetaInformation",
        },
        {
            "file": "/nope/missing.doc",
            "type": "error",
            "error": "PathNotFoundException",
            "message": "Given path does not exist: '/nope/missing.doc'",
        },
    ]
)

OLEVBA_CLEAN_JSON = json.dumps(
    [
        {"script_name": "olevba", "version": "0.60.2", "type": "MetaInformation"},
        {"file": "clean.docx", "type": "Text", "macros": [], "analysis": []},
    ]
)


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["tool"], returncode, stdout, stderr)


class TestOlevbaFailureIsNotACleanDocument:
    def test_an_error_document_raises(self) -> None:
        """The bug: valid JSON, no macros key, therefore scored clean."""
        with (
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(returncode=3, stdout=OLEVBA_ERROR_JSON),
            ),
            pytest.raises(OSError, match="Given path does not exist"),
        ):
            _analyze_macros_olevba(Path("/nope/missing.doc"))

    def test_the_old_guard_would_not_have_fired(self) -> None:
        """Pin the premise: the failure output is non-empty and parses."""
        assert OLEVBA_ERROR_JSON.strip()
        entries = json.loads(OLEVBA_ERROR_JSON)
        assert all("macros" not in e for e in entries)
        assert all("analysis" not in e for e in entries)

    def test_unparseable_output_raises(self) -> None:
        with (
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(stdout="Traceback (most recent call last):"),
            ),
            pytest.raises(OSError, match="unparseable"),
        ):
            _analyze_macros_olevba(Path("/fake/doc.docm"))

    def test_a_nonzero_exit_with_real_results_still_succeeds(self) -> None:
        """olevba's RETURN_WARNINGS is 1: non-zero means *found something*.

        Keying the failure decision off the exit code would turn every
        successful analysis of an interesting document into an error.
        """
        from oletools.olevba import RETURN_WARNINGS

        assert RETURN_WARNINGS == 1

        with patch(
            "mulder.server.tools.documents.subprocess.run",
            return_value=_completed(returncode=RETURN_WARNINGS, stdout=OLEVBA_CLEAN_JSON),
        ):
            macros, indicators, has_vba = _analyze_macros_olevba(Path("/fake/doc.docm"))

        assert (macros, indicators, has_vba) == ([], [], False)


class TestPdfidFailureIsNotACleanPdf:
    def test_a_crash_raises_instead_of_reporting_no_indicators(self) -> None:
        with (
            patch.object(doc, "_pdfid_script", return_value=Path("/fake/pdfid.py")),
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(returncode=1, stderr="ImportError: no module"),
            ),
            pytest.raises(OSError, match="pdfid"),
        ):
            _run_pdfid(Path("/fake/x.pdf"))

    def test_a_nonzero_exit_that_still_printed_indicators_keeps_them(self) -> None:
        """Partial output is kept; only "nothing at all" is a failure."""
        stdout = " /JavaScript            2\n /OpenAction            1\n"
        with (
            patch.object(doc, "_pdfid_script", return_value=Path("/fake/pdfid.py")),
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(returncode=1, stdout=stdout),
            ),
        ):
            indicators = _run_pdfid(Path("/fake/x.pdf"))

        assert {str(i["keyword"]) for i in indicators} == {"/JavaScript", "/OpenAction"}

    def test_a_clean_pdf_is_still_clean(self) -> None:
        with (
            patch.object(doc, "_pdfid_script", return_value=Path("/fake/pdfid.py")),
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(stdout=" /JavaScript            0\n"),
            ),
        ):
            assert _run_pdfid(Path("/fake/x.pdf")) == []


class TestDdeChangesTheVerdict:
    """A DDE maldoc has no VBA, so a VBA-only verdict calls it clean."""

    def test_a_ddeauto_document_is_not_clean(self) -> None:
        links = _parse_msodde_output(MSODDE_DDEAUTO_JSON)
        assert links, "the fixture must contain a link for this test to mean anything"

        assert _assess_office_risk([], False)["risk_level"] == "clean"
        assert _assess_office_risk([], False, links)["risk_level"] == "malicious"

    def test_a_non_auto_dde_link_is_high_not_malicious(self) -> None:
        links = [{"field_type": "DDE", "command": "DDE cmd.exe", "risk": "high"}]
        assert _assess_office_risk([], False, links)["risk_level"] == "high"

    def test_the_reason_names_the_finding(self) -> None:
        links = _parse_msodde_output(MSODDE_DDEAUTO_JSON)
        risk = _assess_office_risk([], False, links)
        assert any("DDE" in str(r) for r in risk["reasons"])  # type: ignore[union-attr]
        assert risk["dde_links_present"] is True

    def test_a_document_with_no_dde_is_unaffected(self) -> None:
        assert _assess_office_risk([], False, []) == _assess_office_risk([], False)


class TestTheOfficeResponseSaysWhetherDdeRan:
    @staticmethod
    def _run(tmp_path: Path, msodde: subprocess.CompletedProcess[str]) -> dict[str, Any]:
        target = tmp_path / "doc.docx"
        target.write_bytes(b"PK\x03\x04")
        captured: dict[str, Any] = {}

        def capture_response(
            tc_id: str, tool_name: str, params: object, results: object, *a: object
        ) -> dict[str, object]:
            if isinstance(results, dict):
                captured.update(results)
            return {"status": "success"}

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if "oletools.msodde" in cmd:
                return msodde
            return _completed(stdout=OLEVBA_CLEAN_JSON)

        with (
            patch("mulder.server.tools.documents.subprocess.run", side_effect=fake_run),
            patch.object(doc, "extract_and_index", return_value={}),
            patch.object(doc, "tool_response", capture_response),
        ):
            doc.analyze_office_document.__wrapped__(  # type: ignore[attr-defined]
                "case-1", str(target), analyze_dde=True
            )
        return captured

    def test_a_successful_run_is_marked_analysed(self, tmp_path: Path) -> None:
        summary = self._run(tmp_path, _completed(stdout=MSODDE_DDEAUTO_JSON))
        assert summary["dde_analyzed"] is True
        assert summary["dde_links"]
        assert "warning" not in summary

    def test_a_failed_run_is_not_reported_as_no_links(self, tmp_path: Path) -> None:
        """`dde_links: []` alone cannot distinguish clean from did-not-run."""
        summary = self._run(tmp_path, _completed(returncode=1, stderr="msodde: cannot open file"))
        assert summary["dde_links"] == []
        assert summary["dde_analyzed"] is False
        assert "did not run" in str(summary["warning"])


class TestTheDdeCommandReachesTheIndex:
    def test_the_indexed_text_carries_the_command(self, tmp_path: Path) -> None:
        """A case-wide search for cmd.exe must be able to find the payload."""
        target = tmp_path / "doc.docx"
        target.write_bytes(b"PK\x03\x04")
        indexed: list[str] = []

        def fake_index(text: str, *a: object, **k: object) -> dict[str, object]:
            indexed.append(text)
            return {}

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if "oletools.msodde" in cmd:
                return _completed(stdout=MSODDE_DDEAUTO_JSON)
            return _completed(stdout=OLEVBA_CLEAN_JSON)

        with (
            patch("mulder.server.tools.documents.subprocess.run", side_effect=fake_run),
            patch.object(doc, "extract_and_index", side_effect=fake_index),
            patch.object(doc, "tool_response", lambda *a, **k: {"status": "success"}),
        ):
            doc.analyze_office_document.__wrapped__(  # type: ignore[attr-defined]
                "case-1", str(target), analyze_dde=True
            )

        assert indexed
        assert "cmd.exe" in indexed[0]
        assert "DDEAUTO" in indexed[0]
