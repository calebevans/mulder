"""Hex-obfuscated PDF names must not make pdfid's indicators disappear.

pdfid prints a keyword row as ``' %-16s %7d'`` and appends the hex-encoded
tally as ``'(%d)'`` -- with no separating space -- whenever any occurrence of
that name was written with an escaped character. So a PDF whose action is
spelled ``/J#61vaScript`` comes back as::

     /JavaScript            1(1)

``_extract_pdfid_count`` did ``int(line.rsplit(None, 1)[1])``, which raises
``ValueError`` on ``"1(1)"`` and returned ``0``. ``_run_pdfid`` keeps only
indicators whose count is ``> 0``, so the indicator was dropped outright:
``has_javascript`` came back ``False``, no "Contains JavaScript" reason was
recorded, and ``analyze_pdf`` never even called the JavaScript extractor --
which it gates on that same indicator.

Escaping a name is the textbook way to hide it from pdfid, and it is exactly
the case this parser turned into silence.
"""

from __future__ import annotations

from mulder.server.tools.documents import _compute_pdf_risk, _extract_pdfid_count

# Verbatim rows from pdfid 0.2.10 run against a PDF using /J#61vaScript
# and /J#53 for its OpenAction JavaScript.
_OBFUSCATED_ROWS = [
    " /JS                    1(1)",
    " /JavaScript            1(1)",
    " /OpenAction            1",
]


def test_a_hex_obfuscated_name_still_reports_its_count() -> None:
    """The row pdfid actually emits for an escaped name."""
    assert _extract_pdfid_count(" /JavaScript            1(1)") == 1


def test_the_count_is_the_total_not_the_hexcode_tally() -> None:
    """pdfid's first number counts every occurrence; the suffix is a subset.

    In pdfid's ``UpdateWords`` the total is incremented for each occurrence and
    the hexcode tally only additionally, so ``2(1)`` means two occurrences, one
    of which was escaped -- not three, and not one.
    """
    assert _extract_pdfid_count(" /EmbeddedFile          2(1)") == 2
    assert _extract_pdfid_count(" /Launch                7(3)") == 7


def test_a_plain_row_is_unchanged() -> None:
    """Pins the fix's narrowness: ordinary rows must parse exactly as before."""
    assert _extract_pdfid_count(" /OpenAction            1") == 1
    assert _extract_pdfid_count(" /JS                   12") == 12
    assert _extract_pdfid_count(" /EmbeddedFile          0") == 0


def test_junk_still_parses_as_zero() -> None:
    """Non-numeric trailing fields must not raise or invent a count."""
    assert _extract_pdfid_count(" PDF Header: %PDF-1.4") == 0
    assert _extract_pdfid_count(" /JS                 (1)") == 0
    assert _extract_pdfid_count(" /JS                  1(") == 0
    assert _extract_pdfid_count(" /JS                 1(1)x") == 0
    assert _extract_pdfid_count("") == 0
    assert _extract_pdfid_count("single") == 0


def test_an_obfuscated_pdf_is_no_longer_reported_without_javascript() -> None:
    """The end-to-end consequence: the risk assessment regains the JS finding.

    Built from the real pdfid rows above. Before the fix both JavaScript rows
    parsed to 0 and were discarded, leaving only /OpenAction -- so the report
    said ``has_javascript: False`` for a PDF that auto-runs a script.
    """
    indicators = [
        {"keyword": kw, "count": _extract_pdfid_count(row), "risk_level": risk}
        for row, kw, risk in (
            (_OBFUSCATED_ROWS[0], "/JS", "high"),
            (_OBFUSCATED_ROWS[1], "/JavaScript", "high"),
            (_OBFUSCATED_ROWS[2], "/OpenAction", "high"),
        )
        if _extract_pdfid_count(row) > 0
    ]

    risk = _compute_pdf_risk(indicators, [])

    assert risk["has_javascript"] is True
    reasons = risk["reasons"]
    assert isinstance(reasons, list)
    assert "Contains JavaScript" in reasons
    assert risk["has_auto_action"] is True
