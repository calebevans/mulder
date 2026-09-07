"""A document olevba could not read must not be reported as macro-free.

``_analyze_macros_olevba`` already refused a non-zero exit that produced *no*
stdout. But olevba reports its own failures as JSON records on stdout and
still exits non-zero -- 5 for a file it cannot open, 3 for a missing one -- so
that stdout-emptiness test never fires for the failures that actually happen.
The error JSON then parses into a result list carrying no ``macros`` and no
``analysis``, and ``analyze_office_document`` returns ``status: success`` with
``has_vba: false`` and ``macro_count: 0``.

For a potentially malicious document that is the worst available answer: an
analysis that never ran, presented as a clean bill of health.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.documents import _analyze_macros_olevba, analyze_office_document

_META = {
    "script_name": "olevba",
    "version": "0.60.2",
    "type": "MetaInformation",
}
_FILE_OPEN_ERROR = {
    "file": "invoice.doc",
    "type": "error",
    "error": "FileOpenError",
    "message": "Failed to open file invoice.doc is not a supported file type, "
    "cannot extract VBA Macros.",
}


@pytest.fixture
def document(tmp_path: Path) -> Path:
    """A .doc that exists, so the run reaches olevba itself."""
    path = tmp_path / "invoice.doc"
    path.write_bytes(b"\xd0\xcf\x11\xe0")
    return path


def _olevba(returncode: int, payload: object, stderr: str = "") -> Any:
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.CompletedProcess(
        args=["olevba"], returncode=returncode, stdout=body, stderr=stderr
    )


def _invoke(document: Path, proc: Any) -> tuple[Any, list[str]]:
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {}

    with (
        patch("mulder.server.tools.documents.subprocess.run", return_value=proc),
        patch("mulder.server.tools.documents.extract_and_index", side_effect=_record),
    ):
        result = analyze_office_document.__wrapped__(  # type: ignore[attr-defined]
            "case-1", str(document), analyze_dde=False
        )
    return result, indexed


def test_an_unreadable_document_is_an_error_not_a_clean_one(document: Path) -> None:
    """The shape that made this silent: exit 5 with error JSON on stdout."""
    result, _indexed = _invoke(document, _olevba(5, [_META, _FILE_OPEN_ERROR]))

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert "exit 5" in message
    assert "FileOpenError" in message
    # The analysis never ran, so it must not answer the question it was asked.
    assert "preview" not in result


def test_a_failed_analysis_is_never_indexed_as_evidence(document: Path) -> None:
    """'Has VBA: False' must not reach the case DB for a document never read."""
    _result, indexed = _invoke(document, _olevba(5, [_META, _FILE_OPEN_ERROR]))

    assert indexed == [], f"a failed olevba run was summarised into the case: {indexed}"


def test_non_json_output_from_a_failed_run_is_an_error(document: Path) -> None:
    """A crashed olevba printing a traceback must not read as 'no macros'."""
    result, _indexed = _invoke(
        document, _olevba(1, "Traceback (most recent call last):\n  ImportError")
    )

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert "not JSON" in str(result["error_message"])


def test_a_genuinely_macro_free_document_is_still_clean(document: Path) -> None:
    """Pins the fix's narrowness: exit 0 with no macros stays a success.

    Most documents are benign. They must keep reporting as analysed-and-clean,
    or the fix trades silent failures for false alarms.
    """
    clean = [_META, {"file": "invoice.doc", "type": "OLE", "macros": [], "analysis": []}]

    result, indexed = _invoke(document, _olevba(0, clean))

    assert result["status"] == "success"
    # tool_response returns a compact preview envelope once `source` is set,
    # so the verdict is carried in the preview rather than as a top-level key.
    assert '"has_vba": false' in str(result["preview"])
    assert '"macro_count": 0' in str(result["preview"])
    assert indexed, "a clean analysis must still be indexed"


def test_unparseable_output_from_a_successful_run_is_still_tolerated(
    document: Path,
) -> None:
    """Pins narrowness the other way: exit 0 keeps its existing lenient path."""
    result, _indexed = _invoke(document, _olevba(0, "not json at all"))

    assert result["status"] == "success"
    assert '"has_vba": false' in str(result["preview"])


def test_macros_found_before_a_non_zero_exit_are_kept(document: Path) -> None:
    """olevba can fail on one member of a container after parsing another.

    The guard is conjunctive -- non-zero *and* error records *and* nothing
    extracted -- so real macro findings are never discarded.
    """
    partial = [
        _META,
        {
            "file": "invoice.doc",
            "type": "OLE",
            "macros": [{"vba_filename": "M1", "code": 'Sub AutoOpen()\nShell "cmd"\nEnd Sub'}],
            "analysis": [],
        },
        _FILE_OPEN_ERROR,
    ]

    result, indexed = _invoke(document, _olevba(5, partial))

    assert result["status"] == "success"
    # Assert on what reached the case DB: the preview is length-capped, the
    # indexed text is not.
    assert indexed and "Module: M1" in indexed[0]
    assert "Has VBA: True" in indexed[0]


@pytest.mark.skipif(
    __import__("importlib.util", fromlist=["util"]).find_spec("oletools") is None,
    reason="oletools not installed",
)
def test_the_real_olevba_binary_rejects_a_corrupt_document(tmp_path: Path) -> None:
    """No mocks: drive the actual olevba that ships as a mulder dependency.

    A random-bytes .doc passes mulder's existence and extension checks, so this
    is reachable through the MCP tool. olevba exits 5 and prints a FileOpenError
    record; before this fix the wrapper turned that into ([], [], False).
    """
    doc = tmp_path / "invoice.doc"
    doc.write_bytes(os.urandom(2048))

    with pytest.raises(OSError, match="olevba failed"):
        _analyze_macros_olevba(doc)
