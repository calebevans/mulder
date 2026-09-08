"""A crashed msodde must not be reported as "no DDE links found".

``analyze_office_document`` ran msodde, and on a non-zero exit merely called
``logger.warning`` -- server-side text the MCP client never sees -- while still
returning ``status: success`` with ``dde_links: []``. The caller could not
distinguish a document with no DDE fields from one msodde never managed to
read. DDEAUTO is a live code-execution vector, so an empty ``dde_links`` list
is read as an authoritative all-clear.

The function's own comment already stated the requirement -- "a broken msodde
must not pass silently as 'no DDE links found'" -- but the code only logged.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.documents import analyze_office_document

_OLEVBA_CLEAN = json.dumps(
    [
        {"script_name": "olevba", "version": "0.60.2", "type": "MetaInformation"},
        {"file": "invoice.doc", "type": "OLE", "macros": [], "analysis": []},
    ]
)
#: msodde still prints its "DDE Links:" section header when it crashes, so the
#: exit code is the only signal that the check did not actually run.
_MSODDE_CRASH = (
    '[{"msg": "Opening file: invoice.doc", "level": "WARNING", "type": "msg"}\n'
    ',     {"msg": "\'utf-8\' codec can\'t decode byte 0xeb in position 3", '
    '"level": "ERROR", "type": "msg"}\n'
    ',     {"msg": "DDE Links:", "level": "WARNING", "type": "msg"}]'
)


@pytest.fixture
def document(tmp_path: Path) -> Path:
    """A .doc that exists, so the run reaches the tools themselves."""
    path = tmp_path / "invoice.doc"
    path.write_bytes(b"\xd0\xcf\x11\xe0")
    return path


def _recorder(sink: list[str]) -> Callable[..., dict[str, object]]:
    """A stand-in for extract_and_index that captures what reached the case DB."""

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        sink.append(raw)
        return {}

    return _record


def _proc(returncode: int, stdout: str, stderr: str = "") -> Any:
    return subprocess.CompletedProcess(
        args=["oletools"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _invoke(document: Path, msodde: Any) -> tuple[Any, list[str]]:
    """olevba always succeeds cleanly; *msodde* is the second call's result."""
    indexed: list[str] = []
    calls = iter([_proc(0, _OLEVBA_CLEAN), msodde])

    def _run(*args: object, **kwargs: object) -> Any:
        return next(calls)

    with (
        patch("mulder.server.tools.documents.subprocess.run", side_effect=_run),
        patch(
            "mulder.server.tools.documents.extract_and_index",
            side_effect=_recorder(indexed),
        ),
    ):
        result = analyze_office_document.__wrapped__(  # type: ignore[attr-defined]
            "case-1", str(document), analyze_dde=True
        )
    return result, indexed


def test_a_crashed_msodde_is_an_error_not_an_all_clear(document: Path) -> None:
    """The shape that made this silent: exit 1 with a banner still on stdout."""
    result, _indexed = _invoke(document, _proc(1, _MSODDE_CRASH))

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    message = str(result["error_message"])
    assert "msodde exited 1" in message
    assert "DDE check did not run" in message


def test_the_error_tells_the_analyst_how_to_get_the_macro_analysis(
    document: Path,
) -> None:
    """Failing the whole call costs a good macro result, so say how to recover."""
    result, _indexed = _invoke(document, _proc(1, _MSODDE_CRASH))

    assert "analyze_dde=False" in str(result["suggestion"])


def test_a_failed_dde_check_is_never_indexed_as_evidence(document: Path) -> None:
    """No half-analysis reaches the case DB claiming the document was checked."""
    _result, indexed = _invoke(document, _proc(1, _MSODDE_CRASH))

    assert indexed == [], f"a failed DDE check was summarised into the case: {indexed}"


def test_a_timeout_running_msodde_is_reported(document: Path) -> None:
    """Previously swallowed by `except (TimeoutExpired, OSError): logger.debug`."""
    indexed: list[str] = []
    calls = [_proc(0, _OLEVBA_CLEAN)]

    def _run(*args: object, **kwargs: object) -> Any:
        if calls:
            return calls.pop()
        raise subprocess.TimeoutExpired(cmd="msodde", timeout=120)

    with (
        patch("mulder.server.tools.documents.subprocess.run", side_effect=_run),
        patch(
            "mulder.server.tools.documents.extract_and_index",
            side_effect=_recorder(indexed),
        ),
    ):
        result = analyze_office_document.__wrapped__(  # type: ignore[attr-defined]
            "case-1", str(document), analyze_dde=True
        )

    assert result["status"] == "error"
    assert result["error_type"] == "tool_failed"
    assert indexed == []


def test_a_document_with_no_dde_links_is_still_a_success(document: Path) -> None:
    """Pins the fix's narrowness: msodde exiting 0 with no links is a result.

    Most documents have no DDE fields. They must keep reporting as
    checked-and-clean, or the fix trades silent failures for false alarms.
    """
    ok = '[{"msg": "DDE Links:", "level": "WARNING", "type": "msg"}]'

    result, indexed = _invoke(document, _proc(0, ok))

    assert result["status"] == "success"
    assert indexed, "a clean analysis must still be indexed"


def test_dde_links_found_on_a_successful_run_are_reported(document: Path) -> None:
    """The positive path still works: a real DDEAUTO field is surfaced."""
    found = json.dumps(
        [
            {"msg": "DDE Links:", "level": "WARNING", "type": "msg"},
            {"msg": 'DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"', "type": "msg"},
        ]
    )

    result, _indexed = _invoke(document, _proc(0, found))

    assert result["status"] == "success"


def test_analyze_dde_false_never_runs_msodde(document: Path) -> None:
    """Opting out of the DDE check must not be affected by this change."""
    indexed: list[str] = []
    runs: list[object] = []

    def _run(cmd: list[str], **kwargs: object) -> Any:
        runs.append(cmd)
        return _proc(0, _OLEVBA_CLEAN)

    with (
        patch("mulder.server.tools.documents.subprocess.run", side_effect=_run),
        patch(
            "mulder.server.tools.documents.extract_and_index",
            side_effect=_recorder(indexed),
        ),
    ):
        result = analyze_office_document.__wrapped__(  # type: ignore[attr-defined]
            "case-1", str(document), analyze_dde=False
        )

    assert result["status"] == "success"
    assert len(runs) == 1, "msodde must not run when analyze_dde is False"


@pytest.mark.skipif(
    __import__("importlib.util", fromlist=["util"]).find_spec("oletools") is None,
    reason="oletools not installed",
)
def test_the_real_msodde_binary_fails_on_a_corrupt_document(tmp_path: Path) -> None:
    """No mocks: the pinned msodde really does exit non-zero here.

    It also still prints its "DDE Links:" section header while crashing, which
    is why parsing stdout cannot substitute for reading the exit code.
    """
    doc = tmp_path / "invoice.doc"
    doc.write_bytes(os.urandom(2048))

    proc = subprocess.run(
        [sys.executable, "-m", "oletools.msodde", "--json", str(doc)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert proc.returncode != 0
    assert "DDE Links:" in proc.stdout
