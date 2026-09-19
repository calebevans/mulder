"""ALEAPP/iLEAPP must index the artefacts themselves, not just how many.

``run_aleapp`` / ``run_ileapp`` built the indexed text from counts only::

    ALEAPP analysis of /evidence/phone.tar
    Artifacts parsed: 42
    Total records: 12000
      messaging: 8000 records

That is what reached ``extract_and_index`` and therefore the case database.
The recovered messages, URLs, filenames and timestamps -- the evidence -- were
never indexed, so ``search()`` over the case could not surface a single one.
``_parse_leapp_output`` also discarded every row past the hundredth before the
caller ever saw it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.phone import _parse_leapp_output, run_aleapp

_HEADERS = "Timestamp\tPartner\tMessage"
_ROWS = [
    "2026-01-14 09:12:03\t+32470112233\tmeet me at the lockup",
    "2026-01-14 09:14:51\t+32470998877\tburn the drive",
]


@pytest.fixture
def extraction(tmp_path: Path) -> Path:
    """An extraction path that exists, so the run reaches ALEAPP."""
    path = tmp_path / "phone.tar"
    path.write_bytes(b"\x00" * 64)
    (tmp_path / "aleapp.py").write_text("")
    return path


def _tsv_tree(root: Path, rows: list[str]) -> Path:
    """The TSV directory shape ``_parse_leapp_output`` reads from."""
    tsv_dir = root / "tsv"
    tsv_dir.mkdir(parents=True, exist_ok=True)
    (tsv_dir / "sms messages.tsv").write_text(
        _HEADERS + "\n" + "\n".join(rows) + "\n", encoding="utf-8"
    )
    return tsv_dir


def _run_aleapp_over(tmpdir_contents: Any, extraction: Path) -> tuple[Any, list[str]]:
    """Drive ``run_aleapp`` with ALEAPP replaced by a fake that writes output."""
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {}

    def _fake_aleapp(cmd: list[str], **_: object) -> Any:
        out = Path(cmd[cmd.index("-o") + 1])
        tmpdir_contents(out)

        class _P:
            returncode = 0
            stdout = ""
            stderr = ""

        return _P()

    with (
        patch(
            "mulder.server.tools.phone._aleapp_script",
            return_value=str(extraction.parent / "aleapp.py"),
        ),
        patch("mulder.server.tools.phone._find_leapp_cmd", return_value=["python", "aleapp.py"]),
        patch("mulder.server.tools.phone.subprocess.run", side_effect=_fake_aleapp),
        patch("mulder.server.tools.phone.extract_and_index", side_effect=_record),
    ):
        result = run_aleapp.__wrapped__(str(extraction))  # type: ignore[attr-defined]
    return result, indexed


def test_the_message_body_reaches_the_index(extraction: Path) -> None:
    """The sharpest form: a recovered SMS must be searchable in the case."""
    result, indexed = _run_aleapp_over(lambda out: _tsv_tree(out, _ROWS), extraction)

    assert result["status"] == "success"
    assert indexed, "nothing was indexed at all"
    blob = indexed[0]
    assert "meet me at the lockup" in blob
    assert "burn the drive" in blob
    assert "+32470112233" in blob


def test_the_index_is_not_just_a_count_summary(extraction: Path) -> None:
    """Counts alone are what main indexed; they must no longer be all of it."""
    _result, indexed = _run_aleapp_over(lambda out: _tsv_tree(out, _ROWS), extraction)

    blob = indexed[0]
    # The count lines stay -- they are useful context, just not sufficient.
    assert "Total records: 2" in blob
    # ...but the evidence is there too.
    assert "Partner" in blob, "column headers were not indexed"


def test_rows_past_the_hundredth_are_indexed(extraction: Path) -> None:
    """``data`` was truncated to 100 rows before anyone could index it.

    Row 250 of a message table is evidence like any other.
    """
    rows = [f"2026-01-14 09:00:{i:02d}\t+3247000{i:04d}\tmessage number {i}" for i in range(300)]
    _result, indexed = _run_aleapp_over(lambda out: _tsv_tree(out, rows), extraction)

    blob = indexed[0]
    assert "message number 250" in blob
    assert "message number 299" in blob


def test_the_response_stays_a_bounded_preview(extraction: Path) -> None:
    """Pins the fix's narrowness: the MCP response must not balloon.

    The index gets everything; the payload handed back keeps its 100-row cap,
    so a 12000-row message table is not shipped through the transport.
    """
    rows = [f"2026-01-14 09:00:{i:02d}\t+3247000{i:04d}\tmessage number {i}" for i in range(300)]
    captured: list[dict[str, Any]] = []

    def _capture(
        tc_id: str, name: str, params: Any, results: Any, *a: object
    ) -> dict[str, object]:
        captured.append(results)
        return {"status": "success"}

    def _fake_aleapp(cmd: list[str], **_: object) -> Any:
        _tsv_tree(Path(cmd[cmd.index("-o") + 1]), rows)

        class _P:
            returncode = 0
            stdout = ""
            stderr = ""

        return _P()

    with (
        patch(
            "mulder.server.tools.phone._aleapp_script",
            return_value=str(extraction.parent / "aleapp.py"),
        ),
        patch("mulder.server.tools.phone._find_leapp_cmd", return_value=["python", "aleapp.py"]),
        patch("mulder.server.tools.phone.subprocess.run", side_effect=_fake_aleapp),
        patch("mulder.server.tools.phone.extract_and_index", return_value={}),
        patch("mulder.server.tools.phone.tool_response", side_effect=_capture),
    ):
        run_aleapp.__wrapped__(str(extraction))  # type: ignore[attr-defined]

    assert captured, "tool_response was never reached"
    artifact = captured[0]["artifacts"][0]
    assert artifact["record_count"] == 300, "the true count must survive"
    assert len(artifact["data"]) == 100, "the response payload must stay capped"


def test_the_parser_keeps_every_row_for_indexing(tmp_path: Path) -> None:
    """``_parse_leapp_output`` must hand the caller all rows, not the first 100."""
    rows = [f"2026-01-14 09:00:{i:02d}\t+3247000{i:04d}\tmessage number {i}" for i in range(300)]
    _tsv_tree(tmp_path, rows)

    result = _parse_leapp_output(tmp_path, "android", "/evidence/phone.tar")

    assert result["artifacts"][0]["record_count"] == 300
    assert len(result["artifacts"][0]["data"]) == 300


def test_a_short_row_does_not_shift_the_columns() -> None:
    """A truncated TSV row yields a short dict; columns must stay aligned."""
    from mulder.server.tools.phone import _leapp_artifact_lines

    artifact = {
        "category": "messaging",
        "artifact_type": "sms",
        "data": [
            {"Timestamp": "t1", "Partner": "+32470", "Message": "hello"},
            {"Timestamp": "t2"},
            {"Timestamp": "t3", "Extra": "late column", "Message": "bye"},
        ],
    }

    lines = _leapp_artifact_lines(artifact)

    assert lines[0] == "[messaging] sms"
    assert lines[1] == "Timestamp\tPartner\tMessage\tExtra"
    # The short row keeps its position under Timestamp and pads the rest.
    assert lines[3] == "t2\t\t\t"
    assert lines[4] == "t3\t\tbye\tlate column"


def test_an_artifact_with_no_rows_renders_nothing() -> None:
    """Pins narrowness: an empty artefact must not emit a stray header."""
    from mulder.server.tools.phone import _leapp_artifact_lines

    assert _leapp_artifact_lines({"category": "c", "artifact_type": "a", "data": []}) == []
    assert _leapp_artifact_lines({"category": "c", "artifact_type": "a"}) == []
