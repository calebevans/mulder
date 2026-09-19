"""ALEAPP/iLEAPP results must actually be found on disk.

Both tools create a timestamped report folder under the ``-o`` path and write
every TSV into a ``_TSV Exports`` directory inside it::

    <output_dir>/ALEAPP_Output_2026-09-08_Monday_054512/_TSV Exports/*.tsv

``_parse_leapp_output`` looked for ``<output_dir>/tsv``, then for a child
directory containing a ``tsv`` subdirectory, then fell back to globbing
``<output_dir>/*.tsv``. All three miss the real layout, so every run of
``run_aleapp`` / ``run_ileapp`` returned ``no_artifacts`` -- a phone full of
evidence reported as "produced no parseable output".

The layout is pinned against ALEAPP/iLEAPP v2026.3.2:
``leapp_functions/app/output.py`` builds ``<leapp_name>_Output_<timestamp>``
and ``scripts/ilapfuncs.py::tsv`` writes into ``_TSV Exports``.
"""

from __future__ import annotations

from pathlib import Path

from mulder.server.tools.phone import _parse_leapp_output

_HEADERS = "Timestamp\tPartner\tMessage"
_ROWS = [
    "2026-01-14 09:12:03\t+32470112233\tmeet me at the lockup",
    "2026-01-14 09:14:51\t+32470998877\tburn the drive",
]


def _write_report_tree(output_dir: Path, tool: str = "ALEAPP") -> Path:
    """Build the real report tree the pinned tools produce under ``-o``."""
    report = output_dir / f"{tool}_Output_2026-09-08_Monday_054512"
    tsv_dir = report / "_TSV Exports"
    tsv_dir.mkdir(parents=True)
    (tsv_dir / "sms messages.tsv").write_text(
        _HEADERS + "\n" + "\n".join(_ROWS) + "\n", encoding="utf-8"
    )
    # The rest of the report folder, so the fixture is not a stripped-down
    # shape the code could accidentally rely on.
    (report / "_HTML" / "_Script_Logs").mkdir(parents=True)
    (report / "_HTML" / "index.html").write_text("<html></html>")
    (report / "data").mkdir()
    (report / "media").mkdir()
    return report


def test_the_real_report_layout_is_found(tmp_path: Path) -> None:
    """The layout ALEAPP v2026.3.2 actually writes must yield artifacts."""
    _write_report_tree(tmp_path)

    result = _parse_leapp_output(tmp_path, "android", "/evidence/phone.tar")

    assert result["total_artifacts_parsed"] == 1
    assert result["total_records"] == 2
    artifact = result["artifacts"][0]
    assert artifact["artifact_type"] == "sms messages"
    assert artifact["data"][0]["Partner"] == "+32470112233"


def test_the_message_body_survives_parsing(tmp_path: Path) -> None:
    """The evidence itself -- not just a count -- must come back."""
    _write_report_tree(tmp_path)

    result = _parse_leapp_output(tmp_path, "android", "/evidence/phone.tar")

    bodies = [row["Message"] for row in result["artifacts"][0]["data"]]
    assert bodies == ["meet me at the lockup", "burn the drive"]


def test_the_ios_report_layout_is_found(tmp_path: Path) -> None:
    """iLEAPP uses the same ``_TSV Exports`` convention under its own folder."""
    _write_report_tree(tmp_path, tool="iLEAPP")

    result = _parse_leapp_output(tmp_path, "ios", "/evidence/backup")

    assert result["total_artifacts_parsed"] == 1
    assert result["platform"] == "ios"


def test_a_run_that_produced_nothing_is_still_empty(tmp_path: Path) -> None:
    """Pins the fix's narrowness: no TSVs means no artifacts, not a crash."""
    report = tmp_path / "ALEAPP_Output_2026-09-08_Monday_054512"
    (report / "_TSV Exports").mkdir(parents=True)
    (report / "_HTML").mkdir()

    result = _parse_leapp_output(tmp_path, "android", "/evidence/phone.tar")

    assert result["total_artifacts_parsed"] == 0
    assert result["total_records"] == 0


def test_an_absent_output_directory_is_handled(tmp_path: Path) -> None:
    """A tool that wrote nothing at all must not raise."""
    result = _parse_leapp_output(tmp_path / "nope", "android", "/evidence/phone.tar")

    assert result["total_artifacts_parsed"] == 0


def test_a_flat_tsv_directory_still_works(tmp_path: Path) -> None:
    """Pins the fix's narrowness: the pre-existing layouts keep working.

    Anything already relying on a ``tsv`` directory -- a custom output folder,
    an older LEAPP -- must not regress.
    """
    tsv_dir = tmp_path / "tsv"
    tsv_dir.mkdir()
    (tsv_dir / "calls.tsv").write_text(_HEADERS + "\n" + _ROWS[0] + "\n", encoding="utf-8")

    result = _parse_leapp_output(tmp_path, "android", "/evidence/phone.tar")

    assert result["total_artifacts_parsed"] == 1
    assert result["artifacts"][0]["artifact_type"] == "calls"


def test_tsv_files_dropped_directly_in_the_output_dir_still_work(tmp_path: Path) -> None:
    """The previous final fallback globbed ``<output_dir>/*.tsv``; keep it."""
    (tmp_path / "wifi.tsv").write_text(_HEADERS + "\n" + _ROWS[0] + "\n", encoding="utf-8")

    result = _parse_leapp_output(tmp_path, "android", "/evidence/phone.tar")

    assert result["total_artifacts_parsed"] == 1
    assert result["artifacts"][0]["artifact_type"] == "wifi"
