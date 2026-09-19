"""Chainsaw's SRUM invocation must match the CLI ``analyse srum`` declares.

``_run_chainsaw_srum`` built ``chainsaw analyse srum <SRUDB.dat> --json
--output <file>``.  Two things are wrong with that line, and either alone is
fatal.  Verified against the pinned release, chainsaw 2.16.0::

    $ chainsaw analyse srum ./evidence/SRUDB.dat --json --output srum.json
    error: unexpected argument '--json' found
    Usage: chainsaw analyse srum --software <SOFTWARE_HIVE_PATH> <SRUM_PATH>
    (exit 2)

1. ``--json`` is not an option of ``analyse srum`` at all.  The subcommand
   always writes JSON to ``--output`` (``cs_print_json!`` in chainsaw's
   ``main.rs``), so there is no format flag to pass.
2. ``--software <SOFTWARE_HIVE_PATH>`` is **required** -- Chainsaw needs the
   SOFTWARE hive to resolve the SRUM extension GUIDs into table names.

They are fixed together because they are one argv, and correcting either alone
leaves SRUM parsing still failing at parse time with exit 2.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.chainsaw import run_chainsaw


@pytest.fixture
def srum_db(tmp_path: Path) -> Path:
    path = tmp_path / "SRUDB.dat"
    path.write_bytes(b"\x00" * 16)
    return path


@pytest.fixture
def software_hive(tmp_path: Path) -> Path:
    path = tmp_path / "SOFTWARE"
    path.write_bytes(b"regf")
    return path


def _srum_argv(srum_db: Path, hive: Path) -> list[str]:
    """Run srum mode with Chainsaw mocked, and return the argv it built."""
    calls: list[list[str]] = []

    def _record(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.subprocess.run", side_effect=_record),
        patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
    ):
        run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
            str(srum_db),
            mode="srum",
            software_hive_path=str(hive),
        )

    assert calls, "Chainsaw was never invoked"
    return calls[0]


def test_srum_passes_the_required_software_hive(srum_db: Path, software_hive: Path) -> None:
    """``--software`` is mandatory; without it chainsaw 2.16.0 exits 2."""
    argv = _srum_argv(srum_db, software_hive)

    assert "--software" in argv, f"chainsaw 2.16.0 exits 2 on this argv: {argv}"
    assert argv[argv.index("--software") + 1] == str(software_hive)


def test_srum_does_not_pass_the_json_flag_it_rejects(srum_db: Path, software_hive: Path) -> None:
    """``analyse srum`` has no ``--json``; passing it is an immediate exit 2.

    The subcommand always writes JSON to ``--output``, so dropping the flag
    loses nothing -- ``_parse_chainsaw_srum_results`` still reads JSON.
    """
    argv = _srum_argv(srum_db, software_hive)

    assert "--json" not in argv, f"chainsaw rejects '--json' for analyse srum; argv was {argv}"
    assert "--output" in argv


def test_srum_never_reaches_chainsaw_carrying_json(srum_db: Path) -> None:
    """The ``--json`` defect, provable without the new parameter.

    Called the way unmodified ``main`` allows -- srum mode, no hive -- the old
    code builds ``analyse srum <db> --json --output <f>`` and hands it to
    chainsaw, which exits 2 on the unexpected ``--json``.  The fixed code never
    reaches ``subprocess.run`` at all, because it asks for the hive first.

    Either way the invariant is the same and is asserted directly: chainsaw is
    never invoked with a flag its ``analyse srum`` subcommand rejects.
    """
    calls: list[list[str]] = []

    def _record(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.subprocess.run", side_effect=_record),
        patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
    ):
        run_chainsaw.__wrapped__(str(srum_db), mode="srum")  # type: ignore[attr-defined]

    for argv in calls:
        assert "--json" not in argv, (
            f"chainsaw 2.16.0 exits 2 on 'analyse srum ... --json'; argv was {argv}"
        )


def test_the_srum_argv_matches_the_declared_usage(srum_db: Path, software_hive: Path) -> None:
    """Pins the whole shape: `analyse srum <db> --software <hive> --output <f>`."""
    argv = _srum_argv(srum_db, software_hive)

    assert argv[1:3] == ["analyse", "srum"]
    assert argv[3] == str(srum_db)
    assert set(argv[4:]) == {
        "--software",
        str(software_hive),
        "--output",
        argv[argv.index("--output") + 1],
    }


def test_a_missing_software_hive_is_reported_not_left_to_clap(srum_db: Path) -> None:
    """Chainsaw cannot guess the hive, so the analyst must be told to supply it."""
    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
    ):
        result: Any = run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
            str(srum_db), mode="srum"
        )

    assert result["status"] == "error"
    assert result["error_type"] == "invalid_argument"
    assert "software_hive_path" in str(result["error_message"])


def test_a_nonexistent_software_hive_is_reported(srum_db: Path, tmp_path: Path) -> None:
    """A supplied-but-absent hive is a file_not_found, not an opaque exit 2."""
    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
    ):
        result: Any = run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
            str(srum_db),
            mode="srum",
            software_hive_path=str(tmp_path / "absent" / "SOFTWARE"),
        )

    assert result["status"] == "error"
    assert result["error_type"] == "file_not_found"


def test_other_modes_keep_their_json_flag(tmp_path: Path) -> None:
    """Narrowness: ``--json`` is invalid only for ``analyse srum``.

    ``hunt``, ``search`` and ``timeline`` all accept ``-j/--json``; stripping it
    from them would be a new defect rather than a fix.
    """
    evidence = tmp_path / "evtx"
    evidence.mkdir()
    (evidence / "Security.evtx").write_bytes(b"ElfFile\x00")
    calls: list[list[str]] = []

    def _record(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.subprocess.run", side_effect=_record),
        patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
    ):
        run_chainsaw.__wrapped__(str(evidence), mode="timeline")  # type: ignore[attr-defined]

    assert calls
    assert "--json" in calls[0]
    assert "--software" not in calls[0]
