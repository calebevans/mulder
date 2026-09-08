"""Chainsaw hunt mode must pass the ``--mapping`` that ``--sigma`` requires.

``_run_chainsaw_hunt`` built ``chainsaw hunt <evidence> -s <sigma> --json
--output <file>``.  Chainsaw declares ``--mapping`` as a hard requirement of
``--sigma``, so clap rejects that command line before Chainsaw opens a single
log.  Verified against the pinned release, chainsaw 2.16.0::

    $ chainsaw hunt ./evidence -s ./sigma --json --output out.json
    error: the following required arguments were not provided:
      --mapping <MAPPING>
    Usage: chainsaw hunt --mapping <MAPPING> --sigma <SIGMA> --json \
        --output <OUTPUT> <RULES> [PATH]...
    (exit 2)

The requirement is not visible in ``chainsaw hunt --help``, which lists
``--mapping`` as an ordinary option -- it is enforced only at parse time.  Hunt
mode is Chainsaw's Sigma engine, so on current ``main`` it can never execute.

These tests deliberately do not import the new resolver, so that against
unmodified ``main`` they fail on the missing flag rather than on an ImportError.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import mulder.server.tools.chainsaw as chainsaw_mod
from mulder.server.tools.chainsaw import run_chainsaw


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    """An evidence directory holding one EVTX file, so the run reaches Chainsaw."""
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"ElfFile\x00")
    return tmp_path


@pytest.fixture
def rules(tmp_path: Path) -> Path:
    path = tmp_path / "sigma"
    path.mkdir()
    return path


@pytest.fixture
def mapping(tmp_path: Path) -> Path:
    """Stands in for the mapping ``mulder setup`` provisions."""
    path = tmp_path / "mappings" / "sigma-event-logs-all.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\n")
    return path


def _run_mode(evidence: Path, mode: str, rules: Path, mapping: Path) -> list[list[str]]:
    """Run *mode* with Chainsaw mocked; return every argv it built.

    ``asset_display_path`` is patched rather than the new resolver, so this
    helper works identically against fixed and unfixed code.
    """
    calls: list[list[str]] = []

    def _record(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    def _assets(*parts: str) -> Path:
        if "mappings" in parts:
            return mapping
        return rules

    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.asset_display_path", side_effect=_assets),
        patch("mulder.server.tools.chainsaw.subprocess.run", side_effect=_record),
        patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
    ):
        run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
            str(evidence),
            mode=mode,
            sigma_rules_path=str(rules),
        )

    assert calls, "Chainsaw was never invoked"
    return calls


def test_hunt_passes_the_mapping_that_sigma_requires(
    evidence: Path, rules: Path, mapping: Path
) -> None:
    """The exact argv defect: ``--sigma`` present, ``--mapping`` absent.

    Against unmodified ``main`` this argv makes chainsaw 2.16.0 exit 2.
    """
    argv = _run_mode(evidence, "hunt", rules, mapping)[0]

    assert "--mapping" in argv, f"chainsaw 2.16.0 exits 2 on this argv: {argv}"
    assert argv[argv.index("--mapping") + 1] == str(mapping)


def test_the_mapping_accompanies_the_sigma_flag(
    evidence: Path, rules: Path, mapping: Path
) -> None:
    """Pins the coupling, not merely the presence of a flag.

    ``--mapping`` is required *because* ``-s/--sigma`` is passed, so a later
    edit that keeps one and drops the other reintroduces the bug.
    """
    argv = _run_mode(evidence, "hunt", rules, mapping)[0]

    assert "-s" in argv
    assert argv[argv.index("-s") + 1] == str(rules)
    assert "--mapping" in argv


def test_the_default_mapping_is_one_the_chainsaw_asset_provides(
    evidence: Path, rules: Path, mapping: Path
) -> None:
    """The mapping must be looked up inside the chainsaw asset's mappings/.

    ``mappings/sigma-event-logs-all.yml`` ships in the 2.16.0 release tarball
    and is also listed in the asset's ``supplement_paths``.
    """
    seen: list[tuple[str, ...]] = []

    def _assets(*parts: str) -> Path:
        seen.append(parts)
        return mapping if "mappings" in parts else rules

    def _record(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.asset_display_path", side_effect=_assets),
        patch("mulder.server.tools.chainsaw.subprocess.run", side_effect=_record),
        patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
    ):
        run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
            str(evidence), mode="hunt", sigma_rules_path=str(rules)
        )

    assert ("chainsaw", "mappings", "sigma-event-logs-all.yml") in seen, (
        f"the mapping was not resolved from the chainsaw asset; lookups were {seen}"
    )


def test_a_missing_mapping_is_reported_not_left_to_clap(
    evidence: Path, rules: Path, tmp_path: Path
) -> None:
    """Without the asset, the analyst gets a real message and a fix.

    Otherwise Chainsaw exits 2 with a clap error the wrapper never reads.
    """
    absent = tmp_path / "does-not-exist" / "sigma-event-logs-all.yml"

    def _assets(*parts: str) -> Path:
        return absent if "mappings" in parts else rules

    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.asset_display_path", side_effect=_assets),
        patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
    ):
        result: Any = run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
            str(evidence), mode="hunt", sigma_rules_path=str(rules)
        )

    assert result["status"] == "error"
    assert result["error_type"] == "file_not_found"
    assert "mapping" in str(result["error_message"]).lower()
    assert "mulder setup" in str(result["suggestion"])


def test_timeline_mode_does_not_get_a_mapping(evidence: Path, rules: Path, mapping: Path) -> None:
    """Narrowness: only hunt passes ``--sigma``, so only hunt needs a mapping.

    ``timeline`` loads no Sigma rules; adding ``--mapping`` there would be a new
    argv defect rather than a fix.
    """
    argv = _run_mode(evidence, "timeline", rules, mapping)[0]

    assert "--mapping" not in argv
    assert "-s" not in argv


def test_the_resolver_exists_and_names_the_shipped_mapping() -> None:
    """The helper itself, once present, must name the file the asset ships."""
    resolver = getattr(chainsaw_mod, "_default_chainsaw_mapping", None)
    assert resolver is not None, "_default_chainsaw_mapping is missing"
    path = resolver()
    assert path.name == "sigma-event-logs-all.yml"
    assert path.parent.name == "mappings"
