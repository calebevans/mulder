"""Regression tests for the argv mulder hands to each wrapped forensic tool.

Every assertion below was checked against the pinned release of the tool
(``src/mulder/assets/manifest.py``) by running the real binary:

* ``chainsaw 2.16.0`` -- ``hunt -s <rules>`` without ``--mapping`` exits 2
  ("the following required arguments were not provided: --mapping");
  ``analyse srum`` requires ``--software`` and has no ``--json``;
  ``dump`` has no ``--from`` / ``--to``.
* ``hayabusa 3.8.1`` -- ``csv-timeline -o <existing file>`` refuses to run
  **and exits 0**, so only ``--clobber`` (or an absent path) makes it work.
* ``capa 9.4.0`` / ``floss 3.1.0`` -- ``--format`` selects the *sample*
  format; ``--format json`` is an invalid choice and both exit 2.
* ``Zircolite 2.20.0`` -- has no ``--json`` flag at all; JSON is the default.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


def _completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


class TestZircoliteArgv:
    def test_no_json_flag(self, tmp_path: Path) -> None:
        from mulder.server.tools.zircolite import _run_zircolite_process

        with patch(
            "mulder.server.tools.zircolite.subprocess.run", return_value=_completed()
        ) as run:
            _run_zircolite_process(
                "zircolite.py", tmp_path, "evtx", tmp_path / "rules.json", tmp_path
            )

        argv = run.call_args[0][0]
        assert "--json" not in argv, "Zircolite 2.20.0 has no --json flag; argparse exits 2"
        assert "--events" in argv
        assert "--ruleset" in argv
        assert "--outfile" in argv


class TestCapaFlossArgv:
    def test_capa_uses_json_not_format_json(self) -> None:
        source = Path("src/mulder/server/tools/binary.py").read_text()
        assert '[capa_bin, "--json", "--quiet"]' in source
        assert '"--format",\n        "json"' not in source

    def test_floss_excludes_static_with_no_static(self) -> None:
        source = Path("src/mulder/server/tools/binary.py").read_text()
        # A bare `--only` is nargs="+" and swallowed the sample path.
        assert 'cmd.extend(["--no", "static"])' in source
        assert 'cmd.append("--only")' not in source


class TestChainsawArgv:
    @staticmethod
    def _run(tmp_path: Path, **kwargs: Any) -> tuple[dict[str, object], list[str] | None]:
        from mulder.server.tools.chainsaw import run_chainsaw

        binary = tmp_path / "chainsaw"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        mapping = tmp_path / "mappings" / "sigma-event-logs-all.yml"
        mapping.parent.mkdir(parents=True, exist_ok=True)
        mapping.write_text("")
        evidence = tmp_path / "evtx"
        evidence.mkdir(exist_ok=True)

        with (
            patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=str(binary)),
            patch("mulder.server.tools.chainsaw._default_chainsaw_mapping", return_value=mapping),
            patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
            patch("mulder.server.tools.chainsaw.subprocess.run", return_value=_completed()) as run,
        ):
            result = run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
                str(evidence), **kwargs
            )
        argv = list(run.call_args[0][0]) if run.call_args else None
        return result, argv

    def test_hunt_passes_mapping(self, tmp_path: Path) -> None:
        _, argv = self._run(tmp_path, mode="hunt")
        assert argv is not None
        assert "--mapping" in argv

    def test_hunt_errors_when_mapping_asset_is_absent(self, tmp_path: Path) -> None:
        from mulder.server.tools.chainsaw import run_chainsaw

        binary = tmp_path / "chainsaw"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        evidence = tmp_path / "evtx"
        evidence.mkdir()

        with (
            patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=str(binary)),
            patch(
                "mulder.server.tools.chainsaw._default_chainsaw_mapping",
                return_value=tmp_path / "nope.yml",
            ),
        ):
            result = run_chainsaw.__wrapped__(str(evidence))  # type: ignore[attr-defined]

        assert result["error_type"] == "asset_missing"

    def test_srum_requires_software_hive(self, tmp_path: Path) -> None:
        result, argv = self._run(tmp_path, mode="srum")
        assert result["error_type"] == "invalid_argument"
        assert "software_hive" in str(result["error_message"])
        assert argv is None, "chainsaw must not be executed without --software"

    def test_srum_passes_software_and_no_json(self, tmp_path: Path) -> None:
        hive = tmp_path / "SOFTWARE"
        hive.write_bytes(b"regf")
        _, argv = self._run(tmp_path, mode="srum", software_hive=str(hive))
        assert argv is not None
        assert "--software" in argv
        assert str(hive) in argv
        assert "--json" not in argv, "chainsaw analyse srum has no --json flag"

    def test_timeline_rejects_a_time_range(self, tmp_path: Path) -> None:
        result, argv = self._run(tmp_path, mode="timeline", time_range_start="2024-01-01T00:00:00")
        assert result["error_type"] == "invalid_argument"
        assert argv is None

    def test_timeline_without_a_range_passes_no_from_to(self, tmp_path: Path) -> None:
        _, argv = self._run(tmp_path, mode="timeline")
        assert argv is not None
        assert "--from" not in argv
        assert "--to" not in argv


class TestHayabusaArgv:
    def test_clobber_is_passed_and_output_path_is_fresh(self, tmp_path: Path) -> None:
        from mulder.server.tools import hayabusa as hb

        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        (evtx_dir / "a.evtx").write_bytes(b"ElfFile\x00")
        binary = tmp_path / "hayabusa"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)

        seen: dict[str, Any] = {}

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            seen["argv"] = cmd
            out = Path(cmd[cmd.index("-o") + 1])
            seen["existed_before"] = out.exists()
            out.write_text("Timestamp,RuleTitle\n")
            return _completed()

        with (
            patch.object(hb, "_hayabusa_binary", return_value=str(binary)),
            patch.object(hb, "_resolve_evtx_dir", return_value=str(evtx_dir)),
            patch.object(hb, "sources_already_indexed", return_value=[]),
            patch.object(hb, "extract_and_index", return_value={}),
            patch.object(hb.subprocess, "run", side_effect=fake_run),
        ):
            hb.run_hayabusa.__wrapped__(str(evtx_dir))  # type: ignore[attr-defined]

        assert "--clobber" in seen["argv"]
        assert seen["existed_before"] is False, (
            "hayabusa refuses to overwrite an existing -o path and exits 0 while doing so"
        )

    def test_missing_output_file_is_an_error_not_zero_alerts(self, tmp_path: Path) -> None:
        from mulder.server.tools import hayabusa as hb

        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        (evtx_dir / "a.evtx").write_bytes(b"ElfFile\x00")
        binary = tmp_path / "hayabusa"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)

        # The real refusal: exit 0, nothing written.
        with (
            patch.object(hb, "_hayabusa_binary", return_value=str(binary)),
            patch.object(hb, "_resolve_evtx_dir", return_value=str(evtx_dir)),
            patch.object(hb, "sources_already_indexed", return_value=[]),
            patch.object(hb, "extract_and_index", return_value={}),
            patch.object(
                hb.subprocess,
                "run",
                return_value=_completed(stdout="[ERROR] The file already exists."),
            ),
        ):
            result = hb.run_hayabusa.__wrapped__(str(evtx_dir))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert result.get("total_alerts") != 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__]))
