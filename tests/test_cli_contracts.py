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

import argparse
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


def _floss_parser() -> argparse.ArgumentParser:
    """floss 3.1.0's parser, for the options mulder passes.

    Mirrors floss/main.py v3.1.0: `-n/--minimum-length`, a positional
    `sample`, `--no`/`--only` as ``action="extend", nargs="+"`` over
    ``{static,stack,tight,decoded}``, `-f/--format` over
    ``{auto,pe,sc32,sc64}`` and `-j/--json`. Parsing mulder's argv with it
    is what catches a flag rename that argparse would still reject.
    """

    class _Extend(argparse.Action):
        def __call__(  # type: ignore[override]
            self,
            parser: argparse.ArgumentParser,
            namespace: argparse.Namespace,
            values: Any,
            option_string: str | None = None,
        ) -> None:
            items = list(getattr(namespace, self.dest, None) or [])
            items.extend(values)
            setattr(namespace, self.dest, items)

    types = ["static", "stack", "tight", "decoded"]
    parser = argparse.ArgumentParser(prog="floss", add_help=False)
    parser.register("action", "extend", _Extend)
    parser.add_argument("-n", "--minimum-length", dest="min_length", type=int, default=4)
    parser.add_argument("sample")
    parser.add_argument(
        "--no", action="extend", dest="disabled_types", nargs="+", choices=types, default=[]
    )
    parser.add_argument(
        "--only", action="extend", dest="enabled_types", nargs="+", choices=types, default=[]
    )
    parser.add_argument("-f", "--format", choices=["auto", "pe", "sc32", "sc64"], default="auto")
    parser.add_argument("-j", "--json", action="store_true")
    return parser


def _capa_parser() -> argparse.ArgumentParser:
    """capa 9.4.0's parser, for the options mulder passes."""
    parser = argparse.ArgumentParser(prog="capa", add_help=False)
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument(
        "-f",
        "--format",
        choices=["auto", "pe", "dotnet", "elf", "sc32", "sc64", "cape", "freeze"],
        default="auto",
    )
    parser.add_argument("-r", "--rules", action="append", default=[])
    parser.add_argument("sample")
    return parser


class TestCapaFlossArgv:
    """Parse mulder's argv with each tool's own parser, not with a substring."""

    @staticmethod
    def _argv(tool: str, tmp_path: Path, **kwargs: Any) -> list[str]:
        from mulder.server.tools import binary as b

        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"MZ\x90\x00")
        fake = tmp_path / tool
        fake.write_text("#!/bin/sh\n")
        fake.chmod(0o755)

        with (
            patch.object(b, "require_binary", return_value=str(fake)),
            patch.object(b, "extract_and_index", return_value={}),
            patch.object(b.subprocess, "run", return_value=_completed(stdout="{}")) as run,
        ):
            fn = b.run_capa if tool == "capa" else b.run_floss
            fn.__wrapped__("case", str(sample), **kwargs)  # type: ignore[attr-defined]
        return list(run.call_args[0][0])

    def test_capa_argv_parses(self, tmp_path: Path) -> None:
        argv = self._argv("capa", tmp_path)
        # capa's --format takes a *sample* format; "--format json" exits 2.
        assert "--format" not in argv
        _capa_parser().parse_args(argv[1:])

    def test_floss_argv_parses_with_static_strings(self, tmp_path: Path) -> None:
        argv = self._argv("floss", tmp_path, include_static=True)
        ns = _floss_parser().parse_args(argv[1:])
        assert ns.json is True
        assert ns.disabled_types == []

    def test_floss_argv_parses_without_static_strings(self, tmp_path: Path) -> None:
        argv = self._argv("floss", tmp_path, include_static=False)
        ns = _floss_parser().parse_args(argv[1:])
        assert ns.disabled_types == ["static"]
        assert ns.sample.endswith("sample.bin")

    def test_floss_sample_precedes_the_type_flags(self, tmp_path: Path) -> None:
        """`--no static <sample>` still exits 2: nargs="+" eats the path."""
        argv = self._argv("floss", tmp_path, include_static=False)
        assert argv.index("--no") > argv.index(next(a for a in argv if a.endswith("sample.bin")))


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
