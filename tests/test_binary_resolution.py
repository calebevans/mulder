"""One property, over every tool that shells out to an external binary:

**the binary the gate accepted is the binary that gets exec'd.**

Four tools got this wrong in the same way -- gate with ``shutil.which``, then
discard the answer and exec a hardcoded absolute path.  The user-visible
symptom is not "not installed"; it is ``os_error: [Errno 2]`` from
``subprocess.run``, which reads as a transient glitch, so the tool silently
never runs.  These tests fail against the pre-fix code for ``chainsaw``,
``zeek``, ``suricata`` and the disk-image PCAP path.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


def _fake_binary(tmp_path: Path, name: str) -> Path:
    """An executable in a directory no tool hardcodes."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    target = bin_dir / name
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o755)
    return target


def _completed(**kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")


def _fake_mapping(root: Path) -> Path:
    """chainsaw hunt refuses to start without --mapping; give it a real file."""
    mapping = root / "chainsaw_mappings" / "sigma-event-logs-all.yml"
    mapping.parent.mkdir(parents=True, exist_ok=True)
    mapping.write_text("")
    return mapping


class TestChainsaw:
    def test_execs_the_binary_the_gate_found(self, tmp_path: Path) -> None:
        from mulder.server.tools.chainsaw import run_chainsaw

        chainsaw = _fake_binary(tmp_path, "chainsaw")
        evidence = tmp_path / "evtx"
        evidence.mkdir()
        mapping = _fake_mapping(tmp_path)

        with (
            patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=str(chainsaw)),
            patch(
                "mulder.server.tools.chainsaw._default_chainsaw_mapping",
                return_value=mapping,
            ),
            patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
            patch(
                "mulder.server.tools.chainsaw.subprocess.run", return_value=_completed()
            ) as mock_run,
        ):
            result = run_chainsaw.__wrapped__(str(evidence))  # type: ignore[attr-defined]

        assert result.get("error_type") != "binary_missing"
        assert mock_run.call_args[0][0][0] == str(chainsaw)

    def test_missing_everywhere_is_binary_missing_not_os_error(self, tmp_path: Path) -> None:
        """The distinction the agent acts on: install me vs. something broke."""
        from mulder.server.tools.chainsaw import run_chainsaw

        with (
            patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=None),
        ):
            result = run_chainsaw.__wrapped__(str(tmp_path))  # type: ignore[attr-defined]

        assert result["error_type"] == "binary_missing"
        assert "mulder setup" in str(result["suggestion"])

    def test_asset_root_copy_is_used_when_path_is_empty(self, asset_root: Path) -> None:
        from mulder.server.tools.chainsaw import run_chainsaw

        installed = asset_root / "chainsaw"
        installed.mkdir()
        binary = installed / "chainsaw"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        mapping = _fake_mapping(asset_root)

        with (
            patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=None),
            patch(
                "mulder.server.tools.chainsaw._default_chainsaw_mapping",
                return_value=mapping,
            ),
            patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
            patch(
                "mulder.server.tools.chainsaw.subprocess.run", return_value=_completed()
            ) as mock_run,
        ):
            run_chainsaw.__wrapped__(str(asset_root))  # type: ignore[attr-defined]

        assert mock_run.call_args[0][0][0] == str(binary)

    def test_empty_sigma_path_resolves_to_the_installed_rules(self, asset_root: Path) -> None:
        """The tool schema must not freeze one machine's path (MCPServer reads the default)."""
        import inspect

        from mulder.server.tools.chainsaw import run_chainsaw

        signature = inspect.signature(run_chainsaw.__wrapped__)  # type: ignore[attr-defined]
        assert signature.parameters["sigma_rules_path"].default == ""

        rules = asset_root / "sigma-rules" / "rules" / "windows"
        rules.mkdir(parents=True)
        chainsaw = asset_root / "chainsaw"
        chainsaw.mkdir()
        (chainsaw / "chainsaw").write_text("")
        (chainsaw / "chainsaw").chmod(0o755)
        mappings = chainsaw / "mappings"
        mappings.mkdir()
        (mappings / "sigma-event-logs-all.yml").write_text("")

        with (
            patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=None),
            patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
            patch(
                "mulder.server.tools.chainsaw.subprocess.run", return_value=_completed()
            ) as mock_run,
        ):
            run_chainsaw.__wrapped__(str(asset_root))  # type: ignore[attr-defined]

        argv = mock_run.call_args[0][0]
        assert str(rules) in argv
        # chainsaw treats --mapping as required whenever Sigma rules are given.
        assert "--mapping" in argv
        assert str(mappings / "sigma-event-logs-all.yml") in argv


def _eve_stub() -> dict[str, Any]:
    return {"statistics": {"total_alerts": 0, "top_signatures": []}}


@pytest.mark.parametrize(
    ("name", "module", "attribute"),
    [
        ("capa", "mulder.server.tools.binary", "_CAPA_BINARY"),
        ("floss", "mulder.server.tools.binary", "_FLOSS_BINARY"),
        ("diec", "mulder.server.tools.binary", "_DIEC_BINARY"),
        ("readpst", "mulder.server.tools.email", "_READPST_BINARY"),
    ],
)
def test_platform_tools_keep_their_already_correct_pattern(
    name: str, module: str, attribute: str
) -> None:
    """These four resolve, gate and exec the same local -- do not "simplify"."""
    import importlib

    mod = importlib.import_module(module)
    source = Path(mod.__file__ or "").read_text(encoding="utf-8")

    assert f'require_binary("{name}")' in source
    assert getattr(mod, attribute).startswith("/")


def test_no_tool_execs_a_module_level_binary_constant() -> None:
    """The shape that produced all four bugs: a constant used as ``cmd[0]``.

    A module-level absolute path may be a *fallback*; it may not be the thing
    handed to ``subprocess.run`` while a different value was gated on.
    """
    from mulder.server.tools.extract import pcap

    source = Path(pcap.__file__ or "").read_text(encoding="utf-8")

    assert "        _ZEEK_BINARY,\n" not in source
    assert "        _SURICATA_BINARY,\n" not in source
