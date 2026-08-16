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
from unittest.mock import MagicMock, patch

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


class TestChainsaw:
    def test_execs_the_binary_the_gate_found(self, tmp_path: Path) -> None:
        from mulder.server.tools.chainsaw import run_chainsaw

        chainsaw = _fake_binary(tmp_path, "chainsaw")
        evidence = tmp_path / "evtx"
        evidence.mkdir()

        with (
            patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=str(chainsaw)),
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

        with (
            patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=None),
            patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
            patch(
                "mulder.server.tools.chainsaw.subprocess.run", return_value=_completed()
            ) as mock_run,
        ):
            run_chainsaw.__wrapped__(str(asset_root))  # type: ignore[attr-defined]

        assert mock_run.call_args[0][0][0] == str(binary)

    def test_empty_sigma_path_resolves_to_the_installed_rules(self, asset_root: Path) -> None:
        """The tool schema must not freeze one machine's path (FastMCP reads the default)."""
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

        with (
            patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=None),
            patch("mulder.server.tools.chainsaw.extract_and_index", return_value={}),
            patch(
                "mulder.server.tools.chainsaw.subprocess.run", return_value=_completed()
            ) as mock_run,
        ):
            run_chainsaw.__wrapped__(str(asset_root))  # type: ignore[attr-defined]

        assert str(rules) in mock_run.call_args[0][0]


class TestZeek:
    def test_execs_the_binary_the_gate_found(self, tmp_path: Path) -> None:
        from mulder.server.tools.extract.pcap import run_zeek_analysis

        zeek = _fake_binary(tmp_path, "zeek")
        pcap = tmp_path / "capture.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1")

        with (
            patch(
                "mulder.server.helpers.shutil.which",
                side_effect=lambda name: str(zeek) if name == "zeek" else None,
            ),
            patch("mulder.server.tools.extract.pcap.extract_and_index", return_value={}),
            patch(
                "mulder.server.tools.extract.pcap.subprocess.run", return_value=_completed()
            ) as mock_run,
        ):
            result = run_zeek_analysis.__wrapped__(str(pcap))  # type: ignore[attr-defined]

        assert result.get("error_type") != "binary_missing"
        assert mock_run.call_args[0][0][0] == str(zeek)

    def test_missing_reports_binary_missing(self, tmp_path: Path) -> None:
        from mulder.server.tools.extract.pcap import run_zeek_analysis

        with patch("mulder.server.helpers.shutil.which", return_value=None):
            result = run_zeek_analysis.__wrapped__(str(tmp_path / "x.pcap"))  # type: ignore[attr-defined]

        assert result["error_type"] == "binary_missing"


class TestSuricata:
    def test_execs_the_binary_the_gate_found(self, tmp_path: Path) -> None:
        from mulder.server.tools.extract.pcap import run_suricata

        suricata = _fake_binary(tmp_path, "suricata")
        pcap = tmp_path / "capture.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1")

        with (
            patch(
                "mulder.server.helpers.shutil.which",
                side_effect=lambda name: str(suricata) if name == "suricata" else None,
            ),
            patch("mulder.server.tools.extract.pcap.extract_and_index", return_value={}),
            patch(
                "mulder.server.tools.extract.pcap.subprocess.run", return_value=_completed()
            ) as mock_run,
        ):
            result = run_suricata.__wrapped__(str(pcap))  # type: ignore[attr-defined]

        assert result.get("error_type") != "binary_missing"
        assert mock_run.call_args[0][0][0] == str(suricata)

    def test_disk_pcap_path_uses_the_resolved_binary_too(self, tmp_path: Path) -> None:
        """The same divergence lived a second time in the disk-image PCAP path."""
        from mulder.server.tools.extract.disk_pcap import _analyze_single_pcap

        suricata = _fake_binary(tmp_path, "suricata")
        pcap = tmp_path / "extracted.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1")

        with (
            patch(
                "mulder.server.helpers.shutil.which",
                side_effect=lambda name: str(suricata) if name == "suricata" else None,
            ),
            patch("mulder.server.tools.extract.disk_pcap._run_tshark_summary", return_value=""),
            patch(
                "mulder.server.tools.extract.pcap.subprocess.run", return_value=_completed()
            ) as mock_run,
            patch("mulder.server.tools.extract.pcap._parse_eve_json", return_value=_eve_stub()),
        ):
            _analyze_single_pcap(
                pcap,
                "extracted.pcap",
                "case",
                run_ids=True,
                extract_credentials=False,
                image_path="/evidence/disk.E01",
            )

        assert mock_run.call_args[0][0][0] == str(suricata)


def _eve_stub() -> dict[str, Any]:
    return {"statistics": {"total_alerts": 0, "top_signatures": []}}


class TestHayabusa:
    def test_asset_root_wins_over_path(self, asset_root: Path) -> None:
        from mulder.server.tools.hayabusa import _hayabusa_binary

        installed = asset_root / "hayabusa"
        installed.mkdir()
        binary = installed / "hayabusa"
        binary.write_text("")
        binary.chmod(0o755)

        with patch("mulder.server.tools.hayabusa.shutil.which", return_value="/usr/bin/hayabusa"):
            assert _hayabusa_binary() == str(binary)

    def test_falls_back_to_path(self, asset_root: Path) -> None:
        from mulder.server.tools.hayabusa import _hayabusa_binary

        with patch("mulder.server.tools.hayabusa.shutil.which", return_value="/usr/bin/hayabusa"):
            assert _hayabusa_binary() == "/usr/bin/hayabusa"

    def test_missing_reports_binary_missing(self, asset_root: Path) -> None:
        from mulder.server.tools.hayabusa import run_hayabusa

        with (
            patch("mulder.server.tools.hayabusa.sources_already_indexed", return_value=[]),
            patch("mulder.server.tools.hayabusa.shutil.which", return_value=None),
        ):
            result = run_hayabusa.__wrapped__(evtx_dir=str(asset_root))  # type: ignore[attr-defined]

        assert result["error_type"] == "binary_missing"
        assert "mulder setup" in str(result["error_message"])


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


def test_mocks_are_wired_the_way_the_helpers_resolve() -> None:
    """Guard the guard: ``require_binary`` must really be ``shutil.which``."""
    from mulder.server import helpers

    with patch("mulder.server.helpers.shutil.which", MagicMock(return_value="/x")) as which:
        assert helpers.require_binary("anything") == "/x"
    which.assert_called_once_with("anything")
