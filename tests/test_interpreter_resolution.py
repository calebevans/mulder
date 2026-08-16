"""Tests for helper-interpreter resolution across the shell-out tool modules.

mulder runs several helper Python programs by shelling out. Under
``pipx install`` / ``uv tool install`` a bare ``python3`` on PATH is *not*
mulder's interpreter and cannot see mulder's dependencies, so every one of
these call sites either uses ``sys.executable`` outright (when mulder owns
the dependency) or probes it first (when someone else owns it).

These tests pin both halves of that split: the sites that must switch, and
the PATH fallbacks that must survive so a native SIFT install keeps working.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.extractors.volatility import _find_vol_binary
from mulder.server.helpers import interpreter_candidates
from mulder.server.tools.documents import _analyze_macros_olevba
from mulder.server.tools.extract.plaso import _find_plaso_cmd
from mulder.server.tools.hindsight import _find_hindsight_cmd
from mulder.server.tools.phone import _ALEAPP_SCRIPT, _ILEAPP_SCRIPT
from mulder.server.tools.zircolite import (
    _ZIRCOLITE_MODULES,
    _run_zircolite_process,
)

_FAKE_PY = "/usr/bin/python3"


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> Any:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _only_interpreters(name: str) -> str | None:
    """A PATH with a python3 on it and nothing else.

    ``shutil`` is a single module object, so a patch on any importer's
    ``shutil.which`` is a patch on all of them — one discriminating
    side_effect is the only way to control both the script lookups and
    ``interpreter_candidates`` in the same test.
    """
    return _FAKE_PY if name in ("python3", "python") else None


# ---------------------------------------------------------------------------
# interpreter_candidates
# ---------------------------------------------------------------------------


class TestInterpreterCandidates:
    """Ordering, deduplication, and missing-interpreter handling."""

    def test_prefers_sys_executable(self) -> None:
        with patch("mulder.server.helpers.shutil.which", return_value=_FAKE_PY):
            assert interpreter_candidates()[0] == sys.executable

    def test_dedupes(self) -> None:
        with patch("mulder.server.helpers.shutil.which", return_value=sys.executable):
            assert interpreter_candidates() == [sys.executable]

    def test_drops_missing(self) -> None:
        with patch("mulder.server.helpers.shutil.which", return_value=None):
            assert interpreter_candidates() == [sys.executable]

    def test_includes_path_interpreters_after_sys_executable(self) -> None:
        with patch("mulder.server.helpers.shutil.which", return_value=_FAKE_PY):
            assert interpreter_candidates() == [sys.executable, _FAKE_PY]


# ---------------------------------------------------------------------------
# _find_vol_binary
# ---------------------------------------------------------------------------


class TestFindVolBinary:
    """Volatility 3 CLI resolution.

    volatility3 ships no ``__main__``, so ``python -m volatility3`` must
    never be returned — the console script is the only real CLI. A platform
    ``vol`` must outrank the venv-local one, because mulder never passes
    ``-s`` and only the platform install can see the platform's ISF symbol
    packs.
    """

    def test_path_vol_outranks_venv_local_script(self) -> None:
        """SIFT's /usr/local/bin/vol wins over mulder's own venv copy."""
        with (
            patch("mulder.extractors.volatility.os.access", return_value=True),
            patch(
                "mulder.extractors.volatility.shutil.which",
                return_value="/usr/local/bin/vol",
            ),
        ):
            assert _find_vol_binary() == ["vol"]

    def test_falls_back_to_venv_local_script(self) -> None:
        """With no vol on PATH, the pipx/uv-tool venv copy is the last resort."""
        expected = str(Path(sys.executable).with_name("vol"))
        with (
            patch("mulder.extractors.volatility.os.access", return_value=True),
            patch("mulder.extractors.volatility.shutil.which", return_value=None),
        ):
            assert _find_vol_binary() == [expected]

    def test_venv_local_script_must_be_executable(self) -> None:
        """A non-executable vol in the venv bin is not a usable command."""
        with (
            patch("mulder.extractors.volatility.os.access", return_value=False),
            patch("mulder.extractors.volatility.shutil.which", return_value=None),
            patch(
                "mulder.extractors.volatility.importlib.util.find_spec",
                return_value=MagicMock(),
            ),
        ):
            assert _find_vol_binary()[0] == sys.executable

    def test_falls_back_to_path_vol(self) -> None:
        with (
            patch("mulder.extractors.volatility.os.access", return_value=False),
            patch(
                "mulder.extractors.volatility.shutil.which",
                side_effect=lambda n: "/usr/local/bin/vol" if n == "vol" else None,
            ),
        ):
            assert _find_vol_binary() == ["vol"]

    def test_falls_back_to_vol3(self) -> None:
        with (
            patch("mulder.extractors.volatility.os.access", return_value=False),
            patch(
                "mulder.extractors.volatility.shutil.which",
                side_effect=lambda n: "/usr/local/bin/vol3" if n == "vol3" else None,
            ),
        ):
            assert _find_vol_binary() == ["vol3"]

    def test_falls_back_to_entry_point(self) -> None:
        with (
            patch("mulder.extractors.volatility.os.access", return_value=False),
            patch("mulder.extractors.volatility.shutil.which", return_value=None),
            patch(
                "mulder.extractors.volatility.importlib.util.find_spec",
                return_value=MagicMock(),
            ),
        ):
            assert _find_vol_binary() == [
                sys.executable,
                "-c",
                "from volatility3.cli import main; main()",
            ]

    def test_never_returns_dash_m_volatility3(self) -> None:
        """``python -m volatility3`` is not a runnable command at any tier."""
        for access, which, spec in (
            (True, "/usr/local/bin/vol", MagicMock()),
            (False, "/usr/local/bin/vol", MagicMock()),
            (True, None, MagicMock()),
            (False, None, MagicMock()),
        ):
            with (
                patch("mulder.extractors.volatility.os.access", return_value=access),
                patch("mulder.extractors.volatility.shutil.which", return_value=which),
                patch(
                    "mulder.extractors.volatility.importlib.util.find_spec",
                    return_value=spec,
                ),
            ):
                assert _find_vol_binary()[:3] != [sys.executable, "-m", "volatility3"]

    def test_raises_when_nothing_found(self) -> None:
        with (
            patch("mulder.extractors.volatility.os.access", return_value=False),
            patch("mulder.extractors.volatility.shutil.which", return_value=None),
            patch(
                "mulder.extractors.volatility.importlib.util.find_spec",
                return_value=None,
            ),
            pytest.raises(RuntimeError),
        ):
            _find_vol_binary()

    @pytest.mark.skipif(
        importlib.util.find_spec("volatility3") is None,
        reason="volatility3 is not installed in this environment",
    )
    def test_resolved_command_actually_runs(self) -> None:
        """The resolved command must execute — unit tests alone go green on a
        command that does not exist."""
        subprocess.run(
            [*_find_vol_binary(), "--help"],
            capture_output=True,
            timeout=120,
            check=True,
        )


# ---------------------------------------------------------------------------
# _find_plaso_cmd / _find_hindsight_cmd — Class B, PATH fallback must survive
# ---------------------------------------------------------------------------


class TestFindPlasoCmd:
    """plaso is not a mulder dependency; the PATH fallback is load-bearing."""

    def test_prefers_path_script(self) -> None:
        with (
            patch(
                "mulder.server.tools.extract.plaso.shutil.which",
                side_effect=lambda n: "/usr/bin/psort.py" if n == "psort.py" else None,
            ),
            patch("mulder.server.tools.extract.plaso.subprocess.run") as mock_run,
        ):
            assert _find_plaso_cmd("psort") == ["/usr/bin/psort.py"]
            mock_run.assert_not_called()

    def test_probes_sys_executable_first(self) -> None:
        with (
            patch(
                "mulder.server.tools.extract.plaso.shutil.which",
                side_effect=_only_interpreters,
            ),
            patch(
                "mulder.server.tools.extract.plaso.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
        ):
            assert _find_plaso_cmd("psort") == [sys.executable, "-m", "plaso.cli.psort"]
            assert mock_run.call_args[0][0][0] == sys.executable

    def test_falls_through_to_path_python(self) -> None:
        """A pipx venv without plaso must still find the system interpreter."""

        def _run(cmd: list[str], **_: object) -> Any:
            if cmd[0] == sys.executable:
                raise subprocess.CalledProcessError(1, cmd)
            return _completed()

        with (
            patch(
                "mulder.server.tools.extract.plaso.shutil.which",
                side_effect=_only_interpreters,
            ),
            patch("mulder.server.tools.extract.plaso.subprocess.run", side_effect=_run),
        ):
            assert _find_plaso_cmd("psort") == [_FAKE_PY, "-m", "plaso.cli.psort"]

    def test_returns_none_when_all_probes_fail(self) -> None:
        with (
            patch(
                "mulder.server.tools.extract.plaso.shutil.which",
                side_effect=_only_interpreters,
            ),
            patch(
                "mulder.server.tools.extract.plaso.subprocess.run",
                side_effect=OSError("boom"),
            ),
        ):
            assert _find_plaso_cmd("psort") is None


class TestFindHindsightCmd:
    """pyhindsight lives in a separate venv on SIFT and in mulder's env in Docker."""

    def test_prefers_path_script(self) -> None:
        with (
            patch(
                "mulder.server.tools.hindsight.shutil.which",
                side_effect=lambda n: (
                    "/usr/local/bin/hindsight.py" if n == "hindsight.py" else None
                ),
            ),
            patch("mulder.server.tools.hindsight.subprocess.run") as mock_run,
        ):
            assert _find_hindsight_cmd() == ["hindsight.py"]
            mock_run.assert_not_called()

    def test_probes_sys_executable_first(self) -> None:
        with (
            patch(
                "mulder.server.tools.hindsight.shutil.which",
                side_effect=_only_interpreters,
            ),
            patch(
                "mulder.server.tools.hindsight.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
        ):
            assert _find_hindsight_cmd() == [sys.executable, "-m", "pyhindsight.hindsight"]
            assert mock_run.call_args[0][0][0] == sys.executable

    def test_falls_through_to_path_python(self) -> None:
        def _run(cmd: list[str], **_: object) -> Any:
            if cmd[0] == sys.executable:
                raise subprocess.CalledProcessError(1, cmd)
            return _completed()

        with (
            patch(
                "mulder.server.tools.hindsight.shutil.which",
                side_effect=_only_interpreters,
            ),
            patch("mulder.server.tools.hindsight.subprocess.run", side_effect=_run),
        ):
            assert _find_hindsight_cmd() == [_FAKE_PY, "-m", "pyhindsight.hindsight"]

    def test_returns_none_when_all_probes_fail(self) -> None:
        with (
            patch(
                "mulder.server.tools.hindsight.shutil.which",
                side_effect=_only_interpreters,
            ),
            patch(
                "mulder.server.tools.hindsight.subprocess.run",
                side_effect=subprocess.TimeoutExpired("python3", 10),
            ),
        ):
            assert _find_hindsight_cmd() is None


# ---------------------------------------------------------------------------
# Zircolite — Class A, plus the importability gate that replaced the PATH gate
# ---------------------------------------------------------------------------


class TestZircolite:
    """Zircolite runs on mulder's own interpreter; its deps ship in an extra."""

    def test_uses_sys_executable(self, tmp_path: Path) -> None:
        with patch("mulder.server.tools.zircolite.subprocess.run") as mock_run:
            _run_zircolite_process(tmp_path / "events.log", "auditd", tmp_path, tmp_path)
        assert mock_run.call_args[0][0][0] == sys.executable

    def test_module_list_matches_upstream(self) -> None:
        """Pinned against Zircolite 2.20.0's requirements.txt and import block.

        A longer list would block a working install, which is the one failure
        mode this gate must never have.
        """
        assert set(_ZIRCOLITE_MODULES) == {"orjson", "xxhash", "colorama", "tqdm"}

    def test_reports_missing_modules(self) -> None:
        from mulder.server.tools.zircolite import run_zircolite

        with (
            patch(
                "mulder.server.tools.zircolite.sources_already_indexed",
                return_value=[],
            ),
            patch(
                "mulder.server.tools.zircolite.importlib.util.find_spec",
                side_effect=lambda m: None if m == "orjson" else MagicMock(),
            ),
        ):
            result = run_zircolite.__wrapped__("/fake/audit.log")  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert result["error_type"] == "binary_missing"
        assert "orjson" in str(result["error_message"])
        assert "forensics" in str(result["suggestion"])

    def test_runs_without_python3_on_path(self) -> None:
        """Regression guard: the removed ``require_binary("python3")`` gate."""
        from mulder.server.tools.zircolite import run_zircolite

        with (
            patch(
                "mulder.server.tools.zircolite.sources_already_indexed",
                return_value=[],
            ),
            patch("mulder.server.helpers.shutil.which", return_value=None),
            patch(
                "mulder.server.tools.zircolite.importlib.util.find_spec",
                return_value=MagicMock(),
            ),
        ):
            result = run_zircolite.__wrapped__("/fake/audit.log")  # type: ignore[attr-defined]

        # It still fails (no /opt/zircolite here), but never on a PATH python3.
        assert "python3" not in str(result.get("error_message", ""))


# ---------------------------------------------------------------------------
# ALEAPP / iLEAPP — Class B probe plus the console-script fallback
# ---------------------------------------------------------------------------


class TestLeappCmdResolution:
    """ALEAPP/iLEAPP deps are not pip-shippable, so probe rather than assume."""

    @pytest.fixture(autouse=True)
    def _clear_probe_cache(self) -> Any:
        """The probe is memoized per process; each test needs a cold cache."""
        from mulder.server.tools.phone import _find_leapp_cmd

        _find_leapp_cmd.cache_clear()
        yield
        _find_leapp_cmd.cache_clear()

    def test_probes_sys_executable_first(self) -> None:
        from mulder.server.tools.phone import _find_leapp_cmd

        with (
            patch("mulder.server.tools.phone.Path.exists", return_value=True),
            patch("mulder.server.helpers.shutil.which", return_value=_FAKE_PY),
            patch(
                "mulder.server.tools.phone.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
        ):
            cmd = _find_leapp_cmd(_ALEAPP_SCRIPT, "aleapp")

        assert cmd == [sys.executable, _ALEAPP_SCRIPT]
        assert mock_run.call_args[0][0][0] == sys.executable

    def test_falls_through_to_path_python(self) -> None:
        """Regression guard for the Class-B reclassification."""
        from mulder.server.tools.phone import _find_leapp_cmd

        def _run(cmd: list[str], **_: object) -> Any:
            if cmd[0] == sys.executable:
                raise subprocess.CalledProcessError(1, cmd)
            return _completed()

        with (
            patch("mulder.server.tools.phone.Path.exists", return_value=True),
            patch("mulder.server.helpers.shutil.which", return_value=_FAKE_PY),
            patch("mulder.server.tools.phone.subprocess.run", side_effect=_run),
        ):
            cmd = _find_leapp_cmd(_ALEAPP_SCRIPT, "aleapp")

        assert cmd == [_FAKE_PY, _ALEAPP_SCRIPT]

    def test_falls_back_to_console_script(self) -> None:
        """Regression guard: the script path was used unconditionally before."""
        from mulder.server.tools.phone import _find_leapp_cmd

        with (
            patch("mulder.server.tools.phone.Path.exists", return_value=False),
            patch(
                "mulder.server.tools.phone.require_binary",
                return_value="/usr/bin/aleapp",
            ),
        ):
            cmd = _find_leapp_cmd(_ALEAPP_SCRIPT, "aleapp")

        assert cmd == ["/usr/bin/aleapp"]
        assert _ALEAPP_SCRIPT not in (cmd or [])

    def test_returns_none_when_nothing_runnable(self) -> None:
        from mulder.server.tools.phone import _find_leapp_cmd

        with (
            patch("mulder.server.tools.phone.Path.exists", return_value=False),
            patch("mulder.server.tools.phone.require_binary", return_value=None),
        ):
            assert _find_leapp_cmd(_ILEAPP_SCRIPT, "ileapp") is None

    def test_probe_is_memoized(self) -> None:
        """A failing probe costs up to 3 x _LEAPP_PROBE_TIMEOUT; pay it once."""
        from mulder.server.tools.phone import _find_leapp_cmd

        with (
            patch("mulder.server.tools.phone.Path.exists", return_value=True),
            patch("mulder.server.helpers.shutil.which", return_value=_FAKE_PY),
            patch(
                "mulder.server.tools.phone.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
        ):
            first = _find_leapp_cmd(_ALEAPP_SCRIPT, "aleapp")
            second = _find_leapp_cmd(_ALEAPP_SCRIPT, "aleapp")

        assert first == second
        assert mock_run.call_count == 1


class TestLeappToolErrors:
    """The tools must report a runnable-command failure, not a bare path."""

    def test_aleapp_errors_when_nothing_runnable(self) -> None:
        from mulder.server.tools.phone import run_aleapp

        with (
            patch("mulder.server.tools.phone.Path.exists", return_value=True),
            patch("mulder.server.tools.phone.require_binary", return_value=None),
            patch("mulder.server.tools.phone._find_leapp_cmd", return_value=None),
        ):
            result = run_aleapp.__wrapped__("/fake/extraction")  # type: ignore[attr-defined]

        assert result["error_type"] == "binary_missing"
        assert "pipx inject" in str(result["suggestion"])

    def test_ileapp_errors_when_nothing_runnable(self) -> None:
        from mulder.server.tools.phone import run_ileapp

        with (
            patch("mulder.server.tools.phone.Path.exists", return_value=True),
            patch("mulder.server.tools.phone.require_binary", return_value=None),
            patch("mulder.server.tools.phone._find_leapp_cmd", return_value=None),
        ):
            result = run_ileapp.__wrapped__("/fake/extraction")  # type: ignore[attr-defined]

        assert result["error_type"] == "binary_missing"
        assert "pipx inject" in str(result["suggestion"])

    def test_aleapp_uses_resolved_cmd(self) -> None:
        """The probed command prefix reaches subprocess.run, not ``python3``."""
        from mulder.server.tools.phone import run_aleapp

        with (
            patch("mulder.server.tools.phone.Path.exists", return_value=True),
            patch(
                "mulder.server.tools.phone._find_leapp_cmd",
                return_value=["/usr/bin/aleapp"],
            ),
            patch(
                "mulder.server.tools.phone.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
            patch(
                "mulder.server.tools.phone._parse_leapp_output",
                return_value={"total_artifacts_parsed": 0},
            ),
        ):
            run_aleapp.__wrapped__("/fake/extraction")  # type: ignore[attr-defined]

        assert mock_run.call_args[0][0][0] == "/usr/bin/aleapp"


# ---------------------------------------------------------------------------
# documents.py — Didier Stevens scripts (Class A) and oletools (Class C)
# ---------------------------------------------------------------------------


class TestDidierStevensScripts:
    """Stdlib-only scripts: any interpreter works, so use mulder's own."""

    def test_pdfid_uses_sys_executable(self) -> None:
        from mulder.server.tools.documents import _run_pdfid

        with (
            patch("mulder.server.tools.documents.Path.exists", return_value=True),
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
        ):
            _run_pdfid(Path("/fake/doc.pdf"))

        assert mock_run.call_args[0][0][0] == sys.executable

    def test_pdfid_falls_back_to_packaged_cli(self) -> None:
        from mulder.server.tools.documents import _run_pdfid

        with (
            patch("mulder.server.tools.documents.Path.exists", return_value=False),
            patch(
                "mulder.server.tools.documents.require_binary",
                return_value="/usr/bin/pdfid",
            ),
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
        ):
            _run_pdfid(Path("/fake/doc.pdf"))

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/usr/bin/pdfid"
        assert sys.executable not in cmd

    def test_pdf_parser_uses_sys_executable(self) -> None:
        from mulder.server.tools.documents import _extract_pdf_javascript

        with (
            patch("mulder.server.tools.documents.Path.exists", return_value=True),
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
        ):
            _extract_pdf_javascript(Path("/fake/doc.pdf"))

        assert mock_run.call_args[0][0][0] == sys.executable


class TestOletoolsModuleInvocation:
    """pipx hides a dependency's console scripts from PATH; use ``-m``."""

    def test_olevba_uses_module_invocation(self) -> None:
        with patch(
            "mulder.server.tools.documents.subprocess.run",
            return_value=_completed(stdout="[]"),
        ) as mock_run:
            _analyze_macros_olevba(Path("/fake/doc.docm"))

        assert mock_run.call_args[0][0][:3] == [sys.executable, "-m", "oletools.olevba"]

    def test_olevba_raises_on_nonzero_exit_with_empty_stdout(self) -> None:
        """A broken oletools must not read as "this document has no macros"."""
        with (
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(returncode=1, stderr="boom"),
            ),
            pytest.raises(OSError, match="olevba failed"),
        ):
            _analyze_macros_olevba(Path("/fake/doc.docm"))

    def test_olevba_empty_stdout_with_zero_exit_is_not_an_error(self) -> None:
        with patch(
            "mulder.server.tools.documents.subprocess.run",
            return_value=_completed(),
        ):
            assert _analyze_macros_olevba(Path("/fake/doc.docm")) == ([], [], False)

    def test_msodde_uses_module_invocation(self) -> None:
        from mulder.server.tools.documents import analyze_office_document

        with (
            patch(
                "mulder.server.tools.documents.importlib.util.find_spec",
                return_value=MagicMock(),
            ),
            patch("mulder.server.tools.documents.Path.exists", return_value=True),
            patch(
                "mulder.server.tools.documents._analyze_macros_olevba",
                return_value=([], [], False),
            ),
            patch(
                "mulder.server.tools.documents.extract_and_index",
                return_value={},
            ),
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
        ):
            analyze_office_document.__wrapped__(  # type: ignore[attr-defined]
                "case-1", "/fake/doc.docm", analyze_dde=True
            )

        assert mock_run.call_args[0][0][:3] == [sys.executable, "-m", "oletools.msodde"]

    def test_msodde_requests_json_output(self) -> None:
        """``--json`` is what makes real links distinguishable from the banner."""
        from mulder.server.tools.documents import analyze_office_document

        with (
            patch(
                "mulder.server.tools.documents.importlib.util.find_spec",
                return_value=MagicMock(),
            ),
            patch("mulder.server.tools.documents.Path.exists", return_value=True),
            patch(
                "mulder.server.tools.documents._analyze_macros_olevba",
                return_value=([], [], False),
            ),
            patch(
                "mulder.server.tools.documents.extract_and_index",
                return_value={},
            ),
            patch(
                "mulder.server.tools.documents.subprocess.run",
                return_value=_completed(),
            ) as mock_run,
        ):
            analyze_office_document.__wrapped__(  # type: ignore[attr-defined]
                "case-1", "/fake/doc.docm", analyze_dde=True
            )

        assert "--json" in mock_run.call_args[0][0]

    def test_office_gate_checks_importability_not_path(self) -> None:
        from mulder.server.tools.documents import analyze_office_document

        with patch(
            "mulder.server.tools.documents.importlib.util.find_spec",
            return_value=None,
        ):
            result = analyze_office_document.__wrapped__(  # type: ignore[attr-defined]
                "case-1", "/fake/doc.docm"
            )

        assert result["error_type"] == "binary_missing"
        assert "importable" in str(result["error_message"])
