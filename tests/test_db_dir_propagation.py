"""``--db-dir`` has to reach the thing that writes the database.

``mulder investigate --db-dir /cases`` accepted the flag, wrote its log file
there, and then dropped it: the orchestrator was constructed without it, the
log tailer read ``~/.mulder/cases/mulder.log``, the model-usage sidecar was
written to a hardcoded ``~/.mulder/cases``, and the ``mulder serve``
processes the agent sessions spawn got no hint at all. The case therefore
landed in the default directory, and the matching ``mulder report --db-dir
/cases`` could never find it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mulder.cli import cli
from mulder.orchestrator.evidence import ServerBridge
from mulder.orchestrator.runner import Orchestrator
from mulder.patterns import DB_DIR_ENV_VAR, DEFAULT_DB_DIR, resolve_db_dir


class TestResolveDbDir:
    def test_an_explicit_directory_wins(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setenv(DB_DIR_ENV_VAR, "/from/env")
        assert resolve_db_dir(tmp_path) == tmp_path

    def test_the_environment_is_the_fallback(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setenv(DB_DIR_ENV_VAR, str(tmp_path))
        assert resolve_db_dir() == tmp_path
        assert resolve_db_dir("") == tmp_path

    def test_the_default_is_the_last_resort(self, monkeypatch: Any) -> None:
        monkeypatch.delenv(DB_DIR_ENV_VAR, raising=False)
        assert resolve_db_dir() == Path(DEFAULT_DB_DIR).expanduser()

    def test_the_result_is_always_expanded(self, monkeypatch: Any) -> None:
        monkeypatch.delenv(DB_DIR_ENV_VAR, raising=False)
        assert "~" not in str(resolve_db_dir("~/somewhere"))


class TestOrchestratorHonoursDbDir:
    @staticmethod
    def _make(db_dir: Path) -> Orchestrator:
        return Orchestrator(evidence_path="/evidence", case_id="case-1", db_dir=db_dir)

    def test_the_log_tailer_reads_the_chosen_directory(self, tmp_path: Path) -> None:
        orch = self._make(tmp_path)
        assert orch._log_tailer._log_path == tmp_path / "mulder.log"

    def test_agent_sessions_inherit_the_directory(self, tmp_path: Path) -> None:
        """Sessions spawn their own ``mulder serve``; without this it defaults."""
        orch = self._make(tmp_path)
        assert orch.env[DB_DIR_ENV_VAR] == str(tmp_path)

    def test_the_server_bridge_gets_the_directory(self, tmp_path: Path) -> None:
        orch = self._make(tmp_path)
        assert resolve_db_dir(orch._server._db_dir) == tmp_path

    def test_the_model_usage_sidecar_lands_in_it(self, tmp_path: Path) -> None:
        orch = self._make(tmp_path)
        orch.dashboard._model_tokens = {"claude-x": {"input": 10, "output": 20}}
        orch._write_model_usage()

        written = tmp_path / "case-1.model_usage.json"
        assert written.exists()
        payload = json.loads(written.read_text())
        assert payload[0]["model"] == "claude-x"

    def test_the_environment_is_the_fallback(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setenv(DB_DIR_ENV_VAR, str(tmp_path))
        orch = Orchestrator(evidence_path="/evidence", case_id="case-1")
        assert orch._log_tailer._log_path == tmp_path / "mulder.log"


class TestServerBridgeHonoursDbDir:
    def test_the_server_config_uses_the_chosen_directory(self, tmp_path: Path) -> None:
        import mulder.server.app as server_app

        bridge = ServerBridge(case_id="", db_dir=tmp_path)
        with (
            patch.object(server_app, "_cfg", None),
            patch.object(server_app, "load_case") as load_case,
        ):
            bridge.ensure_context()
            assert server_app._cfg is not None
            assert server_app._cfg.db_dir == tmp_path
        load_case.assert_not_called()


class TestInvestigateForwardsDbDir:
    @staticmethod
    def _invoke(args: list[str], env: dict[str, str] | None = None) -> MagicMock:
        runner = CliRunner()
        with (
            patch("mulder.orchestrator.runner.Orchestrator") as orchestrator_cls,
            patch("asyncio.run", return_value=MagicMock(success=True)),
        ):
            result = runner.invoke(
                cli,
                ["investigate", "/evidence", "case-1", *args],
                env=env,
                catch_exceptions=False,
            )
        assert result.exit_code == 0, result.output
        return orchestrator_cls

    def test_the_flag_reaches_the_orchestrator(self, tmp_path: Path) -> None:
        """The whole bug: the flag was read, logged to, and then dropped."""
        cls = self._invoke(["--db-dir", str(tmp_path)])
        assert resolve_db_dir(cls.call_args.kwargs["db_dir"]) == tmp_path

    def test_the_environment_variable_reaches_the_orchestrator(self, tmp_path: Path) -> None:
        cls = self._invoke([], env={DB_DIR_ENV_VAR: str(tmp_path)})
        assert resolve_db_dir(cls.call_args.kwargs["db_dir"]) == tmp_path


class TestReportReadsTheSameDirectory:
    """``investigate`` and ``report`` must agree on where the case lives."""

    @pytest.mark.parametrize("command", ["report", "export-iocs", "export-navigator"])
    def test_the_environment_variable_selects_the_directory(
        self, command: str, tmp_path: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [command, "case-1"],
            env={DB_DIR_ENV_VAR: str(tmp_path)},
            catch_exceptions=False,
        )
        # The case does not exist, and the message names where it was sought.
        assert str(tmp_path / "case-1.db") in result.output
