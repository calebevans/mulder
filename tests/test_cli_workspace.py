"""Workspace bootstrap tests for ``mulder investigate``.

A ``pipx install mulder-dfir`` box has no ``/mulder-investigation`` and never
will, so the working directory defaults to ``~/.mulder/workspace`` (overridable
with ``--cwd`` / ``MULDER_CWD``) and mulder materialises the packaged
``.mcp.json`` into it on first run instead of hard-erroring.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mulder.cli import cli
from mulder.patterns import DEFAULT_WORKSPACE_DIR


def _invoke(
    args: list[str],
    db_dir: Path,
    env: dict[str, str] | None = None,
) -> tuple[Any, MagicMock]:
    """Run ``mulder investigate`` with the orchestrator stubbed out."""
    runner = CliRunner()
    with (
        patch("mulder.orchestrator.runner.Orchestrator") as orchestrator_cls,
        patch("asyncio.run", return_value=MagicMock(success=True)),
    ):
        result = runner.invoke(
            cli,
            ["investigate", "/evidence", "case-1", "--db-dir", str(db_dir), *args],
            env=env,
            catch_exceptions=False,
        )
    return result, orchestrator_cls


class TestWorkspaceBootstrap:
    def test_investigate_materialises_mcp_config(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        result, _ = _invoke(["--cwd", str(workspace)], tmp_path / "db")

        assert result.exit_code == 0
        config_file = workspace / ".mcp.json"
        assert config_file.exists()
        config = json.loads(config_file.read_text(encoding="utf-8"))
        assert config["mcpServers"]["mulder"]["command"] == "mulder"

    def test_investigate_does_not_overwrite_existing_mcp_config(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        sentinel = '{"mcpServers": {"sentinel": {}}}'
        (workspace / ".mcp.json").write_text(sentinel, encoding="utf-8")

        result, _ = _invoke(["--cwd", str(workspace)], tmp_path / "db")

        assert result.exit_code == 0
        assert (workspace / ".mcp.json").read_text(encoding="utf-8") == sentinel


class TestWorkspaceResolution:
    def test_default_workspace_is_under_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The default must expand, not reach the orchestrator as a literal ``~``."""
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))

        _, orchestrator_cls = _invoke([], tmp_path / "db")

        resolved = orchestrator_cls.call_args.kwargs["cwd"]
        assert "~" not in resolved
        assert resolved == str(Path(DEFAULT_WORKSPACE_DIR).expanduser())
        assert Path(resolved, ".mcp.json").exists()
