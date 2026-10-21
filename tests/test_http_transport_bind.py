"""Tests for the bind address of ``mulder serve --transport streamable-http``."""

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mulder.cli import cli


def _invoke_serve(tmp_path: Path, *args: str) -> tuple[MagicMock, str]:
    """Run ``serve`` against a stub server module; return its ``mcp`` and the output."""
    fake_app = types.ModuleType("mulder.server.app")
    fake_app.init_server = MagicMock()  # type: ignore[attr-defined]
    fake_app.mcp = MagicMock()  # type: ignore[attr-defined]
    fake_pkg = types.ModuleType("mulder.server")
    fake_pkg.app = fake_app  # type: ignore[attr-defined]
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    try:
        with patch.dict(sys.modules, {"mulder.server": fake_pkg, "mulder.server.app": fake_app}):
            result = CliRunner().invoke(cli, ["serve", "--db-dir", str(tmp_path), *args])
    finally:
        for handler in set(root.handlers) - set(handlers):
            root.removeHandler(handler)
            handler.close()
        root.setLevel(level)
    assert result.exit_code == 0, result.output
    return fake_app.mcp, result.output


class TestHttpTransportBind:
    """The HTTP transport binds loopback unless told otherwise."""

    def test_default_binds_loopback(self, tmp_path: Path) -> None:
        mcp, output = _invoke_serve(tmp_path, "--transport", "streamable-http")
        mcp.run.assert_called_once_with(transport="streamable-http", host="127.0.0.1")
        assert "WARNING" not in output

    @pytest.mark.parametrize("host", ["localhost", "::1"])
    def test_loopback_hosts_do_not_warn(self, tmp_path: Path, host: str) -> None:
        mcp, output = _invoke_serve(tmp_path, "--transport", "streamable-http", "--host", host)
        mcp.run.assert_called_once_with(transport="streamable-http", host=host)
        assert "WARNING" not in output

    def test_non_loopback_host_warns(self, tmp_path: Path) -> None:
        mcp, output = _invoke_serve(
            tmp_path, "--transport", "streamable-http", "--host", "0.0.0.0"
        )
        mcp.run.assert_called_once_with(transport="streamable-http", host="0.0.0.0")
        assert "WARNING" in output
        assert "no authentication" in output

    def test_stdio_ignores_host(self, tmp_path: Path) -> None:
        mcp, output = _invoke_serve(tmp_path, "--host", "0.0.0.0")
        mcp.run.assert_called_once_with(transport="stdio")
        assert "WARNING" not in output

    def test_help_lists_host(self) -> None:
        result = CliRunner().invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output
