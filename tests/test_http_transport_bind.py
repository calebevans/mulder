"""Tests for the bind address and bearer token of ``mulder serve --transport streamable-http``."""

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import anyio
import httpx
import pytest
from click.testing import CliRunner

from mulder.cli import HTTP_TOKEN_ENV_VAR, _require_bearer, cli

TOKEN = "test-token-value"


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

    @pytest.fixture(autouse=True)
    def _no_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(HTTP_TOKEN_ENV_VAR, raising=False)

    def test_default_binds_loopback_and_warns_unauthenticated(self, tmp_path: Path) -> None:
        mcp, output = _invoke_serve(tmp_path, "--transport", "streamable-http")
        mcp.run.assert_called_once_with(transport="streamable-http", host="127.0.0.1")
        assert "no authentication" in output
        assert HTTP_TOKEN_ENV_VAR in output
        assert "DNS-rebinding" not in output

    @pytest.mark.parametrize("host", ["localhost", "::1"])
    def test_loopback_hosts_keep_rebinding_protection(self, tmp_path: Path, host: str) -> None:
        mcp, output = _invoke_serve(tmp_path, "--transport", "streamable-http", "--host", host)
        mcp.run.assert_called_once_with(transport="streamable-http", host=host)
        assert "DNS-rebinding" not in output

    def test_non_loopback_host_warns(self, tmp_path: Path) -> None:
        mcp, output = _invoke_serve(
            tmp_path, "--transport", "streamable-http", "--host", "0.0.0.0"
        )
        mcp.run.assert_called_once_with(transport="streamable-http", host="0.0.0.0")
        assert "no authentication" in output
        assert "DNS-rebinding" in output

    def test_stdio_ignores_host(self, tmp_path: Path) -> None:
        mcp, output = _invoke_serve(tmp_path, "--host", "0.0.0.0")
        mcp.run.assert_called_once_with(transport="stdio")
        assert "WARNING" not in output

    def test_help_lists_host(self) -> None:
        result = CliRunner().invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output


class TestHttpTransportToken:
    """With the token env var set, serve runs uvicorn behind a bearer check."""

    def test_token_runs_guarded_app(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(HTTP_TOKEN_ENV_VAR, TOKEN)
        with patch("uvicorn.run") as uvicorn_run:
            mcp, output = _invoke_serve(
                tmp_path, "--transport", "streamable-http", "--host", "localhost"
            )
        mcp.run.assert_not_called()
        mcp.streamable_http_app.assert_called_once_with(host="localhost")
        uvicorn_run.assert_called_once()
        assert uvicorn_run.call_args.kwargs["host"] == "localhost"
        assert uvicorn_run.call_args.kwargs["port"] == 8000
        assert "no authentication" not in output
        assert TOKEN not in output


async def _inner_app(scope: Any, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _get(headers: dict[str, str]) -> httpx.Response:
    # Drive the ASGI transport directly: conftest blocks ``AsyncClient.send``.
    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=_require_bearer(_inner_app, TOKEN))
        request = httpx.Request("POST", "http://127.0.0.1/mcp", headers=headers)
        response = await transport.handle_async_request(request)
        await response.aread()
        return response

    return anyio.run(go)


class TestRequireBearer:
    """The bearer middleware rejects requests without the exact token."""

    def test_missing_header_is_401(self) -> None:
        response = _get({})
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}
        assert "www-authenticate" not in response.headers

    def test_wrong_token_is_401(self) -> None:
        assert _get({"Authorization": "Bearer wrong"}).status_code == 401

    def test_wrong_scheme_is_401(self) -> None:
        assert _get({"Authorization": TOKEN}).status_code == 401

    def test_right_token_reaches_app(self) -> None:
        response = _get({"Authorization": f"Bearer {TOKEN}"})
        assert response.status_code == 200
        assert response.text == "ok"
