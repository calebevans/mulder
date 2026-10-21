"""ip-api lookups must not leak case IPs over plaintext HTTP by default.

The free ip-api.com endpoint is HTTP-only, so a lookup there sends the
queried IOC in cleartext and accepts an unauthenticated reply.  The source
uses HTTPS (pro.ip-api.com) when ``IP_API_KEY`` is set, is skipped otherwise
unless ``MULDER_IP_API_ALLOW_HTTP=1`` opts in, and type-checks the reply.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from mulder.server.tools import enrichment
from mulder.server.tools.enrichment import _query_ip_api

_IOC = "203.0.113.7"
_FAKE_KEY = "not-a-real-key"


class _FakeResponse:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _FakeClient:
    """Records each GET and returns a canned JSON payload."""

    def __init__(self, payload: Any = None) -> None:
        self.payload = payload
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def get(self, url: str, params: dict[str, str], timeout: float) -> _FakeResponse:
        self.calls.append((url, params))
        return _FakeResponse(self.payload)


def _success(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "success",
        "country": "Exampleland",
        "as": "AS64500 Example Net",
        "query": _IOC,
    }
    payload.update(overrides)
    return payload


@pytest.fixture(autouse=True)
def _clear_ip_api_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IP_API_KEY", raising=False)
    monkeypatch.delenv("MULDER_IP_API_ALLOW_HTTP", raising=False)


async def test_skipped_without_key_or_opt_in() -> None:
    client = _FakeClient(_success())

    result = await _query_ip_api(client, _IOC, "ipv4")  # type: ignore[arg-type]

    assert client.calls == []
    assert result.found is False
    assert result.error is not None
    assert "IP_API_KEY" in result.error
    assert "MULDER_IP_API_ALLOW_HTTP" in result.error


async def test_key_uses_https_pro_endpoint() -> None:
    client = _FakeClient(_success())

    result = await _query_ip_api(client, _IOC, "ipv4", _FAKE_KEY)  # type: ignore[arg-type]

    [(url, params)] = client.calls
    assert url.startswith("https://pro.ip-api.com/")
    assert params["key"] == _FAKE_KEY
    assert result.found is True
    assert result.country == "Exampleland"
    assert not result.tags


async def test_opt_in_uses_http_and_flags_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MULDER_IP_API_ALLOW_HTTP", "1")
    client = _FakeClient(_success())

    result = await _query_ip_api(client, _IOC, "ipv4")  # type: ignore[arg-type]

    [(url, params)] = client.calls
    assert url.startswith("http://ip-api.com/")
    assert "key" not in params
    assert result.found is True
    assert result.tags == ["unauthenticated-transport"]


@pytest.mark.parametrize("payload", [["status", "success"], "success", None, 42])
async def test_non_object_reply_is_rejected(payload: Any) -> None:
    client = _FakeClient(payload)

    result = await _query_ip_api(client, _IOC, "ipv4", _FAKE_KEY)  # type: ignore[arg-type]

    assert result.found is False
    assert result.error is not None


async def test_reply_for_another_ip_is_rejected() -> None:
    client = _FakeClient(_success(query="198.51.100.1"))

    result = await _query_ip_api(client, _IOC, "ipv4", _FAKE_KEY)  # type: ignore[arg-type]

    assert result.found is False
    assert result.country is None


async def test_non_string_fields_are_dropped_and_strings_sanitised() -> None:
    client = _FakeClient(_success(country={"nested": "x"}, **{"as": "AS1\x1b[31m" + "A" * 500}))

    result = await _query_ip_api(client, _IOC, "ipv4", _FAKE_KEY)  # type: ignore[arg-type]

    assert result.found is True
    assert result.country is None
    assert result.asn is not None
    assert "\x1b" not in result.asn
    assert len(result.asn) <= 128


async def test_key_is_redacted_from_exception_text() -> None:
    class _FailingClient(_FakeClient):
        async def get(self, url: str, params: dict[str, str], timeout: float) -> _FakeResponse:
            request = httpx.Request("GET", url, params=params)
            raise httpx.ConnectError(f"connection failed for {request.url}", request=request)

    result = await _query_ip_api(_FailingClient(), _IOC, "ipv4", _FAKE_KEY)  # type: ignore[arg-type]

    assert result.found is False
    assert result.error is not None
    assert _FAKE_KEY not in result.error


async def test_key_never_reaches_response_audit_index_or_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("IP_API_KEY", _FAKE_KEY)
    monkeypatch.setattr(enrichment, "_session_cache", enrichment._SessionCache())
    audit_calls: list[dict[str, Any]] = []
    indexed: list[str] = []
    ctx = SimpleNamespace(audit=SimpleNamespace(log_tool_call=lambda **kw: audit_calls.append(kw)))
    monkeypatch.setattr(enrichment, "get_ctx", lambda: ctx)
    monkeypatch.setattr(
        enrichment, "extract_and_index", lambda **kw: indexed.append(kw["raw_output"])
    )

    async def _send(self: httpx.AsyncClient, request: httpx.Request, **_: Any) -> httpx.Response:
        logging.getLogger("httpx").info("HTTP Request: %s %s", request.method, request.url)
        raise httpx.ConnectError(f"connection failed for {request.url}", request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", _send)
    caplog.set_level(logging.DEBUG)

    results = await enrichment.enrich_iocs("case-1", [_IOC])

    assert results[0]["sources"][0]["error"]
    assert _FAKE_KEY not in json.dumps(results, default=str)
    assert _FAKE_KEY not in json.dumps(audit_calls, default=str)
    assert all(_FAKE_KEY not in raw for raw in indexed)
    assert "HTTP Request" in caplog.text
    assert _FAKE_KEY not in caplog.text


def test_httpx_request_log_line_is_redacted(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="httpx")
    url = httpx.URL(
        f"https://pro.ip-api.com/json/{_IOC}", params={"fields": "query", "key": _FAKE_KEY}
    )

    logging.getLogger("httpx").info(
        'HTTP Request: %s %s "%s %d %s"', "GET", url, "HTTP/1.1", 200, "OK"
    )

    assert "key=[REDACTED]" in caplog.text
    assert _FAKE_KEY not in caplog.text
