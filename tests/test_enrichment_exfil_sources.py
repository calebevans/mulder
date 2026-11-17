"""enrich_iocs: GreyNoise, urlscan and the offline exfil-service list."""

from __future__ import annotations

from typing import Any

import pytest

from mulder.server.tools import enrichment
from mulder.server.tools.enrichment import (
    _enrich_single_ioc,
    _query_exfil_list,
    _query_greynoise,
    _query_urlscan,
)

_KEY = "not-a-real-key"


class _Response:
    def __init__(self, status: int, payload: Any) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _Client:
    """Records each GET and answers with one canned response."""

    def __init__(self, status: int = 200, payload: Any = None) -> None:
        self.response = _Response(status, payload)
        self.calls: list[dict[str, Any]] = []

    async def get(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append({"url": url, **kwargs})
        return self.response


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(enrichment, "_session_cache", enrichment._SessionCache())


@pytest.mark.parametrize(
    ("domain", "category"),
    [
        ("webhook.site", "request-catcher"),
        ("abc123.ngrok-free.app", "tunnel"),
        ("EOXYZ.M.PIPEDREAM.NET", "request-catcher"),
        ("c5k2.oast.fun", "oob-interaction"),
    ],
)
def test_exfil_services_are_tagged_on_the_domain_and_its_subdomains(
    domain: str, category: str
) -> None:
    result = _query_exfil_list(domain, "domain")

    assert result is not None
    assert result.tags == ["exfil-service", category]
    # A tag, not a verdict: it must not move the aggregate score.
    assert result.reputation_score is None
    assert result.malicious is False


@pytest.mark.parametrize("domain", ["example.com", "notwebhook.site", "webhook.site.example.com"])
def test_lookalike_and_ordinary_domains_are_not_tagged(domain: str) -> None:
    assert _query_exfil_list(domain, "domain") is None


async def test_greynoise_reports_a_known_scanner() -> None:
    client = _Client(
        payload={
            "ip": "203.0.113.7",
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "name": "unknown",
            "last_seen": "2026-11-10",
        }
    )

    result = await _query_greynoise(client, "203.0.113.7", "ipv4", _KEY)  # type: ignore[arg-type]

    assert client.calls[0]["url"] == "https://api.greynoise.io/v3/community/203.0.113.7"
    assert client.calls[0]["headers"]["key"] == _KEY
    assert (result.found, result.malicious, result.reputation_score) == (True, True, 100)
    assert result.tags == ["noise"]
    assert result.last_seen == "2026-11-10"


async def test_greynoise_404_means_never_seen_not_an_error() -> None:
    client = _Client(status=404, payload={"noise": False, "riot": False})

    result = await _query_greynoise(client, "203.0.113.7", "ipv4", _KEY)  # type: ignore[arg-type]

    assert result.found is False
    assert result.error is None


async def test_urlscan_searches_and_never_submits() -> None:
    client = _Client(
        payload={
            "total": 2,
            "results": [
                {"task": {"time": "2026-11-10T12:00:00Z"}, "verdicts": {"malicious": True}},
                {"task": {"time": "2026-10-01T08:00:00Z"}, "verdicts": {"malicious": False}},
            ],
        }
    )

    result = await _query_urlscan(client, "evil.example", "domain", _KEY)  # type: ignore[arg-type]

    (call,) = client.calls
    assert call["url"] == "https://urlscan.io/api/v1/search/"
    assert call["params"]["q"] == "domain:evil.example"
    assert (result.found, result.malicious, result.reputation_score) == (True, True, 50)
    assert result.tags == ["2 scans"]
    assert (result.first_seen, result.last_seen) == (
        "2026-10-01T08:00:00Z",
        "2026-11-10T12:00:00Z",
    )


async def test_a_url_is_looked_up_by_host_so_its_path_never_leaves() -> None:
    client = _Client(payload={"total": 0, "results": []})
    url = "https://webhook.site/5f1c-stolen-token?d=c2VjcmV0"

    out = await _enrich_single_ioc(client, url, set(), {"urlscan": _KEY})  # type: ignore[arg-type]

    assert out["ioc"] == url
    assert out["ioc_type"] == "domain"
    assert [s["source"] for s in out["sources"]] == ["exfil-list", "urlscan"]
    assert out["sources"][0]["tags"] == ["exfil-service", "request-catcher"]
    sent = str(client.calls)
    assert "webhook.site" in sent
    assert "stolen-token" not in sent
    assert "c2VjcmV0" not in sent


async def test_new_sources_stay_off_without_keys_and_can_be_skipped() -> None:
    client = _Client(payload={})

    no_keys = await _enrich_single_ioc(client, "webhook.site", set(), {})  # type: ignore[arg-type]
    skipped = await _enrich_single_ioc(
        client,  # type: ignore[arg-type]
        "sub.webhook.site",
        {"exfil-list", "urlscan"},
        {"urlscan": _KEY},
    )

    assert [s["source"] for s in no_keys["sources"]] == ["exfil-list"]
    assert skipped["sources"] == []
    assert client.calls == []


async def test_urlscan_without_verdicts_reports_history_and_no_score() -> None:
    """The free plan returns no verdicts; absence must not read as a clean bill."""
    client = _Client(
        payload={"total": 279, "results": [{"task": {"time": "2026-11-17T15:54:56Z"}}]}
    )

    result = await _query_urlscan(client, "webhook.site", "domain", _KEY)  # type: ignore[arg-type]

    assert result.found is True
    assert result.reputation_score is None
    assert result.malicious is False
    assert result.tags == ["279 scans"]
