"""enrich_iocs: GreyNoise, urlscan and the offline exfil-service list."""

from __future__ import annotations

from typing import Any

import pytest

from mulder.server.tools import enrichment
from mulder.server.tools.enrichment import (
    _enrich_single_ioc,
    _lookup_value,
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
        ("a.b1.oast.fun", "oob-interaction"),
        ("files.0x0.st", "file-drop"),
        ("webhook.site.", "request-catcher"),
        ("hxxps://abc123[.]ngrok-free[.]app/x?tok=1", "tunnel"),
        ("webhook.site/5f1c?d=c2VjcmV0", "request-catcher"),
        ("user:pw@abc.lhr.life:8443", "tunnel"),
    ],
)
def test_exfil_services_are_tagged_on_the_domain_and_its_subdomains(
    domain: str, category: str
) -> None:
    # Through classification, as the tool does: real tunnel and request-catcher
    # hosts have digits and hyphens in labels the old domain pattern rejected.
    host = _lookup_value(domain)
    assert enrichment.classify_ioc(host) == "domain"
    result = _query_exfil_list(host, "domain")

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
    assert result.tags == ["noise", "malicious"]
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
    # page.domain: scans of this host, not every page that loaded a file from it.
    assert call["params"]["q"] == "page.domain:evil.example"
    assert (result.found, result.malicious, result.reputation_score) == (True, True, 50)
    assert result.tags == ["2 scans"]
    assert result.last_seen == "2026-11-10T12:00:00Z"
    assert result.first_seen is None, "a 100-result page cannot say when it was first seen"


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
        payload={
            "total": 222,
            "search_date_limit_days": 30,
            "results": [{"task": {"time": "2026-11-17T15:54:56Z"}}],
        }
    )

    result = await _query_urlscan(client, "webhook.site", "domain", _KEY)  # type: ignore[arg-type]

    assert result.found is True
    assert result.reputation_score is None
    assert result.malicious is False
    assert result.tags == ["222 scans in the last 30 days"]


async def test_greynoise_benign_is_a_tag_and_does_not_dilute_the_score() -> None:
    client = _Client(payload={"noise": True, "riot": False, "classification": "benign"})

    result = await _query_greynoise(client, "203.0.113.7", "ipv4", _KEY)  # type: ignore[arg-type]

    assert result.reputation_score is None
    assert result.tags == ["noise", "benign"]


async def test_urls_on_one_host_share_one_lookup() -> None:
    client: Any = _Client(payload={"total": 0, "results": []})
    keys = {"urlscan": _KEY}

    first = await _enrich_single_ioc(client, "https://evil.example/a", set(), keys)
    second = await _enrich_single_ioc(client, "https://evil.example/b?x=1", set(), keys)
    bare = await _enrich_single_ioc(client, "EVIL.example.", set(), keys)

    assert len(client.calls) == 1
    assert (first["cached"], second["cached"], bare["cached"]) == (False, True, True)
    assert second["ioc"] == "https://evil.example/b?x=1"
    assert second["ioc_type"] == "domain"


@pytest.mark.parametrize("bad", ["http://[bad/path?token=SECRET", "not an indicator", ""])
async def test_unparseable_input_is_unknown_and_contacts_nobody(bad: str) -> None:
    client: Any = _Client(payload={})

    out = await _enrich_single_ioc(client, bad, set(), {"urlscan": _KEY, "greynoise": _KEY})

    assert out["ioc_type"] == "unknown"
    assert out["sources"] == []
    assert client.calls == []


@pytest.mark.parametrize(
    "value", ["1.2.3", "v1.32.0", "-bad.example", "bad-.example", "localhost", "a..example"]
)
def test_the_wider_domain_pattern_still_rejects_non_domains(value: str) -> None:
    assert enrichment.classify_ioc(value) == "unknown"
