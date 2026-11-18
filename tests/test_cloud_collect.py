"""Collecting cloud audit logs with read-only credentials the user supplies.

No network: the HTTP client is a stand-in that answers with real
``httpx.Response`` objects (the suite blocks ``httpx.Client.send``).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from click.testing import CliRunner

from mulder import collect as collector
from mulder.audit import AuditLog
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.orchestrator.evidence import EvidenceContext
from mulder.server import app
from mulder.server.tools.collect import collect_cloud_audit_logs

_TOKEN = "ghp_not-a-real-token"
_SINCE = datetime(2026, 11, 1, tzinfo=UTC)
_UNTIL = datetime(2026, 11, 10, tzinfo=UTC)
_EVENTS = [
    {"@timestamp": 1731800000000, "action": "org.create_actions_secret", "actor": "mallory"},
    {"@timestamp": 1731800060000, "action": "repo.remove_self_hosted_runner", "actor": "mallory"},
    {"@timestamp": 1731800120000, "action": "org.add_member", "actor": "mallory"},
]


class _Client:
    """Answers each request from a queue and records what was asked."""

    def __init__(self, *responses: httpx.Response) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def _next(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        response = self.responses.pop(0)
        response.request = httpx.Request(method, url)
        return response

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self._next("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self._next("POST", url, **kwargs)

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        collector.ENV_GITHUB_TOKEN,
        collector.ENV_GITHUB_ORGS,
        collector.ENV_GITHUB_API,
        collector.ENV_GCP_CREDENTIALS,
        collector.ENV_GCP_PROJECTS,
        collector.ENV_AGENT_COLLECTION,
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def github(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(collector.ENV_GITHUB_TOKEN, _TOKEN)
    monkeypatch.setenv(collector.ENV_GITHUB_ORGS, "acme, acme-labs")


def _page(
    events: list[dict[str, Any]], next_url: str = "", scopes: str | None = "read:audit_log"
) -> httpx.Response:
    headers = {}
    if next_url:
        headers["Link"] = f'<{next_url}>; rel="next"'
    if scopes is not None:
        headers["X-OAuth-Scopes"] = scopes
    return httpx.Response(200, json=events, headers=headers)


def _collect(client: _Client, dest: Path, provider: str = "github", scope: str = "acme") -> Any:
    return collector.collect(provider, scope, _SINCE, _UNTIL, dest, client)  # type: ignore[arg-type]


def test_only_mulders_own_variables_configure_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's ambient login can usually write; it must never be picked up."""
    monkeypatch.setenv("GH_TOKEN", "ghp_developer")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_developer")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/home/dev/adc.json")
    assert collector.targets() == {}

    monkeypatch.setenv(collector.ENV_GITHUB_TOKEN, _TOKEN)
    assert collector.targets() == {}, "a token without a named organization targets nothing"
    monkeypatch.setenv(collector.ENV_GITHUB_ORGS, "acme")
    assert collector.targets() == {"github": ["acme"]}


def test_github_pages_are_followed_and_written_with_a_manifest(
    github: None, tmp_path: Path
) -> None:
    cursor = "https://api.github.com/organizations/1/audit-log?after=abc&per_page=100"
    client = _Client(_page(_EVENTS[:2], next_url=cursor), _page(_EVENTS[2:]))

    done = _collect(client, tmp_path / "out")

    first, second = client.calls
    assert first["url"] == "https://api.github.com/orgs/acme/audit-log"
    assert (
        first["params"]["phrase"] == "created:2026-11-01T00:00:00+00:00..2026-11-10T00:00:00+00:00"
    )
    assert first["params"]["include"] == "all"
    assert first["headers"]["Authorization"] == f"Bearer {_TOKEN}"
    assert (second["url"], second["params"]) == (cursor, None)

    out = Path(done.path)
    assert out.name == "github-acme-20261101T000000Z-20261110T000000Z.jsonl"
    assert [json.loads(line) for line in out.read_text().splitlines()] == _EVENTS
    assert (done.events, done.pages, done.complete, done.warnings) == (3, 2, True, [])
    assert done.sha256 == hashlib.sha256(out.read_bytes()).hexdigest()
    manifest = json.loads(out.with_name(out.name + ".manifest").read_text())
    assert manifest["sha256"] == done.sha256
    assert manifest["query"].startswith("GET https://api.github.com/orgs/acme/audit-log")
    assert _TOKEN not in json.dumps(manifest)


@pytest.mark.parametrize(
    ("scopes", "expected"),
    [
        ("read:audit_log, read:org", []),
        ("repo, admin:org, read:audit_log", ["not read-only; it also grants: admin:org, repo"]),
        (None, ["could not check that the GitHub token is read-only"]),
    ],
)
def test_a_token_that_can_do_more_than_read_is_called_out(
    github: None, tmp_path: Path, scopes: str | None, expected: list[str]
) -> None:
    done = _collect(_Client(_page(_EVENTS, scopes=scopes)), tmp_path)

    assert len(done.warnings) == len(expected)
    for warning, fragment in zip(done.warnings, expected, strict=True):
        assert fragment in warning


def test_the_token_is_never_sent_to_another_host(github: None, tmp_path: Path) -> None:
    client = _Client(_page(_EVENTS, next_url="https://evil.example/audit-log?after=x"))

    with pytest.raises(collector.CollectError, match="another host"):
        _collect(client, tmp_path)

    assert len(client.calls) == 1
    assert list(tmp_path.iterdir()) == [], "a failed collection leaves nothing behind"


def test_a_refused_request_explains_itself_without_the_token(github: None, tmp_path: Path) -> None:
    client = _Client(httpx.Response(404, json={"message": "Not Found"}))

    with pytest.raises(collector.CollectError) as raised:
        _collect(client, tmp_path)

    assert "HTTP 404" in str(raised.value)
    assert "read:audit_log" in str(raised.value)
    assert _TOKEN not in str(raised.value)


def test_a_rate_limit_part_way_keeps_what_was_read_and_says_partial(
    github: None, tmp_path: Path
) -> None:
    cursor = "https://api.github.com/organizations/1/audit-log?after=abc"
    client = _Client(_page(_EVENTS[:2], next_url=cursor), httpx.Response(429, json={}))

    done = _collect(client, tmp_path)

    assert (done.events, done.complete) == (2, False)
    assert "rate limited" in done.warnings[0]


def test_only_configured_targets_can_be_collected(github: None, tmp_path: Path) -> None:
    client = _Client()

    with pytest.raises(collector.CollectError, match="not configured for 'someone-else'"):
        _collect(client, tmp_path, scope="someone-else")

    assert client.calls == []


def _service_account(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    key_file = tmp_path / "sa.json"
    key_file.write_text(
        json.dumps(
            {
                "type": "service_account",
                "project_id": "acme-prod",
                "client_email": "mulder-ro@acme-prod.iam.gserviceaccount.com",
                "private_key": pem,
                "token_uri": "https://evil.example/token",
            }
        )
    )
    monkeypatch.setenv(collector.ENV_GCP_CREDENTIALS, str(key_file))
    return key.public_key()


def test_gcp_asks_only_for_log_reading_and_only_google(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    jwt = pytest.importorskip("jwt")
    public_key = _service_account(tmp_path, monkeypatch)
    entry = {"logName": "projects/acme-prod/logs/cloudaudit.googleapis.com%2Factivity"}
    data = {"logName": "projects/acme-prod/logs/cloudaudit.googleapis.com%2Fdata_access"}
    client = _Client(
        httpx.Response(200, json={"access_token": "ya29.token"}),
        httpx.Response(200, json={"entries": [entry], "nextPageToken": "p2"}),
        httpx.Response(200, json={"nextPageToken": "p3"}),  # empty page, search not finished
        httpx.Response(200, json={"entries": [data]}),
    )
    assert collector.targets() == {"gcp": ["acme-prod"]}

    done = _collect(client, tmp_path / "out", provider="gcp", scope="acme-prod")

    token_call, *pages = client.calls
    # Google's endpoint, not the token_uri the key file names.
    assert token_call["url"] == "https://oauth2.googleapis.com/token"
    claims = jwt.decode(
        token_call["data"]["assertion"],
        public_key,
        algorithms=["RS256"],
        audience="https://oauth2.googleapis.com/token",
    )
    assert claims["scope"] == "https://www.googleapis.com/auth/logging.read"
    assert all(p["url"] == "https://logging.googleapis.com/v2/entries:list" for p in pages)
    assert pages[0]["json"]["resourceNames"] == ["projects/acme-prod"]
    assert 'timestamp>="2026-11-01T00:00:00Z"' in pages[0]["json"]["filter"]
    assert [p["json"].get("pageToken") for p in pages] == [None, "p2", "p3"]
    assert (done.events, done.pages, done.warnings) == (2, 3, [])


def test_gcp_says_when_no_data_access_entries_came_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("jwt")
    _service_account(tmp_path, monkeypatch)
    entry = {"logName": "projects/acme-prod/logs/cloudaudit.googleapis.com%2Factivity"}
    client = _Client(
        httpx.Response(200, json={"access_token": "t"}),
        httpx.Response(200, json={"entries": [entry]}),
    )

    done = _collect(client, tmp_path / "out", provider="gcp", scope="acme-prod")

    assert "roles/logging.privateLogViewer" in done.warnings[0]


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    db = CaseDB.create(case_id="c1", evidence_root=str(tmp_path / "evidence"), db_dir=db_dir)
    ctx = app.ServerContext(
        case_id="c1", db=db, correlator=MagicMock(), audit=AuditLog(db_dir / "c1.audit.jsonl")
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    monkeypatch.setattr(app, "_cfg", app.ServerConfig(db_dir=db_dir))
    return db


def test_an_investigation_cannot_collect_unless_the_user_enabled_it(
    case: CaseDB, github: None
) -> None:
    with patch.object(collector, "collect") as collect:
        result = collect_cloud_audit_logs.__wrapped__("github")  # type: ignore[attr-defined]

    assert result["error_type"] == "not_enabled"
    assert "[COLLECT]" in str(result["suggestion"])
    collect.assert_not_called()


def test_an_enabled_investigation_collects_into_the_case_and_indexes(
    case: CaseDB, github: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(collector.ENV_AGENT_COLLECTION, "1")
    monkeypatch.setenv(collector.ENV_GITHUB_ORGS, "acme")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    real = collector.collect

    def _with_fake_client(provider: str, scope: str, since: Any, until: Any, dest: Path) -> Any:
        client: Any = _Client(_page(_EVENTS))
        return real(provider, scope, since, until, dest, client)

    with (
        patch.object(collector, "collect", side_effect=_with_fake_client) as collect,
        patch("mulder.server.tools.cloudlogs._zircolite_script", return_value=None),
    ):
        tool = collect_cloud_audit_logs.__wrapped__  # type: ignore[attr-defined]
        first = tool("github", start="2026-11-01", end="2026-11-10")
        second = tool("github", start="2026-11-01", end="2026-11-10")

    scope = first["results"]["scopes"]["acme"]
    assert (scope["status"], scope["events"]) == ("collected", 3)
    assert Path(scope["path"]).is_relative_to(tmp_path / "db" / "collected" / "c1")
    assert list(evidence.iterdir()) == [], "the evidence directory is never written to"
    text = "".join(w.raw_text for w in case.get_windows_by_source("cloudlog.github"))
    assert "org.create_actions_secret" in text
    # The same window is not fetched twice.
    assert second["results"]["scopes"]["acme"]["status"] == "already collected"
    assert collect.call_count == 1


def test_the_planner_hears_about_collection_only_when_it_is_enabled(
    github: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ws-01.E01").write_bytes(b"x")
    ctx = EvidenceContext(str(tmp_path))

    assert "collect_cloud_audit_logs" not in ctx.build_evidence_context("ws-01")

    monkeypatch.setenv(collector.ENV_AGENT_COLLECTION, "1")
    text = ctx.build_evidence_context("ws-01")
    assert "Live collection is enabled for the audit logs of:" in text
    assert "  github: acme, acme-labs" in text
    assert "collect_cloud_audit_logs(provider=<provider>" in text


def test_the_command_collects_every_configured_target(github: None, tmp_path: Path) -> None:
    seen: list[tuple[str, str]] = []

    def _fake(provider: str, scope: str, since: Any, until: Any, dest: Path) -> Any:
        seen.append((provider, scope))
        return collector.Collection(
            provider, scope, "s", "e", str(dest / "x.jsonl"), events=3, sha256="ab", warnings=["w"]
        )

    with patch.object(collector, "collect", side_effect=_fake):
        result = CliRunner().invoke(
            cli, ["collect", "github", "--out", str(tmp_path / "out"), "--since", "2026-11-01"]
        )

    assert result.exit_code == 0, result.output
    assert seen == [("github", "acme"), ("github", "acme-labs")]
    assert "github acme: 3 events (complete)" in result.output
    assert "warning: w" in result.output


def test_the_command_fails_clearly_when_nothing_is_configured(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli, ["collect", "gcp", "--out", str(tmp_path)])

    assert result.exit_code != 0
    assert "No gcp collection is configured" in result.output
