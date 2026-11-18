"""Pull cloud audit logs with read-only credentials the user supplies.

Everything else in mulder reads evidence that is already on disk. This module
is the one place that fetches it, and it is deliberately narrow:

* Credentials come only from ``MULDER_*`` variables, never from the ambient
  ``gh`` / ``gcloud`` login, which is usually a developer's and can write.
* The targets (organizations, projects) come from the same configuration. A
  caller chooses a time window, not where to look.
* Only audit-log read endpoints are called, with GET or a read-only POST.
* Output is JSON lines plus a manifest recording the query, the time, the
  event count and the SHA-256, so the export can be accounted for later.

Run it yourself with ``mulder collect``; an investigation can call it too, but
only when ``MULDER_AGENT_COLLECTION=1`` says so.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

ENV_GITHUB_TOKEN = "MULDER_GITHUB_TOKEN"
ENV_GITHUB_ORGS = "MULDER_GITHUB_ORGS"
ENV_GITHUB_API = "MULDER_GITHUB_API_URL"
ENV_GCP_CREDENTIALS = "MULDER_GCP_CREDENTIALS"
ENV_GCP_PROJECTS = "MULDER_GCP_PROJECTS"
ENV_AGENT_COLLECTION = "MULDER_AGENT_COLLECTION"

_GITHUB_API = "https://api.github.com"
_GCP_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GCP_LOGGING_URL = "https://logging.googleapis.com/v2/entries:list"
# The token is minted for this scope alone, so it can read logs and nothing
# else even if the service account behind it was granted more.
_GCP_SCOPE = "https://www.googleapis.com/auth/logging.read"
_TIMEOUT = 60.0
# ponytail: a hard stop, not paging to disk-full; raise or window the request
# if a busy tenant needs more.
_MAX_EVENTS = 1_000_000


class CollectError(Exception):
    """Collection could not start or could not continue; the message says why."""


@dataclass
class Collection:
    """What one collection produced."""

    provider: str
    scope: str
    start: str
    end: str
    path: str
    events: int = 0
    pages: int = 0
    complete: bool = True
    sha256: str = ""
    query: str = ""
    collected_at: str = ""
    warnings: list[str] = field(default_factory=list)


def _split(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def targets() -> dict[str, list[str]]:
    """Provider -> the scopes collection is configured for. Empty when none is."""
    found: dict[str, list[str]] = {}
    if os.environ.get(ENV_GITHUB_TOKEN) and _split(os.environ.get(ENV_GITHUB_ORGS)):
        found["github"] = _split(os.environ.get(ENV_GITHUB_ORGS))
    key_path = os.environ.get(ENV_GCP_CREDENTIALS)
    if key_path:
        projects = _split(os.environ.get(ENV_GCP_PROJECTS))
        if not projects:
            try:
                projects = [str(json.loads(Path(key_path).read_text())["project_id"])]
            except (OSError, ValueError, KeyError):
                projects = []
        if projects:
            found["gcp"] = projects
    return found


def agent_collection_enabled() -> bool:
    """Whether an investigation may collect, as opposed to the user running it."""
    return os.environ.get(ENV_AGENT_COLLECTION) == "1"


def window(start: str | None, end: str | None, days: int) -> tuple[datetime, datetime]:
    """Resolve a collection window in UTC. Defaults to the *days* before now."""

    def parse(value: str) -> datetime:
        try:
            moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise CollectError(f"Not an ISO 8601 date or time: {value!r}") from exc
        return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment

    until = parse(end) if end else datetime.now(timezone.utc)
    since = parse(start) if start else until - timedelta(days=days)
    if since >= until:
        raise CollectError(f"The window is empty: {since.isoformat()} to {until.isoformat()}")
    return since.astimezone(timezone.utc), until.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _check(response: httpx.Response, what: str, hints: dict[int, str]) -> None:
    """Raise a CollectError for a failed request, without echoing credentials."""
    if response.status_code < 400:
        return
    hint = hints.get(response.status_code, "")
    try:
        body = response.json()
        detail = body.get("message") or (body.get("error") or {}).get("message") or ""
    except (ValueError, AttributeError):
        detail = ""
    message = f"{what} failed with HTTP {response.status_code}"
    raise CollectError(". ".join(part for part in (message, str(detail)[:300], hint) if part))


def _github_events(
    client: httpx.Client, org: str, since: datetime, until: datetime, result: Collection
) -> Iterator[dict[str, Any]]:
    token = os.environ.get(ENV_GITHUB_TOKEN, "")
    api = os.environ.get(ENV_GITHUB_API, _GITHUB_API).rstrip("/")
    host = urlsplit(api).hostname
    phrase = (
        f"created:{since.isoformat(timespec='seconds')}..{until.isoformat(timespec='seconds')}"
    )
    result.query = f"GET {api}/orgs/{org}/audit-log phrase={phrase} include=all order=asc"
    url: str | None = f"{api}/orgs/{org}/audit-log"
    params: dict[str, str] | None = {
        "phrase": phrase,
        "include": "all",
        "order": "asc",
        "per_page": "100",
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    while url:
        response = client.get(url, params=params, headers=headers, timeout=_TIMEOUT)
        if response.status_code in (403, 429) and result.pages:
            # Rate limited part-way: keep what was read and say it is partial.
            result.complete = False
            result.warnings.append(f"stopped at page {result.pages}: rate limited by GitHub")
            return
        _check(
            response,
            f"Reading the audit log of {org}",
            {
                401: "The token was rejected.",
                403: "The token needs the read:audit_log scope and its user must be an "
                "organization owner.",
                404: "The audit log API needs GitHub Enterprise Cloud, an organization "
                "owner, and a token with read:audit_log.",
            },
        )
        if not result.pages:
            _github_scope_warning(response, result)
        result.pages += 1
        events = response.json()
        if not isinstance(events, list):
            raise CollectError("GitHub returned something other than a list of events")
        yield from (e for e in events if isinstance(e, dict))
        # The next page is a cursor URL GitHub hands back. Follow it only to
        # the API host the token was meant for.
        url = response.links.get("next", {}).get("url")
        params = None
        if url and urlsplit(url).hostname != host:
            raise CollectError(f"GitHub's next-page link points at another host: {url}")


def _github_scope_warning(response: httpx.Response, result: Collection) -> None:
    """Say so when the token can do more than read."""
    scopes = response.headers.get("X-OAuth-Scopes")
    if scopes is None:
        result.warnings.append(
            "could not check that the GitHub token is read-only (not a classic token)"
        )
        return
    extra = [s for s in _split(scopes) if not s.startswith("read:")]
    if extra:
        result.warnings.append(
            "the GitHub token is not read-only; it also grants: " + ", ".join(sorted(extra))
        )


def _gcp_token(client: httpx.Client) -> str:
    """Exchange the service account key for a token limited to reading logs."""
    try:
        import jwt  # PyJWT, with the cryptography backend for RS256
    except ImportError as exc:
        raise CollectError(
            "GCP collection needs PyJWT with cryptography: pipx inject mulder-dfir 'pyjwt[crypto]'"
        ) from exc
    path = os.environ.get(ENV_GCP_CREDENTIALS, "")
    try:
        key = json.loads(Path(path).read_text(encoding="utf-8"))
        email, private_key = key["client_email"], key["private_key"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CollectError(
            f"{ENV_GCP_CREDENTIALS} does not name a service account key file"
        ) from exc
    now = int(time.time())
    claims = {
        "iss": email,
        "scope": _GCP_SCOPE,
        "aud": _GCP_TOKEN_URL,
        "iat": now,
        "exp": now + 3600,
    }
    try:
        assertion = jwt.encode(claims, private_key, algorithm="RS256")
    except Exception as exc:  # the backend raises several unrelated types
        raise CollectError("The service account key could not sign a token request") from exc
    # Always Google's own endpoint, whatever token_uri the key file names.
    response = client.post(
        _GCP_TOKEN_URL,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        },
        timeout=_TIMEOUT,
    )
    _check(response, "Authenticating to Google Cloud", {})
    token = response.json().get("access_token")
    if not isinstance(token, str):
        raise CollectError("Google returned no access token")
    return token


def _gcp_events(
    client: httpx.Client, project: str, since: datetime, until: datetime, result: Collection
) -> Iterator[dict[str, Any]]:
    token = _gcp_token(client)
    log_filter = (
        f'logName:"cloudaudit.googleapis.com" AND timestamp>="{_iso(since)}" '
        f'AND timestamp<"{_iso(until)}"'
    )
    result.query = f"POST {_GCP_LOGGING_URL} projects/{project} filter={log_filter}"
    body: dict[str, object] = {
        "resourceNames": [f"projects/{project}"],
        "filter": log_filter,
        "orderBy": "timestamp asc",
        "pageSize": 1000,
    }
    data_access = 0
    page_token: str | None = None
    while True:
        response = client.post(
            _GCP_LOGGING_URL,
            json={**body, "pageToken": page_token} if page_token else body,
            headers={"Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT,
        )
        if response.status_code == 429 and result.pages:
            result.complete = False
            result.warnings.append(f"stopped at page {result.pages}: rate limited by Google")
            break
        _check(
            response,
            f"Reading the audit logs of project {project}",
            {
                403: "The service account needs roles/logging.viewer on the project, and "
                "roles/logging.privateLogViewer to read Data Access logs."
            },
        )
        result.pages += 1
        page = response.json()
        for entry in page.get("entries") or []:
            if isinstance(entry, dict):
                data_access += "data_access" in str(entry.get("logName", ""))
                yield entry
        # A page can be empty and still carry a token: the search is not done.
        page_token = page.get("nextPageToken")
        if not page_token:
            break
    if not data_access:
        result.warnings.append(
            "no Data Access audit entries (secret reads, token exchanges): either they are "
            "not enabled for the project or the account lacks roles/logging.privateLogViewer"
        )


_READERS: dict[
    str, Callable[[httpx.Client, str, datetime, datetime, Collection], Iterator[dict[str, Any]]]
] = {"github": _github_events, "gcp": _gcp_events}


def collect(
    provider: str,
    scope: str,
    since: datetime,
    until: datetime,
    dest_dir: Path,
    client: httpx.Client | None = None,
) -> Collection:
    """Collect one scope's audit log for a window into *dest_dir*.

    Writes ``<provider>-<scope>-<window>.jsonl`` and a ``.jsonl.manifest``
    beside it. Refuses a scope that is not in the configuration.

    Raises:
        CollectError: Nothing could be collected. A collection that was cut
            short after it began is returned with ``complete=False`` instead.
    """
    if scope not in targets().get(provider, []):
        raise CollectError(
            f"{provider} collection is not configured for {scope!r}. Configured: "
            f"{targets() or 'nothing'}"
        )
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{provider}-{scope}")
    stamp = f"{since:%Y%m%dT%H%M%SZ}-{until:%Y%m%dT%H%M%SZ}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / f"{name}-{stamp}.jsonl"
    result = Collection(provider, scope, _iso(since), _iso(until), str(out))
    result.collected_at = _iso(datetime.now(timezone.utc))
    digest = hashlib.sha256()
    owned = client is None
    client = client or httpx.Client()
    partial = out.with_suffix(".partial")
    try:
        with partial.open("wb") as handle:
            for event in _READERS[provider](client, scope, since, until, result):
                line = json.dumps(event, separators=(",", ":"), sort_keys=True).encode() + b"\n"
                handle.write(line)
                digest.update(line)
                result.events += 1
                if result.events >= _MAX_EVENTS:
                    result.complete = False
                    result.warnings.append(f"stopped at {_MAX_EVENTS} events; narrow the window")
                    break
    except httpx.HTTPError as exc:
        partial.unlink(missing_ok=True)
        raise CollectError(f"Could not reach {provider}: {type(exc).__name__}") from exc
    except CollectError:
        partial.unlink(missing_ok=True)
        raise
    finally:
        if owned:
            client.close()
    partial.replace(out)
    result.sha256 = digest.hexdigest()
    # Not ".json": the manifest sits beside the log and must not be read as one.
    manifest = out.with_name(out.name + ".manifest")
    manifest.write_text(json.dumps(asdict(result), indent=2) + "\n", encoding="utf-8")
    return result
