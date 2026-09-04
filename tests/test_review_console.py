"""Tests for durable run events and the read-only review-console adapter."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from starlette.types import ASGIApp, Message

from mulder.audit import AuditLog
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.models import AtomicClaimInput, EvidenceAnchorInput, Finding, WindowRow
from mulder.orchestrator.display import InvestigationDashboard
from mulder.review.events import RunEventDraft, RunEventJournal
from mulder.review.model import ReviewQuery, query_case_review
from mulder.review.web import ReviewConsoleConfig, ReviewConsoleError, create_review_app


@dataclass(frozen=True)
class ConsoleFixture:
    case_id: str
    case_dir: Path
    database: Path
    anchor_id: str
    malicious_title: str
    malicious_text: str


@dataclass(frozen=True)
class LocalResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")

    def json(self) -> object:
        return json.loads(self.content)


async def _request(
    app: ASGIApp,
    method: str,
    target: str,
    *,
    headers: dict[str, str] | None = None,
) -> LocalResponse:
    """Exercise the ASGI adapter directly without opening a network socket."""
    path, separator, query = target.partition("?")
    request_sent = False
    wait_forever = asyncio.Event()

    async def receive() -> Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await wait_forever.wait()
        return {"type": "http.disconnect"}

    messages: list[Message] = []

    async def send(message: Message) -> None:
        messages.append(message)

    raw_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in (headers or {}).items()
    ]
    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode() if separator else b"",
            "root_path": "",
            "headers": raw_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("test", 80),
        },
        receive,
        send,
    )
    start = next(message for message in messages if message["type"] == "http.response.start")
    response_headers = {
        name.decode("latin-1"): value.decode("latin-1")
        for name, value in start.get("headers", [])
    }
    content = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return LocalResponse(int(start["status"]), response_headers, content)


def _build_case(tmp_path: Path, case_id: str = "console-case") -> ConsoleFixture:
    case_dir = tmp_path / "cases"
    evidence_dir = tmp_path / f"evidence-{case_id}"
    evidence_dir.mkdir(parents=True)
    evidence_path = evidence_dir / "host.log"
    malicious_text = "<script>alert('evidence')</script>"
    raw_text = f"prefix {malicious_text} suffix"
    evidence_path.write_text(raw_text, encoding="utf-8")
    malicious_title = f"<img src=x onerror=alert('title') data-case='{case_id}'>"

    db = CaseDB.create(case_id, str(evidence_dir), case_dir)
    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    db.register_evidence_file(str(evidence_path), digest, evidence_path.stat().st_size)
    source_id = db.register_source(
        "host.events", str(evidence_path), f"sha256:{digest}", "fixture", 1
    )
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=40,
                line_end=40,
                event_time="2026-09-04T00:00:00Z",
                raw_text=raw_text,
            )
        ],
    )
    window = db.get_windows_by_source("host.events")[0]
    assert window.window_id is not None
    finding_id = f"finding-{case_id}"
    start = raw_text.index(malicious_text)
    db.insert_finding(
        Finding(
            finding_id=finding_id,
            case_id=case_id,
            title=malicious_title,
            description="Observed evidence; no stronger conclusion asserted.",
            severity="high",
            confidence="inference",
            evidence_refs=["tc-evidence"],
            sources=["host.events"],
            submitted_at="2026-09-04T00:00:00Z",
        ),
        [
            AtomicClaimInput(
                statement="A script-shaped literal was observed",
                subject="source:host.events",
                predicate="contains_literal",
                object_value=malicious_text,
                anchors=[
                    EvidenceAnchorInput(
                        tool_call_id="tc-evidence",
                        window_id=window.window_id,
                        char_start=start,
                        char_end=start + len(malicious_text),
                        expected_text=malicious_text,
                    )
                ],
            )
        ],
    )
    claims = db.get_claims(finding_id)
    anchor_id = claims[0].anchors[0].anchor_id
    db.close()
    return ConsoleFixture(
        case_id=case_id,
        case_dir=case_dir,
        database=case_dir / f"{case_id}.db",
        anchor_id=anchor_id,
        malicious_title=malicious_title,
        malicious_text=malicious_text,
    )


def _event_data(response_text: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for frame in response_text.split("\n\n"):
        data = "\n".join(
            line.removeprefix("data: ")
            for line in frame.splitlines()
            if line.startswith("data: ")
        )
        if data:
            loaded = json.loads(data)
            assert isinstance(loaded, dict)
            events.append(loaded)
    return events


def test_dashboard_observations_are_durably_journaled(tmp_path: Path) -> None:
    audit_path = tmp_path / "run.audit.jsonl"
    journal = RunEventJournal(audit_path, "run-case")
    with patch("mulder.orchestrator.display.psutil"):
        dashboard = InvestigationDashboard(event_journal=journal)
    dashboard.set_phase("catalog", 1, 5, "model-a", 20)
    dashboard.set_tasks("host-a", ["scan"])
    dashboard.update_task("host-a", "scan", "running")
    dashboard.update_task("host-a", "scan", "done", elapsed=1.25)
    dashboard.log_gate_pass("catalog", 4)

    events = RunEventJournal(audit_path, "run-case").read().events
    assert [event.kind for event in events] == [
        "phase_changed",
        "task_registered",
        "task_state",
        "task_state",
        "gate_result",
    ]
    assert events[0].phase == "catalog"
    assert events[-1].success is True
    assert [event.sequence for event in events] == list(range(1, len(events) + 1))


async def test_durable_sequences_and_last_event_id_replay_are_equivalent(
    tmp_path: Path,
) -> None:
    fixture = _build_case(tmp_path)
    audit_path = fixture.case_dir / f"{fixture.case_id}.audit.jsonl"
    AuditLog(audit_path).log_tool_call("tc-before", "search", {}, "sha256:x")
    journal = RunEventJournal(audit_path, fixture.case_id)
    written = [
        journal.append(RunEventDraft(kind="investigation_started", total_phases=5)),
        journal.append(RunEventDraft(kind="phase_changed", phase="catalog", phase_index=1)),
        journal.append(RunEventDraft(kind="gate_result", phase="catalog", success=True)),
    ]
    assert [event.sequence for event in written] == [2, 3, 4]

    # A fresh reader after restart sees the same durable IDs.
    reloaded = RunEventJournal(audit_path, fixture.case_id)
    complete = reloaded.read(after_sequence=0)
    prefix = complete.events[:2]
    replay = reloaded.read(after_sequence=prefix[-1].sequence)
    assert (*prefix, *replay.events) == complete.events

    app = create_review_app(ReviewConsoleConfig(fixture.case_id, fixture.case_dir))
    full_response = await _request(
        app, "GET", f"/api/cases/{fixture.case_id}/events?follow=0"
    )
    assert full_response.status_code == 200
    assert full_response.headers["content-type"].startswith("text/event-stream")
    full = _event_data(full_response.text)
    cursor = int(full[1]["sequence"])
    replay_response = await _request(
        app,
        "GET",
        f"/api/cases/{fixture.case_id}/events?follow=0",
        headers={"Last-Event-ID": str(cursor)},
    )
    assert _event_data(replay_response.text) == full[2:]


async def test_default_binding_and_non_loopback_authentication(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)
    local = ReviewConsoleConfig(fixture.case_id, fixture.case_dir)
    assert local.host == "127.0.0.1"
    assert local.loopback_only
    with pytest.raises(ReviewConsoleError, match="requires.*auth token"):
        ReviewConsoleConfig(fixture.case_id, fixture.case_dir, host="0.0.0.0")

    token = "examiner-selected-token"
    remote = ReviewConsoleConfig(
        fixture.case_id,
        fixture.case_dir,
        host="0.0.0.0",
        auth_token=token,
    )
    path = f"/api/cases/{fixture.case_id}"
    app = create_review_app(remote)
    assert (await _request(app, "GET", path)).status_code == 401
    assert (
        await _request(app, "GET", path, headers={"Authorization": "Bearer wrong"})
    ).status_code == 401
    assert (
        await _request(app, "GET", path, headers={"Authorization": f"Bearer {token}"})
    ).status_code == 200
    basic = base64.b64encode(f"mulder:{token}".encode()).decode()
    assert (
        await _request(app, "GET", path, headers={"Authorization": f"Basic {basic}"})
    ).status_code == 200


def test_cli_binds_loopback_and_rejects_unauthorized_remote_host(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)
    runner = CliRunner()
    with patch("mulder.review.web.run_review_console") as run:
        local = runner.invoke(
            cli,
            ["review-console", fixture.case_id, "--db-dir", str(fixture.case_dir)],
        )
        assert local.exit_code == 0, local.output
        config = run.call_args.args[0]
        assert config.host == "127.0.0.1"
        assert config.auth_token is None

        remote = runner.invoke(
            cli,
            [
                "review-console",
                fixture.case_id,
                "--db-dir",
                str(fixture.case_dir),
                "--host",
                "0.0.0.0",
            ],
        )
        assert remote.exit_code == 2
        assert "requires an explicit examiner-supplied auth token" in remote.output
        assert run.call_count == 1


async def test_console_uses_review_model_and_escapes_evidence_html(tmp_path: Path) -> None:
    fixture = _build_case(tmp_path)
    app = create_review_app(ReviewConsoleConfig(fixture.case_id, fixture.case_dir))
    direct = query_case_review(
        ReviewQuery(
            fixture.case_id,
            fixture.case_dir,
            finding_limit=500,
            evidence_limit=1000,
            revision_limit=1000,
        )
    )

    api_response = await _request(app, "GET", f"/api/cases/{fixture.case_id}")
    assert api_response.status_code == 200
    assert api_response.json() == direct.model_dump(mode="json", by_alias=True)
    assert api_response.headers["x-content-type-options"] == "nosniff"

    page = await _request(app, "GET", f"/cases/{fixture.case_id}")
    assert page.status_code == 200
    assert fixture.malicious_title not in page.text
    assert "&lt;img src=x onerror=alert" in page.text
    assert fixture.malicious_text not in page.text
    match = re.search(r'href="([^"]+/evidence/([^"]+))"', page.text)
    assert match is not None
    assert match.group(2) == fixture.anchor_id

    detail_page = await _request(app, "GET", match.group(1))
    assert detail_page.status_code == 200
    assert fixture.malicious_text not in detail_page.text
    assert "<mark>&lt;script&gt;alert" in detail_page.text
    detail_value = (
        await _request(
            app,
            "GET",
            f"/api/cases/{fixture.case_id}/evidence/{fixture.anchor_id}",
        )
    ).json()
    assert isinstance(detail_value, dict)
    detail = detail_value
    assert detail["citation"]["anchor_id"] == fixture.anchor_id
    assert detail["citation"]["exact_text"] == fixture.malicious_text
    assert detail["window"]["selected_text"] == fixture.malicious_text
    assert detail["window"]["raw_text"][
        detail["citation"]["char_start"] : detail["citation"]["char_end"]
    ] == fixture.malicious_text


async def test_cross_case_isolation_and_no_mutating_routes(tmp_path: Path) -> None:
    first = _build_case(tmp_path, "case-a")
    second = _build_case(tmp_path, "case-b")
    app = create_review_app(ReviewConsoleConfig(first.case_id, first.case_dir))
    before = first.database.read_bytes()

    assert (await _request(app, "GET", f"/api/cases/{second.case_id}")).status_code == 404
    assert (
        await _request(
            app, "GET", f"/api/cases/{first.case_id}/evidence/{second.anchor_id}"
        )
    ).status_code == 404
    first_page = await _request(app, "GET", f"/cases/{first.case_id}")
    assert second.malicious_title not in first_page.text

    case_path = f"/api/cases/{first.case_id}"
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert (await _request(app, method, case_path)).status_code == 405

    for route in app.routes:
        methods = getattr(route, "methods", set())
        assert methods <= {"GET", "HEAD"}
    assert first.database.read_bytes() == before
