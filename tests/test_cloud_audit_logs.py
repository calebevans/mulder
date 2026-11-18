"""run_cloud_audit_logs: exported cloud audit logs are classified, indexed and scanned."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.extractors.classifier import EvidenceClassifier
from mulder.server import app
from mulder.server.tools import cloudlogs
from mulder.server.tools.cloudlogs import _MULDER_RULES, _read_events, run_cloud_audit_logs

_GITHUB = [
    {
        "@timestamp": 1731800000000,
        "action": "org.create_actions_secret",
        "actor": "mallory",
        "actor_ip": "203.0.113.9",
        "org": "acme",
    },
    {
        "@timestamp": 1731800060000,
        "action": "repo.remove_self_hosted_runner",
        "actor": "mallory",
        "repo": "acme/app",
    },
]
_GCP = {
    "protoPayload": {
        "serviceName": "iam.googleapis.com",
        "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
        "authenticationInfo": {"principalEmail": "mallory@example.com"},
        "requestMetadata": {"callerIp": "203.0.113.9"},
        "resourceName": "projects/-/serviceAccounts/ci@acme.iam.gserviceaccount.com",
    },
    "timestamp": "2026-11-10T12:01:00.5Z",
    "logName": "projects/acme/logs/cloudaudit.googleapis.com%2Factivity",
}
_CLOUDTRAIL = {
    "Records": [
        {
            "eventTime": "2026-11-10T13:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "sourceIPAddress": "203.0.113.9",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/mallory"},
        }
    ]
}


@pytest.fixture
def case(tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> CaseDB:
    """A real case database behind the server context, so indexing is not mocked."""
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    return tmp_case_db


@pytest.fixture
def logs(tmp_path: Path) -> Path:
    root = tmp_path / "cloud"
    root.mkdir()
    (root / "github.jsonl").write_text("\n".join(json.dumps(e) for e in _GITHUB))
    (root / "gcp.json").write_text(json.dumps([_GCP], indent=2))
    (root / "cloudtrail.json").write_text(json.dumps(_CLOUDTRAIL))
    (root / "package.json").write_text('{"name": "app", "version": "1.0.0"}')
    return root


def _text(db: CaseDB, source: str) -> str:
    return "".join(w.raw_text for w in db.get_windows_by_source(source))


def test_audit_log_exports_are_classified_and_other_json_is_still_skipped(logs: Path) -> None:
    found = {c.path.name: c.artifact_type for c in EvidenceClassifier().classify(logs)}

    assert found == {
        "github.jsonl": "cloud_audit_log",
        "gcp.json": "cloud_audit_log",
        "cloudtrail.json": "cloud_audit_log",
    }


def test_every_export_framing_is_read(tmp_path: Path) -> None:
    """Arrays, JSON lines, CloudTrail Records and gh's back-to-back pages."""
    a, b = _GITHUB
    cases = {
        "array": json.dumps([a, b]),
        "lines": f"{json.dumps(a)}\n{json.dumps(b)}\n",
        "pretty": json.dumps(a, indent=2) + "\n" + json.dumps(b, indent=2),
        "paginated": json.dumps([a]) + json.dumps([b]),
        "records": json.dumps({"Records": [a, b]}),
        "bom": "\ufeff" + json.dumps([a, b]),
    }
    for name, text in cases.items():
        file = tmp_path / f"{name}.json"
        file.write_text(text)
        assert _read_events(file) == ([a, b], False), name

    utf16 = tmp_path / "powershell.json"
    utf16.write_bytes(json.dumps([a, b]).encode("utf-16"))
    assert _read_events(utf16) == ([a, b], False)


def test_a_damaged_export_keeps_its_complete_events_and_says_so(tmp_path: Path) -> None:
    """Truncated mid-event, in every framing: no event lost, none invented."""
    a, b = _GITHUB
    whole = json.dumps([a, b, _GCP], indent=2)
    cut = whole[: whole.rindex('"timestamp"')]  # inside the third, nested event
    cases = {
        "pretty-array": cut,
        "compact-array": json.dumps([a, b, _GCP])[:-40],
        "lines": f'{json.dumps(a)}\n{json.dumps(b)}\n{{"action": "cut off',
        "bad-line-in-the-middle": f"{json.dumps(a)}\nnot json at all\n{json.dumps(b)}\n",
    }
    for name, text in cases.items():
        file = tmp_path / f"{name}.json"
        file.write_text(text)
        assert _read_events(file) == ([a, b], True), name


@pytest.mark.parametrize("poison", ["[" * 200_000, '{"n": ' + "9" * 5000 + "}"])
def test_one_unparseable_file_does_not_cost_the_rest(
    case: CaseDB, logs: Path, poison: str
) -> None:
    """Nesting past the decoder's depth, or an integer too long to convert."""
    (logs / "poison.json").write_text(poison)

    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        result = run_cloud_audit_logs.__wrapped__(str(logs))  # type: ignore[attr-defined]

    summary = result["results"]
    assert summary["log_types"]["github"]["events"] == 2
    assert str(logs / "poison.json") in summary["files_with_problems"]


def test_events_are_indexed_per_log_type_even_when_sigma_cannot_run(
    case: CaseDB, logs: Path
) -> None:
    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        result = run_cloud_audit_logs.__wrapped__(str(logs))  # type: ignore[attr-defined]

    types = result["results"]["log_types"]
    assert {t: v["events"] for t, v in types.items()} == {
        "aws": 1,
        "gcp": 1,
        "generic": 1,
        "github": 2,
    }
    assert types["github"]["sigma"].startswith("skipped")
    # package.json is one object that is not a log event: indexed, not hidden.
    assert "files_with_problems" not in result["results"]

    github = _text(case, "cloudlog.github").splitlines()
    # Epoch milliseconds become ISO, and the summary columns lead the line.
    assert github[0].startswith(
        "2024-11-16T23:33:20Z\tmallory\torg.create_actions_secret\t203.0.113.9\tacme\t"
    )
    assert _text(case, "cloudlog.gcp").startswith(
        "2026-11-10T12:01:00.5Z\tmallory@example.com\t"
        "google.iam.admin.v1.CreateServiceAccountKey\t203.0.113.9\t"
    )
    assert "iam.amazonaws.com:CreateAccessKey" in _text(case, "cloudlog.aws")
    # The event's own time is what the timeline sees.
    window = case.get_windows_by_source("cloudlog.github")[0]
    assert str(window.event_time).startswith("2024-11-16T23:33:20")
    assert case.search_windows("mallory", source_name="cloudlog.gcp")


def test_a_second_run_is_skipped_unless_forced(case: CaseDB, logs: Path) -> None:
    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        run_cloud_audit_logs.__wrapped__(str(logs))  # type: ignore[attr-defined]
        again = run_cloud_audit_logs.__wrapped__(str(logs))  # type: ignore[attr-defined]

    assert again["results"]["status"] == "skipped"


def test_sigma_matches_are_indexed_and_gcp_gets_its_field_mapping(
    case: CaseDB, logs: Path, tmp_path: Path
) -> None:
    """Zircolite is faked; what mulder hands it and does with its output is real."""
    script = tmp_path / "zircolite.py"
    script.write_text("")
    stock = tmp_path / "stock-rules"
    stock.mkdir()
    seen: list[dict[str, Any]] = []

    def _zircolite(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        rulesets = cmd[cmd.index("--ruleset") + 1 : cmd.index("--outfile")]
        config = json.loads(Path(cmd[cmd.index("--config") + 1]).read_text())
        events = Path(cmd[cmd.index("--events") + 1]).read_text().splitlines()
        seen.append({"rulesets": rulesets, "config": config, "events": events})
        hit = {
            "title": "GCP Service Account Key Created",
            "id": "5d6f1c1e-2a57-4b0a-9d5c-0f3f6f0a7c11",
            "description": "d",
            "rule_level": "medium",
            "tags": ["attack.persistence", "attack.t1098.001"],
            "count": 1,
            "matches": [{"row_id": 1, "mulder.event_time": "2026-11-10T12:01:00.5Z"}],
        }
        Path(cmd[cmd.index("--outfile") + 1]).write_text(json.dumps([hit, {}]))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with (
        patch.object(cloudlogs, "_zircolite_script", return_value=script),
        patch.object(cloudlogs, "_missing_zircolite_modules", return_value=[]),
        patch.object(cloudlogs, "asset_path", return_value=stock),
        patch("mulder.server.tools.zircolite.subprocess.run", side_effect=_zircolite),
    ):
        result = run_cloud_audit_logs.__wrapped__(str(logs / "gcp.json"))  # type: ignore[attr-defined]

    gcp = result["results"]["log_types"]["gcp"]
    assert gcp["sigma"] == "ok"
    assert gcp["rules_matched"] == {"GCP Service Account Key Created": 1}
    assert gcp["mitre_coverage"] == {"tactics": ["persistence"], "techniques": ["T1098.001"]}

    (call,) = seen
    assert call["rulesets"] == [str(stock.resolve()), str((_MULDER_RULES / "gcp").resolve())]
    # Sigma's name for the field is added beside the real one, not instead of it.
    assert call["config"]["alias"]["protoPayload.methodName"] == "gcp.audit.method_name"
    (event,) = (json.loads(line) for line in call["events"])
    assert event["protoPayload.methodName"] == "google.iam.admin.v1.CreateServiceAccountKey"
    # Every field keeps its full path as its column name.
    assert call["config"]["mappings"] == {name: name for name in event}

    detections = _text(case, "cloudlog.gcp.detections").splitlines()
    # The event's own time, carried through the scan by mulder.
    assert detections[1].startswith("2026-11-10T12:01:00.5Z\tmedium\tGCP Service Account Key")


def test_generic_json_is_indexed_but_not_scanned_without_a_ruleset(
    case: CaseDB, tmp_path: Path
) -> None:
    file = tmp_path / "app.jsonl"
    file.write_text('{"time": "2026-11-10T09:00:00Z", "msg": "login", "user": "bob"}\n')

    result = run_cloud_audit_logs.__wrapped__(str(file))  # type: ignore[attr-defined]

    generic = result["results"]["log_types"]["generic"]
    assert generic["events"] == 1
    assert generic["sigma"].startswith("skipped: no Sigma rules")
    assert _text(case, "cloudlog.generic").startswith("2026-11-10T09:00:00Z\t")


def test_a_path_with_no_events_is_an_error(case: CaseDB, tmp_path: Path) -> None:
    result = run_cloud_audit_logs.__wrapped__(str(tmp_path))  # type: ignore[attr-defined]

    assert result["status"] == "error"
    assert result["error_type"] == "no_data"


def test_the_shipped_gcp_rules_are_valid_sigma() -> None:
    """Each rule compiles to the SQLite query Zircolite runs, on the mapped field."""
    collection = pytest.importorskip("sigma.collection")
    backend = pytest.importorskip("sigma.backends.sqlite")
    files = sorted((_MULDER_RULES / "gcp").glob("*.yml"))
    assert len(files) == 5

    ids = set()
    for file in files:
        text = file.read_text()
        ids.add(yaml.safe_load(text)["id"])
        rules = collection.SigmaCollection.from_yaml(text)
        (query,) = backend.sqlite.sqliteBackend().convert(rules)
        assert "gcp.audit.method_name" in query, file.name
    assert len(ids) == len(files)


def test_a_nested_key_cannot_stand_in_for_a_top_level_field() -> None:
    """Zircolite names a column by its last path segment, last one wins.

    A tag called "eventName" would replace the real eventName, hiding a
    detection or forging one. Full paths cannot collide.
    """
    event = {
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "requestParameters": {"tags": {"eventName": "DescribeTrails"}},
        "userIdentity": {"type": "Root"},
        "resources": [{"ARN": "a"}],
        "empty": "",
    }

    assert cloudlogs._flatten(event) == {
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "requestParameters.tags.eventName": "DescribeTrails",
        "userIdentity.type": "Root",
        "resources": '[{"ARN": "a"}]',
    }


def test_field_names_from_the_evidence_are_made_safe_for_sql() -> None:
    """Zircolite builds its CREATE TABLE from field names, which an attacker picks."""
    flat = cloudlogs._flatten({"a' TEXT, x": {"b`c": 1, "": 2}})

    assert set(flat) == {"a__TEXT__x.b_c", "a__TEXT__x._"}


def test_a_line_separator_in_a_field_cannot_start_a_second_record() -> None:
    forged = "obj\u20282026-11-09T00:00:00Z\tadmin@victim.example\tCreateServiceAccountKey"
    event = json.loads(json.dumps(_GCP))
    event["protoPayload"]["resourceName"] = forged

    line = cloudlogs._event_line("gcp", event)

    assert len(line.splitlines()) == 1
    assert line.count("\t") == 5


def test_the_whole_event_is_indexed_however_long(case: CaseDB, tmp_path: Path) -> None:
    event = json.loads(json.dumps(_GCP))
    event["protoPayload"]["bindings"] = ["user:pad@example.com"] * 300 + ["user:NEEDLE@x.example"]
    file = tmp_path / "big.json"
    file.write_text(json.dumps([event]))

    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        run_cloud_audit_logs.__wrapped__(str(file))  # type: ignore[attr-defined]

    assert "NEEDLE" in _text(case, "cloudlog.gcp")


def test_github_events_are_recognised_without_an_actor_or_at_timestamp() -> None:
    disable_2fa = {"action": "org.disable_two_factor_requirement", "org": "a"}
    assert cloudlogs._log_type(disable_2fa) == "github"
    assert cloudlogs._log_type({"action": "repo.create", "created_at": 1731800000000}) == "github"
    # "action" alone, or an action that is not category.event, is not GitHub's log.
    assert cloudlogs._log_type({"action": "repo.create"}) == "generic"
    assert cloudlogs._log_type({"action": "Thriller", "actor": "Someone"}) == "generic"


def test_symlinks_are_not_followed_out_of_the_evidence(
    case: CaseDB, logs: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps([{"action": "org.outside_event", "actor": "x"}]))
    (logs / "link.json").symlink_to(outside)

    with patch.object(cloudlogs, "_zircolite_script", return_value=None):
        run_cloud_audit_logs.__wrapped__(str(logs))  # type: ignore[attr-defined]

    assert "org.outside_event" not in _text(case, "cloudlog.github")


def test_the_classifier_does_not_open_a_fifo_or_flag_unrelated_json(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe.json")  # opening it would block forever
    (tmp_path / "movies.json").write_text('[{"title": "x", "action": "y", "actor": "z"}]')

    assert EvidenceClassifier().classify(tmp_path) == []
