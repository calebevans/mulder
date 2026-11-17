"""Cloud audit log MCP tool: index exported JSON audit logs and run Sigma over them.

Mulder's agents stay offline, so nothing here calls a cloud API. The logs are
exported beforehand (``gh api``, ``gcloud logging read``, an S3 copy of
CloudTrail) and dropped into the evidence directory as JSON.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mulder.assets.paths import asset_path
from mulder.extractors.classifier import JSON_LOG_EXTS
from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.zircolite import (
    _NO_RULES_MARKER,
    _detection_field,
    _detection_lines,
    _missing_zircolite_modules,
    _parse_zircolite_output,
    _run_zircolite_process,
    _zircolite_script,
)

__all__ = ["run_cloud_audit_logs"]

logger = logging.getLogger(__name__)

_MULDER_RULES = Path(__file__).resolve().parent.parent / "data" / "sigma"

# Where the SigmaHQ tree keeps the rules for each log type.
_SIGMA_RULE_DIRS: dict[str, tuple[str, ...]] = {
    "github": ("rules", "cloud", "github"),
    "gcp": ("rules", "cloud", "gcp", "audit"),
    "aws": ("rules", "cloud", "aws", "cloudtrail"),
}

# Zircolite names a nested field by its last path segment, so a GCP entry's
# protoPayload.methodName becomes "methodName". Sigma's GCP rules call it
# gcp.audit.method_name; this mapping is what makes them match.
_GCP_FIELD_CONFIG = {
    "exclusions": [],
    "useless": [None, ""],
    "mappings": {
        "protoPayload.methodName": "gcp.audit.method_name",
        "protoPayload.serviceName": "gcp.audit.service_name",
    },
    "alias": {},
    "split": {},
}

_GENERIC_TIME_KEYS = ("timestamp", "@timestamp", "time", "eventTime", "created_at", "date")


def _log_type(event: dict[str, Any]) -> str:
    """Name the audit log an event came from, by the keys only that log has."""
    if "protoPayload" in event:
        return "gcp"
    if "eventSource" in event and "eventName" in event:
        return "aws"
    if "action" in event and ("actor" in event or "@timestamp" in event):
        return "github"
    return "generic"


def _iso(value: object) -> str:
    """Render a log timestamp as ISO 8601 UTC; epoch numbers are converted."""
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, int | float):
        seconds = value / 1000 if value > 1e11 else value  # GitHub logs epoch milliseconds
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            return ""
    return str(value)


def _dig(event: dict[str, Any], *path: str) -> object:
    """Follow *path* through nested dicts; "" where it runs out."""
    current: object = event
    for key in path:
        if not isinstance(current, dict):
            return ""
        current = current.get(key, "")
    return current


def _summary(log_type: str, event: dict[str, Any]) -> tuple[str, object, object, object, object]:
    """Return (time, actor, action, source IP, target) for one event."""
    if log_type == "github":
        return (
            _iso(event.get("@timestamp") or event.get("created_at")),
            event.get("actor", ""),
            event.get("action", ""),
            event.get("actor_ip", ""),
            event.get("repo") or event.get("org", ""),
        )
    if log_type == "gcp":
        return (
            _iso(event.get("timestamp")),
            _dig(event, "protoPayload", "authenticationInfo", "principalEmail"),
            _dig(event, "protoPayload", "methodName"),
            _dig(event, "protoPayload", "requestMetadata", "callerIp"),
            _dig(event, "protoPayload", "resourceName"),
        )
    if log_type == "aws":
        return (
            _iso(event.get("eventTime")),
            _dig(event, "userIdentity", "arn") or _dig(event, "userIdentity", "type"),
            f"{event.get('eventSource', '')}:{event.get('eventName', '')}",
            event.get("sourceIPAddress", ""),
            event.get("awsRegion", ""),
        )
    stamp = next((event[k] for k in _GENERIC_TIME_KEYS if event.get(k)), "")
    return (_iso(stamp), "", "", "", "")


def _event_line(log_type: str, event: dict[str, Any]) -> str:
    """One tab-separated line per event: the summary columns, then the whole event.

    The timestamp leads so the per-window timestamp extraction in
    ``extract_and_index`` reads the event's own time.
    """
    return "\t".join(_detection_field(v) for v in (*_summary(log_type, event), event))


def _events_in(value: object) -> list[dict[str, Any]]:
    """The events in one decoded JSON value: a dict, a list of them, or CloudTrail Records."""
    if isinstance(value, list):
        return [event for item in value for event in _events_in(item)]
    if isinstance(value, dict):
        records = value.get("Records")
        return _events_in(records) if isinstance(records, list) else [value]
    return []


def _read_events(path: Path) -> list[dict[str, Any]]:
    """Read every event in an export, whatever its framing.

    Decodes one JSON value after another, which covers a single array, JSON
    lines, pretty-printed objects, a CloudTrail ``{"Records": [...]}`` file and
    the back-to-back arrays ``gh api --paginate`` writes. A line that is not
    JSON (a truncated tail) is skipped and the rest still counts.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    decoder = json.JSONDecoder()
    events: list[dict[str, Any]] = []
    pos = 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            return events
        try:
            value, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            newline = text.find("\n", pos)
            if newline == -1:
                return events
            pos = newline + 1
            continue
        events.extend(_events_in(value))


def _sigma_scan(
    log_type: str,
    events: list[dict[str, Any]],
    log_path: str,
    ruleset_path: str | None,
    level_filter: str | None,
) -> tuple[str, dict[str, Any] | None]:
    """Run Sigma over *events*. Returns (status, parsed detections or None)."""
    if ruleset_path:
        rulesets = [Path(ruleset_path)]
    else:
        parts = _SIGMA_RULE_DIRS.get(log_type)
        stock = asset_path("sigma-rules", *parts) if parts else None
        own = _MULDER_RULES / log_type
        rulesets = [r for r in (stock, own) if r is not None and r.is_dir()]
    if not rulesets:
        return "skipped: no Sigma rules for this log type (pass ruleset_path)", None

    missing = _missing_zircolite_modules()
    script = _zircolite_script()
    if missing or script is None:
        what = f"missing {', '.join(missing)}" if missing else "Zircolite is not installed"
        return f"skipped: {what} (pipx install 'mulder-dfir[forensics]'; mulder setup)", None

    with tempfile.TemporaryDirectory(prefix="mulder_cloudlogs_") as tmpdir:
        tmp = Path(tmpdir)
        events_file = tmp / "events.json"
        events_file.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
        config = None
        if log_type == "gcp":
            config = tmp / "fields.json"
            config.write_text(json.dumps(_GCP_FIELD_CONFIG), encoding="utf-8")
        try:
            results_path, proc = _run_zircolite_process(
                str(script), events_file, "json", rulesets[0], tmp, rulesets[1:], config
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return f"error: {exc}", None
        if _NO_RULES_MARKER in f"{proc.stdout or ''}{proc.stderr or ''}":
            return "error: Zircolite loaded no rules", None
        if proc.returncode != 0 and not results_path.exists():
            return f"error: Zircolite exited {proc.returncode}", None
        parsed = _parse_zircolite_output(results_path, log_path, "json", level_filter)

    for detection in parsed["detections"]:
        # CloudTrail's time field is eventTime, which Zircolite does not treat as one.
        stamp = detection["timestamp"] or detection["matched_fields"].get("eventTime")
        detection["timestamp"] = _iso(stamp)
    return "ok", parsed


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_cloud_audit_logs(
    log_path: str,
    ruleset_path: str | None = None,
    sigma_level_filter: Literal["informational", "low", "medium", "high", "critical"]
    | None = "low",
    force: bool = False,
) -> dict[str, object]:
    """Index exported cloud audit logs and apply Sigma detection rules to them.

    Call when the evidence holds JSON audit log exports (type "cloud_audit_log"):
    GitHub audit logs, GCP Cloud Audit Logs or AWS CloudTrail. Reads JSON arrays,
    JSON lines and CloudTrail Records files, and recognises the log type per event.

    Returns per-type event and detection counts. Events are indexed one per line
    in cloudlog.<type> (time, actor, action, source IP, target, raw event) and
    Sigma matches in cloudlog.<type>.detections; other JSON is indexed as
    cloudlog.generic and scanned only when ruleset_path is given.

    Args:
        log_path: A JSON log file, or a directory searched recursively for
            .json, .jsonl and .ndjson files.
        ruleset_path: Sigma rules to use instead of the defaults for every
            log type found.
        sigma_level_filter: Minimum Sigma rule level to include. Set None
            to include all levels.
        force: Re-run even if these logs were already indexed.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "run_cloud_audit_logs"
    params: dict[str, object] = {
        "log_path": log_path,
        "ruleset_path": ruleset_path,
        "sigma_level_filter": sigma_level_filter,
        "force": force,
    }

    if not force:
        existing = sources_already_indexed(["cloudlog."], evidence_path=log_path)
        if existing:
            skipped: dict[str, object] = {
                "status": "skipped",
                "reason": "Sources already indexed from prior extraction",
                "existing_sources": existing,
            }
            return tool_response(tc_id, name, params, skipped, None, 0.0)

    root = Path(log_path)
    if not root.exists():
        return error_response(
            tc_id, name, params, f"Path not found: {log_path}", error_type="file_not_found"
        )
    files = (
        sorted(f for f in root.rglob("*") if f.is_file() and f.suffix.lower() in JSON_LOG_EXTS)
        if root.is_dir()
        else [root]
    )

    # ponytail: every event is held in memory; stream per file if exports outgrow RAM.
    by_type: dict[str, list[dict[str, Any]]] = {}
    unreadable: list[str] = []
    for file in files:
        try:
            events = _read_events(file)
        except OSError as exc:
            unreadable.append(f"{file}: {exc}")
            continue
        for event in events:
            by_type.setdefault(_log_type(event), []).append(event)

    if not by_type:
        return error_response(
            tc_id,
            name,
            params,
            f"No JSON events found in {log_path}",
            (time.monotonic() - t0) * 1000,
            error_type="no_data",
        )

    # Returned in full rather than as a preview: it is small, and it is where the
    # caller learns which cloudlog.* sources to search.
    summary: dict[str, object] = {"log_path": log_path, "files_read": len(files)}
    if unreadable:
        summary["unreadable_files"] = unreadable
    per_type: dict[str, object] = {}
    for log_type, events in sorted(by_type.items()):
        lines = sorted(_event_line(log_type, e) for e in events)
        extract_and_index("\n".join(lines), f"cloudlog.{log_type}", log_path, "cloudlogs")
        entry: dict[str, object] = {"events": len(events), "source": f"cloudlog.{log_type}"}

        status, parsed = _sigma_scan(log_type, events, log_path, ruleset_path, sigma_level_filter)
        entry["sigma"] = status
        if parsed is not None:
            detections: list[dict[str, Any]] = parsed["detections"]
            rules: dict[str, int] = {}
            for d in detections:
                rules[d["rule_title"]] = rules.get(d["rule_title"], 0) + 1
            header = f"Sigma detections in {log_type} audit log {log_path}: {len(detections)}"
            extract_and_index(
                "\n".join([header, *sorted(_detection_lines(detections))]),
                f"cloudlog.{log_type}.detections",
                log_path,
                "cloudlogs",
            )
            entry.update(
                detections_source=f"cloudlog.{log_type}.detections",
                detections=len(detections),
                level_counts=parsed["level_counts"],
                rules_matched=rules,
                mitre_coverage=parsed["mitre_coverage"],
            )
        per_type[log_type] = entry
    summary["log_types"] = per_type

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, name, params, summary, None, elapsed)
