"""Cloud audit log MCP tool: index exported JSON audit logs and run Sigma over them.

Mulder's agents stay offline, so nothing here calls a cloud API. The logs are
exported beforehand (``gh api``, ``gcloud logging read``, an S3 copy of
CloudTrail) and dropped into the evidence directory as JSON.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from itertools import chain, repeat
from operator import itemgetter
from pathlib import Path
from typing import Any, Literal

from mulder import logtable
from mulder.assets.paths import asset_path
from mulder.extractors.classifier import JSON_LOG_EXTS
from mulder.server.app import get_ctx, mcp
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

# Sigma's GCP rules call protoPayload.methodName "gcp.audit.method_name"; the
# event keeps its real field name and gains this one beside it.
_GCP_ALIASES = {
    "protoPayload.methodName": "gcp.audit.method_name",
    "protoPayload.serviceName": "gcp.audit.service_name",
}

# SQLite's column limit. Zircolite loads events into one table, a column per field.
_MAX_SIGMA_FIELDS = 1990
_TIME_FIELD = "mulder.event_time"
_UNSAFE_FIELD_CHARS = re.compile(r"[^A-Za-z0-9_.@-]")
_TOP_LEVEL_START = re.compile(r"\n(?=[\[{])")
_SUMMARY_CHARS = 500

_GENERIC_TIME_KEYS = ("timestamp", "@timestamp", "time", "eventTime", "created_at", "date")


def _log_type(event: dict[str, Any]) -> str:
    """Name the audit log an event came from, by the keys only that log has."""
    if "protoPayload" in event:
        return "gcp"
    if "eventSource" in event and "eventName" in event:
        return "aws"
    # GitHub audit actions are "category.event" ("org.create_actions_secret").
    action = event.get("action")
    if (
        isinstance(action, str)
        and "." in action
        and any(key in event for key in ("actor", "@timestamp", "created_at", "org"))
    ):
        return "github"
    return "generic"


def _iso(value: object) -> str:
    """Render a log timestamp as ISO 8601 UTC; epoch numbers are converted."""
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return ""
    if isinstance(value, str):
        return value
    seconds = value / 1000 if value > 1e11 else value  # GitHub logs epoch milliseconds
    try:
        return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


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


def _flat(value: object) -> str:
    """One bounded line. ``str.split`` breaks on every Unicode line separator,
    so an object name holding U+2028 cannot start a second, forged record."""
    return " ".join(str(value).split())[:_SUMMARY_CHARS]


def _event_line(log_type: str, event: dict[str, Any]) -> str:
    """One tab-separated line per event: the summary columns, then the whole event.

    The timestamp leads so the per-window timestamp extraction in
    ``extract_and_index`` reads the event's own time. The event is complete and
    ASCII-escaped JSON, so nothing in it can break the line.
    """
    raw = json.dumps(event, default=str, separators=(",", ":"), sort_keys=True)
    return "\t".join([*(_flat(v) for v in _summary(log_type, event)), raw])


def _log_row(log_type: str, event: dict[str, Any], line: int) -> dict[str, object]:
    """The event as a log table row (``mulder.logtable.ingest``); *line* is its line in
    the indexed text. The first five values are the ones the text line leads with."""
    when, actor, action, src_ip, target = _summary(log_type, event)
    row: dict[str, object] = {
        "event_time": when,
        "actor": actor,
        "action": action,
        "src_ip": src_ip,
        "target": target,
        "line": line,
    }
    if log_type == "aws":
        failed = event.get("errorCode") or ("Failure" if event.get("errorMessage") else "")
        row.update(
            # CloudTrail records an errorCode or errorMessage only when a call fails.
            status=failed or "Success",
            user_agent=event.get("userAgent"),
            session_id=_dig(event, "userIdentity", "accessKeyId"),
            bytes=_dig(event, "additionalEventData", "bytesTransferredOut"),
            extra={
                "event_id": event.get("eventID"),
                "identity_type": _dig(event, "userIdentity", "type"),
                "account": event.get("recipientAccountId"),
                "read_only": event.get("readOnly"),
            },
        )
    elif log_type == "gcp":
        row.update(
            # google.rpc.Status: a missing or zero code is OK.
            status=_dig(event, "protoPayload", "status", "code") or "OK",
            user_agent=_dig(event, "protoPayload", "requestMetadata", "callerSuppliedUserAgent"),
            extra={"event_id": event.get("insertId")},
        )
    elif log_type == "github":
        row.update(
            user_agent=event.get("user_agent"),
            session_id=event.get("hashed_token"),
            extra={
                "event_id": event.get("_document_id"),
                "country": _dig(event, "actor_location", "country_code"),
            },
        )
    return row


def _events_in(value: object) -> list[dict[str, Any] | None]:
    """The events in one decoded JSON value: a dict, a list of them, or CloudTrail Records.

    None stands for a record that is not an object, so that it can be counted.
    """
    if isinstance(value, list):
        return [event for item in value for event in _events_in(item)]
    if isinstance(value, dict):
        records = value.get("Records")
        return _events_in(records) if isinstance(records, list) else [value]
    return [None]


def _read_events(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Read every event in an export, whatever its framing.

    Decodes one JSON value after another, which covers a single array, JSON
    lines, pretty-printed objects, a CloudTrail ``{"Records": [...]}`` file and
    the back-to-back arrays ``gh api --paginate`` writes. A top-level array is
    read element by element, so a truncated export keeps every complete event.

    Returns:
        (events, skipped). *skipped* counts what was not read: each stretch that
        was not valid JSON, an array that truncation left open, and each record
        that is not an object. It is zero for a whole file, and a lower bound on
        the events lost otherwise.
    """
    raw = path.read_bytes()
    # PowerShell's ">" writes UTF-16; several exporters prepend a UTF-8 BOM.
    utf16 = raw[:2] in (b"\xff\xfe", b"\xfe\xff")
    text = raw.decode("utf-16" if utf16 else "utf-8-sig", errors="replace")
    decoder = json.JSONDecoder()
    events: list[dict[str, Any]] = []
    skipped = 0
    pos, end = 0, len(text)

    def resync(at: int) -> int:
        # Resume only at a line that opens a value in column 0. Resuming
        # mid-object would turn nested fragments into bogus events.
        match = _TOP_LEVEL_START.search(text, at)
        return match.end() if match else end

    in_array = False
    while True:
        while pos < end and (text[pos].isspace() or (in_array and text[pos] == ",")):
            pos += 1
        if pos >= end:
            return events, skipped + in_array
        if in_array and text[pos] == "]":
            in_array = False
            pos += 1
            continue
        if not in_array and text[pos] == "[":
            in_array = True
            pos += 1
            continue
        try:
            # ValueError: malformed, or an integer too long to convert.
            # RecursionError: nesting deeper than the decoder allows.
            value, pos = decoder.raw_decode(text, pos)
        except (ValueError, RecursionError):
            skipped, in_array = skipped + 1, False
            pos = resync(pos)
            continue
        found = _events_in(value)
        events.extend(event for event in found if event is not None)
        skipped += found.count(None)


def _flatten(event: dict[str, Any]) -> dict[str, object]:
    """Flatten an event to ``{"full.dotted.path": value}`` for the Sigma scan.

    Zircolite would name each field by its last path segment only, with later
    fields overwriting earlier ones. A nested key such as a tag called
    "eventName" would then replace the real eventName, hiding a detection or
    forging one. Full paths cannot collide, and they are what Sigma rules for
    nested fields ("userIdentity.type") refer to.
    """
    flat: dict[str, object] = {}
    stack: list[tuple[str, object]] = [("", event)]
    while stack:
        prefix, node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                # Field names end up in SQL, and they come from the evidence.
                name = _UNSAFE_FIELD_CHARS.sub("_", str(key)) or "_"
                stack.append((f"{prefix}.{name}" if prefix else name, value))
        elif node is not None and node != "":
            flat[prefix] = json.dumps(node, default=str) if isinstance(node, list) else node
    return flat


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

    rows = []
    seen: dict[str, int] = {}
    for event in events:
        row = _flatten(event)
        row[_TIME_FIELD] = _summary(log_type, event)[0]
        rows.append(row)
        for name in row:
            seen[name] = seen.get(name, 0) + 1
    # Past the column limit Zircolite cannot load the events at all. Keep the
    # shallowest, most widely used fields, which are the ones rules match on.
    fields = sorted(seen, key=lambda f: (f.count("."), -seen[f], f))[:_MAX_SIGMA_FIELDS]
    dropped = len(seen) - len(fields)
    keep = set(fields)

    with tempfile.TemporaryDirectory(prefix="mulder_cloudlogs_") as tmpdir:
        tmp = Path(tmpdir)
        events_file = tmp / "events.json"
        events_file.write_text(
            "\n".join(json.dumps({k: v for k, v in row.items() if k in keep}) for row in rows),
            encoding="utf-8",
        )
        config = tmp / "fields.json"
        config.write_text(
            json.dumps(
                {
                    "exclusions": [],
                    "useless": [None, ""],
                    # Identity mappings: without one, Zircolite truncates a
                    # field name to its last path segment.
                    "mappings": {name: name for name in fields},
                    "alias": _GCP_ALIASES if log_type == "gcp" else {},
                    "split": {},
                }
            ),
            encoding="utf-8",
        )
        try:
            results_path, proc = _run_zircolite_process(
                str(script), events_file, "json", rulesets[0], tmp, rulesets[1:], config
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return f"error: {exc}", None
        if _NO_RULES_MARKER in f"{proc.stdout or ''}{proc.stderr or ''}":
            return "error: Zircolite loaded no rules", None
        if not results_path.exists():
            return f"error: Zircolite exited {proc.returncode} without results", None
        parsed = _parse_zircolite_output(results_path, log_path, "json", level_filter)

    for detection in parsed["detections"]:
        detection["timestamp"] = detection["matched_fields"].pop(_TIME_FIELD, "")
    if dropped:
        return f"ok ({dropped} of {len(seen)} distinct fields left out: column limit)", parsed
    return "ok", parsed


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_cloud_audit_logs(
    evidence_path: str,
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
    cloudlog.generic and scanned only when ruleset_path is given. Files that
    were damaged, truncated or held no events are named in files_with_problems.
    GitHub, GCP and AWS events are also loaded as rows into a log table of the
    source's name, which log_top, log_histogram and log_rows count over. A path
    inside one that was already loaded adds no rows (log_table_note says so).

    Args:
        evidence_path: A JSON log file, or a directory searched recursively for
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
        "evidence_path": evidence_path,
        "ruleset_path": ruleset_path,
        "sigma_level_filter": sigma_level_filter,
        "force": force,
    }

    if not force:
        existing = sources_already_indexed(["cloudlog."], evidence_path=evidence_path)
        if existing:
            skipped: dict[str, object] = {
                "status": "skipped",
                "reason": "Sources already indexed from prior extraction",
                "existing_sources": existing,
            }
            return tool_response(tc_id, name, params, skipped, None, 0.0)

    root = Path(evidence_path)
    if not root.exists():
        return error_response(
            tc_id, name, params, f"Path not found: {evidence_path}", error_type="file_not_found"
        )
    if root.is_dir():
        # Symlinks are not followed: one planted in the evidence could point anywhere.
        files = sorted(
            f
            for f in root.rglob("*")
            if f.suffix.lower() in JSON_LOG_EXTS and f.is_file() and not f.is_symlink()
        )
    elif root.is_file():
        files = [root]
    else:
        return error_response(
            tc_id,
            name,
            params,
            f"Not a regular file: {evidence_path}",
            error_type="invalid_argument",
        )

    # ponytail: every event is held in memory; stream per file if exports outgrow RAM.
    by_type: dict[str, list[dict[str, Any]]] = {}
    problems: dict[str, str] = {}
    # What was not read, per log type of the file it was in ("" when the file shows
    # none): the log tables report it, so a count over a damaged export says so.
    lost: dict[str, int] = {}
    for file in files:
        try:
            events, unread = _read_events(file)
        except (OSError, MemoryError) as exc:
            problems[str(file)] = f"unreadable: {exc}"
            events, unread = [], 1
        else:
            if unread:
                problems[str(file)] = f"damaged or truncated JSON; {len(events)} events recovered"
            elif not events:
                problems[str(file)] = "no events"
        kinds = set()
        for event in events:
            kind = _log_type(event)
            kinds.add(kind)
            by_type.setdefault(kind, []).append(event)
        for kind in kinds or {""}:
            lost[kind] = lost.get(kind, 0) + unread

    if not by_type:
        return error_response(
            tc_id,
            name,
            params,
            f"No JSON events found in {evidence_path}",
            (time.monotonic() - t0) * 1000,
            error_type="no_data",
        )

    # Returned in full rather than as a preview: it is small, and it is where the
    # caller learns which cloudlog.* sources to search.
    summary: dict[str, object] = {"evidence_path": evidence_path, "files_read": len(files)}
    if problems:
        summary["files_with_problems"] = problems
    per_type: dict[str, object] = {}
    for log_type, events in sorted(by_type.items()):
        source = f"cloudlog.{log_type}"
        ordered = sorted(((_event_line(log_type, e), e) for e in events), key=itemgetter(0))
        indexed = extract_and_index(
            "\n".join(line for line, _ in ordered), source, evidence_path, "cloudlogs"
        )
        entry: dict[str, object] = {"events": len(events), "source": source}
        if log_type != "generic":
            # The same events as rows, so log_top and log_histogram can count them. A
            # generic event has a time and nothing else to count on. What a file of this
            # type, or of no recognisable type, lost is passed as records not parsed.
            loaded = logtable.ingest(
                get_ctx().db,
                source,
                int(str(indexed["source_id"])),
                chain(
                    (_log_row(log_type, e, n) for n, (_, e) in enumerate(ordered, 1)),
                    repeat(None, lost.get(log_type, 0) + lost.get("", 0)),
                ),
                # The directory is read recursively, so a path can lie inside one that
                # was already loaded; its events are then in the table once, not twice.
                nested=True,
            )
            entry["log_table"] = source
            if "covered_by" in loaded:
                entry["log_table_note"] = (
                    "no rows added: these events are already in the table from "
                    f"{loaded['covered_by']}, which contains this path"
                )

        status, parsed = _sigma_scan(
            log_type, events, evidence_path, ruleset_path, sigma_level_filter
        )
        entry["sigma"] = status
        if parsed is not None:
            detections: list[dict[str, Any]] = parsed["detections"]
            rules: dict[str, int] = {}
            for d in detections:
                rules[d["rule_title"]] = rules.get(d["rule_title"], 0) + 1
            header = f"Sigma detections in {log_type} audit log {evidence_path}: {len(detections)}"
            extract_and_index(
                "\n".join([header, *sorted(_detection_lines(detections))]),
                f"cloudlog.{log_type}.detections",
                evidence_path,
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
