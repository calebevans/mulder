"""Cloud audit log MCP tool: index exported audit logs and run Sigma over them.

Mulder's agents stay offline, so nothing here calls a cloud API. The logs are
exported beforehand (``gh api``, ``gcloud logging read``, an S3 copy of
CloudTrail, a Purview or ``Search-UnifiedAuditLog`` export, Microsoft Graph) and
dropped into the evidence directory as JSON, or for the Microsoft 365 unified
audit log as the CSV it is usually exported to.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from itertools import chain, repeat
from operator import itemgetter
from pathlib import Path
from typing import Any, Literal

from mulder import logtable, m365
from mulder.assets.paths import asset_path
from mulder.extractors.classifier import JSON_LOG_EXTS, is_audit_log_csv
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
    # The two SigmaHQ rules that match raw audit records. The rest of rules/cloud/m365
    # match Defender alert names through SIEM field names, which an export does not have.
    "m365": ("rules", "cloud", "m365", "audit"),
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
# ponytail: every event of a call is held in memory, at about nine times the size of the
# files (a 361 MB export peaked at 3.4 GB). Stream per file to lift the limit.
_MAX_EXPORT_BYTES = 512 * 1024 * 1024
_MAX_FILES_NAMED = 20

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
    if isinstance(event, m365.Record):
        f = event.fields
        return (f["event_time"], f["actor"], f["action"], f["src_ip"], f["target"])
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
    elif isinstance(event, m365.Record):
        row.update(event.fields)
    return row


def _events_in(value: object) -> list[dict[str, Any] | None]:
    """The events in one decoded JSON value: a dict, a list of them, or an envelope
    around a list (CloudTrail ``Records``, an Azure diagnostic setting's ``records``, a
    Microsoft Graph page's ``value``).

    None stands for a record that is not an object, so that it can be counted.
    """
    if isinstance(value, list):
        return [event for item in value for event in _events_in(item)]
    if isinstance(value, dict):
        for key in ("Records", "records", "value"):
            inner = value.get(key)
            if isinstance(inner, list) and (key != "value" or "@odata.context" in value):
                return _events_in(inner)
        return [value]
    return [None]


def _read_events(path: Path) -> tuple[list[dict[str, Any]], int, int]:
    """Read every event in an export, whatever its framing.

    Decodes one JSON value after another, which covers a single array, JSON
    lines, pretty-printed objects, a CloudTrail ``{"Records": [...]}`` file and
    the back-to-back arrays ``gh api --paginate`` writes. A top-level array is
    read element by element, so a truncated export keeps every complete event.

    Returns:
        (events, damaged, not_objects). *damaged* counts each stretch that was not
        valid JSON and an array that truncation left open: zero for a whole file,
        and a lower bound on the events lost otherwise. *not_objects* counts the
        JSON values that are not an event because they are not an object.
    """
    raw = path.read_bytes()
    # PowerShell's ">" writes UTF-16; several exporters prepend a UTF-8 BOM.
    utf16 = raw[:2] in (b"\xff\xfe", b"\xfe\xff")
    text = raw.decode("utf-16" if utf16 else "utf-8-sig", errors="replace")
    decoder = json.JSONDecoder()
    events: list[dict[str, Any]] = []
    damaged = not_objects = 0
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
            return events, damaged + in_array, not_objects
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
            # RecursionError: nesting deeper than the decoder allows, or arrays inside
            # arrays deeper than _events_in can follow.
            value, pos = decoder.raw_decode(text, pos)
            found = _events_in(value)
        except (ValueError, RecursionError):
            damaged, in_array = damaged + 1, False
            pos = resync(pos)
            continue
        events.extend(event for event in found if event is not None)
        not_objects += found.count(None)


def _is_log_file(path: Path) -> bool:
    """Whether a directory run reads *path*: a JSON suffix, or a CSV whose header has
    the unified audit log's AuditData column."""
    suffix = path.suffix.lower()
    return suffix in JSON_LOG_EXTS or (suffix == ".csv" and is_audit_log_csv(path))


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
        elif isinstance(node, list):
            try:
                flat[prefix] = json.dumps(node, default=str)
            except RecursionError:  # nested about as deep as the decoder allows
                continue
        elif node is not None and node != "":
            flat[prefix] = node
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

    Call when the evidence holds audit log exports (type "cloud_audit_log"):
    GitHub audit logs, GCP Cloud Audit Logs, AWS CloudTrail, the Microsoft 365
    unified audit log (type m365), Entra ID sign-in logs (entra_signin) or Entra
    ID audit logs (entra_audit). Reads JSON arrays, JSON lines, CloudTrail Records
    files and unified audit log CSV exports, and recognises the log type per event.

    Returns per-type event and detection counts. Events are indexed one per line
    in cloudlog.<type> (time, actor, action, source IP, target, raw event) and
    Sigma matches in cloudlog.<type>.detections; other JSON is indexed as
    cloudlog.generic and scanned only when ruleset_path is given. Files that
    were damaged, truncated, held no events or held JSON values that are not
    objects are named in files_with_problems.
    One call reads at most 512 MiB of files, because every event is held in
    memory: past that it returns an error naming the files, to be run one per
    call. A file that is a symlink is not read.
    Every type but generic is also loaded as rows into a log table of the
    source's name, which log_top, log_histogram and log_rows count over. A path
    inside one that was already loaded adds no rows (log_table_note says so).
    The three Microsoft types also get cloudlog.<type>.summary (summary_source):
    per user the source IPs, user agents and sessions, sessions seen from more
    than one source IP, operations that leave access behind, and mailbox access.
    export_warnings names a unified audit log file whose record count is exactly
    a size at which exports stop: it is probably incomplete. A Microsoft record
    that the exports hold twice (the same Id and content) is kept once, and
    duplicates_skipped counts the rest. The two Entra types have no default
    Sigma rules.

    Args:
        evidence_path: A log file, or a directory searched recursively for
            .json, .jsonl and .ndjson files and unified audit log .csv exports.
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
            f for f in root.rglob("*") if not f.is_symlink() and _is_log_file(f) and f.is_file()
        )
    elif root.is_file() and not root.is_symlink():
        files = [root]
    else:
        return error_response(
            tc_id,
            name,
            params,
            f"Not a regular file (a symlink is not followed): {evidence_path}",
            error_type="invalid_argument",
        )

    sizes = {str(f): f.stat().st_size for f in files}
    if sum(sizes.values()) > _MAX_EXPORT_BYTES:
        largest = sorted(sizes.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_FILES_NAMED]
        return error_response(
            tc_id,
            name,
            params,
            f"{evidence_path} holds {sum(sizes.values()) // 2**20} MiB of log files in "
            f"{len(files)} files, and one call reads at most {_MAX_EXPORT_BYTES // 2**20} MiB "
            "because every event is held in memory. Nothing was read. Call the tool once "
            "per file or subdirectory instead; a single file over the limit has to be "
            "exported again over shorter date ranges, or split by the investigator (each "
            "part of a CSV needs the header line). The largest files: "
            + "; ".join(f"{_flat(file)} ({size // 2**20} MiB)" for file, size in largest),
            error_type="invalid_argument",
        )

    by_type: dict[str, list[tuple[str, dict[str, Any]]]] = {}  # type -> (index line, event)
    problems: dict[str, str] = {}
    # What was not read, per log type of the file it was in ("" when the file shows
    # none): the log tables report it, so a count over a damaged export says so.
    lost: dict[str, int] = {}
    unified: dict[str, int] = {}  # file -> unified audit log records in it
    lines_seen: set[str] = set()
    duplicates: Counter[str] = Counter()
    for file in files:
        is_csv = file.suffix.lower() == ".csv"
        not_objects = stopped = 0
        try:
            if is_csv:
                events, damaged, stopped = m365.read_csv(file)
            else:
                events, damaged, not_objects = _read_events(file)
        except (OSError, MemoryError) as exc:
            problems[str(file)] = f"unreadable: {exc}"
            events, damaged = [], 1
        else:
            if damaged and is_csv:
                problems[str(file)] = (
                    f"rows without a readable AuditData event: {damaged}; "
                    f"events read: {len(events)}"
                )
                if stopped:
                    problems[str(file)] += (
                        f"; reading stopped at line {stopped}: the rest of the file was not read"
                    )
            elif damaged:
                problems[str(file)] = f"damaged or truncated JSON; {len(events)} events recovered"
            elif not_objects:
                problems[str(file)] = (
                    f"JSON values that are not objects: {not_objects}; events read: {len(events)}"
                )
            elif not events:
                problems[str(file)] = "no events"
        kinds: Counter[str] = Counter()
        too_deep = 0
        for event in events:
            kind = _log_type(event)
            if kind == "generic" and (record := m365.recognise(event)) is not None:
                kind, event = record.kind, record
            kinds[kind] += 1
            try:
                line = _event_line(kind, event)
            except RecursionError:  # nested about as deep as the JSON decoder allows
                too_deep += 1
                continue
            # Search-UnifiedAuditLog returns a record on more than one page, and exports
            # overlap. Only a record with an Id that is the same in every byte is a repeat.
            if isinstance(event, m365.Record) and event.fields["extra"].get("event_id"):
                if line in lines_seen:
                    duplicates[kind] += 1
                    continue
                lines_seen.add(line)
            by_type.setdefault(kind, []).append((line, event))
        # The rows of a CSV, read or not: an export that stopped at a limit is that long
        # whatever was in its rows.
        unified[str(file)] = len(events) + damaged if is_csv else kinds["m365"]
        if too_deep:
            note = f"events nested too deeply to index: {too_deep}"
            problems[str(file)] = "; ".join(filter(None, (problems.get(str(file)), note)))
            damaged += too_deep
        # A value that is not an object is a lost record of the log around it. In a file
        # with no events it is no sign of a log at all (a list of tags, a number). A CSV
        # is read for one log only, so what it lost is that log's even when all was lost.
        for kind in kinds or {"m365" if is_csv else ""}:
            lost[kind] = lost.get(kind, 0) + damaged + (not_objects if kinds else 0)

    if not by_type:
        return error_response(
            tc_id,
            name,
            params,
            f"No events found in {evidence_path}",
            (time.monotonic() - t0) * 1000,
            error_type="no_data",
        )

    # Returned in full rather than as a preview: it is small, and it is where the
    # caller learns which cloudlog.* sources to search.
    summary: dict[str, object] = {"evidence_path": evidence_path, "files_read": len(files)}
    if problems:
        summary["files_with_problems"] = problems
    per_type: dict[str, object] = {}
    for log_type, pairs in sorted(by_type.items()):
        source = f"cloudlog.{log_type}"
        ordered = sorted(pairs, key=itemgetter(0))
        events = [event for _, event in ordered]
        indexed = extract_and_index(
            "\n".join(line for line, _ in ordered), source, evidence_path, "cloudlogs"
        )
        entry: dict[str, object] = {"events": len(events), "source": source}
        if duplicates[log_type]:
            entry["duplicates_skipped"] = duplicates[log_type]
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
                # Not so a file that reading a directory skips for its suffix: nothing
                # above it holds its events, and nothing above it may replace them.
                nested=root.is_dir() or _is_log_file(root.resolve()),
            )
            entry["log_table"] = source
            if "covered_by" in loaded:
                entry["log_table_note"] = (
                    "no rows added: these events are already in the table from "
                    f"{loaded['covered_by']}, which contains this path"
                )
        if log_type in m365.TYPES:
            # What the events add up to, worked out here so that no model has to count.
            warnings = m365.export_warnings(unified) if log_type == "m365" else []
            lines, counts = m365.summarise(
                log_type,
                evidence_path,
                [e for e in events if isinstance(e, m365.Record)],
                warnings,
                duplicates[log_type],
            )
            extract_and_index("\n".join(lines), f"{source}.summary", evidence_path, "cloudlogs")
            entry.update(summary_source=f"{source}.summary", summary=counts)
            if warnings:
                entry["export_warnings"] = warnings

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
