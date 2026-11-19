"""Microsoft 365 and Entra ID audit records: which log a record is, the fields a
business email compromise case turns on, and a deterministic summary of them.

Pure functions over decoded records. ``mulder.server.tools.cloudlogs`` reads the files,
indexes the events, loads the log tables and runs Sigma; this module says what a record
is and what is in it. Field names follow Microsoft's schema documentation and real
records; the comments say where the two differ.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from mulder.logtable import normalise_time

__all__ = [
    "EXPORT_CAPS",
    "TYPES",
    "Record",
    "export_warnings",
    "read_csv",
    "recognise",
    "summarise",
]

#: Log type -> what it is called in a summary.
TYPES = {
    "m365": "Microsoft 365 unified audit log",
    "entra_signin": "Entra ID sign-in log",
    "entra_audit": "Entra ID audit log",
}

#: Record counts at which an export stops without saying so. Search-UnifiedAuditLog
#: returns 100 results unless ResultSize asks for more, at most 5,000 sorted and 50,000
#: with ReturnLargeSet (10,000 when the two session commands are mixed); a Purview
#: export stops at 50,000 rows, or at 1,000,000 with Audit (Premium).
EXPORT_CAPS = frozenset({100, 5_000, 10_000, 50_000, 1_000_000})

_VALUE_CHARS = 500
_LISTED_CHARS = 120  # one value among several listed on a line
_DETAIL_CHARS = 1000
# The index cuts a line longer than its 4,096-character window in two, and the second
# piece reads back as a line of its own that begins with text taken from a record.
_LINE_CHARS = 4000
_MAX_USERS = 50
_MAX_VALUES = 10
_MAX_SESSIONS = 200
_MAX_OPERATIONS = 40  # of each kind
_MAX_MAILBOXES = 200

# One AuditData value can list every message of a two-minute window. The limit is the
# csv module's own, for the whole process: nothing else in mulder relies on the default.
csv.field_size_limit(32 * 1024 * 1024)

# Exchange Online's own service accounts ("NT AUTHORITY\SYSTEM (Microsoft.Exchange.
# ServiceHost)"): they provision every mailbox with the cmdlets an intruder also uses.
_SYSTEM = "NT AUTHORITY\\"
# Windows PowerShell 5.1's ConvertTo-Json writes a DateTime as "\/Date(<epoch ms>)\/".
_PS_DATE = re.compile(r"/Date\((-?\d{1,15})(?:[+-]\d{4})?\)/")

# Graph audit-query field -> the Management Activity API name of the same value.
_GRAPH_AUDIT = {
    "createdDateTime": "CreationTime",
    "operation": "Operation",
    "userPrincipalName": "UserId",
    "clientIp": "ClientIP",
    "objectId": "ObjectId",
    "service": "Workload",
    "id": "Id",
}

# Operation (lower case, without the trailing period the unified audit log adds to
# directory operations) -> what it leaves behind. Set-Mailbox is decided by its
# parameters in _persistence.
_PERSISTENCE = {
    "new-inboxrule": "inbox rule",
    "set-inboxrule": "inbox rule",
    "updateinboxrules": "inbox rule",
    "add-mailboxpermission": "mailbox permission",
    "add-recipientpermission": "mailbox permission",
    "add-mailboxfolderpermission": "mailbox permission",
    "new-transportrule": "transport rule",
    "set-transportrule": "transport rule",
    "set-mailboxauditbypassassociation": "audit logging",
    "set-adminauditlogconfig": "audit logging",
    "consent to application": "application consent",
    "add delegated permission grant": "application consent",
    "add app role assignment to service principal": "application consent",
    "add service principal credentials": "application credentials",
    "update application – certificates and secrets management": "application credentials",
    "user registered security info": "authentication method",
    "user registered all required security info": "authentication method",
    "admin registered security info": "authentication method",
}
_FORWARDING = {"forwardingsmtpaddress", "forwardingaddress"}


class Record(dict[str, Any]):
    """One recognised record as exported, with its log type and the fields derived from
    it. They are worked out once, so the text line, the table row and the summary agree."""

    kind: str
    fields: dict[str, Any]


def _line(value: object) -> str:
    """One bounded printable line; "" for nothing, an object or an array.

    ``str.split`` breaks on every Unicode line separator and ``isprintable`` drops
    control and format characters, so a value from a record cannot start a second line
    where it is indexed or carry an escape sequence to whoever reads it.
    """
    if value is None or isinstance(value, dict | list):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = " ".join(str(value)[: 4 * _VALUE_CHARS].split())
    return "".join(ch for ch in text if ch.isprintable())[:_VALUE_CHARS]


def _cut(text: str, limit: int) -> str:
    """*text* in at most *limit* characters; one that was cut short ends in "…"."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _first(*values: object) -> object:
    """The first value that is not empty; "" when all are. 0 and False are values."""
    return next((v for v in values if v not in (None, "", [], {})), "")


def _obj(value: object) -> object:
    """Decode a JSON value that an exporter left as a string: an object or array (a CSV
    column, AuditData, a Log Analytics dynamic field) or a quoted string (the new value
    of a directory audit's modified property). Anything else is returned as it is."""
    if isinstance(value, str) and value[:1] in ("{", "[", '"'):
        try:
            return json.loads(value)
        except (ValueError, RecursionError):
            return value
    return value


def _get(record: object, *path: str) -> object:
    """Follow *path* through nested objects whatever the case of their keys; "" where it
    runs out. Graph writes camelCase, Log Analytics and the PowerShell modules PascalCase."""
    current = record
    for name in path:
        current = _obj(current)
        if not isinstance(current, dict):
            return ""
        wanted = name.lower()
        current = next((v for k, v in current.items() if str(k).lower() == wanted), "")
    return current


def fold(pairs: object) -> dict[str, object]:
    """An array of name/value pairs as one object.

    Parameters, ExtendedProperties, OperationProperties and DeviceProperties are
    ``[{"Name", "Value"}]``, ModifiedProperties ``[{"Name", "NewValue", "OldValue"}]``
    (Graph: ``displayName``, ``newValue``) and Graph's additionalDetails
    ``[{"key", "value"}]``. A name that repeats keeps every value, in a list.
    """
    folded: dict[str, list[object]] = {}
    for pair in pairs if isinstance(pairs, list) else ():
        if not isinstance(pair, dict):
            continue
        low = {str(key).lower(): value for key, value in pair.items()}
        name = _first(low.get("name"), low.get("displayname"), low.get("key"))
        if isinstance(name, str) and name:
            folded.setdefault(name, []).append(low.get("value", low.get("newvalue", "")))
    return {name: values[0] if len(values) == 1 else values for name, values in folded.items()}


def _ip(value: object) -> str:
    """A source address without the port or brackets some workloads add
    ("203.0.113.9:443", "[2001:db8::1]:443"), and an IPv4-mapped IPv6 address as the
    IPv4 one, so one client compares equal across workloads and logs. Text that is not
    an address is returned as it was."""
    text = _line(value)
    if text.startswith("["):
        text = text[1:].partition("]")[0]
    elif text.count(":") == 1:
        text = text.partition(":")[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text
    return str(getattr(address, "ipv4_mapped", None) or address)


@lru_cache(maxsize=4096)
def _loopback(ip: str) -> bool:
    """Whether *ip* is a loopback address; text that is not an address is not one."""
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _unified(e: Mapping[str, Any]) -> tuple[dict[str, object], dict[str, object]]:
    """Columns and further fields of a unified audit log record."""
    extended = fold(e.get("ExtendedProperties"))
    context = e.get("AppAccessContext")
    # The schema documents ErrorCode; Entra sign-in records carry ErrorNumber.
    error = _first(e.get("ErrorNumber"), e.get("ErrorCode"))
    return {
        "event_time": e.get("CreationTime"),
        "actor": e.get("UserId"),
        # ClientIP for SharePoint, Entra and Exchange admin records, ClientIPAddress for
        # mailbox records, ActorIpAddress for Entra sign-ins.
        "src_ip": _ip(
            _first(e.get("ClientIP"), e.get("ClientIPAddress"), e.get("ActorIpAddress"))
        ),
        "action": e.get("Operation"),
        "target": _first(e.get("ObjectId"), e.get("MailboxOwnerUPN")),
        "status": e.get("ResultStatus"),
        # UserAgent for SharePoint; ExtendedProperties for Entra sign-ins, and for Entra
        # directory changes inside its additionalDetails JSON; ClientInfoString for mailboxes.
        "user_agent": _first(
            e.get("UserAgent"),
            extended.get("UserAgent"),
            _get(extended.get("additionalDetails"), "User-Agent"),
            e.get("ClientInfoString"),
        ),
        "session_id": _first(
            e.get("SessionId"),
            _get(context, "AADSessionId"),
            fold(e.get("DeviceProperties")).get("SessionId"),
        ),
    }, {
        "event_id": e.get("Id"),
        "workload": e.get("Workload"),
        # The calling application where the record names one, else the one signed in to.
        "app_id": _first(
            e.get("ClientAppId"),
            _get(context, "ClientAppId"),
            e.get("AppId"),
            e.get("ApplicationId"),
        ),
        "error": "" if str(error) == "0" else error,
        "mailbox": e.get("MailboxOwnerUPN"),
        "access_type": fold(e.get("OperationProperties")).get("MailAccessType"),
    }


def _signin(e: Mapping[str, Any]) -> tuple[dict[str, object], dict[str, object]]:
    """Columns and further fields of an Entra sign-in (Graph signIn, Log Analytics SigninLogs)."""
    low = {key.lower(): value for key, value in e.items()}
    code = _first(_get(low.get("status"), "errorCode"), low.get("resulttype"))
    return {
        "event_time": _first(low.get("createddatetime"), low.get("timegenerated")),
        "actor": _first(
            low.get("userprincipalname"),
            low.get("serviceprincipalname"),
            low.get("userdisplayname"),
            low.get("userid"),
            low.get("serviceprincipalid"),
        ),
        "src_ip": _ip(low.get("ipaddress")),
        # What was signed in to, and the resource it asked for.
        "action": _first(low.get("appdisplayname"), low.get("appid")),
        "target": low.get("resourcedisplayname"),
        "status": "Success" if str(code) == "0" else code,
        "user_agent": low.get("useragent"),
        "session_id": low.get("sessionid"),
    }, {
        "event_id": low.get("id"),
        "app_id": low.get("appid"),
        "client_app": low.get("clientappused"),
        "interactive": low.get("isinteractive"),
        "auth_requirement": low.get("authenticationrequirement"),
        "conditional_access": low.get("conditionalaccessstatus"),
        "risk": low.get("risklevelduringsignin"),
        "country": _first(
            _get(low.get("location"), "countryOrRegion"),
            _get(low.get("locationdetails"), "countryOrRegion"),
        ),
        "asn": low.get("autonomoussystemnumber"),
        "token_id": low.get("uniquetokenidentifier"),
    }


def _first_target(record: Mapping[str, Any]) -> object:
    """The first of an Entra audit record's targetResources."""
    targets = _obj(_get(record, "targetResources"))
    return targets[0] if isinstance(targets, list) and targets else {}


def _audit(e: Mapping[str, Any]) -> tuple[dict[str, object], dict[str, object]]:
    """Columns and further fields of an Entra directory audit record (Graph
    directoryAudit, Log Analytics AuditLogs)."""
    low = {key.lower(): value for key, value in e.items()}
    by, target = low.get("initiatedby"), _first_target(e)
    return {
        "event_time": _first(low.get("activitydatetime"), low.get("timegenerated")),
        "actor": _first(
            _get(by, "user", "userPrincipalName"),
            _get(by, "app", "displayName"),
            _get(by, "user", "displayName"),
            _get(by, "user", "id"),
            _get(by, "app", "servicePrincipalId"),
        ),
        "src_ip": _ip(_get(by, "user", "ipAddress")),
        "action": _first(low.get("activitydisplayname"), low.get("operationname")),
        "target": _first(
            _get(target, "userPrincipalName"), _get(target, "displayName"), _get(target, "id")
        ),
        "status": low.get("result"),
        "user_agent": fold(_obj(low.get("additionaldetails"))).get("User-Agent"),
        "session_id": "",
    }, {
        "event_id": low.get("id"),
        "category": low.get("category"),
        "service": low.get("loggedbyservice"),
        "target_type": _get(target, "type"),
        "correlation_id": low.get("correlationid"),
    }


_FIELDS: dict[str, Callable[[Mapping[str, Any]], tuple[dict[str, object], dict[str, object]]]] = {
    "m365": _unified,
    "entra_signin": _signin,
    "entra_audit": _audit,
}
_SIGNIN_KEYS = {"conditionalaccessstatus", "clientappused", "resulttype"}


def recognise(event: dict[str, Any]) -> Record | None:
    """The Microsoft audit record in *event*, out of whatever an exporter wrapped it in;
    None when it is not one.

    ``Search-UnifiedAuditLog | ConvertTo-Json`` and the Graph audit query carry the
    record as ``AuditData`` / ``auditData`` (an object, or JSON in a string), and an
    Azure Monitor diagnostic setting carries a sign-in or directory audit as
    ``properties``. Key case is ignored for the two Entra logs: Graph, Log Analytics
    and the PowerShell modules each spell the same fields differently.
    """
    record = event
    inner = _obj(event.get("AuditData", event.get("auditData")))
    if isinstance(inner, dict):
        # Graph repeats the common fields beside auditData; take them where it lacks them.
        outer = {new: event[old] for old, new in _GRAPH_AUDIT.items() if event.get(old)}
        record = {**outer, **inner}
    elif isinstance(event.get("properties"), dict):
        record = event["properties"]
    names = {str(key).lower() for key in record}
    if "Operation" in record and "CreationTime" in record:
        kind = "m365"
    elif {"initiatedby", "targetresources"} <= names:
        kind = "entra_audit"
    elif {"appid", "ipaddress"} <= names and names & _SIGNIN_KEYS:
        kind = "entra_signin"
    else:
        return None
    columns, extra = _FIELDS[kind](record)
    found = Record(record)
    found.kind = kind
    found.fields = {name: _line(value) for name, value in columns.items()}
    when = columns["event_time"]
    if isinstance(when, str) and (stamp := _PS_DATE.fullmatch(when.strip())):
        when = int(stamp[1]) / 1000
    found.fields["event_time"] = normalise_time(when) or ""
    found.fields["extra"] = {key: text for key, value in extra.items() if (text := _line(value))}
    # A user principal name is compared without case and the workloads spell one user
    # differently: in lower case the index, the table and the summary count one user.
    for where, name in ((found.fields, "actor"), (found.fields["extra"], "mailbox")):
        if "@" in where.get(name, ""):
            where[name] = where[name].lower()
    return found


def read_csv(path: Path) -> tuple[list[dict[str, Any]], int, int]:
    """Read a Unified Audit Log CSV export: each row's event is the JSON in its
    ``AuditData`` column (Purview's export, ``Search-UnifiedAuditLog | Export-Csv``).

    Returns the events, the rows that held no event, and the line at which reading
    stopped: 0 when the file was read to its end, else the line of a field the csv module
    cannot get past, after which nothing was read or counted. A file without an
    ``AuditData`` column holds no events.
    """
    raw = path.read_bytes()
    # Windows PowerShell's Out-File writes UTF-16; Export-Csv -Encoding UTF8 a BOM.
    utf16 = raw[:2] in (b"\xff\xfe", b"\xfe\xff")
    text = raw.decode("utf-16" if utf16 else "utf-8-sig", errors="replace")
    del raw
    events: list[dict[str, Any]] = []
    damaged = stopped = 0
    column: int | None = None
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=_delimiter(text[:65536]))
    try:
        for row in reader:
            if not row:
                continue
            if column is None:
                if row[0].startswith("#TYPE"):  # Export-Csv without -NoTypeInformation
                    continue
                names = [name.strip(' "').lower() for name in row]
                if "auditdata" not in names:
                    return [], 0, 0
                column = names.index("auditdata")
                continue
            event = _obj(row[column]) if len(row) > column else None
            if isinstance(event, dict):
                events.append(event)
            else:
                damaged += 1
    except csv.Error:  # a field past the size limit, or a quote that is never closed
        damaged, stopped = damaged + 1, reader.line_num
    return events, damaged, stopped


def _delimiter(head: str) -> str:
    """The separator of the CSV that begins with *head*: the commonest of comma,
    semicolon and tab in its header line. ``Export-Csv -UseCulture`` writes the host's
    list separator, a semicolon in much of Europe."""
    lines = (line for line in head.splitlines() if line.strip())
    header = next((line for line in lines if not line.startswith("#TYPE")), "")
    return max(",;\t", key=header.count)


def export_warnings(counts: Mapping[str, int]) -> list[str]:
    """One sentence per file whose unified audit record count is exactly a size at
    which an export stops. *counts* maps a file to the records in it, read or not."""
    return [
        f"{_line(file)}: exactly {count} unified audit records, a size at which an export "
        "stops without saying so (Search-UnifiedAuditLog at 100 unless ResultSize asks for "
        "more, and at 5,000, 10,000 or 50,000; a Purview export at 50,000 or 1,000,000). "
        "This export is probably incomplete: events after the last one in it may exist "
        "and are not here."
        for file, count in sorted(counts.items())
        if count in EXPORT_CAPS
    ]


def _persistence(record: Record) -> str:
    """What an operation leaves behind for later access or to hide it; "" when nothing."""
    operation = record.fields["action"].rstrip(". ").lower()
    if operation != "set-mailbox":
        return _PERSISTENCE.get(operation, "")
    names = {name.lower() for name in fold(record.get("Parameters"))}
    if names & _FORWARDING:
        return "mailbox forwarding"
    return "audit logging" if "auditenabled" in names else ""


def _details(record: Record) -> str:
    """An operation's parameters as one JSON object, from whichever name/value array
    carries them: cmdlet Parameters, a mailbox record's OperationProperties, a directory
    record's ModifiedProperties (their new values)."""
    if record.kind == "entra_audit":
        pairs = fold(_obj(_get(_first_target(record), "modifiedProperties")))
    else:
        pairs = {
            **fold(record.get("ModifiedProperties")),
            **fold(record.get("OperationProperties")),
            **fold(record.get("Parameters")),
        }
    try:
        text = json.dumps({name: _obj(value) for name, value in pairs.items()}, default=str)
    except (RecursionError, ValueError):
        # A value nested about as deep as the decoder allows cannot be written back.
        text = json.dumps({name: _line(value) for name, value in pairs.items()})
    return _cut(text, _DETAIL_CHARS)


def _bump(span: list[Any], when: str) -> None:
    """Count one event at *when* into ``[first seen, last seen, events]``."""
    span[2] += 1
    if when:
        span[0] = min(span[0] or when, when)
        span[1] = max(span[1], when)


def _listed(total: int, limit: int, rest: str) -> str:
    """Say so when only the first *limit* of *total* lines are listed, and name the log
    table query (*rest*) that counts them all."""
    return f" (the first {limit} are listed; {rest} counts all)" if total > limit else ""


def _top(counts: Counter[str]) -> str:
    """The commonest values with their event counts, and how many more there are."""
    named = [(value, n) for value, n in counts.most_common() if value]
    shown = ", ".join(f"{_cut(value, _LISTED_CHARS)} ({n})" for value, n in named[:_MAX_VALUES])
    more = len(named) - _MAX_VALUES
    return f"{shown}, and {more} more" if more > 0 else shown


def summarise(
    kind: str,
    path: str,
    records: Sequence[Record],
    warnings: Sequence[str] = (),
    repeats: int = 0,
) -> tuple[list[str], dict[str, int]]:
    """The lines of the ``cloudlog.<kind>.summary`` source, and the counts to return.

    Deterministic, and bounded whatever the export holds: per user the source IPs, user
    agents and sessions with first seen, last seen and events; sessions seen from more
    than one source IP; operations that leave access behind, with their parameters
    folded; for the unified audit log, MailItemsAccessed per mailbox and access type.
    Lines are tab-separated, lead with a first-seen time and fit one index window.
    Where a section is cut short the output says so, and names the log table query that
    is not. *repeats* is how many further records repeated one of *records* and were
    left out.
    """
    table = f"cloudlog.{kind}"
    seen: dict[tuple[str, str], dict[str, list[Any]]] = {}  # (user, field) -> value -> span
    sessions: dict[str, dict[str, list[Any]]] = {}  # session -> source IP -> span
    session_users: dict[str, set[str]] = {}
    operations: list[tuple[str, ...]] = []
    by_system = 0
    mail: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        f = record.fields
        when, user, ip, session = f["event_time"], f["actor"], f["src_ip"], f["session_id"]
        for name in ("src_ip", "user_agent", "session_id"):
            if user and f[name]:
                _bump(seen.setdefault((user, name), {}).setdefault(f[name], ["", "", 0]), when)
        # Exchange records the loopback address for its own work inside a user's session.
        if session and ip and not _loopback(ip):
            _bump(sessions.setdefault(session, {}).setdefault(ip, ["", "", 0]), when)
            session_users.setdefault(session, set()).add(user)
        label = _persistence(record) if kind != "entra_signin" else ""
        if label and user.upper().startswith(_SYSTEM):
            by_system += 1
        elif label:
            target, action = f["target"], f["action"]
            operations.append((when, label, user, action, ip, session, target, _details(record)))
        if kind == "m365" and f["action"] == "MailItemsAccessed":
            props = fold(record.get("OperationProperties"))
            how = _line(props.get("MailAccessType")) or "unknown"
            box = mail.setdefault(
                (f["extra"].get("mailbox") or user, how),
                {"span": ["", "", 0], "items": 0, "throttled": 0}
                | {name: Counter() for name in ("folders", "by", "ips", "sessions")},
            )
            _bump(box["span"], when)
            box["throttled"] += _line(props.get("IsThrottled")).lower() == "true"
            box["by"][user] += 1
            box["ips"][ip] += 1
            box["sessions"][session] += 1
            # A bind record lists the messages read per folder; a sync record names the
            # one folder that was synchronised.
            folders = record.get("Folders")
            for folder in folders if isinstance(folders, list) else ():
                items = _get(folder, "FolderItems")
                box["items"] += len(items) if isinstance(items, list) else 0
                box["folders"][_line(_get(folder, "Path"))] += 1
            parent = _get(record.get("Item"), "ParentFolder")
            box["folders"][_line(_first(_get(parent, "Name"), _get(parent, "Path")))] += 1

    times = sorted(r.fields["event_time"] for r in records if r.fields["event_time"])
    span = f", {times[0]} to {times[-1]}" if times else ""
    again = f" (and {repeats} repeats of them, counted once)" if repeats else ""
    lines = [
        f"# {TYPES[kind]} summary of {_line(path)}: {len(records)} events{again}{span}",
        f"# Computed by mulder from the events in {table}, not by a model. It describes the "
        "records in this export only: what was not logged, not retained or not exported "
        "is not here.",
    ]
    lines += [f"WARNING\t{warning}" for warning in warnings]
    if kind == "entra_signin":
        absent = [n for n in ("user_agent", "session_id") if not any(r.fields[n] for r in records)]
        if absent:
            lines.append(
                f"# No record in this export has a {' or a '.join(absent)} (a Graph v1.0 "
                "export has no user agent and no session id), so sign-ins cannot be linked "
                "by it. That is not a finding that they differ or agree."
            )

    several = sorted(  # most source IPs first
        ((s, ips) for s, ips in sessions.items() if len(ips) > 1),
        key=lambda item: (-len(item[1]), item[0]),
    )
    # The newest operations of each kind, so that many of one kind (sign-in methods are
    # registered daily) cannot push the one inbox rule off the list.
    by_kind: dict[str, list[tuple[str, ...]]] = {}
    for row in sorted(operations):
        by_kind.setdefault(row[1], []).append(row)
    kept = sorted(row for rows in by_kind.values() for row in rows[-_MAX_OPERATIONS:])

    # First the users behind a line listed below, whom the analyst will ask about: those
    # of a persistence line before those of a session line, of which a tenant has many.
    # Then those with the most source IPs.
    acted = {row[2] for row in kept}
    moved: set[str] = set().union(*(session_users[s] for s, _ in several[:_MAX_SESSIONS]))
    users = sorted(
        {user for user, _ in seen},
        key=lambda u: (u not in acted, u not in moved, -len(seen.get((u, "src_ip"), ())), u),
    )
    counts = {"users": len(users)}
    lines.append(
        f"# users: {len(users)}. One line per user and source IP, user agent or session: "
        "first seen, 'user', user, field, value, events, last seen."
    )
    for user in users[:_MAX_USERS]:
        for name in ("src_ip", "user_agent", "session_id"):
            values = seen.get((user, name), {})
            # An intruder's address is in few events beside the user's own, so when
            # there are too many values to list, the least frequent ones are kept.
            rare = sorted(values.items(), key=lambda kv: (kv[1][2], kv[1][0], kv[0]))[:_MAX_VALUES]
            for value, (first, last, events) in sorted(rare, key=lambda kv: (kv[1][0], kv[0])):
                lines.append(
                    f"{first}\tuser\t{user}\t{name}\t{value}\tevents={events}\tlast={last}"
                )
            if len(values) > _MAX_VALUES:
                only = json.dumps([{"field": "actor", "op": "eq", "value": user}])
                lines.append(
                    f"\tuser\t{user}\t{name}\t(the {_MAX_VALUES} least frequent of "
                    f'{len(values)} values are listed; log_top(table="{table}", '
                    f'fields=["{name}"], filters={only}) lists them all)'
                )
    if len(users) > _MAX_USERS:
        lines.append(
            f"# {len(users) - _MAX_USERS} more users are not listed (those named in a "
            "persistence line below come first, then those named in a session line, then "
            f'those with the most source IPs); log_top(table="{table}", '
            'fields=["actor", "src_ip"]) counts all.'
        )

    if kind != "entra_audit":
        counts["sessions_from_several_ips"] = len(several)
        rest = f'log_top(table="{table}", fields=["session_id", "src_ip"])'
        lines.append(
            f"# sessions seen from more than one source IP: {len(several)}"
            f"{_listed(len(several), _MAX_SESSIONS, rest)}. First seen, 'session', session, "
            "users, source IPs with their events and times. Loopback addresses are not counted."
        )
        for session, ips in several[:_MAX_SESSIONS]:
            first = min((s[0] for s in ips.values() if s[0]), default="")
            shown = "; ".join(
                f"{_cut(ip, _LISTED_CHARS)} (events={s[2]}, {s[0]} to {s[1]})"
                for ip, s in sorted(ips.items(), key=lambda kv: (kv[1][0], kv[0]))[:_MAX_VALUES]
            )
            who = ", ".join(sorted(filter(None, session_users[session])))[:_VALUE_CHARS]
            lines.append(f"{first}\tsession\t{session}\tusers={who}\tips={len(ips)}: {shown}")

    if kind != "entra_signin":
        counts["persistence_operations"] = len(operations)
        each = ", ".join(f"{label} {len(rows)}" for label, rows in sorted(by_kind.items()))
        system = f"; {by_system} more by Exchange's own service account are not listed"
        lines.append(
            f"# operations that leave access behind or hide it: {len(operations)}"
            f"{f' ({each})' if each else ''}{system if by_system else ''}. Time, "
            "'persistence', kind, actor, operation, source IP, session, target, parameters."
        )
        for label, rows in sorted(by_kind.items()):
            if len(rows) > _MAX_OPERATIONS:
                names = Counter(row[3] for row in rows).most_common(_MAX_VALUES)
                only = json.dumps(
                    [{"field": "action", "op": "in", "value": [n for n, _ in names]}]
                )
                lines.append(
                    f"# {label}: the newest {_MAX_OPERATIONS} of {len(rows)} are listed; "
                    f'log_rows(table="{table}", filters={only}, newest_first=True) pages '
                    "through every event of these operations."
                )
        lines += ["\t".join((row[0], "persistence", *row[1:])) for row in kept]

    if kind == "m365":
        counts["mailboxes_accessed"] = len({mailbox for mailbox, _ in mail})
        rest = (
            f'log_top(table="{table}", fields=["mailbox", "access_type"], filters='
            '[{"field": "action", "op": "eq", "value": "MailItemsAccessed"}])'
        )
        lines.append(
            f"# MailItemsAccessed by mailbox and access type: {len(mail)}"
            f"{_listed(len(mail), _MAX_MAILBOXES, rest)}. A Sync record means a folder was "
            "copied to a mail client; a Bind record lists the messages read (items)."
        )
        for (mailbox, how), box in sorted(mail.items())[:_MAX_MAILBOXES]:
            first, last, events = box["span"]
            lines.append(
                f"{first}\tmailbox\t{mailbox}\t{how}\tevents={events}\tlast={last}"
                f"\titems={box['items']}\tthrottled={box['throttled']}"
                f"\tfolders={_top(box['folders'])}\tby={_top(box['by'])}"
                f"\tips={_top(box['ips'])}\tsessions={_top(box['sessions'])}"
            )

    return [_cut(line, _LINE_CHARS) for line in lines], counts
