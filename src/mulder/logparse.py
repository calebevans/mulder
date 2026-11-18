"""Loose log formats: recognise a log file from its first lines, and read its lines as
log table rows (:func:`mulder.logtable.ingest`).

Nothing here opens a file. :func:`sniff` is handed a file's name and first lines and
returns a :class:`Format`; ``format.parse(line)`` returns a row, ``None`` for a line that
should have been an event and could not be read, or :data:`SKIP` for a line that is no
event (a header, a directive, a continuation). ``format.source`` names the text source
and log table of the line just parsed.

The formats: Apache and nginx access logs, IIS W3C, Zeek (tab-separated and JSON),
Suricata ``eve.json``, FortiGate and SonicWall key=value syslog, Cisco ASA, ESXi, and
syslog as the fallback. A log is evidence and may be hostile: every pattern is linear in
the line, and a name read from a log becomes a value, never a table or a field name.
"""

from __future__ import annotations

import codecs
import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

__all__ = [
    "ESXI_CATEGORIES",
    "SKIP",
    "Format",
    "Row",
    "sniff",
]

Row = dict[str, Any]
#: Returned by ``parse`` for a line that is not an event. Compared by identity.
SKIP: Row = {}

_SNIFF_LINES = 50
_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
_IP = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]+)"


def _number(value: object) -> int | None:
    """*value* as a whole number, or None."""
    try:
        return int(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None


def _total(*values: object) -> int | None:
    """The sum of the *values* that are numbers; None when none is."""
    numbers = [n for n in map(_number, values) if n is not None]
    return sum(numbers) if numbers else None


def _joined(value: object) -> object:
    """A list as one comma-separated value (a Zeek set, Suricata answers)."""
    return ",".join(map(str, value[:50])) if isinstance(value, list) else value


def _when(value: object) -> object:
    """An epoch written as text ("1705314153.12") as a number; anything else unchanged."""
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return value
    return value


def _json(line: str) -> dict[str, Any] | None:
    """One JSON object, or None when *line* is not one."""
    try:
        value = json.loads(line)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _split_uri(uri: object) -> tuple[object, object]:
    """(path, query) of a request target."""
    if not isinstance(uri, str):
        return uri, None
    path, _, query = uri.partition("?")
    return path, query or None


class Format:
    """One file's log format.

    ``source`` is the text source, and the log table, of the line just parsed.
    ``tabular`` is False for a format that yields no rows. ``naive`` and ``guessed_year``
    record what was assumed about the times read so far: no offset (read as UTC), and no
    year (taken from the file's modification time).
    """

    source = "logs.text"
    tabular = True
    naive = False
    guessed_year = False

    def parse(self, line: str) -> Row | None:
        """*line* as a row, None when it could not be read, or SKIP when it is no event."""
        raise NotImplementedError


class Text(Format):
    """A format that was not recognised: its lines are indexed and nothing is parsed."""

    tabular = False

    def parse(self, line: str) -> Row | None:
        return SKIP


# --- Web access logs ---------------------------------------------------------------

# Apache and nginx "common" and "combined", with or without a leading virtual host.
_CLF = re.compile(
    r"(?:(?P<host>\S+) )?(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]{1,40})\] "
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<agent>(?:[^"\\]|\\.)*)")?'
)


def _clf_time(stamp: str) -> str | None:
    """``10/Oct/2023:13:55:36 +0000`` as ISO 8601 with its offset."""
    try:
        day, month, rest = stamp.split("/", 2)
        year, hour, minute, tail = rest.split(":", 3)
        second, _, offset = tail.partition(" ")
        return f"{year}-{_MONTHS[month]:02d}-{day}T{hour}:{minute}:{second}{offset}"
    except (ValueError, KeyError):
        return None


def _dash(value: str | None) -> str | None:
    return None if value in (None, "-", "") else value


class Web(Format):
    """Apache and nginx access logs in the common and combined formats."""

    source = "logs.web"

    def parse(self, line: str) -> Row | None:
        match = _CLF.match(line)
        if match is None:
            return None
        request = match["request"]
        method, _, rest = request.partition(" ")
        # "GET /a b HTTP/1.1": the protocol is the last word. A request that is not
        # three words (a TLS handshake sent to a plain port) has no method.
        uri = rest.rsplit(" ", 1)[0] if " " in rest else rest
        path, query = _split_uri(uri) if rest else (request, None)
        return {
            "event_time": _clf_time(match["time"]),
            "src_ip": match["ip"],
            "actor": _dash(match["user"]),
            "action": method if rest else None,
            "target": path,
            "status": _dash(match["status"]),
            "bytes": _dash(match["bytes"]),
            "user_agent": _dash(match["agent"]),
            "extra": {"query": query, "referer": _dash(match["referer"]), "host": match["host"]},
        }


class W3C(Format):
    """IIS W3C extended logs: the columns are whatever the ``#Fields`` directive names."""

    source = "logs.web"

    def __init__(self) -> None:
        self.fields: list[str] = []
        self.date = ""

    def parse(self, line: str) -> Row | None:
        if line.startswith("#"):
            name, _, value = line.partition(":")
            if name == "#Fields":
                self.fields = value.lower().split()
            elif name == "#Date":
                self.date = (value.split() or [""])[0]
            return SKIP
        parts = line.split(" ")
        if not self.fields or len(parts) != len(self.fields):
            return None
        get = {k: v for k, v in zip(self.fields, parts, strict=True) if v != "-"}.get
        date, time = get("date", self.date), get("time")
        agent = get("cs(user-agent)")
        referer = get("cs(referer)")
        return {
            # W3C times are UTC.
            "event_time": f"{date}T{time}Z" if date and time else None,
            "src_ip": get("c-ip"),
            "actor": get("cs-username"),
            "action": get("cs-method"),
            "target": get("cs-uri-stem") or get("cs-uri"),
            "status": get("sc-status"),
            "bytes": get("sc-bytes"),
            # IIS writes a space as "+".
            "user_agent": agent.replace("+", " ") if agent else None,
            "extra": {"query": get("cs-uri-query"), "referer": referer, "host": get("cs-host")},
        }


# --- Zeek ----------------------------------------------------------------------------

_ZEEK_LOGS = ("conn", "http", "dns", "ssl", "files", "notice")
_ZEEK_NAME = re.compile(r"^(?:.*?(?:zeek|bro)[_-])?(?P<log>[a-z][a-z0-9_]*)")


def _zeek_row(log: str, rec: Mapping[str, Any]) -> Row:
    """One Zeek record as a row. The tab-separated and the JSON form share field names."""
    get = rec.get
    row: Row = {
        "event_time": _when(get("ts")),
        "src_ip": get("id.orig_h"),
        "target": get("id.resp_h"),
        "session_id": get("uid"),
    }
    extra: Row = {"dest_port": get("id.resp_p")}
    if log == "conn":
        row.update(
            action=get("service"),
            status=get("conn_state"),
            bytes=_total(get("orig_bytes"), get("resp_bytes")),
        )
        extra.update(proto=get("proto"), duration=get("duration"))
    elif log == "http":
        path, query = _split_uri(get("uri"))
        row.update(
            actor=get("username"),
            action=get("method"),
            target=path,
            status=get("status_code"),
            user_agent=get("user_agent"),
            bytes=_number(get("response_body_len")),
        )
        extra.update(
            query=query, host=get("host"), dest_ip=get("id.resp_h"), referer=get("referrer")
        )
    elif log == "dns":
        row.update(action=get("qtype_name"), target=get("query"), status=get("rcode_name"))
        extra.update(dest_ip=get("id.resp_h"), answers=_joined(get("answers")), proto=get("proto"))
    elif log == "ssl":
        row.update(target=get("server_name"), status=get("validation_status"))
        extra.update(
            dest_ip=get("id.resp_h"),
            version=get("version"),
            established=get("established"),
            subject=get("subject"),
            issuer=get("issuer"),
            ja3=get("ja3"),
        )
    elif log == "files":
        row.update(
            src_ip=_joined(get("tx_hosts")) or get("id.orig_h"),
            action=get("source"),
            target=get("filename"),
            bytes=_number(get("seen_bytes")),
            session_id=_joined(get("conn_uids")) or get("uid"),
        )
        extra.update(
            dest_ip=_joined(get("rx_hosts")) or get("id.resp_h"),
            mime_type=get("mime_type"),
            md5=get("md5"),
            sha1=get("sha1"),
            sha256=get("sha256"),
            fuid=get("fuid"),
        )
    elif log == "notice":
        row.update(
            src_ip=get("src") or get("id.orig_h"),
            target=get("dst") or get("id.resp_h"),
            action=get("note"),
        )
        extra.update(dest_port=get("p") or get("id.resp_p"), message=get("msg"), sub=get("sub"))
    else:
        # Any other Zeek log: who talked to whom, and which log said so.
        extra["log"] = log
    row["extra"] = extra
    return row


class _Zeek(Format):
    source = "logs.zeek.other"
    log = "other"

    def _set_log(self, log: object) -> None:
        self.log = str(log)
        self.source = f"logs.zeek.{self.log if self.log in _ZEEK_LOGS else 'other'}"


class ZeekTsv(_Zeek):
    """Zeek's own format: ``#fields`` names the tab-separated columns."""

    def __init__(self) -> None:
        self.sep = "\t"
        self.fields: list[str] = []
        self.unset = "-"
        self.empty = "(empty)"

    def parse(self, line: str) -> Row | None:
        if line.startswith("#separator"):
            try:
                self.sep = codecs.decode(line.split(" ", 1)[-1], "unicode_escape") or "\t"
            except ValueError:
                self.sep = "\t"
            return SKIP
        if line.startswith("#"):
            key, *values = line[1:].split(self.sep)
            if key == "fields":
                self.fields = values
            elif values and key == "path":
                self._set_log(values[0])
            elif values and key == "unset_field":
                self.unset = values[0]
            elif values and key == "empty_field":
                self.empty = values[0]
            return SKIP
        parts = line.split(self.sep)
        if not self.fields or len(parts) != len(self.fields):
            return None
        missing = (self.unset, self.empty)
        rec = {k: v for k, v in zip(self.fields, parts, strict=True) if v not in missing}
        return _zeek_row(self.log, rec)


class ZeekJson(_Zeek):
    """Zeek logs written as JSON lines. The log is ``_path``, or the file's name."""

    def __init__(self, name: str) -> None:
        match = _ZEEK_NAME.match(name.lower().split(".")[0])
        self.named = match["log"] if match else "other"

    def parse(self, line: str) -> Row | None:
        rec = _json(line)
        self._set_log((rec or {}).get("_path") or self.named)
        return _zeek_row(self.log, rec) if rec is not None else None


# --- Suricata ------------------------------------------------------------------------

_SURICATA_TYPES = ("alert", "http", "dns", "tls", "flow")


class Suricata(Format):
    """Suricata ``eve.json``: one table per event type that has its own columns."""

    source = "logs.suricata.other"

    def parse(self, line: str) -> Row | None:
        event = _json(line)
        kind = (event or {}).get("event_type")
        self.source = f"logs.suricata.{kind if kind in _SURICATA_TYPES else 'other'}"
        if event is None:
            return None
        found = event.get(kind) if isinstance(kind, str) else None
        get = (found if isinstance(found, dict) else {}).get
        row: Row = {
            # ISO 8601 with an offset that has no colon, which fromisoformat reads.
            "event_time": event.get("timestamp"),
            "src_ip": event.get("src_ip"),
            "target": event.get("dest_ip"),
            "session_id": event.get("flow_id"),
        }
        extra: Row = {"dest_port": event.get("dest_port"), "proto": event.get("proto")}
        if kind == "alert":
            row.update(action=get("signature"), status=get("action"))
            extra.update(
                signature_id=get("signature_id"),
                category=get("category"),
                severity=get("severity"),
            )
        elif kind == "http":
            path, query = _split_uri(get("url"))
            row.update(
                action=get("http_method"),
                target=path,
                status=get("status"),
                user_agent=get("http_user_agent"),
                bytes=_number(get("length")),
            )
            extra.update(query=query, host=get("hostname"), dest_ip=event.get("dest_ip"))
        elif kind == "dns":
            # Version 1 writes one event per answer with "rdata"; version 2 one event
            # with an "answers" list; later versions put the question in "queries".
            queries, answers = get("queries"), get("answers")
            first = queries[0] if isinstance(queries, list) and queries else {}
            asked = first if isinstance(first, dict) else {}
            listed = answers[:50] if isinstance(answers, list) else []
            rdata = [a.get("rdata") for a in listed if isinstance(a, dict)]
            row.update(
                action=get("type"),
                target=get("rrname") or asked.get("rrname"),
                status=get("rcode"),
            )
            extra.update(
                rrtype=get("rrtype") or asked.get("rrtype"),
                answers=get("rdata") or _joined([r for r in rdata if r]) or None,
                dest_ip=event.get("dest_ip"),
            )
        elif kind == "tls":
            ja3 = get("ja3")
            row.update(target=get("sni"))
            extra.update(
                dest_ip=event.get("dest_ip"),
                version=get("version"),
                subject=get("subject"),
                issuer=get("issuerdn"),
                fingerprint=get("fingerprint"),
                ja3=ja3.get("hash") if isinstance(ja3, dict) else None,
            )
        elif kind == "flow":
            row.update(
                action=event.get("app_proto"),
                status=get("state"),
                bytes=_total(get("bytes_toserver"), get("bytes_toclient")),
            )
            extra.update(reason=get("reason"))
        else:
            extra["event_type"] = kind
        row["extra"] = extra
        return row


# --- Syslog headers ------------------------------------------------------------------

# An optional priority and version, then an ISO 8601 time or "Mon d [yyyy] hh:mm:ss".
_HEAD = re.compile(
    r"(?:<\d{1,3}>)?(?:\d )?:?"
    r"(?:(?P<iso>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:[.,]\d+)?(?P<zone>Z|[+-]\d\d:?\d\d)?"
    r"|(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?:(?P<year>\d{4}) )?"
    r"(?P<hms>\d\d:\d\d:\d\d)(?:\.\d+)?(?: [A-Z]{2,5}(?=:))?)"
    r"\S* ?(?P<rest>.*)"
)
_PROGRAM = re.compile(
    r"(?P<host>\S+) (?P<program>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<message>.*)"
)


def _header(line: str) -> re.Match[str] | None:
    """The syslog header of *line*.

    A relay that received the line puts its own year-less header and the sender's name
    in front of it. The sender's ISO 8601 time behind those is the event's own.
    """
    head = _HEAD.match(line)
    if head and head["mon"] and not head["year"]:
        inner = _HEAD.match(head["rest"].partition(" ")[2])
        if inner and inner["iso"]:
            return inner
    return head


class _Timed(Format):
    """A format whose lines open with a syslog header."""

    def __init__(self, mtime: datetime | None = None) -> None:
        self.mtime = mtime

    def _time(self, head: re.Match[str]) -> str | None:
        """The header's time as ISO 8601, noting what had to be assumed."""
        if head["iso"]:
            self.naive = self.naive or not head["zone"]
            return f"{head['iso']}{head['zone'] or ''}"
        month, day = _MONTHS.get(head["mon"]), int(head["day"])
        year = head["year"]
        if month is None:
            return None
        if not year:
            # Syslog leaves the year out. The file was last written in some year: take
            # that one, or the one before for a date later in the calendar.
            if self.mtime is None:
                return None
            self.guessed_year = True
            ahead = (month, day) > (self.mtime.month, self.mtime.day + 1)
            year = str(self.mtime.year - 1 if ahead else self.mtime.year)
        self.naive = True
        return f"{year}-{month:02d}-{day:02d}T{head['hms']}"


class Syslog(_Timed):
    """Syslog as most daemons write it: time, host, program, message."""

    source = "logs.syslog"

    def parse(self, line: str) -> Row | None:
        head = _header(line)
        if head is None:
            return None
        found = _PROGRAM.match(head["rest"])
        extra: Row = (
            {"host": found["host"], "program": found["program"], "message": found["message"]}
            if found
            else {"message": head["rest"]}
        )
        return {"event_time": self._time(head), "extra": extra}


# --- Firewall and VPN ----------------------------------------------------------------

# A key starts where a word starts: tried inside a long run of letters, the search
# would rescan the run from every position.
_KV = re.compile(r'(?<![\w.-])([A-Za-z_][\w.-]*)=(?:"((?:[^"\\]|\\.)*)"|(\S*))')
_FORTI = re.compile(r"\bdate=\d{4}-\d\d-\d\d\s+time=\d\d:\d\d:\d\d\b")
_ASA = re.compile(r"%(?:ASA|FTD)-(?P<level>\d)-(?P<id>\d{6}): ?(?P<text>.*)")
# The VPN session messages; every other ASA message keeps only its id and text.
_ASA_VPN = {
    "113039": "session-started",
    "113019": "session-disconnected",
    "113038": "session-failed",
    "722051": "address-assigned",
    "722055": "client-type",
}
# Matched from the start of the message, with bounded fields: neither can be made to
# rescan a long line.
_ASA_WHO = re.compile(
    r"Group <(?P<group>[^>]{0,256})> User <(?P<user>[^>]{0,256})> IP <(?P<ip>[^>]{0,64})>"
)
_ASA_ENDED = re.compile(
    r"Group = (?P<group>[^,]{0,256}), Username = (?P<user>[^,]{0,256}), IP = (?P<ip>[^,]{0,64}),"
    r" Session disconnected\. Session Type: (?P<type>[^,]{0,64}), Duration: "
    r"(?P<duration>[^,]{0,64}), Bytes xmt: (?P<sent>\d+), Bytes rcv: (?P<received>\d+),"
    r" Reason: (?P<reason>.*)"
)
_ASA_ADDRESS = re.compile(r"IPv4 Address <(?P<ip>[^>]{0,64})>")
_ASA_CLIENT = re.compile(r"Client Type: (?P<client>.*)")


def _vendor(line: str) -> str | None:
    """Which firewall wrote *line*, by the marks only that vendor leaves."""
    if "%ASA-" in line or "%FTD-" in line:
        return "asa" if _ASA.search(line) else None
    if "id=firewall" in line and " sn=" in line:
        return "sonicwall"
    if _FORTI.search(line) and ("logid=" in line or "devid=" in line or "devname=" in line):
        return "fortigate"
    return None


def _pairs(line: str) -> dict[str, str]:
    """The key=value pairs of *line*. The first of a repeated key wins: the device
    writes its own fields first, and what follows may quote a visitor."""
    found: dict[str, str] = {}
    for key, quoted, bare in _KV.findall(line):
        value = quoted or bare
        if value and value != "N/A":
            found.setdefault(key, value)
    return found


class Firewall(_Timed):
    """FortiGate and SonicWall key=value logs and Cisco ASA syslog, told apart per line."""

    source = "logs.firewall"

    def parse(self, line: str) -> Row | None:
        vendor = _vendor(line)
        if vendor == "asa":
            return self._asa(line)
        if vendor == "fortigate":
            return self._fortigate(_pairs(line))
        if vendor == "sonicwall":
            return self._sonicwall(_pairs(line))
        return None

    def _fortigate(self, rec: dict[str, str]) -> Row:
        get = rec.get
        stamp: object = f"{get('date')}T{get('time')}"
        zone = get("tz", "")
        if re.fullmatch(r"[+-]\d{4}", zone):
            stamp = f"{stamp}{zone}"
        elif get("eventtime", "")[:10].isdigit() and len(get("eventtime", "")) >= 10:
            # Epoch seconds, or milli-, micro- or nanoseconds: the first ten digits.
            stamp = int(get("eventtime", "")[:10])
        else:
            self.naive = True
        # An administrator's address is inside ui="https(203.0.113.9)".
        ui = re.search(rf"\(({_IP})\)", get("ui", ""))
        return {
            "event_time": stamp,
            "actor": get("user") or get("xauthuser"),
            "src_ip": get("remip") or get("srcip") or (ui[1] if ui else None),
            "action": get("action"),
            "target": get("dstip"),
            "status": get("status"),
            "bytes": _total(get("sentbyte"), get("rcvdbyte")),
            "session_id": get("tunnelid") or get("sessionid"),
            "extra": {
                "vendor": "fortigate",
                "device": get("devname") or get("devid"),
                "log_type": "/".join(v for v in (get("type"), get("subtype")) if v) or None,
                "message_id": get("logid"),
                "level": get("level"),
                "tunnel_type": get("tunneltype"),
                "assigned_ip": get("tunnelip"),
                "dest_port": get("dstport"),
                "reason": get("reason"),
                "message": get("logdesc") or get("msg"),
            },
        }

    def _sonicwall(self, rec: dict[str, str]) -> Row:
        get = rec.get
        # time="2024-01-15 10:22:33 UTC"; without the zone it is the device's own time.
        stamp, _, zone = get("time", "").partition(" UTC")
        self.naive = self.naive or not (zone == "" and get("time", "").endswith(" UTC"))
        # src=203.0.113.50:51234:X1 is address:port:interface.
        src, dst = get("src", "").split(":"), get("dst", "").split(":")
        return {
            "event_time": stamp.strip()[:19],
            "actor": get("usr") or get("user"),
            "src_ip": src[0] or None,
            "action": get("msg"),
            "target": dst[0] or None,
            "bytes": _total(get("sent"), get("rcvd")),
            "extra": {
                "vendor": "sonicwall",
                "device": get("fw") or get("sn"),
                "message_id": get("m"),
                "level": get("pri"),
                "tunnel_type": get("sess"),
                "dest_port": dst[1] if len(dst) > 1 else None,
            },
        }

    def _asa(self, line: str) -> Row | None:
        found = _ASA.search(line)
        if found is None:
            return None
        head = _header(line[: found.start()])
        device = head["rest"].strip(" :") if head else ""
        row: Row = {"event_time": self._time(head) if head else None}
        extra: Row = {
            "vendor": "asa",
            "device": device.split(" ")[-1] or None,
            "message_id": found["id"],
            "level": found["level"],
        }
        text = found["text"]
        action = _ASA_VPN.get(found["id"])
        who = _ASA_ENDED.match(text) if found["id"] == "113019" else _ASA_WHO.match(text)
        if action is None or who is None:
            extra["message"] = text
        else:
            row.update(actor=who["user"], src_ip=who["ip"].strip(), action=action)
            extra.update(group=who["group"], tunnel_type="anyconnect")
            if found["id"] == "113019":
                row["bytes"] = _total(who["sent"], who["received"])
                extra.update(
                    tunnel_type=who["type"], duration=who["duration"], reason=who["reason"]
                )
            address, client = _ASA_ADDRESS.search(text), _ASA_CLIENT.search(text)
            if address:
                extra["assigned_ip"] = address["ip"]
            if client:
                row["user_agent"] = client["client"]
        row["extra"] = extra
        return row


# --- ESXi ----------------------------------------------------------------------------

#: The highlight categories of an ESXi log line, in the order a hypervisor ransomware
#: case usually runs: access opened, someone logs in, commands, machines stopped, the
#: execution policy touched, packages installed.
ESXI_CATEGORIES = (
    "ssh_shell_access",
    "login",
    "shell_command",
    "vm_power",
    "exec_policy",
    "vib_install",
)
_ESXI_NAMES = frozenset(
    {
        "shell",
        "auth",
        "hostd",
        "vobd",
        "vmkernel",
        "vmkwarning",
        "syslog",
        "esxupdate",
        "rhttpproxy",
        "vpxa",
    }
)
# An optional header from the syslog server that received the line, then ESXi's own
# UTC time.
_ESXI = re.compile(
    r"(?:[A-Z][a-z]{2} {1,2}\d{1,2} \d\d:\d\d:\d\d \S+ )?"
    r"(?P<time>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z:? +(?P<rest>.*)"
)
# "Hostd[263196]:" after at most a host name and a severity ("info", "In(166)").
_ESXI_PROGRAM = re.compile(r"(?:\S+ ){0,2}?(?P<program>[A-Za-z][\w-]*)\[\d+\]:? ?")
_ESXI_MARK = re.compile(
    r"Originator@6876|\[(?:vob|esx)\.[\w.]+\]|\bcpu\d+:\d+\)"
    r"|\b(?:[Hh]ostd|vobd|vmkernel|vmkwarning|esxupdate|rhttpproxy|vpxa|shell)(?:\[\d+\])?:"
)
# First match wins, so a shell command that kills machines is "vm_power".
_ESXI_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("exec_policy", re.compile(r"exec-?installed-?only", re.IGNORECASE)),
    (
        "vib_install",
        re.compile(
            r"software\s+(?:vib|component|profile)\s+(?:install|update)"
            r"|software\s+acceptance\s+set|esximage|install an image profile|no-?sig-?check",
            re.IGNORECASE,
        ),
    ),
    (
        "vm_power",
        re.compile(
            r"vm\s+process\s+kill|vmsvc/power\.(?:off|shutdown)|is powered off"
            r"|VM_STATE_POWERING_OFF|VirtualMachine\.(?:powerOff|terminate)",
            re.IGNORECASE,
        ),
    ),
    (
        "ssh_shell_access",
        re.compile(
            r"SSH access has been (?:en|dis)abled|ESXi Shell\b.{0,80}has been (?:en|dis)abled"
            r"|command line shell has been (?:en|dis)abled|\.(?:ssh|shell)\.(?:en|dis)abled\]"
            r"|hostsvc/(?:enable|start|disable|stop)_(?:ssh|esx_shell)|init\.d/SSH",
            re.IGNORECASE,
        ),
    ),
)
_ESXI_LOGIN = re.compile(
    r"accepted \S+ for |failed \S+ for |authentication failure|\blogged in\b|cannot login"
    r"|session was opened|session opened for user|rejected password|login failure",
    re.IGNORECASE,
)
_ESXI_FAILED = re.compile(r"fail|cannot|reject|invalid|denied", re.IGNORECASE)
_SHELL = re.compile(r"\[(?P<user>[^\]]{1,64})\]: (?P<command>.*)")
_USER_AT = re.compile(rf"(?<![\w.$\\-])(?P<user>[\w.$\\-]+)@(?P<ip>{_IP})")
_FOR_FROM = re.compile(rf"for (?:invalid user )?(?P<user>\S+) from (?P<ip>{_IP})")
_RHOST = re.compile(rf"rhost=(?P<ip>{_IP})?\s+user=(?P<user>\S+)")
_OP_USER = re.compile(r"\buser=(?P<user>[^\s\]]+)")
_USER_WORD = re.compile(r"\b[Uu]ser (?P<user>[\w.$\\-]+)")
_CLIENT = re.compile(r"logged in as (?P<client>.+)")


class Esxi(Format):
    """ESXi logs, as a host writes them and as a syslog server receives them.

    Every line is a row with its program and message. A line that matters in a
    hypervisor ransomware case also carries ``highlight`` (one of ESXI_CATEGORIES) and,
    where the line says, who acted, from which address and with what command.
    """

    source = "logs.esxi"

    def __init__(self, name: str) -> None:
        # vobd.log and vmkernel.log name no program on their lines: the file does.
        self.named = name.lower().split(".")[0]

    def parse(self, line: str) -> Row | None:
        if line.startswith("-->"):
            return SKIP  # the rest of a multi-line hostd entry
        match = _ESXI.match(line)
        if match is None:
            return None
        rest = match["rest"]
        found = _ESXI_PROGRAM.match(rest)
        program = found["program"].lower() if found else self.named
        message = (rest[found.end() :] if found else rest).strip()
        row: Row = {"event_time": f"{match['time']}Z"}
        extra: Row = {"program": program, "message": message}
        shell = _SHELL.match(message) if program == "shell" else None
        category = next((name for name, pat in _ESXI_PATTERNS if pat.search(message)), None)
        if category is None and shell:
            category = "shell_command"
        if category is None and _ESXI_LOGIN.search(message):
            category = "login"
            row["status"] = "failure" if _ESXI_FAILED.search(message) else "success"
        if category is not None:
            extra["highlight"] = category
            # hostd opens with "[Originator@6876 ... user=root]": not a user at an address.
            head, _, body = message.partition("] ") if message.startswith("[") else ("", "", "")
            body = body or message
            who = _USER_AT.search(body) or _FOR_FROM.search(body) or _RHOST.search(body)
            operator = _OP_USER.search(head) or _USER_WORD.search(body)
            client = _CLIENT.search(body)
            if shell:
                row.update(actor=shell["user"], action=shell["command"])
            elif who:
                row.update(actor=who["user"], src_ip=who["ip"])
            elif operator:
                row["actor"] = operator["user"]
            if client:
                row["user_agent"] = client["client"]
        row["extra"] = extra
        return row


# --- Recognition -------------------------------------------------------------------


def _most(lines: Sequence[str], test: Callable[[str], object]) -> bool:
    """Whether more than half of *lines* pass *test*."""
    return sum(1 for line in lines if test(line)) * 2 > len(lines)


def _is_syslog(line: str) -> bool:
    head = _header(line)
    return head is not None and _PROGRAM.match(head["rest"]) is not None


def sniff(
    name: str, head: Sequence[str], mtime: datetime | None = None, esxi: bool = False
) -> Format:
    """The format of the file called *name* whose first lines are *head*.

    *mtime* is the file's modification time, for syslog lines that carry no year.
    *esxi* says the file sits in the log directory of an ESXi support bundle. A file
    nothing here recognises is :class:`Text`.
    """
    lines = [line.lstrip("\ufeff") for line in head if line.strip()][:_SNIFF_LINES]
    if not lines:
        return Text()
    if any(line.startswith(("#separator", "#fields\t")) for line in lines):
        zeek = ZeekTsv()
        for line in lines:  # so that the header's own lines go to the log it names
            if line.startswith("#"):
                zeek.parse(line)
        return zeek
    fields = next((line.lower().split() for line in lines if line.startswith("#Fields:")), None)
    if fields is not None:
        web = "c-ip" in fields and not {"cs-method", "cs-uri-stem", "cs-uri"}.isdisjoint(fields)
        return W3C() if web else Text()
    if lines[0].startswith("{"):
        event = _json(lines[0]) or {}
        if "event_type" in event and "timestamp" in event:
            return Suricata()
        if "ts" in event and not {"_path", "uid", "fuid", "id.orig_h", "note"}.isdisjoint(event):
            return ZeekJson(name)
        return Text()
    if _most(lines, _vendor):
        return Firewall(mtime)
    if _most(lines, _CLF.match):
        return Web()
    if _most(lines, _ESXI.match) and (
        esxi
        or name.lower().split(".")[0] in _ESXI_NAMES
        or any(_ESXI_MARK.search(line) for line in lines)
    ):
        return Esxi(name)
    if _most(lines, _is_syslog):
        return Syslog(mtime)
    return Text()
