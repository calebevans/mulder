"""Loose log formats: each is recognised from its first lines and read into rows.

The lines are real ones (Splunk BOTS v1 for IIS, FortiGate and Suricata; splunk
attack_data for ESXi and Zeek) or written from the vendor's message reference where no
public sample exists (FortiGate VPN, SonicWall, Cisco ASA).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import pytest

from mulder import logparse
from mulder.logparse import SKIP, Format, sniff
from mulder.logtable import normalise_time

_MTIME = datetime(2025, 7, 8, tzinfo=UTC)

_COMBINED = (
    '203.0.113.9 - bob [10/Oct/2023:13:55:36 -0700] "POST /up/shell.php?c=id HTTP/1.1" '
    '200 2326 "http://x.example/" "curl/8.4"'
)
_IIS_FIELDS = (
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
    "cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken"
)
_IIS = (
    "2016-08-10 22:21:34 192.168.250.70 GET /joomla/agent.php - 80 - 23.22.63.114 "
    "Opera/9.02+(Windows+NT+5.1;+U;+en) http://71.39.18.126/?wNO=QS 200 0 0 78"
)
_ZEEK_HEADER = [
    "#separator \\x09",
    "#set_separator\t,",
    "#empty_field\t(empty)",
    "#unset_field\t-",
    "#path\tconn",
    "#open\t2024-01-15-10-00-00",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration"
    "\torig_bytes\tresp_bytes\tconn_state",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring",
]
_ZEEK_CONN = (
    "1705314153.123456\tCabc\t10.0.0.5\t51234\t203.0.113.9\t443\ttcp\tssl\t1.5\t100\t-\tSF"
)
_EVE_DNS_V1 = (
    '{"timestamp":"2016-08-28T23:58:59.931869-0600","flow_id":3560840892,"in_iface":"eth1",'
    '"event_type":"dns","src_ip":"8.8.8.8","src_port":53,"dest_ip":"192.168.225.125",'
    '"dest_port":53338,"proto":"UDP","dns":{"type":"answer","id":11774,"rcode":"NOERROR",'
    '"rrname":"kv401-prod.do.dsp.mp.microsoft.com.edgekey.net","rrtype":"CNAME","ttl":20773,'
    '"rdata":"e7589.g.akamaiedge.net"}}'
)
_FORTIGATE = (
    "Aug 05 06:28:35 192.168.250.1 date=2016-08-05 time=06:28:35 devname=gotham-fortigate "
    "devid=FGT60D4614044725 logid=0100026003 type=event subtype=system level=information "
    'vd="root" logdesc="DHCP statistics" interface="internal1" total=155 used=24 '
    'msg="DHCP statistics"'
)
_ESXI_VOBD = (
    "May  7 17:58:30 192.168.8.233 2025-05-07T17:58:28.526Z localhost.localdomain "
    "vobd[262381]:  [UserLevelCorrelator] 621288555us: [vob.user.ssh.enabled] "
    "SSH access has been enabled"
)


def _row(fmt: Format, line: str) -> dict[str, Any]:
    """The parsed row without empty values, its time as the table would store it."""
    row = fmt.parse(line)
    assert row, line
    out = {k: v for k, v in row.items() if v is not None and k != "extra"}
    out.update({k: v for k, v in row["extra"].items() if v is not None})
    out["event_time"] = normalise_time(row.get("event_time"))
    return out


def test_apache_and_nginx_combined_lines_become_requests() -> None:
    fmt = sniff("access.log", [_COMBINED])

    assert fmt.source == "logs.web"
    assert _row(fmt, _COMBINED) == {
        "event_time": "2023-10-10T20:55:36Z",  # the offset is applied
        "src_ip": "203.0.113.9",
        "actor": "bob",
        "action": "POST",
        "target": "/up/shell.php",
        "query": "c=id",
        "status": "200",
        "bytes": "2326",
        "referer": "http://x.example/",
        "user_agent": "curl/8.4",
    }


def test_the_common_format_a_virtual_host_and_a_request_that_is_no_request() -> None:
    fmt = sniff("access.log", [_COMBINED])
    common = '203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "GET /a%20b HTTP/1.0" 304 -'
    vhost = f"shop.example:443 {common}"
    tls = '203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "\\x16\\x03\\x01" 400 226 "-" "-"'

    assert _row(fmt, common) == {
        "event_time": "2023-10-10T13:55:36Z",
        "src_ip": "203.0.113.9",
        "action": "GET",
        "target": "/a%20b",
        "status": "304",
    }
    assert _row(fmt, vhost)["host"] == "shop.example:443"
    # A TLS handshake sent to a plain port: no method is invented for it.
    assert _row(fmt, tls)["target"] == "\\x16\\x03\\x01" and "action" not in _row(fmt, tls)
    assert fmt.parse("not an access log line") is None


def test_iis_columns_follow_the_fields_directive() -> None:
    fmt = sniff("u_ex160810.log", ["#Software: Microsoft Internet Information Services 8.5"])
    assert isinstance(fmt, logparse.Text)  # no #Fields in sight: not taken for IIS

    fmt = sniff("u_ex160810.log", ["#Version: 1.0", _IIS_FIELDS, _IIS])
    assert fmt.parse("#Date: 2016-08-10 00:00:00") is SKIP
    assert fmt.parse(_IIS) is None  # before its #Fields line a row cannot be read
    assert fmt.parse(_IIS_FIELDS) is SKIP
    assert _row(fmt, _IIS) == {
        "event_time": "2016-08-10T22:21:34Z",
        "src_ip": "23.22.63.114",
        "action": "GET",
        "target": "/joomla/agent.php",
        "status": "200",
        "user_agent": "Opera/9.02 (Windows NT 5.1; U; en)",
        "referer": "http://71.39.18.126/?wNO=QS",
    }
    # A restart writes a new header, and it may name other columns.
    assert fmt.parse("#Fields: time c-ip cs-method cs-uri-stem sc-status sc-bytes") is SKIP
    assert _row(fmt, "22:30:00 198.51.100.7 POST /x.aspx 500 12") == {
        "event_time": "2016-08-10T22:30:00Z",  # the date of the #Date directive
        "src_ip": "198.51.100.7",
        "action": "POST",
        "target": "/x.aspx",
        "status": "500",
        "bytes": "12",
    }
    assert fmt.parse("2016-08-10 22:21:34 truncated") is None


def test_w3c_logs_that_are_not_web_requests_stay_text() -> None:
    fields = "#Fields: date-time,client-ip,client-hostname,server-ip,event-id"

    assert isinstance(sniff("MSGTRK.LOG", ["#Software: Exchange", fields]), logparse.Text)


def test_zeek_tab_separated_logs_are_read_by_their_header() -> None:
    fmt = sniff("conn.log", _ZEEK_HEADER[:2])
    for line in _ZEEK_HEADER:
        assert fmt.parse(line) is SKIP

    assert fmt.source == "logs.zeek.conn"
    assert _row(fmt, _ZEEK_CONN) == {
        "event_time": "2024-01-15T10:22:33Z",
        "src_ip": "10.0.0.5",
        "target": "203.0.113.9",
        "dest_port": "443",
        "session_id": "Cabc",
        "action": "ssl",
        "status": "SF",
        "bytes": 100,  # resp_bytes is unset ("-") and adds nothing
        "proto": "tcp",
        "duration": "1.5",
    }
    assert fmt.parse("1705314153.1\tshort") is None
    assert fmt.parse("#close\t2024-01-15-11-00-00") is SKIP


@pytest.mark.parametrize(
    ("log", "fields", "values", "expected"),
    [
        (
            "http",
            "ts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tmethod\thost\turi\treferrer"
            "\tuser_agent\tresponse_body_len\tstatus_code\tusername",
            "1705314153.0\tC1\t10.0.0.5\t203.0.113.9\t80\tPOST\tshop.example\t/a.php?x=1"
            "\t-\tcurl/8\t12\t200\t-",
            {
                "action": "POST",
                "target": "/a.php",
                "query": "x=1",
                "status": "200",
                "user_agent": "curl/8",
                "bytes": 12,
                "host": "shop.example",
                "dest_ip": "203.0.113.9",
            },
        ),
        (
            "dns",
            "ts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name\trcode_name"
            "\tanswers",
            "1705314153.0\tC2\t10.0.0.5\t10.0.0.1\t53\tudp\tevil.example\tA\tNOERROR"
            "\t203.0.113.9,203.0.113.10",
            {
                "action": "A",
                "target": "evil.example",
                "status": "NOERROR",
                "answers": "203.0.113.9,203.0.113.10",
            },
        ),
        (
            "ssl",
            "ts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tversion\tserver_name\testablished",
            "1705314153.0\tC3\t10.0.0.5\t203.0.113.9\t443\tTLSv12\tc2.example\tT",
            {"target": "c2.example", "version": "TLSv12", "established": "T"},
        ),
        (
            "files",
            "ts\tfuid\ttx_hosts\trx_hosts\tconn_uids\tsource\tmime_type\tfilename\tseen_bytes"
            "\tsha256",
            "1705314153.0\tF1\t203.0.113.9\t10.0.0.5\tC4\tHTTP\tapplication/x-dosexec"
            "\tupdate.exe\t4096\tabc123",
            {
                "src_ip": "203.0.113.9",
                "dest_ip": "10.0.0.5",
                "action": "HTTP",
                "target": "update.exe",
                "bytes": 4096,
                "session_id": "C4",
                "sha256": "abc123",
            },
        ),
        (
            "notice",
            "ts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tnote\tmsg\tsrc\tdst\tp",
            "1705314153.0\tC5\t10.0.0.5\t10.0.0.9\t445\tScan::Port_Scan\t10.0.0.5 scanned"
            "\t10.0.0.5\t10.0.0.9\t445",
            {"action": "Scan::Port_Scan", "message": "10.0.0.5 scanned", "target": "10.0.0.9"},
        ),
    ],
)
def test_each_zeek_log_has_its_own_columns(
    log: str, fields: str, values: str, expected: dict[str, object]
) -> None:
    fmt = sniff(f"{log}.log", ["#separator \\x09"])
    for line in ("#separator \\x09", f"#path\t{log}", f"#fields\t{fields}"):
        fmt.parse(line)

    row = _row(fmt, values)

    assert fmt.source == f"logs.zeek.{log}"
    assert row["event_time"] == "2024-01-15T10:22:33Z"
    assert expected.items() <= row.items()


def test_zeek_json_takes_its_log_from_path_or_from_the_file_name() -> None:
    conn = (
        '{"ts":"2024-02-27T08:08:03.569305Z","uid":"CzeKJi1fKJy8mqFsTi",'
        '"id.orig_h":"217.241.55.94","id.orig_p":57960,"id.resp_h":"10.0.1.14","id.resp_p":3389,'
        '"proto":"tcp","service":"ssl","orig_bytes":1051131,"resp_bytes":2170972,'
        '"conn_state":"RSTR","tunnel_parents":["Cig89y3S7FkojKffBk"]}'
    )
    ssh = (
        '{"_path":"ssh","ts":1665164348.511363,"uid":"C2","id.orig_h":"192.168.10.50",'
        '"id.resp_h":"203.0.113.10","id.resp_p":22,"auth_success":true}'
    )

    for name in ("zeek_conn.log", "bro_conn.json", "conn.2024-02-27.log"):
        fmt = sniff(name, [conn])
        assert _row(fmt, conn)["bytes"] == 3222103, name
        assert fmt.source == "logs.zeek.conn", name
    # Any other Zeek log gets the columns every log has; its name is a value, and never
    # a table name read from evidence.
    assert _row(fmt, ssh) == {
        "event_time": "2022-10-07T17:39:08Z",
        "src_ip": "192.168.10.50",
        "target": "203.0.113.10",
        "dest_port": 22,
        "session_id": "C2",
        "log": "ssh",
    }
    assert fmt.source == "logs.zeek.other"
    hostile = '{"_path":"x; DROP TABLE","ts":1665164348,"uid":"C3","id.orig_h":"10.0.0.1"}'
    assert _row(fmt, hostile)["log"] == "x; DROP TABLE" and fmt.source == "logs.zeek.other"
    assert fmt.parse("{not json") is None


def test_suricata_events_go_to_a_table_per_event_type() -> None:
    fmt = sniff("eve.json", [_EVE_DNS_V1])
    http = (
        '{"timestamp":"2024-08-02T14:21:23.992673+0000","flow_id":1879083606744645,'
        '"event_type":"http","src_ip":"10.3.10.8","src_port":50296,"dest_ip":"10.3.99.1",'
        '"dest_port":80,"proto":"TCP","http":{"hostname":"10.3.99.1","url":"/plugin/search/?q=1",'
        '"http_user_agent":"Mozilla/5.0","http_method":"POST","status":200,"length":59}}'
    )
    alert = (
        '{"timestamp":"2024-08-02T14:21:24.000001+0000","flow_id":7,"event_type":"alert",'
        '"src_ip":"10.3.10.8","dest_ip":"10.3.99.1","dest_port":80,"proto":"TCP","alert":'
        '{"action":"allowed","signature_id":2024897,"signature":"ET WEB_SERVER WebShell",'
        '"category":"Trojan","severity":1}}'
    )
    flow = (
        '{"timestamp":"2016-08-28T23:58:58.000072-0600","flow_id":786872163,"event_type":"flow",'
        '"src_ip":"192.168.230.74","dest_ip":"192.168.229.240","dest_port":9997,"proto":"TCP",'
        '"app_proto":"http","flow":{"bytes_toserver":492,"bytes_toclient":252,"state":"closed",'
        '"reason":"timeout"}}'
    )
    tls = (
        '{"timestamp":"2016-08-28T23:58:51.464001-0600","flow_id":3525056877,"event_type":"tls",'
        '"src_ip":"192.168.230.20","dest_ip":"192.168.225.203","dest_port":8089,"proto":"TCP",'
        '"tls":{"subject":"CN=SplunkServerDefaultCert","issuerdn":"CN=SplunkCommonCA",'
        '"sni":"splunk.example","version":"TLS 1.2","ja3":{"hash":"abc"}}}'
    )

    assert _row(fmt, http) == {
        "event_time": "2024-08-02T14:21:23Z",
        "src_ip": "10.3.10.8",
        "session_id": 1879083606744645,
        "action": "POST",
        "target": "/plugin/search/",
        "query": "q=1",
        "status": 200,
        "user_agent": "Mozilla/5.0",
        "bytes": 59,
        "host": "10.3.99.1",
        "dest_ip": "10.3.99.1",
        "dest_port": 80,
        "proto": "TCP",
    }
    assert fmt.source == "logs.suricata.http"
    row = _row(fmt, alert)
    assert (row["action"], row["status"]) == ("ET WEB_SERVER WebShell", "allowed")
    assert row["target"] == "10.3.99.1" and row["signature_id"] == 2024897
    assert fmt.source == "logs.suricata.alert"
    row = _row(fmt, flow)
    assert (row["bytes"], row["status"], row["action"]) == (744, "closed", "http")
    row = _row(fmt, tls)
    assert (row["target"], row["issuer"], row["ja3"]) == (
        "splunk.example",
        "CN=SplunkCommonCA",
        "abc",
    )
    fileinfo = (
        '{"timestamp":"2024-08-02T14:21:25+0000","event_type":"fileinfo","src_ip":"10.0.0.1"}'
    )
    assert _row(fmt, fileinfo)["event_type"] == "fileinfo"
    assert fmt.source == "logs.suricata.other"
    assert fmt.parse('["a list is not an event"]') is None


def test_suricata_dns_records_are_read_in_both_shapes() -> None:
    """Version 1 writes one event per answer; version 2 one event with a list."""
    fmt = sniff("eve.json", [_EVE_DNS_V1])
    v2 = (
        '{"timestamp":"2024-08-02T14:21:23.992673+0000","flow_id":2,"event_type":"dns",'
        '"src_ip":"10.0.0.2","dest_ip":"10.0.0.1","dest_port":53,"proto":"UDP","dns":{"version":2,'
        '"type":"answer","rrname":"evil.example","rrtype":"A","rcode":"NOERROR","answers":['
        '{"rrname":"evil.example","rrtype":"A","ttl":1,"rdata":"203.0.113.9"},'
        '{"rrname":"evil.example","rrtype":"A","rdata":"203.0.113.10"}]}}'
    )
    v3 = (
        '{"timestamp":"2025-07-02T15:42:33+0000","event_type":"dns","src_ip":"10.0.0.2",'
        '"dns":{"version":3,"type":"request","queries":[{"rrname":"evil.example","rrtype":"A"}]}}'
    )

    one = _row(fmt, _EVE_DNS_V1)
    assert one["event_time"] == "2016-08-29T05:58:59Z"  # "-0600", an offset without a colon
    assert (one["action"], one["status"], one["rrtype"]) == ("answer", "NOERROR", "CNAME")
    assert one["target"] == "kv401-prod.do.dsp.mp.microsoft.com.edgekey.net"
    assert one["answers"] == "e7589.g.akamaiedge.net"
    assert _row(fmt, v2)["answers"] == "203.0.113.9,203.0.113.10"
    assert _row(fmt, v3)["target"] == "evil.example" and _row(fmt, v3)["rrtype"] == "A"
    # Not a list where a list belongs: read as no answers, not a crash.
    odd = _EVE_DNS_V1.replace('"rdata":"e7589.g.akamaiedge.net"', '"answers":{"a":1},"queries":7')
    assert "answers" not in _row(fmt, odd)


def test_fortigate_events_and_vpn_logins() -> None:
    fmt = sniff("fortigate.log", [_FORTIGATE], _MTIME)
    vpn = (
        'date=2024-01-15 time=03:12:44 eventtime=1705317164123456789 tz="-0800" '
        'logid="0101039947" type="event" subtype="vpn" level="information" vd="root" '
        'logdesc="SSL VPN tunnel up" action="tunnel-up" tunneltype="ssl-web" tunnelid=1234567 '
        'remip=203.0.113.50 tunnelip=10.212.134.200 user="jsmith" group="VPN-Users" '
        'dst_host="N/A" reason="login successfully" msg="SSL tunnel established"'
    )
    admin = (
        "date=2016-08-05 time=06:30:00 devname=gotham-fortigate logid=0100032001 type=event "
        'subtype=system user="admin" ui="https(203.0.113.9)" action=login status=success '
        'msg="Administrator admin logged in successfully from https(203.0.113.9)"'
    )

    assert _row(fmt, _FORTIGATE) == {
        "event_time": "2016-08-05T06:28:35Z",
        "vendor": "fortigate",
        "device": "gotham-fortigate",
        "log_type": "event/system",
        "message_id": "0100026003",
        "level": "information",
        "message": "DHCP statistics",
    }
    assert fmt.naive  # no tz field: the device's own clock, read as UTC
    row = _row(fmt, vpn)
    assert row["event_time"] == "2024-01-15T11:12:44Z"  # 03:12:44 at -0800
    assert (row["actor"], row["src_ip"], row["action"]) == ("jsmith", "203.0.113.50", "tunnel-up")
    assert (row["tunnel_type"], row["assigned_ip"]) == ("ssl-web", "10.212.134.200")
    assert row["reason"] == "login successfully" and "group" not in row
    row = _row(fmt, admin)
    assert (row["actor"], row["src_ip"], row["status"]) == ("admin", "203.0.113.9", "success")
    # Text a visitor chose sits inside a quoted value, escaped quote and all: it cannot
    # pose as a field. And of a repeated key, the device's own (the first) is kept.
    forged = admin.replace('msg="', 'msg="x \\" remip=10.9.9.9 user=root y" user="root" note="')
    row = _row(fmt, forged)
    assert (row["actor"], row["src_ip"]) == ("admin", "203.0.113.9")


def test_fortigate_epoch_time_is_used_when_there_is_no_zone() -> None:
    fmt = sniff("fortigate.log", [_FORTIGATE], _MTIME)
    line = "date=2024-01-15 time=03:12:44 eventtime=1705317164 logid=1 type=event devname=fw"

    assert _row(fmt, line)["event_time"] == "2024-01-15T11:12:44Z"


def test_sonicwall_logins() -> None:
    line = (
        '<134>id=firewall sn=18B1690729A8 time="2024-01-15 10:22:33 UTC" fw=198.51.100.2 pri=6 '
        'c=16 m=1080 msg="SSL VPN zone remote user login allowed" sess="sslvpnc" n=123 '
        'usr="jsmith" src=203.0.113.50:51234:X1 dst=198.51.100.2:4433:X1 proto=tcp/4433'
    )
    fmt = sniff("sonicwall.log", [line], _MTIME)

    assert _row(fmt, line) == {
        "event_time": "2024-01-15T10:22:33Z",
        "actor": "jsmith",
        "src_ip": "203.0.113.50",
        "action": "SSL VPN zone remote user login allowed",
        "target": "198.51.100.2",
        "vendor": "sonicwall",
        "device": "198.51.100.2",
        "message_id": "1080",
        "level": "6",
        "tunnel_type": "sslvpnc",
        "dest_port": "4433",
    }
    assert not fmt.naive
    assert _row(fmt, line.replace(" UTC", ""))["event_time"] == "2024-01-15T10:22:33Z"
    assert fmt.naive  # without the zone it is the device's own time


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            "Jan 15 2024 10:22:33 fw01 : %ASA-6-113039: Group <GroupPolicy_VPN> User <jsmith> "
            "IP <203.0.113.50> AnyConnect parent session started.",
            {"action": "session-started", "tunnel_type": "anyconnect", "device": "fw01"},
        ),
        (
            "<166>Jan 15 2024 10:22:34: %ASA-6-722051: Group <GroupPolicy_VPN> User <jsmith> "
            "IP <203.0.113.50> IPv4 Address <10.10.10.5> IPv6 address <::> assigned to session",
            {"action": "address-assigned", "assigned_ip": "10.10.10.5"},
        ),
        (
            "Jan 15 2024 10:22:35 fw01 : %ASA-6-722055: Group <GroupPolicy_VPN> User <jsmith> "
            "IP <203.0.113.50> Client Type: Cisco AnyConnect VPN Agent for Windows 4.10.07061",
            {
                "action": "client-type",
                "user_agent": "Cisco AnyConnect VPN Agent for Windows 4.10.07061",
            },
        ),
        (
            "Jan 15 2024 10:21:00 fw01 : %ASA-4-113038: Group <GroupPolicy_VPN> User <jsmith> "
            "IP <203.0.113.50> Unable to create AnyConnect parent session.",
            {"action": "session-failed"},
        ),
        (
            "Jan 15 2024 10:27:33 fw01 : %ASA-4-113019: Group = VPN, Username = jsmith, "
            "IP = 203.0.113.50, Session disconnected. Session Type: SSL, Duration: 0h:05m:10s, "
            "Bytes xmt: 1234, Bytes rcv: 5678, Reason: User Requested",
            {
                "action": "session-disconnected",
                "tunnel_type": "SSL",
                "bytes": 6912,
                "duration": "0h:05m:10s",
                "reason": "User Requested",
            },
        ),
    ],
)
def test_the_cisco_asa_vpn_session_messages(line: str, expected: dict[str, object]) -> None:
    fmt = sniff("asa.log", [line], _MTIME)

    row = _row(fmt, line)

    assert fmt.source == "logs.firewall"
    assert (row["actor"], row["src_ip"], row["vendor"]) == ("jsmith", "203.0.113.50", "asa")
    assert row["event_time"].startswith("2024-01-15T10:2")
    assert row["message_id"] == line.split("%ASA-")[1][2:8]
    assert expected.items() <= row.items()


def test_other_asa_messages_keep_their_id_and_text_only() -> None:
    line = (
        "Jan 15 2024 10:22:35 UTC: %ASA-6-302013: Built inbound TCP connection 1 for "
        "outside:1.2.3.4/1 (1.2.3.4/1) to inside:10.0.0.1/443 (10.0.0.1/443)"
    )
    fmt = sniff("asa.log", [line], _MTIME)

    assert _row(fmt, line) == {
        "event_time": "2024-01-15T10:22:35Z",
        "vendor": "asa",
        "message_id": "302013",
        "level": "6",
        "message": "Built inbound TCP connection 1 for outside:1.2.3.4/1 (1.2.3.4/1) to "
        "inside:10.0.0.1/443 (10.0.0.1/443)",
    }
    assert fmt.parse("Jan 15 2024 10:22:35 fw01 : link up") is None


def test_syslog_takes_its_year_from_the_file_and_says_so() -> None:
    line = "Mar  4 12:38:02 web01 sshd[1234]: Accepted password for root from 203.0.113.9"
    fmt = sniff("messages", [line], _MTIME)

    assert _row(fmt, line) == {
        "event_time": "2025-03-04T12:38:02Z",
        "host": "web01",
        "program": "sshd",
        "message": "Accepted password for root from 203.0.113.9",
    }
    assert fmt.guessed_year and fmt.naive
    # A date later in the calendar than the file's last write is from the year before.
    assert _row(fmt, "Dec 31 23:59:59 web01 cron[1]: x")["event_time"] == "2024-12-31T23:59:59Z"
    # Without a modification time there is no year to take: no time, rather than a guess.
    blind = sniff("messages", [line])
    assert _row(blind, line)["event_time"] is None


def test_syslog_with_an_iso_time_and_a_relayed_line() -> None:
    iso = "2024-01-15T10:22:33.123456+01:00 web01 sudo: pam_unix(sudo:session): session opened"
    relayed = (
        "May  8 17:16:27 192.168.8.233 2025-05-08T17:14:39.069Z localhost.lan login[294069]: "
        "pam_authenticate call failed: Authentication failure (7)"
    )
    fmt = sniff("syslog", [iso], _MTIME)

    assert _row(fmt, iso)["event_time"] == "2024-01-15T09:22:33Z"
    assert not fmt.naive and not fmt.guessed_year
    # The relay's own header has no year; the sender's time behind it does.
    row = _row(fmt, relayed)
    assert (row["event_time"], row["host"], row["program"]) == (
        "2025-05-08T17:14:39Z",
        "localhost.lan",
        "login",
    )
    assert not fmt.guessed_year
    assert fmt.parse("no time at the start of this line") is None


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (_ESXI_VOBD, {"program": "vobd", "highlight": "ssh_shell_access"}),
        (
            "2021-04-01T10:00:00.123Z info hostd[2099999] [Originator@6876 "
            "sub=Vimsvc.ha-eventmgr opID=esxui-6b8 user=root] Event 105 : ESXi Shell for the "
            "host localhost.lan has been enabled",
            {"program": "hostd", "highlight": "ssh_shell_access", "actor": "root"},
        ),
        (
            "May 12 19:40:22 192.168.8.233 2025-05-12T19:38:34.990Z localhost.lan Hostd[263201]: "
            "[Originator@6876 sub=Vimsvc.ha-eventmgr opID=esxui-1800-833c sid=52743bc3] Event "
            "3237 : User root@192.168.196.95 logged in as Mozilla/5.0 (Macintosh)",
            {
                "program": "hostd",
                "highlight": "login",
                "status": "success",
                "actor": "root",
                "src_ip": "192.168.196.95",
                "user_agent": "Mozilla/5.0 (Macintosh)",
            },
        ),
        (
            "2025-05-07T18:06:33.014Z sshd-session[264746]: error: PAM: Authentication failure "
            "for root from 192.168.196.95",
            {
                "highlight": "login",
                "status": "failure",
                "actor": "root",
                "src_ip": "192.168.196.95",
            },
        ),
        (
            "2025-05-07T18:06:27.948Z sshd-session[264748]: pam_unix(sshd:auth): authentication "
            "failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.196.95  user=root",
            {
                "highlight": "login",
                "status": "failure",
                "actor": "root",
                "src_ip": "192.168.196.95",
            },
        ),
        (
            "2021-04-01T10:00:00Z sshd[2100001]: Accepted keyboard-interactive/pam for root "
            "from 10.1.1.5 port 50000 ssh2",
            {"highlight": "login", "status": "success", "actor": "root", "src_ip": "10.1.1.5"},
        ),
        (
            "2025-05-08T17:11:31.361Z localhost.lan DCUI[263670]: User root logged in",
            {"program": "dcui", "highlight": "login", "actor": "root"},
        ),
        (
            "2023-06-01T10:00:00.123Z In(14) shell[2100000]: [root]: chmod +x /tmp/encrypt",
            {
                "program": "shell",
                "highlight": "shell_command",
                "actor": "root",
                "action": "chmod +x /tmp/encrypt",
            },
        ),
        (
            "2025-05-06T14:35:04.373Z shell[288199]: [root]: esxcli vm process kill --type=force "
            "--world-id=12345",
            {"highlight": "vm_power", "actor": "root"},
        ),
        (
            "2021-04-01T10:05:00.000Z info hostd[2099999] [Originator@6876 "
            "sub=Vimsvc.ha-eventmgr] Event 150 : db01 on esx1 in ha-datacenter is powered off",
            {"highlight": "vm_power"},
        ),
        (
            "2025-07-07T18:51:55.336Z shell[1798020]: [root]: esxcli system settings encryption "
            "set --require-exec-installed-only=0",
            {"highlight": "exec_policy", "actor": "root"},
        ),
        (
            "2025-07-07T18:50:00.000Z shell[1798020]: [root]: esxcli system settings kernel set "
            "-s execInstalledOnly -v FALSE",
            {"highlight": "exec_policy"},
        ),
        (
            "2025-05-07T18:07:09Z esxupdate[264778]: Attempting to install an image profile "
            "bypassing signing and acceptance level verification.",
            {"program": "esxupdate", "highlight": "vib_install"},
        ),
        (
            "2025-05-07T17:59:03.482Z shell[264232]: [root]: esxcli software acceptance set "
            "--level=CommunitySupported",
            {"highlight": "vib_install", "actor": "root"},
        ),
    ],
)
def test_esxi_lines_and_what_makes_one_a_highlight(line: str, expected: dict[str, object]) -> None:
    fmt = sniff("esxi.log", [_ESXI_VOBD])

    row = _row(fmt, line)

    assert fmt.source == "logs.esxi"
    assert row["event_time"] and row["highlight"] in logparse.ESXI_CATEGORIES
    assert expected.items() <= row.items()


def test_ordinary_esxi_lines_are_rows_without_a_highlight() -> None:
    fmt = sniff("vmkernel.log", ["2021-04-01T10:00:00.123Z cpu1:2097152)NMP: nmp_Throttle"])
    info = (
        "2025-05-07T13:18:58.568Z Hostd[263198]: [Originator@6876 sub=Solo.VmwareCLI "
        "opID=esxcli-60-866e user=root] Dispatch system.version.get done"
    )

    # vmkernel.log names no program on its lines: the file does.
    assert _row(fmt, "2021-04-01T10:00:00.123Z cpu1:2097152)NMP: nmp_Throttle") == {
        "event_time": "2021-04-01T10:00:00Z",
        "program": "vmkernel",
        "message": "cpu1:2097152)NMP: nmp_Throttle",
    }
    assert "highlight" not in _row(fmt, info) and "actor" not in _row(fmt, info)
    assert fmt.parse('-->    eventTypeId = "esx.audit.lockdownmode.disabled",') is SKIP
    assert fmt.parse("not an ESXi line") is None


def test_which_files_are_taken_for_esxi_logs() -> None:
    auth = "2021-04-01T10:00:00Z sshd[2100001]: Accepted password for root from 10.1.1.5 port 5"

    assert isinstance(sniff("auth.log", [auth]), logparse.Esxi)  # an ESXi log by its name
    assert isinstance(sniff("hostd.0.gz", [auth]), logparse.Esxi)
    assert isinstance(sniff("collected.log", [auth], esxi=True), logparse.Esxi)  # in a bundle
    # The same line in a file of another name is syslog: nothing says ESXi.
    assert isinstance(sniff("collected.log", [f"{auth[:20]} esx1 {auth[21:]}"]), logparse.Syslog)


def test_unknown_text_is_not_parsed_and_most_lines_decide() -> None:
    assert isinstance(sniff("notes.txt", ["Meeting notes", "second line"]), logparse.Text)
    assert isinstance(sniff("empty.log", ["", "  "]), logparse.Text)
    assert sniff("notes.txt", ["x"]).parse("anything") is SKIP
    assert not sniff("notes.txt", ["x"]).tabular
    # A banner above the log does not hide it; a single log-like line does not make one.
    assert isinstance(
        sniff("access.log", ["# exported by ops", _COMBINED, _COMBINED]), logparse.Web
    )
    assert isinstance(sniff("mail.txt", [_COMBINED, "a", "b", "c"]), logparse.Text)
    # JSON that is neither Suricata nor Zeek stays text.
    assert isinstance(sniff("app.json", ['{"level":"info","msg":"started"}']), logparse.Text)


def test_hostile_lines_cost_linear_time() -> None:
    """A log line is evidence. Each of these made some pattern rescan the line from
    every position before it was anchored or bounded: seconds to minutes for one line of
    the 64 KiB a line is read to, against well under a second for all of them now."""
    web = sniff("access.log", [_COMBINED])
    firewall = sniff("fw.log", [_FORTIGATE], _MTIME)
    esxi = sniff("esxi.log", [_ESXI_VOBD])
    syslog = sniff("messages", ["Mar  4 12:38:02 web01 sshd[1234]: x"], _MTIME)
    size = 64_000
    junk = [c * size for c in (" ", '"', "\\", "a", "[", "<", "=", ":", "@")]
    junk += [(word * size)[:size] for word in ("a=", "Group = ", "Group <", "for ", "a@", "x ")]
    started = time.monotonic()

    for text in junk:
        web.parse(f'203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "{text}')
        web.parse(text)
        firewall.parse(f"{_FORTIGATE} {text}")
        firewall.parse(f"Jan 15 2024 10:27:33 fw01 : %ASA-4-113019: {text}")
        firewall.parse(f"Jan 15 2024 10:27:33 fw01 : %ASA-6-722051: {text}")
        # "logged in" makes the line a highlight, so the user and address are looked for.
        esxi.parse(f"2025-05-07T17:58:28.526Z hostd[1]: User logged in {text}")
        esxi.parse(f"2025-05-07T17:58:28.526Z {text}")
        syslog.parse(f"Mar  4 12:38:02 {text}")

    assert time.monotonic() - started < 5
