#!/usr/bin/env python3
"""Synthetic NetFlow v5 catalog builder + sender for the NetFlow test fixtures.

Builds a fully deterministic, synthetic flow catalog (RFC 5737 documentation
addresses + RFC 1918 private addresses only, timestamps in 2001-02-03..2001-02-10
UTC) and emits it as raw NetFlow v5 UDP export packets to a listening nfcapd
collector.

Three subcommands:
  catalog   - build the full synthetic catalog (all buckets), write CSV audit
              files under <outdir>/_catalog/, print a summary. No network I/O.
  send      - rebuild ONE bucket ('day1', 'day2', or 'tiny3') deterministically
              and emit it as NetFlow v5 UDP packets to HOST:PORT (a running
              nfcapd instance). Prints a summary JSON line to stdout.
  normalize - make one nfcapd layout-2 file byte-reproducible: the collector
              stamps its own wall clock into the file header ("created") and
              into every flow record ("received"); both are set from the data
              (the rotation time in the file name, each record's last-seen + 1 s).

Because the catalog builder is a pure, seeded function of (bucket name), calling
`send BUCKET` in a fresh process reproduces byte-for-byte the same flow list
that `catalog` printed/audited, with no need to pass state between processes.
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import struct
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from random import Random

UTC = timezone.utc

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEED = 20010203  # fixed seed -> fully deterministic "organic" jitter
BOOT_EPOCH_MS = int(datetime(2001, 2, 1, tzinfo=UTC).timestamp() * 1000)

TCP = 6
UDP = 17
ICMP = 1

F_FIN = 0x01
F_SYN = 0x02
F_RST = 0x04
F_PSH = 0x08
F_ACK = 0x10
F_URG = 0x20

FLAGS_SYN_ONLY = F_SYN
FLAGS_COMPLETED = F_SYN | F_ACK | F_PSH | F_FIN  # 0x1B


def dt(y, m, d, hh=0, mm=0, ss=0, us=0):
    return datetime(y, m, d, hh, mm, ss, us, tzinfo=UTC)


def mk(sip, sp, dip, dp, pr, flags, pkts, byts, first, last, bucket, tag):
    assert last >= first, (tag, first, last)
    return {
        "sip": sip,
        "sp": sp,
        "dip": dip,
        "dp": dp,
        "pr": pr,
        "flags": flags,
        "pkts": pkts,
        "byts": byts,
        "first": first,
        "last": last,
        "bucket": bucket,
        "tag": tag,
    }


# ---------------------------------------------------------------------------
# Category builders
# ---------------------------------------------------------------------------

SWEEP_SOURCE = "10.0.3.44"
SWEEP_TARGETS = (
    [f"10.0.8.{i}" for i in (21, 23, 27, 30, 34, 38, 41, 45)]  # 8 on one /24
    + [f"10.0.9.{i}" for i in (12, 15, 19, 60, 66)]  # 5 on another
)
SWEEP_PORTS = (445, 3389)


def sweep_open(target_idx, port):
    """Which (target, port) probes are answered: a completed connection follows the SYNs."""
    return target_idx % 3 == 0 if port == 445 else target_idx % 4 == 2


def build_sweep():
    """(a) internal sweep: 10.0.3.44 -> 13 targets on two /24s, TCP/445 + TCP/3389.

    Every (target, port) gets two SYN-only probes 70 ms apart; the answered ones
    (``sweep_open``) also get one completed connection."""
    targets = SWEEP_TARGETS
    assert len(targets) == 13
    pairs = [(i, t, p) for i, t in enumerate(targets) for p in SWEEP_PORTS]
    n_pairs = len(pairs)  # 26
    base = dt(2001, 2, 3, 14, 22, 7)
    span_s = 22.5
    spacing = span_s / (n_pairs - 1)

    flows = []
    for idx, (t_idx, target, port) in enumerate(pairs):
        pair_start = base + timedelta(seconds=idx * spacing)
        t1 = pair_start
        t2 = pair_start + timedelta(milliseconds=70)
        flows.append(
            mk(
                SWEEP_SOURCE,
                40100 + idx * 4,
                target,
                port,
                TCP,
                FLAGS_SYN_ONLY,
                1,
                52,
                t1,
                t1,
                "day1",
                "sweep_syn",
            )
        )
        flows.append(
            mk(
                SWEEP_SOURCE,
                40101 + idx * 4,
                target,
                port,
                TCP,
                FLAGS_SYN_ONLY,
                1,
                52,
                t2,
                t2,
                "day1",
                "sweep_syn",
            )
        )
        if sweep_open(t_idx, port):
            t3 = pair_start + timedelta(milliseconds=150)
            t3_last = t3 + timedelta(milliseconds=240)
            flows.append(
                mk(
                    SWEEP_SOURCE,
                    40102 + idx * 4,
                    target,
                    port,
                    TCP,
                    FLAGS_COMPLETED,
                    8,
                    1236,
                    t3,
                    t3_last,
                    "day1",
                    "sweep_completed",
                )
            )
    return flows


SESSION = ("10.0.2.37", 49731, "203.0.113.77", 40519)  # client, sport, server, dport


def build_session():
    """(b) long-lived low-rate session: one record of exactly 17 h at 143 B/s."""
    sip, sp, dip, dp = SESSION
    first = dt(2001, 2, 3, 9, 48, 30)
    duration_s = 17 * 3600  # 61200 s
    last = first + timedelta(seconds=duration_s)
    rate_bps = 143
    byts = rate_bps * duration_s  # 8,751,600 B, exactly 143 B/s
    pkts = duration_s // 2  # one packet every 2 s -> 286 B per packet
    return [mk(sip, sp, dip, dp, TCP, FLAGS_COMPLETED, pkts, byts, first, last, "day1", "session")]


RETRIES = ("10.0.5.83", "192.0.2.150", 993)  # client, server, dport: a pair of its own


def build_retries():
    """(c) periodic SYN-only retries on their own pair: 240 unanswered connection
    attempts 53 s apart on day 2, each from the next source port."""
    sip, dip, dp = RETRIES
    first = dt(2001, 2, 4, 11, 7, 26)
    n_retries = 240
    interval_s = 53
    flows = []
    for i in range(n_retries):
        t = first + timedelta(seconds=interval_s * i)
        flows.append(
            mk(sip, 50212 + i, dip, dp, TCP, FLAGS_SYN_ONLY, 1, 60, t, t, "day2", "retry_syn")
        )
    return flows


def build_admin():
    """(d) inbound management traffic to the session host: 10.0.4.12 -> TCP/22 and
    UDP/161, both days (gives the host profile an inbound side)."""
    admin, host = "10.0.4.12", SESSION[0]
    flows = []
    for day_date, bucket in ((date(2001, 2, 3), "day1"), (date(2001, 2, 4), "day2")):
        day_start = datetime.combine(day_date, time(0, 0, 0), UTC)
        for k, hh in enumerate((8, 12, 16)):
            f = day_start + timedelta(hours=hh, minutes=11 + k)
            flows.append(
                mk(
                    admin,
                    52210 + k,
                    host,
                    22,
                    TCP,
                    FLAGS_COMPLETED,
                    24,
                    5120 + 64 * k,
                    f,
                    f + timedelta(seconds=41),
                    bucket,
                    "admin_ssh",
                )
            )
        for hh in (6, 10, 14, 18):
            f = day_start + timedelta(hours=hh, minutes=5)
            flows.append(
                mk(
                    admin,
                    161,
                    host,
                    161,
                    UDP,
                    0,
                    2,
                    187,
                    f,
                    f + timedelta(milliseconds=12),
                    bucket,
                    "admin_snmp",
                )
            )
    return flows


NIGHTLY = ("10.0.2.90", "198.51.100.23", 873)  # client, server, dport


def build_nightly():
    """(e) nightly ~04:37 transfer, both days."""
    sip, dip, dp = NIGHTLY
    f1 = dt(2001, 2, 3, 4, 37, 0)
    l1 = f1 + timedelta(seconds=140)
    f2 = dt(2001, 2, 4, 4, 38, 12)
    l2 = f2 + timedelta(seconds=133)
    return [
        mk(sip, 47012, dip, dp, TCP, FLAGS_COMPLETED, 1650, 2_350_000, f1, l1, "day1", "nightly"),
        mk(sip, 47655, dip, dp, TCP, FLAGS_COMPLETED, 1622, 2_310_000, f2, l2, "day2", "nightly"),
    ]


PROXY = ("10.0.1.5", 3128)


def build_proxy(rng: Random):
    """(f) proxy-style traffic: many clients -> 10.0.1.5:3128, and
    10.0.1.5 -> a few external :443 destinations."""
    proxy_ip, proxy_port = PROXY
    clients = [f"10.0.2.{i}" for i in range(101, 119)] + [f"10.0.3.{i}" for i in range(150, 156)]
    assert len(clients) == 24
    upstream = ["192.0.2.45", "198.51.100.61", "203.0.113.140"]

    flows = []
    for day_date, bucket in ((date(2001, 2, 3), "day1"), (date(2001, 2, 4), "day2")):
        day_start = datetime.combine(day_date, time(0, 0, 0), UTC)
        for client in clients:
            off = rng.randint(0, 10 * 3600)  # business hours 08:00-18:00
            first = day_start + timedelta(seconds=8 * 3600 + off)
            durs = rng.randint(1, 40)
            pkts = rng.randint(8, 60)
            byts = pkts * rng.randint(80, 900)
            sp = rng.randint(1024, 65000)
            flows.append(
                mk(
                    client,
                    sp,
                    proxy_ip,
                    proxy_port,
                    TCP,
                    FLAGS_COMPLETED,
                    pkts,
                    byts,
                    first,
                    first + timedelta(seconds=durs),
                    bucket,
                    "proxy_client",
                )
            )
        for target in upstream:
            for _ in range(6):
                off = rng.randint(0, 10 * 3600)
                first = day_start + timedelta(seconds=8 * 3600 + off)
                durs = rng.randint(1, 60)
                pkts = rng.randint(10, 100)
                byts = pkts * rng.randint(200, 1400)
                sp = rng.randint(1024, 65000)
                flows.append(
                    mk(
                        proxy_ip,
                        sp,
                        target,
                        443,
                        TCP,
                        FLAGS_COMPLETED,
                        pkts,
                        byts,
                        first,
                        first + timedelta(seconds=durs),
                        bucket,
                        "proxy_upstream",
                    )
                )
    return flows


ICMP_PAIRS = [
    ("10.0.12.1", "10.0.12.2"),
    ("10.0.12.3", "10.0.12.4"),
    ("10.0.12.5", "10.0.12.6"),
    ("10.0.12.7", "10.0.12.8"),
]


def build_icmp(rng: Random):
    """(g) ICMP noise: internal echo request/reply pairs + a few unanswered
    pings to an external documentation-range host."""
    flows = []
    for day_date, bucket in ((date(2001, 2, 3), "day1"), (date(2001, 2, 4), "day2")):
        day_start = datetime.combine(day_date, time(0, 0, 0), UTC)
        for i in range(8):
            a, b = ICMP_PAIRS[i % len(ICMP_PAIRS)]
            off = rng.randint(0, 24 * 3600 - 1)
            t = day_start + timedelta(seconds=off)
            flows.append(mk(a, 0, b, 8 * 256, ICMP, 0, 1, 84, t, t, bucket, "icmp_req"))
            t2 = t + timedelta(milliseconds=5)
            flows.append(mk(b, 0, a, 0, ICMP, 0, 1, 84, t2, t2, bucket, "icmp_rep"))
        for i in range(4):
            a = ICMP_PAIRS[i % len(ICMP_PAIRS)][0]
            off = rng.randint(0, 24 * 3600 - 1)
            t = day_start + timedelta(seconds=off)
            flows.append(
                mk(a, 0, "203.0.113.9", 8 * 256, ICMP, 0, 1, 84, t, t, bucket, "icmp_ext")
            )
    return flows


def build_dns(rng: Random):
    """(g) UDP/53 noise."""
    resolver_int = "10.0.1.10"
    resolver_ext = "198.51.100.8"
    dns_clients = [f"10.0.2.{i}" for i in range(101, 113)]
    flows = []
    for day_date, bucket in ((date(2001, 2, 3), "day1"), (date(2001, 2, 4), "day2")):
        day_start = datetime.combine(day_date, time(0, 0, 0), UTC)
        for client in dns_clients:
            for _ in range(2):
                off = rng.randint(0, 24 * 3600 - 1)
                t = day_start + timedelta(seconds=off)
                sp = rng.randint(1024, 65000)
                flows.append(
                    mk(
                        client,
                        sp,
                        resolver_int,
                        53,
                        UDP,
                        0,
                        2,
                        132,
                        t,
                        t + timedelta(milliseconds=30),
                        bucket,
                        "dns_int",
                    )
                )
        for i in range(6):
            client = dns_clients[i % len(dns_clients)]
            off = rng.randint(0, 24 * 3600 - 1)
            t = day_start + timedelta(seconds=off)
            sp = rng.randint(1024, 65000)
            flows.append(
                mk(
                    client,
                    sp,
                    resolver_ext,
                    53,
                    UDP,
                    0,
                    2,
                    146,
                    t,
                    t + timedelta(milliseconds=45),
                    bucket,
                    "dns_ext",
                )
            )
    return flows


def build_tiny3():
    """Tiny third file: 2001-02-10, a handful of records, no duplicates."""
    d = date(2001, 2, 10)
    t0 = datetime.combine(d, time(6, 0, 0), UTC)
    flows = [
        mk("10.0.12.1", 0, "10.0.12.2", 8 * 256, ICMP, 0, 1, 84, t0, t0, "tiny3", "icmp_req"),
        mk(
            "10.0.12.2",
            0,
            "10.0.12.1",
            0,
            ICMP,
            0,
            1,
            84,
            t0 + timedelta(milliseconds=5),
            t0 + timedelta(milliseconds=5),
            "tiny3",
            "icmp_rep",
        ),
        mk(
            "10.0.2.101",
            40501,
            "10.0.1.10",
            53,
            UDP,
            0,
            2,
            132,
            t0 + timedelta(minutes=1),
            t0 + timedelta(minutes=1, milliseconds=30),
            "tiny3",
            "dns_int",
        ),
        mk(
            "10.0.2.101",
            40502,
            PROXY[0],
            PROXY[1],
            TCP,
            FLAGS_COMPLETED,
            10,
            4000,
            t0 + timedelta(minutes=2),
            t0 + timedelta(minutes=2, seconds=5),
            "tiny3",
            "proxy_client",
        ),
        mk(
            NIGHTLY[0],
            52000,
            NIGHTLY[1],
            NIGHTLY[2],
            TCP,
            FLAGS_COMPLETED,
            50,
            60000,
            t0 + timedelta(minutes=5),
            t0 + timedelta(minutes=5, seconds=10),
            "tiny3",
            "nightly",
        ),
    ]
    return flows


# ---------------------------------------------------------------------------
# Catalog assembly + exporter-duplicate simulation
# ---------------------------------------------------------------------------


def build_all():
    rng = Random(SEED)
    sweep = build_sweep()
    sess = build_session() + build_retries()  # the session is day 1's, the retries day 2's
    admin = build_admin()
    nightly = build_nightly()
    proxy = build_proxy(rng)
    icmp = build_icmp(rng)
    dns = build_dns(rng)
    tiny3 = build_tiny3()

    everything = sweep + sess + admin + nightly + proxy + icmp + dns + tiny3
    buckets = {"day1": [], "day2": [], "tiny3": []}
    for f in everything:
        buckets[f["bucket"]].append(f)
    return buckets


def duplicate_expand(flows, dup=True):
    """Exporter-duplicate ~22% of records: same 5-tuple/times, slightly
    different byte counts (as an exporter reporting a flow on two interfaces
    would). Deterministic: every group of 9 records (by build order) has its
    first 2 duplicated, each copy carrying 2 % more bytes (at least +1)."""
    if not dup:
        return list(flows)
    out = []
    for i, f in enumerate(flows):
        out.append(f)
        if i % 9 < 2:
            d = dict(f)
            bump = max(1, round(f["byts"] * 0.02))
            d["byts"] = f["byts"] + bump
            d["tag"] = f["tag"] + "_dup"
            out.append(d)
    return out


def bucket_flows(name):
    buckets = build_all()
    flows = buckets[name]
    flows = duplicate_expand(flows, dup=(name != "tiny3"))
    return flows


# ---------------------------------------------------------------------------
# NetFlow v5 encoding + UDP send
# ---------------------------------------------------------------------------


def ip_to_int(ip):
    return int.from_bytes(socket.inet_aton(ip), "big")


def epoch_ms(d: datetime):
    return int(d.timestamp() * 1000)


def encode_packet(records, seq):
    count = len(records)
    last_ms_list = [epoch_ms(r["last"]) for r in records]
    export_ms = max(last_ms_list) + 1000
    sysuptime = export_ms - BOOT_EPOCH_MS
    unix_secs = export_ms // 1000
    unix_nsecs = (export_ms % 1000) * 1_000_000
    header = struct.pack(
        "!HHIIIIBBH",
        5,
        count,
        sysuptime & 0xFFFFFFFF,
        unix_secs & 0xFFFFFFFF,
        unix_nsecs & 0xFFFFFFFF,
        seq & 0xFFFFFFFF,
        0,
        0,
        0,
    )
    body = bytearray()
    for r in records:
        first_ms = epoch_ms(r["first"]) - BOOT_EPOCH_MS
        last_ms = epoch_ms(r["last"]) - BOOT_EPOCH_MS
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            ip_to_int(r["sip"]),
            ip_to_int(r["dip"]),
            0,
            1,
            2,
            r["pkts"] & 0xFFFFFFFF,
            r["byts"] & 0xFFFFFFFF,
            first_ms & 0xFFFFFFFF,
            last_ms & 0xFFFFFFFF,
            r["sp"] & 0xFFFF,
            r["dp"] & 0xFFFF,
            0,
            r["flags"] & 0xFF,
            r["pr"] & 0xFF,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    return bytes(header) + bytes(body)


def send_flows(flows, host, port, batch=24, pace_s=0.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    npkts = 0
    for i in range(0, len(flows), batch):
        chunk = flows[i : i + batch]
        pkt = encode_packet(chunk, seq)
        sock.sendto(pkt, (host, port))
        seq += len(chunk)
        npkts += 1
        if pace_s:
            import time as _t

            _t.sleep(pace_s)
    sock.close()
    return npkts, seq


# ---------------------------------------------------------------------------
# nfcapd output normalisation (layout 2, uncompressed)
# ---------------------------------------------------------------------------

NF_MAGIC = 0xA50C
V3_RECORD = 11  # nfdump 1.7 record type
EX_GENERIC_FLOW = 1  # element: msecFirst, msecLast, msecReceived, ...


def normalize_nffile(path: Path) -> int:
    """Set the header's creation time to the rotation time in the file name and every flow
    record's msecReceived to its msecLast + 1000; return the number of records touched."""
    stamp = path.name.split(".", 1)[1][:12]
    created = int(datetime.strptime(stamp, "%Y%m%d%H%M").replace(tzinfo=UTC).timestamp())
    data = bytearray(path.read_bytes())
    (
        magic,
        version,
        _nfv,
        _created,
        compression,
        encryption,
        _appx,
        _unused,
        _off_appx,
        _bsize,
        nblocks,
    ) = struct.unpack_from("<HHIQBBHIQII", data, 0)
    if magic != NF_MAGIC or version != 2 or compression or encryption:
        raise SystemExit(f"{path}: not an uncompressed nfdump layout-2 file")
    struct.pack_into("<Q", data, 8, created)
    pos, touched = 40, 0
    for _ in range(nblocks):
        nrec, size, btype, _flags = struct.unpack_from("<IIHH", data, pos)
        if btype != 3:
            raise SystemExit(f"{path}: unexpected data block type {btype}")
        rpos, end = pos + 12, pos + 12 + size
        for _ in range(nrec):
            rtype, rsize = struct.unpack_from("<HH", data, rpos)
            if rsize < 4 or rpos + rsize > end:
                raise SystemExit(f"{path}: record overruns its block at offset {rpos}")
            if rtype == V3_RECORD:
                epos = rpos + 12
                for _ in range(data[rpos + 4]):
                    etype, elen = struct.unpack_from("<HH", data, epos)
                    if etype == EX_GENERIC_FLOW:
                        _first, last = struct.unpack_from("<QQ", data, epos + 4)
                        struct.pack_into("<Q", data, epos + 20, last + 1000)
                        touched += 1
                    epos += elen
            rpos += rsize
        pos = end
    path.write_bytes(bytes(data))
    return touched


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def summarize(flows):
    by_tag = {}
    for f in flows:
        by_tag[f["tag"]] = by_tag.get(f["tag"], 0) + 1
    firsts = [f["first"] for f in flows]
    lasts = [f["last"] for f in flows]
    return {
        "count": len(flows),
        "by_tag": by_tag,
        "first_min": min(firsts).isoformat() if firsts else None,
        "last_max": max(lasts).isoformat() if lasts else None,
    }


def write_csv(flows, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "first",
                "last",
                "sip",
                "sp",
                "dip",
                "dp",
                "pr",
                "flags",
                "pkts",
                "byts",
                "bucket",
                "tag",
            ]
        )
        for f in flows:
            w.writerow(
                [
                    f["first"].isoformat(),
                    f["last"].isoformat(),
                    f["sip"],
                    f["sp"],
                    f["dip"],
                    f["dp"],
                    f["pr"],
                    f["flags"],
                    f["pkts"],
                    f["byts"],
                    f["bucket"],
                    f["tag"],
                ]
            )


def cmd_catalog(args):
    outdir = Path(args.outdir)
    buckets = build_all()
    total_summary = {}
    for name in ("day1", "day2", "tiny3"):
        base = buckets[name]
        expanded = duplicate_expand(base, dup=(name != "tiny3"))
        write_csv(expanded, outdir / "_catalog" / f"{name}.csv")
        total_summary[name] = {
            "base_count": len(base),
            "expanded_count": len(expanded),
            "dup_count": len(expanded) - len(base),
            **summarize(expanded),
        }
    write_csv(
        sum(
            (duplicate_expand(buckets[n], dup=(n != "tiny3")) for n in ("day1", "day2", "tiny3")),
            [],
        ),
        outdir / "_catalog" / "all_flows.csv",
    )
    print(json.dumps(total_summary, indent=2, default=str))


def cmd_send(args):
    flows = bucket_flows(args.bucket)
    npkts, total_sent = send_flows(flows, args.host, args.port, batch=args.batch, pace_s=args.pace)
    summary = {
        "bucket": args.bucket,
        "flows": len(flows),
        "packets": npkts,
        "sequence_end": total_sent,
        **summarize(flows),
    }
    print(json.dumps(summary, default=str))
    if args.summary_json:
        Path(args.summary_json).write_text(json.dumps(summary, indent=2, default=str))


def cmd_normalize(args):
    touched = normalize_nffile(Path(args.file))
    print(json.dumps({"file": args.file, "flow_records_normalized": touched}))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("catalog", help="build+audit the full catalog (no network I/O)")
    pc.add_argument("--outdir", required=True, help="output directory")
    pc.set_defaults(func=cmd_catalog)

    ps = sub.add_parser("send", help="rebuild one bucket and send it via NetFlow v5 UDP")
    ps.add_argument("bucket", choices=["day1", "day2", "tiny3"])
    ps.add_argument("--host", default="127.0.0.1")
    ps.add_argument("--port", type=int, default=9995)
    ps.add_argument("--batch", type=int, default=24)
    ps.add_argument("--pace", type=float, default=0.0)
    ps.add_argument("--summary-json", default=None)
    ps.set_defaults(func=cmd_send)

    pn = sub.add_parser("normalize", help="make one nfcapd file byte-reproducible")
    pn.add_argument("file", help="nfcapd.YYYYMMDDhhmm file written by nfcapd")
    pn.set_defaults(func=cmd_normalize)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
