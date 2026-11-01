#!/usr/bin/env python3
"""Exercise the built image without credentials or network access.

Run from the checkout (the normal entrypoint drops privileges):
    docker run --rm -i --pull=never --network none IMAGE python3 - \
        < scripts/container-smoke.py

Fixtures and tool outputs live in a temporary container directory. This checks
representative extraction paths, not forensic accuracy across every parser.
"""

import importlib
import json
import os
import plistlib
import shlex
import socket
import struct
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path


def run(*args: str | Path, cwd: Path | None = None, timeout: int = 180) -> str:
    print("RUN", shlex.join(str(arg) for arg in args), flush=True)
    result = subprocess.run(
        [str(arg) for arg in args], cwd=cwd, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def netflow_v5(flows: list[tuple[str, int, str, int, int, int, int, int, float, float]]) -> bytes:
    """One NetFlow v5 export packet.

    Each flow is (src, sport, dst, dport, proto, flags, packets, bytes, first, last).
    """
    boot = min(f[8] for f in flows) - 100
    export = max(f[9] for f in flows) + 1
    header = struct.pack(
        "!HHIIIIBBH", 5, len(flows), int((export - boot) * 1000), int(export), 0, 0, 0, 0, 0
    )
    records = b"".join(
        struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBBH",
            socket.inet_aton(src),
            socket.inet_aton(dst),
            bytes(4),
            1,
            2,
            packets,
            octets,
            int((first - boot) * 1000),
            int((last - boot) * 1000),
            sport,
            dport,
            0,
            flags,
            proto,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        for src, sport, dst, dport, proto, flags, packets, octets, first, last in flows
    )
    return header + records


def netflow_smoke(work: Path) -> None:
    """Collect a synthetic NetFlow v5 export with the bundled nfcapd, then read it back
    through the NetFlow tools' own nfdump runner and parsers, so the csv layouts they
    expect are checked against the bundled nfdump rather than the unit tests' fake."""
    from mulder.extractors.classifier import is_nfcapd
    from mulder.server.tools.netflow import core, tools

    t0 = 1700000000.0
    flows = [
        ("192.0.2.10", 40000, "198.51.100.20", 443, 6, 0x1B, 10, 5000, t0, t0 + 5),
        ("192.0.2.10", 40001, "198.51.100.21", 53, 17, 0, 1, 80, t0 + 1, t0 + 1),
    ]
    collect = work / "nfcapd"
    collect.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    collector = subprocess.Popen(
        ["nfcapd", "-w", collect, "-b", "127.0.0.1", "-p", str(port), "-I", "smoke"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(2)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(netflow_v5(flows), ("127.0.0.1", port))
        time.sleep(2)
    finally:
        collector.terminate()  # nfcapd flushes and closes its file on SIGTERM
        output, _ = collector.communicate(timeout=30)
    captures = sorted(collect.glob("nfcapd.2*"))
    assert len(captures) == 1, (captures, output)
    capture = captures[0]
    assert is_nfcapd(capture), f"classifier rejects {capture.name}"

    def nfdump(read: list[str], mode: list[str], fmt: str | None, filter_expr: str | None) -> str:
        result = tools._run_nfdump(read, mode, fmt, filter_expr, 60)
        assert isinstance(result, tools.NfRun), result
        return result.stdout

    info = core.parse_dash_i(nfdump(["-I", "-r", str(capture)], [], None, None))
    assert info["Flows"] == 2 and info["First"] == int(t0), info

    read = ["-r", str(capture)]
    raw = core.parse_flow_csv(nfdump(read, ["-c", "10"], core.RAW_FMT, "any"))
    got = {(r.sa, r.sp, r.da, r.dp, r.proto, r.pkt, r.byt, r.first, r.last) for r in raw.rows}
    want = {(f[0], f[1], f[2], f[3], f[4], f[6], f[7], f[8], f[9]) for f in flows}
    assert raw.dropped == 0 and got == want, (got, want)

    stats = core.parse_stat_csv(
        nfdump(read, ["-s", "srcip/flows", "-n", "5"], core.STAT_FMT, "any"), [True]
    )
    (row,) = stats.tables[0].rows
    assert (row.val, row.fl, row.byt) == ("192.0.2.10", 2, 5080), row

    seg_mode = ["-A", core.SEG_AGG_KEYS, "-s", "record/flows", "-n", "5"]
    segments = core.parse_flow_csv(nfdump(read, seg_mode, core.SEG_FMT, "any"))
    assert {(r.sa, r.da, r.fl) for r in segments.rows} == {("192.0.2.0", "198.51.100.0", 2)}

    empty = nfdump(read, ["-c", "10"], core.RAW_FMT, "src ip 203.0.113.99")
    assert core.parse_flow_csv(empty).saw_no_match, empty
    print("PASS NetFlow collection and nfdump csv layouts", flush=True)


def main() -> None:
    assert os.getuid() != 0, "Run through the image entrypoint as mulder"
    assert Path.home() == Path("/home/mulder"), "Unexpected HOME"
    report = json.loads(run("mulder", "setup", "--verify", "--json", timeout=300))
    assert report["root"] == "/opt", report["root"]
    bad = [
        asset
        for asset in report["assets"]
        if asset["selected"] and asset["status"] not in ("up-to-date", "up-to-date (unmanaged)")
    ]
    assert not bad, bad
    shadowed = [asset for asset in report["assets"] if asset["shadowed_by"]]
    assert not shadowed, shadowed
    assert report["exit"] == 0, report["exit"]
    for name in ("pyewf", "pysqlcipher3.dbapi2", "volatility3", "plaso", "mvt", "oletools"):
        importlib.import_module(name)
    from pysqlcipher3 import dbapi2

    with dbapi2.connect(":memory:") as connection:
        assert connection.execute("PRAGMA cipher_version").fetchone()[0]

    for name in ("aleapp", "ileapp", "zircolite", "signature-base", "didier-stevens"):
        root = Path("/opt") / name
        assert (root / ".git").is_dir(), f"Missing Git metadata: {root}"
        run("git", "-c", f"safe.directory={root}", "-C", root, "cat-file", "-e", "HEAD^{tree}")

    cache = Path.home() / ".cache/volatility3/symbols"
    with tempfile.TemporaryFile(dir=cache) as writable:
        writable.write(b"symbol cache is writable")
    for name in ("linux.zip", "windows.zip"):
        with zipfile.ZipFile(cache / name) as archive:
            entry = next(member for member in archive.infolist() if not member.is_dir())
            assert archive.read(entry), f"Empty symbol member: {name}/{entry.filename}"

    for command in (
        ("ewfinfo", "-V"),
        ("yara", "--version"),
        ("r2", "-v"),
        ("dotnet", "--list-runtimes"),
        ("zeek", "--version"),
        ("suricata", "-V"),
        ("chainsaw", "--version"),
        ("hayabusa", "help"),
        ("capa", "--version"),
        ("floss", "--version"),
        ("guestmount", "--version"),
        ("xmount", "--version"),
        ("ntfs-3g", "--version"),
        ("fuse2fs", "-V"),
        ("clamscan", "--version"),
        ("nfdump", "-V"),
    ):
        run(*command)
    # The unprivileged mulder user can only mount NTFS through the source-built
    # external-FUSE ntfs-3g; the distro binary (integrated FUSE) refuses.
    ntfs_version = subprocess.run(["ntfs-3g", "--version"], capture_output=True, text=True).stderr
    assert "external FUSE" in ntfs_version, (
        f"ntfs-3g is not the external-FUSE build: {ntfs_version!r}"
    )
    proxy = importlib.import_module("mulder.orchestrator.proxy")
    with proxy.ProxyManager(models=["ollama/smoke"]):
        print("PASS LiteLLM proxy startup and health", flush=True)
    # Exercise the shared .NET runtime and every installed forensic parser.
    for dll in (
        "AmcacheParser",
        "AppCompatCacheParser",
        "EvtxECmd",
        "JLECmd",
        "LECmd",
        "MFTECmd",
        "PECmd",
        "RBCmd",
        "RECmd",
        "SBECmd",
        "SrumECmd",
    ):
        path = next(Path("/opt/zimmermantools").rglob(f"{dll}.dll"))
        run("dotnet", path, "-h")

    with tempfile.TemporaryDirectory(prefix="mulder-smoke-") as directory:
        work = Path(directory)
        # One Ethernet/IPv4/UDP DNS query. Offline decoders explicitly ignore
        # checksums so this tiny fixture needs no packet-generation dependency.
        dns = (
            struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + b"\x05smoke\x07example\x00\x00\x01\x00\x01"
        )
        udp = struct.pack("!4H", 54321, 53, 8 + len(dns), 0) + dns
        ip = (
            struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(udp),
                1,
                0,
                64,
                17,
                0,
                bytes((192, 0, 2, 1)),
                bytes((192, 0, 2, 53)),
            )
            + udp
        )
        packet = bytes.fromhex("00112233445566778899aabb0800") + ip
        pcap = work / "smoke.pcap"
        pcap.write_bytes(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1700000000, 0, len(packet), len(packet))
            + packet
        )
        zeek = work / "zeek"
        zeek.mkdir()
        run("zeek", "-C", "-r", pcap, cwd=zeek)
        assert "smoke.example" in (zeek / "dns.log").read_text()

        suricata = work / "suricata"
        suricata.mkdir()
        rules = work / "smoke.rules"
        rules.write_text(
            'alert udp any any -> any 53 (msg:"mulder smoke DNS"; sid:1000001; rev:1;)\n'
        )
        config = work / "suricata.yaml"
        if not os.access("/etc/suricata/suricata.yaml", os.R_OK):
            print(
                "NOTE packaged Suricata config missing or unreadable; using synthetic config",
                flush=True,
            )
        config.write_text(
            "%YAML 1.1\n---\noutputs:\n  - eve-log:\n      enabled: yes\n"
            "      filetype: regular\n      filename: eve.json\n      types:\n        - alert\n"
        )
        if os.access("/etc/suricata/rules", os.R_OK | os.X_OK):
            assert any(Path("/etc/suricata/rules").glob("*.rules")), "ET rules missing"
        else:
            print(
                "NOTE packaged Suricata rules unreadable; verify their inventory as root",
                flush=True,
            )
        run(
            "suricata",
            "--runmode",
            "single",
            "-k",
            "none",
            "-r",
            pcap,
            "-c",
            config,
            "-S",
            rules,
            "-l",
            suricata,
        )
        events = [json.loads(line) for line in (suricata / "eve.json").read_text().splitlines()]
        assert any(event.get("alert", {}).get("signature_id") == 1000001 for event in events)

        netflow_smoke(work)

        evidence = work / "email.raw"
        original = (b"Contact smoke@example.org for the smoke test.\n" * 100).ljust(8192, b"\0")
        evidence.write_bytes(original)
        run("ewfacquire", "-u", "-q", "-t", work / "evidence", evidence)
        pyewf = importlib.import_module("pyewf")
        handle = pyewf.handle()
        try:
            handle.open(pyewf.glob(str(work / "evidence.E01")))
            assert handle.read_buffer(len(original)) == original, "E01 roundtrip differs"
        finally:
            handle.close()
        print("PASS E01 acquisition and pyewf byte-for-byte readback", flush=True)
        bulk = work / "bulk"
        run("bulk_extractor", "-E", "email", "-j", "1", "-o", bulk, evidence)
        assert "smoke@example.org" in (bulk / "email.txt").read_text()

        for name in ("aleapp", "ileapp"):
            source = work / f"{name}-input"
            output = work / f"{name}-output"
            output.mkdir()
            if name == "aleapp":
                fixture = source / "data/misc/adb/adb_keys"
                fixture.parent.mkdir(parents=True)
                fixture.write_text("AAAA smoke@mulder-smoke-host\n")
                expected = "mulder-smoke-host"
            else:
                fixture = source / "Library/Preferences/com.apple.wifi-private-mac-networks.plist"
                fixture.parent.mkdir(parents=True)
                fixture.write_bytes(
                    plistlib.dumps(
                        {
                            "List of scanned networks with private mac": [
                                {"SSID_STR": "mulder-smoke-wifi", "BSSID": "00:11:22:33:44:55"}
                            ]
                        }
                    )
                )
                expected = "mulder-smoke-wifi"
            run(
                "python3",
                f"/opt/{name}/{name}.py",
                "-t",
                "fs",
                "-i",
                source,
                "-o",
                output,
                cwd=work,
                timeout=300,
            )
            assert any(expected in path.read_text() for path in output.rglob("*.tsv")), name
            assert list(output.rglob("tabler-icons.css")), f"{name} report assets missing"
            print(f"PASS {name} synthetic artifact and HTML assets", flush=True)
    print("PASS container smoke checks", flush=True)


if __name__ == "__main__":
    main()
