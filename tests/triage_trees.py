"""Synthetic triage collections, laid out the way each collector writes them."""

from __future__ import annotations

import json
from pathlib import Path

COPYLOG = (
    "\ufeffCopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,"
    "CreatedOnUtc,ModifiedOnUtc,LastAccessedOnUtc,CopyDuration\n"
    "2023-03-24 12:39:26.5195695,C:\\Windows\\System32\\config\\SYSTEM,"
    "C:\\out\\C\\Windows\\System32\\config\\SYSTEM,11,"
    "C70BFFF0A559AF8CB76AD80A504DD55BD6CC484D,True,2021-09-15 16:02:35.2937725,"
    "2023-03-15 06:17:16.6838553,2023-03-15 06:17:16.6838553,00:00:00.0156220\n"
)
SKIPLOG = (
    "\ufeffSourceFile,SourceFileSha1,Reason\n"
    "C:\\Windows\\System32\\winevt\\logs\\Empty.evtx,"
    "C70BFFF0A559AF8CB76AD80A504DD55BD6CC484D,Deduped\n"
)
CONSOLE = (
    "[2023-03-24 12:39:20.8787476 | INF] Command line:   --tsource C: --tdest C:\\out\n"
    "[2023-03-24 12:39:20.8787476 | INF] System info: Machine name: WS-01, 64-bit: true, "
    'User: Administrator OS: "WindowsServer2016" (10.0.20348)\n'
)
BODY = "0|/etc/passwd|131|-rw-r--r--|0|0|1024|1704164645|1704164645|1704164645|0\n"
UAC_NAME = "uac-web01-linux-20240102030405"
C_NTFS = "%5C%5C.%5CC%3A"  # \\.\C: as Velociraptor stores it


def write(root: Path, files: dict[str, bytes | str]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
    return root


def kape(root: Path) -> Path:
    """KAPE target output: a drive-letter directory and KAPE's three logs."""
    return write(
        root,
        {
            "C/$MFT": b"FILE0-mft",
            "C/$Extend/$J": b"usn-journal",
            "C/$Secure_$SDS": b"security-stream",
            "C/Windows/System32/config/SYSTEM": b"regf-system",
            "C/Windows/System32/config/SOFTWARE": b"regf-software",
            "C/Windows/System32/winevt/logs/Security.evtx": b"ElfFile-security",
            "C/Windows/AppCompat/Programs/Amcache.hve": b"regf-amcache",
            "C/Users/alice/NTUSER.DAT": b"regf-alice",
            "C/Program Files/App/app.ini": "[server]\nhost=10.0.0.5\n",
            "2023-03-24T12_39_01_6137377_CopyLog.csv": COPYLOG,
            "2023-03-24T12_39_01_6137377_SkipLog.csv.csv": SKIPLOG,
            "2023-03-24T12_39_01_6137377_ConsoleLog.txt": CONSOLE,
        },
    )


def velociraptor(root: Path) -> Path:
    """An unpacked offline collection: drive C split over two accessors, and a drive D."""
    return write(
        root,
        {
            f"uploads/ntfs/{C_NTFS}/$MFT": b"FILE0-mft",
            f"uploads/ntfs/{C_NTFS}/$Extend/$UsnJrnl%3A$J": b"usn-journal",
            "uploads/auto/C%3A/Windows/System32/config/SYSTEM": b"regf-system",
            "uploads/auto/C%3A/Users/bob/NTUSER.DAT": b"regf-bob",
            "uploads/auto/D%3A/data/report.txt": "quarterly\n",
            "results/Windows.KapeFiles.Targets%2FUploads.json": json.dumps(
                {
                    "SourceFile": "C:\\Users\\bob\\NTUSER.DAT",
                    "Modified": "2024-10-14T15:32:30.3560316Z",
                    "SourceFileSha256": "e05793b7",
                }
            )
            + "\n",
            "results/Windows.KapeFiles.Targets%2FUploads.json.index": b"\x00\x00",
            "client_info.json": json.dumps(
                {"Hostname": "DESKTOP-9", "Fqdn": "DESKTOP-9.corp.local", "OS": "windows"}
            ),
            "collection_context.json": "{}",
            "uploads.json": "{}\n",
        },
    )


def uac(parent: Path) -> Path:
    """UAC output, in a directory named the way UAC names its archive."""
    return write(
        parent / UAC_NAME,
        {
            "uac.log": "2024-01-02 03:04:05 +0000 INF UAC started\n",
            "[root]/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "[root]/var/log/auth.log": "Jan  2 03:00:01 web01 sshd[9]: Accepted password\n",
            "live_response/process/ps_auxwww.txt": "root 1 0.0 /sbin/init\nwww 77 /tmp/.x/miner\n",
            "live_response/process/ps_auxwww.txt.stderr": "ps: warning\n",
            "live_response/network/ss_-tlnp.txt": "LISTEN 0 128 0.0.0.0:4444\n",
            "bodyfile/bodyfile.txt": BODY,
        },
    )


def windows_volume(root: Path) -> Path:
    """A plain directory that is the root of a Windows volume."""
    return write(
        root,
        {
            "Windows/System32/config/SAM": b"regf-sam",
            "Users/carol/NTUSER.DAT": b"regf-carol",
        },
    )


def snapshot(root: Path) -> dict[str, tuple[int, int, bytes]]:
    """Every file under *root* with its size, mtime and content, to prove nothing changed."""
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns, p.read_bytes())
        for p in sorted(root.rglob("*"))
        if p.is_file() and not p.is_symlink()
    }
