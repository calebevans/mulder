"""Linux volumes Sleuth Kit cannot open: recognise them, and name where their files go.

Sleuth Kit 4.11 (Ubuntu 22.04) reads neither LVM nor XFS, so on the usual
Linux server image ``fls`` fails, or lists ``/boot`` and nothing else.  dfVFS,
which plaso's command-line tools are built on, reads both.  :func:`probe`
tells which case an image is from the first sectors of each partition; the
export itself is ``export_linux_files`` in ``mulder.server.tools.linux``.
"""

from __future__ import annotations

import functools
import hashlib
import re
import struct
import subprocess
from pathlib import Path
from typing import NamedTuple

from mulder.patterns import parse_mmls_rows

EXPORTS_DIR = ".linux-exports"
"""Where exports live under a case's extraction directory.

Hidden, because the evidence walk enters no hidden directory: an export is
never taken for evidence, and nothing has to recognise one by a file inside
it, which evidence could carry too. No archive is unpacked to this name.
"""

EXPORT_MARKER = ".mulder-linux-export.json"
"""Written by export_linux_files beside a finished export's files: what it reported."""

SECRET_FILES = re.compile(
    r"(?:^|/)(?:etc/(?:g?shadow|master\.passwd|security/opasswd)[^/]*"
    r"|var/backups/g?shadow[^/]*"
    r"|etc/ssh/ssh_host_[^/]*_key|\.ssh/id_[^/]*(?<!\.pub)"
    r"|etc/(?:ssl|pki/tls)/private/.*|privkey[^/]*\.pem)$",
    re.IGNORECASE,
)
"""Password hash files and private keys by their well-known names, from any directory.

Not copied into the case directory and not indexed, asked for or not. That
they exist, their size and their times are in the listing; their content is
a credential. Without case, as image_export matches the names it is given.
A secret under another name (a copy, a hard link, a key called deploy.pem)
is not caught here; :data:`PRIVATE_KEY` catches a key by its content.
"""

PRIVATE_KEY = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
"""The first line of a PEM or OpenSSH private key, whatever the file is called."""

_KINDS = {
    "lvm": "LVM physical volume",
    "xfs": "XFS file system",
    "luks": "LUKS-encrypted volume",
    "btrfs": "btrfs file system",
}
_SECTOR = 512
_HEAD_SECTORS = 129  # the btrfs magic is 64 bytes into sector 128
_MAX_STARTS = 64
_MAX_METADATA_SECTORS = 2048
_LVM_MDA_MAGIC = b" LVM2 x[5A%r0N*>"


class Volume(NamedTuple):
    """A volume that needs something other than Sleuth Kit."""

    sector: int
    kind: str
    """A key of ``_KINDS``."""
    group: str = ""
    """LVM: the volume group's name."""
    disks: int = 0
    """LVM: physical volumes in the group, 0 when the metadata could not be read."""

    @property
    def readable(self) -> bool:
        """Whether dfVFS can read it from this one image without a key."""
        return self.kind in ("lvm", "xfs") and self.disks <= 1

    def __str__(self) -> str:
        text = f"{_KINDS[self.kind]} at sector {self.sector}"
        if self.group:
            text += f", volume group {self.group}"
        if self.disks > 1:
            text += f" on {self.disks} disks of which this image is one"
        return text


def _lvm_label(head: bytes) -> int | None:
    """Where the LVM2 label is: it sits in one of a physical volume's first four sectors."""
    return next(
        (
            i
            for i in range(0, 4 * _SECTOR, _SECTOR)
            if head[i : i + 8] == b"LABELONE" and head[i + 24 : i + 32] == b"LVM2 001"
        ),
        None,
    )


def volume_kind(head: bytes) -> str | None:
    """Which of ``_KINDS`` a volume is, from its first 66 KiB; None for anything else."""
    if _lvm_label(head) is not None:
        return "lvm"
    if head[:4] == b"XFSB":
        return "xfs"
    if head[:6] == b"LUKS\xba\xbe":
        return "luks"
    return "btrfs" if head[0x10040:0x10048] == b"_BHRfS_M" else None


def export_dir(extract_root: Path, image_path: str) -> Path:
    """Where export_linux_files puts the files of *image_path*.

    Fixed by the image's resolved path, so the planner can name the directory
    in the same plan that creates it.
    """
    resolved = Path(image_path).resolve()
    digest = hashlib.blake2b(str(resolved).encode("utf-8", "surrogateescape"), digest_size=6)
    return extract_root / EXPORTS_DIR / f"{resolved.name}-{digest.hexdigest()}" / "files"


def _sectors(image_path: str, start: int, count: int) -> bytes:
    """*count* sectors from *start*, through img_cat: it reads EWF and raw images alike."""
    # img_cat refuses "-s 0", and prints nothing at all when the range ends past the image.
    cmd = ["img_cat", *(["-s", str(start)] if start else []), "-e", str(start + count - 1)]
    try:
        proc = subprocess.run([*cmd, image_path], capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return b""
    return proc.stdout if proc.returncode == 0 else b""


def _lvm(image_path: str, start: int) -> Volume:
    """The physical volume at *start*, with what its metadata says about the group."""
    # Metadata area header, 4096 bytes in: crc(4) magic(16) version(4) start(8) size(8),
    # then where the current metadata text is: offset(8) size(8).
    header = _sectors(image_path, start + 8, 1)
    if header[4:20] != _LVM_MDA_MAGIC or len(header) < 56:
        return Volume(start, "lvm")
    offset, size = struct.unpack_from("<QQ", header, 40)
    count = min(size // _SECTOR + 2, _MAX_METADATA_SECTORS)
    raw = _sectors(image_path, start + 8 + offset // _SECTOR, count)
    text = raw[offset % _SECTOR :][:size].decode("ascii", "replace")
    name = re.match(r"([A-Za-z0-9_.+-]{1,64}) \{", text)
    disks = set(re.findall(r"^\s*(pv\d+) \{", text, re.MULTILINE))
    return Volume(start, "lvm", name.group(1) if name else "", len(disks))


# What Sleuth Kit reads by itself, by the bytes at the start of a partition.
_PLAIN = (
    ("ntfs", 3, b"NTFS    "),
    ("exfat", 3, b"EXFAT   "),
    ("ext", 1080, b"\x53\xef"),
    ("fat", 82, b"FAT32"),
    ("fat", 54, b"FAT1"),
)
# An allocated row of mmls: "002:  000:000   0000002048" (DOS), "004:  000   0000002048" (GPT).
_MMLS_SLOT_RE = re.compile(r"^\s*\d+:\s+(\d+)(?::(\d+))?\s+(\d+)\s", re.MULTILINE)


class Scan(NamedTuple):
    """What a disk image holds, as far as routing it needs to know."""

    volumes: tuple[Volume, ...] = ()
    """The LVM, XFS, LUKS and btrfs volumes."""
    plain: frozenset[str] = frozenset()
    """Names from ``_PLAIN`` of the file systems found beside them."""
    partitions: tuple[tuple[int, int], ...] = ()
    """``(start sector, number)`` of each allocated partition, numbered as dfVFS does."""


@functools.lru_cache(maxsize=32)
def scan(image_path: str) -> Scan:
    """What starts at sector 0 of a disk image and at every row ``mmls`` prints."""
    if image_path.startswith("-"):
        return Scan()
    try:
        mmls = subprocess.run(
            ["mmls", image_path], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return Scan()
    # mmls fails on an image with no partition table: then the volume starts at 0.
    table = mmls.stdout if mmls.returncode == 0 else ""
    starts = sorted({0, *(start for start, _, _ in parse_mmls_rows(table))})[:_MAX_STARTS]
    found: list[Volume] = []
    plain: set[str] = set()
    for start in starts:
        head = _sectors(image_path, start, _HEAD_SECTORS) or _sectors(image_path, start, 4)
        label, kind = _lvm_label(head), volume_kind(head)
        if label is not None:
            # The label says which sector of its volume it is in, so a row that
            # starts just before the volume does not count it a second time.
            first = start + label // _SECTOR - struct.unpack_from("<Q", head, label + 8)[0]
            if first >= 0 and all(v.sector != first for v in found):
                found.append(_lvm(image_path, first))
        elif kind is not None:
            found.append(Volume(start, kind))
        else:
            plain.update(name for name, at, magic in _PLAIN if head[at:].startswith(magic))
    # As dfVFS's Sleuth Kit back end numbers them: a DOS table by table and
    # slot (the first logical partition is 5), any other in table order.
    numbered = tuple(
        (int(m[3]), int(m[1]) * 4 + int(m[2]) + 1 if m[2] is not None else count)
        for count, m in enumerate(_MMLS_SLOT_RE.finditer(table), 1)
    )
    return Scan(tuple(found), frozenset(plain), numbered)


def probe(image_path: str) -> tuple[Volume, ...]:
    """The LVM, XFS, LUKS and btrfs volumes in a disk image; empty when it has none.

    A volume is found whether it fills the disk or sits in a partition, and
    whatever the partition table calls it.
    """
    return scan(image_path).volumes


def route(image_path: str) -> str:
    """How an image that holds such a volume is examined; ``""`` when it holds none.

    ``export``: export_linux_files stands in for the Sleuth Kit tools, since
    dfVFS also reads whatever else a Linux disk holds (``/boot``, an EFI
    partition). ``also``: the disk holds NTFS or exFAT too, so the export is
    planned beside the usual disk tools. ``rest``: nothing reads the volume and
    Sleuth Kit reads the rest. ``none``: nothing reads anything on the image.
    """
    found = scan(image_path)
    if not found.volumes:
        return ""
    if any(v.readable for v in found.volumes):
        return "also" if found.plain & {"ntfs", "exfat"} else "export"
    return "rest" if found.plain else "none"


def unencrypted_partitions(image_path: str) -> str:
    """plaso's ``--partitions`` value that leaves the LUKS partitions out; ``""`` if none is left.

    plaso stops at an encrypted volume it has no key for and has no option to
    pass one by: naming the other partitions is how it is kept off it.
    """
    found = scan(image_path)
    locked = {v.sector for v in found.volumes if v.kind == "luks"}
    keep = sorted(number for start, number in found.partitions if start not in locked)
    return ",".join(map(str, keep)) if locked and len(keep) < len(found.partitions) else ""
