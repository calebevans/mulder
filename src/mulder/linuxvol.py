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

EXPORT_MARKER = ".mulder-linux-export.json"
"""Written by export_linux_files at the top of a finished export; not evidence."""

SECRET_FILES = re.compile(
    r"(?:^|/)(?:etc/(?:g?shadow|master\.passwd|security/opasswd)[^/]*"
    r"|etc/ssh/ssh_host_[^/]*_key|\.ssh/id_[^/]*(?<!\.pub)"
    r"|etc/(?:ssl|pki/tls)/private/.*|privkey[^/]*\.pem)$",
    re.IGNORECASE,
)
"""Password hash files and private keys, matched from any directory of a path.

Never copied into the case directory and never indexed, asked for or not.
That they exist, their size and their times are in the listing; their content
is a credential. Without case, as image_export matches the names it is given.
"""

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


def export_dir(extract_root: Path, image_path: str) -> Path:
    """Where export_linux_files puts the files of *image_path*.

    Fixed by the image's resolved path, so the planner can name the directory
    in the same plan that creates it.
    """
    resolved = Path(image_path).resolve()
    digest = hashlib.blake2b(str(resolved).encode("utf-8", "surrogateescape"), digest_size=6)
    return extract_root / f"{resolved.name}.files-{digest.hexdigest()}"


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


@functools.lru_cache(maxsize=32)
def probe(image_path: str) -> tuple[Volume, ...]:
    """The LVM, XFS, LUKS and btrfs volumes in a disk image; empty when it has none.

    Looks at the image's first sectors and at the start of every row ``mmls``
    prints, so a volume is found whether it fills the disk or sits in a
    partition, and whatever the partition table calls it.
    """
    if image_path.startswith("-"):
        return ()
    try:
        mmls = subprocess.run(
            ["mmls", image_path], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    # mmls fails on an image with no partition table: then the volume starts at 0.
    rows = parse_mmls_rows(mmls.stdout) if mmls.returncode == 0 else []
    starts = sorted({0, *(start for start, _, _ in rows)})[:_MAX_STARTS]
    found: list[Volume] = []
    for start in starts:
        head = _sectors(image_path, start, _HEAD_SECTORS) or _sectors(image_path, start, 4)
        label = next(
            (
                i
                for i in range(0, 4 * _SECTOR, _SECTOR)
                if head[i : i + 8] == b"LABELONE" and head[i + 24 : i + 32] == b"LVM2 001"
            ),
            None,
        )
        if label is not None:
            # The label is in one of its volume's first four sectors and says which,
            # so a row that starts just before the volume does not count it twice.
            first = start + label // _SECTOR - struct.unpack_from("<Q", head, label + 8)[0]
            if first >= 0 and all(v.sector != first for v in found):
                found.append(_lvm(image_path, first))
        elif head[:4] == b"XFSB":
            found.append(Volume(start, "xfs"))
        elif head[:6] == b"LUKS\xba\xbe":
            found.append(Volume(start, "luks"))
        elif head[0x10040:0x10048] == b"_BHRfS_M":
            found.append(Volume(start, "btrfs"))
    return tuple(found)
