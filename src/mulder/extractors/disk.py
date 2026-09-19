"""Disk image mount/unmount and EVTX parsing utilities.

Provides shared functions used by the Tier 2 MCP tool layer:

- ``_parse_evtx_file``: Parse an EVTX file into timestamped text lines.
- ``_mount_image`` / ``_unmount_image``: Mount/unmount disk images read-only
  over FUSE (xmount + ntfs-3g/fuse2fs); no root required.
"""

from __future__ import annotations

import logging
import re
import shlex
import shutil
import string
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from mulder.patterns import parse_mmls_rows

logger = logging.getLogger(__name__)
_EVTX_EXTS = frozenset({".evtx"})

_SECTOR_SIZE = 512
_NTFS_INDICATORS = ("ntfs", "exfat", "0x07", "win95 fat", "0x0b", "0x0c")
_LINUX_INDICATORS = ("linux", "0x83", "ext", "0x8e")


def _parse_evtx_file(
    evtx_path: Path,
    event_ids: set[int] | None = None,
) -> tuple[str, str]:
    """Parse an EVTX file and return ``(channel_name, text_output)``.

    Each record is formatted as: ``timestamp | EventID | Channel | xml_one_line``

    When *event_ids* is provided, only records with matching Event IDs
    are included.  This dramatically speeds up parsing of large logs.
    """
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        logger.warning("python-evtx not installed, skipping %s", evtx_path)
        return "", ""

    channel = _channel_from_path(evtx_path)
    lines: list[str] = []

    try:
        with Evtx(str(evtx_path)) as evtx:
            for record in evtx.records():
                try:
                    xml_str = record.xml()
                    event_id = _extract_event_id(xml_str)
                    if event_ids is not None and int(event_id) not in event_ids:
                        continue
                    timestamp = str(record.timestamp())
                    one_line = xml_str.replace("\n", " ").replace("\r", "")
                    lines.append(f"{timestamp} | {event_id} | {channel} | {one_line}")
                except Exception:
                    logger.debug("Skipping malformed record in %s", evtx_path, exc_info=True)
    except Exception:
        logger.warning("Failed to parse EVTX file %s", evtx_path, exc_info=True)
        return channel, ""

    return channel, "\n".join(lines)


def _channel_from_path(evtx_path: Path) -> str:
    """Derive a channel name from the filename.

    ``Security.evtx`` -> ``security``, ``Microsoft-Windows-Sysmon%4Operational.evtx`` ->
    ``sysmon-operational``.
    """
    stem = evtx_path.stem.lower()
    stem = stem.replace("microsoft-windows-", "").replace("%4", "-")
    stem = re.sub(r"[^a-z0-9\-]", "-", stem)
    stem = re.sub(r"-+", "-", stem).strip("-")
    return stem or "unknown"


def _extract_event_id(xml_str: str) -> str:
    """Pull the EventID from an EVTX record's XML."""
    try:
        root = ET.fromstring(xml_str)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        eid_elem = root.find(".//e:EventID", ns)
        if eid_elem is not None and eid_elem.text:
            return eid_elem.text
    except ET.ParseError:
        pass
    return "?"


def _detect_mount_offset(image_path: str) -> int:
    """Run ``mmls`` to find the partition byte offset for ``xmount --offset``.

    Returns the byte offset of the preferred partition (NTFS first, then
    Linux, then largest).  Returns 0 if ``mmls`` is unavailable or the
    image has no partition table (i.e. it is a bare filesystem image).
    """
    if not shutil.which("mmls"):
        logger.debug("mmls not found, skipping partition offset detection")
        return 0

    try:
        proc = subprocess.run(
            ["mmls", image_path],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("mmls timed out on %s", image_path)
        return 0

    if proc.returncode != 0 or not proc.stdout.strip():
        logger.debug("mmls found no partition table in %s", image_path)
        return 0

    annotated = parse_mmls_rows(proc.stdout)

    if not annotated:
        return 0

    for start, length, dl in annotated:
        if any(ind in dl for ind in _NTFS_INDICATORS) and length > 0:
            offset = start * _SECTOR_SIZE
            logger.info(
                "Detected partition at sector %d (byte offset %d) in %s: %s",
                start,
                offset,
                image_path,
                dl,
            )
            return offset

    for start, length, dl in annotated:
        if any(ind in dl for ind in _LINUX_INDICATORS) and length > 0:
            offset = start * _SECTOR_SIZE
            logger.info(
                "Detected partition at sector %d (byte offset %d) in %s: %s",
                start,
                offset,
                image_path,
                dl,
            )
            return offset

    biggest = max(annotated, key=lambda t: t[1])
    if biggest[1] > 0:
        offset = biggest[0] * _SECTOR_SIZE
        logger.info(
            "No known FS indicator; using largest partition at sector %d "
            "(byte offset %d) in %s: %s",
            biggest[0],
            offset,
            image_path,
            biggest[2],
        )
        return offset

    logger.debug("mmls parsed no usable partitions from %s", image_path)
    return 0


#: Read-only FUSE filesystem drivers, tried in order against the flat
#: partition file xmount exposes.  The first that mounts wins; the others
#: fail fast on a foreign signature.  Both mount unprivileged via setuid
#: fusermount (ntfs-3g only when built with external FUSE, as the container
#: does).  exfat-fuse is deliberately absent: it hardcodes a ``user=`` option
#: fusermount3 rejects, and exFAT media carry none of the Windows artifacts
#: this fallback exists for; TSK reads exFAT directly anyway.
_FUSE_DRIVERS: tuple[tuple[str, ...], ...] = (
    # no_def_opts drops ntfs-3g's implicit allow_other, which fusermount refuses
    # for non-root users unless /etc/fuse.conf opts in.
    ("ntfs-3g", "-o", "ro,noexec,no_def_opts"),
    ("fuse2fs", "-o", "ro,noexec"),
)


def _raw_dir(mount_point: Path) -> Path:
    """Where xmount exposes the partition file for *mount_point*."""
    return mount_point.with_name(mount_point.name + ".raw")


def _run(cmd: list[str], timeout: int) -> bool:
    """Run *cmd*; return True on exit 0, logging its output and argv otherwise.

    xmount reports errors on stdout, so stdout is logged when stderr is empty.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.warning("%s failed: %s", cmd[0], exc)
        return False
    if proc.returncode != 0:
        output = (proc.stderr.strip() or proc.stdout).decode("utf-8", errors="replace")
        output = " ".join(output.split())[:600]
        logger.warning(
            "%s exited %d: %s (argv: %s)", cmd[0], proc.returncode, output, shlex.join(cmd)
        )
    return proc.returncode == 0


#: First segment of an EWF (EnCase ``.E01``) or SMART (``.s01``) image, both of
#: which xmount's ewf input library reads.  EWF2 (``.Ex01``) is deliberately
#: absent: xmount 0.7.6 rejects it ("not valid EWF files").
_EWF_FIRST_SEGMENT = re.compile(r"\.[es]01$", re.IGNORECASE)


def _next_ewf_suffix(suffix: str) -> str:
    """libewf's segment naming: ``.E01``..``.E99``, ``.EAA``..``.EZZ``, ``.FAA``..``.ZZZ``."""
    if suffix[-2:].isdigit():
        if suffix[-2:] != "99":
            return f"{suffix[:-2]}{int(suffix[-2:]) + 1:02d}"
        return suffix[:-2] + ("AA" if suffix[-3].isupper() else "aa")
    letters = string.ascii_uppercase if suffix[-1].isupper() else string.ascii_lowercase
    n = 0
    for char in suffix[-3:]:
        n = n * 26 + letters.index(char)
    n += 1
    tail = ""
    for _ in range(3):
        tail = letters[n % 26] + tail
        n //= 26
    return suffix[:-3] + tail


def _ewf_segments(first: Path) -> list[Path]:
    """Every segment file of the EWF image starting at *first*, in order.

    xmount does not find ``.E02``... itself: its ``--in`` help says "If your
    image is split into multiple files, you have to specify them all!", and
    they must be in order.  Walks the names until one is missing; a gap in
    the middle is logged, since xmount will then fail to read the end of the
    data.
    """
    segments = [first]
    while (nxt := segments[-1].with_suffix(_next_ewf_suffix(segments[-1].suffix))).exists():
        segments.append(nxt)
    sibling = re.compile(re.escape(first.stem + first.suffix[:2]) + r"\w\w$")
    strays = sum(1 for p in first.parent.iterdir() if sibling.match(p.name)) - len(segments)
    if strays > 0:
        logger.warning(
            "%s is missing but %d later segment(s) exist; mounting %d segment(s) up to %s",
            nxt.name,
            strays,
            len(segments),
            segments[-1].name,
        )
    return segments


def _mount_image(image_path: Path, mount_point: Path) -> bool:
    """Mount *image_path* (E01 or raw) read-only at *mount_point*.

    Everything is user-space FUSE, so this works as the unprivileged
    ``mulder`` user with nothing more than ``/dev/fuse``:

    1. ``xmount`` exposes the preferred partition (see
       :func:`_detect_mount_offset`) as a flat ``.dd`` file in a sibling
       directory ``<mount_point>.raw`` (libfuse2 drivers refuse a non-empty
       mount point, so it cannot live inside).  It reads E01 natively, given
       every segment (see :func:`_ewf_segments`).
    2. A FUSE filesystem driver (ntfs-3g, fuse2fs) mounts that file at
       *mount_point*.

    Kernel ``mount -o loop`` is deliberately not used: it needs root and a
    loop device, and a ``--cap-add SYS_ADMIN --device /dev/fuse`` container
    has neither (nor does a native install running as a normal user).  There
    is no ``guestmount`` fallback either: libguestfs boots a supermin
    appliance, which needs a kernel image the container does not ship.
    """
    if not shutil.which("xmount"):
        logger.error("Could not mount %s: xmount not found", image_path)
        return False

    raw_dir = _raw_dir(mount_point)
    raw_dir.mkdir(parents=True, exist_ok=True)
    is_ewf = _EWF_FIRST_SEGMENT.search(image_path.name) is not None
    inputs = _ewf_segments(image_path) if is_ewf else [image_path]
    cmd = ["xmount", "--in", "ewf" if is_ewf else "raw", *map(str, inputs), "--out", "raw"]
    offset_bytes = _detect_mount_offset(str(image_path))
    if offset_bytes > 0:
        cmd += ["--offset", str(offset_bytes)]
    cmd.append(str(raw_dir))
    if not _run(cmd, timeout=120):
        logger.error("xmount failed on %s", image_path)
        shutil.rmtree(raw_dir, ignore_errors=True)
        return False

    raw_file = next(raw_dir.glob("*.dd"), None)
    if raw_file is not None:
        for driver in _FUSE_DRIVERS:
            if shutil.which(driver[0]) and _run([*driver, str(raw_file), str(mount_point)], 60):
                return True

    logger.error("No FUSE filesystem driver could mount %s (offset %d)", image_path, offset_bytes)
    _unmount_path(raw_dir)
    shutil.rmtree(raw_dir, ignore_errors=True)
    return False


def _unmount_path(path: Path, lazy: bool = False) -> None:
    """Best-effort unmount.  *lazy* detaches now and lets the daemon exit later."""
    for cmd in (
        ["fusermount", "-u", *(["-z"] if lazy else [])],
        ["umount", *(["-l"] if lazy else [])],
    ):
        cmd.append(str(path))
        try:
            subprocess.run(cmd, capture_output=True, timeout=30, check=True)
            return
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            continue
    logger.warning("Could not unmount %s", path)


def _unmount_image(mount_point: Path) -> None:
    """Unmount the filesystem, then the xmount partition file it was read from."""
    _unmount_path(mount_point)
    raw_dir = _raw_dir(mount_point)
    if raw_dir.exists():
        # Lazy: the filesystem daemon may still be closing the .dd file, which
        # makes an immediate unmount of the xmount layer fail with EBUSY.
        _unmount_path(raw_dir, lazy=True)
        shutil.rmtree(raw_dir, ignore_errors=True)
