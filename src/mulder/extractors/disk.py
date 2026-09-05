"""Disk image mount/unmount and EVTX parsing utilities.

Provides shared functions used by the Tier 2 MCP tool layer:

- ``_parse_evtx_file``: Parse an EVTX file into timestamped text lines.
- ``_mount_image`` / ``_unmount_image``: Mount/unmount disk images read-only.
"""

from __future__ import annotations

import logging
import re
import shutil
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
    """Run ``mmls`` to find the partition byte offset for ``mount -o offset=``.

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


def _mount_image(image_path: Path, mount_point: Path) -> bool:
    """Mount *image_path* read-only at *mount_point*. Returns True on success."""
    ext = image_path.suffix.lower()

    if ext == ".e01":
        return _mount_e01(image_path, mount_point)

    # Raw / dd images
    offset_bytes = _detect_mount_offset(str(image_path))
    mount_opts = "ro,loop,noexec,nodev"
    if offset_bytes > 0:
        mount_opts += f",offset={offset_bytes}"

    try:
        subprocess.run(
            ["mount", "-o", mount_opts, str(image_path), str(mount_point)],
            capture_output=True,
            timeout=60,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: guestmount (libguestfs, handles partitions natively via -i)
    if shutil.which("guestmount"):
        try:
            subprocess.run(
                [
                    "guestmount",
                    "-a",
                    str(image_path),
                    "-i",
                    "--ro",
                    str(mount_point),
                ],
                capture_output=True,
                timeout=120,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    logger.error("Could not mount %s (tried mount and guestmount)", image_path)
    return False


def _mount_e01(image_path: Path, mount_point: Path) -> bool:
    """Mount an E01 image read-only, trying multiple strategies.

    Strategy 1: ``ewfmount`` exposes a raw device, then ``mount -o loop``
    mounts the partition.  Strategy 2 (fallback): ``guestmount`` handles
    E01 images natively via libguestfs and auto-detects partitions.
    """
    ewf_mount = mount_point / "_ewf"
    ewf_mounted = False

    if shutil.which("ewfmount"):
        ewf_mount.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                ["ewfmount", str(image_path), str(ewf_mount)],
                capture_output=True,
                timeout=120,
                check=True,
            )
            ewf_mounted = True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            stderr = ""
            if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
                stderr = exc.stderr.decode("utf-8", errors="replace")[:300]
            logger.warning(
                "ewfmount failed on %s: %s %s",
                image_path,
                exc,
                stderr,
            )
            shutil.rmtree(ewf_mount, ignore_errors=True)
    else:
        logger.warning("ewfmount not found; will try guestmount for E01")

    if ewf_mounted:
        raw_device = ewf_mount / "ewf1"
        if not raw_device.exists():
            logger.error("ewfmount did not produce ewf1 device in %s", ewf_mount)
            _unmount_path(ewf_mount)
            shutil.rmtree(ewf_mount, ignore_errors=True)
        else:
            offset_bytes = _detect_mount_offset(str(raw_device))
            mount_opts = "ro,loop,noexec,nodev"
            if offset_bytes > 0:
                mount_opts += f",offset={offset_bytes}"
            try:
                subprocess.run(
                    ["mount", "-o", mount_opts, str(raw_device), str(mount_point)],
                    capture_output=True,
                    timeout=60,
                    check=True,
                )
                return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                logger.warning(
                    "Loop mount of ewf device %s failed: %s",
                    raw_device,
                    exc,
                )
                _unmount_path(ewf_mount)
                shutil.rmtree(ewf_mount, ignore_errors=True)

    if shutil.which("guestmount"):
        try:
            subprocess.run(
                [
                    "guestmount",
                    "-a",
                    str(image_path),
                    "-i",
                    "--ro",
                    str(mount_point),
                ],
                capture_output=True,
                timeout=180,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.warning("guestmount failed on E01 %s: %s", image_path, exc)

    logger.error(
        "Could not mount E01 %s (tried ewfmount+mount and guestmount)",
        image_path,
    )
    return False


def _unmount_path(path: Path) -> None:
    """Best-effort unmount."""
    for cmd in (["umount", str(path)], ["fusermount", "-u", str(path)]):
        try:
            subprocess.run(cmd, capture_output=True, timeout=30, check=True)
            return
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            continue
    logger.warning("Could not unmount %s", path)


def _unmount_image(mount_point: Path) -> None:
    """Unmount the main mount point and any nested ewf mount."""
    _unmount_path(mount_point)
    ewf_mount = mount_point / "_ewf"
    if ewf_mount.exists():
        _unmount_path(ewf_mount)
