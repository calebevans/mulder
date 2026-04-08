"""Disk image and standalone EVTX extractor.

Handles disk images (``.E01``, ``.dd``, ``.img``): mounts the image
read-only, walks the filesystem for Windows artifacts (EVTX logs, Prefetch
files, registry hives, known log paths), parses each, and returns one
:class:`ExtractionResult` per logical source.

Also handles standalone ``.evtx`` files without mounting.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from mulder.extractors.base import ExtractionResult

logger = logging.getLogger(__name__)

_DISK_IMAGE_EXTS = frozenset({".e01", ".dd", ".img"})
_EVTX_EXTS = frozenset({".evtx"})
_REGISTRY_HIVES = frozenset({"system", "software", "sam", "ntuser.dat", "security", "default"})
_PREFETCH_EXT = ".pf"
_REGRIPPER_BINS = ("rip.pl", "regripper")


# ---------------------------------------------------------------------------
# EVTX parsing helpers
# ---------------------------------------------------------------------------


def _parse_evtx_file(evtx_path: Path) -> tuple[str, str]:
    """Parse an EVTX file and return ``(channel_name, text_output)``.

    Each record is formatted as: ``timestamp | EventID | Channel | xml_one_line``
    """
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        logger.warning("python-evtx not installed -- skipping %s", evtx_path)
        return "", ""

    channel = _channel_from_path(evtx_path)
    lines: list[str] = []

    try:
        with Evtx(str(evtx_path)) as evtx:
            for record in evtx.records():
                try:
                    xml_str = record.xml()
                    timestamp = str(record.timestamp())
                    event_id = _extract_event_id(xml_str)
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


# ---------------------------------------------------------------------------
# Prefetch parsing helper
# ---------------------------------------------------------------------------


def _parse_prefetch_dir(prefetch_dir: Path) -> str:
    """Read all ``.pf`` files in *prefetch_dir* and return combined text.

    Prefetch files are partially binary; we extract whatever ASCII text is
    readable and include the filename + timestamps from the file metadata.
    """
    lines: list[str] = []
    for pf_file in sorted(prefetch_dir.glob(f"*{_PREFETCH_EXT}")):
        try:
            stat = pf_file.stat()
            lines.append(f"PREFETCH {pf_file.name} | size={stat.st_size} | mtime={stat.st_mtime}")
        except OSError:
            logger.debug("Cannot stat prefetch file %s", pf_file)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Registry parsing helper
# ---------------------------------------------------------------------------


def _find_regripper_bin() -> str | None:
    """Return the first available RegRipper binary name, or None."""
    for name in _REGRIPPER_BINS:
        if shutil.which(name):
            return name
    return None


def _parse_registry_hive(hive_path: Path) -> str:
    """Run RegRipper on a registry hive if available, else return empty."""
    rip_cmd = _find_regripper_bin()
    if rip_cmd is None:
        logger.debug("RegRipper not found -- skipping %s", hive_path)
        return ""
    try:
        proc = subprocess.run(
            [rip_cmd, "-r", str(hive_path), "-a"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return proc.stdout.strip()
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("RegRipper failed on %s: %s", hive_path, exc)
        return ""


# ---------------------------------------------------------------------------
# Disk mount / unmount helpers
# ---------------------------------------------------------------------------


def _mount_image(image_path: Path, mount_point: Path) -> bool:
    """Mount *image_path* read-only at *mount_point*. Returns True on success."""
    ext = image_path.suffix.lower()

    if ext == ".e01":
        return _mount_e01(image_path, mount_point)

    # Raw / dd images
    try:
        subprocess.run(
            ["sudo", "mount", "-o", "ro,loop,noexec,nodev", str(image_path), str(mount_point)],
            capture_output=True,
            timeout=60,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: guestmount (libguestfs, no root needed)
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

    logger.error("Could not mount %s -- tried mount and guestmount", image_path)
    return False


def _mount_e01(image_path: Path, mount_point: Path) -> bool:
    """Mount an E01 image via ewfmount -> mount."""
    if not shutil.which("ewfmount"):
        logger.error("ewfmount not found -- cannot mount E01 images")
        return False

    ewf_mount = mount_point / "_ewf"
    ewf_mount.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            ["ewfmount", str(image_path), str(ewf_mount)],
            capture_output=True,
            timeout=60,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.error("ewfmount failed on %s: %s", image_path, exc)
        return False

    raw_device = ewf_mount / "ewf1"
    if not raw_device.exists():
        logger.error("ewfmount did not produce ewf1 device in %s", ewf_mount)
        _unmount_path(ewf_mount)
        return False

    try:
        subprocess.run(
            ["sudo", "mount", "-o", "ro,loop,noexec,nodev", str(raw_device), str(mount_point)],
            capture_output=True,
            timeout=60,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.error("Failed to mount ewf device %s: %s", raw_device, exc)
        _unmount_path(ewf_mount)
        return False


def _unmount_path(path: Path) -> None:
    """Best-effort unmount."""
    for cmd in (["sudo", "umount", str(path)], ["fusermount", "-u", str(path)]):
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


# ---------------------------------------------------------------------------
# Filesystem walking helpers
# ---------------------------------------------------------------------------


def _find_evtx_files(root: Path) -> list[Path]:
    """Find all .evtx files under ``Windows/System32/winevt/Logs/`` or similar."""
    candidates: list[Path] = []
    for evtx_dir in (
        root / "Windows" / "System32" / "winevt" / "Logs",
        root / "windows" / "system32" / "winevt" / "logs",
    ):
        if evtx_dir.is_dir():
            candidates.extend(sorted(evtx_dir.glob("*.evtx")))
    if not candidates:
        candidates = sorted(root.rglob("*.evtx"))
    return candidates


def _find_prefetch_dir(root: Path) -> Path | None:
    for candidate in (
        root / "Windows" / "Prefetch",
        root / "windows" / "prefetch",
    ):
        if candidate.is_dir():
            return candidate
    return None


def _find_registry_hives(root: Path) -> list[tuple[str, Path]]:
    """Return list of ``(hive_label, path)`` pairs for known registry hives."""
    results: list[tuple[str, Path]] = []
    config_dirs = [
        root / "Windows" / "System32" / "config",
        root / "windows" / "system32" / "config",
    ]
    for config_dir in config_dirs:
        if not config_dir.is_dir():
            continue
        for item in config_dir.iterdir():
            if item.name.lower() in _REGISTRY_HIVES and item.is_file():
                label = item.name.lower().replace(".dat", "")
                results.append((label, item))
    # NTUSER.DAT in user profiles
    users_dirs = [root / "Users", root / "Documents and Settings"]
    for users_dir in users_dirs:
        if not users_dir.is_dir():
            continue
        for ntuser in users_dir.rglob("NTUSER.DAT"):
            user = ntuser.parent.name.lower()
            results.append((f"ntuser-{user}", ntuser))
    return results


def _find_log_paths(root: Path) -> list[Path]:
    """Find known text-log directories inside a mounted filesystem."""
    candidates: list[Path] = []
    for log_dir in (
        root / "var" / "log",
        root / "inetpub" / "logs",
        root / "Windows" / "System32" / "LogFiles",
        root / "windows" / "system32" / "logfiles",
    ):
        if log_dir.is_dir():
            candidates.append(log_dir)
    return candidates


def _read_text_file_safe(path: Path, max_bytes: int = 100 * 1024 * 1024) -> str:
    """Read a text file, skipping binary files and capping at *max_bytes*."""
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
            if b"\x00" in head:
                return ""
            size = path.stat().st_size
            if size > max_bytes:
                f.seek(-max_bytes, os.SEEK_END)
            else:
                f.seek(0)
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------


class DiskImageExtractor:
    """Handles disk images: mount read-only, run artifact parsers.

    Also handles standalone ``.evtx`` files directly (without mounting).
    """

    name: str = "disk"

    def can_handle(self, path: Path) -> bool:
        ext = path.suffix.lower()
        if ext in _DISK_IMAGE_EXTS:
            return True
        return ext in _EVTX_EXTS

    def extract(self, path: Path, case_id: str) -> list[ExtractionResult]:
        if path.suffix.lower() in _EVTX_EXTS:
            return self._extract_standalone_evtx(path)
        return self._extract_disk_image(path, case_id)

    def version(self) -> str:
        parts: list[str] = []
        try:
            from Evtx import __version__ as evtx_ver

            parts.append(f"python-evtx {evtx_ver}")
        except (ImportError, AttributeError):
            parts.append("python-evtx (available)" if _has_evtx() else "python-evtx (missing)")

        if _find_regripper_bin() is not None:
            parts.append("regripper (available)")
        return "; ".join(parts) if parts else "disk-extractor (builtin)"

    # -- standalone EVTX ---------------------------------------------------

    def _extract_standalone_evtx(self, evtx_path: Path) -> list[ExtractionResult]:
        channel, text = _parse_evtx_file(evtx_path)
        if not text:
            return []
        return [
            ExtractionResult(
                source_name=f"evtx.{channel}",
                source_path=str(evtx_path),
                extractor="python-evtx",
                text_output=text,
                line_count=text.count("\n") + 1,
            )
        ]

    # -- disk image ---------------------------------------------------------

    def _extract_disk_image(self, image_path: Path, case_id: str) -> list[ExtractionResult]:
        mount_point = Path(tempfile.mkdtemp(prefix=f"mulder_{case_id}_mount_"))
        mounted = False

        try:
            mounted = _mount_image(image_path, mount_point)
            if not mounted:
                logger.error("Cannot mount %s -- skipping disk extraction", image_path)
                return []

            results: list[ExtractionResult] = []
            results.extend(self._extract_evtx_from_mount(mount_point, image_path))
            results.extend(self._extract_prefetch(mount_point, image_path))
            results.extend(self._extract_registry(mount_point, image_path))
            results.extend(self._extract_logs_from_mount(mount_point, image_path))
            return results
        finally:
            if mounted:
                _unmount_image(mount_point)
            with contextlib.suppress(OSError):
                mount_point.rmdir()

    def _extract_evtx_from_mount(self, root: Path, image_path: Path) -> list[ExtractionResult]:
        results: list[ExtractionResult] = []
        for evtx_file in _find_evtx_files(root):
            channel, text = _parse_evtx_file(evtx_file)
            if not text:
                continue
            results.append(
                ExtractionResult(
                    source_name=f"evtx.{channel}",
                    source_path=str(image_path),
                    extractor="python-evtx",
                    text_output=text,
                    line_count=text.count("\n") + 1,
                )
            )
        return results

    def _extract_prefetch(self, root: Path, image_path: Path) -> list[ExtractionResult]:
        pf_dir = _find_prefetch_dir(root)
        if pf_dir is None:
            return []
        text = _parse_prefetch_dir(pf_dir)
        if not text:
            return []
        return [
            ExtractionResult(
                source_name="prefetch.all",
                source_path=str(image_path),
                extractor="prefetch-parser",
                text_output=text,
                line_count=text.count("\n") + 1,
            )
        ]

    def _extract_registry(self, root: Path, image_path: Path) -> list[ExtractionResult]:
        results: list[ExtractionResult] = []
        for label, hive_path in _find_registry_hives(root):
            text = _parse_registry_hive(hive_path)
            if not text:
                continue
            results.append(
                ExtractionResult(
                    source_name=f"registry.{label}",
                    source_path=str(image_path),
                    extractor="regripper",
                    text_output=text,
                    line_count=text.count("\n") + 1,
                )
            )
        return results

    def _extract_logs_from_mount(self, root: Path, image_path: Path) -> list[ExtractionResult]:
        results: list[ExtractionResult] = []
        for log_dir in _find_log_paths(root):
            for log_file in sorted(log_dir.rglob("*")):
                if not log_file.is_file():
                    continue
                text = _read_text_file_safe(log_file)
                if not text:
                    continue
                rel = log_file.relative_to(root)
                name = f"disk.{str(rel).replace(os.sep, '.').lower()}"
                results.append(
                    ExtractionResult(
                        source_name=name,
                        source_path=str(image_path),
                        extractor="disk-log-reader",
                        text_output=text,
                        line_count=text.count("\n") + 1,
                    )
                )
        return results


def _has_evtx() -> bool:
    try:
        import Evtx  # noqa: F401

        return True
    except ImportError:
        return False
