"""Narrow subprocess entry point for read-only image mount operations.

The protocol accepts only ``mount IMAGE MOUNT_POINT`` and
``unmount MOUNT_POINT``. It never accepts an executable or arbitrary argv from
the caller, and all mount strategies use fixed read-only/no-exec options.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

_SECTOR_SIZE = 512
_MMLS_ROW_RE = re.compile(r"^\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$", re.MULTILINE)
_NTFS_INDICATORS = ("ntfs", "exfat", "0x07", "win95 fat", "0x0b", "0x0c")
_LINUX_INDICATORS = ("linux", "0x83", "ext", "0x8e")


def _run(argv: list[str], timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        capture_output=True,
        timeout=timeout,
        check=False,
        shell=False,
    )


def _detect_mount_offset(image_path: Path) -> int:
    mmls = shutil.which("mmls")
    if mmls is None:
        return 0
    try:
        proc = _run([mmls, str(image_path)], 60)
    except subprocess.TimeoutExpired:
        return 0
    if proc.returncode != 0 or not proc.stdout.strip():
        return 0
    text = proc.stdout.decode("utf-8", errors="replace")
    rows = [(int(m[1]), int(m[2]), m[3].strip().lower()) for m in _MMLS_ROW_RE.finditer(text)]
    for indicators in (_NTFS_INDICATORS, _LINUX_INDICATORS):
        for start, length, description in rows:
            if length > 0 and any(value in description for value in indicators):
                return start * _SECTOR_SIZE
    usable = [row for row in rows if row[1] > 0]
    return max(usable, key=lambda row: row[1])[0] * _SECTOR_SIZE if usable else 0


def _unmount_path(path: Path) -> bool:
    for executable, args in (("umount", []), ("fusermount", ["-u"])):
        resolved = shutil.which(executable)
        if resolved is None:
            continue
        try:
            if _run([resolved, *args, str(path)], 30).returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            continue
    return False


def _guestmount(image_path: Path, mount_point: Path, timeout: float) -> bool:
    guestmount = shutil.which("guestmount")
    if guestmount is None:
        return False
    try:
        return (
            _run(
                [guestmount, "-a", str(image_path), "-i", "--ro", str(mount_point)],
                timeout,
            ).returncode
            == 0
        )
    except subprocess.TimeoutExpired:
        return False


def _mount_raw(image_path: Path, mount_point: Path) -> bool:
    mount = shutil.which("mount")
    if mount is not None:
        offset = _detect_mount_offset(image_path)
        options = "ro,loop,noexec,nodev,nosuid"
        if offset > 0:
            options += f",offset={offset}"
        try:
            if _run([mount, "-o", options, str(image_path), str(mount_point)], 60).returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            pass
    return _guestmount(image_path, mount_point, 120)


def _mount_e01(image_path: Path, mount_point: Path) -> bool:
    ewfmount = shutil.which("ewfmount")
    ewf_dir = mount_point / "_ewf"
    if ewfmount is not None:
        ewf_dir.mkdir(parents=True, exist_ok=True)
        try:
            mounted = _run([ewfmount, str(image_path), str(ewf_dir)], 120).returncode == 0
        except subprocess.TimeoutExpired:
            mounted = False
        if mounted:
            raw_device = ewf_dir / "ewf1"
            if raw_device.exists() and _mount_raw(raw_device, mount_point):
                return True
            _unmount_path(ewf_dir)
        shutil.rmtree(ewf_dir, ignore_errors=True)
    return _guestmount(image_path, mount_point, 180)


def _validated_existing_path(value: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("helper paths must be absolute and may not be symlinks")
    resolved = path.resolve(strict=True)
    if directory and not resolved.is_dir():
        raise ValueError("mount point must be an existing directory")
    if not directory and not resolved.is_file():
        raise ValueError("image must be an existing regular file")
    return resolved


def perform(action: str, path: str, mount_point: str | None = None) -> bool:
    """Perform one operation from the closed mount-helper protocol."""
    if action == "mount":
        image = _validated_existing_path(path, directory=False)
        if mount_point is None:
            raise ValueError("mount requires a mount point")
        target = _validated_existing_path(mount_point, directory=True)
        return (
            _mount_e01(image, target)
            if image.suffix.lower() == ".e01"
            else _mount_raw(image, target)
        )
    if action == "unmount":
        if mount_point is not None:
            raise ValueError("unmount accepts one path")
        target = _validated_existing_path(path, directory=True)
        main_ok = _unmount_path(target)
        ewf_dir = target / "_ewf"
        if ewf_dir.exists():
            _unmount_path(ewf_dir)
        return main_ok
    raise ValueError("unsupported mount-helper action")


def main(argv: list[str] | None = None) -> int:
    """Parse the closed protocol, emit one JSON result, and return status."""
    parser = argparse.ArgumentParser(prog="mulder-mount-helper")
    subparsers = parser.add_subparsers(dest="action", required=True)
    mount_parser = subparsers.add_parser("mount")
    mount_parser.add_argument("image")
    mount_parser.add_argument("mount_point")
    unmount_parser = subparsers.add_parser("unmount")
    unmount_parser.add_argument("mount_point")
    args = parser.parse_args(argv)
    try:
        if args.action == "mount":
            ok = perform("mount", args.image, args.mount_point)
        else:
            ok = perform("unmount", args.mount_point)
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "reason": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps({"ok": ok}, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
