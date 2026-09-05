"""Broker for the narrowly scoped privileged image-mount helper process."""

from __future__ import annotations

import json
import re
import secrets
import sys
from pathlib import Path
from typing import Protocol

from mulder.execution.mount_protocol import (
    canonical_mount_path,
    mount_request_digest,
    mount_request_payload,
    mount_response_payload,
)
from mulder.execution.policy import (
    CommandPolicy,
    CommandRequest,
    NetworkClass,
    PathAccess,
    PathArgument,
)
from mulder.execution.runner import (
    CommandRunner,
    ExecutionStatus,
    UnshareNetworkIsolationBackend,
)

_MOUNT_ESCAPE_RE = re.compile(r"\\([0-7]{3})")
_REQUIRED_MOUNT_FLAGS = frozenset({"ro", "nodev", "nosuid", "noexec"})
_MOUNT_NETWORK_ISOLATION = UnshareNetworkIsolationBackend()


def _decode_mountinfo(value: str) -> str:
    return _MOUNT_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _mount_entries() -> list[dict[str, object]]:
    """Read the current process mount namespace into minimal typed entries."""
    entries: list[dict[str, object]] = []
    lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    for line in lines:
        before, separator, after = line.partition(" - ")
        left = before.split()
        right = after.split()
        if not separator or len(left) < 6 or len(right) < 3:
            continue
        entries.append(
            {
                "major_minor": left[2],
                "mount_point": _decode_mountinfo(left[4]),
                "flags": frozenset(left[5].split(",")) | frozenset(right[2].split(",")),
                "source": _decode_mountinfo(right[1]),
            }
        )
    return entries


def _loop_backing_path(major_minor: str) -> Path | None:
    path = Path("/sys/dev/block") / major_minor / "loop" / "backing_file"
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not value:
        return None
    candidate = Path(value if value.startswith("/") else f"/{value}")
    try:
        return candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _verified_mount_state(image_path: Path, mount_point: Path) -> bool:
    """Verify exact target, immutable flags, and a traceable backing image."""
    try:
        entries = _mount_entries()
    except OSError:
        return False
    target = str(mount_point)
    entry = next((item for item in entries if item["mount_point"] == target), None)
    if entry is None or not _REQUIRED_MOUNT_FLAGS.issubset(entry["flags"]):  # type: ignore[arg-type]
        return False
    source = Path(str(entry["source"]))
    try:
        if source.is_absolute() and source.resolve(strict=True) == image_path:
            return True
    except (OSError, RuntimeError):
        pass
    backing = _loop_backing_path(str(entry["major_minor"]))
    if backing == image_path:
        return True
    if image_path.suffix.lower() == ".e01" and backing is not None:
        ewf_root = mount_point / "_ewf"
        try:
            backing.relative_to(ewf_root)
        except ValueError:
            return False
        return any(item["mount_point"] == str(ewf_root) for item in entries)
    return False


def _verified_unmounted(mount_point: Path) -> bool:
    target = str(mount_point)
    ewf_target = str(mount_point / "_ewf")
    try:
        entries = _mount_entries()
    except OSError:
        return False
    return all(entry["mount_point"] not in {target, ewf_target} for entry in entries)


class MountBroker(Protocol):
    """Minimal mount authority used by the extraction cache."""

    def mount_read_only(self, image_path: Path, mount_point: Path) -> bool:
        """Mount one image at one existing directory, read-only."""
        ...

    def unmount(self, mount_point: Path) -> bool:
        """Unmount one existing mount directory."""
        ...


class MountRollbackError(RuntimeError):
    """A failed or unverifiable mount could not be proven unmounted."""


class SubprocessMountBroker:
    """Invoke the fixed helper module through the central command-policy seam."""

    @classmethod
    def _invoke(cls, action: str, paths: tuple[PathArgument, ...]) -> bool:
        if action == "mount" and len(paths) == 2:
            image = canonical_mount_path(paths[0].path, directory=False)
            mount_point = canonical_mount_path(paths[1].path, directory=True)
        elif action == "unmount" and len(paths) == 1:
            image = None
            mount_point = canonical_mount_path(paths[0].path, directory=True)
        else:
            return False
        if action == "mount" and not _verified_unmounted(mount_point):
            return False
        nonce = secrets.token_hex(32)
        request_payload = mount_request_payload(
            action,  # type: ignore[arg-type]
            nonce,
            mount_point,
            image,
        )
        request_digest = mount_request_digest(request_payload)
        roots = tuple(dict.fromkeys(argument.path.parent.resolve() for argument in paths))
        policy = CommandPolicy.for_executable(
            sys.executable,
            allowed_roots=roots,
            max_timeout_seconds=240,
            max_output_bytes=4096,
        )
        request = CommandRequest(
            executable=sys.executable,
            arguments=(
                "-I",
                "-m",
                "mulder.execution.mount_helper",
                action,
                "--nonce",
                nonce,
                "--request-digest",
                request_digest,
                *paths,
            ),
            timeout_seconds=240,
            max_output_bytes=4096,
            network_class=NetworkClass.NONE,
        )

        def reject_unverified_result() -> bool:
            if action != "mount" or _verified_unmounted(mount_point):
                return False
            rolled_back = cls._invoke(
                "unmount",
                (PathArgument(mount_point, PathAccess.WRITE),),
            )
            if not rolled_back or not _verified_unmounted(mount_point):
                raise MountRollbackError(
                    f"unverified mount could not be rolled back: {mount_point}"
                )
            return False

        result = CommandRunner(
            policy,
            network_isolation=_MOUNT_NETWORK_ISOLATION,
        ).run(request)
        if result.status is not ExecutionStatus.COMPLETED or result.returncode != 0:
            return reject_unverified_result()
        try:
            payload = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return reject_unverified_result()
        expected_response = mount_response_payload(
            request_payload,
            request_digest,
            ok=True,
        )
        if payload != expected_response:
            return reject_unverified_result()
        if action == "mount":
            if image is not None and _verified_mount_state(image, mount_point):
                return True
            return reject_unverified_result()
        return _verified_unmounted(mount_point)

    def mount_read_only(self, image_path: Path, mount_point: Path) -> bool:
        """Ask the helper to mount the image without accepting arbitrary argv."""
        return self._invoke(
            "mount",
            (
                PathArgument(image_path, PathAccess.READ),
                PathArgument(mount_point, PathAccess.WRITE),
            ),
        )

    def unmount(self, mount_point: Path) -> bool:
        """Ask the helper to unmount the fixed target path."""
        return self._invoke("unmount", (PathArgument(mount_point, PathAccess.WRITE),))
