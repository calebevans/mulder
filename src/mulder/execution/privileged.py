"""Broker for the narrowly scoped privileged image-mount helper process."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Protocol

from mulder.execution.policy import (
    CommandPolicy,
    CommandRequest,
    NetworkClass,
    PathAccess,
    PathArgument,
)
from mulder.execution.runner import CommandRunner, ExecutionStatus


class MountBroker(Protocol):
    """Minimal mount authority used by the extraction cache."""

    def mount_read_only(self, image_path: Path, mount_point: Path) -> bool:
        """Mount one image at one existing directory, read-only."""
        ...

    def unmount(self, mount_point: Path) -> bool:
        """Unmount one existing mount directory."""
        ...


class SubprocessMountBroker:
    """Invoke the fixed helper module through the central command-policy seam."""

    @staticmethod
    def _invoke(action: str, paths: tuple[PathArgument, ...]) -> bool:
        roots = tuple(dict.fromkeys(argument.path.parent.resolve() for argument in paths))
        policy = CommandPolicy.for_executable(
            sys.executable,
            allowed_roots=roots,
            max_timeout_seconds=240,
            max_output_bytes=4096,
        )
        request = CommandRequest(
            executable=sys.executable,
            arguments=("-I", "-m", "mulder.execution.mount_helper", action, *paths),
            timeout_seconds=240,
            max_output_bytes=4096,
            network_class=NetworkClass.NONE,
        )
        result = CommandRunner(policy).run(request)
        if result.status is not ExecutionStatus.COMPLETED or result.returncode != 0:
            return False
        try:
            payload = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        return isinstance(payload, dict) and payload.get("ok") is True and len(payload) == 1

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
