"""Canonical request commitments for the privileged mount helper."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Literal

_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _is_descriptor_path(path: Path) -> bool:
    parts = path.parts
    return len(parts) == 5 and parts[:4] == ("/", "proc", "self", "fd") and parts[4].isdigit()


def canonical_mount_path(
    value: str | Path,
    *,
    directory: bool,
    descriptor_only: bool = False,
) -> Path:
    """Resolve an original or runner-held descriptor path with strict typing."""
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("helper paths must be absolute")
    if descriptor_only and not _is_descriptor_path(path):
        raise ValueError("helper accepts only exact /proc/self/fd descriptors")
    if path.is_symlink() and not _is_descriptor_path(path):
        raise ValueError("helper paths may not be caller-controlled symlinks")
    resolved = path.resolve(strict=True)
    value_stat = resolved.stat()
    if directory and not stat.S_ISDIR(value_stat.st_mode):
        raise ValueError("mount point must be an existing directory")
    if not directory and not stat.S_ISREG(value_stat.st_mode):
        raise ValueError("image must be an existing regular file")
    return resolved


def path_commitment(path: Path) -> dict[str, int | str]:
    """Return the canonical identity fields shared by parent and helper."""
    value = path.stat()
    return {
        "path": str(path),
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": value.st_mode,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def mount_request_payload(
    action: Literal["mount", "unmount"],
    nonce: str,
    mount_point: Path,
    image_path: Path | None = None,
) -> dict[str, object]:
    """Build the exact canonical operation committed by the protocol."""
    if not _NONCE_RE.fullmatch(nonce):
        raise ValueError("mount request nonce is malformed")
    if action == "mount" and image_path is None:
        raise ValueError("mount request requires an image")
    if action == "unmount" and image_path is not None:
        raise ValueError("unmount request cannot include an image")
    return {
        "schema": "mulder.mount-request:v1",
        "action": action,
        "nonce": nonce,
        "image": path_commitment(image_path) if image_path is not None else None,
        "mount_point": path_commitment(mount_point),
    }


def mount_request_digest(payload: dict[str, object]) -> str:
    """Digest one canonical request without accepting alternate encodings."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_mount_request_digest(value: str) -> None:
    """Reject malformed request commitments before attempting an operation."""
    if not _DIGEST_RE.fullmatch(value):
        raise ValueError("mount request digest is malformed")


def mount_response_payload(
    request: dict[str, object],
    request_digest: str,
    *,
    ok: bool,
) -> dict[str, object]:
    """Return a response bound to the complete canonical request."""
    validate_mount_request_digest(request_digest)
    return {
        "schema": "mulder.mount-response:v1",
        "ok": ok,
        "request": request,
        "request_digest": request_digest,
    }
