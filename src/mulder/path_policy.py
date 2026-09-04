"""Resolved filesystem path-containment policy.

The interface deliberately returns the authorized, resolved path.  Callers must
use that path for the subsequent filesystem operation so a symlink is not
authorized by its destination and then accessed again through its original
name.

Resolution falls back to non-strict mode only when a path does not exist, which
preserves support for probing missing paths without treating other resolution
errors as safe.  A missing path is allowed only when its prospective resolved
location is inside an allowed root.  Existing symlinks (including an existing
prefix of a non-existent path) are followed, so a symlink whose destination
escapes every allowed root is denied.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


class PathPolicyError(ValueError):
    """Raised when a path cannot be safely resolved inside an allowed root."""


def _resolve(path: Path) -> Path:
    """Resolve *path*, permitting absence but rejecting other resolution errors."""
    try:
        return path.resolve(strict=True)
    except FileNotFoundError:
        return path.resolve(strict=False)


def resolve_allowed_path(target: Path, allowed_roots: Iterable[Path]) -> Path:
    """Return *target* resolved inside one of *allowed_roots*.

    Resolution makes containment path-component aware, collapses ``..``,
    follows existing symlinks, and retains the previous behavior for
    non-existent paths.  Symlink loops and other resolution failures are
    denied.

    Raises:
        PathPolicyError: If resolution fails or the target is outside every
            allowed root.
    """
    try:
        resolved_target = _resolve(target)
    except (OSError, RuntimeError) as exc:
        raise PathPolicyError(f"Cannot resolve path: {target}") from exc

    resolved_roots: list[Path] = []
    for root in allowed_roots:
        try:
            resolved_roots.append(_resolve(root))
        except (OSError, RuntimeError) as exc:
            raise PathPolicyError(f"Cannot resolve allowed root: {root}") from exc

    if any(resolved_target.is_relative_to(root) for root in resolved_roots):
        return resolved_target

    raise PathPolicyError("Access denied: path is outside allowed directories")
