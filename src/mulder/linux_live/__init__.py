"""Sealed, typed Linux live-state acquisition.

The public surface is intentionally small: create an explicit scope, collect a
bounded set of built-in checks, or verify an existing bundle entirely offline.
No command, SSH, network, or model interface exists in this package.
"""

from mulder.linux_live.collector import (
    ALL_LINUX_CHECKS,
    LINUX_LIVE_COLLECTOR_VERSION,
    BundleVerification,
    CollectionResult,
    LinuxCheck,
    LinuxCollectionRequest,
    LinuxCollectionScope,
    LinuxLiveCollectionError,
    collect_linux_live_state,
    verify_linux_live_bundle,
)
from mulder.linux_live.pack import (
    linux_live_pack_descriptor,
    linux_live_pack_fixture_root,
)

__all__ = [
    "ALL_LINUX_CHECKS",
    "LINUX_LIVE_COLLECTOR_VERSION",
    "BundleVerification",
    "CollectionResult",
    "LinuxCheck",
    "LinuxCollectionRequest",
    "LinuxCollectionScope",
    "LinuxLiveCollectionError",
    "collect_linux_live_state",
    "linux_live_pack_descriptor",
    "linux_live_pack_fixture_root",
    "verify_linux_live_bundle",
]
