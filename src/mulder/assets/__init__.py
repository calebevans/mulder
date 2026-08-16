"""Mulder-owned forensic assets: where they live and how ``mulder setup`` gets them.

Only the path resolver is re-exported here.  ``manifest``, ``fetch``,
``install`` and ``state`` are imported lazily from the CLI command bodies so
that ``mulder serve`` start-up cost is unchanged.
"""

from mulder.assets.paths import (
    ENV_ASSET_ROOT,
    asset_candidates,
    asset_display_path,
    asset_path,
    asset_roots,
    asset_search_summary,
    asset_write_root,
    bin_dir,
    register_cache_clear,
    reset_asset_caches,
    user_root,
)

__all__ = [
    "ENV_ASSET_ROOT",
    "asset_candidates",
    "asset_display_path",
    "asset_path",
    "asset_roots",
    "asset_search_summary",
    "asset_write_root",
    "bin_dir",
    "register_cache_clear",
    "reset_asset_caches",
    "user_root",
]
