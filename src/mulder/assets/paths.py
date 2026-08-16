"""Resolution of every mulder-owned asset path.

Historically each MCP tool module carried its own ``/opt/...`` literal, which
made a native install impossible without root.  Every one of those constants now
routes through this module, which separates two questions that used to be one:

* **where may mulder read from** -- ``/opt`` first, so an existing SIFT or
  container layout keeps winning, then mulder's own per-user directory;
* **where may ``mulder setup`` write** -- ``/opt`` only when it is genuinely
  writable (i.e. under ``sudo``), otherwise the per-user directory.

They differ inside the container, where ``/opt`` is ``root:root 0755`` and the
server runs as ``mulder``: a single writability-tested resolver would fall
through to ``$HOME`` there and break every lookup.

This module is imported by MCP tool modules that load on *every* server start,
so it deliberately imports nothing beyond ``functools``/``os``/``pathlib``.
``tests/test_import_weight.py`` enforces that.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Callable, Iterator
from pathlib import Path

ENV_ASSET_ROOT = "MULDER_ASSET_ROOT"
ENV_BIN_DIR = "MULDER_BIN_DIR"
SYSTEM_ROOT = Path("/opt")
SYSTEM_BIN = Path("/usr/local/bin")

_cache_clearers: list[Callable[[], None]] = []


def register_cache_clear(fn: Callable[[], None]) -> None:
    """Register a memoized lookup so ``reset_asset_caches`` can flush it.

    Consumers call this at import time with e.g. ``_find_ez_tool.cache_clear``;
    this module never imports them, so there is no cycle.
    """
    _cache_clearers.append(fn)


def user_root() -> Path:
    """The per-user asset root.

    ``XDG_DATA_HOME`` is deliberately *not* honoured here: the path is a fixed
    contract shared with the docs and with ``mulder setup``'s output.  The
    Volatility symbol cache is the opposite case -- see
    ``mulder.assets.manifest.volatility_symbol_dir``.
    """
    return Path.home() / ".local" / "share" / "mulder" / "assets"


@functools.lru_cache(maxsize=8)
def _roots(env: str | None, home: str) -> tuple[Path, ...]:
    if env:
        return (Path(env).expanduser(),)
    roots: list[Path] = []
    if SYSTEM_ROOT.is_dir():
        roots.append(SYSTEM_ROOT)
    roots.append(Path(home) / ".local" / "share" / "mulder" / "assets")
    return tuple(roots)


def asset_roots() -> tuple[Path, ...]:
    """Ordered read roots.

    Keyed on the environment variable and ``$HOME`` so a change in either takes
    effect without an explicit cache flush; only the ``/opt`` stat is memoized.

    ``MULDER_ASSET_ROOT`` is *exclusive* rather than prepended, so that the test
    suite can be hermetic and the container can pin an exact root that a
    bind-mounted ``$HOME`` cannot shadow.
    """
    return _roots(os.environ.get(ENV_ASSET_ROOT) or None, str(Path.home()))


def asset_candidates(*parts: str) -> Iterator[Path]:
    """Yield ``<root>/<parts...>`` for every read root, in order."""
    for root in asset_roots():
        yield root.joinpath(*parts)


def asset_path(*parts: str) -> Path | None:
    """First existing candidate, else None."""
    for candidate in asset_candidates(*parts):
        if candidate.exists():
            return candidate
    return None


def asset_display_path(*parts: str) -> Path:
    """First existing candidate, else the path ``mulder setup`` *would* write.

    The fallback is deliberately the write root, not ``asset_roots()[0]``.
    ``/opt`` is a directory on essentially every Linux host, so the first read
    root is ``/opt`` even when ``setup`` will provision
    ``~/.local/share/mulder/assets`` -- and every "not found at ..." message and
    every copy-pasteable ``pipx inject --requirements ...`` suggestion built
    from it would then name a path that is never going to exist.
    """
    return asset_path(*parts) or asset_write_root().joinpath(*parts)


def asset_search_summary(*parts: str) -> str:
    """Human-readable list of every place a lookup looked, in order.

    For "not found under any of: a, b" errors, where naming one path is
    misleading because two were searched.
    """
    return ", ".join(str(p) for p in asset_candidates(*parts))


def asset_write_root() -> Path:
    """Where ``mulder setup`` provisions assets.

    ``MULDER_ASSET_ROOT`` wins even when it is unwritable, so ``setup`` fails
    loudly rather than silently writing somewhere the reader will not look.
    """
    env = os.environ.get(ENV_ASSET_ROOT)
    if env:
        return Path(env).expanduser()
    if SYSTEM_ROOT.is_dir() and os.access(SYSTEM_ROOT, os.W_OK | os.X_OK):
        return SYSTEM_ROOT
    return user_root()


def bin_dir() -> Path:
    """Where ``mulder setup`` drops PATH shims.

    ``capa``, ``floss`` and ``diec`` are resolved through ``shutil.which``
    first, falling back to a ``/usr/local/bin`` literal
    (``server/tools/binary.py``).  An asset-root drop with no shim is therefore
    invisible anywhere but the container -- this directory has to be on
    ``$PATH``.

    ``/usr/local/bin`` comes last because it is writable only when running as
    root, which this whole feature exists to avoid; ``~/.local/bin`` is on
    ``$PATH`` by default on every modern distro and needs no privilege.
    """
    env = os.environ.get(ENV_BIN_DIR) or os.environ.get("PIPX_BIN_DIR")
    if env:
        return Path(env).expanduser()
    local = Path.home() / ".local" / "bin"
    if local.is_dir() or not os.access(SYSTEM_BIN, os.W_OK | os.X_OK):
        return local
    return SYSTEM_BIN


def reset_asset_caches() -> None:
    """Flush this module's memoization and every registered consumer cache.

    Called by ``mulder setup`` after provisioning (so an in-process server picks
    up new assets) and by the test fixtures that move the root.
    """
    _roots.cache_clear()
    for fn in _cache_clearers:
        fn()
