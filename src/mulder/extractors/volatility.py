"""Volatility 3 utility functions shared by MCP tools.

Provides ``_find_vol_binary`` (locates the vol CLI) and
``_plugin_short_name`` (extracts the human-friendly plugin name from a
fully-qualified Volatility 3 plugin class path).
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path


def _find_vol_binary() -> list[str]:
    """Locate the Volatility 3 CLI.

    volatility3 ships no ``__main__``: ``python -m volatility3`` does not work.
    Its CLI exists only as the ``vol`` console script.

    Resolution order, and why:

    1. ``vol`` / ``vol3`` on PATH.  A platform Volatility (SIFT's
       ``/usr/local/bin/vol``, the container's) **must** win.  mulder never
       passes ``-s``, so volatility3 resolves ISF symbol tables relative to its
       own package directory; a platform install is the one with the platform's
       Windows/Linux symbol packs installed against it.  Preferring a
       venv-local copy would silently orphan those packs and degrade Windows
       memory analysis to the "ISF symbols are missing" path.
    2. The ``vol`` script sitting next to ``sys.executable``.  ``volatility3``
       is a hard mulder dependency, so under ``pipx install`` / ``uv tool
       install`` this always exists, but it is not linked onto PATH — it is the
       last-resort fallback that makes a native install work at all.
    3. An in-process entry point call, if the console script is somehow missing
       but the library imports.

    Returns the command list to use with :func:`subprocess.run`.
    Raises :class:`RuntimeError` if none are found.
    """
    for name in ("vol", "vol3"):
        if shutil.which(name):
            return [name]

    vol_local = Path(sys.executable).with_name("vol")
    if os.access(vol_local, os.X_OK):
        return [str(vol_local)]

    if importlib.util.find_spec("volatility3") is not None:
        return [sys.executable, "-c", "from volatility3.cli import main; main()"]

    raise RuntimeError(
        "Volatility 3 is not installed or not on $PATH. "
        "Install it (pip install volatility3) or ensure 'vol' / 'vol3' is available."
    )


def _plugin_short_name(full_name: str) -> str:
    """Extract the short plugin name from a fully-qualified class path.

    ``"windows.pslist.PsList"`` -> ``"pslist"``
    """
    parts = full_name.split(".")
    return parts[-2] if len(parts) >= 2 else parts[-1].lower()
