"""Volatility 3 utility functions shared by MCP tools.

Provides ``_find_vol_binary`` (locates the vol CLI) and
``_plugin_short_name`` (extracts the human-friendly plugin name from a
fully-qualified Volatility 3 plugin class path).
"""

from __future__ import annotations

import shutil
import subprocess


def _find_vol_binary() -> list[str]:
    """Locate the Volatility 3 CLI binary.

    Tries in order: ``vol``, ``vol3``, ``python3 -m volatility3``.
    Returns the command list to use with :func:`subprocess.run`.
    Raises :class:`RuntimeError` if none are found.
    """
    for name in ("vol", "vol3"):
        if shutil.which(name):
            return [name]

    try:
        subprocess.run(
            ["python3", "-m", "volatility3", "--help"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        return ["python3", "-m", "volatility3"]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

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
