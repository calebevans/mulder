"""Volatility 3 memory dump extractor.

Runs a curated set of Volatility 3 plugins against a memory dump via
subprocess, captures each plugin's tab-separated text output as a separate
logical source, and returns them for windowing and embedding.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from mulder.extractors.base import ExtractionResult

logger = logging.getLogger(__name__)

_MEMORY_DUMP_EXTS = frozenset({".mem", ".raw", ".vmem", ".dmp"})
_MEMORY_DUMP_MIN_BYTES = 100 * 1024 * 1024  # 100 MB

_PLUGIN_TIMEOUT_SECONDS = 300
_MAX_WORKERS = 4


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


class VolatilityExtractor:
    """Runs Volatility 3 plugins against a memory dump."""

    name: str = "volatility"

    PLUGINS: list[str] = [
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.cmdline.CmdLine",
        "windows.netscan.NetScan",
        "windows.malfind.Malfind",
        "windows.dlllist.DllList",
        "windows.svcscan.SvcScan",
        "windows.handles.Handles",
    ]

    def __init__(self) -> None:
        self._vol_cmd: list[str] | None = None
        self._cached_version: str | None = None

    def _vol_command(self) -> list[str]:
        if self._vol_cmd is None:
            self._vol_cmd = _find_vol_binary()
        return self._vol_cmd

    def can_handle(self, path: Path) -> bool:
        """Return True for memory dump files (.mem, .raw, .vmem, .dmp) or large binaries."""
        if path.suffix.lower() in _MEMORY_DUMP_EXTS:
            return True
        try:
            return path.is_file() and path.stat().st_size > _MEMORY_DUMP_MIN_BYTES
        except OSError:
            return False

    def extract(self, path: Path, case_id: str) -> list[ExtractionResult]:
        """Run all plugins against *path* and return one result per successful plugin."""
        vol_cmd = self._vol_command()
        results: list[ExtractionResult] = []

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {
                pool.submit(self._run_plugin, vol_cmd, path, plugin): plugin
                for plugin in self.PLUGINS
            }
            for future in as_completed(futures):
                plugin = futures[future]
                try:
                    result = future.result()
                except Exception:
                    logger.exception("Unexpected error running plugin %s", plugin)
                    continue
                if result is not None:
                    results.append(result)

        results.sort(key=lambda r: r.source_name)
        return results

    def version(self) -> str:
        """Return the Volatility 3 version string (cached after first call)."""
        if self._cached_version is not None:
            return self._cached_version

        vol_cmd = self._vol_command()
        try:
            proc = subprocess.run(
                [*vol_cmd, "--help"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            first_line = (proc.stdout or proc.stderr or "").split("\n", 1)[0]
            self._cached_version = first_line.strip() or "volatility3 (unknown version)"
        except (subprocess.TimeoutExpired, OSError):
            self._cached_version = "volatility3 (unknown version)"
        return self._cached_version

    @staticmethod
    def _run_plugin(vol_cmd: list[str], dump_path: Path, plugin: str) -> ExtractionResult | None:
        short = _plugin_short_name(plugin)
        cmd = [*vol_cmd, "-f", str(dump_path), plugin]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_PLUGIN_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.error(
                "Plugin %s timed out after %ds on %s",
                plugin,
                _PLUGIN_TIMEOUT_SECONDS,
                dump_path,
            )
            return None

        if proc.returncode != 0:
            stderr_preview = (proc.stderr or "")[:500]
            logger.warning(
                "Plugin %s exited %d on %s: %s",
                plugin,
                proc.returncode,
                dump_path,
                stderr_preview,
            )
            return None

        output = proc.stdout.strip()
        if not output:
            logger.debug("Plugin %s produced no output for %s", plugin, dump_path)
            return None

        return ExtractionResult(
            source_name=f"volatility.{short}",
            source_path=str(dump_path),
            extractor="volatility3",
            text_output=output,
            line_count=output.count("\n") + 1,
        )
