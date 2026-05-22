"""Windows Registry parsing MCP tools."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index, mount_disk_image
from mulder.server.helpers import (
    _HINT_CHAR_LIMIT,
    error_response,
    make_tool_call_id,
    tool_response,
)
from mulder.server.tools_extract_misc import _DOTNET, _find_ez_tool
from mulder.server.tools_extract_tsk import _tsk_extract_files

__all__ = [
    "run_registry_parser",
]

logger = logging.getLogger(__name__)

_TOOL_TIMEOUT = 600

_HIVE_NAMES = {"system", "software", "sam", "security", "default"}


def _require_binary(name: str) -> str | None:
    """Return the binary path if found, else None."""
    return shutil.which(name)


def _discover_hives_from_mount(mount_path: Path) -> list[tuple[Path, str]]:
    """Walk a mounted filesystem to find registry hive files.

    Searches standard Windows registry config directory locations and
    returns all recognized hive files found.

    Args:
        mount_path: Root path of the mounted disk image.

    Returns:
        List of (hive_file_path, hive_name_lowercase) tuples for each
        discovered hive.

    Raises:
        FileNotFoundError: If the Windows registry config directory cannot
            be located within the mount.
    """
    config_dir = None
    for candidate in (
        mount_path / "Windows" / "System32" / "config",
        mount_path / "windows" / "system32" / "config",
    ):
        if candidate.is_dir():
            config_dir = candidate
            break

    if config_dir is None:
        raise FileNotFoundError("Registry config directory not found")

    hives: list[tuple[Path, str]] = []
    for item in config_dir.iterdir():
        name_lower = item.name.lower()
        if name_lower in _HIVE_NAMES and item.is_file():
            hives.append((item, name_lower))

    return hives


def _discover_hives_via_tsk(image_path: str, offset: int | None = None) -> list[tuple[Path, str]]:
    """Extract registry hives from a disk image using The Sleuth Kit.

    Falls back to TSK file extraction when mount-based discovery is not
    possible. Extracts standard hive files and maps them to canonical names.

    Args:
        image_path: Path to the disk image file.
        offset: Partition offset in bytes (reserved for future use).

    Returns:
        List of (extracted_hive_path, hive_name_lowercase) tuples.
    """
    _ = offset
    extracted = _tsk_extract_files(
        image_path,
        ["config/SYSTEM", "config/SOFTWARE", "config/SAM", "config/SECURITY", "config/DEFAULT"],
    )

    hives: list[tuple[Path, str]] = []
    for _rel, fpath in extracted:
        name_lower = fpath.name.lower()
        if name_lower not in _HIVE_NAMES:
            for h in _HIVE_NAMES:
                if h in fpath.name.lower():
                    name_lower = h
                    break
            else:
                continue
        hives.append((fpath, name_lower))

    return hives


def _parse_single_hive(
    hive_path: Path,
    source_name: str,
    image_path: str,
) -> dict[str, Any]:
    """Parse a single registry hive using available tools.

    Attempts parsing in order of preference: RECmd (EZ Tools), then
    RegRipper. Returns either indexed extraction results on success or
    a status dict describing the failure.

    Args:
        hive_path: Path to the registry hive file.
        source_name: Logical source identifier (e.g. "registry.system").
        image_path: Original disk image path (for indexing metadata).

    Returns:
        Dict containing either indexed extraction results (on success) or
        a status dict with ``source_name`` and ``status`` keys on failure.
    """
    hive_status: str | None = None

    dll = _find_ez_tool("RECmd.dll")
    if dll and _require_binary(_DOTNET):
        with tempfile.TemporaryDirectory(prefix="mulder_reg_") as tmpdir:
            cmd = [_DOTNET, dll, "-f", str(hive_path), "--csv", tmpdir]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=_TOOL_TIMEOUT,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                hive_status = "recmd_timeout"
            else:
                combined = ""
                for csv_file in sorted(Path(tmpdir).glob("*.csv")):
                    combined += csv_file.read_text(encoding="utf-8", errors="replace")
                if combined:
                    return extract_and_index(combined, source_name, image_path, "eztools")
                stderr_hint = (proc.stderr or "")[:_HINT_CHAR_LIMIT].strip()
                hive_status = (
                    f"recmd_empty_output ({stderr_hint})" if stderr_hint else "recmd_empty_output"
                )

    rip = _require_binary("rip.pl") or _require_binary("regripper")
    if rip:
        try:
            proc = subprocess.run(
                [rip, "-r", str(hive_path), "-a"],
                capture_output=True,
                text=True,
                timeout=_TOOL_TIMEOUT,
                check=False,
            )
            if proc.stdout.strip():
                return extract_and_index(proc.stdout.strip(), source_name, image_path, "regripper")
            stderr_hint = (proc.stderr or "")[:_HINT_CHAR_LIMIT].strip()
            hive_status = (
                f"regripper_empty_output ({stderr_hint})"
                if stderr_hint
                else "regripper_empty_output"
            )
        except subprocess.TimeoutExpired:
            hive_status = "regripper_timeout"
        except OSError as exc:
            hive_status = f"regripper_error ({exc})"
    elif hive_status is None:
        has_recmd = bool(dll and _require_binary(_DOTNET))
        hive_status = (
            "no_parser_installed (neither RECmd nor RegRipper found on PATH)"
            if not has_recmd
            else "no_regripper_fallback (RECmd failed, RegRipper not on PATH)"
        )

    return {"source_name": source_name, "status": hive_status}


def _summarize_hive_results(statuses: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-hive parsing results into a batch summary.

    Computes totals, strips internal IDs, and produces the final response
    payload for the registry parser tool.

    Args:
        statuses: List of per-hive result dicts from ``_parse_single_hive``.

    Returns:
        Summary dict with ``hives_parsed``, ``total_windows_indexed``,
        and ``per_hive`` keys.
    """
    total_windows = sum(r.get("windows_indexed", 0) for r in statuses if isinstance(r, dict))
    for r in statuses:
        if isinstance(r, dict):
            r.pop("source_id", None)

    return {
        "hives_parsed": len(statuses),
        "total_windows_indexed": total_windows,
        "per_hive": statuses,
    }


@mcp.tool()
def run_registry_parser(image_path: str, hive: str | None = None) -> dict[str, object]:
    """Parse Windows registry hives from a disk image.

    Uses RECmd (EZ Tools) when available, falls back to RegRipper.
    Parses all standard hives (SYSTEM, SOFTWARE, SAM, SECURITY,
    NTUSER.DAT) unless a specific hive is requested.

    Args:
        image_path: Path to the disk image.
        hive: Optional specific hive to parse (e.g. "SYSTEM", "SOFTWARE").
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "hive": hive}

    try:
        with mount_disk_image(image_path) as mount_point:
            try:
                discovered = _discover_hives_from_mount(Path(mount_point))
            except FileNotFoundError:
                return error_response(
                    tc_id, "run_registry_parser", params, "Registry config directory not found"
                )

            if hive:
                discovered = [(p, n) for p, n in discovered if n == hive.lower()]

            if not discovered:
                return error_response(
                    tc_id, "run_registry_parser", params, "No registry hives found to parse"
                )

            results: list[dict[str, Any]] = []
            for hive_path, hive_name in discovered:
                source_name = f"registry.{hive_name}"
                results.append(_parse_single_hive(hive_path, source_name, image_path))

            elapsed = (time.monotonic() - t0) * 1000
            return tool_response(
                tc_id,
                "run_registry_parser",
                params,
                _summarize_hive_results(results),
                "registry",
                elapsed,
            )
    except RuntimeError:
        pass

    discovered_tsk = _discover_hives_via_tsk(image_path)
    if hive:
        discovered_tsk = [(p, n) for p, n in discovered_tsk if n == hive.lower()]

    if not discovered_tsk:
        return error_response(
            tc_id,
            "run_registry_parser",
            params,
            "Mount failed and no registry hives found via TSK extraction",
            (time.monotonic() - t0) * 1000,
        )

    results_fb: list[dict[str, Any]] = []
    for hive_path, hive_name in discovered_tsk:
        source_name = f"registry.{hive_name}"
        results_fb.append(_parse_single_hive(hive_path, source_name, image_path))

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_registry_parser",
        params,
        _summarize_hive_results(results_fb),
        "registry",
        elapsed,
    )
