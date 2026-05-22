"""Windows Registry parsing MCP tools."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

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
            config_dir = None
            for candidate in (
                Path(mount_point) / "Windows" / "System32" / "config",
                Path(mount_point) / "windows" / "system32" / "config",
            ):
                if candidate.is_dir():
                    config_dir = candidate
                    break

            if config_dir is None:
                return error_response(
                    tc_id, "run_registry_parser", params, "Registry config directory not found"
                )

            hives_to_parse: list[tuple[str, Path]] = []
            for item in config_dir.iterdir():
                name_lower = item.name.lower()
                if hive and name_lower != hive.lower():
                    continue
                if name_lower in _HIVE_NAMES and item.is_file():
                    hives_to_parse.append((name_lower, item))

            if not hives_to_parse:
                return error_response(
                    tc_id, "run_registry_parser", params, "No registry hives found to parse"
                )

            results: list[object] = []
            for hive_name, hive_path in hives_to_parse:
                source_name = f"registry.{hive_name}"
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
                                combined += csv_file.read_text(
                                    encoding="utf-8", errors="replace"
                                )
                            if combined:
                                results.append(
                                    extract_and_index(
                                        combined, source_name, image_path, "eztools"
                                    )
                                )
                                continue
                            stderr_hint = (proc.stderr or "")[:_HINT_CHAR_LIMIT].strip()
                            hive_status = (
                                f"recmd_empty_output ({stderr_hint})"
                                if stderr_hint
                                else "recmd_empty_output"
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
                            results.append(
                                extract_and_index(
                                    proc.stdout.strip(), source_name, image_path, "regripper"
                                )
                            )
                            continue
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

                results.append({"source_name": source_name, "status": hive_status})

            total_windows = sum(
                r.get("windows_indexed", 0) for r in results if isinstance(r, dict)
            )
            for r in results:
                if isinstance(r, dict):
                    r.pop("source_id", None)

            elapsed = (time.monotonic() - t0) * 1000
            return tool_response(
                tc_id,
                "run_registry_parser",
                params,
                {
                    "hives_parsed": len(results),
                    "total_windows_indexed": total_windows,
                    "per_hive": results,
                },
                "registry",
                elapsed,
            )
    except RuntimeError:
        pass

    extracted = _tsk_extract_files(
        image_path,
        ["config/SYSTEM", "config/SOFTWARE", "config/SAM", "config/SECURITY", "config/DEFAULT"],
    )
    hives_to_parse_fb: list[tuple[str, Path]] = []
    for _rel, fpath in extracted:
        name_lower = fpath.name.lower()
        if name_lower not in _HIVE_NAMES:
            for h in _HIVE_NAMES:
                if h in fpath.name.lower():
                    name_lower = h
                    break
            else:
                continue
        if hive and name_lower != hive.lower():
            continue
        hives_to_parse_fb.append((name_lower, fpath))

    if not hives_to_parse_fb:
        return error_response(
            tc_id,
            "run_registry_parser",
            params,
            "Mount failed and no registry hives found via TSK extraction",
            (time.monotonic() - t0) * 1000,
        )

    results_fb: list[object] = []
    for hive_name, hive_path in hives_to_parse_fb:
        source_name = f"registry.{hive_name}"
        fb_status: str | None = None

        dll = _find_ez_tool("RECmd.dll")
        if dll and _require_binary(_DOTNET):
            with tempfile.TemporaryDirectory(prefix="mulder_reg_") as tmpdir:
                cmd = [_DOTNET, dll, "-f", str(hive_path), "--csv", tmpdir]
                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=_TOOL_TIMEOUT, check=False
                    )
                except subprocess.TimeoutExpired:
                    fb_status = "recmd_timeout"
                else:
                    combined = ""
                    for csv_file in sorted(Path(tmpdir).glob("*.csv")):
                        combined += csv_file.read_text(encoding="utf-8", errors="replace")
                    if combined:
                        results_fb.append(
                            extract_and_index(combined, source_name, image_path, "eztools")
                        )
                        continue
                    stderr_hint = (proc.stderr or "")[:_HINT_CHAR_LIMIT].strip()
                    fb_status = (
                        f"recmd_empty_output ({stderr_hint})"
                        if stderr_hint
                        else "recmd_empty_output"
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
                    results_fb.append(
                        extract_and_index(
                            proc.stdout.strip(), source_name, image_path, "regripper"
                        )
                    )
                    continue
                stderr_hint = (proc.stderr or "")[:_HINT_CHAR_LIMIT].strip()
                fb_status = (
                    f"regripper_empty_output ({stderr_hint})"
                    if stderr_hint
                    else "regripper_empty_output"
                )
            except subprocess.TimeoutExpired:
                fb_status = "regripper_timeout"
            except OSError as exc:
                fb_status = f"regripper_error ({exc})"
        elif fb_status is None:
            has_recmd = bool(dll and _require_binary(_DOTNET))
            fb_status = (
                "no_parser_installed (neither RECmd nor RegRipper found on PATH)"
                if not has_recmd
                else "no_regripper_fallback (RECmd failed, RegRipper not on PATH)"
            )

        results_fb.append({"source_name": source_name, "status": fb_status})

    total_windows_fb = sum(
        r.get("windows_indexed", 0) for r in results_fb if isinstance(r, dict)
    )
    for r in results_fb:
        if isinstance(r, dict):
            r.pop("source_id", None)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_registry_parser",
        params,
        {
            "hives_parsed": len(results_fb),
            "total_windows_indexed": total_windows_fb,
            "per_hive": results_fb,
        },
        "registry",
        elapsed,
    )
