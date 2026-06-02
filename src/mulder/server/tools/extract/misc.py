"""Miscellaneous extraction MCP tools: EZ Tools, utilities, and encrypted volumes."""

from __future__ import annotations

import atexit
import contextlib
import functools
import logging
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping
from pathlib import Path

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index, mount_disk_image
from mulder.server.helpers import (
    _PREVIEW_CHAR_LIMIT,
    TOOL_TIMEOUT,
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    require_binary,
    run_cli_tool,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import _cleanup_tsk_extract_dir, _tsk_extract_files

__all__ = [
    "_DOTNET",
    "_EZ_TOOLS_DIR",
    "_find_ez_tool",
    "_run_ez_tool",
    "run_amcache_parser",
    "run_bdeinfo",
    "run_chkrootkit",
    "run_clamav",
    "run_dislocker",
    "run_exiftool",
    "run_fvdeinfo",
    "run_hashdeep",
    "run_mft_parser",
    "run_pasco",
    "run_prefetch_parser",
    "run_radare2",
    "run_regripper",
    "run_shimcache_parser",
    "run_ssdeep",
    "run_strings",
    "run_tcpflow",
    "run_tcpxtract",
    "run_vshadow_info",
]

logger = logging.getLogger(__name__)

_dislocker_mounts: dict[str, str] = {}
_dislocker_lock = threading.Lock()


def _cleanup_dislocker_mounts() -> None:
    """Unmount and remove all registered dislocker FUSE mounts."""
    for mount_point in list(_dislocker_mounts.values()):
        try:
            subprocess.run(
                ["fusermount", "-u", mount_point],
                capture_output=True,
                timeout=10,
            )
            shutil.rmtree(mount_point, ignore_errors=True)
        except Exception:
            pass


atexit.register(_cleanup_dislocker_mounts)

_EZ_TOOLS_DIR = Path("/opt/zimmermantools")
_DOTNET = "dotnet"


@functools.lru_cache(maxsize=32)
def _find_ez_tool(dll_name: str) -> str | None:
    """Find an EZ tool DLL under /opt/zimmermantools (cached)."""
    candidates = list(_EZ_TOOLS_DIR.rglob(dll_name))
    return str(candidates[0]) if candidates else None


def _run_ez_tool(
    dll_name: str,
    args: list[str],
    source_name: str,
    source_path: str,
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    t0: float,
) -> dict[str, object]:
    """Run an EZ tool, parse CSV output, index it, and return response."""
    if not require_binary(_DOTNET):
        return error_response(
            tc_id, tool_name, params, "dotnet not found on PATH", (time.monotonic() - t0) * 1000
        )

    dll = _find_ez_tool(dll_name)
    if dll is None:
        return error_response(
            tc_id,
            tool_name,
            params,
            f"{dll_name} not found under {_EZ_TOOLS_DIR}",
            (time.monotonic() - t0) * 1000,
        )

    with tempfile.TemporaryDirectory(prefix="mulder_ez_") as tmpdir:
        cmd = [_DOTNET, dll, *args, "--csv", tmpdir]

        try:
            subprocess.run(
                cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT * 2, check=False
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id, tool_name, params, f"{dll_name} timed out", (time.monotonic() - t0) * 1000
            )

        csv_files = list(Path(tmpdir).glob("*.csv"))
        if not csv_files:
            return error_response(
                tc_id,
                tool_name,
                params,
                f"{dll_name} produced no CSV output",
                (time.monotonic() - t0) * 1000,
            )

        combined_text = ""
        for csv_file in sorted(csv_files):
            with contextlib.suppress(OSError):
                combined_text += csv_file.read_text(encoding="utf-8", errors="replace")

    summary = extract_and_index(combined_text, source_name, source_path, "eztools")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, tool_name, params, summary, source_name, elapsed)


# ---------------------------------------------------------------------------
# EZ Tools MCP handlers
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_prefetch_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse Windows Prefetch files from a disk image using PECmd (EZ Tools).

    Mounts the disk image, locates Prefetch files, parses them for
    execution history, and indexes the results.  Falls back to TSK
    extraction when mounting fails.

    Args:
        image_path: Path to the disk image (E01, dd, img).
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "force": force}

    if not force:
        existing = sources_already_indexed(["prefetch.", "ez.prefetch"], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "run_prefetch_parser",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "ez.prefetch",
                0.0,
            )

    try:
        with mount_disk_image(image_path) as mount_point:
            prefetch_dir = None
            for candidate in (
                Path(mount_point) / "Windows" / "Prefetch",
                Path(mount_point) / "windows" / "prefetch",
            ):
                if candidate.is_dir():
                    prefetch_dir = str(candidate)
                    break
            if prefetch_dir is None:
                return error_response(
                    tc_id, "run_prefetch_parser", params, "No Prefetch directory found"
                )
            return _run_ez_tool(
                "PECmd.dll",
                ["-d", prefetch_dir],
                "ez.prefetch",
                image_path,
                tc_id,
                "run_prefetch_parser",
                params,
                t0,
            )
    except RuntimeError:
        pass

    extracted = _tsk_extract_files(image_path, ["Prefetch/", ".pf"])
    if not extracted:
        return error_response(
            tc_id,
            "run_prefetch_parser",
            params,
            "Mount failed and no Prefetch files found via TSK extraction",
            (time.monotonic() - t0) * 1000,
        )
    extract_dir = str(extracted[0][1].parent)
    try:
        return _run_ez_tool(
            "PECmd.dll",
            ["-d", extract_dir],
            "ez.prefetch",
            image_path,
            tc_id,
            "run_prefetch_parser",
            params,
            t0,
        )
    finally:
        _cleanup_tsk_extract_dir(extract_dir)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_amcache_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse Amcache from a disk image using AmcacheParser (EZ Tools).

    Shows program execution history with SHA1 hashes, file paths, and
    timestamps.  Falls back to TSK extraction when mounting fails.

    Args:
        image_path: Path to the disk image.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "force": force}

    if not force:
        existing = sources_already_indexed(["amcache.", "ez.amcache"], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "run_amcache_parser",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "ez.amcache",
                0.0,
            )

    try:
        with mount_disk_image(image_path) as mount_point:
            amcache_path = None
            for candidate in (
                Path(mount_point) / "Windows" / "appcompat" / "Programs" / "Amcache.hve",
                Path(mount_point) / "windows" / "appcompat" / "programs" / "Amcache.hve",
            ):
                if candidate.exists():
                    amcache_path = str(candidate)
                    break
            if amcache_path is None:
                return error_response(tc_id, "run_amcache_parser", params, "Amcache.hve not found")
            return _run_ez_tool(
                "AmcacheParser.dll",
                ["-f", amcache_path],
                "ez.amcache",
                image_path,
                tc_id,
                "run_amcache_parser",
                params,
                t0,
            )
    except RuntimeError:
        pass

    extracted = _tsk_extract_files(image_path, ["Amcache.hve"])
    if not extracted:
        return error_response(
            tc_id,
            "run_amcache_parser",
            params,
            "Mount failed and Amcache.hve not found via TSK extraction",
            (time.monotonic() - t0) * 1000,
        )
    extract_dir = str(extracted[0][1].parent)
    try:
        return _run_ez_tool(
            "AmcacheParser.dll",
            ["-f", str(extracted[0][1])],
            "ez.amcache",
            image_path,
            tc_id,
            "run_amcache_parser",
            params,
            t0,
        )
    finally:
        _cleanup_tsk_extract_dir(extract_dir)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_shimcache_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse ShimCache (AppCompatCache) from a disk image using AppCompatCacheParser.

    Shows file existence evidence with timestamps.  Falls back to TSK
    extraction when mounting fails.

    Args:
        image_path: Path to the disk image.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "force": force}

    if not force:
        existing = sources_already_indexed(
            ["shimcache.", "ez.shimcache"], evidence_path=image_path
        )
        if existing:
            return tool_response(
                tc_id,
                "run_shimcache_parser",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "ez.shimcache",
                0.0,
            )

    try:
        with mount_disk_image(image_path) as mount_point:
            system_hive = None
            for candidate in (
                Path(mount_point) / "Windows" / "System32" / "config" / "SYSTEM",
                Path(mount_point) / "windows" / "system32" / "config" / "SYSTEM",
            ):
                if candidate.exists():
                    system_hive = str(candidate)
                    break
            if system_hive is None:
                return error_response(
                    tc_id, "run_shimcache_parser", params, "SYSTEM hive not found"
                )
            return _run_ez_tool(
                "AppCompatCacheParser.dll",
                ["-f", system_hive],
                "ez.shimcache",
                image_path,
                tc_id,
                "run_shimcache_parser",
                params,
                t0,
            )
    except RuntimeError:
        pass

    extracted = _tsk_extract_files(image_path, ["config/SYSTEM"])
    if not extracted:
        return error_response(
            tc_id,
            "run_shimcache_parser",
            params,
            "Mount failed and SYSTEM hive not found via TSK extraction",
            (time.monotonic() - t0) * 1000,
        )
    extract_dir = str(extracted[0][1].parent)
    try:
        system_files = [
            (r, p)
            for r, p in extracted
            if p.name.upper() == "SYSTEM" or "config_system" in p.name.lower()
        ]
        if not system_files:
            return error_response(
                tc_id,
                "run_shimcache_parser",
                params,
                "Mount failed and SYSTEM hive not found via TSK extraction",
                (time.monotonic() - t0) * 1000,
            )
        return _run_ez_tool(
            "AppCompatCacheParser.dll",
            ["-f", str(system_files[0][1])],
            "ez.shimcache",
            image_path,
            tc_id,
            "run_shimcache_parser",
            params,
            t0,
        )
    finally:
        _cleanup_tsk_extract_dir(extract_dir)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_mft_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse the $MFT from a disk image using MFTECmd (EZ Tools).

    The Master File Table contains timestamps, sizes, and parent
    directories for every file on an NTFS volume.  Falls back to TSK
    icat extraction (inode 0) when mounting fails.

    Args:
        image_path: Path to the disk image.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "force": force}

    if not force:
        existing = sources_already_indexed(["mft.", "ez.mft"], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "run_mft_parser",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "ez.mft",
                0.0,
            )

    try:
        with mount_disk_image(image_path) as mount_point:
            mft_path = None
            for candidate in (
                Path(mount_point) / "$MFT",
                Path(mount_point) / "Windows" / "$MFT",
            ):
                if candidate.exists():
                    mft_path = str(candidate)
                    break
            if mft_path is None:
                return error_response(
                    tc_id, "run_mft_parser", params, "$MFT not found on mounted image"
                )
            return _run_ez_tool(
                "MFTECmd.dll",
                ["-f", mft_path],
                "ez.mft",
                image_path,
                tc_id,
                "run_mft_parser",
                params,
                t0,
            )
    except RuntimeError:
        pass

    from mulder.server.tools.extract.tsk import _detect_partition_offset

    if not require_binary("icat"):
        return error_response(
            tc_id,
            "run_mft_parser",
            params,
            "Mount failed and icat not available for TSK fallback",
            (time.monotonic() - t0) * 1000,
        )

    offset = _detect_partition_offset(image_path)
    with tempfile.TemporaryDirectory(prefix="mulder_mft_") as tmpdir:
        mft_dest = Path(tmpdir) / "$MFT"
        cmd = ["icat"]
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.extend([image_path, "0"])
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=TOOL_TIMEOUT, check=False)
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_mft_parser",
                params,
                "icat timed out extracting $MFT",
                (time.monotonic() - t0) * 1000,
            )

        if proc.returncode != 0 or not proc.stdout:
            return error_response(
                tc_id,
                "run_mft_parser",
                params,
                "Mount failed and $MFT extraction via icat failed",
                (time.monotonic() - t0) * 1000,
            )

        mft_dest.write_bytes(proc.stdout)
        return _run_ez_tool(
            "MFTECmd.dll",
            ["-f", str(mft_dest)],
            "ez.mft",
            image_path,
            tc_id,
            "run_mft_parser",
            params,
            t0,
        )


# ---------------------------------------------------------------------------
# Utility MCP handlers
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_strings(target_path: str, min_length: int = 8) -> dict[str, object]:
    """Extract printable strings from a file or disk image.

    Useful for quick triage of binary files, memory dumps, or disk
    images to find embedded text, URLs, commands, etc.

    Args:
        target_path: Path to the file to scan.
        min_length: Minimum string length to extract (default 8).
    """
    return run_cli_tool(
        binary="strings",
        cmd=["strings", f"-n{min_length}", target_path],
        tool_name="run_strings",
        params={"target_path": target_path, "min_length": min_length},
        source_name="strings.output",
        source_path=target_path,
        extractor_label="strings",
        timeout=adaptive_timeout(target_path),
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_clamav(target_path: str) -> dict[str, object]:
    """Scan files for malware signatures using ClamAV.

    Runs clamscan recursively on the target path and indexes any
    detections found.

    Args:
        target_path: Path to the file or directory to scan.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path}

    if not require_binary("clamscan"):
        return error_response(tc_id, "run_clamav", params, "clamscan not found on PATH")

    try:
        proc = subprocess.run(
            ["clamscan", "-r", "--no-summary", target_path],
            capture_output=True,
            text=True,
            timeout=adaptive_timeout(target_path),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_clamav", params, "clamscan timed out")

    output = proc.stdout.strip()
    infected_lines = [line for line in output.splitlines() if "FOUND" in line]
    summary_text = "\n".join(infected_lines) if infected_lines else output

    summary = extract_and_index(summary_text, "clamav.scan", target_path, "clamav")
    summary["detections"] = len(infected_lines)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_clamav", params, summary, "clamav.scan", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_hashdeep(target_path: str) -> dict[str, object]:
    """Compute recursive cryptographic hashes using hashdeep.

    Generates MD5, SHA1, and SHA256 hashes for all files under the
    target path.  Useful for integrity verification and IOC matching.

    Args:
        target_path: Path to the file or directory to hash.
    """
    return run_cli_tool(
        binary="hashdeep",
        cmd=["hashdeep", "-r", "-l", target_path],
        tool_name="run_hashdeep",
        params={"target_path": target_path},
        source_name="hashdeep.hashes",
        source_path=target_path,
        extractor_label="hashdeep",
        timeout=adaptive_timeout(target_path),
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def run_exiftool(target_path: str = "", file_path: str = "") -> dict[str, object]:
    """Extract file metadata (EXIF, document properties) using exiftool.

    Returns metadata for all files in the target path including
    timestamps, author information, GPS data, and more.

    Args:
        target_path: Path to the file or directory.
        file_path: Alias for target_path.
    """
    if not target_path and file_path:
        target_path = file_path
    return run_cli_tool(
        binary="exiftool",
        cmd=["exiftool", "-r", target_path],
        tool_name="run_exiftool",
        params={"target_path": target_path},
        source_name="exiftool.metadata",
        source_path=target_path,
        extractor_label="exiftool",
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_regripper(hive_path: str, profile: str | None = None) -> dict[str, object]:
    """Analyze a Windows registry hive using RegRipper.

    Runs all plugins by default, or a specific plugin profile if given.

    Args:
        hive_path: Path to the registry hive file.
        profile: Optional RegRipper plugin profile name.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"hive_path": hive_path, "profile": profile}

    rip = require_binary("rip.pl") or require_binary("regripper")
    if not rip:
        return error_response(tc_id, "run_regripper", params, "RegRipper not found on PATH")

    cmd = [rip, "-r", hive_path]
    if profile:
        cmd.extend(["-p", profile])
    else:
        cmd.append("-a")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_regripper", params, "RegRipper timed out")

    hive_label = Path(hive_path).stem.lower()
    source_name = f"regripper.{hive_label}"
    summary = extract_and_index(proc.stdout.strip(), source_name, hive_path, "regripper")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_regripper", params, summary, source_name, elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_ssdeep(target_path: str, recursive: bool = False) -> dict[str, object]:
    """Compute fuzzy hashes of files using ssdeep.

    Fuzzy hashing identifies similar (not identical) files, useful for
    finding malware variants or modified documents across systems.

    Args:
        target_path: Path to a file or directory to hash.
        recursive: If True and target is a directory, hash all files
            recursively.
    """
    cmd = ["ssdeep"]
    if recursive:
        cmd.append("-r")
    cmd.append(target_path)

    return run_cli_tool(
        binary="ssdeep",
        cmd=cmd,
        tool_name="run_ssdeep",
        params={"target_path": target_path, "recursive": recursive},
        source_name="ssdeep.hashes",
        source_path=target_path,
        extractor_label="ssdeep",
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_pasco(indexdat_path: str) -> dict[str, object]:
    """Parse an Internet Explorer index.dat file for browser history.

    Extracts URLs, timestamps, and cache entries from IE's index.dat
    files.  Relevant for older Windows systems (XP/Vista/7).

    Args:
        indexdat_path: Path to the index.dat file.
    """
    return run_cli_tool(
        binary="pasco",
        cmd=["pasco", indexdat_path],
        tool_name="run_pasco",
        params={"indexdat_path": indexdat_path},
        source_name="pasco.history",
        source_path=indexdat_path,
        extractor_label="pasco",
        check_exists=indexdat_path,
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_vshadow_info(image_path: str, offset: int = 0) -> dict[str, object]:
    """List Volume Shadow Copy (VSS) snapshots in a disk image.

    Enumerates VSS snapshots with creation dates, sizes, and identifiers.
    Use this to discover which shadow copies exist before mounting them
    for deeper analysis.

    Args:
        image_path: Path to the disk image or raw partition.
        offset: Volume offset in bytes (default 0).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "offset": offset}

    if not require_binary("vshadowinfo"):
        return error_response(
            tc_id,
            "run_vshadow_info",
            params,
            "vshadowinfo not found on PATH",
            error_type="binary_missing",
            suggestion="Install libvshadow-utils: apt-get install libvshadow-utils",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_vshadow_info",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    cmd = ["vshadowinfo"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_vshadow_info",
            params,
            "vshadowinfo timed out",
            error_type="timeout",
        )

    output = proc.stdout.strip()
    if not output and proc.stderr.strip():
        output = proc.stderr.strip()

    summary = extract_and_index(output, "vshadow.info", image_path, "vshadowinfo")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_vshadow_info", params, summary, "vshadow.info", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_chkrootkit(target_path: str | None = None) -> dict[str, object]:
    """Scan for known Linux rootkits and suspicious kernel modifications.

    Checks for known rootkits, suspicious kernel modules, and signs of
    system compromise.  Complements ClamAV which focuses on file
    malware signatures.

    Args:
        target_path: Optional alternate root path to check (e.g. a
            mounted disk image).  If None, checks the live system.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path}

    if not require_binary("chkrootkit"):
        return error_response(
            tc_id,
            "run_chkrootkit",
            params,
            "chkrootkit not found on PATH",
            error_type="binary_missing",
        )

    cmd = ["chkrootkit"]
    if target_path:
        cmd.extend(["-r", target_path])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=adaptive_timeout(target_path or "/"),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_chkrootkit",
            params,
            "chkrootkit timed out",
            error_type="timeout",
        )

    source_path = target_path or "/"
    summary = extract_and_index(
        proc.stdout.strip(),
        "chkrootkit.scan",
        source_path,
        "chkrootkit",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_chkrootkit", params, summary, "chkrootkit.scan", elapsed)


# ---------------------------------------------------------------------------
# radare2, tcpflow, tcpxtract
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_radare2(
    target_path: str,
    commands: str = "iI;iS;iz;afl",
) -> dict[str, object]:
    """Analyze a binary executable using radare2 for malware triage.

    Runs radare2 in batch mode (non-interactive) with the given
    commands.  Default commands extract: binary info (iI), sections (iS),
    strings (iz), and function list (afl).

    Args:
        target_path: Path to the binary to analyze.
        commands: Semicolon-separated r2 commands to run (batch mode).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"target_path": target_path, "commands": commands}

    if not require_binary("r2"):
        return error_response(
            tc_id,
            "run_radare2",
            params,
            "r2 (radare2) not found on PATH",
            error_type="binary_missing",
        )

    if not Path(target_path).exists():
        return error_response(
            tc_id,
            "run_radare2",
            params,
            f"File not found: {target_path}",
            error_type="file_not_found",
        )

    try:
        proc = subprocess.run(
            ["r2", "-q", "-c", commands, target_path],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_radare2",
            params,
            "radare2 timed out",
            error_type="timeout",
        )

    summary = extract_and_index(
        proc.stdout.strip(),
        "radare2.analysis",
        target_path,
        "radare2",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_radare2", params, summary, "radare2.analysis", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_tcpflow(pcap_path: str) -> dict[str, object]:
    """Reconstruct TCP streams from a PCAP file using tcpflow.

    Reassembles TCP connections into individual stream files, making it
    easy to examine HTTP transactions, file transfers, and other
    application-layer data extracted from network captures.

    Args:
        pcap_path: Path to the PCAP/PCAPNG file.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"pcap_path": pcap_path}

    if not require_binary("tcpflow"):
        return error_response(
            tc_id,
            "run_tcpflow",
            params,
            "tcpflow not found on PATH",
            error_type="binary_missing",
        )

    if not Path(pcap_path).exists():
        return error_response(
            tc_id,
            "run_tcpflow",
            params,
            f"File not found: {pcap_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_tcpflow_") as tmpdir:
        try:
            subprocess.run(
                ["tcpflow", "-r", pcap_path, "-o", tmpdir],
                capture_output=True,
                text=True,
                timeout=adaptive_timeout(pcap_path),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_tcpflow",
                params,
                "tcpflow timed out",
                error_type="timeout",
            )

        parts: list[str] = []
        for stream_file in sorted(Path(tmpdir).iterdir()):
            if not stream_file.is_file():
                continue
            st = stream_file.stat()
            if st.st_size == 0:
                continue
            with contextlib.suppress(OSError):
                preview = stream_file.read_text(
                    encoding="utf-8",
                    errors="replace",
                )[:4096]
                parts.append(f"=== {stream_file.name} ({st.st_size} bytes) ===\n{preview}")

        combined = "\n\n".join(parts) if parts else "No TCP streams reconstructed"

    summary = extract_and_index(combined, "tcpflow.streams", pcap_path, "tcpflow")
    summary["stream_count"] = len(parts)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_tcpflow", params, summary, "tcpflow.streams", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_tcpxtract(pcap_path: str) -> dict[str, object]:
    """Extract files from TCP streams in a PCAP using tcpxtract.

    Carves files from network traffic based on file signatures, similar
    to foremost but for network captures.  Useful for recovering
    transferred documents, images, and executables.

    Args:
        pcap_path: Path to the PCAP file.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"pcap_path": pcap_path}

    if not require_binary("tcpxtract"):
        return error_response(
            tc_id,
            "run_tcpxtract",
            params,
            "tcpxtract not found on PATH",
            error_type="binary_missing",
        )

    if not Path(pcap_path).exists():
        return error_response(
            tc_id,
            "run_tcpxtract",
            params,
            f"File not found: {pcap_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_tcpxtract_") as tmpdir:
        try:
            proc = subprocess.run(
                ["tcpxtract", "-f", pcap_path, "-o", tmpdir],
                capture_output=True,
                text=True,
                timeout=adaptive_timeout(pcap_path),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_tcpxtract",
                params,
                "tcpxtract timed out",
                error_type="timeout",
            )

        parts: list[str] = []
        for carved in sorted(Path(tmpdir).iterdir()):
            if carved.is_file():
                parts.append(f"{carved.name}  {carved.stat().st_size} bytes")

        inventory = "\n".join(parts) if parts else proc.stdout.strip()

    summary = extract_and_index(inventory, "tcpxtract.carved", pcap_path, "tcpxtract")
    summary["files_carved"] = len(parts)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_tcpxtract", params, summary, "tcpxtract.carved", elapsed)


# ---------------------------------------------------------------------------
# Encrypted volume tools: dislocker, bdeinfo, fvdeinfo
# ---------------------------------------------------------------------------


def _run_dislocker_metadata_mode(
    image_path: str,
    tc_id: str,
    params: dict[str, object],
    t0: float,
) -> dict[str, object]:
    """Extract BitLocker metadata without decryption credentials.

    Args:
        image_path: Path to the BitLocker-encrypted partition/image.
        tc_id: Tool call identifier for response construction.
        params: Parameters dict for response construction.
        t0: Start time for elapsed calculation.

    Returns:
        Tool response dict with metadata or an error response.
    """
    if not require_binary("dislocker-metadata"):
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            "dislocker-metadata not found on PATH",
            error_type="binary_missing",
        )
    try:
        proc = subprocess.run(
            ["dislocker-metadata", "-V", image_path],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            "dislocker-metadata timed out",
            error_type="timeout",
        )
    summary = extract_and_index(
        proc.stdout.strip(),
        "dislocker.metadata",
        image_path,
        "dislocker",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_dislocker",
        params,
        summary,
        "dislocker.metadata",
        elapsed,
    )


def _run_dislocker_decrypt_mode(
    image_path: str,
    password: str,
    recovery_key: str,
    tc_id: str,
    params: dict[str, object],
    t0: float,
) -> dict[str, object]:
    """Decrypt a BitLocker volume via FUSE using provided credentials.

    Args:
        image_path: Path to the BitLocker-encrypted partition/image.
        password: BitLocker password (may be empty if recovery_key is set).
        recovery_key: BitLocker 48-digit recovery key (may be empty if password is set).
        tc_id: Tool call identifier for response construction.
        params: Parameters dict for response construction.
        t0: Start time for elapsed calculation.

    Returns:
        Tool response dict with mount point info or an error response.
    """
    if not require_binary("dislocker-fuse"):
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            "dislocker-fuse not found on PATH",
            error_type="binary_missing",
        )

    mount_point = tempfile.mkdtemp(prefix="mulder_dislocker_")
    cmd = ["dislocker-fuse"]
    if recovery_key:
        cmd.extend(["-p", recovery_key])
    elif password:
        cmd.extend(["-u", password])
    cmd.extend(["--", image_path, mount_point])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            "dislocker-fuse timed out",
            error_type="timeout",
        )

    if proc.returncode != 0:
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            f"dislocker-fuse failed: {proc.stderr.strip()[:_PREVIEW_CHAR_LIMIT]}",
        )

    with _dislocker_lock:
        _dislocker_mounts[image_path] = mount_point

    result_text = (
        f"BitLocker volume decrypted and mounted at: {mount_point}\n"
        f"Decrypted image: {mount_point}/dislocker-file\n"
        f"Use this path with run_fls or run_mmls for filesystem analysis."
    )
    summary = extract_and_index(
        result_text,
        "dislocker.decrypted",
        image_path,
        "dislocker",
    )
    summary["mount_point"] = mount_point
    summary["decrypted_path"] = f"{mount_point}/dislocker-file"
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_dislocker",
        params,
        summary,
        "dislocker.decrypted",
        elapsed,
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_dislocker(
    image_path: str,
    recovery_key: str = "",
    password: str = "",
) -> dict[str, object]:
    """Inspect or decrypt a BitLocker-encrypted volume.

    Without credentials, returns BitLocker metadata (encryption method,
    protector types, volume ID).  With a recovery key or password,
    decrypts the volume to a FUSE mountpoint for subsequent TSK analysis.

    Args:
        image_path: Path to the BitLocker-encrypted partition/image.
        recovery_key: BitLocker 48-digit recovery key (optional).
        password: BitLocker password (optional).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "image_path": image_path,
        "recovery_key": "***" if recovery_key else "",
        "password": "***" if password else "",
    }

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    if not recovery_key and not password:
        return _run_dislocker_metadata_mode(image_path, tc_id, params, t0)

    return _run_dislocker_decrypt_mode(image_path, password, recovery_key, tc_id, params, t0)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_bdeinfo(image_path: str) -> dict[str, object]:
    """Extract metadata from a BitLocker-encrypted volume using libbde.

    Returns encryption method, volume identifier, protector types, and
    creation timestamps without requiring the decryption key.

    Args:
        image_path: Path to the BitLocker-encrypted partition/image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path}

    if not require_binary("bdeinfo"):
        return error_response(
            tc_id,
            "run_bdeinfo",
            params,
            "bdeinfo not found on PATH",
            error_type="binary_missing",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_bdeinfo",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    try:
        proc = subprocess.run(
            ["bdeinfo", image_path],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_bdeinfo",
            params,
            "bdeinfo timed out",
            error_type="timeout",
        )

    summary = extract_and_index(
        proc.stdout.strip(),
        "bde.info",
        image_path,
        "bdeinfo",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_bdeinfo", params, summary, "bde.info", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_fvdeinfo(image_path: str) -> dict[str, object]:
    """Extract metadata from a FileVault-encrypted macOS volume.

    Returns encryption type, volume UUID, and protector information
    without requiring the decryption passphrase.

    Args:
        image_path: Path to the FileVault-encrypted volume image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path}

    if not require_binary("fvdeinfo"):
        return error_response(
            tc_id,
            "run_fvdeinfo",
            params,
            "fvdeinfo not found on PATH",
            error_type="binary_missing",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_fvdeinfo",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    try:
        proc = subprocess.run(
            ["fvdeinfo", image_path],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_fvdeinfo",
            params,
            "fvdeinfo timed out",
            error_type="timeout",
        )

    summary = extract_and_index(
        proc.stdout.strip(),
        "fvde.info",
        image_path,
        "fvdeinfo",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_fvdeinfo", params, summary, "fvde.info", elapsed)
