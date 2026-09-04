"""Windows Registry parsing MCP tools."""

from __future__ import annotations

import logging
import re
import tempfile
import time
from pathlib import Path
from typing import Any

from mulder.execution import safe_subprocess as subprocess
from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index, mount_disk_image
from mulder.server.helpers import (
    _HINT_CHAR_LIMIT,
    TOOL_TIMEOUT,
    error_response,
    make_tool_call_id,
    require_binary,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.misc import _DOTNET, _find_ez_tool
from mulder.server.tools.extract.tsk import (
    _cleanup_tsk_extract_dir,
    _collect_fls_chunks,
    _tsk_extract_files,
)

__all__ = [
    "run_registry_parser",
]

logger = logging.getLogger(__name__)

_HIVE_NAMES = {"system", "software", "sam", "security", "default"}

_USER_HIVE_PATTERNS: list[str] = [
    "Documents and Settings/*/NTUSER.DAT",
    "Users/*/NTUSER.DAT",
]

_USRCLASS_PATTERNS: list[str] = [
    "Documents and Settings/*/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat",
    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat",
]

_USERNAME_RE = re.compile(
    r"(?:Documents and Settings|Users)/([^/]+)/",
    re.IGNORECASE,
)

_NTUSER_PLUGINS: list[str] = [
    "userassist",
    "recentdocs",
    "typedurls",
    "mru",
    "shellfolders",
    "desktop",
    "environment",
    "run",
    "winlogon",
    "mountpoints2",
    "wordwheelquery",
    "comdlg32",
]

_USRCLASS_PLUGINS: list[str] = [
    "shellbags",
]


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


def _extract_username(path: str) -> str | None:
    """Extract the username from a user profile path.

    Handles both XP-style (Documents and Settings) and modern
    (Users) profile directory layouts.

    Args:
        path: File path containing a user profile directory.

    Returns:
        Username string or None if the path does not match
        expected patterns.
    """
    match = _USERNAME_RE.search(path)
    return match.group(1) if match else None


def _discover_user_hives_via_tsk(
    image_path: str,
    offset: int | None = None,
) -> tuple[list[tuple[Path, str, str]], str | None]:
    """Discover per-user registry hives from a disk image.

    Searches the TSK file listing for NTUSER.DAT and UsrClass.dat
    files across all user profile directories for both XP-era and
    modern Windows layouts.

    Args:
        image_path: Path to the disk image file.
        offset: Partition offset in bytes.

    Returns:
        Tuple of (hive list, extract_dir). Each hive entry is
        (extracted_path, hive_type, username). hive_type is either
        "ntuser" or "usrclass". extract_dir is the temp directory
        path for caller cleanup, or None when nothing was extracted.
    """
    _ = offset

    chunk_groups = _collect_fls_chunks(image_path)
    if not chunk_groups:
        return [], None

    inode_re = re.compile(
        r"^[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.+)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )

    ntuser_patterns = [
        "documents and settings/",
        "users/",
    ]
    ntuser_suffix = "ntuser.dat"
    usrclass_suffix = "usrclass.dat"

    hives: list[tuple[Path, str, str]] = []
    extract_dir: Path | None = None
    seen: set[str] = set()

    for chunks, chunk_offset in chunk_groups:
        for chunk in chunks:
            for m in inode_re.finditer(chunk):
                inode_str = m.group(1).split("-")[0]
                rel_path = m.group(2).strip()
                rel_lower = rel_path.lower().replace("\\", "/")

                hive_type: str | None = None
                if rel_lower.endswith(ntuser_suffix) and any(
                    p in rel_lower for p in ntuser_patterns
                ):
                    hive_type = "ntuser"
                elif rel_lower.endswith(usrclass_suffix) and any(
                    p in rel_lower for p in ntuser_patterns
                ):
                    hive_type = "usrclass"

                if hive_type is None:
                    continue

                username = _extract_username(rel_path)
                if not username:
                    continue

                dedup_key = f"{chunk_offset}:{inode_str}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                if extract_dir is None:
                    extract_dir = Path(tempfile.mkdtemp(prefix="mulder_user_hives_"))

                sanitized = rel_path.replace("/", "_").replace(chr(92), "_")
                safe_name = f"{username}_{hive_type}_{sanitized}"
                out_path = extract_dir / safe_name
                cmd = ["icat"]
                if chunk_offset > 0:
                    cmd.extend(["-o", str(chunk_offset)])
                cmd.extend([image_path, inode_str])
                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        timeout=30,
                        check=False,
                    )
                    if proc.returncode == 0 and proc.stdout:
                        out_path.write_bytes(proc.stdout)
                        hives.append((out_path, hive_type, username))
                except (subprocess.TimeoutExpired, OSError):
                    logger.warning(
                        "Failed to extract %s hive for user %s (inode %s)",
                        hive_type,
                        username,
                        inode_str,
                    )
                    continue

    return hives, str(extract_dir) if extract_dir else None


def _discover_hives_via_tsk(
    image_path: str, offset: int | None = None
) -> tuple[list[tuple[Path, str]], str | None]:
    """Extract registry hives from a disk image using The Sleuth Kit.

    Falls back to TSK file extraction when mount discovery is not
    possible. Extracts standard hive files and maps them to canonical names.

    Args:
        image_path: Path to the disk image file.
        offset: Partition offset in bytes (reserved for future use).

    Returns:
        Tuple of (hive list, extract_dir). Each hive entry is
        (extracted_hive_path, hive_name_lowercase). extract_dir is the
        temp directory path for caller cleanup, or None when nothing was
        extracted.
    """
    _ = offset
    extracted = _tsk_extract_files(
        image_path,
        ["config/SYSTEM", "config/SOFTWARE", "config/SAM", "config/SECURITY", "config/DEFAULT"],
    )

    hives: list[tuple[Path, str]] = []
    extract_dir: str | None = None
    for _rel, fpath in extracted:
        if extract_dir is None:
            extract_dir = str(fpath.parent)
        name_lower = fpath.name.lower()
        if name_lower not in _HIVE_NAMES:
            for h in _HIVE_NAMES:
                if h in fpath.name.lower():
                    name_lower = h
                    break
            else:
                continue
        hives.append((fpath, name_lower))

    return hives, extract_dir


def _run_regripper_plugins(
    rip_binary: str,
    hive_path: Path,
    plugins: list[str],
) -> str:
    """Run RegRipper with specific plugins and concatenate output.

    Args:
        rip_binary: Path to the RegRipper binary.
        hive_path: Path to the hive file to parse.
        plugins: List of plugin names to invoke.

    Returns:
        Concatenated stdout from all successful plugin invocations.
    """
    outputs: list[str] = []
    for plugin in plugins:
        try:
            proc = subprocess.run(
                [rip_binary, "-r", str(hive_path), "-p", plugin],
                capture_output=True,
                text=True,
                timeout=TOOL_TIMEOUT,
                check=False,
            )
            if proc.stdout.strip():
                outputs.append(proc.stdout.strip())
        except (subprocess.TimeoutExpired, OSError):
            logger.debug("RegRipper plugin %s timed out or failed", plugin)
            continue
    return "\n\n".join(outputs)


def _parse_single_hive(
    hive_path: Path,
    source_name: str,
    image_path: str,
    plugins: list[str] | None = None,
) -> dict[str, Any]:
    """Parse a single registry hive using available tools.

    Attempts parsing in order of preference: RECmd (EZ Tools), then
    RegRipper. When *plugins* is provided, skips RECmd and uses
    RegRipper with specific plugin flags. Returns either indexed
    extraction results on success or a status dict describing the failure.

    Args:
        hive_path: Path to the registry hive file.
        source_name: Logical source identifier (e.g. "registry.system").
        image_path: Original disk image path (for indexing metadata).
        plugins: Optional list of RegRipper plugin names. When provided,
            runs each plugin individually rather than using ``-a``.

    Returns:
        Dict containing either indexed extraction results (on success) or
        a status dict with ``source_name`` and ``status`` keys on failure.
    """
    hive_status: str | None = None

    if plugins is None:
        dll = _find_ez_tool("RECmd.dll")
        if dll and require_binary(_DOTNET):
            with tempfile.TemporaryDirectory(prefix="mulder_reg_") as tmpdir:
                cmd = [_DOTNET, dll, "-f", str(hive_path), "--csv", tmpdir]
                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=TOOL_TIMEOUT,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    hive_status = "recmd_timeout"
                else:
                    combined = ""
                    for csv_file in sorted(Path(tmpdir).rglob("*.csv")):
                        combined += csv_file.read_text(encoding="utf-8", errors="replace")
                    if combined:
                        return extract_and_index(combined, source_name, image_path, "eztools")
                    stderr_hint = (proc.stderr or "")[:_HINT_CHAR_LIMIT].strip()
                    hive_status = (
                        f"recmd_empty_output ({stderr_hint})"
                        if stderr_hint
                        else "recmd_empty_output"
                    )

    rip = require_binary("rip.pl") or require_binary("regripper")
    if rip:
        try:
            if plugins:
                combined_output = _run_regripper_plugins(rip, hive_path, plugins)
            else:
                proc = subprocess.run(
                    [rip, "-r", str(hive_path), "-a"],
                    capture_output=True,
                    text=True,
                    timeout=TOOL_TIMEOUT,
                    check=False,
                )
                combined_output = proc.stdout.strip()
            if combined_output:
                return extract_and_index(combined_output, source_name, image_path, "regripper")
            hive_status = "regripper_empty_output"
        except subprocess.TimeoutExpired:
            hive_status = "regripper_timeout"
        except OSError as exc:
            hive_status = f"regripper_error ({exc})"
    elif hive_status is None:
        has_recmd = bool(_find_ez_tool("RECmd.dll") and require_binary(_DOTNET))
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
@tool_access(Role.EXTRACT_EXECUTOR)
def run_registry_parser(
    image_path: str,
    hive: str | None = None,
    force: bool = False,
    include_user_hives: bool = True,
) -> dict[str, object]:
    """Parse Windows registry hives from a disk image using RECmd or RegRipper.

    Call after run_fls on disk images containing Windows installations.
    Extracts hive files via TSK, then parses all standard hives (SYSTEM,
    SOFTWARE, SAM, SECURITY) unless a specific hive is requested.

    When include_user_hives is True (the default), also discovers and
    parses per-user NTUSER.DAT and UsrClass.dat hives from both XP-era
    (Documents and Settings) and modern (Users) profile directories.
    User hive results are indexed as ``registry.ntuser.<username>`` and
    ``registry.usrclass.<username>``.

    Indexes system hives as ``registry.<hive>`` (e.g. ``registry.system``).
    Contains service configurations, installed software, user accounts,
    autorun entries, and per-user activity artifacts (TypedURLs,
    RecentDocs, UserAssist, MRU lists, mapped drives).

    Args:
        image_path: Path to the disk image.
        hive: Optional specific hive to parse (e.g. "SYSTEM", "SOFTWARE").
        force: Re-run extraction even if sources already exist.
        include_user_hives: Whether to discover and parse per-user
            hives (NTUSER.DAT, UsrClass.dat). Defaults to True.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {
        "image_path": image_path,
        "hive": hive,
        "force": force,
        "include_user_hives": include_user_hives,
    }

    if not force:
        existing = sources_already_indexed(["registry."], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "run_registry_parser",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "registry",
                0.0,
            )

    discovered_tsk, tsk_extract_dir = _discover_hives_via_tsk(image_path)
    if hive:
        discovered_tsk = [(p, n) for p, n in discovered_tsk if n == hive.lower()]

    if discovered_tsk:
        try:
            results: list[dict[str, Any]] = []
            for hive_path, hive_name in discovered_tsk:
                source_name = f"registry.{hive_name}"
                results.append(_parse_single_hive(hive_path, source_name, image_path))

            if include_user_hives and not hive:
                user_results = _parse_all_user_hives(image_path)
                results.extend(user_results)

            elapsed = (time.monotonic() - t0) * 1000
            return tool_response(
                tc_id,
                "run_registry_parser",
                params,
                _summarize_hive_results(results),
                "registry",
                elapsed,
            )
        finally:
            if tsk_extract_dir:
                _cleanup_tsk_extract_dir(tsk_extract_dir)

    if tsk_extract_dir:
        _cleanup_tsk_extract_dir(tsk_extract_dir)

    try:
        with mount_disk_image(image_path) as mount_point:
            try:
                discovered_mount = _discover_hives_from_mount(Path(mount_point))
            except FileNotFoundError:
                return error_response(
                    tc_id, "run_registry_parser", params, "Registry config directory not found"
                )

            if hive:
                discovered_mount = [(p, n) for p, n in discovered_mount if n == hive.lower()]

            if not discovered_mount:
                return error_response(
                    tc_id, "run_registry_parser", params, "No registry hives found to parse"
                )

            results_mount: list[dict[str, Any]] = []
            for hive_path, hive_name in discovered_mount:
                source_name = f"registry.{hive_name}"
                results_mount.append(_parse_single_hive(hive_path, source_name, image_path))

            if include_user_hives and not hive:
                user_results = _parse_all_user_hives(image_path)
                results_mount.extend(user_results)

            elapsed = (time.monotonic() - t0) * 1000
            return tool_response(
                tc_id,
                "run_registry_parser",
                params,
                _summarize_hive_results(results_mount),
                "registry",
                elapsed,
            )
    except RuntimeError:
        pass

    return error_response(
        tc_id,
        "run_registry_parser",
        params,
        "No registry hives found via TSK extraction or mount",
        (time.monotonic() - t0) * 1000,
    )


def _parse_all_user_hives(image_path: str) -> list[dict[str, Any]]:
    """Discover and parse all per-user registry hives from a disk image.

    Iterates over discovered NTUSER.DAT and UsrClass.dat files, parsing
    each with the appropriate RegRipper plugin set. Failures for individual
    users are isolated so that one corrupted hive does not prevent parsing
    of other users.

    Args:
        image_path: Path to the disk image.

    Returns:
        List of per-hive result dicts (indexed results or error status).
    """
    user_hives, user_extract_dir = _discover_user_hives_via_tsk(image_path)
    if not user_hives:
        return []

    results: list[dict[str, Any]] = []
    try:
        for hive_path, hive_type, username in user_hives:
            source_name = f"registry.{hive_type}.{username.lower()}"
            plugins = _NTUSER_PLUGINS if hive_type == "ntuser" else _USRCLASS_PLUGINS
            try:
                result = _parse_single_hive(hive_path, source_name, image_path, plugins=plugins)
                results.append(result)
            except Exception:
                logger.warning(
                    "Failed to parse %s for user %s",
                    hive_type,
                    username,
                    exc_info=True,
                )
                results.append(
                    {
                        "source_name": source_name,
                        "status": "error",
                        "error": f"Failed to parse {hive_type} for {username}",
                    }
                )
    finally:
        if user_extract_dir:
            _cleanup_tsk_extract_dir(user_extract_dir)

    return results
