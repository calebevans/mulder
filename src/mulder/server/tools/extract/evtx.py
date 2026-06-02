"""Windows Event Log (EVTX) extraction and indexing MCP tools."""

from __future__ import annotations

import atexit
import contextlib
import logging
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import cast

from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    require_binary,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.misc import _DOTNET, _find_ez_tool
from mulder.server.tools.extract.tsk import (
    _detect_partition_offset,
    _parse_partition_offset,
    _run_fls_inline,
    _tsk_extract_dirs,
    _tsk_lock,
)

__all__ = [
    "_cleanup_temp_dirs",
    "_evtx_extract_dirs",
    "index_evtx_file",
    "run_evtx_parser",
]

logger = logging.getLogger(__name__)

_evtx_extract_dirs: dict[str, str] = {}
_evtx_lock = threading.Lock()


def _extract_evtx_from_image(image_path: str, dest_dir: str) -> list[Path]:
    """Extract .evtx files from a disk image to *dest_dir* using TSK icat.

    Uses the fls listing already indexed for the case to locate EVTX
    inodes, then extracts each with icat.  When the DB has no
    ``tsk.filelist`` source (e.g. ``run_fls`` has not completed yet),
    runs fls inline so extraction is self-contained.

    Works on E01 and raw images without mounting.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    fls_source = next((s for s in sources if s.source_name == "tsk.filelist"), None)

    fls_text_chunks: list[str] = []
    offset = 0

    if fls_source is not None:
        windows = ctx.db.get_windows_by_source("tsk.filelist")
        fls_text_chunks = [w.raw_text for w in windows]
        part_src = next((s for s in sources if s.source_name == "tsk.partitions"), None)
        if part_src:
            part_windows = ctx.db.get_windows_by_source("tsk.partitions")
            mmls_text = "\n".join(w.raw_text for w in part_windows)
            offset = _parse_partition_offset(mmls_text)
    else:
        logger.info(
            "tsk.filelist not yet indexed; running fls inline for EVTX extraction from %s",
            image_path,
        )
        inline_output = _run_fls_inline(image_path)
        if inline_output:
            fls_text_chunks = [inline_output]
            offset = _detect_partition_offset(image_path)

    if not fls_text_chunks:
        return []

    evtx_re = re.compile(
        r"^[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.+\.evtx)\s*$", re.IGNORECASE | re.MULTILINE
    )

    extracted: list[Path] = []
    seen_inodes: set[str] = set()
    for chunk in fls_text_chunks:
        for m in evtx_re.finditer(chunk):
            inode_str = m.group(1).split("-")[0]
            if inode_str in seen_inodes:
                continue
            seen_inodes.add(inode_str)
            rel_path = m.group(2).strip()
            safe_name = rel_path.replace("/", "_").replace("\\", "_")
            out_path = Path(dest_dir) / safe_name
            cmd = ["icat"]
            if offset > 0:
                cmd.extend(["-o", str(offset)])
            cmd.extend([image_path, inode_str])
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
                if proc.returncode == 0 and proc.stdout:
                    out_path.write_bytes(proc.stdout)
                    extracted.append(out_path)
            except (subprocess.TimeoutExpired, OSError):
                continue
    return extracted


def _find_carved_evtx(dest_dir: str) -> list[Path]:
    """Scan bulk_extractor output for carved .evtx files as a fallback.

    When the TSK path (fls + icat) fails, bulk_extractor may have
    carved EVTX fragments.  This checks the case DB for bulk_extractor
    output paths and copies any .evtx files to *dest_dir*.
    """
    ctx = get_ctx()
    cfg = get_cfg()
    found: list[Path] = []
    search_dirs: list[Path] = []

    sources = ctx.db.get_sources()
    for s in sources:
        if s.source_name.startswith("bulk."):
            src_path = Path(s.source_path)
            if src_path.is_dir():
                search_dirs.append(src_path)
            elif src_path.parent.is_dir():
                search_dirs.append(src_path.parent)

    if cfg.db_dir.is_dir():
        search_dirs.append(cfg.db_dir)

    seen: set[str] = set()
    for d in search_dirs:
        for evtx in d.rglob("*.evtx"):
            if evtx.name in seen:
                continue
            seen.add(evtx.name)
            dest = Path(dest_dir) / evtx.name
            try:
                shutil.copy2(str(evtx), str(dest))
                found.append(dest)
            except OSError:
                continue
    return found


def _cleanup_temp_dirs() -> None:
    """Remove all extraction temp directories."""
    with _evtx_lock:
        dirs = list(_evtx_extract_dirs.values())
        _evtx_extract_dirs.clear()
    for path in dirs:
        shutil.rmtree(path, ignore_errors=True)
    with _tsk_lock:
        tsk_dirs = list(_tsk_extract_dirs)
        _tsk_extract_dirs.clear()
    for path in tsk_dirs:
        shutil.rmtree(path, ignore_errors=True)


atexit.register(_cleanup_temp_dirs)

_HIGH_PRIORITY_KEYWORDS = (
    "security.evtx",
    "system.evtx",
    "powershell",
    "sysmon",
    "taskscheduler",
    "winrm",
    "rdp",
)


def _build_evtx_priority_manifest(evtx_files: list[Path]) -> list[dict[str, object]]:
    """Score EVTX files by forensic priority and build a manifest.

    Files matching known forensic sources (Security, System, PowerShell,
    Sysmon, TaskScheduler, WinRM, RDP) are scored HIGH. Files over 1 MB
    are MEDIUM; the rest are LOW. Results are sorted by size descending.

    Args:
        evtx_files: Extracted EVTX file paths to evaluate.

    Returns:
        Manifest entries with filename, size, human-readable size,
        and priority.
    """
    manifest: list[dict[str, object]] = []
    for ef in sorted(evtx_files, key=lambda p: p.stat().st_size, reverse=True):
        size = ef.stat().st_size
        name = ef.name
        priority = (
            "HIGH"
            if any(k in name.lower() for k in _HIGH_PRIORITY_KEYWORDS)
            else "MEDIUM"
            if size > 1_000_000
            else "LOW"
        )
        manifest.append(
            {
                "filename": name,
                "size_bytes": size,
                "size_human": f"{size / 1_048_576:.1f} MB"
                if size > 1_048_576
                else f"{size / 1024:.0f} KB",
                "priority": priority,
            }
        )
    return manifest


def _parse_evtx_with_eztools(evtx_path: str, evtx_dir: str | None) -> dict[str, object] | None:
    """Parse EVTX files using EZTools EvtxECmd.

    Attempts to locate EvtxECmd.dll and the dotnet runtime. If available,
    runs EvtxECmd to produce CSV output and indexes the combined result.

    Args:
        evtx_path: Path to a single EVTX file (used when evtx_dir is None).
        evtx_dir: Path to a directory of EVTX files, or None for single file.

    Returns:
        Indexed summary dict on success, or None if EZTools is unavailable
        or produces no output.

    Raises:
        subprocess.TimeoutExpired: If EvtxECmd exceeds the timeout.
    """
    dll = _find_ez_tool("EvtxECmd.dll")
    if not (dll and require_binary(_DOTNET)):
        return None

    with tempfile.TemporaryDirectory(prefix="mulder_evtx_csv_") as csv_dir:
        if evtx_dir:
            cmd = [_DOTNET, dll, "-d", evtx_dir, "--csv", csv_dir]
        else:
            cmd = [_DOTNET, dll, "-f", evtx_path, "--csv", csv_dir]

        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=adaptive_timeout(evtx_path),
            check=False,
        )

        combined = ""
        for csv_file in sorted(Path(csv_dir).glob("*.csv")):
            with contextlib.suppress(OSError):
                combined += csv_file.read_text(encoding="utf-8", errors="replace")

        if combined:
            return extract_and_index(combined, "ez.evtx", evtx_path, "eztools")
    return None


def _parse_evtx_with_python_fallback(evtx_path: str, evtx_dir: str | None) -> list[object]:
    """Parse EVTX files using the pure-Python python-evtx library.

    Used as a fallback when EZTools is unavailable or produces no output.

    Args:
        evtx_path: Path to a single EVTX file (used when evtx_dir is None).
        evtx_dir: Path to a directory of EVTX files, or None for single file.

    Returns:
        List of indexed summary dicts, one per successfully parsed file.

    Raises:
        ImportError: If python-evtx is not installed.
    """
    from mulder.extractors.disk import _parse_evtx_file

    results: list[object] = []
    files = sorted(Path(evtx_dir).rglob("*.evtx")) if evtx_dir else [Path(evtx_path)]
    for ef in files:
        channel, text = _parse_evtx_file(ef)
        if text:
            summary = extract_and_index(text, f"evtx.{channel}", str(ef), "python-evtx")
            results.append(summary)
    return results


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_evtx_parser(evtx_path: str, force: bool = False) -> dict[str, object]:
    """Extract and list Windows Event Log (.evtx) files from a disk image.

    When given a disk image (E01/raw), extracts ALL .evtx files to a
    persistent temp directory and returns a manifest with file names and
    sizes. Does NOT parse or index them; use ``index_evtx_file`` to
    selectively parse the most relevant logs.

    When given a directory or single .evtx file, parses it immediately.

    Recommended workflow for disk images:
    1. Call ``run_evtx_parser("<image_path>")`` to extract and list files
    2. Review the manifest: start with Security.evtx, System.evtx,
       PowerShell.evtx, Sysmon.evtx
    3. Call ``index_evtx_file("<filename>")`` on each relevant log
    4. Only index archived/rotated logs if you need historical data

    Args:
        evtx_path: Path to an EVTX file, directory, or disk image.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"evtx_path": evtx_path, "force": force}

    if not force:
        existing = sources_already_indexed(["evtx.", "ez.evtx"], evidence_path=evtx_path)
        if existing:
            return tool_response(
                tc_id,
                "run_evtx_parser",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "evtx",
                0.0,
            )

    target = Path(evtx_path)
    if not target.exists():
        return error_response(tc_id, "run_evtx_parser", params, f"Path not found: {evtx_path}")

    is_image = target.suffix.lower() in (".e01", ".dd", ".img", ".raw", ".001")

    if is_image:
        extract_dir = tempfile.mkdtemp(prefix="mulder_evtx_extract_")
        with _evtx_lock:
            _evtx_extract_dirs[evtx_path] = extract_dir
        evtx_files = _extract_evtx_from_image(evtx_path, extract_dir)
        if not evtx_files:
            evtx_files = _find_carved_evtx(extract_dir)
        if not evtx_files:
            shutil.rmtree(extract_dir, ignore_errors=True)
            with _evtx_lock:
                _evtx_extract_dirs.pop(evtx_path, None)
            return error_response(
                tc_id,
                "run_evtx_parser",
                params,
                "No EVTX files found in disk image. "
                "Ensure run_fls has been called first, or run run_bulk_extractor "
                "which can carve EVTX fragments even when fls fails.",
            )

        manifest = _build_evtx_priority_manifest(evtx_files)
        high_count = sum(1 for m in manifest if m["priority"] == "HIGH")
        total_size: int = sum(cast(int, m["size_bytes"]) for m in manifest)

        manifest_text = "\n".join(
            f"{m['filename']}\t{m['size_human']}\t{m['priority']}" for m in manifest
        )
        extract_and_index(manifest_text, "evtx.manifest", evtx_path, "evtx-extract")

        result = {
            "extract_dir": extract_dir,
            "total_files": len(manifest),
            "total_size_human": f"{total_size / 1_073_741_824:.1f} GB"
            if total_size > 1_073_741_824
            else f"{total_size / 1_048_576:.0f} MB",
            "high_priority_count": high_count,
            "manifest": manifest,
            "hint": (
                f"Extracted {len(manifest)} EVTX files ({total_size / 1_048_576:.0f} MB total). "
                f"{high_count} are HIGH priority. Use index_evtx_file(filename) to parse "
                f"specific logs. Start with Security, System, PowerShell, and Sysmon. "
                f"Only index archived logs (Archive-Security-*) if you need historical data."
            ),
        }

        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(tc_id, "run_evtx_parser", params, result, "evtx.manifest", elapsed)

    evtx_dir = evtx_path if target.is_dir() else None

    try:
        ez_result = _parse_evtx_with_eztools(evtx_path, evtx_dir)
        if ez_result is not None:
            elapsed = (time.monotonic() - t0) * 1000
            return tool_response(tc_id, "run_evtx_parser", params, ez_result, "ez.evtx", elapsed)
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_evtx_parser", params, "EvtxECmd timed out")

    try:
        results = _parse_evtx_with_python_fallback(evtx_path, evtx_dir)
    except ImportError:
        return error_response(tc_id, "run_evtx_parser", params, "No EVTX parser available")

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_evtx_parser", params, results, "evtx", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def index_evtx_file(
    filename: str,
    event_ids: list[int] | None = None,
    image_path: str = "",
) -> dict[str, object]:
    """Parse and index a specific EVTX file from a previous extraction.

    Call ``run_evtx_parser`` on a disk image first to extract all EVTX
    files. Then call this tool on specific files you want to analyze.
    The filename should match one from the manifest returned by
    ``run_evtx_parser``.

    Pass *event_ids* to extract only specific Event IDs.  This is
    **dramatically faster** on large logs: a Security.evtx with 200k
    events takes minutes to parse fully but seconds when filtered to
    the 10-15 forensically relevant Event IDs.

    Recommended order:
    1. Security.evtx (logon events, account changes, privilege use)
    2. System.evtx (service installs, driver loads)
    3. Windows PowerShell.evtx (PowerShell commands)
    4. Sysmon logs (if present: detailed process/network activity)
    5. WinRM, TaskScheduler, RDP logs (lateral movement)
    6. Archived logs only if you need to check a specific time window

    Args:
        filename: Name of the .evtx file to parse (from the manifest).
        event_ids: Optional list of Event IDs to extract.  When provided,
            only events matching these IDs are parsed and indexed.
            When omitted, all events are extracted.  Choose IDs based
            on the log type and what you're investigating.
        image_path: Disk image path passed to ``run_evtx_parser``.
            Required when multiple images have been extracted in the
            same session; omit for single-image cases.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"filename": filename, "event_ids": event_ids, "image_path": image_path}

    with _evtx_lock:
        if image_path and image_path in _evtx_extract_dirs:
            extract_dir = _evtx_extract_dirs[image_path]
        elif _evtx_extract_dirs:
            extract_dir = next(reversed(_evtx_extract_dirs.values()))
        else:
            extract_dir = ""

    if not extract_dir or not Path(extract_dir).is_dir():
        return error_response(
            tc_id,
            "index_evtx_file",
            params,
            "No EVTX extraction directory found. Call run_evtx_parser on a disk image first.",
        )

    evtx_path = Path(extract_dir) / filename
    if not evtx_path.exists():
        candidates = sorted(Path(extract_dir).glob(f"*{filename}*"))
        if candidates:
            evtx_path = candidates[0]
        else:
            available = [f.name for f in sorted(Path(extract_dir).glob("*.evtx"))[:10]]
            return error_response(
                tc_id,
                "index_evtx_file",
                params,
                f"File not found: {filename}. Available files include: {', '.join(available)}",
            )

    dll = _find_ez_tool("EvtxECmd.dll")
    if dll and require_binary(_DOTNET):
        with tempfile.TemporaryDirectory(prefix="mulder_evtx_csv_") as csv_dir:
            cmd = [_DOTNET, dll, "-f", str(evtx_path), "--csv", csv_dir]
            if event_ids:
                cmd.extend(["--inc", ",".join(str(eid) for eid in event_ids)])
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=adaptive_timeout(str(evtx_path)),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return error_response(
                    tc_id, "index_evtx_file", params, f"EvtxECmd timed out on {filename}"
                )

            combined = ""
            for csv_file in sorted(Path(csv_dir).glob("*.csv")):
                with contextlib.suppress(OSError):
                    combined += csv_file.read_text(encoding="utf-8", errors="replace")

            if combined:
                source_name = "evtx." + evtx_path.stem.lower().replace(" ", "-").replace("%", "")
                summary = extract_and_index(combined, source_name, str(evtx_path), "eztools")
                elapsed = (time.monotonic() - t0) * 1000
                return tool_response(
                    tc_id, "index_evtx_file", params, summary, source_name, elapsed
                )

    try:
        from mulder.extractors.disk import _parse_evtx_file
    except ImportError:
        return error_response(tc_id, "index_evtx_file", params, "No EVTX parser available")

    id_filter = set(event_ids) if event_ids else None
    channel, text = _parse_evtx_file(evtx_path, event_ids=id_filter)
    if text:
        summary = extract_and_index(text, f"evtx.{channel}", str(evtx_path), "python-evtx")
        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(tc_id, "index_evtx_file", params, summary, f"evtx.{channel}", elapsed)

    elapsed = (time.monotonic() - t0) * 1000
    return error_response(tc_id, "index_evtx_file", params, f"No events parsed from {filename}")
