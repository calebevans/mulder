"""SleuthKit (TSK) filesystem analysis MCP tools."""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
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

__all__ = [
    "_cleanup_tsk_extract_dir",
    "_detect_partition_offset",
    "_parse_partition_offset",
    "_resolve_partition_offset",
    "_run_fls_inline",
    "_tsk_extract_dirs",
    "_tsk_extract_files",
    "_tsk_lock",
    "run_fls",
    "run_fsstat",
    "run_mactime",
    "run_mmls",
]

logger = logging.getLogger(__name__)


def _detect_partition_offset(image_path: str) -> int:
    """Run mmls to find the main partition offset (in sectors)."""
    if not require_binary("mmls"):
        return 0
    try:
        proc = subprocess.run(
            ["mmls", image_path], capture_output=True, text=True, timeout=30, check=False
        )
        if proc.returncode != 0:
            return 0
    except (subprocess.TimeoutExpired, OSError):
        return 0

    ntfs_indicators = ("ntfs", "0x07", "win95 fat", "0x0b", "0x0c")
    linux_indicators = ("linux", "0x83", "ext", "0x8e")
    row_re = re.compile(r"^\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$", re.MULTILINE)
    rows = [
        (int(m.group(1)), int(m.group(2)), m.group(3).strip().lower())
        for m in row_re.finditer(proc.stdout)
    ]
    if not rows:
        return 0

    for start, length, desc in rows:
        if any(ind in desc for ind in ntfs_indicators) and length > 0:
            return start
    for start, length, desc in rows:
        if any(ind in desc for ind in linux_indicators) and length > 0:
            return start
    biggest = max(rows, key=lambda t: t[1])
    return biggest[0] if biggest[1] > 0 else 0


def _parse_partition_offset(mmls_text: str) -> int:
    """Parse the NTFS partition offset from mmls output."""
    row_re = re.compile(r"^\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$", re.MULTILINE)
    for m in row_re.finditer(mmls_text):
        start, length, desc = int(m.group(1)), int(m.group(2)), m.group(3).strip().lower()
        if any(ind in desc for ind in ("ntfs", "0x07", "win95 fat")) and length > 0:
            return start
    return 0


_KV_OFFSET_PREFIX = "tsk_partition_offset:"
"""DB kv_store key prefix for persisted partition offsets."""


def _resolve_partition_offset(image_path: str) -> int:
    """Resolve the partition offset for *image_path* using all available sources.

    Checks, in order:
      1. The DB ``kv_store`` (set by a prior successful ``run_fls``).
      2. The indexed ``tsk.partitions`` source (mmls output).
      3. Live ``_detect_partition_offset`` (runs mmls on the fly).

    This ensures that when ``run_fls`` was called with an explicit offset
    (e.g. on multi-segment E01 images where mmls may not work),
    downstream icat extractions reuse the same working offset.
    """
    ctx = get_ctx()

    stored = ctx.db.get_kv(f"{_KV_OFFSET_PREFIX}{image_path}")
    if stored is not None:
        with contextlib.suppress(ValueError):
            return int(stored)

    sources = ctx.db.get_sources()
    part_src = next((s for s in sources if s.source_name == "tsk.partitions"), None)
    if part_src:
        part_windows = ctx.db.get_windows_by_source("tsk.partitions")
        mmls_text = "\n".join(w.raw_text for w in part_windows)
        parsed = _parse_partition_offset(mmls_text)
        if parsed > 0:
            return parsed

    return _detect_partition_offset(image_path)


_tsk_extract_dirs: list[str] = []
_tsk_lock = threading.Lock()


def _cleanup_tsk_extract_dir(dir_path: str) -> None:
    """Remove a TSK extraction temp directory and deregister it.

    Callers should invoke this after consuming extracted files so that
    disk space is reclaimed promptly rather than at process exit.

    Args:
        dir_path: Absolute path to the temp directory to remove.
    """
    shutil.rmtree(dir_path, ignore_errors=True)
    with _tsk_lock, contextlib.suppress(ValueError):
        _tsk_extract_dirs.remove(dir_path)


def _run_fls_inline(image_path: str) -> str:
    """Run fls directly and return the output text without indexing to DB.

    Used when the pre-indexed ``tsk.filelist`` is not yet available
    (e.g. when extraction tools run concurrently with ``run_fls``).
    Persists the detected partition offset to the kv_store so that
    subsequent icat calls can reuse it.
    """
    if not require_binary("fls"):
        return ""
    offset = _resolve_partition_offset(image_path)
    cmd = ["fls", "-r", "-p"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=TOOL_TIMEOUT, check=False)
        if proc.returncode == 0:
            ctx = get_ctx()
            ctx.db.set_kv(f"{_KV_OFFSET_PREFIX}{image_path}", str(offset))
            return proc.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""


def _tsk_extract_files(
    image_path: str,
    path_patterns: list[str],
) -> list[tuple[str, Path]]:
    """Extract files from a disk image via TSK fls + icat.

    Searches the pre-indexed ``tsk.filelist`` for entries matching any of
    the *path_patterns* (case-insensitive substring match), then extracts
    each via ``icat`` to a temp directory.

    When the DB has no ``tsk.filelist`` source (e.g. ``run_fls`` has not
    completed yet), runs fls inline so the fallback is self-contained.

    Returns a list of ``(relative_path, extracted_path)`` tuples.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    fls_source = next((s for s in sources if s.source_name == "tsk.filelist"), None)

    fls_text_chunks: list[str] = []

    if fls_source is not None:
        windows = ctx.db.get_windows_by_source("tsk.filelist")
        fls_text_chunks = [w.raw_text for w in windows]
    else:
        logger.info(
            "tsk.filelist not yet indexed; running fls inline for TSK extraction from %s",
            image_path,
        )
        inline_output = _run_fls_inline(image_path)
        if inline_output:
            fls_text_chunks = [inline_output]

    if not fls_text_chunks:
        return []

    offset = _resolve_partition_offset(image_path)

    inode_re = re.compile(
        r"^[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.+)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )

    extract_dir = Path(tempfile.mkdtemp(prefix="mulder_tsk_extract_"))
    with _tsk_lock:
        _tsk_extract_dirs.append(str(extract_dir))
    ctx = get_ctx()
    ctx.db.set_kv("tsk_extract_dir", str(extract_dir))
    extracted: list[tuple[str, Path]] = []
    seen: set[str] = set()

    for chunk in fls_text_chunks:
        for m in inode_re.finditer(chunk):
            inode_str = m.group(1).split("-")[0]
            rel_path = m.group(2).strip()
            rel_lower = rel_path.lower().replace("\\", "/")

            if not any(pat.lower() in rel_lower for pat in path_patterns):
                continue
            if inode_str in seen:
                continue
            seen.add(inode_str)

            safe_name = rel_path.replace("/", "_").replace("\\", "_")
            out_path = extract_dir / safe_name
            cmd = ["icat"]
            if offset > 0:
                cmd.extend(["-o", str(offset)])
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
                    extracted.append((rel_path, out_path))
            except (subprocess.TimeoutExpired, OSError):
                continue

    return extracted


def _classify_mmls_failure(returncode: int, stderr: str) -> tuple[str, str, str]:
    """Classify an mmls failure into an error type, message, and suggestion.

    Returns:
        A (error_type, error_message, suggestion) tuple.
    """
    stderr_lower = stderr.strip().lower()

    ewf_indicators = ("ewf", "libewf", "e01", "expert witness")
    if any(kw in stderr_lower for kw in ewf_indicators):
        return (
            "ewf_unsupported",
            f"mmls cannot read this E01 image (exit {returncode}): {stderr[:300]}",
            "The SleuthKit binary may lack libewf support. "
            "Try mounting the E01 with ewfmount first, then pass the "
            "raw device path to run_fls with partition_offset=0.",
        )

    if not stderr_lower:
        return (
            "no_partition_table",
            f"mmls found no partition table (exit {returncode}). "
            "This image is likely a partition dump or single-filesystem "
            "image rather than a full disk.",
            "Skip mmls and call run_fls with partition_offset=0 to "
            "list files directly from the filesystem.",
        )

    return (
        "mmls_failed",
        f"mmls exited {returncode}: {stderr[:300]}",
        "If the image is a partition dump rather than a full disk, "
        "call run_fls with partition_offset=0 directly.",
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_mmls(image_path: str) -> dict[str, object]:
    """List partitions in a disk image using TSK mmls.

    Call first on any disk image to discover partition layout before
    running run_fls or other disk extraction tools.

    Indexes as ``tsk.partitions``; provides the sector offsets needed
    by downstream tools.

    Args:
        image_path: Path to the disk image (E01, dd, img).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not require_binary("mmls"):
        return error_response(
            tc_id, "run_mmls", params, "mmls not found on PATH", error_type="binary_missing"
        )

    try:
        proc = subprocess.run(
            ["mmls", image_path], capture_output=True, text=True, timeout=60, check=False
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_mmls", params, "mmls timed out", error_type="timeout")

    if proc.returncode != 0:
        stderr_text = (proc.stderr or "").strip()
        error_type, error_msg, suggestion = _classify_mmls_failure(proc.returncode, stderr_text)
        logger.info("mmls failed on %s: %s", image_path, error_type)
        return error_response(
            tc_id,
            "run_mmls",
            params,
            error_msg,
            error_type=error_type,
            suggestion=suggestion,
        )

    summary = extract_and_index(proc.stdout.strip(), "tsk.partitions", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_mmls", params, summary, "tsk.partitions", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_fls(
    image_path: str,
    partition_offset: int | None = None,
    force: bool = False,
) -> dict[str, object]:
    """List all files and directories (including deleted) from a disk image.

    Call after run_mmls on disk images. Partition offset is auto-detected
    if omitted. Required before run_evtx_parser and run_registry_parser
    which use the file listing to locate artifacts via inode extraction.

    Indexes as ``tsk.filelist``; entries marked with ``*`` are deleted
    files. Searchable via search(query, source='tsk.filelist').

    Args:
        image_path: Path to the disk image.
        partition_offset: Sector offset of the partition.  Auto-detected
            via mmls if omitted.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "partition_offset": partition_offset, "force": force}

    if not force:
        existing = sources_already_indexed(["tsk.filelist"], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "run_fls",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "tsk.filelist",
                0.0,
            )

    if not require_binary("fls"):
        return error_response(
            tc_id, "run_fls", params, "fls not found on PATH", error_type="binary_missing"
        )

    if partition_offset is None:
        partition_offset = _detect_partition_offset(image_path)

    cmd = ["fls", "-r", "-p"]
    if partition_offset > 0:
        cmd.extend(["-o", str(partition_offset)])
    cmd.append(image_path)

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=TOOL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_fls", params, "fls timed out", error_type="timeout")

    stdout_text = proc.stdout.decode("utf-8", errors="replace")
    stderr_text = (proc.stderr or b"").decode("utf-8", errors="replace")

    if proc.returncode != 0:
        stderr_hint = stderr_text[:_HINT_CHAR_LIMIT].strip()
        return error_response(
            tc_id,
            "run_fls",
            params,
            f"fls exited {proc.returncode} (tried partition_offset={partition_offset}). "
            f"Run run_mmls first to find the correct NTFS partition offset, then retry "
            f"run_fls with that offset. stderr: {stderr_hint}",
            error_type="extraction_failed",
        )

    ctx = get_ctx()
    ctx.db.set_kv(f"{_KV_OFFSET_PREFIX}{image_path}", str(partition_offset))

    summary = extract_and_index(stdout_text.strip(), "tsk.filelist", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_fls", params, summary, "tsk.filelist", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_mactime(image_path: str, time_range: str | None = None) -> dict[str, object]:
    """Generate a filesystem MAC timeline from a disk image using TSK fls + mactime.

    Call on disk images when you need file modification/access/change
    timestamps. Automatically detects partition offset. Use time_range
    to narrow to an incident window.

    Indexes as ``tsk.timeline``; timestamps are in mactime CSV format,
    queryable via search() and get_timeline().

    Args:
        image_path: Path to the disk image.
        time_range: Optional date range filter for mactime (e.g.
            "2015-08-01..2015-08-05").
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "time_range": time_range}

    for binary in ("fls", "mactime"):
        if not require_binary(binary):
            return error_response(tc_id, "run_mactime", params, f"{binary} not found on PATH")

    offset = _detect_partition_offset(image_path)
    fls_cmd = ["fls", "-r", "-m", "/"]
    if offset > 0:
        fls_cmd.extend(["-o", str(offset)])
    fls_cmd.append(image_path)

    try:
        fls_proc = subprocess.run(
            fls_cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_mactime", params, "fls timed out")

    if not fls_proc.stdout.strip():
        return error_response(tc_id, "run_mactime", params, "fls produced no bodyfile output")

    mac_cmd = ["mactime", "-b", "-", "-d"]
    if time_range:
        mac_cmd.extend(time_range.split(".."))

    try:
        mac_proc = subprocess.run(
            mac_cmd,
            input=fls_proc.stdout,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_mactime", params, "mactime timed out")

    summary = extract_and_index(mac_proc.stdout.strip(), "tsk.timeline", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_mactime", params, summary, "tsk.timeline", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_fsstat(image_path: str) -> dict[str, object]:
    """Retrieve filesystem metadata (type, block size, volume label) from a disk image.

    Call on disk images to identify the filesystem type and configuration
    before deeper analysis. Useful for confirming NTFS vs FAT vs ext.

    Indexes as ``tsk.fsstat``; output includes filesystem version, cluster
    size, and volume serial number.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not require_binary("fsstat"):
        return error_response(tc_id, "run_fsstat", params, "fsstat not found on PATH")

    offset = _detect_partition_offset(image_path)
    cmd = ["fsstat"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_fsstat", params, "fsstat timed out")

    summary = extract_and_index(proc.stdout.strip(), "tsk.fsstat", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_fsstat", params, summary, "tsk.fsstat", elapsed)
