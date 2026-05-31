"""SleuthKit (TSK) filesystem analysis MCP tools."""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
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
    tool_response,
)

__all__ = [
    "_parse_partition_offset",
    "_tsk_extract_dirs",
    "_tsk_extract_files",
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


_tsk_extract_dirs: list[str] = []


def _tsk_extract_files(
    image_path: str,
    path_patterns: list[str],
) -> list[tuple[str, Path]]:
    """Extract files from a disk image via TSK fls + icat.

    Searches the pre-indexed ``tsk.filelist`` for entries matching any of
    the *path_patterns* (case-insensitive substring match), then extracts
    each via ``icat`` to a temp directory.

    Returns a list of ``(relative_path, extracted_path)`` tuples.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    fls_source = next((s for s in sources if s.source_name == "tsk.filelist"), None)
    if fls_source is None:
        return []

    windows = ctx.db.get_windows_by_source("tsk.filelist")
    part_src = next((s for s in sources if s.source_name == "tsk.partitions"), None)
    offset = 0
    if part_src:
        part_windows = ctx.db.get_windows_by_source("tsk.partitions")
        mmls_text = "\n".join(w.raw_text for w in part_windows)
        offset = _parse_partition_offset(mmls_text)

    inode_re = re.compile(
        r"^[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.+)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )

    extract_dir = Path(tempfile.mkdtemp(prefix="mulder_tsk_extract_"))
    _tsk_extract_dirs.append(str(extract_dir))
    extracted: list[tuple[str, Path]] = []
    seen: set[str] = set()

    for w in windows:
        for m in inode_re.finditer(w.raw_text):
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


@mcp.tool()
def run_mmls(image_path: str) -> dict[str, object]:
    """List partitions in a disk image using TSK mmls.

    Shows partition layout including type, start sector, and size.
    Indexes the output for later reference.

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
        return error_response(
            tc_id,
            "run_mmls",
            params,
            f"mmls exited {proc.returncode}: {(proc.stderr or '')[:300]}",
        )

    summary = extract_and_index(proc.stdout.strip(), "tsk.partitions", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_mmls", params, summary, "tsk.partitions", elapsed)


@mcp.tool()
def run_fls(image_path: str, partition_offset: int | None = None) -> dict[str, object]:
    """Run recursive file listing on a disk image using TSK fls.

    Lists all files and directories (including deleted entries marked
    with ``*``).  Indexes the output for searching and deleted file
    detection.

    Args:
        image_path: Path to the disk image.
        partition_offset: Sector offset of the partition.  Auto-detected
            via mmls if omitted.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "partition_offset": partition_offset}

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

    summary = extract_and_index(stdout_text.strip(), "tsk.filelist", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_fls", params, summary, "tsk.filelist", elapsed)


@mcp.tool()
def run_mactime(image_path: str, time_range: str | None = None) -> dict[str, object]:
    """Generate a MAC timeline from a disk image using TSK fls + mactime.

    Creates a filesystem timeline showing file creation, modification,
    access, and change times.  Optionally filter to a date range.

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
def run_fsstat(image_path: str) -> dict[str, object]:
    """Get filesystem statistics from a disk image using TSK fsstat.

    Shows filesystem type, block size, volume label, and other metadata.

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
