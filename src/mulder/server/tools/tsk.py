"""Sleuth Kit MCP tools for filesystem forensics.

Ingest-time tools query pre-extracted TSK data from the case database.
Query-time tools shell out to ``icat`` and ``istat`` for on-demand file
extraction and metadata retrieval.  All tools are read-only.
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import subprocess
import time

from mulder.server import source_names as _sn
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    _PREVIEW_CHAR_LIMIT,
    hash_output,
    make_tool_call_id,
    windowed_response,
)

logger = logging.getLogger(__name__)

_SRC_PARTITIONS = _sn.SRC_TSK_PARTITIONS
_SRC_FILELIST = _sn.SRC_TSK_FILELIST
_SRC_TIMELINE = _sn.SRC_TSK_TIMELINE
_SRC_ICAT = _sn.SRC_TSK_ICAT
_SRC_ISTAT = _sn.SRC_TSK_ISTAT

_ICAT_TIMEOUT = 30
_ISTAT_TIMEOUT = 15
_MAX_TEXT_BYTES = 1024 * 1024  # 1 MB cap for text file extraction

# Matches mmls partition rows to extract the offset used during ingest.
_MMLS_ROW_RE = re.compile(
    r"^\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$",
    re.MULTILINE,
)
_NTFS_INDICATORS = ("ntfs", "exfat", "0x07", "win95 fat", "0x0b", "0x0c")
_LINUX_INDICATORS = ("linux", "0x83", "ext", "0x8e")

_cached_image_info: dict[str, tuple[str, int, str | None]] = {}

_FSSTAT_TYPE_RE = re.compile(r"File System Type:\s*(.+)", re.IGNORECASE)


def _find_tsk_source_path() -> str:
    """Find the disk image path from any ingested TSK source."""
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    for s in sources:
        if s.source_name.startswith("tsk."):
            return s.source_path
    raise RuntimeError("No TSK sources found in this case. Was the disk image ingested?")


def _parse_offset_from_windows(mmls_text: str) -> int:
    """Parse partition offset from mmls text, preferring NTFS then Linux."""
    rows: list[tuple[int, int, str]] = [
        (int(m.group(1)), int(m.group(2)), m.group(3).strip().lower())
        for m in _MMLS_ROW_RE.finditer(mmls_text)
    ]
    if not rows:
        return 0

    for start, length, desc in rows:
        if any(ind in desc for ind in _NTFS_INDICATORS) and length > 0:
            return start

    for start, length, desc in rows:
        if any(ind in desc for ind in _LINUX_INDICATORS) and length > 0:
            return start

    biggest = max(rows, key=lambda t: t[1])
    return biggest[0] if biggest[1] > 0 else 0


def _detect_filesystem_type(image_path: str, offset: int) -> str | None:
    """Run ``fsstat`` to determine the filesystem type at *offset*.

    Returns a TSK filesystem type string (``ntfs``, ``ext4``, ``hfs``,
    ``fat32``, etc.) or ``None`` when detection fails.
    """
    fsstat = shutil.which("fsstat")
    if not fsstat:
        return None
    cmd = ["fsstat"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0:
            return None
        m = _FSSTAT_TYPE_RE.search(proc.stdout)
        if m:
            raw = m.group(1).strip().lower()
            if "ntfs" in raw:
                return "ntfs"
            if "fat32" in raw or "fat16" in raw or "fat12" in raw:
                return "fat"
            if "exfat" in raw:
                return "exfat"
            if "ext" in raw:
                return "ext"
            if "hfs" in raw:
                return "hfs"
            if "ufs" in raw:
                return "ufs"
            return raw.split()[0] if raw else None
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _resolve_image_and_offset() -> tuple[str, int, str | None]:
    """Resolve the disk image path, partition offset, and filesystem type.

    Reads the ``tsk.partitions`` source metadata and window text to
    determine the image path (from ``source_path``) and the partition
    offset used during ingest.  Also runs ``fsstat`` to detect the
    filesystem type for use with ``-f`` flag in icat/istat.
    Result is cached per case_id so switching cases invalidates stale data.
    """
    ctx = get_ctx()
    cache_key = ctx.case_id
    if cache_key in _cached_image_info:
        return _cached_image_info[cache_key]

    sources = ctx.db.get_sources()
    tsk_source = next((s for s in sources if s.source_name == _SRC_PARTITIONS), None)

    if tsk_source is None:
        image_path = _find_tsk_source_path()
        fs_type = _detect_filesystem_type(image_path, 0)
        result = (image_path, 0, fs_type)
        _cached_image_info[cache_key] = result
        return result

    windows = ctx.db.get_windows_by_source(_SRC_PARTITIONS)
    mmls_text = "\n".join(w.raw_text for w in windows)
    offset = _parse_offset_from_windows(mmls_text)
    fs_type = _detect_filesystem_type(tsk_source.source_path, offset)

    result = (tsk_source.source_path, offset, fs_type)
    _cached_image_info[cache_key] = result
    return result


@mcp.tool()
def list_partitions() -> dict[str, object]:
    """Return the partition table extracted from the disk image (TSK mmls).

    Shows partition layout including type, start sector, end sector,
    and size.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PARTITIONS)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_PARTITIONS, "list_partitions", {}, elapsed)


@mcp.tool()
def list_files(
    path_filter: str | None = None,
    include_deleted: bool = False,
) -> dict[str, object]:
    """List files from the disk image filesystem (TSK fls).

    Returns a summary of matching files with counts. Use search() to
    find specific files by name or path, and get_raw_output() to
    paginate through the full listing.

    Args:
        path_filter: Optional substring filter on file paths.
        include_deleted: If True, only show deleted files (TSK ``*`` marker).
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_FILELIST)

    if include_deleted:
        windows = [w for w in windows if "* " in w.raw_text]

    if path_filter:
        pf_lower = path_filter.lower()
        windows = [w for w in windows if pf_lower in w.raw_text.lower()]

    total_entries = sum(w.raw_text.count("\n") + 1 for w in windows)

    top_dirs: dict[str, int] = {}
    for w in windows[:50]:
        for line in w.raw_text.split("\n"):
            parts = line.split("\t")
            if len(parts) >= 2:
                path = parts[-1].strip()
                top_dir = path.split("/")[0] if "/" in path else path
                top_dirs[top_dir] = top_dirs.get(top_dir, 0) + 1

    sorted_dirs = sorted(top_dirs.items(), key=lambda x: -x[1])[:20]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="list_files",
        params={"path_filter": path_filter, "include_deleted": include_deleted},
        output_hash=hash_output({"total": len(windows)}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "source": _SRC_FILELIST,
        "total_windows": len(windows),
        "approx_file_count": total_entries,
        "top_directories": [{"name": d, "entries": c} for d, c in sorted_dirs],
        "hint": (
            f"Showing summary of {total_entries} entries. "
            f"Use search(query, source='tsk.filelist') to find specific files, "
            f"or get_raw_output('tsk.filelist') to paginate the full listing."
        ),
    }


@mcp.tool()
def get_deleted_files() -> dict[str, object]:
    """Return a summary of deleted files detected in the disk image.

    TSK marks deleted entries with a ``*`` prefix. Returns counts and
    top directories containing deleted files. Use search() to find
    specific deleted files by name.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_FILELIST)
    deleted = [w for w in windows if "* " in w.raw_text]

    total_entries = sum(w.raw_text.count("\n") + 1 for w in deleted)

    top_dirs: dict[str, int] = {}
    for w in deleted[:50]:
        for line in w.raw_text.split("\n"):
            if "* " not in line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                path = parts[-1].strip()
                top_dir = path.split("/")[0] if "/" in path else path
                top_dirs[top_dir] = top_dirs.get(top_dir, 0) + 1

    sorted_dirs = sorted(top_dirs.items(), key=lambda x: -x[1])[:20]

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_deleted_files",
        params={},
        output_hash=hash_output({"total": len(deleted)}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "source": _SRC_FILELIST,
        "total_windows": len(deleted),
        "approx_deleted_count": total_entries,
        "top_directories": [{"name": d, "entries": c} for d, c in sorted_dirs],
        "hint": (
            f"{total_entries} deleted entries found. "
            f"Use search('* ', source='tsk.filelist') to find specific "
            f"deleted files, or get_raw_output('tsk.filelist') to browse."
        ),
    }


@mcp.tool()
def get_fs_timeline(t_start: str, t_end: str) -> dict[str, object]:
    """Return the filesystem timeline (mactime) within a time range.

    The timeline is generated from TSK ``fls`` bodyfile output processed
    through ``mactime``.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_TIMELINE, t_start, t_end)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(
        tc_id,
        windows,
        _SRC_TIMELINE,
        "get_fs_timeline",
        {"t_start": t_start, "t_end": t_end},
        elapsed,
    )


def _build_tsk_cmd(
    tool: str,
    image_path: str,
    offset: int,
    fs_type: str | None,
) -> list[str]:
    """Build the base TSK command with optional offset and filesystem type."""
    cmd = [tool]
    if fs_type:
        cmd.extend(["-f", fs_type])
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)
    return cmd


@mcp.tool()
def extract_file_by_inode(inode: int, filesystem_type: str | None = None) -> dict[str, object]:
    """Extract a file from the disk image by inode number using TSK icat.

    For text files the content is returned directly (capped at 1 MB).
    For binary files a SHA-256 hash and size are returned instead.
    Requires ``icat`` on PATH.  Read-only against the original image.

    Args:
        inode: The inode number of the file to extract.
        filesystem_type: Optional TSK filesystem type (e.g. "ntfs", "ext",
            "fat", "hfs").  Auto-detected via ``fsstat`` when omitted.
            Specify manually if auto-detection fails on raw DD images.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if not shutil.which("icat"):
        error_msg = "icat not found on PATH"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="extract_file_by_inode",
            params={"inode": inode},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_ICAT,
            "result_count": 0,
        }

    image_path, offset, detected_fs = _resolve_image_and_offset()
    fs_type = filesystem_type or detected_fs
    cmd = _build_tsk_cmd("icat", image_path, offset, fs_type)
    cmd.append(str(inode))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_ICAT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        error_msg = f"icat timed out after {_ICAT_TIMEOUT}s for inode {inode}"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="extract_file_by_inode",
            params={"inode": inode},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_ICAT,
            "result_count": 0,
        }

    raw = proc.stdout
    if proc.returncode != 0:
        error_msg = f"icat exited {proc.returncode}"
        stderr_text = (proc.stderr or b"").decode("utf-8", errors="replace")[:_PREVIEW_CHAR_LIMIT]
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="extract_file_by_inode",
            params={"inode": inode},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"{error_msg}: {stderr_text}".rstrip(": "),
            "results": [],
            "source": _SRC_ICAT,
            "result_count": 0,
        }

    if b"\x00" in raw[:8192]:
        file_hash = hashlib.sha256(raw).hexdigest()
        results: dict[str, object] = {
            "type": "binary",
            "inode": inode,
            "size_bytes": len(raw),
            "sha256": file_hash,
        }
    else:
        text = raw[:_MAX_TEXT_BYTES].decode("utf-8", errors="replace")
        source_name = f"tsk.extracted.{inode}"
        index_summary: dict[str, object] = {}
        if text.strip():
            index_summary = extract_and_index(text, source_name, image_path, "icat")
        results = {
            "type": "text",
            "inode": inode,
            "size_bytes": len(raw),
            "source_name": source_name,
            "windows_indexed": index_summary.get("windows_indexed", 0),
            "hint": f"Use get_raw_output('{source_name}') to read the file content.",
        }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="extract_file_by_inode",
        params={"inode": inode},
        output_hash=hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_ICAT,
        "result_count": 1,
    }


@mcp.tool()
def get_file_metadata(inode: int, filesystem_type: str | None = None) -> dict[str, object]:
    """Return file metadata (MAC times, size, blocks) for an inode using TSK istat.

    Shells out to ``istat`` at query time.  Requires ``istat`` on PATH.
    Read-only against the original image.

    Args:
        inode: The inode number of the file.
        filesystem_type: Optional TSK filesystem type (e.g. "ntfs", "ext",
            "fat", "hfs").  Auto-detected via ``fsstat`` when omitted.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if not shutil.which("istat"):
        error_msg = "istat not found on PATH"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="get_file_metadata",
            params={"inode": inode},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_ISTAT,
            "result_count": 0,
        }

    image_path, offset, detected_fs = _resolve_image_and_offset()
    fs_type = filesystem_type or detected_fs
    cmd = _build_tsk_cmd("istat", image_path, offset, fs_type)
    cmd.append(str(inode))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_ISTAT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        error_msg = f"istat timed out after {_ISTAT_TIMEOUT}s for inode {inode}"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="get_file_metadata",
            params={"inode": inode},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_ISTAT,
            "result_count": 0,
        }

    if proc.returncode != 0:
        error_msg = f"istat exited {proc.returncode}"
        stderr_text = (proc.stderr or "")[:_PREVIEW_CHAR_LIMIT]
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="get_file_metadata",
            params={"inode": inode},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"{error_msg}: {stderr_text}".rstrip(": "),
            "results": [],
            "source": _SRC_ISTAT,
            "result_count": 0,
        }

    output_text = proc.stdout.strip()
    source_name = f"tsk.metadata.{inode}"

    index_summary: dict[str, object] = {}
    if output_text:
        index_summary = extract_and_index(output_text, source_name, image_path, "istat")

    results: dict[str, object] = {
        "inode": inode,
        "source_name": source_name,
        "windows_indexed": index_summary.get("windows_indexed", 0),
        "hint": f"Use get_raw_output('{source_name}') to read the metadata.",
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_file_metadata",
        params={"inode": inode},
        output_hash=hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_ISTAT,
        "result_count": 1,
    }
