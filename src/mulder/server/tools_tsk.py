"""Sleuth Kit MCP tools for filesystem forensics.

Ingest-time tools query pre-extracted TSK data from the case database.
Query-time tools shell out to ``icat`` and ``istat`` for on-demand file
extraction and metadata retrieval.  All tools are read-only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import subprocess
import time
from uuid import uuid4

from mulder.server.app import get_ctx, mcp

logger = logging.getLogger(__name__)

_SRC_PARTITIONS = "tsk.partitions"
_SRC_FILELIST = "tsk.filelist"
_SRC_TIMELINE = "tsk.timeline"
_SRC_FSSTAT = "tsk.fsstat"
_SRC_ICAT = "tsk.icat"
_SRC_ISTAT = "tsk.istat"

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

_cached_image_info: tuple[str, int] | None = None


def _make_tool_call_id() -> str:
    return f"tc_{uuid4().hex[:8]}"


def _hash_output(output: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(output, sort_keys=True, default=str).encode()).hexdigest()
    )


def _serialize_windows(windows: list) -> list[dict]:
    return [w.model_dump() for w in windows]


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


def _resolve_image_and_offset() -> tuple[str, int]:
    """Resolve the disk image path and partition offset from ingested TSK data.

    Reads the ``tsk.partitions`` source metadata and window text to
    determine the image path (from ``source_path``) and the partition
    offset used during ingest.  Result is cached for the session.
    """
    global _cached_image_info  # noqa: PLW0603
    if _cached_image_info is not None:
        return _cached_image_info

    ctx = get_ctx()
    sources = ctx.db.get_sources()
    tsk_source = next((s for s in sources if s.source_name == _SRC_PARTITIONS), None)

    if tsk_source is None:
        _cached_image_info = (_find_tsk_source_path(), 0)
        return _cached_image_info

    windows = ctx.db.get_windows_by_source(_SRC_PARTITIONS)
    mmls_text = "\n".join(w.raw_text for w in windows)
    offset = _parse_offset_from_windows(mmls_text)

    _cached_image_info = (tsk_source.source_path, offset)
    return _cached_image_info


# ------------------------------------------------------------------
# Tool: list_partitions
# ------------------------------------------------------------------


@mcp.tool()
def list_partitions() -> dict:
    """Return the partition table extracted from the disk image (TSK mmls).

    Shows partition layout including type, start sector, end sector,
    and size.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PARTITIONS)
    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="list_partitions",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_PARTITIONS,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: list_files
# ------------------------------------------------------------------


@mcp.tool()
def list_files(
    path_filter: str | None = None,
    include_deleted: bool = False,
) -> dict:
    """List files from the disk image filesystem (TSK fls).

    Returns the recursive file listing extracted at ingest time.
    Optionally filter by *path_filter* substring.  Set *include_deleted*
    to True to include only deleted files (marked with ``*`` by TSK).
    Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_FILELIST)

    if include_deleted:
        windows = [w for w in windows if "* " in w.raw_text]

    if path_filter:
        pf_lower = path_filter.lower()
        windows = [w for w in windows if pf_lower in w.raw_text.lower()]

    results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="list_files",
        params={"path_filter": path_filter, "include_deleted": include_deleted},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_FILELIST,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_deleted_files
# ------------------------------------------------------------------


@mcp.tool()
def get_deleted_files() -> dict:
    """Return deleted files detected in the disk image (TSK fls).

    TSK marks deleted entries with a ``*`` prefix.  This tool filters
    the full file listing to show only those entries.  Useful for
    detecting evidence tampering or recovering deleted artifacts.
    Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_FILELIST)
    deleted = [w for w in windows if "* " in w.raw_text]
    results = _serialize_windows(deleted)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_deleted_files",
        params={},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_FILELIST,
        "result_count": len(results),
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_fs_timeline
# ------------------------------------------------------------------


@mcp.tool()
def get_fs_timeline(t_start: str, t_end: str) -> dict:
    """Return the filesystem timeline (mactime) within a time range.

    The timeline is generated from TSK ``fls`` bodyfile output processed
    through ``mactime``.  Large results are Cordon-reduced to keep
    context-window usage manageable.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.query_engine.get_windows_in_range(_SRC_TIMELINE, t_start, t_end)

    reduced = False
    reduction_ratio: float | None = None
    raw_text = "\n".join(w.raw_text for w in windows)
    if raw_text and ctx.reducer.should_reduce(_SRC_TIMELINE, len(raw_text)):
        reduced_out = ctx.reducer.reduce(raw_text)
        blocks = [b.model_dump() for b in reduced_out.blocks]
        results: list[dict] = [{"reduced_text": reduced_out.text, "blocks": blocks}]
        reduced = True
        reduction_ratio = reduced_out.reduction_ratio
    else:
        results = _serialize_windows(windows)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_fs_timeline",
        params={"t_start": t_start, "t_end": t_end},
        output_hash=_hash_output(results),
        cordon_ratio=reduction_ratio,
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_TIMELINE,
        "result_count": len(results),
        "reduced": reduced,
        "reduction_ratio": reduction_ratio,
    }


# ------------------------------------------------------------------
# Tool: extract_file_by_inode
# ------------------------------------------------------------------


@mcp.tool()
def extract_file_by_inode(inode: int) -> dict:
    """Extract a file from the disk image by inode number using TSK icat.

    For text files the content is returned directly (capped at 1 MB).
    For binary files a SHA-256 hash and size are returned instead.
    Requires ``icat`` on PATH.  Read-only against the original image.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    if not shutil.which("icat"):
        error_msg = "icat not found on PATH"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="extract_file_by_inode",
            params={"inode": inode},
            output_hash=_hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_ICAT,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    image_path, offset = _resolve_image_and_offset()
    cmd = ["icat"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image_path, str(inode)])

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
            output_hash=_hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_ICAT,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    raw = proc.stdout
    if proc.returncode != 0:
        error_msg = f"icat exited {proc.returncode}"
        stderr_text = (proc.stderr or b"").decode("utf-8", errors="replace")[:500]
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="extract_file_by_inode",
            params={"inode": inode},
            output_hash=_hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"{error_msg}: {stderr_text}".rstrip(": "),
            "results": [],
            "source": _SRC_ICAT,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    if b"\x00" in raw[:8192]:
        file_hash = hashlib.sha256(raw).hexdigest()
        results = {
            "type": "binary",
            "inode": inode,
            "size_bytes": len(raw),
            "sha256": file_hash,
        }
    else:
        text = raw[:_MAX_TEXT_BYTES].decode("utf-8", errors="replace")
        results = {
            "type": "text",
            "inode": inode,
            "size_bytes": len(raw),
            "content": text,
            "truncated": len(raw) > _MAX_TEXT_BYTES,
        }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="extract_file_by_inode",
        params={"inode": inode},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_ICAT,
        "result_count": 1,
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: get_file_metadata
# ------------------------------------------------------------------


@mcp.tool()
def get_file_metadata(inode: int) -> dict:
    """Return file metadata (MAC times, size, blocks) for an inode using TSK istat.

    Shells out to ``istat`` at query time.  Requires ``istat`` on PATH.
    Read-only against the original image.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    if not shutil.which("istat"):
        error_msg = "istat not found on PATH"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="get_file_metadata",
            params={"inode": inode},
            output_hash=_hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_ISTAT,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    image_path, offset = _resolve_image_and_offset()
    cmd = ["istat"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image_path, str(inode)])

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
            output_hash=_hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_ISTAT,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    if proc.returncode != 0:
        error_msg = f"istat exited {proc.returncode}"
        stderr_text = (proc.stderr or "")[:500]
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="get_file_metadata",
            params={"inode": inode},
            output_hash=_hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"{error_msg}: {stderr_text}".rstrip(": "),
            "results": [],
            "source": _SRC_ISTAT,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    results = {
        "inode": inode,
        "metadata": proc.stdout.strip(),
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="get_file_metadata",
        params={"inode": inode},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": _SRC_ISTAT,
        "result_count": 1,
        "reduced": False,
        "reduction_ratio": None,
    }
