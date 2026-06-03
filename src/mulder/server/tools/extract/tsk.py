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
    "_collect_fls_chunks",
    "_detect_partition_offset",
    "_parse_all_partitions",
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


_MMLS_ROW_RE = re.compile(
    r"^\s*\d+:\s*\S+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$",
    re.MULTILINE,
)
"""Regex matching mmls partition rows across TSK output variations.

Handles formats with or without leading whitespace, with or without
spaces in the slot field (e.g. ``002:000`` vs ``002:  000:000``).
Captures: (start_sector, length, description).
"""

_NTFS_INDICATORS = ("ntfs", "0x07", "win95 fat", "0x0b", "0x0c", "basic data")
_LINUX_INDICATORS = ("linux", "0x83", "ext", "0x8e")

_MIN_PARTITION_SECTORS = 204800
"""Minimum partition size in 512-byte sectors (~100 MB).

Partitions smaller than this threshold are skipped during multi-partition
analysis to avoid indexing tiny boot, EFI, or recovery stubs.
"""


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

    return _parse_partition_offset(proc.stdout)


def _parse_partition_offset(mmls_text: str) -> int:
    """Parse the primary data partition offset (in sectors) from mmls output.

    Searches for NTFS/Windows partitions first, then Linux, then falls
    back to the largest partition by sector count.
    """
    rows: list[tuple[int, int, str]] = [
        (int(m.group(1)), int(m.group(2)), m.group(3).strip().lower())
        for m in _MMLS_ROW_RE.finditer(mmls_text)
    ]
    if not rows:
        return 0

    # Find the LARGEST NTFS/Windows partition (not just the first)
    ntfs_parts = [
        (start, length, desc)
        for start, length, desc in rows
        if any(ind in desc for ind in _NTFS_INDICATORS) and length > 0
    ]
    if ntfs_parts:
        biggest_ntfs = max(ntfs_parts, key=lambda t: t[1])
        return biggest_ntfs[0]

    linux_parts = [
        (start, length, desc)
        for start, length, desc in rows
        if any(ind in desc for ind in _LINUX_INDICATORS) and length > 0
    ]
    if linux_parts:
        biggest_linux = max(linux_parts, key=lambda t: t[1])
        return biggest_linux[0]

    biggest = max(rows, key=lambda t: t[1])
    return biggest[0] if biggest[1] > 0 else 0


def _parse_all_partitions(mmls_text: str) -> list[tuple[int, int, str]]:
    """Parse all non-trivial data partitions from mmls output.

    Returns NTFS/Linux/data partitions above ``_MIN_PARTITION_SECTORS``
    sorted by sector count descending (largest first).  The first element
    is the primary partition used by downstream tools.

    Args:
        mmls_text: Raw stdout from ``mmls``.

    Returns:
        List of ``(start_sector, length, description)`` tuples.
    """
    rows: list[tuple[int, int, str]] = [
        (int(m.group(1)), int(m.group(2)), m.group(3).strip().lower())
        for m in _MMLS_ROW_RE.finditer(mmls_text)
    ]
    if not rows:
        return []

    data_parts: list[tuple[int, int, str]] = []
    for start, length, desc in rows:
        if length < _MIN_PARTITION_SECTORS:
            continue
        is_data = any(ind in desc for ind in _NTFS_INDICATORS) or any(
            ind in desc for ind in _LINUX_INDICATORS
        )
        if is_data:
            data_parts.append((start, length, desc))

    data_parts.sort(key=lambda t: t[1], reverse=True)
    return data_parts


_KV_OFFSET_PREFIX = "tsk_partition_offset:"
"""DB kv_store key prefix for persisted partition offsets."""

_KV_SOURCE_OFFSET_PREFIX = "tsk_source_offset:"
"""DB kv_store key mapping indexed source names to their partition offset.

Keys follow the pattern ``tsk_source_offset:{source_name}:{image_path}``.
"""


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


def _collect_fls_chunks(image_path: str) -> list[tuple[list[str], int]]:
    """Collect fls text chunks paired with their partition offsets.

    Gathers output from all indexed ``tsk.filelist*`` sources (primary
    and secondary partitions).  Each returned element is a ``(chunks,
    offset)`` pair representing one partition's file listing and the
    sector offset required for ``icat`` extraction.

    Falls back to ``_run_fls_inline`` on the primary partition when no
    indexed sources exist.

    Args:
        image_path: Path to the disk image.

    Returns:
        List of ``(text_chunks, sector_offset)`` pairs, one per partition.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    fls_sources = sorted(
        [s for s in sources if s.source_name.startswith("tsk.filelist")],
        key=lambda s: s.source_name,
    )

    if fls_sources:
        result: list[tuple[list[str], int]] = []
        for src in fls_sources:
            windows = ctx.db.get_windows_by_source(src.source_name)
            chunks = [w.raw_text for w in windows]
            if not chunks:
                continue

            stored = ctx.db.get_kv(f"{_KV_SOURCE_OFFSET_PREFIX}{src.source_name}:{image_path}")
            if stored is not None:
                with contextlib.suppress(ValueError):
                    offset = int(stored)
                    result.append((chunks, offset))
                    continue
            result.append((chunks, _resolve_partition_offset(image_path)))
        return result

    inline_output = _run_fls_inline(image_path)
    if inline_output:
        offset = _resolve_partition_offset(image_path)
        return [([inline_output], offset)]
    return []


def _discover_partitions(image_path: str) -> list[tuple[int, int, str]]:
    """Discover all non-trivial partitions for *image_path*.

    Checks the indexed ``tsk.partitions`` source first, then falls back
    to running ``mmls`` directly.

    Args:
        image_path: Path to the disk image.

    Returns:
        List of ``(start_sector, length, description)`` from
        ``_parse_all_partitions``, largest first.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    part_src = next((s for s in sources if s.source_name == "tsk.partitions"), None)

    if part_src:
        windows = ctx.db.get_windows_by_source("tsk.partitions")
        mmls_text = "\n".join(w.raw_text for w in windows)
        return _parse_all_partitions(mmls_text)

    if not require_binary("mmls"):
        return []
    try:
        proc = subprocess.run(
            ["mmls", image_path], capture_output=True, text=True, timeout=30, check=False
        )
        if proc.returncode != 0:
            return []
        return _parse_all_partitions(proc.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return []


def _index_secondary_partitions(
    image_path: str,
    primary_offset: int,
) -> list[dict[str, object]]:
    """Run fls on non-primary partitions and index their output.

    Each secondary partition is indexed as ``tsk.filelist.p{i}`` with
    its sector offset stored in the kv_store for downstream extraction.

    Args:
        image_path: Path to the disk image.
        primary_offset: Sector offset of the primary (largest) partition,
            used to exclude it from the secondary list.

    Returns:
        List of ``extract_and_index`` summary dicts, one per indexed
        secondary partition.
    """
    all_parts = _discover_partitions(image_path)
    secondary_parts = [
        (start, length, desc) for start, length, desc in all_parts if start != primary_offset
    ]
    if not secondary_parts:
        return []

    ctx = get_ctx()
    summaries: list[dict[str, object]] = []
    for i, (start, _length, desc) in enumerate(secondary_parts, 1):
        source_name = f"tsk.filelist.p{i}"
        try:
            proc = subprocess.run(
                ["fls", "-r", "-p", "-o", str(start), image_path],
                capture_output=True,
                timeout=TOOL_TIMEOUT,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            logger.warning("fls timed out on secondary partition at offset %d", start)
            continue

        if proc.returncode != 0:
            logger.info(
                "fls failed on secondary partition at offset %d (%s), skipping",
                start,
                desc,
            )
            continue

        stdout_text = proc.stdout.decode("utf-8", errors="replace").strip()
        if not stdout_text:
            continue

        ctx.db.set_kv(
            f"{_KV_SOURCE_OFFSET_PREFIX}{source_name}:{image_path}",
            str(start),
        )
        summary = extract_and_index(stdout_text, source_name, image_path, "sleuthkit")
        summary["partition_offset"] = start
        summary["partition_description"] = desc
        summaries.append(summary)
        logger.info(
            "Indexed secondary partition %s: offset=%d, desc=%s",
            source_name,
            start,
            desc,
        )

    return summaries


def _tsk_extract_files(
    image_path: str,
    path_patterns: list[str],
) -> list[tuple[str, Path]]:
    """Extract files from a disk image via TSK fls + icat.

    Searches all indexed ``tsk.filelist*`` sources (primary and secondary
    partitions) for entries matching any of the *path_patterns*
    (case-insensitive substring match), then extracts each via ``icat``
    using the correct partition offset.

    When no indexed sources exist (e.g. ``run_fls`` has not completed
    yet), runs fls inline on the primary partition as a fallback.

    Args:
        image_path: Path to the disk image.
        path_patterns: Substring patterns to match against file paths.

    Returns:
        List of ``(relative_path, extracted_path)`` tuples.
    """
    chunk_groups = _collect_fls_chunks(image_path)
    if not chunk_groups:
        return []

    ctx = get_ctx()
    inode_re = re.compile(
        r"^[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.+)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )

    extract_dir: Path | None = None
    extracted: list[tuple[str, Path]] = []
    seen: set[str] = set()

    for chunks, offset in chunk_groups:
        for chunk in chunks:
            for m in inode_re.finditer(chunk):
                inode_str = m.group(1).split("-")[0]
                rel_path = m.group(2).strip()
                rel_lower = rel_path.lower().replace("\\", "/")

                if not any(pat.lower() in rel_lower for pat in path_patterns):
                    continue
                dedup_key = f"{offset}:{inode_str}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                if extract_dir is None:
                    extract_dir = Path(tempfile.mkdtemp(prefix="mulder_tsk_extract_"))
                    with _tsk_lock:
                        _tsk_extract_dirs.append(str(extract_dir))
                    ctx.db.set_kv("tsk_extract_dir", str(extract_dir))

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

    Indexes the primary (largest) partition as ``tsk.filelist`` and any
    additional non-trivial partitions as ``tsk.filelist.p1``,
    ``tsk.filelist.p2``, etc.  Entries marked with ``*`` are deleted
    files.  Searchable via ``search(query, source='tsk.filelist')``.

    Args:
        image_path: Path to the disk image.
        partition_offset: Sector offset of the partition.  Auto-detected
            via mmls if omitted.  When provided explicitly, only that
            single partition is analyzed.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "partition_offset": partition_offset, "force": force}
    explicit_offset = partition_offset is not None

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
        ctx = get_ctx()
        stored = ctx.db.get_kv(f"{_KV_OFFSET_PREFIX}{image_path}")
        if stored is not None:
            with contextlib.suppress(ValueError):
                partition_offset = int(stored)
        if partition_offset is None:
            partition_offset = 0

    def _try_fls(offset: int) -> subprocess.CompletedProcess[bytes]:
        cmd = ["fls", "-r", "-p"]
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.append(image_path)
        return subprocess.run(cmd, capture_output=True, timeout=TOOL_TIMEOUT, check=False)

    try:
        proc = _try_fls(partition_offset)
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_fls", params, "fls timed out", error_type="timeout")

    if proc.returncode != 0 and partition_offset == 0:
        detected = _detect_partition_offset(image_path)
        if detected > 0:
            logger.info(
                "run_fls: offset 0 failed, retrying with mmls-detected offset %d",
                detected,
            )
            try:
                proc = _try_fls(detected)
                partition_offset = detected
            except subprocess.TimeoutExpired:
                return error_response(
                    tc_id, "run_fls", params, "fls timed out on retry", error_type="timeout"
                )

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
    ctx.db.set_kv(
        f"{_KV_SOURCE_OFFSET_PREFIX}tsk.filelist:{image_path}",
        str(partition_offset),
    )

    summary = extract_and_index(stdout_text.strip(), "tsk.filelist", image_path, "sleuthkit")

    if not explicit_offset:
        secondary = _index_secondary_partitions(image_path, partition_offset)
        if secondary:
            summary["secondary_partitions"] = secondary

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

    offset = _resolve_partition_offset(image_path)
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

    offset = _resolve_partition_offset(image_path)
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
