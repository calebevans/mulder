"""Application directory file indexer for disk image forensics.

Discovers, extracts, and indexes readable text and configuration files
from application directories on disk images. This is a general-purpose
extraction tool that makes raw application data searchable without
requiring format-specific parsers.
"""

from __future__ import annotations

import fnmatch
import logging
import shutil
import subprocess
import time
from typing import Any

from mulder.patterns import fls_file_entries
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import (
    _collect_fls_chunks,
)

__all__ = ["index_app_files"]

logger = logging.getLogger(__name__)

_DEFAULT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".ini",
        ".cfg",
        ".conf",
        ".txt",
        ".log",
        ".xml",
        ".json",
        ".yaml",
        ".yml",
        ".properties",
        ".csv",
        ".bat",
        ".cmd",
        ".ps1",
        ".reg",
        ".inf",
        ".manifest",
    }
)

_ICAT_TIMEOUT = 30
_MAX_TEXT_BYTES = 512 * 1024


def _derive_source_name(directory_pattern: str) -> str:
    """Generate a source identifier from the directory pattern.

    Normalizes the pattern into a dot-separated source name suitable
    for indexing. Strips wildcards and path separators, collapses
    spaces to underscores.

    Args:
        directory_pattern: The original directory pattern.

    Returns:
        Source string like ``appfiles.program_files.mirc``.
    """
    normalized = directory_pattern.lower().replace("\\", "/")
    parts = [p for p in normalized.split("/") if p and p != "*"]
    parts = [p.replace(" ", "_") for p in parts]
    slug = ".".join(parts[:3])
    return f"appfiles.{slug}"


def _find_matching_files(
    fls_chunks: list[str],
    directory_pattern: str,
    extensions: frozenset[str],
    offset: int,
) -> list[tuple[str, str, int]]:
    """Search TSK file listing for text files under matching directories.

    Filters the fls output for files whose paths match the directory
    pattern and whose extensions are in the allowed set.

    Args:
        fls_chunks: Text chunks from the TSK file listing.
        directory_pattern: Glob-style directory pattern to match paths.
        extensions: Set of allowed file extensions (lowercase, with dot).
        offset: Partition sector offset for icat extraction.

    The size threshold is not applied here: ``fls -r -p`` prints no size
    column (that needs ``fls -l``), so it is enforced on the bytes ``icat``
    returns instead.

    Returns:
        List of ``(inode_str, relative_path, partition_offset)`` tuples
        for files matching the criteria.
    """
    glob_pattern = directory_pattern.lower().replace("\\", "/").rstrip("/") + "/*"
    matches: list[tuple[str, str, int]] = []
    seen_inodes: set[str] = set()

    for chunk in fls_chunks:
        for entry in fls_file_entries(chunk):
            inode_str = entry.base_inode
            rel_path = entry.path
            rel_lower = rel_path.lower().replace("\\", "/")

            if not fnmatch.fnmatch(rel_lower, glob_pattern):
                continue

            dot_pos = rel_lower.rfind(".")
            if dot_pos < 0:
                continue
            ext = rel_lower[dot_pos:]
            if ext not in extensions:
                continue

            dedup_key = f"{offset}:{inode_str}"
            if dedup_key in seen_inodes:
                continue
            seen_inodes.add(dedup_key)

            matches.append((inode_str, rel_path, offset))

    return matches


def _is_binary_content(data: bytes) -> bool:
    """Check if data appears to be binary by looking for null bytes.

    Args:
        data: Raw file content to inspect.

    Returns:
        True if null bytes are found in the first 1024 bytes.
    """
    return b"\x00" in data[:1024]


def _extract_and_read_file(
    image_path: str,
    inode_str: str,
    offset: int,
    max_size_bytes: int | None = None,
) -> str | None:
    """Extract a file via icat and return its text content.

    Returns None if icat fails, the file is binary, or the file
    exceeds the text size limit.

    Args:
        image_path: Path to the disk image.
        inode_str: TSK inode identifier.
        offset: Partition sector offset.
        max_size_bytes: Skip the file when it is larger than this. The
            caller's ``max_file_size_kb`` used to be checked against a size
            field parsed out of the fls listing, but ``fls -r -p`` does not
            print one, so nothing was ever skipped.

    Returns:
        Decoded text content or None if extraction fails, the file is
        binary, or it exceeds *max_size_bytes*.
    """
    if not shutil.which("icat"):
        return None

    cmd = ["icat"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image_path, inode_str])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_ICAT_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    if proc.returncode != 0 or not proc.stdout:
        return None

    if max_size_bytes is not None and len(proc.stdout) > max_size_bytes:
        return None

    if _is_binary_content(proc.stdout):
        return None

    return proc.stdout[:_MAX_TEXT_BYTES].decode("utf-8", errors="replace")


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def index_app_files(
    case_id: str,
    image_path: str,
    directory_pattern: str,
    extensions: list[str] | None = None,
    max_file_size_kb: int = 512,
    max_files: int = 200,
) -> dict[str, Any]:
    """Index text and config files from application directories on a disk image.

    Discovers files matching the given directory pattern and file
    extensions from the TSK file listing, extracts them via icat, and
    indexes their content for search. This is a general-purpose tool
    that does not parse specific file formats; it makes raw content
    searchable so the analyst can interpret it.

    Useful for extracting application configuration, logs, and data
    files after execution artifacts (Prefetch, ShimCache, UserAssist)
    identify installed applications.

    Args:
        case_id: Active case identifier.
        image_path: Path to the disk image.
        directory_pattern: Path pattern to match directories. Supports
            wildcards: ``Program Files/*`` matches all program dirs,
            ``Documents and Settings/*/Application Data/mIRC`` matches
            a specific app for all users. Pattern is matched against
            the TSK file listing paths.
        extensions: File extensions to include. Defaults to common text
            and config extensions: .ini, .cfg, .conf, .txt, .log, .xml,
            .json, .yaml, .yml, .properties, .csv, .bat, .cmd, .ps1,
            .reg, .inf, .manifest.
        max_file_size_kb: Skip files larger than this threshold to avoid
            extracting multi-megabyte logs. Defaults to 512 KB.
        max_files: Maximum number of files to extract per invocation to
            bound execution time. Defaults to 200.

    Returns:
        Dict containing count of files discovered, extracted, and
        indexed, plus a sample of filenames for context.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, Any] = {
        "case_id": case_id,
        "image_path": image_path,
        "directory_pattern": directory_pattern,
        "extensions": extensions,
        "max_file_size_kb": max_file_size_kb,
        "max_files": max_files,
    }

    ctx = get_ctx()
    _ = ctx.case_id

    ext_set: frozenset[str]
    if extensions is not None:
        ext_set = frozenset(
            e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions
        )
    else:
        ext_set = _DEFAULT_EXTENSIONS

    chunk_groups = _collect_fls_chunks(image_path)
    if not chunk_groups:
        return error_response(
            tc_id,
            "index_app_files",
            params,
            "No TSK file listing available. Run run_fls on this image first.",
            error_type="no_filelist",
        )

    all_matches: list[tuple[str, str, int]] = []
    for chunks, offset in chunk_groups:
        matches = _find_matching_files(chunks, directory_pattern, ext_set, offset)
        all_matches.extend(matches)

    if not all_matches:
        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(
            tc_id,
            "index_app_files",
            params,
            {
                "files_discovered": 0,
                "files_extracted": 0,
                "files_indexed": 0,
                "pattern": directory_pattern,
                "message": f"No files matching pattern '{directory_pattern}' "
                f"with extensions {sorted(ext_set)} were found in the file listing.",
            },
            source=None,
            elapsed_ms=elapsed,
        )

    capped = all_matches[:max_files]
    source_name = _derive_source_name(directory_pattern)

    files_extracted = 0
    files_indexed = 0
    total_windows = 0
    sample_files: list[str] = []
    skipped_binary = 0

    for inode_str, rel_path, offset in capped:
        content = _extract_and_read_file(
            image_path, inode_str, offset, max_size_bytes=max_file_size_kb * 1024
        )
        if content is None:
            skipped_binary += 1
            continue

        files_extracted += 1
        if not content.strip():
            continue

        filename = rel_path.rsplit("/", 1)[-1] if "/" in rel_path else rel_path
        header = f"=== {rel_path} ===\n"
        file_source = f"{source_name}.{filename.lower().replace(' ', '_')}"
        index_result = extract_and_index(header + content, file_source, image_path, "icat")

        windows_count = index_result.get("windows_indexed", 0)
        if isinstance(windows_count, int):
            total_windows += windows_count
        files_indexed += 1

        if len(sample_files) < 20:
            sample_files.append(rel_path)

    elapsed = (time.monotonic() - t0) * 1000
    results: dict[str, Any] = {
        "files_discovered": len(all_matches),
        "files_capped_at": max_files if len(all_matches) > max_files else None,
        "files_extracted": files_extracted,
        "files_indexed": files_indexed,
        "files_skipped_binary": skipped_binary,
        "windows_indexed": total_windows,
        "source_prefix": source_name,
        "sample_files": sample_files,
        "pattern": directory_pattern,
        "extensions_used": sorted(ext_set),
    }

    return tool_response(
        tc_id,
        "index_app_files",
        params,
        results,
        source=None,
        elapsed_ms=elapsed,
    )
