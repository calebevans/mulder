"""MCP tools for artifact extraction and analysis.

Browser history, plist parsing, generic SQLite queries,
steganography detection, and timestomping analysis.  All tools use
TSK icat to extract files from disk images without mounting, then
parse the extracted content.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import plistlib
import re
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from mulder.execution import safe_subprocess as subprocess
from mulder.path_policy import PathPolicyError, resolve_allowed_path
from mulder.security.evidence_envelope import present_model_evidence
from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import hash_output, make_tool_call_id
from mulder.server.tool_access import Role, tool_access

logger = logging.getLogger(__name__)

_ALLOWED_SQLITE_OPS: frozenset[int] = frozenset(
    {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
    }
)


def _readonly_authorizer(
    action: int, arg1: object, arg2: object, db_name: object, trigger: object
) -> int:
    """SQLite authorizer that only permits read operations."""
    if action in _ALLOWED_SQLITE_OPS:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _resolve_artifact_path(target: Path) -> Path:
    """Resolve *target* within the active evidence or case-storage root."""
    cfg = get_cfg()
    allowed_roots = [Path(cfg.db_dir)]
    ctx = get_ctx()
    meta = ctx.db.get_case_metadata()
    if meta and meta.evidence_root:
        allowed_roots.append(Path(meta.evidence_root))
    return resolve_allowed_path(target, allowed_roots)


_TOOL_TIMEOUT = 120


def _icat_extract(image_path: str, offset: int, inode: str, dest: Path) -> bool:
    """Extract a file from disk image to dest using icat."""
    cmd = ["icat"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image_path, inode])
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
        if proc.returncode == 0 and proc.stdout:
            dest.write_bytes(proc.stdout)
            return True
    except (subprocess.TimeoutExpired, OSError):
        pass
    return False


def _resolve_image_and_offset() -> tuple[str, int]:
    """Get disk image path and primary partition offset from indexed TSK data.

    Returns:
        Tuple of ``(image_path, primary_partition_offset)``.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()

    part_src = next((s for s in sources if s.source_name == "tsk.partitions"), None)
    fls_src = next((s for s in sources if s.source_name == "tsk.filelist"), None)

    image_path = ""
    offset = 0

    if part_src:
        image_path = part_src.source_path
        windows = ctx.db.get_windows_by_source("tsk.partitions")

        mmls_text = "\n".join(w.raw_text for w in windows)
        row_re = re.compile(r"^\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$", re.MULTILINE)
        for m in row_re.finditer(mmls_text):
            start, length, desc = int(m.group(1)), int(m.group(2)), m.group(3).strip().lower()
            if any(ind in desc for ind in ("ntfs", "0x07", "hfs", "apfs")) and length > 0:
                offset = start
                break
    elif fls_src:
        image_path = fls_src.source_path

    return image_path, offset


_KV_SOURCE_OFFSET_PREFIX = "tsk_source_offset:"


def _find_inodes_by_pattern(pattern: str) -> list[tuple[str, str, int]]:
    """Search all fls listings for files matching a name pattern.

    Searches the primary ``tsk.filelist`` and any secondary partition
    sources (``tsk.filelist.p1``, etc.), returning the correct partition
    offset for each match so callers can extract via ``icat`` with the
    right offset.

    Args:
        pattern: Regex pattern with at least two capture groups:
            group(1) = inode string, group(2) = relative path.

    Returns:
        List of ``(inode_str, relative_path, partition_offset)`` tuples.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    fls_sources = sorted(
        [s for s in sources if s.source_name.startswith("tsk.filelist")],
        key=lambda s: s.source_name,
    )

    _, primary_offset = _resolve_image_and_offset()
    pat = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    results: list[tuple[str, str, int]] = []

    for src in fls_sources:
        stored = ctx.db.get_kv(f"{_KV_SOURCE_OFFSET_PREFIX}{src.source_name}:{src.source_path}")
        offset = int(stored) if stored is not None else primary_offset

        windows = ctx.db.get_windows_by_source(src.source_name)
        for w in windows:
            for m in pat.finditer(w.raw_text):
                inode_str = m.group(1).split("-")[0]
                rel_path = m.group(2).strip()
                results.append((inode_str, rel_path, offset))
    return results


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def parse_browser_history() -> dict[str, object]:
    """Extract browser history from Chrome, Firefox, and Safari databases.

    Automatically finds browser SQLite databases in the fls listing,
    extracts them via icat, and queries for URLs, timestamps, and visit
    counts.  Works on both Windows and macOS disk images.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if not shutil.which("icat"):
        return {"tool_call_id": tc_id, "status": "error", "error_message": "icat not found"}

    image_path, _ = _resolve_image_and_offset()
    if not image_path:
        return {"tool_call_id": tc_id, "status": "error", "error_message": "No disk image indexed"}

    browser_patterns = [
        (r"[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.*?/Chrome/.*?/History)\s*$", "chrome"),
        (
            r"[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.*?/Firefox/Profiles/.*?/places\.sqlite)\s*$",
            "firefox",
        ),
        (r"[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.*?/Safari/History\.db)\s*$", "safari"),
        (r"[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.*?/Google/Chrome/.*?/History)\s*$", "chrome"),
    ]

    all_results: list[str] = []

    with tempfile.TemporaryDirectory(prefix="mulder_browser_") as tmpdir:
        for pattern, browser in browser_patterns:
            matches = _find_inodes_by_pattern(pattern)
            for inode_str, rel_path, match_offset in matches:
                db_path = Path(tmpdir) / f"{browser}_{inode_str}.sqlite"
                if not _icat_extract(image_path, match_offset, inode_str, db_path):
                    continue

                try:
                    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                    conn.row_factory = sqlite3.Row

                    if browser == "chrome":
                        rows = conn.execute(
                            "SELECT url, title, visit_count, "
                            "datetime(last_visit_time/1000000-11644473600, "
                            "'unixepoch') as visit_time "
                            "FROM urls ORDER BY last_visit_time DESC LIMIT 500"
                        ).fetchall()
                    elif browser == "firefox":
                        rows = conn.execute(
                            "SELECT url, title, visit_count, "
                            "datetime(last_visit_date/1000000, 'unixepoch') as visit_time "
                            "FROM moz_places WHERE visit_count > 0 "
                            "ORDER BY last_visit_date DESC LIMIT 500"
                        ).fetchall()
                    elif browser == "safari":
                        rows = conn.execute(
                            "SELECT hi.url, hv.title, "
                            "datetime(hv.visit_time + 978307200, 'unixepoch') as visit_time "
                            "FROM history_items hi "
                            "JOIN history_visits hv ON hi.id = hv.history_item "
                            "ORDER BY hv.visit_time DESC LIMIT 500"
                        ).fetchall()
                    else:
                        rows = []

                    conn.close()

                    if rows:
                        header = f"=== {browser.upper()} History ({rel_path}) ===\n"
                        lines = [header]
                        for r in rows:
                            lines.append("\t".join(str(v) for v in dict(r).values()))
                        all_results.append("\n".join(lines))

                except (sqlite3.Error, OSError) as exc:
                    logger.debug("Browser DB parse error for %r: %s", rel_path, exc)

    combined = "\n\n".join(all_results) if all_results else ""
    if combined:
        summary = extract_and_index(combined, "browser.history", image_path, "browser_parser")
    else:
        summary = {"status": "no_results", "message": "No browser history databases found"}

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_browser_history",
        params={},
        output_hash=hash_output(summary),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": summary,
        "source": "browser.history",
        "result_count": len(all_results),
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def parse_plist(plist_filter: str | None = None) -> dict[str, object]:
    """Extract and parse macOS plist files from a disk image.

    Finds plist files in the fls listing matching *plist_filter* (or
    key system plists if omitted), extracts via icat, and parses with
    Python's plistlib.  Read-only.

    Args:
        plist_filter: Optional filename filter (e.g. "loginitems",
            "recentitems", "wifi").  If omitted, extracts common
            system plists.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if not shutil.which("icat"):
        return {"tool_call_id": tc_id, "status": "error", "error_message": "icat not found"}

    image_path, _ = _resolve_image_and_offset()
    if not image_path:
        return {"tool_call_id": tc_id, "status": "error", "error_message": "No disk image indexed"}

    if plist_filter:
        escaped_filter = re.escape(plist_filter)
        pattern = rf"[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.*?{escaped_filter}.*?\.plist)\s*$"
    else:
        pattern = (
            r"[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+"
            r"(.*?(?:loginitems|recentitems|wifi|known-networks|"
            r"SystemVersion|loginwindow|LaunchAgents|LaunchDaemons).*?\.plist)\s*$"
        )

    matches = _find_inodes_by_pattern(pattern)
    all_results: list[str] = []

    with tempfile.TemporaryDirectory(prefix="mulder_plist_") as tmpdir:
        for inode_str, rel_path, match_offset in matches[:50]:
            plist_path = Path(tmpdir) / f"plist_{inode_str}.plist"
            if not _icat_extract(image_path, match_offset, inode_str, plist_path):
                continue

            try:
                with open(plist_path, "rb") as f:
                    data = plistlib.load(f)
                text = f"=== {rel_path} (inode {inode_str}) ===\n"
                text += json.dumps(data, indent=2, default=str, ensure_ascii=False)
                all_results.append(text)
            except Exception as exc:
                logger.debug("Plist parse error for %r: %s", rel_path, exc)

    combined = "\n\n".join(all_results) if all_results else ""
    if combined:
        summary = extract_and_index(combined, "plist.parsed", image_path, "plist_parser")
    else:
        summary = {"status": "no_results", "message": "No matching plist files found"}

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_plist",
        params={"plist_filter": plist_filter},
        output_hash=hash_output(summary),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": summary,
        "source": "plist.parsed",
        "result_count": len(all_results),
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def query_sqlite_from_image(inode: int, query: str, description: str = "") -> dict[str, object]:
    """Extract a SQLite database from a disk image and run a SQL query.

    Uses icat to extract the file at *inode* to a temp directory, opens
    it as a read-only SQLite database, and executes the given *query*.
    Results are indexed into the case database.  Read-only.

    Args:
        inode: The inode number of the SQLite database (from fls listing).
        query: The SQL SELECT query to execute.
        description: Optional label for the indexed source name.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"inode": inode, "query": query, "description": description}

    if not shutil.which("icat"):
        return {"tool_call_id": tc_id, "status": "error", "error_message": "icat not found"}

    image_path, offset = _resolve_image_and_offset()
    if not image_path:
        return {"tool_call_id": tc_id, "status": "error", "error_message": "No disk image indexed"}

    if not query.strip().upper().startswith("SELECT"):
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": "Only SELECT queries are allowed (read-only)",
        }

    if ";" in query:
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": "Multi-statement queries are not allowed",
        }

    with tempfile.TemporaryDirectory(prefix="mulder_sqlite_") as tmpdir:
        db_path = Path(tmpdir) / f"inode_{inode}.sqlite"
        if not _icat_extract(image_path, offset, str(inode), db_path):
            elapsed = (time.monotonic() - t0) * 1000
            return {
                "tool_call_id": tc_id,
                "status": "error",
                "error_message": f"Failed to extract inode {inode}",
            }

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.set_authorizer(_readonly_authorizer)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query).fetchall()
            conn.close()
        except sqlite3.Error as exc:
            logger.error("SQLite query failed on inode %d: %s", inode, exc)
            elapsed = (time.monotonic() - t0) * 1000
            return {
                "tool_call_id": tc_id,
                "status": "error",
                "error_message": "SQLite query failed",
            }

    if rows:
        columns = rows[0].keys()
        header = "\t".join(columns)
        lines = [header]
        for r in rows[:1000]:
            lines.append("\t".join(str(r[c]) for c in columns))
        combined = "\n".join(lines)

        source_name = f"sqlite.{description}" if description else f"sqlite.inode_{inode}"
        summary = extract_and_index(combined, source_name, image_path, "sqlite_query")
    else:
        summary = {"status": "no_results", "message": "Query returned 0 rows"}
        source_name = f"sqlite.inode_{inode}"

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="query_sqlite_from_image",
        params=params,
        output_hash=hash_output(summary),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": summary,
        "source": source_name,
        "result_count": len(rows) if rows else 0,
    }


@mcp.tool()
@tool_access(Role.CATALOG | Role.EXTRACT_PLANNER | Role.EXTRACT_EXECUTOR)
def list_directory(
    path: str,
    recursive: bool = False,
) -> dict[str, object]:
    """List files and directories at a given path.

    Use this instead of Bash ``ls`` to maintain the audit trail.
    Returns file names, sizes, and types for each entry.

    Args:
        path: Directory path to list.
        recursive: If True, list all files recursively.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    try:
        target = _resolve_artifact_path(Path(path))
    except PathPolicyError as exc:
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": str(exc),
            "results": [],
            "result_count": 0,
        }
    if not target.exists():
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="list_directory",
            params={"path": path, "recursive": recursive},
            output_hash=hash_output({"error": "not found"}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"Path not found: {path}",
            "results": [],
            "result_count": 0,
        }

    entries: list[dict[str, object]] = []
    items = sorted(target.rglob("*")) if recursive else sorted(target.iterdir())
    for item in items:
        try:
            rel = str(item.relative_to(target))
        except ValueError:
            rel = str(item)
        entry: dict[str, object] = {
            "name": rel,
            "type": "directory" if item.is_dir() else "file",
        }
        if item.is_file():
            try:
                size = item.stat().st_size
                entry["size_bytes"] = size
                if size >= 1_073_741_824:
                    entry["size_human"] = f"{size / 1_073_741_824:.1f} GB"
                elif size >= 1_048_576:
                    entry["size_human"] = f"{size / 1_048_576:.1f} MB"
                elif size >= 1024:
                    entry["size_human"] = f"{size / 1024:.0f} KB"
                else:
                    entry["size_human"] = f"{size} B"
            except OSError:
                pass
        entries.append(entry)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="list_directory",
        params={"path": path, "recursive": recursive},
        output_hash=hash_output({"count": len(entries)}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "path": path,
        "results": entries,
        "result_count": len(entries),
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def read_evidence_file(
    file_path: str = "",
    max_bytes: int = 1_048_576,
    path: str = "",
) -> dict[str, object]:
    """Read a text file from the evidence directory.

    Use this instead of shell commands to read README files, config
    files, log files, or any text file in the evidence. Files are read
    as UTF-8 with replacement for non-decodable bytes. Binary files
    return a hex preview. Capped at *max_bytes* (default 1 MB). Read-only.

    Args:
        file_path: Absolute path to the file to read.
        max_bytes: Maximum bytes to read (default 1 MB).
        path: Alias for file_path.
    """
    file_path = file_path or path
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"file_path": file_path, "max_bytes": max_bytes}

    try:
        target = _resolve_artifact_path(Path(file_path))
    except PathPolicyError as exc:
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": str(exc),
        }
    if not target.exists():
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="read_evidence_file",
            params=params,
            output_hash=hash_output({"error": "not found"}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"File not found: {file_path}",
        }

    if not target.is_file():
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="read_evidence_file",
            params=params,
            output_hash=hash_output({"error": "not a file"}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"Not a file: {file_path}",
        }

    try:
        with open(target, "rb") as f:
            raw = f.read(max_bytes)
        try:
            raw.decode("utf-8")
            is_binary = False
        except UnicodeDecodeError:
            is_binary = any(b < 0x20 and b not in (0x09, 0x0A, 0x0D) for b in raw[:512])
    except OSError as exc:
        logger.error("Failed to read evidence file %r: %s", file_path, exc)
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="read_evidence_file",
            params=params,
            output_hash=hash_output({"error": "read_failed"}),
            duration_ms=elapsed,
        )
        return {"tool_call_id": tc_id, "status": "error", "error_message": "Failed to read file"}

    file_size = target.stat().st_size
    truncated = file_size > max_bytes

    selector = json.dumps(
        {"byte_end": len(raw), "byte_start": 0, "file_size": file_size},
        sort_keys=True,
        separators=(",", ":"),
    )
    presentation = present_model_evidence(
        raw,
        source_id=str(target),
        source_name=target.name,
        selector=selector,
        max_characters=(2000 if is_binary else max(1, max_bytes)),
    )
    result = {
        **presentation.response_fields(
            content_key="content", metadata_key="evidence_envelope"
        ),
        "file_size": file_size,
        "truncated": truncated,
        "is_binary": is_binary,
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="read_evidence_file",
        params=params,
        output_hash=hash_output({"size": file_size}),
        duration_ms=elapsed,
    )
    return {"tool_call_id": tc_id, "status": "success", **result}


def _convert_heic_to_jpeg(heic_files: list[Path], tmpdir: str) -> list[Path]:
    """Convert HEIC/HEIF files to JPEG for steg analysis."""
    if not shutil.which("heif-convert"):
        return []
    converted: list[Path] = []
    for hf in heic_files[:100]:
        out = Path(tmpdir) / f"{hf.stem}.jpg"
        try:
            subprocess.run(
                ["heif-convert", str(hf), str(out)],
                capture_output=True,
                timeout=15,
                check=False,
            )
            if out.exists() and out.stat().st_size > 0:
                converted.append(out)
        except (subprocess.TimeoutExpired, OSError):
            continue
    return converted


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def detect_steganography(target_path: str) -> dict[str, object]:
    """Scan image files for hidden steganographic content.

    Runs stegdetect on JPEG files, checks PNG files for appended data,
    and converts HEIC/HEIF files to JPEG before scanning.  *target_path*
    can be a directory (scanned recursively) or a single file.  Read-only.

    Args:
        target_path: Path to a file or directory of image files.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path}

    target = Path(target_path)
    if not target.exists():
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"Path not found: {target_path}",
        }

    results_text: list[str] = []
    has_stegdetect = shutil.which("stegdetect") is not None
    has_zsteg = shutil.which("zsteg") is not None

    if target.is_dir():
        jpgs = sorted(target.rglob("*.jpg")) + sorted(target.rglob("*.jpeg"))
        pngs = sorted(target.rglob("*.png"))
        heics = (
            sorted(target.rglob("*.heic"))
            + sorted(target.rglob("*.HEIC"))
            + sorted(target.rglob("*.heif"))
        )
    else:
        ext = target.suffix.lower()
        jpgs = [target] if ext in (".jpg", ".jpeg") else []
        pngs = [target] if ext == ".png" else []
        heics = [target] if ext in (".heic", ".heif") else []

    with tempfile.TemporaryDirectory(prefix="mulder_steg_") as tmpdir:
        if heics:
            converted = _convert_heic_to_jpeg(heics, tmpdir)
            if converted:
                results_text.append(f"Converted {len(converted)} HEIC files to JPEG for analysis")
                jpgs.extend(converted)

        if not jpgs and not pngs:
            summary: dict[str, object] = {
                "status": "no_results",
                "message": (
                    f"No image files found in {target_path} (checked .jpg/.jpeg/.png/.heic)"
                ),
            }
            elapsed = (time.monotonic() - t0) * 1000
            ctx.audit.log_tool_call(
                tool_call_id=tc_id,
                tool_name="detect_steganography",
                params=params,
                output_hash=hash_output(summary),
                duration_ms=elapsed,
            )
            return {
                "tool_call_id": tc_id,
                "status": "success",
                "results": summary,
                "source": "steg.detection",
                "result_count": 0,
                "files_scanned": 0,
                "tools_available": {"stegdetect": has_stegdetect, "zsteg": has_zsteg},
            }

        if has_stegdetect:
            for jpg in jpgs[:200]:
                try:
                    proc = subprocess.run(
                        ["stegdetect", str(jpg)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    output = proc.stdout.strip()
                    if output and "negative" not in output.lower():
                        results_text.append(output)
                except (subprocess.TimeoutExpired, OSError):
                    continue

        if has_zsteg:
            for png in pngs[:100]:
                try:
                    proc = subprocess.run(
                        ["zsteg", str(png)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    output = proc.stdout.strip()
                    if output:
                        results_text.append(f"=== {png.name} ===\n{output}")
                except (subprocess.TimeoutExpired, OSError):
                    continue

        if not has_stegdetect and not has_zsteg:
            results_text.append(
                "WARNING: Neither stegdetect nor zsteg installed. "
                "Using basic EOI/IEND marker check only."
            )

        _STEG_TAIL_SIZE = 8192

        for img in (jpgs + pngs)[:200]:
            try:
                file_size = img.stat().st_size
                with open(img, "rb") as f:
                    if img.suffix.lower() in (".jpg", ".jpeg"):
                        tail_offset = max(0, file_size - _STEG_TAIL_SIZE)
                        f.seek(tail_offset)
                        tail = f.read()
                        eoi = tail.rfind(b"\xff\xd9")
                        if eoi >= 0:
                            trailing = len(tail) - eoi - 2
                            if trailing > 10:
                                results_text.append(
                                    f"{img.name}: {trailing} bytes after JPEG EOI marker "
                                    "(possible appended data)"
                                )
                    elif img.suffix.lower() == ".png":
                        tail_offset = max(0, file_size - _STEG_TAIL_SIZE)
                        f.seek(tail_offset)
                        tail = f.read()
                        iend = tail.rfind(b"IEND")
                        if iend >= 0:
                            trailing = len(tail) - iend - 12
                            if trailing > 10:
                                results_text.append(
                                    f"{img.name}: {trailing} bytes after PNG IEND chunk "
                                    "(possible appended data)"
                                )
            except OSError:
                continue

    files_scanned = len(jpgs) + len(pngs)
    combined = "\n".join(results_text) if results_text else ""
    if combined:
        summary = extract_and_index(combined, "steg.detection", target_path, "steganography")
    else:
        summary = {
            "status": "no_results",
            "message": f"No steganographic content detected in {files_scanned} files",
        }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="detect_steganography",
        params=params,
        output_hash=hash_output(summary),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": summary,
        "source": "steg.detection",
        "result_count": len(results_text),
        "files_scanned": files_scanned,
        "tools_available": {"stegdetect": has_stegdetect, "zsteg": has_zsteg},
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def extract_steganography(
    image_path: str,
    passwords: list[str] | None = None,
) -> dict[str, object]:
    """Extract hidden data from a steganographic JPEG image.

    Attempts to extract hidden content using known passwords first, then
    falls back to brute-force with stegbreak.  Supports jphide (detected
    by stegdetect), outguess, and jsteg formats.  Read-only against the
    original image; extraction writes to a temp directory.

    Args:
        image_path: Path to a JPEG file flagged by detect_steganography.
        passwords: List of passwords to try (e.g. passwords found during
            the investigation from keylogger, browser history, etc.).
            If omitted, tries common/empty passwords only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "passwords": passwords is not None}

    target = Path(image_path)
    if not target.exists():
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"File not found: {image_path}",
        }

    results_text: list[str] = []
    extracted_content: str | None = None
    password_used: str | None = None

    if passwords is None:
        passwords = []

    passwords = list(passwords) + ["", "password", "123456"]

    with tempfile.TemporaryDirectory(prefix="mulder_steg_extract_") as tmpdir:
        out_file = Path(tmpdir) / "extracted.bin"

        # Try jpseek (jphide extraction) with each password
        if shutil.which("jpseek"):
            for pw in passwords:
                try:
                    proc = subprocess.run(
                        ["jpseek", str(target), str(out_file)],
                        input=pw + "\n",
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    if out_file.exists() and out_file.stat().st_size > 0:
                        raw = out_file.read_bytes()
                        try:
                            content = raw.decode("utf-8", errors="replace")
                            if any(c.isprintable() for c in content[:100]):
                                extracted_content = content[:10000]
                                password_used = pw if pw else "(empty)"
                                results_text.append(
                                    f"jpseek extracted {len(raw)} bytes with password "
                                    f"'{password_used}':\n{content[:2000]}"
                                )
                                break
                        except Exception:
                            results_text.append(
                                f"jpseek extracted {len(raw)} bytes (binary) with password "
                                f"'{pw or '(empty)'}'"
                            )
                            password_used = pw if pw else "(empty)"
                            break
                    out_file.unlink(missing_ok=True)
                except (subprocess.TimeoutExpired, OSError):
                    out_file.unlink(missing_ok=True)
                    continue

        # Try outguess extraction (no password needed)
        if not extracted_content and shutil.which("outguess"):
            try:
                proc = subprocess.run(
                    ["outguess", "-r", str(target), str(out_file)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if out_file.exists() and out_file.stat().st_size > 0:
                    raw = out_file.read_bytes()
                    content = raw.decode("utf-8", errors="replace")
                    if any(c.isprintable() for c in content[:100]):
                        extracted_content = content[:10000]
                        password_used = "(none - outguess)"
                        results_text.append(
                            f"outguess extracted {len(raw)} bytes:\n{content[:2000]}"
                        )
                out_file.unlink(missing_ok=True)
            except (subprocess.TimeoutExpired, OSError):
                out_file.unlink(missing_ok=True)

        # Try stegbreak brute-force if nothing found yet
        if not extracted_content and shutil.which("stegbreak"):
            wordlist = Path(tmpdir) / "wordlist.txt"
            wordlist.write_text("\n".join(passwords) + "\n")
            try:
                proc = subprocess.run(
                    ["stegbreak", "-t", "p", "-f", str(wordlist), str(target)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                output = proc.stdout.strip()
                if output and "found" in output.lower():
                    results_text.append(f"stegbreak result: {output}")
            except (subprocess.TimeoutExpired, OSError):
                pass

    if not results_text:
        results_text.append(
            f"Could not extract steganographic content from {target.name}. "
            f"Tried {len(passwords)} passwords with available tools. "
            f"Tools: jpseek={'yes' if shutil.which('jpseek') else 'no'}, "
            f"outguess={'yes' if shutil.which('outguess') else 'no'}, "
            f"stegbreak={'yes' if shutil.which('stegbreak') else 'no'}"
        )

    combined = "\n".join(results_text)
    if extracted_content:
        summary = extract_and_index(combined, "steg.extracted", image_path, "steganography")
    else:
        summary = {"status": "extraction_failed", "message": combined}

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="extract_steganography",
        params=params,
        output_hash=hash_output(summary),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success" if extracted_content else "no_extraction",
        "results": summary,
        "source": "steg.extracted",
        "password_used": password_used,
        "extracted_size": len(extracted_content) if extracted_content else 0,
    }


# ---------------------------------------------------------------------------
# Timestomping detection
# ---------------------------------------------------------------------------

_TIMESTOMP_THRESHOLD = timedelta(seconds=10)

_TIMESTOMP_FALSE_POSITIVE_PATHS: tuple[str, ...] = (
    "\\windows\\winsxs\\",
    "\\windows\\installer\\",
    "\\windows\\servicing\\",
    "\\windows\\softwaredistribution\\",
    "\\$recycle.bin\\",
    "\\system volume information\\",
    "\\windows\\assembly\\",
)

_SI_CREATED_COLUMNS = ("Created0x10_0", "Created0x10")
_FN_CREATED_COLUMNS = ("Created0x30_0", "Created0x30")
_SI_MODIFIED_COLUMNS = ("LastModified0x10_0", "Modified0x10_0", "Modified0x10", "LastModified0x10")
_FILENAME_COLUMN_CANDIDATES = ("FileName", "Filename", "filename", "File Name")
_PARENT_PATH_COLUMNS = ("ParentPath", "Parent Path", "parentpath")


def _find_column(headers: list[str], candidates: tuple[str, ...]) -> str | None:
    """Find the first matching column name from a list of candidates."""
    for c in candidates:
        if c in headers:
            return c
    return None


def _parse_mft_timestamp(value: str) -> datetime | None:
    """Parse a timestamp string from MFTECmd CSV output."""
    if not value or not value.strip():
        return None
    value = value.strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _is_false_positive_path(filepath: str) -> bool:
    """Return True if the file path is a known source of benign timestamp anomalies."""
    lower = filepath.lower()
    return any(fp in lower for fp in _TIMESTOMP_FALSE_POSITIVE_PATHS)


def _analyze_mft_windows_for_timestomping(
    windows: list[Any],
) -> list[dict[str, Any]]:
    """Analyze raw MFT window text for timestamp anomalies.

    Handles both CSV-formatted MFT data and tab-delimited output
    by parsing each window's content.
    """
    suspicious: list[dict[str, Any]] = []

    for w in windows:
        text = w.raw_text
        if not text.strip():
            continue

        lines = text.strip().splitlines()
        if len(lines) < 2:
            continue

        reader = csv.reader(io.StringIO(text))
        try:
            headers = next(reader)
        except StopIteration:
            continue

        headers = [h.strip() for h in headers]

        si_created_col = _find_column(headers, _SI_CREATED_COLUMNS)
        fn_created_col = _find_column(headers, _FN_CREATED_COLUMNS)
        si_modified_col = _find_column(headers, _SI_MODIFIED_COLUMNS)
        filename_col = _find_column(headers, _FILENAME_COLUMN_CANDIDATES)
        parent_col = _find_column(headers, _PARENT_PATH_COLUMNS)

        if not si_created_col or not fn_created_col:
            continue

        for row in reader:
            if len(row) <= max(
                headers.index(si_created_col),
                headers.index(fn_created_col),
            ):
                continue

            try:
                si_created_val = row[headers.index(si_created_col)]
                fn_created_val = row[headers.index(fn_created_col)]
            except (IndexError, ValueError):
                continue

            si_created = _parse_mft_timestamp(si_created_val)
            fn_created = _parse_mft_timestamp(fn_created_val)

            if si_created is None or fn_created is None:
                continue

            fname = ""
            if filename_col and headers.index(filename_col) < len(row):
                fname = row[headers.index(filename_col)].strip()
            parent = ""
            if parent_col and headers.index(parent_col) < len(row):
                parent = row[headers.index(parent_col)].strip()

            full_path = f"{parent}\\{fname}" if parent else fname
            if _is_false_positive_path(full_path):
                continue

            reasons: list[str] = []

            # SI Created significantly earlier than FN Created = backdated
            if fn_created - si_created > _TIMESTOMP_THRESHOLD:
                reasons.append(
                    f"SI Created ({si_created_val}) is earlier than "
                    f"FN Created ({fn_created_val}) by "
                    f"{fn_created - si_created}"
                )

            # SI Created > SI Modified is impossible without manipulation
            if si_modified_col:
                try:
                    si_modified_val = row[headers.index(si_modified_col)]
                    si_modified = _parse_mft_timestamp(si_modified_val)
                    if si_modified and si_created > si_modified:
                        reasons.append(
                            f"SI Created ({si_created_val}) is after "
                            f"SI Modified ({si_modified_val})"
                        )
                except (IndexError, ValueError):
                    pass

            if reasons:
                suspicious.append(
                    {
                        "file": full_path,
                        "si_created": si_created_val,
                        "fn_created": fn_created_val,
                        "reasons": reasons,
                    }
                )

    return suspicious


@mcp.tool()
@tool_access(
    Role.EXTRACT_EXECUTOR
    | Role.EXTRACT_ANALYST
    | Role.CROSS_EXECUTOR
    | Role.NARRATIVE_EXECUTOR
)
def detect_timestomping() -> dict[str, object]:
    """Analyze MFT data for files with manipulated timestamps (timestomping).

    Reads the indexed ``ez.mft`` source (MFTECmd output) and compares
    $STANDARD_INFORMATION timestamps against $FILE_NAME timestamps for
    each file entry.  Flags files where:

    - $SI Created is significantly earlier than $FN Created (SI was
      backdated to blend in with legitimate files)
    - $SI Created is later than $SI Modified (impossible without
      timestamp manipulation)

    Filters out known false positives from Windows Update, servicing,
    and installer paths.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    sources = ctx.db.get_sources()
    mft_source = next(
        (s for s in sources if s.source_name == "ez.mft" or s.source_name.startswith("ez.mft.")),
        None,
    )

    if mft_source is None:
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="detect_timestomping",
            params={},
            output_hash=hash_output({"error": "no_mft"}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": (
                "No MFT data indexed. Run MFTECmd first: run_ez_tool('MFTECmd', '<image_path>')"
            ),
            "suggestion": "run_ez_tool('MFTECmd', '<image_path>')",
        }

    windows = ctx.db.get_windows_by_source_prefix("ez.mft")
    if not windows:
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="detect_timestomping",
            params={},
            output_hash=hash_output({"error": "empty_mft"}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": "MFT source is indexed but contains no data windows.",
        }

    suspicious = _analyze_mft_windows_for_timestomping(windows)

    if suspicious:
        output_lines: list[str] = []
        for entry in suspicious:
            reasons_str = "; ".join(entry["reasons"])
            output_lines.append(
                f"{entry['file']}\tSI_Created={entry['si_created']}\t"
                f"FN_Created={entry['fn_created']}\t{reasons_str}"
            )
        combined = "\n".join(output_lines)
        summary = extract_and_index(
            combined, "forensic.timestomping", "mft_analysis", "timestomp_detector"
        )
    else:
        summary = {
            "status": "no_results",
            "message": (
                f"No timestomping indicators found in {len(windows)} MFT windows. "
                "This does not guarantee absence of timestomping if SI/FN columns "
                "are not present in the MFTECmd output format."
            ),
        }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="detect_timestomping",
        params={},
        output_hash=hash_output(summary),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": summary,
        "source": "forensic.timestomping",
        "result_count": len(suspicious),
        "total_mft_windows_analyzed": len(windows),
    }


# ---------------------------------------------------------------------------
# Sysinternals Autoruns CSV parsing
# ---------------------------------------------------------------------------

_AUTORUNS_GLOB_PATTERNS: tuple[str, ...] = (
    "*autorunsc*.csv",
    "*autoruns*.csv",
)

_AUTORUNS_KEY_COLUMNS: tuple[str, ...] = (
    "Entry Location",
    "Entry",
    "Enabled",
    "Category",
    "Image Path",
    "Launch String",
    "Signer",
    "Company",
    "Description",
    "MD5",
    "SHA-256",
    "Time",
    "Profile",
)


def _discover_autoruns_csvs(evidence_path: str) -> list[Path]:
    """Find Autoruns CSV files in the evidence or extracted directories.

    Searches both the evidence root and the case db_dir for files matching
    common Autoruns export naming patterns.
    """
    import fnmatch as _fnmatch

    candidates: list[Path] = []
    search_roots: list[Path] = []

    ctx = get_ctx()
    meta = ctx.db.get_case_metadata()
    if meta and meta.evidence_root:
        search_roots.append(Path(meta.evidence_root))
    cfg = get_cfg()
    search_roots.append(Path(cfg.db_dir))

    if evidence_path:
        ep = Path(evidence_path)
        if ep.is_file():
            return [ep] if ep.exists() else []
        if ep.is_dir():
            search_roots.insert(0, ep)

    seen: set[Path] = set()
    for root in search_roots:
        if not root.exists():
            continue
        for item in root.rglob("*.csv"):
            name_lower = item.name.lower()
            if any(_fnmatch.fnmatch(name_lower, pat) for pat in _AUTORUNS_GLOB_PATTERNS):
                resolved = item.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    candidates.append(item)

    return sorted(candidates)


def _parse_autoruns_csv_content(csv_path: Path) -> tuple[list[str], str]:
    """Parse an Autoruns CSV and return formatted lines and hostname hint.

    Handles both comma-separated and tab-separated variants, and is
    robust to missing columns. Returns (lines, hostname).
    """
    try:
        raw = csv_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        raw = csv_path.read_text(encoding="utf-8", errors="replace")

    if not raw.strip():
        return [], ""

    # Detect delimiter: if header has tabs, treat as TSV
    first_line = raw.split("\n", 1)[0]
    delimiter = "\t" if "\t" in first_line and "," not in first_line else ","

    reader = csv.DictReader(io.StringIO(raw), delimiter=delimiter)
    if not reader.fieldnames:
        return [], ""

    fieldnames = [f.strip() for f in reader.fieldnames]
    reader.fieldnames = fieldnames

    hostname = ""
    if "Profile" in fieldnames:
        pass  # extract from first row below

    lines: list[str] = []
    for row in reader:
        entry_location = row.get("Entry Location", "").strip()
        entry_name = row.get("Entry", "").strip()
        category = row.get("Category", "").strip()
        image_path = row.get("Image Path", "").strip()
        enabled = row.get("Enabled", "").strip()
        signer = row.get("Signer", "").strip()
        launch_string = row.get("Launch String", "").strip()
        company = row.get("Company", "").strip()
        description = row.get("Description", "").strip()
        timestamp = row.get("Time", "").strip()
        profile = row.get("Profile", "").strip()
        md5 = row.get("MD5", "").strip()
        sha256 = row.get("SHA-256", row.get("SHA256", "")).strip()

        if not hostname and profile:
            hostname = profile.replace("\\", "_").replace(" ", "_").lower()

        parts = [
            f"Category={category}" if category else "",
            f"Location={entry_location}" if entry_location else "",
            f"Entry={entry_name}" if entry_name else "",
            f"ImagePath={image_path}" if image_path else "",
            f"LaunchString={launch_string}" if launch_string else "",
            f"Enabled={enabled}" if enabled else "",
            f"Signer={signer}" if signer else "",
            f"Company={company}" if company else "",
            f"Description={description}" if description else "",
            f"Time={timestamp}" if timestamp else "",
            f"MD5={md5}" if md5 else "",
            f"SHA256={sha256}" if sha256 else "",
        ]
        line = "\t".join(p for p in parts if p)
        if line:
            lines.append(line)

    return lines, hostname


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def parse_autoruns(csv_path: str = "", force: bool = False) -> dict[str, object]:
    """Parse Sysinternals Autoruns CSV output to identify persistence mechanisms.

    Call when autoruns CSV files are present in the evidence. Indexes all
    autostart entries (services, registry, scheduled tasks, drivers) for
    searching. Output indexed as 'autoruns.*'.

    Args:
        csv_path: Path to the Autoruns CSV file (or auto-discover from
            evidence/extracted directories if empty).
        force: Re-run even if already indexed.
    """
    from mulder.server.helpers import sources_already_indexed

    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"csv_path": csv_path, "force": force}

    if not force:
        existing = sources_already_indexed(["autoruns."])
        if existing:
            elapsed = (time.monotonic() - t0) * 1000
            ctx.audit.log_tool_call(
                tool_call_id=tc_id,
                tool_name="parse_autoruns",
                params=params,
                output_hash=hash_output({"skipped": existing}),
                duration_ms=elapsed,
            )
            return {
                "tool_call_id": tc_id,
                "status": "already_indexed",
                "existing_sources": existing,
                "hint": "Use force=True to re-index.",
            }

    csv_files = (
        [Path(csv_path)]
        if csv_path and Path(csv_path).is_file()
        else _discover_autoruns_csvs(csv_path)
    )

    if not csv_files:
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="parse_autoruns",
            params=params,
            output_hash=hash_output({"error": "no_csv"}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": (
                "No Autoruns CSV files found. "
                "Provide csv_path or place files in evidence directory."
            ),
        }

    total_entries = 0
    indexed_sources: list[str] = []

    for csv_file in csv_files:
        lines, hostname = _parse_autoruns_csv_content(csv_file)
        if not lines:
            continue

        source_name = f"autoruns.{hostname}" if hostname else "autoruns"
        combined = "\n".join(lines)
        extract_and_index(combined, source_name, str(csv_file), "autoruns_parser")
        total_entries += len(lines)
        indexed_sources.append(source_name)

    if not indexed_sources:
        summary: dict[str, object] = {
            "status": "no_results",
            "message": "Autoruns CSV files found but contained no parseable entries.",
        }
    else:
        summary = {
            "status": "success",
            "sources_indexed": indexed_sources,
            "total_entries": total_entries,
            "files_parsed": len(csv_files),
        }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="parse_autoruns",
        params=params,
        output_hash=hash_output(summary),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success" if indexed_sources else "no_results",
        "results": summary,
        "sources": indexed_sources,
        "result_count": total_entries,
    }
