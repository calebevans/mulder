"""MCP tools for artifact extraction and analysis.

Browser history, plist parsing, generic SQLite queries, and
steganography detection.  All tools use TSK icat to extract files from
disk images without mounting, then parse the extracted content.
"""

from __future__ import annotations

import json
import logging
import plistlib
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import hash_output, make_tool_call_id

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


def _validate_path_access(target: Path) -> str | None:
    """Return an error message if the path is not under an allowed root, else None."""
    try:
        resolved = target.resolve()
    except OSError:
        return f"Cannot resolve path: {target}"
    cfg = get_cfg()
    allowed_roots = [Path(cfg.db_dir).resolve()]
    ctx = get_ctx()
    meta = ctx.db.get_case_metadata()
    if meta and meta.evidence_root:
        allowed_roots.append(Path(meta.evidence_root).resolve())
    if not any(str(resolved).startswith(str(root)) for root in allowed_roots):
        return "Access denied: path is outside allowed directories"
    return None


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
    """Get disk image path and partition offset from indexed TSK data."""
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


def _find_inodes_by_pattern(pattern: str) -> list[tuple[str, str]]:
    """Search fls listing for files matching a name pattern.

    Returns list of (inode_str, relative_path) tuples.
    """
    ctx = get_ctx()
    windows = ctx.db.get_windows_by_source("tsk.filelist")
    pat = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    results: list[tuple[str, str]] = []
    for w in windows:
        for m in pat.finditer(w.raw_text):
            inode_str = m.group(1).split("-")[0]
            rel_path = m.group(2).strip()
            results.append((inode_str, rel_path))
    return results


@mcp.tool()
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

    image_path, offset = _resolve_image_and_offset()
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
            for inode_str, rel_path in matches:
                db_path = Path(tmpdir) / f"{browser}_{inode_str}.sqlite"
                if not _icat_extract(image_path, offset, inode_str, db_path):
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
                    logger.debug("Browser DB parse error for %s: %s", rel_path, exc)

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

    image_path, offset = _resolve_image_and_offset()
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
        for inode_str, rel_path in matches[:50]:
            plist_path = Path(tmpdir) / f"plist_{inode_str}.plist"
            if not _icat_extract(image_path, offset, inode_str, plist_path):
                continue

            try:
                with open(plist_path, "rb") as f:
                    data = plistlib.load(f)
                text = f"=== {rel_path} (inode {inode_str}) ===\n"
                text += json.dumps(data, indent=2, default=str, ensure_ascii=False)
                all_results.append(text)
            except Exception as exc:
                logger.debug("Plist parse error for %s: %s", rel_path, exc)

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
            elapsed = (time.monotonic() - t0) * 1000
            return {
                "tool_call_id": tc_id,
                "status": "error",
                "error_message": f"SQLite error: {exc}",
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

    target = Path(path)
    path_err = _validate_path_access(target)
    if path_err:
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": path_err,
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

    target = Path(file_path)
    path_err = _validate_path_access(target)
    if path_err:
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": path_err,
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
        raw = target.read_bytes()[:max_bytes]
        try:
            content = raw.decode("utf-8")
            is_binary = False
        except UnicodeDecodeError:
            content = raw.decode("utf-8", errors="replace")
            is_binary = any(b < 0x20 and b not in (0x09, 0x0A, 0x0D) for b in raw[:512])
    except OSError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="read_evidence_file",
            params=params,
            output_hash=hash_output({"error": str(exc)}),
            duration_ms=elapsed,
        )
        return {"tool_call_id": tc_id, "status": "error", "error_message": f"Read error: {exc}"}

    file_size = target.stat().st_size
    truncated = file_size > max_bytes

    result = {
        "content": content
        if not is_binary
        else content[:2000] + "\n... (binary file, showing first 2000 chars with replacements)",
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

        for img in (jpgs + pngs)[:200]:
            try:
                data = img.read_bytes()
                if img.suffix.lower() in (".jpg", ".jpeg"):
                    eoi = data.rfind(b"\xff\xd9")
                    if eoi >= 0 and eoi < len(data) - 2:
                        trailing = len(data) - eoi - 2
                        if trailing > 10:
                            results_text.append(
                                f"{img.name}: {trailing} bytes after JPEG EOI marker "
                                "(possible appended data)"
                            )
                elif img.suffix.lower() == ".png":
                    iend = data.rfind(b"IEND")
                    if iend >= 0 and iend + 12 < len(data):
                        trailing = len(data) - iend - 12
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
