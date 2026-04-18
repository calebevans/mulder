"""Phone forensics MCP tools.

SQLite carving from raw phone dumps, Android/iOS artifact parsing,
and encrypted app data decryption.  All tools operate read-only on
evidence and index results into the case database.
"""

from __future__ import annotations

import contextlib
import logging
import mmap
import shutil
import sqlite3
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import error_response, make_tool_call_id, tool_response

logger = logging.getLogger(__name__)

_SQLITE_MAGIC = b"SQLite format 3\000"
_MAX_DB_SIZE = 500_000_000


def _require_binary(name: str) -> str | None:
    """Return the binary path if found, else None."""
    return shutil.which(name)


def _carve_sqlite_databases(
    image_path: str,
    tmpdir: str,
    max_dbs: int = 50,
) -> list[dict[str, object]]:
    """Scan a raw image for SQLite databases using magic byte matching.

    Uses mmap for memory-efficient scanning of large phone dumps.
    """
    file_size = Path(image_path).stat().st_size
    databases: list[dict[str, object]] = []

    with open(image_path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        offset = 0
        while len(databases) < max_dbs and offset < file_size:
            pos = mm.find(_SQLITE_MAGIC, offset)
            if pos == -1:
                break

            if pos + 100 > file_size:
                break
            header = mm[pos : pos + 100]
            page_size = int.from_bytes(header[16:18], "big")
            if page_size == 1:
                page_size = 65536
            db_size_pages = int.from_bytes(header[28:32], "big")
            db_size = page_size * db_size_pages

            if db_size > 0 and db_size < _MAX_DB_SIZE and pos + db_size <= file_size:
                db_path = Path(tmpdir) / f"carved_{pos:010x}.sqlite"
                db_path.write_bytes(mm[pos : pos + db_size])

                try:
                    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                    tables = [
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    ]
                    conn.close()
                    databases.append(
                        {
                            "offset": pos,
                            "size": db_size,
                            "path": str(db_path),
                            "tables": tables,
                        }
                    )
                except sqlite3.Error:
                    db_path.unlink(missing_ok=True)

            offset = pos + max(page_size, 1)

    return databases


@mcp.tool()
def carve_sqlite_from_raw(
    image_path: str,
    max_databases: int = 50,
) -> dict[str, object]:
    """Carve SQLite databases from a raw binary image (phone dump).

    Scans for SQLite magic bytes and extracts complete databases to
    the case working directory.  Returns database paths, sizes, and
    table listings.  Use query_sqlite_from_image or parse_android_artifacts
    on the carved databases for deeper analysis.

    Args:
        image_path: Path to the raw binary image (.bin phone dump).
        max_databases: Maximum number of databases to carve (default 50).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "max_databases": max_databases}

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "carve_sqlite_from_raw",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    try:
        ctx = get_ctx()
        carved_dir = Path(ctx.db.db_path).parent / "carved_sqlite"
        carved_dir.mkdir(parents=True, exist_ok=True)

        databases = _carve_sqlite_databases(image_path, str(carved_dir), max_dbs=max_databases)

        if not databases:
            elapsed = (time.monotonic() - t0) * 1000
            return tool_response(
                tc_id,
                "carve_sqlite_from_raw",
                params,
                {"status": "no_databases_found", "databases": []},
                "phone.carved_sqlite",
                elapsed,
            )

        summary_lines = [f"Carved {len(databases)} SQLite database(s) from {image_path}\n"]
        for db in databases:
            tables = db["tables"]
            tables_str = ", ".join(str(t) for t in tables) if isinstance(tables, list) else ""
            summary_lines.append(
                f"Offset 0x{db['offset']:010x}  Size {db['size']:,} bytes  "
                f"Tables: {tables_str or '(empty)'}"
            )
        summary_text = "\n".join(summary_lines)

        index_result = extract_and_index(
            summary_text,
            "phone.carved_sqlite",
            image_path,
            "sqlite_carver",
        )
        index_result["databases"] = databases

    except OSError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return error_response(
            tc_id,
            "carve_sqlite_from_raw",
            params,
            f"I/O error reading image: {exc}",
            elapsed,
            error_type="io_error",
        )

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "carve_sqlite_from_raw",
        params,
        index_result,
        "phone.carved_sqlite",
        elapsed,
    )


_ANDROID_ARTIFACTS: dict[str, dict[str, object]] = {
    "sms": {
        "db_names": ["mmssms.db"],
        "query": "SELECT address, body, date, type FROM sms ORDER BY date DESC LIMIT 1000",
        "label": "SMS/MMS Messages",
    },
    "contacts": {
        "db_names": ["contacts2.db"],
        "query": (
            "SELECT display_name, data1 FROM contacts "
            "JOIN data ON contacts._id = data.raw_contact_id "
            "WHERE mimetype_id IN (5, 6) LIMIT 1000"
        ),
        "label": "Contacts",
    },
    "calls": {
        "db_names": ["contacts2.db", "calllog.db"],
        "query": (
            "SELECT number, name, duration, date, type FROM calls ORDER BY date DESC LIMIT 1000"
        ),
        "label": "Call Log",
    },
    "browser": {
        "db_names": ["browser2.db"],
        "query": (
            "SELECT url, title, date FROM bookmarks "
            "WHERE bookmark = 0 ORDER BY date DESC LIMIT 500"
        ),
        "label": "Browser History",
    },
    "accounts": {
        "db_names": ["accounts.db"],
        "query": "SELECT name, type FROM accounts LIMIT 500",
        "label": "Accounts",
    },
    "downloads": {
        "db_names": ["downloads.db"],
        "query": "SELECT uri, _data, title, lastmod FROM downloads LIMIT 500",
        "label": "Downloads",
    },
    "calendar": {
        "db_names": ["calendar.db"],
        "query": "SELECT title, dtstart, dtend, description FROM Events LIMIT 500",
        "label": "Calendar Events",
    },
    "whatsapp": {
        "db_names": ["msgstore.db"],
        "query": (
            "SELECT key_remote_jid, data, timestamp "
            "FROM messages ORDER BY timestamp DESC LIMIT 1000"
        ),
        "label": "WhatsApp Messages",
    },
    "telegram": {
        "db_names": ["cache4.db"],
        "query": None,
        "label": "Telegram Data",
    },
    "signal": {
        "db_names": ["signal.db"],
        "query": "SELECT body, date_sent, address FROM sms ORDER BY date_sent DESC LIMIT 1000",
        "label": "Signal Messages",
    },
    "skype": {
        "db_names": ["main.db"],
        "query": (
            "SELECT author, body_xml, timestamp FROM Messages ORDER BY timestamp DESC LIMIT 1000"
        ),
        "label": "Skype Messages",
    },
    "gmail": {
        "db_names": [],
        "query": (
            "SELECT fromAddress, subject, snippet, dateReceivedMs "
            "FROM messages ORDER BY dateReceivedMs DESC LIMIT 500"
        ),
        "label": "Gmail",
        "glob_pattern": "mailstore.*.db",
    },
}


def _query_sqlite_safe(db_path: Path, query: str) -> list[str]:
    """Run a read-only query, returning formatted rows or empty list on error."""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query).fetchall()
        conn.close()
    except sqlite3.Error:
        return []

    if not rows:
        return []

    columns = rows[0].keys()
    lines = ["\t".join(columns)]
    for r in rows:
        lines.append("\t".join(str(r[c]) for c in columns))
    return lines


def _find_databases(search_dir: Path, db_names: list[str]) -> list[Path]:
    """Find database files by name anywhere under search_dir."""
    found: list[Path] = []
    for name in db_names:
        found.extend(search_dir.rglob(name))
    return found


@mcp.tool()
def parse_android_artifacts(
    evidence_path: str,
    artifact_types: list[str] | None = None,
) -> dict[str, object]:
    """Parse Android artifacts from a logical extraction or carved databases.

    evidence_path can be a directory containing extracted phone backup
    files, or a path to a raw .bin image (will carve SQLite DBs first).

    artifact_types filters which artifacts to parse (e.g. ["sms",
    "contacts", "calls", "whatsapp"]).  Parses all known types if omitted.

    Known artifact types: sms, contacts, calls, browser, accounts,
    downloads, calendar, whatsapp, telegram, signal, skype, gmail.

    Args:
        evidence_path: Directory with extracted Android data, or raw
            .bin phone dump.
        artifact_types: Optional list of artifact types to parse.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"evidence_path": evidence_path, "artifact_types": artifact_types}

    target = Path(evidence_path)
    if not target.exists():
        return error_response(
            tc_id,
            "parse_android_artifacts",
            params,
            f"Path not found: {evidence_path}",
            error_type="file_not_found",
        )

    types_to_parse = artifact_types or list(_ANDROID_ARTIFACTS.keys())
    invalid = [t for t in types_to_parse if t not in _ANDROID_ARTIFACTS]
    if invalid:
        return error_response(
            tc_id,
            "parse_android_artifacts",
            params,
            f"Unknown artifact types: {invalid}. Valid types: {sorted(_ANDROID_ARTIFACTS.keys())}",
            error_type="invalid_argument",
        )

    cleanup_tmpdir = None
    search_dir = target

    if target.is_file() and target.suffix.lower() in (".bin", ".raw", ".dd", ".img"):
        cleanup_tmpdir = tempfile.mkdtemp(prefix="mulder_android_carve_")
        databases = _carve_sqlite_databases(str(target), cleanup_tmpdir)
        if not databases:
            elapsed = (time.monotonic() - t0) * 1000
            return tool_response(
                tc_id,
                "parse_android_artifacts",
                params,
                {"status": "no_databases_found", "message": "No SQLite databases found in image"},
                "phone.android",
                elapsed,
            )
        search_dir = Path(cleanup_tmpdir)

    try:
        all_results: list[str] = []
        parsed_types: list[str] = []

        for atype in types_to_parse:
            spec = _ANDROID_ARTIFACTS[atype]
            query = spec["query"]
            if query is None:
                continue

            db_files: list[Path] = []
            glob_pat = spec.get("glob_pattern")
            if glob_pat:
                db_files = list(search_dir.rglob(str(glob_pat)))
            else:
                db_names = spec["db_names"]
                assert isinstance(db_names, list)
                db_files = _find_databases(search_dir, db_names)

            for db_path in db_files:
                lines = _query_sqlite_safe(db_path, str(query))
                if lines:
                    header = f"=== {spec['label']} ({db_path.name}) ==="
                    all_results.append(header + "\n" + "\n".join(lines))
                    if atype not in parsed_types:
                        parsed_types.append(atype)

        combined = "\n\n".join(all_results) if all_results else ""
        if combined:
            index_result = extract_and_index(
                combined,
                "phone.android",
                evidence_path,
                "android_parser",
            )
            index_result["parsed_types"] = parsed_types
        else:
            index_result = {
                "status": "no_results",
                "message": "No Android artifacts found",
                "searched_types": types_to_parse,
            }

    finally:
        if cleanup_tmpdir:
            shutil.rmtree(cleanup_tmpdir, ignore_errors=True)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "parse_android_artifacts",
        params,
        index_result,
        "phone.android",
        elapsed,
    )


_IOS_MANIFEST_ARTIFACTS: dict[str, dict[str, object]] = {
    "sms": {
        "file_id": "3d0d7e5fb2ce288813306e4d4636395e047a3d28",
        "db_name": "sms.db",
        "query": (
            "SELECT text, datetime(date + 978307200, 'unixepoch') as timestamp, "
            "handle.id as contact "
            "FROM message LEFT JOIN handle ON message.handle_id = handle.ROWID "
            "ORDER BY date DESC LIMIT 1000"
        ),
        "label": "SMS/iMessage",
    },
    "calls": {
        "file_id": "2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca",
        "db_name": "call_history.db",
        "query": "SELECT address, duration, date, flags FROM call ORDER BY date DESC LIMIT 1000",
        "label": "Call History",
    },
    "contacts": {
        "file_id": "31bb7ba8914766d4ba40d6dfb6113c8b614be442",
        "db_name": "AddressBook.sqlitedb",
        "query": (
            "SELECT c0First, c1Last, c16Phone FROM ABPersonFullTextSearch_content LIMIT 1000"
        ),
        "label": "Contacts",
    },
    "safari": {
        "file_id": "e74113c185fd8297e140571b60c618c6b47da205",
        "db_name": "History.db",
        "query": (
            "SELECT hi.url, hv.title, "
            "datetime(hv.visit_time + 978307200, 'unixepoch') as visit_time "
            "FROM history_items hi JOIN history_visits hv ON hi.id = hv.history_item "
            "ORDER BY hv.visit_time DESC LIMIT 500"
        ),
        "label": "Safari History",
    },
    "notes": {
        "file_id": None,
        "db_name": "NoteStore.sqlite",
        "query": "SELECT ZTITLE, ZBODY FROM ZSFNOTE LIMIT 500",
        "label": "Notes",
    },
    "locations": {
        "file_id": None,
        "db_name": "consolidated.db",
        "query": (
            "SELECT Latitude, Longitude, Timestamp, HorizontalAccuracy "
            "FROM CellLocation ORDER BY Timestamp DESC LIMIT 500"
        ),
        "label": "Location Data",
    },
    "voicemail": {
        "file_id": None,
        "db_name": "voicemail.db",
        "query": "SELECT sender, date, duration FROM voicemail ORDER BY date DESC LIMIT 500",
        "label": "Voicemail",
    },
    "knowledgec": {
        "file_id": None,
        "db_name": "knowledgeC.db",
        "query": (
            "SELECT ZOBJECT.ZSTREAMNAME, ZOBJECT.ZVALUESTRING, "
            "datetime(ZOBJECT.ZCREATIONDATE + 978307200, 'unixepoch') as created "
            "FROM ZOBJECT WHERE ZOBJECT.ZSTREAMNAME IS NOT NULL "
            "ORDER BY ZOBJECT.ZCREATIONDATE DESC LIMIT 500"
        ),
        "label": "KnowledgeC Activity",
    },
}


def _resolve_ios_manifest(backup_dir: Path) -> dict[str, Path]:
    """Parse Manifest.db to map file IDs to actual paths on disk.

    iTunes/Finder backups store files named by their SHA1 hash in
    two-character subdirectories (e.g. ``3d/3d0d7e5f...``).
    """
    manifest = backup_dir / "Manifest.db"
    if not manifest.exists():
        return {}

    mapping: dict[str, Path] = {}
    try:
        conn = sqlite3.connect(f"file:{manifest}?mode=ro", uri=True)
        rows = conn.execute("SELECT fileID, relativePath, domain FROM Files").fetchall()
        conn.close()
    except sqlite3.Error:
        return {}

    for file_id, _rel_path, _domain in rows:
        candidate = backup_dir / file_id[:2] / file_id
        if candidate.exists():
            mapping[file_id] = candidate
        flat_candidate = backup_dir / file_id
        if flat_candidate.exists():
            mapping[file_id] = flat_candidate

    return mapping


@mcp.tool()
def parse_ios_artifacts(
    evidence_path: str,
    artifact_types: list[str] | None = None,
) -> dict[str, object]:
    """Parse iOS artifacts from an iTunes/Finder backup or extracted files.

    Supports iTunes backup format (with Manifest.db mapping SHA1 file
    names to real paths) and directories containing extracted iOS
    databases directly.

    Known artifact types: sms, calls, contacts, safari, notes,
    locations, voicemail, knowledgec.

    Args:
        evidence_path: Path to the iOS backup directory or directory
            containing extracted iOS database files.
        artifact_types: Optional list of artifact types to parse.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"evidence_path": evidence_path, "artifact_types": artifact_types}

    target = Path(evidence_path)
    if not target.exists() or not target.is_dir():
        return error_response(
            tc_id,
            "parse_ios_artifacts",
            params,
            f"Directory not found: {evidence_path}",
            error_type="file_not_found",
        )

    types_to_parse = artifact_types or list(_IOS_MANIFEST_ARTIFACTS.keys())
    invalid = [t for t in types_to_parse if t not in _IOS_MANIFEST_ARTIFACTS]
    if invalid:
        return error_response(
            tc_id,
            "parse_ios_artifacts",
            params,
            f"Unknown artifact types: {invalid}. "
            f"Valid types: {sorted(_IOS_MANIFEST_ARTIFACTS.keys())}",
            error_type="invalid_argument",
        )

    manifest_map = _resolve_ios_manifest(target)
    has_manifest = bool(manifest_map)

    all_results: list[str] = []
    parsed_types: list[str] = []

    with tempfile.TemporaryDirectory(prefix="mulder_ios_") as tmpdir:
        for atype in types_to_parse:
            spec = _IOS_MANIFEST_ARTIFACTS[atype]

            db_path: Path | None = None
            file_id = str(spec["file_id"]) if spec["file_id"] else None
            db_name = str(spec["db_name"])
            if has_manifest and file_id and file_id in manifest_map:
                src = manifest_map[file_id]
                db_path = Path(tmpdir) / f"{atype}_{db_name}"
                shutil.copy2(str(src), str(db_path))
            else:
                candidates = list(target.rglob(db_name))
                if candidates:
                    db_path = candidates[0]

            if db_path is None or not db_path.exists():
                continue

            lines = _query_sqlite_safe(db_path, str(spec["query"]))
            if lines:
                header = f"=== {spec['label']} ({spec['db_name']}) ==="
                all_results.append(header + "\n" + "\n".join(lines))
                parsed_types.append(atype)

    combined = "\n\n".join(all_results) if all_results else ""
    if combined:
        index_result = extract_and_index(
            combined,
            "phone.ios",
            evidence_path,
            "ios_parser",
        )
        index_result["parsed_types"] = parsed_types
        index_result["manifest_found"] = has_manifest
    else:
        index_result = {
            "status": "no_results",
            "message": "No iOS artifacts found",
            "searched_types": types_to_parse,
            "manifest_found": has_manifest,
        }

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "parse_ios_artifacts",
        params,
        index_result,
        "phone.ios",
        elapsed,
    )


def _parse_shared_prefs(app_dir: Path) -> list[str]:
    """Extract key-value pairs from Android SharedPreferences XML files."""
    results: list[str] = []
    prefs_dirs = list(app_dir.rglob("shared_prefs"))
    xml_files: list[Path] = []
    for d in prefs_dirs:
        xml_files.extend(d.glob("*.xml"))
    xml_files.extend(app_dir.rglob("*.xml"))
    seen: set[Path] = set()

    for xml_path in xml_files:
        xml_path = xml_path.resolve()
        if xml_path in seen:
            continue
        seen.add(xml_path)
        try:
            tree = ET.parse(xml_path)  # noqa: S314
            root = tree.getroot()
            if root.tag != "map":
                continue
            entries: list[str] = []
            for child in root:
                key = child.get("name", "")
                value = child.get("value", "") or child.text or ""
                if key:
                    entries.append(f"  {key} = {value}")
            if entries:
                results.append(f"SharedPreferences: {xml_path.name}\n" + "\n".join(entries))
        except (ET.ParseError, OSError):
            continue

    return results


def _try_sqlcipher(db_path: Path, passwords: list[str]) -> list[str] | None:
    """Attempt to open an encrypted SQLite DB with SQLCipher.

    Returns table listing + sample data if successful, None otherwise.
    """
    try:
        from pysqlcipher3 import dbapi2 as sqlcipher
    except ImportError:
        return None

    for password in passwords:
        try:
            conn = sqlcipher.connect(str(db_path))
            conn.execute(f"PRAGMA key = '{password}'")
            tables = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            if not tables:
                conn.close()
                continue

            lines = [f"Decrypted with password: {'(empty)' if not password else '***'}"]
            lines.append(f"Tables: {', '.join(tables)}")

            for table in tables[:5]:
                try:
                    rows = conn.execute(f"SELECT * FROM [{table}] LIMIT 10").fetchall()
                    if rows:
                        desc = conn.execute(f"SELECT * FROM [{table}] LIMIT 0")
                        cols = [d[0] for d in desc.description]
                        lines.append(f"\n--- {table} ({len(cols)} columns) ---")
                        lines.append("\t".join(cols))
                        for r in rows:
                            lines.append("\t".join(str(v) for v in r))
                except sqlcipher.Error:
                    continue

            conn.close()
            return lines
        except sqlcipher.Error:
            with contextlib.suppress(Exception):
                conn.close()
            continue

    return None


def _extract_strings_from_file(file_path: Path, min_length: int = 8) -> list[str]:
    """Extract printable ASCII strings from a binary file."""
    if _require_binary("strings"):
        try:
            proc = subprocess.run(
                ["strings", f"-n{min_length}", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.stdout.strip():
                return proc.stdout.strip().splitlines()[:200]
        except (subprocess.TimeoutExpired, OSError):
            pass

    try:
        data = file_path.read_bytes()
    except OSError:
        return []

    current: list[int] = []
    strings: list[str] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(bytes(current).decode("ascii"))
            current = []
            if len(strings) >= 200:
                break
    if len(current) >= min_length and len(strings) < 200:
        strings.append(bytes(current).decode("ascii"))
    return strings


@mcp.tool()
def decrypt_app_data(
    app_data_path: str,
    known_passwords: list[str] | None = None,
) -> dict[str, object]:
    """Attempt to decrypt and parse application data.

    Searches the app data directory for SQLite databases (both plain
    and encrypted), SharedPreferences XML files, and binary data files.
    Tries SQLCipher decryption with provided passwords, parses XML
    configs for keys/tokens, and extracts plaintext strings from
    binary files.

    known_passwords should include any passwords found during the
    investigation (from keylogger output, browser saved passwords,
    etc.).  An empty string is always tried first (common default).

    Args:
        app_data_path: Path to the app's data directory.
        known_passwords: Optional list of passwords to try for
            SQLCipher decryption.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    pw_count = len(known_passwords or [])
    params = {"app_data_path": app_data_path, "known_passwords": ["***"] * pw_count}

    target = Path(app_data_path)
    if not target.exists():
        return error_response(
            tc_id,
            "decrypt_app_data",
            params,
            f"Path not found: {app_data_path}",
            error_type="file_not_found",
        )

    passwords = [""]
    if known_passwords:
        passwords.extend(p for p in known_passwords if p not in passwords)

    all_results: list[str] = []

    prefs_data = _parse_shared_prefs(target)
    if prefs_data:
        all_results.append("=== SharedPreferences / XML Config ===")
        all_results.extend(prefs_data)

    sqlite_files: list[Path] = []
    for ext in ("*.db", "*.sqlite", "*.sqlitedb"):
        sqlite_files.extend(target.rglob(ext))

    plaintext_dbs: list[str] = []
    encrypted_dbs: list[str] = []

    for db_path in sqlite_files:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            tables = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            conn.close()
            if tables:
                lines = [f"=== Plaintext DB: {db_path.name} ==="]
                lines.append(f"Tables: {', '.join(tables)}")
                for table in tables[:5]:
                    try:
                        c2 = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                        c2.row_factory = sqlite3.Row
                        rows = c2.execute(f"SELECT * FROM [{table}] LIMIT 10").fetchall()
                        c2.close()
                        if rows:
                            cols = rows[0].keys()
                            lines.append(f"\n--- {table} ---")
                            lines.append("\t".join(cols))
                            for r in rows:
                                lines.append("\t".join(str(r[c]) for c in cols))
                    except sqlite3.Error:
                        continue
                plaintext_dbs.append("\n".join(lines))
            continue
        except sqlite3.Error:
            pass

        cipher_result = _try_sqlcipher(db_path, passwords)
        if cipher_result:
            encrypted_dbs.append(
                f"=== Decrypted DB: {db_path.name} ===\n" + "\n".join(cipher_result)
            )

    all_results.extend(plaintext_dbs)
    all_results.extend(encrypted_dbs)

    binary_files = [
        f
        for f in target.rglob("*")
        if f.is_file()
        and f.suffix.lower() not in (".xml", ".db", ".sqlite", ".sqlitedb", ".json")
        and f.stat().st_size > 100
        and f.stat().st_size < 50_000_000
    ]
    for bf in binary_files[:20]:
        strings = _extract_strings_from_file(bf)
        if strings:
            all_results.append(
                f"=== Strings from {bf.name} ({len(strings)} extracted) ===\n"
                + "\n".join(strings[:50])
            )

    combined = "\n\n".join(all_results) if all_results else ""
    if combined:
        index_result = extract_and_index(
            combined,
            "phone.app_data",
            app_data_path,
            "app_decryptor",
        )
        index_result["plaintext_dbs_found"] = len(plaintext_dbs)
        index_result["encrypted_dbs_decrypted"] = len(encrypted_dbs)
        index_result["shared_prefs_found"] = len(prefs_data)
    else:
        index_result = {
            "status": "no_results",
            "message": "No parseable data found in app directory",
        }

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "decrypt_app_data",
        params,
        index_result,
        "phone.app_data",
        elapsed,
    )
