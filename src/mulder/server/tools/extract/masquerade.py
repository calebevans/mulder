"""Extension/content mismatch (file masquerading) detection over a TSK filesystem.

Walks ``fls -r -p -l`` (allocated and deleted entries), samples the head
of every regular file with ``icat`` and compares the magic-byte family
against what the extension claims.  A ``.zip`` that is really a ``.pptx``
or a ``.amr`` that is really an OLE ``.ppt`` is reported as a hit.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from typing import NamedTuple

from mulder.patterns import parse_mmls_rows
from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    require_binary,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import (
    _partition_table_text,
    _resolve_partition_offset,
)

__all__ = ["detect_masquerading"]

logger = logging.getLogger(__name__)

_SOURCE = "tsk.masquerade"
_DEFAULT_MAX_FILES = 5000
_DEFAULT_SAMPLE_BYTES = 8192
_WALK_BUDGET_S = 300
_HITS_IN_RESPONSE = 25
_FLS_TIMEOUT = 300
_NON_FS_ROWS = ("unallocated", "table", "gpt header")

# (offset, magic, family).  First match wins, so longer/more specific
# signatures go before short ones that share a prefix.
_SIGNATURES: tuple[tuple[int, bytes, str], ...] = (
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (0, b"%PDF", "pdf"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"GIF87a", "gif"),
    (0, b"GIF89a", "gif"),
    (0, b"II*\x00", "tiff"),
    (0, b"MM\x00*", "tiff"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"\x7fELF", "elf"),
    (0, b"MZ", "pe"),
    (0, b"{\\rtf", "rtf"),
    (0, b"ID3", "mp3"),
    (0, b"\xff\xfb", "mp3"),
    (0, b"\xff\xf3", "mp3"),
    (0, b"\xff\xf2", "mp3"),
    (0, b"#!AMR", "amr"),
    (4, b"ftyp", "mp4"),
    (0, b"SQLite format 3\x00", "sqlite"),
    (0, b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3", "onenote"),
    (0, b"OggS", "ogg"),
    (0, b"fLaC", "flac"),
    (0, b"\x1a\x45\xdf\xa3", "matroska"),
)

_RIFF_FORMS = {b"AVI ": "avi", b"WAVE": "wav", b"WEBP": "webp"}
_OOXML_DIRS = ((b"ppt/", "pptx"), (b"xl/", "xlsx"), (b"word/", "docx"))

# Extension -> content families that are legitimate for it.  Extensions
# not listed here are never reported (we cannot say what they should hold).
_EXT_FAMILIES: dict[str, frozenset[str]] = {}


def _ext(exts: str, *families: str) -> None:
    for e in exts.split():
        _EXT_FAMILIES[e] = frozenset(families)


_ext("pptx pptm ppsx potx", "pptx", "ooxml", "zip")
_ext("xlsx xlsm xltx xlsb", "xlsx", "ooxml", "zip")
_ext("docx docm dotx", "docx", "ooxml", "zip")
_ext("zip jar war apk xpi epub", "zip")
_ext("odt ods odp", "odf", "zip")
_ext("doc dot", "ole", "rtf")
_ext("xls xlt ppt pps pot msg", "ole")
_ext("rtf", "rtf")
_ext("pdf", "pdf")
_ext("jpg jpeg jpe", "jpeg")
_ext("png", "png")
_ext("gif", "gif")
_ext("bmp dib", "bmp")
_ext("tif tiff", "tiff")
_ext("webp", "webp")
_ext("7z", "7z")
_ext("rar", "rar")
_ext("gz tgz", "gzip")
_ext("bz2", "bzip2")
_ext("xz", "xz")
_ext("exe dll sys scr ocx cpl drv", "pe")
_ext("so elf", "elf")
_ext("mp3", "mp3")
_ext("amr", "amr")
_ext("mp4 m4a m4v mov 3gp heic", "mp4")
_ext("avi", "avi")
_ext("wav", "wav")
_ext("ogg oga ogv", "ogg")
_ext("flac", "flac")
_ext("mkv webm", "matroska")
_ext("db sqlite sqlite3", "sqlite")
_ext("one", "onenote")
_ext("txt log csv ini xml html htm svg json md", "text")

# Whole-name exceptions checked before the extension table.
_NAME_FAMILIES: dict[str, frozenset[str]] = {"thumbs.db": frozenset({"ole"})}

_TEXT_OK = (
    frozenset(range(0x20, 0x7F)) | frozenset(b"\t\n\r\f\v\x1b") | frozenset(range(0x80, 0x100))
)


def identify_content(head: bytes) -> str | None:
    """Return the content family for a file head, or None if unrecognised."""
    if not head:
        return None
    if head[:4] == b"PK\x03\x04":
        if b"[Content_Types].xml" in head or b"_rels/.rels" in head:
            return next((fam for marker, fam in _OOXML_DIRS if marker in head), "ooxml")
        if head[30:38] == b"mimetype" and b"application/vnd.oasis" in head:
            return "odf"
        return "zip"
    if head[:4] == b"PK\x05\x06":
        return "zip"
    if head[:4] == b"RIFF":
        return _RIFF_FORMS.get(head[8:12], "riff")
    if head[:2] == b"BM" and len(head) >= 14 and head[6:10] == b"\x00\x00\x00\x00":
        return "bmp"
    for offset, magic, family in _SIGNATURES:
        if head[offset : offset + len(magic)] == magic:
            return family
    if b"\x00" not in head and sum(b in _TEXT_OK for b in head) >= 0.95 * len(head):
        return "text"
    return None


def is_mismatch(path: str, detected: str | None) -> bool:
    """True when the file name implies a family and *detected* is not one of them."""
    name = path.rsplit("/", 1)[-1].lower()
    allowed = _NAME_FAMILIES.get(name) or _EXT_FAMILIES.get(_extension(name))
    return allowed is not None and detected is not None and detected not in allowed


class _Entry(NamedTuple):
    inode: str
    path: str
    deleted: bool
    size: int
    mtime: str
    atime: str
    ctime: str
    crtime: str


_FLS_TYPE_RE = re.compile(
    r"^(?P<nt>[A-Za-z\-])/(?P<mt>[A-Za-z\-])\s+(?P<del>\*\s+)?(?P<inode>\d+)(?:-\d+-\d+)?:$"
)


def parse_fls_long(text: str) -> list[_Entry]:
    """Parse ``fls -r -p -l`` output, keeping regular non-empty files only.

    Columns are tab separated: type/inode, path, mtime, atime, ctime,
    crtime, size, uid, gid.
    """
    out: list[_Entry] = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) < 9:
            continue
        m = _FLS_TYPE_RE.match(fields[0])
        if not m or m.group("mt").lower() in "dv" or m.group("nt").lower() == "v":
            continue
        try:
            size = int(fields[6])
        except ValueError:
            continue
        if size <= 0:
            continue
        out.append(
            _Entry(
                inode=m.group("inode"),
                path=fields[1].strip(),
                deleted=m.group("del") is not None,
                size=size,
                mtime=fields[2],
                atime=fields[3],
                ctime=fields[4],
                crtime=fields[5],
            )
        )
    return out


def _tsk_cmd(binary: str, image_path: str, offset: int, *args: str) -> list[str]:
    cmd = [binary, *args]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)
    return cmd


def _read_head(image_path: str, offset: int, inode: str, n: int) -> bytes:
    """Return the first *n* bytes of *inode* via icat, killing icat afterwards."""
    cmd = [*_tsk_cmd("icat", image_path, offset), inode]
    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            assert proc.stdout is not None
            try:
                head: bytes = proc.stdout.read(n)
                return head
            finally:
                proc.kill()
    except OSError:
        return b""


def _extension(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def detect_masquerading(
    image_path: str,
    partition_offset: int | None = None,
    max_files: int = _DEFAULT_MAX_FILES,
    sample_bytes: int = _DEFAULT_SAMPLE_BYTES,
    force: bool = False,
) -> dict[str, object]:
    """Find files whose content signature contradicts their extension (renamed files).

    Call on disk images and removable media, especially in data-theft or
    concealment investigations: a suspect who renames ``design.pptx`` to
    ``holiday.zip`` or ``report.xlsx`` to ``movie.7z`` defeats listings
    that trust extensions.  Walks allocated AND deleted entries with
    ``fls``, samples the head of each regular file with ``icat`` and
    compares magic bytes (OOXML, OLE, PDF, images, archives, PE/ELF,
    audio/video, SQLite, text) against the extension.  An OOXML document
    inside a ``.zip`` is reported as the document type it really is.

    Without ``partition_offset`` every partition mmls reports is walked;
    ones fls cannot open are listed under ``partitions_skipped`` so a
    partial scan is never mistaken for a clean image.

    Indexes as ``tsk.masquerade``, one line per mismatch with partition
    offset, path, extension, detected type, size, allocated/deleted
    status and timestamps.  Searchable via
    ``search(query, source='tsk.masquerade')``.

    Args:
        image_path: Path to the disk image (E01, dd, img).
        partition_offset: Sector offset of a single partition to scan.
            If omitted, all partitions are scanned.
        max_files: Stop sampling after this many files (default 5000).
        sample_bytes: Bytes read from the head of each file (default 8192).
        force: Re-run even if ``tsk.masquerade`` is already indexed.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "image_path": image_path,
        "partition_offset": partition_offset,
        "max_files": max_files,
        "sample_bytes": sample_bytes,
        "force": force,
    }
    name = "detect_masquerading"

    if not force:
        existing = sources_already_indexed([_SOURCE], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                name,
                params,
                {"status": "skipped", "reason": "Already indexed", "existing_sources": existing},
                _SOURCE,
                0.0,
            )

    for binary in ("fls", "icat"):
        if not require_binary(binary):
            return error_response(
                tc_id, name, params, f"{binary} not found on PATH", error_type="binary_missing"
            )

    if partition_offset is not None:
        targets = [(partition_offset, "explicit")]
    else:
        targets = [
            (start, desc)
            for start, length, desc in parse_mmls_rows(_partition_table_text(image_path))
            if length > 0 and not any(w in desc for w in _NON_FS_ROWS)
        ] or [(_resolve_partition_offset(image_path), "auto")]

    # ponytail: samples the first max_files in fls order within a wall-clock
    # budget; add user-directory prioritisation if system images need it.
    hits: list[dict[str, object]] = []
    scanned: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    listed = 0
    sampled = 0
    truncated = False
    for offset, desc in targets:
        try:
            proc = subprocess.run(
                _tsk_cmd("fls", image_path, offset, "-r", "-p", "-l"),
                capture_output=True,
                timeout=_FLS_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            skipped.append({"partition_offset": offset, "description": desc, "reason": "timeout"})
            continue
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", errors="replace")[:200].strip()
            reason = f"fls exited {proc.returncode}: {stderr}"
            skipped.append({"partition_offset": offset, "description": desc, "reason": reason})
            continue

        entries = parse_fls_long(proc.stdout.decode("utf-8", errors="replace"))
        listed += len(entries)
        part_hits = 0
        # Only extensions we know a family for can ever produce a hit, so skip the rest.
        for entry in (e for e in entries if _extension(e.path) in _EXT_FAMILIES):
            if sampled >= max_files or time.monotonic() - t0 > _WALK_BUDGET_S:
                truncated = True
                break
            sampled += 1
            detected = identify_content(_read_head(image_path, offset, entry.inode, sample_bytes))
            if is_mismatch(entry.path, detected):
                part_hits += 1
                hits.append(
                    {
                        "path": entry.path,
                        "extension": _extension(entry.path),
                        "detected": detected,
                        "size": entry.size,
                        "deleted": entry.deleted,
                        "inode": entry.inode,
                        "mtime": entry.mtime,
                        "atime": entry.atime,
                        "ctime": entry.ctime,
                        "crtime": entry.crtime,
                        "partition_offset": offset,
                    }
                )
        scanned.append(
            {
                "partition_offset": offset,
                "description": desc,
                "files_listed": len(entries),
                "mismatches": part_hits,
            }
        )

    if not scanned:
        return error_response(
            tc_id,
            name,
            params,
            "fls could not open any partition: "
            + "; ".join(f"offset {s['partition_offset']} ({s['reason']})" for s in skipped),
            error_type="extraction_failed",
            suggestion="Run run_mmls and pass the data partition start sector as the offset.",
        )

    lines = [
        f"{h['path']} | ext={h['extension']} | detected={h['detected']} | size={h['size']} | "
        f"{'deleted' if h['deleted'] else 'allocated'} | inode={h['inode']} | "
        f"mtime={h['mtime']} | atime={h['atime']} | ctime={h['ctime']} | crtime={h['crtime']} | "
        f"offset={h['partition_offset']}"
        for h in hits
    ]
    # Partition report goes before the hits so the 500-char preview never drops it.
    summary: dict[str, object] = {
        "mismatches": len(hits),
        "partitions_scanned": scanned,
        "partitions_skipped": skipped,
        "files_listed": listed,
        "files_sampled": sampled,
        "truncated": truncated,
        "hits": hits[:_HITS_IN_RESPONSE],
    }
    summary.update(extract_and_index("\n".join(lines), _SOURCE, image_path, "sleuthkit"))
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, name, params, summary, _SOURCE, elapsed)
