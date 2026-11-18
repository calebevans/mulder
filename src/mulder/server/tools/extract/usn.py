"""NTFS change journal extraction: ``$Extend\\$UsnJrnl:$J`` -> MFTECmd -> ``ez.usnjrnl``."""

from __future__ import annotations

import contextlib
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from mulder.patterns import fls_file_entries
from mulder.server.app import mcp
from mulder.server.helpers import (
    adaptive_timeout,
    cli_path,
    error_response,
    make_tool_call_id,
    require_binary,
    run_subprocess,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.misc import _run_ez_tool
from mulder.server.tools.extract.tsk import _resolve_partition_offset
from mulder.server.tools.tsk import _detect_filesystem_type

__all__ = ["run_usn_parser"]

_SOURCE = "ez.usnjrnl"
_TOOL = "run_usn_parser"
# $Extend is MFT entry 11 on every NTFS volume, so the journal's inode is one
# directory listing away and needs no indexed file listing.
_EXTEND_INODE = "11"
_JOURNAL_NAME = "$usnjrnl:$j"
_CHUNK = 1024 * 1024
_ZEROS = bytes(_CHUNK)
# Records never cross a 4096-byte boundary, so any multiple of it starts a record.
_USN_PAGE = 4096
# Journal data parsed, newest first. 256 MiB is about 2.5 million records and a
# CSV of roughly twice that size held in memory while it is indexed; a larger
# journal loses its oldest records, which the response says.
_MAX_JOURNAL_BYTES = 256 * 1024 * 1024


def _stream_journal(
    cmd: list[str], timeout: int, dest: Path | None = None, start: int = 0
) -> tuple[int, int] | None:
    """Read ``icat``'s output once and return ``(first data offset, total bytes)``.

    A journal is sparse: its logical size is everything ever written and only
    the tail holds records, so ``icat`` emits gigabytes of zeros first. Without
    *dest* the stream is only measured, to the 1 MiB chunk holding the first
    record. With *dest*, everything from byte *start* on is written to it.
    Returns None when ``icat`` fails or runs past *timeout*.
    """
    first_data = -1
    pos = 0
    try:
        with (
            subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc,
            dest.open("wb") if dest else contextlib.nullcontext() as out,
        ):
            timer = threading.Timer(timeout, proc.kill)
            timer.start()
            try:
                while proc.stdout and (chunk := proc.stdout.read(_CHUNK)):
                    if first_data < 0 and chunk != _ZEROS[: len(chunk)]:
                        first_data = pos
                    if out and pos + len(chunk) > start:
                        out.write(chunk[max(0, start - pos) :])
                    pos += len(chunk)
            finally:
                timer.cancel()
    except OSError:
        return None
    if proc.returncode != 0 or first_data < 0:
        return None
    return first_data, pos


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_usn_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse the NTFS change journal ($UsnJrnl:$J) from a disk image using MFTECmd.

    Call on a Windows (NTFS) disk image. The journal records each recent file
    create, rename, overwrite and delete with its time, which is what
    find_encryption_activity reads to time a mass encryption.

    Indexes as ``ez.usnjrnl``. The journal is a ring holding only the most
    recent changes, so its first record is not the first activity on the
    volume. A missing journal is not a clean volume: journaling can be off,
    and attackers delete the journal to hide what they changed.

    Args:
        image_path: Path to the disk image.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "force": force}

    def _error(message: str, error_type: str = "unknown") -> dict[str, object]:
        elapsed = (time.monotonic() - t0) * 1000
        return error_response(tc_id, _TOOL, params, message, elapsed, error_type=error_type)

    if not force:
        existing = sources_already_indexed([_SOURCE], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                _TOOL,
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                _SOURCE,
                0.0,
            )

    offset = _resolve_partition_offset(image_path)
    fs_type = _detect_filesystem_type(image_path, offset)
    if fs_type and fs_type != "ntfs":
        return tool_response(
            tc_id,
            _TOOL,
            params,
            {
                "status": "skipped",
                "reason": f"Not applicable: filesystem is {fs_type}, no USN journal",
                "filesystem_type": fs_type,
            },
            _SOURCE,
            (time.monotonic() - t0) * 1000,
        )
    if not (require_binary("fls") and require_binary("icat")):
        return _error("fls and icat (The Sleuth Kit) not found on PATH", "binary_missing")

    offset_args = ["-o", str(offset)] if offset > 0 else []
    listing = run_subprocess(
        ["fls", *offset_args, cli_path(image_path), _EXTEND_INODE], timeout=120
    )
    if isinstance(listing, str) or listing.returncode != 0:
        detail = listing if isinstance(listing, str) else listing.stderr.strip()[:200]
        return _error(f"Could not list $Extend on {image_path}: {detail}", "tool_failed")
    inode = next(
        (e.inode for e in fls_file_entries(listing.stdout) if e.path.lower() == _JOURNAL_NAME),
        None,
    )
    if inode is None:
        return _error(
            "No $UsnJrnl:$J in $Extend: the volume has no change journal. Journaling may "
            "be off, or the journal was deleted (fsutil usn deletejournal), which attackers "
            "do to hide file changes. This is not evidence that nothing changed; "
            "find_encryption_activity can still work from the MFT (run_mft_parser).",
            "no_journal",
        )

    cmd = ["icat", *offset_args, cli_path(image_path), inode]
    timeout = adaptive_timeout(image_path)
    unread = f"icat returned no journal records from $UsnJrnl:$J (inode {inode})"
    measured = _stream_journal(cmd, timeout)
    if measured is None:
        return _error(unread, "tool_failed")
    first_data, total = measured
    start = max(first_data, (total - _MAX_JOURNAL_BYTES) // _USN_PAGE * _USN_PAGE)

    with tempfile.TemporaryDirectory(prefix="mulder_usn_") as tmpdir:
        journal = Path(tmpdir) / "$J"
        if _stream_journal(cmd, timeout, journal, start) is None:
            return _error(unread, "tool_failed")
        response = _run_ez_tool(
            "MFTECmd.dll", ["-f", str(journal)], _SOURCE, image_path, tc_id, _TOOL, params, t0
        )

    response["journal_bytes_parsed"] = total - start
    if start > first_data:
        response["truncated"] = (
            f"The journal holds {total - first_data} bytes of records; only the newest "
            f"{total - start} were parsed. Older records were not examined."
        )
    return response
