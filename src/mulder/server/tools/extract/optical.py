"""Optical media (CD/DVD: UDF, ISO 9660) listing and extraction MCP tools.

Sleuth Kit has no UDF/ISO 9660 support, so ``run_fls``/``run_fsstat`` fail on
a burned disc with "Possible encryption detected (High entropy)".  These tools
use :mod:`mulder.extractors.optical` instead.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path

from mulder.extractors.optical import (
    OpticalEntry,
    OpticalError,
    extract_optical,
    list_optical,
    raw_image,
)
from mulder.server import source_names as _sn
from mulder.server.app import get_cfg, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = ["extract_optical_file", "run_optical_listing"]

logger = logging.getLogger(__name__)

_SRC = _sn.SRC_OPTICAL_LISTING


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_optical_listing(image_path: str, force: bool = False) -> dict[str, object]:
    """List every file on an optical disc image (CD/DVD: UDF or ISO 9660), deleted ones included.

    Call on a disc image (CD-R, DVD) instead of run_fls/run_mmls/run_mactime,
    which Sleuth Kit cannot apply to optical filesystems.  Reads E01 and raw
    (.dd/.iso/.bin) images.  On write-once UDF media every earlier burn
    session is walked too, so files deleted or renamed later are still
    listed (marked ``*`` / ``deleted``) and remain extractable.

    Indexes as ``optical.listing``: a header line with the filesystem,
    volume label and session count, then one line per entry with path,
    size, modified/created timestamps (UTC) and present/deleted state.
    Searchable via ``search(query, source='optical.listing')``.  Follow up
    with extract_optical_file to pull a file out for read_evidence_file,
    analyze_office_document or run_hashdeep.

    Args:
        image_path: Path to the disc image (E01, dd, iso, bin).
        force: Re-run even if ``optical.listing`` already exists.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "force": force}

    if not force:
        existing = sources_already_indexed([_SRC], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "run_optical_listing",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                _SRC,
                0.0,
            )

    try:
        with raw_image(image_path) as raw:
            listing = list_optical(raw)
    except (OpticalError, OSError) as exc:
        return error_response(
            tc_id,
            "run_optical_listing",
            params,
            f"Not a readable optical disc image: {exc}",
            error_type="not_optical_media",
            suggestion="For hard disk and USB images use run_mmls / run_fls instead.",
        )

    summary = extract_and_index(listing.to_text(), _SRC, image_path, "mulder-optical")
    summary["filesystem"] = listing.fs_type
    summary["volume_label"] = listing.volume_label
    summary["sessions"] = listing.generations
    summary["files_present"] = sum(1 for e in listing.entries if not e.is_dir and not e.deleted)
    summary["files_deleted"] = sum(1 for e in listing.entries if not e.is_dir and e.deleted)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_optical_listing", params, summary, _SRC, elapsed)


def _find_entry(entries: list[OpticalEntry], file_path: str) -> OpticalEntry | None:
    """The entry whose path equals *file_path* (case-insensitive); a present one wins."""
    wanted = "/" + file_path.strip("/").lower()
    matches = [e for e in entries if not e.is_dir and e.path.lower() == wanted]
    return min(matches, key=lambda e: e.deleted, default=None)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def extract_optical_file(image_path: str, file_path: str) -> dict[str, object]:
    """Extract one file from an optical disc image so other tools can read it.

    Call after run_optical_listing.  The file is copied under the case's
    ``extracted/`` directory; pass the returned ``extracted_to`` path to
    read_evidence_file, analyze_office_document, run_hashdeep, yara_scan_files
    or run_exiftool.  Deleted files on write-once (CD-R/DVD-R) media are
    recoverable: their data is never overwritten.

    Args:
        image_path: Path to the disc image (E01, dd, iso, bin).
        file_path: Path on the disc exactly as run_optical_listing shows it
            (e.g. ``/design/winter_storm.amr``).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "file_path": file_path}

    dest_dir = Path(get_cfg().db_dir) / "extracted" / f"{Path(image_path).stem}_optical"
    try:
        with raw_image(image_path) as raw:
            listing = list_optical(raw)
            entry = _find_entry(listing.entries, file_path)
            if entry is None:
                names = sorted({e.path for e in listing.entries if not e.is_dir})
                return error_response(
                    tc_id,
                    "extract_optical_file",
                    params,
                    f"{file_path!r} is not on the disc. Files: {', '.join(names[:40])}",
                    error_type="file_not_found",
                )
            dest = dest_dir / entry.path.strip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            written = extract_optical(raw, entry, dest)
    except (OpticalError, OSError) as exc:
        return error_response(
            tc_id,
            "extract_optical_file",
            params,
            f"Could not extract {file_path!r}: {exc}",
            error_type="extraction_failed",
        )

    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    elapsed = (time.monotonic() - t0) * 1000
    results: dict[str, object] = {
        "extracted_to": str(dest),
        "disc_path": entry.path,
        "size_bytes": written,
        "sha256": digest,
        "deleted_on_disc": entry.deleted,
        "modified": entry.mtime,
        "created": entry.ctime,
        "hint": (
            "Pass extracted_to to read_evidence_file, analyze_office_document, "
            "run_hashdeep or run_exiftool."
        ),
    }
    if written != entry.size:
        results["warning"] = f"expected {entry.size} bytes, extracted {written}"
    return tool_response(tc_id, "extract_optical_file", params, results, None, elapsed)
