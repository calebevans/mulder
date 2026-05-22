"""File carving and bulk extraction MCP tools."""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    _FILE_LIST_CAP,
    _PREVIEW_CHAR_LIMIT,
    error_response,
    make_tool_call_id,
    tool_response,
)

__all__ = [
    "run_binwalk",
    "run_bulk_extractor",
    "run_foremost",
    "run_photorec",
    "run_scalpel",
]

logger = logging.getLogger(__name__)

_BULK_TIMEOUT = 1800
_SCALPEL_TIMEOUT = 1800
_PHOTOREC_TIMEOUT = 3600
_TOOL_TIMEOUT = 600


def _require_binary(name: str) -> str | None:
    """Return the binary path if found, else None."""
    return shutil.which(name)


def _bulk_page_size() -> int:
    """Pick bulk_extractor page size based on available system memory.

    Allocates roughly 1/4 of available memory across threads (bulk_extractor
    needs ~2-3x page size per thread for decompression buffers).  Clamped
    between 16 MiB and 512 MiB, rounded down to a power of 2.  Adapts
    automatically to small containers and large servers.
    """
    _16M = 16 * 1024 * 1024
    avail = 0
    try:
        import psutil

        avail = psutil.virtual_memory().available
    except (ImportError, AttributeError):
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        avail = int(line.split()[1]) * 1024
                        break
        except OSError:
            pass
    if avail <= 0:
        return _16M
    ncpu = os.cpu_count() or 2
    per_thread = avail // (ncpu * 4)
    page = max(_16M, min(per_thread, 512 * 1024 * 1024))
    page = 1 << (page.bit_length() - 1)
    return page


@mcp.tool()
def run_bulk_extractor(
    image_path: str,
    features: list[str] | None = None,
    scanners: list[str] | None = None,
    max_depth: int | None = None,
) -> dict[str, object]:
    """Carve IOCs (URLs, emails, domains, IPs) from a disk image using bulk_extractor.

    Runs bulk_extractor and indexes each feature file as a separate
    source (bulk.email, bulk.url, bulk.domain, etc.).

    Pass *scanners* to run only specific bulk_extractor scanners,
    which is significantly faster than the default (all scanners).
    For IOC-focused investigations, ``scanners=["email", "net",
    "exif", "winpe", "winlnk", "httplogs"]`` skips expensive
    scanners like zip decompression and NTFS parsing.

    Available scanner names: accts, aes, base64, elf, email, evtx,
    exif, facebook, find, gps, gzip, httplogs, json, kml_carved,
    msxml, net, ntfsindx, ntfslogfile, ntfsmft, ntfsusn, pdf, rar,
    sqlite, utmp, vcard_carved, vin, windirs, winlnk, winpe,
    winprefetch, zip.

    NOTE: There is no "url" scanner. URLs are extracted by the
    "email" and "httplogs" scanners. IPs/domains come from "net".

    Args:
        image_path: Path to the disk image.
        features: Optional list of feature types to index from the
            output (e.g. ["email", "url"]).  Indexes all if omitted.
        scanners: Optional list of bulk_extractor scanner names to
            enable.  When provided, ONLY these scanners run (uses
            -E/-e flags).  When omitted, all scanners run.
        max_depth: Maximum recursion depth for decompressing nested
            archives (default: 12).  Use ``max_depth=2`` for a faster
            first-pass scan: most forensic artifacts are at depth
            0-1.  Re-run with full depth on specific images if you
            suspect nested compressed content.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {
        "image_path": image_path,
        "features": features,
        "scanners": scanners,
        "max_depth": max_depth,
    }

    if not _require_binary("bulk_extractor"):
        return error_response(
            tc_id, "run_bulk_extractor", params, "bulk_extractor not found on PATH"
        )

    with tempfile.TemporaryDirectory(prefix="mulder_bulk_") as tmpdir:
        ncpu = os.cpu_count() or 2
        page_size = _bulk_page_size()
        cmd = ["bulk_extractor", "-j", str(ncpu), "-G", str(page_size), "-o", tmpdir]

        if max_depth is not None:
            cmd.extend(["-M", str(max_depth)])

        _SCANNER_ALIASES = {
            "url": "email",
            "domain": "net",
            "ip": "net",
            "http": "httplogs",
            "kml": "kml_carved",
            "vcard": "vcard_carved",
            "email_lg": "email",
            "accts_lg": "accts",
            "gps_lg": "gps",
            "base16_lg": "base64",
            "httpheader_lg": "httplogs",
        }
        if scanners:
            resolved = [_SCANNER_ALIASES.get(s, s) for s in scanners]
            deduped = list(dict.fromkeys(resolved))
            cmd.extend(["-E", deduped[0]])
            for s in deduped[1:]:
                cmd.extend(["-e", s])

        cmd.append(image_path)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=_BULK_TIMEOUT, check=False
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_bulk_extractor",
                params,
                f"bulk_extractor timed out after {_BULK_TIMEOUT}s",
            )

        if proc.returncode != 0:
            stderr_hint = (proc.stderr or "")[:_PREVIEW_CHAR_LIMIT].strip()
            logger.error("bulk_extractor exited %d: %r", proc.returncode, stderr_hint)
            return error_response(
                tc_id,
                "run_bulk_extractor",
                params,
                f"bulk_extractor exited {proc.returncode}: {stderr_hint}",
                error_type="extraction_failed",
            )

        feature_map = {
            "email": "bulk.email",
            "url": "bulk.url",
            "domain": "bulk.domain",
            "ip": "bulk.ip",
            "telephone": "bulk.telephone",
            "find": "bulk.find",
            "pii": "bulk.pii",
            "elf": "bulk.elf",
            "exe": "bulk.exe",
            "json": "bulk.json",
            "winpe": "bulk.winpe",
            "winlnk": "bulk.winlnk",
        }

        results: list[object] = []
        for feature_file in sorted(Path(tmpdir).iterdir()):
            if not feature_file.is_file() or feature_file.suffix == ".xml":
                continue
            stem = feature_file.stem.replace("_histogram", "").replace("_find", "find")
            if "histogram" in feature_file.name:
                continue
            if features and stem not in features:
                continue

            source_name = feature_map.get(stem, f"bulk.{stem}")
            try:
                text = feature_file.read_text(encoding="utf-8", errors="replace").strip()
                if text:
                    results.append(
                        extract_and_index(text, source_name, image_path, "bulk_extractor")
                    )
            except OSError:
                pass

    total_windows = sum(r.get("windows_indexed", 0) for r in results if isinstance(r, dict))
    for r in results:
        if isinstance(r, dict):
            r.pop("source_id", None)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_bulk_extractor",
        params,
        {
            "features_indexed": len(results),
            "total_windows_indexed": total_windows,
            "per_feature": results,
        },
        "bulk",
        elapsed,
    )


@mcp.tool()
def run_foremost(image_path: str) -> dict[str, object]:
    """Carve files from a disk image using foremost.

    Recovers deleted files by scanning for file headers and footers
    in the raw disk image.  Indexes an audit summary of carved files.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not _require_binary("foremost"):
        return error_response(tc_id, "run_foremost", params, "foremost not found on PATH")

    with tempfile.TemporaryDirectory(prefix="mulder_foremost_") as tmpdir:
        try:
            subprocess.run(
                ["foremost", "-i", image_path, "-o", tmpdir, "-T"],
                capture_output=True,
                text=True,
                timeout=_BULK_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(tc_id, "run_foremost", params, "foremost timed out")

        audit_text = ""
        for audit_file in Path(tmpdir).rglob("audit.txt"):
            with contextlib.suppress(OSError):
                audit_text += audit_file.read_text(encoding="utf-8", errors="replace")

    summary = extract_and_index(
        audit_text or "No files carved", "foremost.audit", image_path, "foremost"
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_foremost", params, summary, "foremost.audit", elapsed)


@mcp.tool()
def run_scalpel(image_path: str) -> dict[str, object]:
    """Carve files from a disk image or partition using Scalpel.

    Scalpel recovers files based on header/footer signatures.  More
    configurable than foremost: edit /etc/scalpel/scalpel.conf to
    enable specific file types before running.

    Args:
        image_path: Path to the disk image or raw partition.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not _require_binary("scalpel"):
        return error_response(
            tc_id,
            "run_scalpel",
            params,
            "scalpel not found on PATH",
            error_type="binary_missing",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_scalpel",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_scalpel_") as tmpdir:
        cmd = ["scalpel", "-o", tmpdir, image_path]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_SCALPEL_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_scalpel",
                params,
                f"scalpel timed out after {_SCALPEL_TIMEOUT}s",
                error_type="timeout",
            )

        audit_path = Path(tmpdir) / "audit.txt"
        audit_text = ""
        if audit_path.exists():
            audit_text = audit_path.read_text(errors="replace")

        if not audit_text.strip():
            audit_text = proc.stdout.strip() or "scalpel produced no output"

        summary = extract_and_index(audit_text, "scalpel.audit", image_path, "scalpel")

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_scalpel", params, summary, "scalpel.audit", elapsed)


@mcp.tool()
def run_binwalk(target_path: str, extract: bool = False) -> dict[str, object]:
    """Scan a file for embedded files, firmware headers, and compressed archives.

    binwalk identifies embedded content by signature.  Use extract=True
    to also extract discovered embedded files into a temp directory.

    Args:
        target_path: Path to the file to scan.
        extract: If True, extract embedded files (``binwalk -e``).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path, "extract": extract}

    if not _require_binary("binwalk"):
        return error_response(
            tc_id,
            "run_binwalk",
            params,
            "binwalk not found on PATH",
            error_type="binary_missing",
        )

    if not Path(target_path).exists():
        return error_response(
            tc_id,
            "run_binwalk",
            params,
            f"File not found: {target_path}",
            error_type="file_not_found",
        )

    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(target_path)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT * 3,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_binwalk",
            params,
            "binwalk timed out",
            error_type="timeout",
        )

    summary = extract_and_index(proc.stdout.strip(), "binwalk.scan", target_path, "binwalk")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_binwalk", params, summary, "binwalk.scan", elapsed)


@mcp.tool()
def run_photorec(image_path: str) -> dict[str, object]:
    """Recover deleted files from a disk image using PhotoRec.

    PhotoRec recovers files by signature (480+ file types) from disk
    images, partitions, or raw devices.  Runs in non-interactive mode.

    Args:
        image_path: Path to the disk image or partition.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not _require_binary("photorec"):
        return error_response(
            tc_id,
            "run_photorec",
            params,
            "photorec not found on PATH",
            error_type="binary_missing",
            suggestion="Install testdisk package: apt-get install testdisk",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_photorec",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_photorec_") as tmpdir:
        cmd = [
            "photorec",
            "/cmd",
            image_path,
            "fileopt,everything,enable",
            f"search,{tmpdir}/",
        ]
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_PHOTOREC_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_photorec",
                params,
                f"photorec timed out after {_PHOTOREC_TIMEOUT}s",
                error_type="timeout",
            )

        report_path = Path(tmpdir) / "report.xml"
        report_text = ""
        if report_path.exists():
            report_text = report_path.read_text(errors="replace")

        if not report_text.strip():
            recovered = list(Path(tmpdir).rglob("*"))
            file_list = [str(f.relative_to(tmpdir)) for f in recovered if f.is_file()]
            report_text = f"PhotoRec recovered {len(file_list)} file(s):\n" + "\n".join(
                file_list[:_FILE_LIST_CAP]
            )
            if len(file_list) > _FILE_LIST_CAP:
                report_text += f"\n... and {len(file_list) - _FILE_LIST_CAP} more"

        summary = extract_and_index(report_text, "photorec.report", image_path, "photorec")

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_photorec", params, summary, "photorec.report", elapsed)
