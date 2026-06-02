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
from typing import cast

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    _FILE_LIST_CAP,
    _PREVIEW_CHAR_LIMIT,
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    require_binary,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

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
_MAX_FEATURE_FILE_SIZE = 256 * 1024 * 1024  # 256 MiB read cap per feature file
_MIN_FREE_SPACE_BYTES = 1024 * 1024 * 1024  # 1 GiB absolute minimum


def _check_disk_space(image_path: str, multiplier: float = 0.1) -> str | None:
    """Verify sufficient temp-partition space before running a carving tool.

    Estimates needed space as *multiplier* times the image file size
    (minimum 1 GiB) and compares against free space on the temp
    filesystem.

    Args:
        image_path: Path to the disk image.
        multiplier: Fraction of image size to require as free space.

    Returns:
        An error message when space is insufficient, None otherwise.
    """
    try:
        image_size = Path(image_path).stat().st_size
    except OSError:
        return None
    needed = max(int(image_size * multiplier), _MIN_FREE_SPACE_BYTES)
    try:
        usage = shutil.disk_usage(tempfile.gettempdir())
    except OSError:
        return None
    if usage.free < needed:
        free_gib = usage.free / (1024**3)
        needed_gib = needed / (1024**3)
        return (
            f"Insufficient disk space: {free_gib:.1f} GiB free, "
            f"estimated {needed_gib:.1f} GiB needed"
        )
    return None


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


_SCANNER_ALIASES: dict[str, str] = {
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

_FEATURE_SOURCE_MAP: dict[str, str] = {
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


def _build_bulk_extractor_cmd(
    image_path: str,
    outdir: str,
    scanners: list[str] | None,
    depth: int | None,
) -> list[str]:
    """Build the bulk_extractor command line.

    Configures thread count from available CPUs, page size from available
    memory, scanner selection via aliases, and recursion depth.

    Args:
        image_path: Path to the disk image to scan.
        outdir: Output directory for feature files.
        scanners: Scanner names to enable (resolved through aliases).
            When None, all scanners run.
        depth: Maximum recursion depth, or None for the default.

    Returns:
        Complete argument list ready for subprocess.run.
    """
    ncpu = os.cpu_count() or 2
    page_size = _bulk_page_size()
    cmd = ["bulk_extractor", "-j", str(ncpu), "-G", str(page_size), "-o", outdir]

    if depth is not None:
        cmd.extend(["-M", str(depth)])

    if scanners:
        resolved = [_SCANNER_ALIASES.get(s, s) for s in scanners]
        deduped = list(dict.fromkeys(resolved))
        cmd.extend(["-E", deduped[0]])
        for s in deduped[1:]:
            cmd.extend(["-e", s])

    cmd.append(image_path)
    return cmd


def _read_capped_feature_file(feature_file: Path) -> str | None:
    """Read a single feature file, capped at ``_MAX_FEATURE_FILE_SIZE``.

    Args:
        feature_file: Path to a bulk_extractor feature file.

    Returns:
        Stripped file content, or None on read failure or empty content.
    """
    try:
        file_size = feature_file.stat().st_size
        if file_size > _MAX_FEATURE_FILE_SIZE:
            logger.warning(
                "Feature file %s is %d bytes; reading first %d only",
                feature_file.name,
                file_size,
                _MAX_FEATURE_FILE_SIZE,
            )
        with open(feature_file, encoding="utf-8", errors="replace") as fh:
            text = fh.read(_MAX_FEATURE_FILE_SIZE).strip()
    except OSError:
        return None
    return text or None


def _stream_and_index_features(
    outdir: str,
    features: list[str] | None,
    image_path: str,
) -> list[dict[str, object]]:
    """Read, index, and discard each feature file sequentially.

    Bounds peak memory to a single feature file (capped at
    ``_MAX_FEATURE_FILE_SIZE`` characters) rather than all combined.
    Safely handles a missing or empty output directory so that partial
    results can be collected after a timeout.

    Args:
        outdir: bulk_extractor output directory.
        features: Feature stems to include, or None for all.
        image_path: Disk image path for source registration.

    Returns:
        List of per-feature index summary dicts.
    """
    results: list[dict[str, object]] = []
    out_path = Path(outdir)
    if not out_path.is_dir():
        return results
    for feature_file in sorted(out_path.iterdir()):
        if not feature_file.is_file() or feature_file.suffix == ".xml":
            continue
        stem = feature_file.stem.replace("_histogram", "").replace("_find", "find")
        if "histogram" in feature_file.name:
            continue
        if features and stem not in features:
            continue

        text = _read_capped_feature_file(feature_file)
        if text is None:
            continue

        source_name = _FEATURE_SOURCE_MAP.get(stem, f"bulk.{stem}")
        summary = extract_and_index(text, source_name, image_path, "bulk_extractor")
        results.append(summary)
        del text

    return results


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_bulk_extractor(
    image_path: str,
    features: list[str] | None = None,
    scanners: list[str] | None = None,
    max_depth: int | None = None,
    force: bool = False,
) -> dict[str, object]:
    """Carve IOCs (URLs, emails, domains, IPs) from a disk image using bulk_extractor.

    Call on any disk image or raw partition. No prerequisite tools
    required. Pass specific scanners for faster runs (e.g.
    ``scanners=["email", "net", "httplogs"]``). Use max_depth=2 for a
    quick first pass. NOTE: there is no "url" scanner; URLs come from
    "email" and "httplogs". IPs/domains come from "net".

    Indexes each feature type as ``bulk.<feature>`` (e.g. ``bulk.email``,
    ``bulk.url``). Use get_carved_iocs() for a summary or search() to
    query specific features.

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
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "image_path": image_path,
        "features": features,
        "scanners": scanners,
        "max_depth": max_depth,
        "force": force,
    }

    if not force:
        existing = sources_already_indexed(["bulk."], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "run_bulk_extractor",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "bulk",
                0.0,
            )

    if not require_binary("bulk_extractor"):
        return error_response(
            tc_id, "run_bulk_extractor", params, "bulk_extractor not found on PATH"
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_bulk_extractor",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    space_err = _check_disk_space(image_path)
    if space_err:
        return error_response(
            tc_id, "run_bulk_extractor", params, space_err, error_type="disk_space"
        )

    timeout = adaptive_timeout(image_path, base=_BULK_TIMEOUT)

    with tempfile.TemporaryDirectory(prefix="mulder_bulk_") as tmpdir:
        cmd = _build_bulk_extractor_cmd(image_path, tmpdir, scanners, max_depth)
        timed_out = False

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            proc = None
            logger.warning(
                "bulk_extractor timed out after %ds on %s; salvaging partial results",
                timeout,
                image_path,
            )

        if proc is not None and proc.returncode != 0:
            stderr_hint = (proc.stderr or "")[:_PREVIEW_CHAR_LIMIT].strip()
            logger.error("bulk_extractor exited %d: %r", proc.returncode, stderr_hint)
            return error_response(
                tc_id,
                "run_bulk_extractor",
                params,
                f"bulk_extractor exited {proc.returncode}: {stderr_hint}",
                error_type="extraction_failed",
            )

        results = _stream_and_index_features(tmpdir, features, image_path)

    total_windows = sum(cast(int, r.get("windows_indexed", 0)) for r in results)
    for r in results:
        r.pop("source_id", None)

    elapsed = (time.monotonic() - t0) * 1000
    response_data: dict[str, object] = {
        "features_indexed": len(results),
        "total_windows_indexed": total_windows,
        "per_feature": results,
    }
    if timed_out:
        response_data["partial"] = True
        response_data["warning"] = (
            f"bulk_extractor timed out after {timeout}s; "
            f"indexed {len(results)} partial feature file(s)"
        )

    return tool_response(
        tc_id,
        "run_bulk_extractor",
        params,
        response_data,
        "bulk",
        elapsed,
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_foremost(image_path: str) -> dict[str, object]:
    """Carve files from a disk image using foremost.

    Recovers deleted files by scanning for file headers and footers
    in the raw disk image.  Indexes an audit summary of carved files.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path}

    if not require_binary("foremost"):
        return error_response(tc_id, "run_foremost", params, "foremost not found on PATH")

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_foremost",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    space_err = _check_disk_space(image_path, multiplier=0.5)
    if space_err:
        return error_response(tc_id, "run_foremost", params, space_err, error_type="disk_space")

    timeout = adaptive_timeout(image_path, base=_BULK_TIMEOUT)

    with tempfile.TemporaryDirectory(prefix="mulder_foremost_") as parent:
        outdir = os.path.join(parent, "output")
        try:
            subprocess.run(
                ["foremost", "-i", image_path, "-o", outdir, "-T"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_foremost",
                params,
                f"foremost timed out after {timeout}s",
            )

        audit_text = ""
        for audit_file in Path(parent).rglob("audit.txt"):
            with contextlib.suppress(OSError):
                audit_text += audit_file.read_text(encoding="utf-8", errors="replace")

    summary = extract_and_index(
        audit_text or "No files carved", "foremost.audit", image_path, "foremost"
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_foremost", params, summary, "foremost.audit", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
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
    params: dict[str, object] = {"image_path": image_path}

    if not require_binary("scalpel"):
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

    space_err = _check_disk_space(image_path, multiplier=0.5)
    if space_err:
        return error_response(tc_id, "run_scalpel", params, space_err, error_type="disk_space")

    timeout = adaptive_timeout(image_path, base=_SCALPEL_TIMEOUT)

    with tempfile.TemporaryDirectory(prefix="mulder_scalpel_") as parent:
        outdir = os.path.join(parent, "output")
        cmd = ["scalpel", "-o", outdir, image_path]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_scalpel",
                params,
                f"scalpel timed out after {timeout}s",
                error_type="timeout",
            )

        audit_path = Path(outdir) / "audit.txt"
        audit_text = ""
        if audit_path.exists():
            audit_text = audit_path.read_text(errors="replace")

        if not audit_text.strip():
            audit_text = proc.stdout.strip() or "scalpel produced no output"

        summary = extract_and_index(audit_text, "scalpel.audit", image_path, "scalpel")

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_scalpel", params, summary, "scalpel.audit", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
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
    params: dict[str, object] = {"target_path": target_path, "extract": extract}

    if not require_binary("binwalk"):
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

    if extract:
        space_err = _check_disk_space(target_path, multiplier=0.5)
        if space_err:
            return error_response(tc_id, "run_binwalk", params, space_err, error_type="disk_space")

    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(target_path)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=adaptive_timeout(target_path),
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
@tool_access(Role.EXTRACT_EXECUTOR)
def run_photorec(image_path: str) -> dict[str, object]:
    """Recover deleted files from a disk image using PhotoRec.

    PhotoRec recovers files by signature (480+ file types) from disk
    images, partitions, or raw devices.  Runs in non-interactive mode.

    Args:
        image_path: Path to the disk image or partition.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path}

    if not require_binary("photorec"):
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

    space_err = _check_disk_space(image_path, multiplier=0.5)
    if space_err:
        return error_response(tc_id, "run_photorec", params, space_err, error_type="disk_space")

    timeout = adaptive_timeout(image_path, base=_PHOTOREC_TIMEOUT)

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
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_photorec",
                params,
                f"photorec timed out after {timeout}s",
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
