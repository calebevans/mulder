"""MCP tools for case management and evidence scanning.

Tier 1 tools: help the agent orient before running any extractions.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path

from mulder.server.app import (
    create_case,
    get_cfg,
    get_ctx,
    has_ctx,
    load_case,
    mcp,
    slugify,
)
from mulder.server.helpers import error_response, hash_output, make_tool_call_id
from mulder.server.tool_access import ALL_ROLES, Role, tool_access

logger = logging.getLogger(__name__)

_EXTRACT_TIMEOUT = 600


@mcp.tool()
@tool_access(Role.CATALOG)
def scan_evidence(
    evidence_path: str,
    case_id: str | None = None,
    replace: bool = False,
) -> dict[str, object]:
    """Scan an evidence directory and create a new case for investigation.

    Walks the evidence directory recursively, classifies files by type
    (disk images, memory dumps, EVTX logs, log files), and returns a
    manifest describing what is available.  Creates an empty case database
    so subsequent extraction tools can populate it incrementally.

    Does NOT run any extractors or perform any analysis.  The agent
    decides which tools to run based on the manifest.

    Args:
        evidence_path: Directory (or file) containing forensic evidence.
        case_id: Unique case identifier.  Auto-derived from directory name
            if omitted.
        replace: If True and the case already exists, delete and recreate
            it.  If False (default), returns info about the existing case
            so the caller can decide whether to replace or resume.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path,
        "case_id": case_id,
        "replace": replace,
    }

    ev_path = Path(evidence_path).expanduser().resolve()

    if not ev_path.exists():
        return error_response(
            tc_id,
            "scan_evidence",
            params,
            f"Evidence path does not exist: {ev_path}",
            (time.monotonic() - t0) * 1000,
            error_type="file_not_found",
        )

    enforced_id = os.environ.get("MULDER_CASE_ID", "")
    if enforced_id:
        if case_id is not None and case_id != enforced_id:
            logger.warning(
                "Overriding requested case_id '%s' with MULDER_CASE_ID='%s'",
                case_id,
                enforced_id,
            )
        case_id = enforced_id
    elif case_id is None:
        case_id = slugify(ev_path.name)

    try:
        result = _scan_evidence_inner(ev_path, case_id, replace)
    except Exception as exc:
        logger.exception("scan_evidence failed for %r", ev_path)
        return error_response(
            tc_id,
            "scan_evidence",
            params,
            f"scan_evidence failed: {exc}",
            (time.monotonic() - t0) * 1000,
        )

    elapsed = (time.monotonic() - t0) * 1000
    result["tool_call_id"] = tc_id
    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="scan_evidence",
            params=params,
            output_hash=hash_output(result),
            duration_ms=elapsed,
        )
    return result


def _hash_and_register_evidence(manifest: list[dict[str, object]]) -> list[str]:
    """Hash each evidence file and register it for chain of custody.

    Returns:
        List of file paths that failed to hash.
    """
    import hashlib as _hashlib

    from mulder.server.app import get_ctx, has_ctx

    if not has_ctx():
        return []
    ctx = get_ctx()
    failed_files: list[str] = []
    for item in manifest:
        fp = Path(str(item.get("path", "")))
        if not fp.is_file():
            continue
        try:
            h = _hashlib.sha256()
            size = 0
            with open(fp, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
                    size += len(chunk)
            ctx.db.register_evidence_file(
                file_path=str(fp),
                sha256=h.hexdigest(),
                size_bytes=size,
            )
        except Exception as exc:
            logger.warning("Failed to hash evidence file %s: %s", fp, exc)
            failed_files.append(str(fp))
    return failed_files


def _scan_evidence_inner(ev_path: Path, case_id: str, replace: bool) -> dict[str, object]:
    """Inner implementation of scan_evidence with full error propagation."""
    from mulder.extractors.classifier import ClassifierConfig, EvidenceClassifier

    classifier = EvidenceClassifier(ClassifierConfig())
    classified = classifier.classify(ev_path)

    manifest: list[dict[str, object]] = []
    for item in classified:
        entry: dict[str, object] = {
            "path": str(item.path),
            "artifact_type": item.artifact_type,
        }
        try:
            if item.path.is_file():
                size = item.path.stat().st_size
                entry["size_bytes"] = size
                entry["size_human"] = _human_size(size)
        except OSError:
            pass
        manifest.append(entry)

    type_counts: dict[str, int] = {}
    for mi in manifest:
        t = str(mi["artifact_type"])
        type_counts[t] = type_counts.get(t, 0) + 1

    tree_lines: list[str] = [str(ev_path) + "/"]
    for mi in manifest:
        try:
            rel = str(Path(str(mi["path"])).relative_to(ev_path))
        except ValueError:
            rel = str(mi["path"])
        depth = rel.count("/") + rel.count("\\")
        indent = "  " * depth
        name = Path(rel).name
        size_label = mi.get("size_human", "")
        atype = mi["artifact_type"]
        tree_lines.append(f"{indent}{name}  [{atype}] {size_label}")

    result = create_case(case_id, str(ev_path), replace=replace)

    if isinstance(result, dict) and result.get("status") == "case_exists":
        result["evidence_tree"] = "\n".join(tree_lines)
        result["type_summary"] = type_counts
        result["total_items"] = len(manifest)
        return result

    if isinstance(result, dict) and result.get("status") == "error":
        return result

    failed_files = _hash_and_register_evidence(list(manifest))

    archive_count = type_counts.get("compressed_archive", 0)
    message = (
        f"Case '{case_id}' created. Found {len(manifest)} evidence item(s). "
        "Evidence hashing complete for chain of custody. "
        "Use Tier 2 extraction tools to start analyzing immediately."
    )
    if failed_files:
        message += f" WARNING: {len(failed_files)} file(s) failed to hash."
    if archive_count > 0:
        message += (
            f" NOTE: {archive_count} compressed archive(s) detected. "
            "If you need to unpack them, use extract_archive with the "
            "full path shown in the evidence tree. If archives were already "
            "extracted by a prior phase, skip this step and proceed with "
            "analysis tools directly."
        )

    response: dict[str, object] = {
        "status": "success",
        "case_id": case_id,
        "evidence_path": str(ev_path),
        "evidence_tree": "\n".join(tree_lines),
        "type_summary": type_counts,
        "total_items": len(manifest),
        "message": message,
    }
    if failed_files:
        response["failed_files"] = failed_files
    return response


@mcp.tool()
@tool_access(Role.CATALOG | Role.EXTRACT_PLANNER | Role.REPORT)
def list_cases() -> dict[str, object]:
    """List all cases in the database directory.

    Returns case IDs, evidence paths, source counts, and creation dates
    for every case that has been created or ingested.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    cfg = get_cfg()
    cases: list[dict[str, object]] = []

    for db_path in sorted(cfg.db_dir.glob("*.db")):
        cid = db_path.stem
        try:
            from mulder.db import CaseDB

            db = CaseDB.open(cid, cfg.db_dir)
            meta = db.get_case_metadata()
            count = db.get_source_count()
            cases.append(
                {
                    "case_id": cid,
                    "evidence_root": meta.evidence_root,
                    "source_count": count,
                    "ingested_at": meta.ingested_at,
                }
            )
            db.close()
        except Exception as exc:
            logger.warning("Failed to read case '%s': %s", cid, exc)
            cases.append({"case_id": cid, "error": str(exc)})

    active = None
    if has_ctx():
        active = get_ctx().case_id

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "results": cases,
        "result_count": len(cases),
        "active_case": active,
    }

    elapsed = (time.monotonic() - t0) * 1000
    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="list_cases",
            params={},
            output_hash=hash_output(result),
            duration_ms=elapsed,
        )
    return result


@mcp.tool()
@tool_access(ALL_ROLES)
def open_case(case_id: str) -> dict[str, object]:
    """Switch the active case to an already-existing case.

    All subsequent tool calls will operate on this case.

    Args:
        case_id: The case identifier to load (must already exist).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"case_id": case_id}

    cfg = get_cfg()
    db_path = cfg.db_dir / f"{case_id}.db"

    if not db_path.exists():
        return error_response(
            tc_id,
            "open_case",
            params,
            f"Case '{case_id}' not found. Use list_cases() to see available cases, "
            f"or scan_evidence() to create a new one.",
            (time.monotonic() - t0) * 1000,
            error_type="not_found",
        )

    ctx = load_case(case_id)
    source_count = ctx.db.get_source_count()

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "case_id": case_id,
        "source_count": source_count,
    }

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="open_case",
        params=params,
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return result


def _human_size(nbytes: int) -> str:
    """Convert byte count to human-readable string."""
    size = float(nbytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


@mcp.tool()
@tool_access(Role.CATALOG)
def verify_evidence_integrity() -> dict[str, object]:
    """Verify the integrity of all indexed source data.

    Recomputes BLAKE2b hashes from stored windows and compares against
    the hashes recorded at ingestion. This is a fast DB-only operation.
    Wall-clock time is included in the response since verification
    duration is meaningful for integrity auditing.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    ctx = get_ctx()

    results = ctx.db.verify_evidence_integrity()
    total = len(results)
    verified = sum(1 for r in results if r["status"] == "verified")
    modified = sum(1 for r in results if r["status"] == "modified")
    no_hash = sum(1 for r in results if r["status"] == "no_hash_recorded")

    elapsed_ms = (time.monotonic() - t0) * 1000

    if total == 0:
        status = "no_sources_indexed"
    elif modified > 0:
        status = "integrity_issues_detected"
    else:
        status = "all_verified"

    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": status,
        "total_sources": total,
        "verified_count": verified,
        "modified_count": modified,
        "no_hash_count": no_hash,
        "sources": results,
        "elapsed_ms": round(elapsed_ms, 1),
    }

    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="verify_evidence_integrity",
        params={},
        output_hash=hash_output(result),
        duration_ms=elapsed_ms,
    )
    return result


def _extract_zip(archive: Path, dest: Path) -> list[str]:
    """Extract a zip archive to *dest* and return paths relative to *dest*.

    Falls back to the ``7z`` binary when Python's zipfile module cannot
    handle the compression method (e.g. deflate64, LZMA).
    """
    try:
        with zipfile.ZipFile(archive, "r") as zf:
            for member in zf.namelist():
                if member.startswith("/") or ".." in member:
                    logger.warning("Skipping unsafe zip entry: %r", member)
                    continue
                zf.extract(member, dest)
    except (NotImplementedError, zipfile.BadZipFile):
        if not shutil.which("7z"):
            raise
        return _extract_7z(archive, dest)
    return [str(f.relative_to(dest)) for f in dest.rglob("*") if f.is_file()]


def _safe_tar_filter(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    """Allow extraction but neutralize absolute symlinks and path traversal."""
    if member.name.startswith("/") or ".." in member.name:
        return None
    if member.issym() or member.islnk():
        if ".." in member.linkname:
            return None
        if member.linkname.startswith("/"):
            member.linkname = member.linkname.lstrip("/")
    return member


def _extract_tar(archive: Path, dest: Path) -> list[str]:
    """Extract a tar/tar-compressed archive to *dest*; return relative file paths."""
    with tarfile.open(archive, "r:*") as tf:
        tf.extractall(dest, filter=_safe_tar_filter)
    return [str(f.relative_to(dest)) for f in dest.rglob("*") if f.is_file()]


def _extract_7z(archive: Path, dest: Path) -> list[str]:
    """Extract via the ``7z`` CLI to *dest*; return paths relative to *dest*."""
    cmd = ["7z", "x", f"-o{dest}", "-y", str(archive)]
    subprocess.run(cmd, capture_output=True, timeout=_EXTRACT_TIMEOUT, check=True)
    return [str(f.relative_to(dest)) for f in dest.rglob("*") if f.is_file()]


@mcp.tool()
@tool_access(Role.CATALOG | Role.EXTRACT_EXECUTOR)
def extract_archive(
    archive_path: str,
    extract_to: str | None = None,
) -> dict[str, object]:
    """Extract a compressed evidence archive to make its contents accessible.

    Call when the evidence catalog includes compressed archives (zip, tar,
    gz, bz2, 7z, rar). Idempotent: returns existing files if already
    extracted. The original evidence is never modified.

    Outputs to a writable directory under the mulder cases directory.
    Follow up with extraction tools (run_volatility_batch, run_fls, etc.)
    on the extracted files.

    Args:
        archive_path: Path to the compressed archive.
        extract_to: Optional destination directory.  If omitted, creates
            a directory under the mulder cases dir.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"archive_path": archive_path, "extract_to": extract_to}

    archive = Path(archive_path).expanduser().resolve()

    if not archive.exists():
        return error_response(
            tc_id,
            "extract_archive",
            params,
            f"Archive not found: {archive}",
            (time.monotonic() - t0) * 1000,
            error_type="file_not_found",
        )

    if extract_to:
        dest = Path(extract_to).expanduser().resolve()
    else:
        cfg = get_cfg()
        dest = cfg.db_dir / "extracted" / archive.stem

    # Idempotent: if already extracted, return the existing files
    if dest.exists() and any(dest.iterdir()):
        existing_files = [str(f.relative_to(dest)) for f in dest.rglob("*") if f.is_file()]
        result: dict[str, object] = {
            "tool_call_id": tc_id,
            "status": "already_extracted",
            "archive": str(archive),
            "extracted_to": str(dest),
            "files": existing_files,
            "message": (
                f"Archive already extracted to {dest}. "
                f"Use this path for analysis tools "
                f"(e.g., memory_path='{dest}/{existing_files[0]}' "
                "for run_volatility)."
                if existing_files
                else ""
            ),
        }
        elapsed = (time.monotonic() - t0) * 1000
        if has_ctx():
            ctx = get_ctx()
            ctx.audit.log_tool_call(
                tool_call_id=tc_id,
                tool_name="extract_archive",
                params=params,
                output_hash=hash_output(result),
                duration_ms=elapsed,
            )
        return result

    dest.mkdir(parents=True, exist_ok=True)

    name_lower = archive.name.lower()
    ext = archive.suffix.lower()

    try:
        if ext == ".zip":
            files = _extract_zip(archive, dest)
        elif (
            ext in (".tar", ".tgz")
            or name_lower.endswith((".tar.gz", ".tar.bz2"))
            or (ext in (".gz", ".bz2") and ".tar" not in name_lower)
        ):
            files = _extract_tar(archive, dest)
        elif ext in (".7z", ".rar") or ".7z." in name_lower:
            if not shutil.which("7z"):
                return error_response(
                    tc_id,
                    "extract_archive",
                    params,
                    "7z not found on PATH. Install p7zip-full.",
                    (time.monotonic() - t0) * 1000,
                    error_type="binary_missing",
                )
            files = _extract_7z(archive, dest)
        else:
            return error_response(
                tc_id,
                "extract_archive",
                params,
                f"Unsupported archive format: {ext}",
                (time.monotonic() - t0) * 1000,
                error_type="unsupported_format",
            )
    except Exception as exc:
        logger.error("Archive extraction failed for %r: %s", archive, exc)
        return error_response(
            tc_id,
            "extract_archive",
            params,
            f"Extraction failed: {exc}",
            (time.monotonic() - t0) * 1000,
        )

    from mulder.extractors.classifier import ClassifierConfig, EvidenceClassifier

    classifier = EvidenceClassifier(ClassifierConfig())
    classified = classifier.classify(dest)

    manifest: list[dict[str, object]] = []
    for item in classified:
        entry: dict[str, object] = {
            "path": str(item.path),
            "artifact_type": item.artifact_type,
        }
        try:
            if item.path.is_file():
                size = item.path.stat().st_size
                entry["size_bytes"] = size
                entry["size_human"] = _human_size(size)
        except OSError:
            pass
        manifest.append(entry)

    type_counts: dict[str, int] = {}
    for mi in manifest:
        t = str(mi["artifact_type"])
        type_counts[t] = type_counts.get(t, 0) + 1

    result = {
        "tool_call_id": tc_id,
        "status": "success",
        "archive": str(archive),
        "extracted_to": str(dest),
        "total_files_extracted": len(files),
        "type_summary": type_counts,
        "total_evidence_items": len(manifest),
        "message": (
            f"Extracted {len(files)} file(s) to {dest}. "
            f"Found {len(manifest)} evidence item(s). "
            "Use scan_evidence on the extracted directory to create a case, "
            "or run extraction tools directly on the evidence files."
        ),
    }

    elapsed = (time.monotonic() - t0) * 1000
    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="extract_archive",
            params=params,
            output_hash=hash_output(result),
            duration_ms=elapsed,
        )
    return result
