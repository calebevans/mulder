"""MCP tools for case management and evidence scanning.

Tier 1 tools: help the agent orient before running any extractions.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tarfile
import threading
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

logger = logging.getLogger(__name__)

_EXTRACT_TIMEOUT = 600


@mcp.tool()
def scan_evidence(
    evidence_path: str,
    case_id: str | None = None,
    replace: bool = False,
) -> str:
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
    ev_path = Path(evidence_path).expanduser().resolve()

    if not ev_path.exists():
        return json.dumps({"error": f"Evidence path does not exist: {ev_path}"})

    if case_id is None:
        case_id = slugify(ev_path.name)

    try:
        return _scan_evidence_inner(ev_path, case_id, replace)
    except Exception as exc:
        logger.exception("scan_evidence failed for %s", ev_path)
        return json.dumps({"error": f"scan_evidence failed: {exc}"})


def _hash_and_register_evidence(manifest: list[dict[str, object]]) -> None:
    """Hash each evidence file and register it for chain of custody."""
    import hashlib as _hashlib

    from mulder.server.app import get_ctx, has_ctx

    if not has_ctx():
        return
    ctx = get_ctx()
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
        except Exception:
            logger.debug("Failed to hash %s", fp, exc_info=True)


def _scan_evidence_inner(ev_path: Path, case_id: str, replace: bool) -> str:
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
        return json.dumps(result)

    threading.Thread(
        target=_hash_and_register_evidence,
        args=(list(manifest),),
        daemon=True,
    ).start()

    archive_count = type_counts.get("compressed_archive", 0)
    message = (
        f"Case '{case_id}' created. Found {len(manifest)} evidence item(s). "
        "Evidence hashing running in background for chain of custody. "
        "Use Tier 2 extraction tools to start analyzing immediately."
    )
    if archive_count > 0:
        message += (
            f" NOTE: {archive_count} compressed archive(s) detected. "
            "Call extract_archive() on each to unpack evidence files inside, "
            "then scan_evidence() on the extracted directory."
        )

    return json.dumps(
        {
            "status": "success",
            "case_id": case_id,
            "evidence_path": str(ev_path),
            "evidence_tree": "\n".join(tree_lines),
            "type_summary": type_counts,
            "total_items": len(manifest),
            "message": message,
        }
    )


@mcp.tool()
def list_cases() -> str:
    """List all cases in the database directory.

    Returns case IDs, evidence paths, source counts, and creation dates
    for every case that has been created or ingested.
    """
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

    return json.dumps(
        {
            "cases": cases,
            "active_case": active,
            "total": len(cases),
        }
    )


@mcp.tool()
def open_case(case_id: str) -> str:
    """Switch the active case to an already-existing case.

    All subsequent tool calls will operate on this case.

    Args:
        case_id: The case identifier to load (must already exist).
    """
    cfg = get_cfg()
    db_path = cfg.db_dir / f"{case_id}.db"

    if not db_path.exists():
        return json.dumps(
            {
                "error": f"Case '{case_id}' not found. Use list_cases() to see available cases, "
                f"or scan_evidence() to create a new one.",
            }
        )

    ctx = load_case(case_id)
    source_count = ctx.db.get_source_count()

    return json.dumps(
        {
            "status": "success",
            "case_id": case_id,
            "source_count": source_count,
        }
    )


def _human_size(nbytes: int) -> str:
    """Convert byte count to human-readable string."""
    size = float(nbytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


@mcp.tool()
def verify_evidence_integrity() -> str:
    """Verify the integrity of all registered evidence files.

    Re-computes SHA-256 hashes for every evidence file registered at the
    start of the investigation and compares against the stored hash.
    Returns a summary with per-file verification status.

    Call this before ``finalize_report()`` to include chain-of-custody
    verification in the final report.
    """
    ctx = get_ctx()
    t0 = time.monotonic()

    results = ctx.db.verify_evidence_integrity()
    total = len(results)
    verified = sum(1 for r in results if r["status"] == "verified")
    modified = sum(1 for r in results if r["status"] == "modified")
    missing = sum(1 for r in results if r["status"] == "missing")

    elapsed_ms = (time.monotonic() - t0) * 1000

    if total == 0:
        status = "no_evidence_registered"
    elif modified > 0 or missing > 0:
        status = "integrity_issues_detected"
    else:
        status = "all_verified"

    return json.dumps(
        {
            "status": status,
            "total_files": total,
            "verified_count": verified,
            "modified_count": modified,
            "missing_count": missing,
            "files": results,
            "elapsed_ms": round(elapsed_ms, 1),
        }
    )


def _extract_zip(archive: Path, dest: Path) -> list[str]:
    """Extract a zip archive to *dest* and return paths relative to *dest*."""
    with zipfile.ZipFile(archive, "r") as zf:
        zf.extractall(dest)
    return [str(f.relative_to(dest)) for f in dest.rglob("*") if f.is_file()]


def _safe_tar_filter(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    """Allow extraction but neutralize absolute symlinks and path traversal."""
    if member.name.startswith("/") or ".." in member.name:
        return None
    if (member.issym() or member.islnk()) and member.linkname.startswith("/"):
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
def extract_archive(
    archive_path: str,
    extract_to: str | None = None,
) -> str:
    """Extract a compressed evidence archive (zip, tar, gz, bz2, 7z, rar).

    Extracts the archive contents so that evidence files inside become
    accessible to extraction and analysis tools.  Extracts to a writable
    temporary directory under the mulder cases directory -- the original
    evidence is never modified.

    After extraction, call ``scan_evidence`` on the extracted directory
    to classify the newly available evidence files.

    Args:
        archive_path: Path to the compressed archive.
        extract_to: Optional destination directory.  If omitted, creates
            a directory under the mulder cases dir.
    """
    archive = Path(archive_path).expanduser().resolve()

    if not archive.exists():
        return json.dumps({"error": f"Archive not found: {archive}"})

    if extract_to:
        dest = Path(extract_to).expanduser().resolve()
    else:
        cfg = get_cfg()
        dest = cfg.db_dir / "extracted" / archive.stem

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
        elif ext in (".7z", ".rar"):
            if not shutil.which("7z"):
                return json.dumps(
                    {
                        "error": "7z not found on PATH. Install p7zip-full.",
                    }
                )
            files = _extract_7z(archive, dest)
        else:
            return json.dumps(
                {
                    "error": f"Unsupported archive format: {ext}",
                    "supported": [
                        ".zip",
                        ".tar",
                        ".tar.gz",
                        ".tar.bz2",
                        ".tgz",
                        ".gz",
                        ".bz2",
                        ".7z",
                        ".rar",
                    ],
                }
            )
    except Exception as exc:
        return json.dumps(
            {
                "error": f"Extraction failed: {exc}",
                "archive": str(archive),
            }
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

    return json.dumps(
        {
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
    )
