"""MCP Adapters for the local EVTX, Kubernetes, and CloudTrail pilot packs."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from mulder.models import SourceRow, WindowRow
from mulder.packs.pilot_analysis import (
    MAX_DOCUMENT_BYTES,
    MAX_DOCUMENTS,
    DocumentCompression,
    DocumentMediaType,
    LocalEvidenceDocument,
    PilotAnalysisResult,
    analyze_cloudtrail_documents,
    analyze_evtx_documents,
    analyze_kubernetes_documents,
)
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import hash_output, make_tool_call_id
from mulder.server.tool_access import Role, tool_access


def _raw_source(windows: Sequence[WindowRow]) -> bytes:
    chunks: list[bytes] = []
    size = 0
    for window in sorted(windows, key=lambda item: item.line_start):
        chunk = window.raw_text.encode("utf-8", errors="surrogatepass")
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_DOCUMENT_BYTES:
            break
    return b"".join(chunks)[: MAX_DOCUMENT_BYTES + 1]


def _source_id(source_name: str) -> str:
    """Derive a relocation-stable identity from the evidence-relative name."""
    return "file_" + hashlib.sha256(source_name.encode("utf-8")).hexdigest()[:20]


def _evtx_media_type(source: SourceRow) -> DocumentMediaType:
    return "text/csv" if source.extractor == "eztools" else "application/x-evtx-lines"


def _indexed_evtx_documents() -> tuple[LocalEvidenceDocument, ...]:
    ctx = get_ctx()
    documents: list[LocalEvidenceDocument] = []
    for source in sorted(ctx.db.get_sources(), key=lambda item: item.source_name):
        if not source.source_name.startswith("evtx.") or source.source_name == "evtx.manifest":
            continue
        documents.append(
            LocalEvidenceDocument(
                source_id=str(source.source_id),
                source_name=source.source_name,
                media_type=_evtx_media_type(source),
                content=_raw_source(ctx.db.get_windows_by_source(source.source_name)),
            )
        )
    return tuple(documents)


def _is_kubernetes_candidate(path: Path, root: Path) -> bool:
    if path.suffix.casefold() not in {".json", ".yaml", ".yml", ".log"}:
        return False
    relative = path.relative_to(root)
    context = "/".join(part.casefold() for part in relative.parts)
    markers = (
        "kubernetes",
        "k8s",
        "kube-audit",
        "audit.log",
        "manifests",
        "networkpolicy",
        "rbac",
    )
    return any(marker in context for marker in markers)


def _is_cloudtrail_candidate(path: Path, root: Path) -> bool:
    name = path.name.casefold()
    if not (name.endswith(".json") or name.endswith(".json.gz")):
        return False
    context = "/".join(part.casefold() for part in path.relative_to(root).parts)
    return "cloudtrail" in context or "awslogs" in context


def _local_documents(
    predicate: Callable[[Path, Path], bool],
) -> tuple[LocalEvidenceDocument, ...]:
    ctx = get_ctx()
    metadata = ctx.db.get_case_metadata()
    try:
        target = Path(metadata.evidence_root).resolve(strict=True)
        root = target if target.is_dir() else target.parent
        paths = sorted(target.rglob("*")) if target.is_dir() else [target]
        candidates = [
            path
            for path in paths
            if path.is_file() and not path.is_symlink() and predicate(path, root)
        ]
    except OSError as exc:
        return (
            LocalEvidenceDocument(
                source_id="evidence_root_unavailable",
                source_name="evidence-root-unavailable",
                media_type="application/json",
                content=f"unsupported local evidence root: {exc}".encode(),
            ),
        )
    documents: list[LocalEvidenceDocument] = []
    for path in candidates[:MAX_DOCUMENTS]:
        source_name = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
            if size > MAX_DOCUMENT_BYTES:
                content = (
                    f"unsupported local document: compressed/input size {size} exceeds "
                    f"{MAX_DOCUMENT_BYTES}"
                ).encode()
            else:
                content = path.read_bytes()
        except OSError as exc:
            content = f"unsupported local document read: {exc}".encode()
        if path.name.casefold().endswith(".json.gz"):
            media_type: DocumentMediaType = "application/json"
            compression: DocumentCompression = "gzip"
        elif path.suffix.casefold() == ".json":
            media_type = "application/json"
            compression = "none"
        elif path.suffix.casefold() in {".yaml", ".yml"}:
            media_type = "application/yaml"
            compression = "none"
        else:
            media_type = "application/x-ndjson"
            compression = "none"
        documents.append(
            LocalEvidenceDocument(
                source_id=_source_id(source_name),
                source_name=source_name,
                media_type=media_type,
                content=content,
                compression=compression,
            )
        )
    if len(candidates) > MAX_DOCUMENTS:
        documents.append(
            LocalEvidenceDocument(
                source_id="collection_limit",
                source_name="collection-limit",
                media_type="application/json",
                content=(
                    f"unsupported: {len(candidates) - MAX_DOCUMENTS} local documents "
                    "exceeded the deterministic collection limit"
                ).encode(),
            )
        )
    return tuple(documents)


def _run_local_analysis(
    tool_name: str,
    analyzer: Callable[[Sequence[LocalEvidenceDocument]], PilotAnalysisResult],
    documents: Sequence[LocalEvidenceDocument],
) -> dict[str, object]:
    ctx = get_ctx()
    tool_call_id = make_tool_call_id()
    started = time.monotonic()
    result = analyzer(documents)
    payload = result.model_dump(mode="json")
    ctx.audit.log_tool_call(
        tool_call_id=tool_call_id,
        tool_name=tool_name,
        params={},
        output_hash=hash_output(payload),
        duration_ms=(time.monotonic() - started) * 1000,
    )
    return {"tool_call_id": tool_call_id, "status": "success", **payload}


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR)
def analyze_evtx_pack() -> dict[str, object]:
    """Analyze supported indexed EVTX records using local versioned rules."""
    return _run_local_analysis(
        "analyze_evtx_pack", analyze_evtx_documents, _indexed_evtx_documents()
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR)
def analyze_kubernetes_pack() -> dict[str, object]:
    """Analyze Kubernetes artifacts under the active local evidence root."""
    return _run_local_analysis(
        "analyze_kubernetes_pack",
        analyze_kubernetes_documents,
        _local_documents(_is_kubernetes_candidate),
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR)
def analyze_cloudtrail_pack() -> dict[str, object]:
    """Analyze documented CloudTrail JSON exports under the evidence root."""
    return _run_local_analysis(
        "analyze_cloudtrail_pack",
        analyze_cloudtrail_documents,
        _local_documents(_is_cloudtrail_candidate),
    )
