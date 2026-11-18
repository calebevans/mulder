"""Triage collections: index what a KAPE, Velociraptor or UAC collection says about itself.

The files a collection holds are read by the ordinary artifact tools, which
take the collection's directory where they take a disk image (see
``mulder.dirroot``).  This tool indexes the rest: which files were collected,
and the collector's own records about them.
"""

from __future__ import annotations

import csv
import io
import os
import re
import time
from pathlib import Path
from urllib.parse import unquote

from mulder.dirroot import (
    KAPE_LOG_RE,
    LAYOUTS,
    Collection,
    detect_collection,
    dir_root,
    listed_name,
    read_regular,
    real_dir,
    walk_files,
)
from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import _index_dir_listing

__all__ = ["index_triage_collection"]

_MAX_SOURCE_BYTES = 8 * 1024 * 1024
"""Most text read into one indexed source."""

_MAX_OUTPUT_BYTES = 256 * 1024
"""Most read from one UAC command output file."""

_MAX_RESULT_FILES = 200
"""Velociraptor result files indexed per collection."""

_MAX_LISTED = 40
"""Names of any one kind returned in the response, and UAC categories indexed."""

_READING_NOTE = (
    "A triage collection holds copies of selected files, not a disk: there is no "
    "unallocated space, there are no deleted files and nothing can be carved. An artifact "
    "that was not collected is not thereby absent from the system. The timestamps on the "
    "copies are those of the copy: original timestamps are in $MFT when it was collected, "
    "in triage.kape.copylog, or in the upload metadata under triage.velociraptor.*."
)

# (what it is, a pattern on the lower-cased original path)
_WINDOWS_ARTIFACTS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern))
    for name, pattern in (
        ("registry hives", r"(^|/)windows/system32/config/(system|software|sam|security)$"),
        ("user registry hives", r"/ntuser\.dat$"),
        ("event logs", r"\.evtx$"),
        ("Prefetch", r"(^|/)windows/prefetch/[^/]+\.pf$"),
        ("Amcache", r"/amcache\.hve$"),
        ("$MFT", r"(^|/)\$mft$"),
        ("USN journal", r"\$usnjrnl:\$j$"),
        ("SRUM", r"/srudb\.dat$"),
        ("scheduled tasks", r"(^|/)windows/system32/tasks/"),
        ("LNK files and jump lists", r"\.(lnk|automaticdestinations-ms)$"),
        ("browser history", r"/(history|places\.sqlite|webcachev\d+\.dat)$"),
    )
)

_NOT_SLUG = re.compile(r"[^a-z0-9._-]+")


def _slug(name: str) -> str:
    """A source-name segment: lower case, with ``/`` as ``.``."""
    return _NOT_SLUG.sub("_", name.lower().replace("/", ".")).strip("._") or "unnamed"


def _text(path: str | Path, limit: int) -> tuple[str, bool] | None:
    """A file's text up to *limit* bytes, cut at a line end, and whether it was cut."""
    got = read_regular(path, limit)
    if got is None:
        return None
    data, complete = got
    if not complete:
        data = data[: data.rfind(b"\n") + 1]
    return data.decode("utf-8-sig", errors="replace"), not complete


def _field(value: object) -> str:
    return " ".join(str(value or "").split())


def _children(directory: Path, dirs: bool = False) -> list[tuple[str, str]]:
    """Sorted ``(name, path)`` of the regular files in *directory*, or of its directories.

    Symlinks are left out either way.
    """
    try:
        with os.scandir(directory) as it:
            return sorted(
                (e.name, e.path)
                for e in it
                if (e.is_dir if dirs else e.is_file)(follow_symlinks=False)
            )
    except OSError:
        return []


def _kape_sources(collection: Collection, evidence_path: str) -> tuple[list[str], list[str]]:
    """Index KAPE's copy and skip logs, each row reduced to what describes the source file."""
    rows: dict[str, list[str]] = {"copylog": [], "skiplog": []}
    problems: list[str] = []
    for name, path in _children(collection.root):
        match = KAPE_LOG_RE.match(name)
        kind = match.group(1).lower() if match else ""
        if kind not in rows:
            continue
        text = _text(path, _MAX_SOURCE_BYTES)
        if text is None:
            problems.append(f"{listed_name(name)}: not readable")
            continue
        if text[1]:
            problems.append(f"{listed_name(name)}: only the first {_MAX_SOURCE_BYTES} bytes read")
        try:
            for row in csv.DictReader(io.StringIO(text[0])):
                line = [_field(row.get("SourceFile")), f"sha1={_field(row.get('SourceFileSha1'))}"]
                if kind == "copylog":
                    line += [
                        f"size={_field(row.get('FileSize'))}",
                        f"created={_field(row.get('CreatedOnUtc'))}",
                        f"modified={_field(row.get('ModifiedOnUtc'))}",
                        f"accessed={_field(row.get('LastAccessedOnUtc'))}",
                    ]
                else:
                    line.append(f"reason={_field(row.get('Reason'))}")
                rows[kind].append("\t".join(line))
        except csv.Error as exc:
            problems.append(f"{listed_name(name)}: damaged CSV ({exc})")

    headers = {
        "copylog": "KAPE copy log: each collected file as it was on the source system "
        "(original path, SHA-1, size, and created/modified/accessed times in UTC)",
        "skiplog": "KAPE skip log: files found on the source system and not copied "
        "(Deduped: identical to a file that was copied; Excluded: left out by hash)",
    }
    sources: list[str] = []
    for kind, lines in rows.items():
        if lines:
            source = f"triage.kape.{kind}"
            extract_and_index("\n".join([headers[kind], *lines]), source, evidence_path, "triage")
            sources.append(source)
    return sources, problems


def _velociraptor_sources(
    collection: Collection, evidence_path: str
) -> tuple[list[str], list[str]]:
    """Index each ``results/<Artifact>.json`` (one JSON row per line) as a source."""
    results = real_dir(collection.root, "results")
    if results is None:
        return [], []
    files = [(n, p) for n, p in _children(results) if n.lower().endswith(".json")]
    sources: list[str] = []
    problems: list[str] = []
    if len(files) > _MAX_RESULT_FILES:
        problems.append(
            f"{len(files) - _MAX_RESULT_FILES} result files beyond the first "
            f"{_MAX_RESULT_FILES} were not indexed"
        )
    for name, path in files[:_MAX_RESULT_FILES]:
        source = f"triage.velociraptor.{_slug(unquote(name[: -len('.json')]))}"
        text = _text(path, _MAX_SOURCE_BYTES)
        if text is None or source in sources:
            problems.append(f"{listed_name(name)}: not indexed")
            continue
        body = text[0]
        if text[1]:
            body += f"\n[cut: only the first {_MAX_SOURCE_BYTES} bytes were indexed]"
            problems.append(f"{source}: only the first {_MAX_SOURCE_BYTES} bytes indexed")
        if body.strip():
            extract_and_index(body, source, evidence_path, "triage")
            sources.append(source)
    return sources, problems


def _uac_sources(collection: Collection, evidence_path: str) -> tuple[list[str], list[str]]:
    """Index UAC's ``live_response/<category>`` command output, one source per category."""
    live = real_dir(collection.root, "live_response")
    if live is None:
        return [], []
    sources: list[str] = []
    problems: list[str] = []
    budget = [20_000]
    categories = _children(live, dirs=True)
    if len(categories) > _MAX_LISTED:
        problems.append(f"live_response: only the first {_MAX_LISTED} categories were indexed")
    for category, directory in categories[:_MAX_LISTED]:
        blocks: list[str] = []
        size = 0
        left_out = 0
        for rel, stored in sorted(walk_files(Path(directory), budget)):
            if not rel.endswith(".txt"):
                continue
            text = _text(stored, _MAX_OUTPUT_BYTES) if size < _MAX_SOURCE_BYTES else None
            if text is None:
                left_out += 1
                continue
            if text[0].strip():
                cut = f"\n[cut at {_MAX_OUTPUT_BYTES} bytes]" if text[1] else ""
                block = f"=== live_response/{listed_name(f'{category}/{rel}')} ===\n{text[0]}{cut}"
                blocks.append(block)
                size += len(block)
        source = f"triage.uac.{_slug(category)}"
        if left_out:
            problems.append(f"{source}: {left_out} output files unreadable or over the size limit")
        if blocks and source not in sources:
            extract_and_index("\n".join(blocks), source, evidence_path, "triage")
            sources.append(source)
    if budget[0] <= 0:
        problems.append("live_response: more files than the walk limit; the rest were not indexed")
    return sources, problems


def _capped(names: list[str]) -> list[str]:
    if len(names) <= _MAX_LISTED:
        return names
    return [*names[:_MAX_LISTED], f"... and {len(names) - _MAX_LISTED} more"]


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def index_triage_collection(evidence_path: str, force: bool = False) -> dict[str, object]:
    """Index a triage collection's file list and the collector's own records.

    Call once on each evidence item of type "triage_collection" (KAPE target
    output, a Velociraptor offline collection, UAC output, or a Windows volume
    directory), before the artifact parsers. The collected files themselves
    are read by the ordinary tools: pass the same directory as image_path.

    Returns the layout, the host name the collection states, which kinds of
    artifact were collected and which were not, and the sources written:
    tsk.filelist (the collected files), triage.summary, triage.kape.copylog
    and triage.kape.skiplog (original path, SHA-1 and timestamps per file),
    triage.velociraptor.<artifact> (query results, one JSON row per line),
    triage.uac.<category> (command output from the live system). A collection
    is not a disk: no deleted files, no unallocated space, and the timestamps
    on the copies are those of the copy.

    Args:
        evidence_path: The collection's directory, as the evidence context lists it.
        force: Re-index even if this collection was already indexed.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "index_triage_collection"
    params: dict[str, object] = {"evidence_path": evidence_path, "force": force}

    if not force:
        existing = sources_already_indexed(["triage."], evidence_path=evidence_path)
        if existing:
            skipped: dict[str, object] = {
                "status": "skipped",
                "reason": "Sources already indexed from prior extraction",
                "existing_sources": existing,
            }
            return tool_response(tc_id, name, params, skipped, None, 0.0)

    root = dir_root(evidence_path)
    collection = detect_collection(Path(evidence_path)) if root is not None else None
    if root is None or collection is None:
        return error_response(
            tc_id,
            name,
            params,
            f"Not a triage collection directory: {evidence_path}",
            error_type="file_not_found" if root is None else "not_a_collection",
            suggestion=(
                "Pass the directory the evidence context lists as a triage collection. "
                "Extract an archive with extract_archive first; a disk image goes to run_fls."
            ),
        )

    sources: list[str] = []
    if not sources_already_indexed(["tsk.filelist"], evidence_path=evidence_path):
        _index_dir_listing(evidence_path)
        sources.append("tsk.filelist")

    indexers = {"kape": _kape_sources, "velociraptor": _velociraptor_sources, "uac": _uac_sources}
    problems: list[str] = []
    if collection.layout in indexers:
        indexed, problems = indexers[collection.layout](collection, evidence_path)
        sources += indexed

    collected: list[str] = []
    not_collected: list[str] = []
    if collection.layout == "uac":
        collected = [listed_name(d) for d, _ in _children(collection.root, dirs=True)]
    elif collection.windows:
        paths = [original.lower() for original, _ in root.files]
        for artifact, pattern in _WINDOWS_ARTIFACTS:
            held = any(pattern.search(path) for path in paths)
            (collected if held else not_collected).append(artifact)

    summary: dict[str, object] = {
        "evidence_path": evidence_path,
        "layout": LAYOUTS[collection.layout],
        "host": collection.host or "not stated by the collection",
        "volumes": _capped(
            [f"{label or '/'} -> {listed_name(str(path))}" for label, path in collection.volumes]
        ),
        "files_collected": len(root.files),
        "listing_truncated": root.truncated,
        "collected": _capped(collected),
        "not_collected": not_collected,
        "sources": _capped([*sources, "triage.summary"]),
        "not_indexed": _capped(problems),
        "note": _READING_NOTE,
    }
    extract_and_index(
        "\n".join(
            f"{key}: {'; '.join(value) if isinstance(value, list) else value}"
            for key, value in summary.items()
        ),
        "triage.summary",
        evidence_path,
        "triage",
    )
    elapsed = (time.monotonic() - t0) * 1000
    # Returned in full rather than as a preview: it is bounded, and it is where
    # the caller learns what the collection holds and which sources to search.
    return tool_response(tc_id, name, params, summary, None, elapsed)
