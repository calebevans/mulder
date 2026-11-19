"""Evidence discovery, system identification, and direct server tool invocations.

Contains two collaborators extracted from the Orchestrator:

- ``EvidenceContext``: discovers evidence files, builds per-system context
  strings, identifies systems from catalog output, and groups them for
  extraction sessions.
- ``ServerBridge``: performs zero-LLM-cost direct tool invocations against
  the mulder server for summaries, readiness checks, and consistency reports.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from mulder import collect as collector
from mulder.dirroot import Collection, detect_collection
from mulder.extractors.classifier import (
    LOOSE_LOG_TYPES,
    MAX_AUDIT_LOG_BYTES,
    RAW_CONTAINER_EXTS,
    ClassifiedEvidence,
    EvidenceClassifier,
    _dir_has_named_nfcapd,
    audit_log_files,
    has_disk_signature,
    is_esxi_bundle,
    is_nfcapd,
    loose_log_targets,
)
from mulder.extractors.optical import probe_optical
from mulder.models import Finding
from mulder.orchestrator.types import PhaseResult, extract_catalog_result
from mulder.patterns import (
    DISK_IMAGE_EXTS,
    case_extract_dir,
    extract_iocs_from_text,
    resolve_db_dir,
)
from mulder.questions import (
    ID_LABELS,
    MAX_QUESTION_CHARS,
    MAX_QUESTIONS_PER_PLAN,
    MAX_SYSTEM_CHARS,
    clean,
)

logger = logging.getLogger(__name__)

# artifact type -> (heading, the instruction the planner is given for it)
_CI_CLOUD_TYPES: dict[str, tuple[str, str]] = {
    "cloud_audit_log": (
        "Cloud audit logs",
        'Plan one run_cloud_audit_logs(evidence_path=<path>) task, group "foundation", '
        "for each path above.",
    ),
    "repository": (
        "Repository checkouts",
        "Plan run_workflow_audit(evidence_path=<directory>) and "
        'run_secret_scan(evidence_path=<directory>), group "foundation", '
        "for each directory above.",
    ),
    "ci_run_logs": (
        "CI run logs",
        'Plan one run_secret_scan(evidence_path=<directory>) task, group "foundation", '
        "for each directory above.",
    ),
    "log_directory": (
        "Log directories",
        'Plan one run_loose_logs(evidence_path=<directory>) task, group "foundation", '
        "for each directory above.",
    ),
    "log_file": (
        "Loose log files",
        'Plan one run_loose_logs(evidence_path=<path>) task, group "foundation", '
        "for each path above.",
    ),
    "esxi_bundle": (
        "ESXi support bundles",
        'Plan one run_loose_logs(evidence_path=<directory>) task, group "foundation", '
        "for each bundle above: it reads the bundle's logs.",
    ),
    "mailbox": (
        "Mailbox files (Outlook .pst/.ost)",
        'Plan one parse_pst(case_id=<case id>, file_path=<file>) task, group "foundation", '
        "for each file above.",
    ),
}

# How many files of a directory too large for one run_cloud_audit_logs call are planned
# one by one: each is a task the planner has to write out.
_MAX_AUDIT_LOG_FILES_PLANNED = 50

_MAX_SIMPLE_SYSTEMS_PER_SESSION: int = 4

#: Paths of one evidence type that the planner is shown: a tree can hold hundreds.
_MAX_LISTED: int = 25

_MEMORY_EXTENSIONS: frozenset[str] = frozenset(
    (".raw", ".vmem", ".mem", ".img", ".dmp", ".lime", ".001")
)

_ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(
    (".7z", ".zip", ".gz", ".tar", ".xz", ".bz2", ".rar", ".zst")
)


def _unprintable(path: object) -> bool:
    """Whether *path* holds a control character, which would start a prompt line of its own."""
    return any(ch < " " or ch == "\x7f" for ch in str(path))


def _audit_log_paths(target: Path, files: list[Path]) -> tuple[list[str], list[str]]:
    """The planner lines for one cloud audit log target, a file or a directory holding
    *files*: (the paths to plan, what cannot be read).

    One run_cloud_audit_logs call refuses more than MAX_AUDIT_LOG_BYTES, and the executor
    runs the plan as written, so a directory over the limit is planned file by file here.
    A file over the limit by itself, and the files of such a directory beyond the number a
    plan can name, are listed apart: the planner then says they were not examined instead
    of planning a call that reads nothing.
    """

    def size(path: Path) -> int:
        try:
            return path.stat().st_size
        except OSError:
            return 0

    if not target.is_dir():
        files = [target]
    elif sum(size(f) for f in audit_log_files(target)) <= MAX_AUDIT_LOG_BYTES:
        return [f"  {target}  ({len(files)} files)"], []
    fits = sorted(  # the largest first: as much of the evidence as the plan can hold
        (f for f in files if size(f) <= MAX_AUDIT_LOG_BYTES), key=lambda f: (-size(f), f)
    )
    rest = fits[_MAX_AUDIT_LOG_FILES_PLANNED:]
    unread = [f"  {f}  ({size(f) // 2**20} MiB)" for f in sorted(set(files) - set(fits))]
    if rest:
        total = sum(size(f) for f in rest) // 2**20
        unread.append(f"  {len(rest)} more files in {target}  ({total} MiB)")
    return [f"  {f}" for f in sorted(fits[:_MAX_AUDIT_LOG_FILES_PLANNED])], unread


def _is_raw_disk(path: Path) -> bool:
    """A ``.raw``/``.001`` file whose first bytes show a disk, not a memory dump."""
    return path.suffix.lower() in RAW_CONTAINER_EXTS and has_disk_signature(path)


def _is_log(path: Path, root: Path) -> bool:
    """Whether ``run_loose_logs`` reads *path* as it is: a ``.log`` or ``.txt`` file, or
    a file in a log directory or an ESXi bundle under *root*, a rotated ``.gz``
    included. Such a file is not an archive to unpack first and, however large, not a
    memory dump. What the tool cannot read is still what its name says, there as
    anywhere: a tarball, an archive of another kind (a log rotated with xz or zstd
    too), a memory or a disk image."""
    ext = path.suffix.lower()
    if ext in (".log", ".txt"):
        return True
    if (
        ext in _MEMORY_EXTENSIONS
        or ext in _ARCHIVE_EXTENSIONS - {".gz"}
        or path.name.lower().endswith((".tar.gz", ".tgz"))
    ):
        return False
    for parent in path.parents:
        if parent == root or not parent.is_relative_to(root):
            break
        if EvidenceClassifier._is_log_directory(parent) or is_esxi_bundle(parent):
            return True
    return False


class EvidenceContext:
    """Discovers evidence files and builds context for extraction phases.

    Scans evidence directories for disk images, memory dumps, and nested
    archives. Identifies systems from structured catalog JSON output and
    groups them into extraction sessions based on evidence complexity.
    """

    def __init__(self, evidence_path: str, extracted_dir: str | Path | None = None) -> None:
        """Initialize the evidence context.

        Args:
            evidence_path: Filesystem path to the evidence directory.
            extracted_dir: Where this investigation's extractions are,
                normally ``case_extract_dir(db_dir, case_id)``.  Defaults to
                the shared ``extracted/`` root of the resolved cases dir.
        """
        self.evidence_path = evidence_path
        self._catalog_systems: dict[str, dict[str, Any]] = {}
        self.extracted_dir = (
            Path(extracted_dir)
            if extracted_dir is not None
            else case_extract_dir(resolve_db_dir(), None)
        )

    def load_case_briefing(self) -> str:
        """Load optional MULDER.md case briefing from the evidence directory.

        If a MULDER.md file exists in the evidence root, its contents are
        returned wrapped with an INVESTIGATOR BRIEFING header. This context
        is injected into planner, analyst, and report prompts to guide the
        investigation toward user-specified questions and known facts.

        Returns:
            Formatted briefing string, or empty string if no file exists.
        """
        briefing_path = Path(self.evidence_path) / "MULDER.md"
        if briefing_path.is_file():
            content = briefing_path.read_text(encoding="utf-8", errors="replace").strip()
            if content:
                return f"INVESTIGATOR BRIEFING:\n{content}\n"
        return ""

    def build_evidence_context(self, system_name: str) -> str:
        """Build a pre-populated evidence context string for a system.

        Scans the evidence directory and the extracted directory to locate
        disk images and memory dumps belonging to this system. The result
        is injected into the planner prompt so it can plan without calling
        list_directory.

        Recursively scans the extracted directory to handle nested archive
        structures (e.g., zip containing a 7z). Classifies files as raw
        memory dumps or nested archives that need further extraction.

        Args:
            system_name: Identifier for the target system (e.g. "base-dc").

        Returns:
            Multi-line context string listing discovered file paths, or a
            fallback instruction when no files are found.
        """
        evidence_path = Path(self.evidence_path)
        extracted_dir = self.extracted_dir

        sys_lower = system_name.lower()

        # One walk of each directory, shared by the passes that classify.
        classified = {
            base: EvidenceClassifier().classify(base)
            for base in (evidence_path, extracted_dir)
            if base.is_dir()
        }
        # A file below a triage collection's top level is one of the collected
        # files, not a loose image, dump or archive: the collection is listed
        # as a whole further down.
        collections = self._collections(classified)
        claimed = self._claimed(sys_lower, collections)
        inside = tuple(f"{c.root}{os.sep}" for c in collections)

        def collected(f: Path) -> bool:
            path = str(f)
            return any(path.startswith(p) and os.sep in path[len(p) :] for p in inside)

        disk_images: list[str] = []
        if evidence_path.is_dir():
            for f in evidence_path.rglob("*"):
                if not f.is_file() or f.suffix.lower() not in DISK_IMAGE_EXTS:
                    continue
                if collected(f):
                    continue
                try:
                    rel = str(f.relative_to(evidence_path)).lower()
                except ValueError:
                    rel = str(f).lower()
                if sys_lower in rel:
                    disk_images.append(str(f))

        memory_dumps: list[str] = []
        nested_archives: list[str] = []

        if evidence_path.is_dir():
            for f in evidence_path.rglob("*"):
                if not f.is_file():
                    continue
                if collected(f):
                    continue
                try:
                    rel = str(f.relative_to(evidence_path)).lower()
                except ValueError:
                    rel = str(f).lower()
                if sys_lower not in rel:
                    continue
                ext = f.suffix.lower()
                if ext in _MEMORY_EXTENSIONS:
                    if not _is_raw_disk(f):
                        memory_dumps.append(str(f))
                elif ext in _ARCHIVE_EXTENSIONS and not _is_log(f, evidence_path):
                    nested_archives.append(str(f))

        if extracted_dir.is_dir():
            for subdir in extracted_dir.iterdir():
                if subdir.is_dir() and sys_lower in subdir.name.lower():
                    for f in subdir.rglob("*"):
                        if not f.is_file() or _is_log(f, extracted_dir):
                            continue
                        if collected(f):
                            continue
                        ext = f.suffix.lower()
                        if ext in _ARCHIVE_EXTENSIONS:
                            nested_archives.append(str(f))
                        elif _is_raw_disk(f) or ext in (".vhd", ".vhdx"):
                            # A disk unpacked from an archive, not a memory dump
                            # (KAPE zips the VHD or VHDX it writes).
                            disk_images.append(str(f))
                        elif (
                            ext in _MEMORY_EXTENSIONS or f.stat().st_size > 100 * 1024 * 1024
                        ) and str(f) not in memory_dumps:
                            memory_dumps.append(str(f))

        # Memory and crash dumps a collector copied (KAPE takes MEMORY.DMP and
        # *.dmp) belong to the system the collection belongs to.
        memory_dumps += [
            dump
            for c in claimed
            for dump in collections[c]
            if dump not in memory_dumps and not _unprintable(dump)
        ]

        # parent dir -> (file count, first name, last name, matches system name)
        netflow_dirs: dict[str, tuple[int, str, str, bool]] = {}
        # the sibling-name cache is per walk: a directory that gained a rotation-named file
        # since an earlier scan in this process must be re-sniffed
        _dir_has_named_nfcapd.cache_clear()
        if evidence_path.is_dir():
            for f in evidence_path.rglob("*"):
                if not f.is_file() or not is_nfcapd(f):
                    continue
                if f.parent.is_relative_to(evidence_path):
                    rel_dir = str(f.parent.relative_to(evidence_path)).lower()
                else:
                    rel_dir = str(f.parent).lower()
                key = str(f.parent)
                cnt, first, last, _ = netflow_dirs.get(key, (0, f.name, f.name, False))
                netflow_dirs[key] = (
                    cnt + 1,
                    min(first, f.name),
                    max(last, f.name),
                    sys_lower in rel_dir,
                )
        # NetFlow delivered inside an archive lands under the extracted slot named after the
        # archive (case.py extracts to extracted/<stem>-<digest>/): scan the slots whose name
        # contains the system name, as the memory-dump pass above does
        if extracted_dir.is_dir():
            for subdir in extracted_dir.iterdir():
                if not (subdir.is_dir() and sys_lower in subdir.name.lower()):
                    continue
                for f in subdir.rglob("*"):
                    if not f.is_file() or not is_nfcapd(f):
                        continue
                    key = str(f.parent)
                    cnt, first, last, _ = netflow_dirs.get(key, (0, f.name, f.name, True))
                    netflow_dirs[key] = (cnt + 1, min(first, f.name), max(last, f.name), True)
        catalog_ev = self._catalog_systems.get(sys_lower, {}).get("evidence", [])
        catalog_says_netflow = isinstance(catalog_ev, list) and any(
            "netflow" in str(e).lower() for e in catalog_ev
        )
        mine = {d: v for d, v in netflow_dirs.items() if v[3]}
        # rescue path (the catalog named the system descriptively): show only the directories
        # no OTHER catalog system claims by name, so two exporters are not both planned under
        # each system
        others = [n for n in self._catalog_systems if n and n != sys_lower]

        def _claimed_by_other(d: str) -> bool:
            path = Path(d)
            if path.is_relative_to(evidence_path):
                rel = str(path.relative_to(evidence_path)).lower()
            else:
                rel = d.lower()
            return any(n in rel for n in others)

        unclaimed = {d: v for d, v in netflow_dirs.items() if not _claimed_by_other(d)}
        shown = mine if mine else (unclaimed if catalog_says_netflow else {})

        ci_cloud = self._ci_cloud_lines(sys_lower, classified)
        triage = self._triage_lines(claimed)

        lines: list[str] = [f"System: {system_name}"]
        if disk_images:
            lines.append("Disk images:")
            for p in sorted(disk_images):
                media = probe_optical(p)
                if media is not None:
                    lines.append(
                        f"  {p}  (optical media, {media.upper()}: plan run_optical_listing, "
                        "not run_fls/run_mmls)"
                    )
                else:
                    lines.append(f"  {p}")
        if memory_dumps:
            lines.append("Extracted memory dumps (ready for Volatility):")
            for p in sorted(memory_dumps):
                lines.append(f"  {p}")
        if nested_archives:
            lines.append("NESTED ARCHIVES (must be extracted before analysis):")
            for p in sorted(nested_archives):
                lines.append(f"  {p}")
        if shown:
            lines.append(
                "NetFlow (nfdump nfcapd files; pass the DIRECTORY as evidence_path, "
                "spelled exactly as below):"
            )
            for d, (cnt, first, last, _) in sorted(shown.items()):
                lines.append(f"  {d}  ({cnt} files, {first} .. {last})")
            if not mine and shown:
                lines.append(
                    "  (directory name does not contain the system name; listed because "
                    "the catalog assigns netflow_capture to this system)"
                )
                if len(shown) > 1:
                    lines.append(
                        "  (several exporter directories; plan only the one that belongs to "
                        "this system per the catalog description and ignore the others)"
                    )
            lines.append(
                "  Plan one run_netflow_analysis(evidence_path=<directory>) task, group "
                '"foundation", for each directory above that belongs to this system, and no '
                "other run_netflow_* tool (the targeted tools are follow-ups for the analyst)."
            )

        lines.extend(ci_cloud)
        lines.extend(triage)
        # Not evidence paths, so they do not stand in for the fallback below.
        collection = self._collection_lines()

        if (
            not disk_images
            and not memory_dumps
            and not nested_archives
            and not shown
            and not ci_cloud
            and not triage
        ):
            lines.append(
                "(No pre-populated paths available. "
                f"Call list_directory on {self.evidence_path} to discover files.)"
            )

        lines.extend(collection)
        # A path is a name from the evidence: one with a line break in it (of any of
        # the kinds str.splitlines knows) must not start a line of its own in the prompt.
        return "\n".join(" ".join(line.splitlines()) for line in lines)

    @staticmethod
    def _collection_lines() -> list[str]:
        """Tell the planner which audit logs it may fetch, when it may at all."""
        configured = collector.targets()
        if not collector.agent_collection_enabled() or not configured:
            return []
        lines = ["Live collection is enabled for the audit logs of:"]
        lines += [f"  {provider}: {', '.join(scopes)}" for provider, scopes in configured.items()]
        lines.append(
            "  If this system or the briefing involves one of these and no export of its "
            "audit log is listed above, plan collect_cloud_audit_logs(provider=<provider>, "
            'start=<ISO time>, end=<ISO time>) covering the incident window, group "foundation". '
            "Otherwise do not plan it."
        )
        return lines

    def _ci_cloud_lines(
        self, sys_lower: str, classified: dict[Path, list[ClassifiedEvidence]]
    ) -> list[str]:
        """Planner lines for cloud audit logs, repository checkouts, CI run logs, loose
        logs (log directories, log files, ESXi support bundles) and mailbox files.

        These are evidence of a kind the planner cannot recognise from a file
        listing, so each is named with its type, its path and the tool to plan.
        Looked for in the evidence directory and in unpacked archives.

        An item belongs to this system when the system's name appears in its
        path. Failing that, when the catalog assigned that evidence type to the
        system, the items no other system's name claims are shown: a cloud
        "system" is an organization or account, whose name is rarely a path.
        """
        found: dict[str, dict[str, list[Path]]] = {t: {} for t in _CI_CLOUD_TYPES}
        log_files: dict[str, int] = {}  # run_loose_logs target -> the log files it covers
        for root, items in classified.items():
            # Loose logs are planned per run_loose_logs target, not per classified file.
            for log_path, (kind, count) in loose_log_targets(items, root).items():
                found[kind][str(log_path)] = []
                log_files[str(log_path)] = count
            for item in items:
                if item.artifact_type not in found or item.artifact_type in LOOSE_LOG_TYPES:
                    continue
                # Loose audit log files are planned once, by their directory.
                # One at the top of the evidence is planned by itself: its
                # "directory" is the whole evidence root, which the tool would
                # then search recursively, for every system that owns a file.
                is_file = item.artifact_type == "cloud_audit_log"
                grouped = is_file and item.path.parent.resolve() != root.resolve()
                target = str(item.path.parent if grouped else item.path)
                found[item.artifact_type].setdefault(target, []).append(item.path)

        catalog_ev = self._catalog_systems.get(sys_lower, {}).get("evidence", [])
        catalog_types = (
            {str(e).lower() for e in catalog_ev} if isinstance(catalog_ev, list) else set()
        )
        others = [n for n in self._catalog_systems if n and n != sys_lower]

        lines: list[str] = []
        for artifact_type, (label, plan) in _CI_CLOUD_TYPES.items():
            targets = found[artifact_type]
            mine = {p: n for p, n in targets.items() if sys_lower in p.lower()}
            if not mine and artifact_type in catalog_types:
                mine = {
                    p: n for p, n in targets.items() if not any(o in p.lower() for o in others)
                }
            if not mine:
                continue
            lines.append(f'{label} (type "{artifact_type}"):')
            planned: list[str] = []
            unread: list[str] = []
            for path, files in sorted(mine.items())[:_MAX_LISTED]:
                if artifact_type == "cloud_audit_log":
                    paths, left = _audit_log_paths(Path(path), files)
                    planned += paths
                    unread += left
                elif artifact_type == "log_file" and Path(path).is_dir():
                    planned.append(f"  {path}  ({log_files[path]} files)")
                else:
                    planned.append(f"  {path}")
            if len(mine) > _MAX_LISTED:
                planned.append(
                    f"  ({len(mine) - _MAX_LISTED} more are not listed here: "
                    "list_directory shows them)"
                )
            if planned:
                lines += [*planned, f"  {plan}"]
            if unread:
                lines.append(
                    "  NOT READ, do not plan these: one run_cloud_audit_logs call reads at "
                    f"most {MAX_AUDIT_LOG_BYTES // 2**20} MiB, and of a directory over that at "
                    f"most {_MAX_AUDIT_LOG_FILES_PLANNED} files are planned one by one. Name "
                    "each in investigation_questions as evidence that was not examined. A file "
                    "has to be split or exported again over shorter date ranges, and many files "
                    f"laid out in subdirectories of at most {MAX_AUDIT_LOG_BYTES // 2**20} MiB."
                )
                lines += unread
        return lines

    @staticmethod
    def _collections(
        classified: dict[Path, list[ClassifiedEvidence]],
    ) -> dict[Collection, list[str]]:
        """Triage collections in the evidence directory and in unpacked archives.

        Each keeps the spelling of the directory it was found under, as the
        other paths the planner is given do, and comes with the memory and
        crash dumps found inside it.
        """
        found: dict[Collection, list[str]] = {}
        for base, items in classified.items():
            resolved = base.resolve()
            for item in items:
                if item.artifact_type != "triage_collection":
                    continue
                collection = detect_collection(base / item.path.relative_to(resolved))
                if collection is not None:
                    found[collection] = [
                        str(base / dump.path.relative_to(resolved))
                        for dump in items
                        if dump.artifact_type == "memory_dump" and item.path in dump.path.parents
                    ]
        return found

    def _claimed(self, sys_lower: str, found: Iterable[Collection]) -> list[Collection]:
        """The collections among *found* that belong to this system.

        One whose stated host name is the system's name, compared on the first
        DNS label, or whose path below the evidence or extraction directory
        holds the name as a whole word: PC1 does not claim PC10's collection,
        and a name that occurs in the path to the evidence claims nothing.
        Failing that, as for cloud evidence, the ones no other system claims
        when the catalog assigned the type to this system.
        """
        bases = (Path(self.evidence_path), self.extracted_dir)

        def below(root: Path) -> str:
            base = next((b for b in bases if root.is_relative_to(b)), root.parent)
            return str(root.relative_to(base)).lower()

        def claims(name: str, collection: Collection) -> bool:
            host = collection.host.lower().split(".")[0]
            if host and host == name.split(".")[0]:
                return True
            whole = rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])"
            return bool(name) and re.search(whole, below(collection.root)) is not None

        found = list(found)
        mine = [c for c in found if claims(sys_lower, c)]
        catalog_ev = self._catalog_systems.get(sys_lower, {}).get("evidence", [])
        if not mine and isinstance(catalog_ev, list) and "triage_collection" in catalog_ev:
            others = [n for n in self._catalog_systems if n and n != sys_lower]
            mine = [c for c in found if not any(claims(o, c) for o in others)]
        return mine

    @staticmethod
    def _triage_lines(mine: list[Collection]) -> list[str]:
        """Planner lines for this system's triage collections: where each is and how to pass it."""
        if not mine:
            return []
        lines = [
            'Triage collections (type "triage_collection": files copied from a live system, '
            "not a disk image):"
        ]
        listed = [c for c in mine if not _unprintable(c.root)]
        # The tools do not take a symlink for a collection, so one is spelled out.
        lines += sorted(
            f"  {c.root.resolve() if c.root.is_symlink() else c.root}  ({c.description})"
            for c in listed
        )
        if len(listed) < len(mine):
            lines.append(
                f"  ({len(mine) - len(listed)} left out: the directory name holds control "
                "characters, so its path cannot be given to a tool.)"
            )
        if not listed:
            return lines
        mine = listed
        lines.append(
            "  Plan index_triage_collection(evidence_path=<directory>), group "
            '"foundation", for each directory above.'
        )
        if any(c.windows for c in mine):
            lines.append(
                "  Windows files: plan the Windows artifact tools with the same directory as "
                "image_path (run_registry_parser, run_prefetch_parser, run_amcache_parser, "
                "run_shimcache_parser, run_mft_parser, query_registry_value), as evtx_path of "
                "run_evtx_parser, as evtx_dir of run_hayabusa and as evidence_path of "
                "run_chainsaw."
            )
        if any(c.layout == "uac" for c in mine):
            lines.append(
                "  UAC: plan run_mactime(image_path=<directory>) for a timeline from the body "
                "file the collector wrote."
            )
        lines.append(
            "  Do not plan run_mmls, run_bulk_extractor, carving tools or detect_masquerading "
            "on a collection: it has no partition table, no unallocated space and no deleted "
            "files."
        )
        return lines

    def identify_systems(
        self,
        catalog_result: PhaseResult,
        cached_catalog_data: dict[str, Any] | None = None,
    ) -> tuple[list[str], dict[str, Any]]:
        """Extract system names from the catalog phase's structured JSON.

        Uses cached catalog data from gate validation when available,
        falling back to parsing the messages directly. Returns an empty
        list if the catalog did not produce valid structured output (the
        gate should have caught this, but this provides a defensive
        safety net).

        Args:
            catalog_result: The completed catalog phase result.
            cached_catalog_data: Pre-parsed catalog JSON from gate
                validation, avoiding redundant re-parsing.

        Returns:
            Tuple of (system name list, full catalog JSON dict). Returns
            ([], {}) if no valid catalog JSON was found.
        """
        catalog_data = cached_catalog_data
        if catalog_data is None:
            catalog_data = extract_catalog_result(catalog_result.messages)
        if catalog_data is None:
            logger.error(
                "Catalog did not produce valid JSON with a 'systems' array. "
                "Cannot identify systems for extraction."
            )
            return [], {}

        systems = [str(s["name"]) for s in catalog_data["systems"]]
        self._catalog_systems = {
            str(s.get("name", "")).lower(): s
            for s in catalog_data["systems"]
            if isinstance(s, dict)
        }
        logger.info(
            "Identified %d system(s) from catalog JSON: %s",
            len(systems),
            systems,
        )
        return systems, catalog_data

    @staticmethod
    def group_systems(
        systems: list[str],
        catalog_data: dict[str, Any],
    ) -> list[list[str]]:
        """Group systems into extraction sessions.

        Systems with disk image evidence get individual sessions. Systems
        with only memory dumps are batched together when there are many
        systems. Uses structured evidence type arrays from the catalog
        JSON rather than scanning free text.

        Args:
            systems: Full list of system identifiers.
            catalog_data: Structured catalog JSON with per-system evidence
                types in the ``systems`` array.

        Returns:
            List of system groups, each group processed in one session.
        """
        systems_by_name: dict[str, dict[str, Any]] = {
            str(s.get("name", "")).lower(): s
            for s in catalog_data.get("systems", [])
            if isinstance(s, dict)
        }

        rich_systems: list[str] = []
        simple_systems: list[str] = []

        for sys_name in systems:
            sys_info = systems_by_name.get(sys_name.lower(), {})
            evidence: object = sys_info.get("evidence", [])
            if not isinstance(evidence, list):
                evidence = []

            has_disk = "disk_image" in evidence
            has_memory = "memory_dump" in evidence

            if has_disk:
                rich_systems.append(sys_name)
            elif has_memory and len(systems) > 3:
                simple_systems.append(sys_name)
            else:
                rich_systems.append(sys_name)

        groups: list[list[str]] = []
        for sys_name in rich_systems:
            groups.append([sys_name])

        for i in range(0, len(simple_systems), _MAX_SIMPLE_SYSTEMS_PER_SESSION):
            groups.append(simple_systems[i : i + _MAX_SIMPLE_SYSTEMS_PER_SESSION])

        if not groups:
            fallback_name = systems[0] if systems else "unknown"
            return [[fallback_name]]
        return groups


class ServerBridge:
    """Zero-cost direct tool invocations bypassing the LLM layer.

    Encapsulates coupling to ``mulder.server.app`` internals, providing
    direct access to the investigation database for summaries, readiness
    checks, and consistency analysis without spending LLM tokens.
    """

    def __init__(self, case_id: str, db_dir: str | Path | None = None) -> None:
        """Initialize the server bridge.

        Args:
            case_id: Case identifier for loading the correct database.
            db_dir: Directory holding the case database. Falls back to
                ``$MULDER_DB_DIR`` and then the default when not given.
        """
        self._case_id = case_id
        self._db_dir = db_dir

    def ensure_context(self) -> None:
        """Initialize a fresh server context for direct tool invocations.

        Always rebuilds the context to ensure the DB and audit log reflect
        the latest state (tools may have indexed data since last call).
        """
        import mulder.server.app as server_app

        if server_app._cfg is None:
            from mulder.server.app import ServerConfig

            server_app._cfg = ServerConfig(db_dir=resolve_db_dir(self._db_dir))

        if self._case_id:
            server_app.load_case(self._case_id)

    def cleanup(self) -> None:
        """Close the local server context opened for direct tool calls."""
        try:
            import mulder.server.app as server_app

            if server_app._ctx is not None:
                server_app._close_current_ctx()
        except Exception:
            logger.debug("Error cleaning up orchestrator server context", exc_info=True)

    def get_summary(self) -> dict[str, Any] | None:
        """Retrieve the investigation summary via direct DB read.

        Uses ``_tool_dispatch_sync`` to call the original unwrapped sync
        function (not the async-wrapped version registered with MCP).

        Returns:
            Investigation summary dict, or None on failure.
        """
        try:
            self.ensure_context()
            from mulder.server.app import _tool_dispatch_sync

            fn = _tool_dispatch_sync["get_investigation_summary"]
            result: dict[str, Any] = dict(fn())
            return result
        except Exception:
            logger.warning("get_summary failed", exc_info=True)
            return None

    def get_readiness(self) -> dict[str, Any] | None:
        """Retrieve finalize readiness via direct DB read.

        Uses ``_tool_dispatch_sync`` to call the original unwrapped sync
        function (not the async-wrapped version registered with MCP).

        Returns:
            Readiness result dict, or None on failure.
        """
        try:
            self.ensure_context()
            from mulder.server.app import _tool_dispatch_sync

            fn = _tool_dispatch_sync["check_finalize_readiness"]
            result: dict[str, Any] = dict(fn())
            return result
        except Exception:
            logger.warning("get_readiness failed", exc_info=True)
            return None

    def record_questions(self, phase: str, system: str, questions: list[Any]) -> list[Any]:
        """Store a plan's investigation questions and label them with their ids.

        Writes straight to the case database: no LLM call. Each question
        that was stored comes back as ``"[q_1a2b3c4d] <question>"`` so the
        analyst can name it to ``resolve_question``. Anything that cannot be
        stored (not a string, or past the per-plan cap) is passed through as
        the planner wrote it, and so is everything when the write fails:
        the analyst then gets its questions exactly as it did before they
        were recorded.

        Args:
            phase: Phase the plan belongs to.
            system: System the plan is for, or "" when it covers the case.
            questions: ``investigation_questions`` from the planner's JSON.

        Returns:
            The questions to hand the analyst, in the planner's order.
        """
        if not isinstance(questions, list):
            return questions
        # A follow-up planner is shown the analyst's request, which quotes
        # questions with their labels: store the question, not the label, so
        # an echoed one is the question already on record.
        cleaned = [
            clean(ID_LABELS.sub("", q) if isinstance(q, str) else q, MAX_QUESTION_CHARS)
            for q in questions
        ]
        try:
            self.ensure_context()
            from mulder.server.app import get_ctx

            rows = get_ctx().db.record_questions(
                phase,
                clean(system, MAX_SYSTEM_CHARS),
                [c for c in cleaned if c][:MAX_QUESTIONS_PER_PLAN],
            )
        except Exception:
            logger.warning("Failed to record investigation questions", exc_info=True)
            return questions
        ids = {row.question: row.question_id for row in rows}
        return [
            f"[{ids[c]}] {c}" if c in ids else q for q, c in zip(questions, cleaned, strict=True)
        ]

    def build_consistency_report(self) -> str:
        """Build a consistency report identifying dedup clusters.

        Reads all findings directly from the case database, extracts IOCs
        using regex, groups findings by shared IOCs, and returns a
        formatted report. Bypasses the MCP tool layer entirely for zero
        LLM cost.

        Returns:
            Formatted string for the narrative planner prompt, or empty string.
        """
        try:
            self.ensure_context()
            from mulder.server.app import get_ctx

            findings = get_ctx().db.get_findings()
        except Exception:
            logger.warning("Failed to query findings for consistency report", exc_info=True)
            return ""

        if not findings:
            return ""

        ioc_to_findings: dict[str, list[str]] = {}

        for f in findings:
            text = f"{f.title} {f.description}"

            ioc_set = extract_iocs_from_text(text)
            iocs: set[str] = set()
            for ip in ioc_set.ips:
                iocs.add(f"ip:{ip}")
            for path in ioc_set.paths:
                iocs.add(f"path:{path[:60]}")
            for proc in ioc_set.processes:
                iocs.add(f"proc:{proc.lower()}")
            for h in ioc_set.hashes:
                iocs.add(f"hash:{h}")
            for domain in ioc_set.domains:
                iocs.add(f"domain:{domain.lower()}")

            for ioc in iocs:
                if ioc not in ioc_to_findings:
                    ioc_to_findings[ioc] = []
                ioc_to_findings[ioc].append(f.finding_id)

        clusters: list[str] = []
        seen_clusters: set[frozenset[str]] = set()
        for ioc, fids in sorted(ioc_to_findings.items()):
            if len(fids) < 2:
                continue
            cluster_key = frozenset(fids)
            if cluster_key in seen_clusters:
                continue
            seen_clusters.add(cluster_key)
            clusters.append(f"  - IOC '{ioc}' shared by: {', '.join(fids)}")

        if not clusters:
            return ""

        report_lines = [
            "CONSISTENCY ANALYSIS (auto-generated):",
            f"Found {len(clusters)} potential dedup clusters:",
        ]
        report_lines.extend(clusters[:30])
        report_lines.append(
            "\nReview these clusters for duplicate findings that should be "
            "consolidated and for contradictions that need resolution."
        )
        return "\n".join(report_lines)

    def get_progress_notes(self, system_name: str, since: datetime) -> list[str]:
        """Return the ``track_progress`` notes recorded for a system since a time.

        The notes are what a session that ran out of turns left for the one
        that continues its work. They are model-written text; the caller
        sanitises them before they reach a prompt.

        Args:
            system_name: The label the notes were recorded under. A
                comma-separated group also matches a note recorded under
                one of its members, which is how an analyst records one
                unprompted. Case and whitespace differences are ignored.
            since: Timezone-aware lower bound on when a note was recorded.

        Returns:
            Non-empty notes, oldest first; empty on any failure.
        """
        try:
            self.ensure_context()
            from mulder.server.app import get_ctx

            records = get_ctx().db.get_all_progress()
        except Exception:
            logger.warning("get_progress_notes failed", exc_info=True)
            return []

        wanted = {
            " ".join(name.split()).casefold() for name in (system_name, *system_name.split(","))
        } - {""}
        notes: list[str] = []
        for record in records:
            note = (record["notes"] or "").strip()
            if not note or " ".join(record["system_name"].split()).casefold() not in wanted:
                continue
            try:
                if datetime.fromisoformat(record["recorded_at"]) >= since:
                    notes.append(note)
            except (TypeError, ValueError):  # not a timestamp, or not timezone-aware
                continue
        return notes

    def get_findings_since(self, since: datetime) -> list[Finding]:
        """Return the findings saved to the case since a time.

        Findings carry no system or role, so this is every finding saved in
        the window, including any saved by a session running alongside.

        Args:
            since: Timezone-aware lower bound on when a finding was saved.

        Returns:
            Findings, oldest first; empty on any failure.
        """
        try:
            self.ensure_context()
            from mulder.server.app import get_ctx

            findings = get_ctx().db.get_findings()
        except Exception:
            logger.warning("get_findings_since failed", exc_info=True)
            return []

        saved: list[Finding] = []
        for finding in findings:
            try:
                if datetime.fromisoformat(finding.submitted_at) >= since:
                    saved.append(finding)
            except (TypeError, ValueError):  # not a timestamp, or not timezone-aware
                continue
        return saved

    def record_cut_short(self, phase: str, role: str, system: str, question: str) -> None:
        """Record a role session that was still unfinished after every continuation.

        The report and the investigation summary read these rows to say
        which analysis was cut short. A failure to record is logged, not
        raised: it must not end a run that is otherwise going on.

        Args:
            phase: Phase the session belonged to.
            role: Its role in a split phase; empty for a single-mode phase.
            system: The system it worked on; empty when the phase has none.
            question: The investigation question it was given, when it had
                one of its own. Sanitised by the caller, like *system*.
        """
        try:
            self.ensure_context()
            from mulder.server.app import get_ctx

            get_ctx().db.record_cut_short(phase, role, system, question)
        except Exception:
            logger.warning("record_cut_short failed", exc_info=True)

    def record_rejected_plan(self, system: str) -> None:
        """Record that a plan for *system* was rejected at the questions gate.

        A system with a rejected plan and no plan that reached an analyst is
        named as not analysed by the investigation summary and the report,
        which then never says that no incident was found
        (``CaseDB.get_unanalysed``). Counted under the
        name the system's questions are recorded under, so that an accepted
        plan takes it off that list. A failure to record is logged, not
        raised.

        Args:
            system: The system, or group of systems, the plan was for.
        """
        try:
            self.ensure_context()
            from mulder.server.app import get_ctx

            get_ctx().db.record_rejected_plan(clean(system, MAX_SYSTEM_CHARS))
        except Exception:
            logger.warning("record_rejected_plan failed", exc_info=True)
