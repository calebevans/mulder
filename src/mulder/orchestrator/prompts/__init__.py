"""Prompt templates for each investigation phase and role.

Each prompt is stored as a separate markdown file in this directory
and loaded at import time. Single-mode phases (catalog, report) have
one prompt. Split-mode phases have three: planner, executor, analyst.

A prompt is a core plus modules. Guidance for one kind of evidence sits
between two marker lines in its prompt file::

    <!-- module: netflow -->
    NETFLOW EVIDENCE:
    ...
    <!-- /module -->

and is a block of the module named there; a block that names several
(``disk memory``) belongs to each. Everything outside markers is the core.
``assemble`` builds a session's prompt from the core and the modules the
session needs, and ``modules_for`` decides which those are from ``MODULES``.
The markers are removed on load and never reach a model, so each ``*_PROMPT``
constant is its file's text with every module in place.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Collection, Iterable
from pathlib import Path

logger = logging.getLogger(__name__)

_DIR = Path(__file__).resolve().parent

MODULES: dict[str, tuple[str, ...]] = {
    # Evidence types, as the classifier and scan_evidence label them. One
    # that is not listed is unknown, and unknown means every module.
    "disk_image": ("disk",),
    "memory_dump": ("memory",),
    # Files copied from a live system, read with the disk artifact tools.
    "triage_collection": ("triage", "disk"),
    "evtx": ("disk",),
    "event_logs": ("disk",),
    "autoruns_csv": ("disk",),
    "network_capture": ("pcap",),
    "netflow_capture": ("netflow",),
    "cloud_audit_log": ("cloud",),
    "mailbox": ("cloud",),
    "repository": ("cloud",),
    "ci_run_logs": ("cloud",),
    "log_file": ("logs",),
    "log_directory": ("logs",),
    "esxi_bundle": ("logs",),
    # A phone image is also listed and carved with the disk tools.
    "phone_dump": ("mobile", "disk"),
    "ios_backup": ("mobile", "disk"),
    "phone_database": ("mobile",),
    # The catalog's label for an archive it unpacked: what was inside is
    # listed under its own type. One still packed makes the system's types
    # unknown (EvidenceContext.evidence_types).
    "compressed_archive": (),
    "sqlite_database": (),
    "browser_history": (),
    "yara_rules": (),
    # Source prefixes: a source name up to and including its first dot.
    "volatility.": ("memory",),
    "tsk.": ("disk",),
    "optical.": ("disk",),
    "ez.": ("disk",),
    "mft.": ("disk",),
    "registry.": ("disk",),
    "prefetch.": ("disk",),
    "amcache.": ("disk",),
    "shimcache.": ("disk",),
    "autoruns.": ("disk",),
    "evtx.": ("disk",),
    "evtx_recovered.": ("disk",),
    "hayabusa.": ("disk",),
    "chainsaw.": ("disk",),
    "zircolite.": ("disk",),
    "logon.": ("disk",),
    "rmm.": ("disk",),
    "vshadow.": ("disk",),
    "appfiles.": ("disk",),
    "plist.": ("disk",),
    "linux.": ("disk",),
    "regripper.": ("disk",),
    "plaso.": ("disk",),
    "bulk.": ("disk",),
    "forensic.": ("disk",),
    "pcap.": ("pcap",),
    "zeek.": ("pcap",),
    "suricata.": ("pcap",),
    "tcpflow.": ("pcap",),
    "tcpxtract.": ("pcap",),
    "netflow.": ("netflow",),
    "cloudlog.": ("cloud",),
    "secrets.": ("cloud",),
    "workflow.": ("cloud",),
    "pst.": ("cloud",),
    "logs.": ("logs",),
    "triage.": ("triage", "disk"),
    "phone.": ("mobile",),
    "mvt.": ("mobile",),
    # Sources that say nothing about the kind of evidence: output about one
    # file, a lookup, or something computed from other sources.
    "logtable.": (),
    "composite.": (),
    "enrichment.": (),
    "yara.": (),
    "binary.": (),
    "capa.": (),
    "floss.": (),
    "die.": (),
    "radare2.": (),
    "strings.": (),
    "exiftool.": (),
    "hashdeep.": (),
    "ssdeep.": (),
    "clamav.": (),
    "chkrootkit.": (),
    "binwalk.": (),
    "foremost.": (),
    "scalpel.": (),
    "photorec.": (),
    "steg.": (),
    "office.": (),
    "pdf.": (),
    "browser.": (),
    "hindsight.": (),
    "pasco.": (),
    "dislocker.": (),
    "bde.": (),
    "fvde.": (),
    "sqlite.": (),
}
"""Evidence type or source prefix -> the prompt modules a session then needs.

The one table every role's prompt is assembled from. An empty value means
"known, and needs no module". A key that is missing means the kind of
evidence cannot be determined, and the session gets every module.
"""

_MODULE_NAMES: frozenset[str] = frozenset(name for names in MODULES.values() for name in names)

_MARKER = re.compile(r"^<!-- (?:module: ([a-z ]+)|/module) -->\n", re.MULTILINE)

# full prompt -> its text in order: (modules of the block, None for the core; text)
_BLOCKS: dict[str, list[tuple[frozenset[str] | None, str]]] = {}


def _load(name: str) -> str:
    """Read a prompt file from this package directory.

    Args:
        name: Filename (e.g., ``catalog.md``) relative to this directory.

    Returns:
        The file contents without its module markers, with leading/trailing
        whitespace stripped.

    Raises:
        ValueError: The markers are not balanced, or name an unknown module.
    """
    # Split on the markers: core, names, block, None, core, names, block, ...
    parts = _MARKER.split((_DIR / name).read_text(encoding="utf-8"))
    blocks: list[tuple[frozenset[str] | None, str]] = [(None, parts[0])]
    for i in range(1, len(parts), 2):
        opens = i % 4 == 1
        if (parts[i] is not None) != opens:
            raise ValueError(f"{name}: module markers are not balanced")
        names = frozenset(parts[i].split()) if opens else None
        if names is not None and not names <= _MODULE_NAMES:
            raise ValueError(f"{name}: unknown module in {sorted(names)}")
        blocks.append((names, parts[i + 1]))
    if len(parts) % 4 != 1:
        raise ValueError(f"{name}: a module block is not closed")
    prompt = "".join(text for _, text in blocks).strip()
    _BLOCKS[prompt] = blocks
    return prompt


def type_key(evidence_type: object) -> str:
    """An evidence type as ``MODULES`` spells it ("Disk image" is ``disk_image``)."""
    return "_".join(str(evidence_type).lower().replace("-", " ").split())


def modules_for(
    types: Iterable[object] | None, sources: Iterable[str] | None
) -> frozenset[str] | None:
    """Choose the prompt modules for what a system, or a case, holds.

    Args:
        types: Its evidence types, from the catalog. Spelling is normalised
            ("Disk image" is ``disk_image``).
        sources: The names of the sources indexed for it so far.

    Returns:
        The module names, or None for every module: when either argument is
        None or no type is given, when a type or a source prefix is not in
        ``MODULES``, and when nothing it holds selects a module. Leaving out
        guidance for evidence that is present is the failure to avoid, so
        anything unknown selects everything.
    """
    if not types or sources is None:
        return None
    keys = [type_key(t) for t in types]
    keys += [source.split(".", 1)[0] + "." for source in sources]
    unknown = sorted({key for key in keys if key not in MODULES})
    if unknown:
        logger.info("Prompt modules: every module, %s not in the table", ", ".join(unknown)[:200])
        return None
    # A system of loose files only: the planner has to find out what they are.
    return frozenset(name for key in keys for name in MODULES[key]) or None


def assemble(prompt: str, modules: Collection[str] | None) -> str:
    """Return a role prompt with only the given modules' blocks.

    Args:
        prompt: One of the ``*_PROMPT`` constants.
        modules: Module names to keep, or None for all of them.

    Returns:
        The core and the blocks of *modules*, in the order of the file. The
        prompt unchanged when *modules* is None or it is not one of the
        constants (a prompt of the caller's own has no modules).
    """
    blocks = _BLOCKS.get(prompt)
    if blocks is None or modules is None:
        return prompt
    kept = frozenset(modules)
    return "".join(text for names, text in blocks if names is None or names & kept).strip()


# Single-mode phases
CATALOG_PROMPT: str = _load("catalog.md")
REPORT_PROMPT: str = _load("report.md")

# Extract phase (split: planner / executor / analyst)
EXTRACT_PLANNER_PROMPT: str = _load("extract_planner.md")
EXTRACT_EXECUTOR_PROMPT: str = _load("extract_executor.md")
EXTRACT_ANALYST_PROMPT: str = _load("extract_analyst.md")

# Cross-system phase (split: planner / executor / analyst)
CROSS_SYSTEM_PLANNER_PROMPT: str = _load("cross_system_planner.md")
CROSS_SYSTEM_EXECUTOR_PROMPT: str = _load("cross_system_executor.md")
CROSS_SYSTEM_ANALYST_PROMPT: str = _load("cross_system_analyst.md")

# Alternative narrative phase (split: planner / executor / analyst)
NARRATIVE_PLANNER_PROMPT: str = _load("narrative_planner.md")
NARRATIVE_EXECUTOR_PROMPT: str = _load("narrative_executor.md")
NARRATIVE_ANALYST_PROMPT: str = _load("narrative_analyst.md")
