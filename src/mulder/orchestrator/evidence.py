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
from pathlib import Path
from typing import Any

from mulder.orchestrator.types import PhaseResult, extract_catalog_result
from mulder.patterns import DEFAULT_DB_DIR, DISK_IMAGE_EXTS, extract_iocs_from_text

logger = logging.getLogger(__name__)

_MAX_SIMPLE_SYSTEMS_PER_SESSION: int = 4

_MEMORY_EXTENSIONS: frozenset[str] = frozenset(
    (".raw", ".vmem", ".mem", ".img", ".dmp", ".lime", ".001")
)

_ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(
    (".7z", ".zip", ".gz", ".tar", ".xz", ".bz2", ".rar", ".zst")
)


class EvidenceContext:
    """Discovers evidence files and builds context for extraction phases.

    Scans evidence directories for disk images, memory dumps, and nested
    archives. Identifies systems from structured catalog JSON output and
    groups them into extraction sessions based on evidence complexity.
    """

    def __init__(self, evidence_path: str) -> None:
        """Initialize the evidence context.

        Args:
            evidence_path: Filesystem path to the evidence directory.
        """
        self.evidence_path = evidence_path

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
        extracted_dir = Path.home() / ".mulder" / "cases" / "extracted"

        sys_lower = system_name.lower()

        disk_images: list[str] = []
        if evidence_path.is_dir():
            for f in evidence_path.rglob("*"):
                if not f.is_file() or f.suffix.lower() not in DISK_IMAGE_EXTS:
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
                try:
                    rel = str(f.relative_to(evidence_path)).lower()
                except ValueError:
                    rel = str(f).lower()
                if sys_lower not in rel:
                    continue
                ext = f.suffix.lower()
                if ext in _MEMORY_EXTENSIONS:
                    memory_dumps.append(str(f))
                elif ext in _ARCHIVE_EXTENSIONS:
                    nested_archives.append(str(f))

        if extracted_dir.is_dir():
            for subdir in extracted_dir.iterdir():
                if subdir.is_dir() and sys_lower in subdir.name.lower():
                    for f in subdir.rglob("*"):
                        if not f.is_file():
                            continue
                        ext = f.suffix.lower()
                        if ext in _ARCHIVE_EXTENSIONS:
                            nested_archives.append(str(f))
                        elif (
                            ext in _MEMORY_EXTENSIONS or f.stat().st_size > 100 * 1024 * 1024
                        ) and str(f) not in memory_dumps:
                            memory_dumps.append(str(f))

        lines: list[str] = [f"System: {system_name}"]
        if disk_images:
            lines.append("Disk images:")
            for p in sorted(disk_images):
                lines.append(f"  {p}")
        if memory_dumps:
            lines.append("Extracted memory dumps (ready for Volatility):")
            for p in sorted(memory_dumps):
                lines.append(f"  {p}")
        if nested_archives:
            lines.append(
                "NESTED ARCHIVES (must be extracted before analysis; "
                "likely contain raw memory dumps):"
            )
            for p in sorted(nested_archives):
                lines.append(f"  {p}")
        if not disk_images and not memory_dumps and not nested_archives:
            lines.append(
                "(No pre-populated paths available. "
                f"Call list_directory on {self.evidence_path} to discover files.)"
            )

        return "\n".join(lines)

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

    def __init__(self, case_id: str) -> None:
        """Initialize the server bridge.

        Args:
            case_id: Case identifier for loading the correct database.
        """
        self._case_id = case_id

    def ensure_context(self) -> None:
        """Initialize a fresh server context for direct tool invocations.

        Always rebuilds the context to ensure the DB and audit log reflect
        the latest state (tools may have indexed data since last call).
        """
        import mulder.server.app as server_app

        if server_app._cfg is None:
            from mulder.server.app import ServerConfig

            db_dir = Path(DEFAULT_DB_DIR).expanduser()
            server_app._cfg = ServerConfig(db_dir=db_dir)

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
