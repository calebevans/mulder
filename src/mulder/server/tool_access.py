"""Declarative tool-role access registry for the Mulder MCP surface.

Tools self-declare which pipeline roles may invoke them via the
``@tool_access`` decorator. The ``get_tools_for_role`` function
builds allowlists at import time so ``phases.py`` never needs manual
tool list maintenance.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from enum import Enum, Flag, auto
from typing import TypeVar

F = TypeVar("F", bound=Callable[..., object])


class Role(Flag):
    """Pipeline roles that can invoke MCP tools."""

    CATALOG = auto()
    EXTRACT_PLANNER = auto()
    EXTRACT_EXECUTOR = auto()
    EXTRACT_ANALYST = auto()
    CROSS_PLANNER = auto()
    CROSS_EXECUTOR = auto()
    CROSS_ANALYST = auto()
    NARRATIVE_PLANNER = auto()
    NARRATIVE_EXECUTOR = auto()
    NARRATIVE_ANALYST = auto()
    REPORT = auto()


PLANNERS = Role.EXTRACT_PLANNER | Role.CROSS_PLANNER | Role.NARRATIVE_PLANNER
EXECUTORS = Role.EXTRACT_EXECUTOR | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR
ANALYSTS = Role.EXTRACT_ANALYST | Role.CROSS_ANALYST | Role.NARRATIVE_ANALYST
ALL_ROLES = Role.CATALOG | PLANNERS | EXECUTORS | ANALYSTS | Role.REPORT

_registry: dict[str, Role] = {}
_effect_registry: dict[str, frozenset[ToolEffect]] = {}


class ToolEffect(str, Enum):
    """Explicit security-relevant effect of a registered MCP tool."""

    CASE_READ = "case-read"
    FORENSIC_EXECUTION = "forensic-execution"
    CASE_WRITE = "case-mutation"
    CASE_MUTATION = "case-mutation"  # Backwards-compatible symbolic alias.
    JOB_CONTROL = "job-control"
    PUBLICATION = "publication"


_TOOLS_BY_EFFECT: dict[ToolEffect, frozenset[str]] = {
    ToolEffect.CASE_WRITE: frozenset(
        {
            "bookmark_window",
            "create_hypothesis",
            "deduplicate_findings",
            "delete_finding",
            "record_claim_verification",
            "record_contradiction",
            "record_coverage",
            "record_hypothesis_test",
            "record_review_verdict",
            "remove_bookmark",
            "resolve_contradiction",
            "submit_finding",
            "submit_narrative",
            "track_progress",
            "update_finding",
            "withdraw_finding",
        }
    ),
    ToolEffect.JOB_CONTROL: frozenset(
        {
            "check_extraction_status",
            "get_completed_results",
            "run_parallel",
            "start_extraction_batch",
            "wait",
            "wait_all",
        }
    ),
    ToolEffect.PUBLICATION: frozenset({"finalize_report"}),
    ToolEffect.FORENSIC_EXECUTION: frozenset(
        {
            "analyze_disk_pcaps",
            "analyze_office_document",
            "analyze_pdf",
            "carve_sqlite_from_raw",
            "collect_linux_live_state_bundle",
            "decrypt_app_data",
            "detect_steganography",
            "extract_archive",
            "extract_file_by_inode",
            "extract_steganography",
            "export_timeline_slice",
            "filter_timeline",
            "get_file_metadata",
            "index_app_files",
            "index_evtx_file",
            "parse_android_artifacts",
            "parse_browser_history",
            "parse_ios_artifacts",
            "parse_plist",
            "parse_pst",
            "query_sqlite_from_image",
            "run_aleapp",
            "run_amcache_parser",
            "run_bdeinfo",
            "run_binwalk",
            "run_bulk_extractor",
            "run_capa",
            "run_chainsaw",
            "run_chkrootkit",
            "run_clamav",
            "run_detect_it_easy",
            "run_dislocker",
            "run_evtx_parser",
            "run_exiftool",
            "run_floss",
            "run_fls",
            "run_foremost",
            "run_fsstat",
            "run_fvdeinfo",
            "run_hashdeep",
            "run_hayabusa",
            "run_hindsight",
            "run_ileapp",
            "run_mactime",
            "run_mft_parser",
            "run_mmls",
            "run_mvt_android",
            "run_mvt_ios",
            "run_pasco",
            "run_pcap_analysis",
            "run_photorec",
            "run_plaso",
            "run_prefetch_parser",
            "run_radare2",
            "run_registry_parser",
            "run_regripper",
            "run_scalpel",
            "run_shimcache_parser",
            "run_ssdeep",
            "run_strings",
            "run_suricata",
            "run_tcpflow",
            "run_tcpxtract",
            "run_volatility",
            "run_volatility_batch",
            "run_vshadow_info",
            "run_zeek_analysis",
            "run_zircolite",
            "triage_binary",
            "yara_scan_files",
            "yara_scan_memory",
            "yara_scan_with_volatility",
        }
    ),
    ToolEffect.CASE_READ: frozenset(
        {
            "analyze_anti_forensics_clock",
            "analyze_cloudtrail_pack",
            "analyze_evtx_pack",
            "analyze_execution_timeline",
            "analyze_kubernetes_pack",
            "assess_recovery",
            "audit_evidence_coverage",
            "audit_tool_coverage",
            "check_finalize_readiness",
            "correlate_pcap_with_host",
            "decode_payload",
            "detect_timestomping",
            "enrich_iocs",
            "events_for_entity",
            "extract_mft_timeline",
            "find_data_exfiltration_indicators",
            "find_defense_evasion",
            "find_execution_evidence",
            "find_file_staging",
            "find_lateral_movement_indicators",
            "find_persistence_mechanisms",
            "find_suspicious_processes",
            "get_amcache",
            "get_bookmarks",
            "get_carved_iocs",
            "get_deleted_files",
            "get_eventlog_anomalies",
            "get_findings",
            "get_fs_timeline",
            "get_investigation_summary",
            "get_ioc_summary",
            "get_plaso_stats",
            "get_process_environment",
            "get_process_privileges",
            "get_process_tree",
            "get_raw_output",
            "get_reasoning_review",
            "get_source_stats",
            "get_timeline",
            "get_tool_guide",
            "get_userassist",
            "host_timeline",
            "list_cases",
            "list_directory",
            "list_files",
            "list_partitions",
            "list_processes_from_memory",
            "list_sources",
            "lookup_attack_technique",
            "neighbors",
            "open_case",
            "parse_amcache",
            "parse_jump_lists",
            "parse_lnk_files",
            "parse_mft",
            "parse_prefetch",
            "parse_prefetch_detailed",
            "parse_shellbags",
            "parse_shimcache",
            "parse_srum",
            "parse_usn_journal",
            "path_between",
            "query_registry_value",
            "read_evidence_file",
            "reconstruct_execution_chains",
            "scan_files_in_memory",
            "scan_hidden_processes",
            "scan_kernel_modules",
            "search",
            "verify_evidence_integrity",
        }
    ),
}

_EFFECT_DECLARATIONS = {
    name: effect for effect, names in _TOOLS_BY_EFFECT.items() for name in names
}
if sum(len(names) for names in _TOOLS_BY_EFFECT.values()) != len(_EFFECT_DECLARATIONS):
    raise RuntimeError("tool effect declarations overlap")


def tool_access(
    *roles: Role,
    effect: ToolEffect | None = None,
    effects: Iterable[ToolEffect] | None = None,
) -> Callable[[F], F]:
    """Declare which pipeline roles may call this tool.

    Place this decorator BELOW ``@mcp.tool()`` so it runs first
    and registers the function before MCPServer wraps it.

    Example::

        @mcp.tool()
        @tool_access(EXECUTORS)
        def run_volatility(...):
            ...
    """
    combined = Role(0)
    for r in roles:
        combined |= r
    if effect is not None and effects is not None:
        raise TypeError("declare either effect or effects, not both")
    explicit_effects = (
        frozenset(effects)
        if effects is not None
        else frozenset({effect})
        if effect is not None
        else None
    )
    if explicit_effects is not None and not explicit_effects:
        raise ValueError("tool effect declarations must be nonempty")
    if explicit_effects is not None and not all(
        isinstance(declared, ToolEffect) for declared in explicit_effects
    ):
        raise TypeError("tool effects must be ToolEffect values")

    def decorator(fn: F) -> F:
        built_in_effect = _EFFECT_DECLARATIONS.get(fn.__name__)
        built_in_effects = (
            frozenset({built_in_effect}) if built_in_effect is not None else None
        )
        registered_effects = explicit_effects or built_in_effects
        if registered_effects is None:
            raise RuntimeError(
                f"registered tool {fn.__name__!r} has no explicit effect declaration"
            )
        if (
            explicit_effects is not None
            and built_in_effects is not None
            and explicit_effects != built_in_effects
        ):
            raise RuntimeError(
                f"registered tool {fn.__name__!r} conflicts with its built-in effect declaration"
            )
        _registry[fn.__name__] = combined
        _effect_registry[fn.__name__] = registered_effects
        return fn

    return decorator


def get_tools_for_role(role: Role) -> list[str]:
    """Return sorted MCP tool names accessible by a given role."""
    return sorted(f"mcp__mulder__{name}" for name, allowed in _registry.items() if role & allowed)


def get_registered_tool_roles(tool_name: str) -> Role | None:
    """Return the declared roles for one Mulder MCP tool.

    Both SDK-qualified names (``mcp__mulder__search``) and registry names
    (``search``) are accepted.  Returning ``None`` for unknown tools keeps
    authorization fail-closed without exposing the mutable registry.
    """
    return get_tool_access(tool_name)


def get_registered_tool_effect(tool_name: str) -> frozenset[ToolEffect] | None:
    """Return the immutable nonempty effect set for a registered tool."""
    return _effect_registry.get(tool_name.removeprefix("mcp__mulder__"))


def get_registered_tool_effect_set(tool_name: str) -> frozenset[ToolEffect] | None:
    """Compatibility alias for :func:`get_registered_tool_effect`."""
    return get_registered_tool_effect(tool_name)


def get_registered_tool_effects() -> Mapping[str, frozenset[ToolEffect]]:
    """Return an immutable snapshot suitable for completeness validation."""
    return dict(_effect_registry)


def get_tool_access(tool_name: str) -> Role | None:
    """Resolve one short or MCP-qualified tool name through the registry."""
    short_name = tool_name.removeprefix("mcp__mulder__")
    return _registry.get(short_name)
