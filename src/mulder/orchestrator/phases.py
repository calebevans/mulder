"""Phase definitions for the planner/executor/analyst investigation pipeline.

Each phase declares whether it uses a single agent or the three-role
split pipeline. Single-mode phases (catalog, report) run one agent.
Split-mode phases (extract, cross-system, narrative, audit) run a
planner, executor, and analyst in sequence with optional follow-up loops.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from mulder.orchestrator.prompts import (
    AUDIT_ANALYST_PROMPT,
    AUDIT_EXECUTOR_PROMPT,
    AUDIT_PLANNER_PROMPT,
    CATALOG_PROMPT,
    CROSS_SYSTEM_ANALYST_PROMPT,
    CROSS_SYSTEM_EXECUTOR_PROMPT,
    CROSS_SYSTEM_PLANNER_PROMPT,
    EXTRACT_ANALYST_PROMPT,
    EXTRACT_EXECUTOR_PROMPT,
    EXTRACT_PLANNER_PROMPT,
    NARRATIVE_ANALYST_PROMPT,
    NARRATIVE_EXECUTOR_PROMPT,
    NARRATIVE_PLANNER_PROMPT,
    REPORT_PROMPT,
)


@dataclass
class PhaseConfig:
    """Configuration for a single investigation phase.

    Phases operate in one of two modes:

    - **single**: One agent runs the entire phase. Used by catalog and
      report where the task is self-contained.
    - **split**: Three agents (planner, executor, analyst) collaborate
      in sequence. The planner outputs a JSON tool plan, the executor
      runs it, and the analyst interprets results and submits findings.

    Attributes:
        name: Phase identifier, also used as display label.
        mode: Whether this phase uses a single agent or the three-role
            split pipeline.
        single_role: Which role the single agent fills (planner or analyst).
        single_system_prompt: System prompt for single-mode agents.
        single_prompt_template: User message template for single-mode agents.
        single_allowed_tools: Tool whitelist for single-mode agents.
        single_disallowed_tools: Extra tool blocklist for single-mode agents.
        single_max_turns: Turn limit for single-mode agents.
        single_max_budget_usd: Spend cap for single-mode agents.
        planner_system_prompt: System prompt for the planner role.
        planner_prompt_template: User message template for the planner.
        planner_allowed_tools: Tool whitelist for the planner.
        planner_max_turns: Turn limit for the planner.
        planner_max_budget_usd: Spend cap for the planner.
        executor_system_prompt: System prompt for the executor role.
        executor_prompt_template: User message template for the executor.
        executor_allowed_tools: Tool whitelist for the executor.
        executor_max_turns: Turn limit for the executor.
        executor_max_budget_usd: Spend cap for the executor.
        analyst_system_prompt: System prompt for the analyst role.
        analyst_prompt_template: User message template for the analyst.
        analyst_allowed_tools: Tool whitelist for the analyst.
        analyst_max_turns: Turn limit for the analyst.
        analyst_max_budget_usd: Spend cap for the analyst.
        max_retries: Retry attempts when a quality gate fails.
        max_follow_ups: Times the analyst can request additional work.
        disallowed_tools: Global tool blocklist applied to all roles.
    """

    name: str
    mode: Literal["single", "split"]

    # Single-mode fields (catalog, report)
    single_role: Literal["planner", "analyst"] = "planner"
    single_system_prompt: str = ""
    single_prompt_template: str = ""
    single_allowed_tools: list[str] = field(default_factory=list)
    single_disallowed_tools: list[str] = field(default_factory=list)
    single_max_turns: int = 20
    single_max_budget_usd: float = 5.0

    # Split-mode planner fields
    planner_system_prompt: str = ""
    planner_prompt_template: str = ""
    planner_allowed_tools: list[str] = field(default_factory=list)
    planner_max_turns: int = 10
    planner_max_budget_usd: float = 2.0

    # Split-mode executor fields
    executor_system_prompt: str = ""
    executor_prompt_template: str = ""
    executor_allowed_tools: list[str] = field(default_factory=list)
    executor_max_turns: int = 40
    executor_max_budget_usd: float = 3.0

    # Split-mode analyst fields
    analyst_system_prompt: str = ""
    analyst_prompt_template: str = ""
    analyst_allowed_tools: list[str] = field(default_factory=list)
    analyst_max_turns: int = 20
    analyst_max_budget_usd: float = 5.0

    # Shared across all roles
    max_retries: int = 2
    max_follow_ups: int = 2
    disallowed_tools: list[str] = field(default_factory=lambda: ["Bash", "Shell"])


# ---------------------------------------------------------------------------
# Tool groups: reusable lists of MCP tool names to keep phase definitions DRY.
# ---------------------------------------------------------------------------

_EXTRACTION_TOOLS: list[str] = [
    # Cross-platform extraction
    "mcp__mulder__run_volatility",
    "mcp__mulder__run_volatility_batch",
    "mcp__mulder__run_fls",
    "mcp__mulder__run_mmls",
    "mcp__mulder__run_mactime",
    "mcp__mulder__run_fsstat",
    "mcp__mulder__run_bulk_extractor",
    "mcp__mulder__run_plaso",
    "mcp__mulder__run_pcap_analysis",
    "mcp__mulder__run_strings",
    "mcp__mulder__run_clamav",
    "mcp__mulder__run_hashdeep",
    "mcp__mulder__run_exiftool",
    "mcp__mulder__run_ssdeep",
    "mcp__mulder__run_foremost",
    "mcp__mulder__run_scalpel",
    "mcp__mulder__run_binwalk",
    "mcp__mulder__run_photorec",
    "mcp__mulder__run_radare2",
    "mcp__mulder__run_tcpflow",
    "mcp__mulder__run_tcpxtract",
    "mcp__mulder__carve_sqlite_from_raw",
    # Windows
    "mcp__mulder__run_evtx_parser",
    "mcp__mulder__run_hayabusa",
    "mcp__mulder__index_evtx_file",
    "mcp__mulder__run_registry_parser",
    "mcp__mulder__run_prefetch_parser",
    "mcp__mulder__run_amcache_parser",
    "mcp__mulder__run_shimcache_parser",
    "mcp__mulder__run_mft_parser",
    "mcp__mulder__run_regripper",
    "mcp__mulder__run_vshadow_info",
    "mcp__mulder__run_dislocker",
    "mcp__mulder__run_bdeinfo",
    # macOS
    "mcp__mulder__run_fvdeinfo",
    "mcp__mulder__run_hindsight",
    "mcp__mulder__run_pasco",
    # Mobile
    "mcp__mulder__run_mvt_android",
    "mcp__mulder__run_mvt_ios",
    "mcp__mulder__parse_android_artifacts",
    "mcp__mulder__parse_ios_artifacts",
    "mcp__mulder__decrypt_app_data",
    # Linux
    "mcp__mulder__run_chkrootkit",
    # Steganography and YARA
    "mcp__mulder__detect_steganography",
    "mcp__mulder__extract_steganography",
    "mcp__mulder__yara_scan_files",
    "mcp__mulder__yara_scan_memory",
    "mcp__mulder__yara_scan_with_volatility",
]

_COMPOSITE_TOOLS: list[str] = [
    "mcp__mulder__find_persistence_mechanisms",
    "mcp__mulder__find_lateral_movement_indicators",
    "mcp__mulder__find_data_exfiltration_indicators",
    "mcp__mulder__find_execution_evidence",
    "mcp__mulder__find_defense_evasion",
    "mcp__mulder__find_suspicious_processes",
    "mcp__mulder__correlate_across_sources",
    "mcp__mulder__reconstruct_execution_chains",
    "mcp__mulder__analyze_execution_timeline",
    "mcp__mulder__assess_recovery",
    "mcp__mulder__correlate_pcap_with_host",
]

# ---------------------------------------------------------------------------
# Phase definitions
# ---------------------------------------------------------------------------

CATALOG: PhaseConfig = PhaseConfig(
    name="catalog",
    mode="single",
    single_role="planner",
    single_system_prompt=CATALOG_PROMPT,
    single_prompt_template="Catalog all evidence in {evidence_path}.",
    single_allowed_tools=[
        "mcp__mulder__scan_evidence",
        "mcp__mulder__list_directory",
        "mcp__mulder__extract_archive",
        "mcp__mulder__start_extraction_batch",
        "mcp__mulder__check_extraction_status",
        "mcp__mulder__get_completed_results",
        "mcp__mulder__list_sources",
        "mcp__mulder__get_source_stats",
        "mcp__mulder__wait",
    ],
    single_max_turns=20,
    single_max_budget_usd=5.0,
)

EXTRACTION: PhaseConfig = PhaseConfig(
    name="extraction",
    mode="split",
    # Planner: evidence context is pre-populated; produce a tool plan
    planner_system_prompt=EXTRACT_PLANNER_PROMPT,
    planner_prompt_template=(
        "System: {system_name}\n"
        "Evidence path: {evidence_path}\n\n"
        "EVIDENCE CONTEXT:\n{evidence_context}"
    ),
    planner_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__list_cases",
        "mcp__mulder__list_sources",
        "mcp__mulder__list_directory",
    ],
    planner_max_turns=5,
    planner_max_budget_usd=2.0,
    # Executor: run every tool in the plan, report results
    executor_system_prompt=EXTRACT_EXECUTOR_PROMPT,
    executor_prompt_template="{plan}",
    executor_allowed_tools=[
        *_EXTRACTION_TOOLS,
        "mcp__mulder__start_extraction_batch",
        "mcp__mulder__check_extraction_status",
        "mcp__mulder__get_completed_results",
        "mcp__mulder__wait",
        "mcp__mulder__open_case",
    ],
    executor_max_turns=40,
    executor_max_budget_usd=3.0,
    # Analyst: query indexed results, submit findings
    analyst_system_prompt=EXTRACT_ANALYST_PROMPT,
    analyst_prompt_template=(
        "System: {system_name}\n\n"
        "Execution results:\n{execution_results}\n\n"
        "Investigation questions:\n{investigation_questions}"
    ),
    analyst_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__search",
        "mcp__mulder__get_raw_output",
        "mcp__mulder__submit_finding",
        "mcp__mulder__update_finding",
        "mcp__mulder__bookmark_window",
        "mcp__mulder__get_findings",
        "mcp__mulder__get_timeline",
        "mcp__mulder__track_progress",
        "mcp__mulder__get_investigation_summary",
    ],
    analyst_max_turns=20,
    analyst_max_budget_usd=5.0,
)

CROSS_SYSTEM: PhaseConfig = PhaseConfig(
    name="cross_system",
    mode="split",
    # Planner: review findings and sources, plan correlation queries
    planner_system_prompt=CROSS_SYSTEM_PLANNER_PROMPT,
    planner_prompt_template=(
        "Review all findings and sources. Plan cross-system correlation queries."
    ),
    planner_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__get_findings",
        "mcp__mulder__get_investigation_summary",
        "mcp__mulder__list_sources",
        "mcp__mulder__get_source_stats",
        "mcp__mulder__get_timeline",
        "mcp__mulder__get_bookmarks",
    ],
    planner_max_turns=10,
    planner_max_budget_usd=3.0,
    # Executor: run correlation and composite tools per the plan
    executor_system_prompt=CROSS_SYSTEM_EXECUTOR_PROMPT,
    executor_prompt_template="{plan}",
    executor_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__search",
        "mcp__mulder__get_raw_output",
        *_COMPOSITE_TOOLS,
        "mcp__mulder__list_processes_from_memory",
        "mcp__mulder__get_process_tree",
        "mcp__mulder__scan_hidden_processes",
        "mcp__mulder__scan_kernel_modules",
        "mcp__mulder__get_eventlog_anomalies",
        "mcp__mulder__get_carved_iocs",
        "mcp__mulder__decode_payload",
        "mcp__mulder__run_parallel",
    ],
    executor_max_turns=40,
    executor_max_budget_usd=5.0,
    # Analyst: interpret correlations, map MITRE, submit findings
    analyst_system_prompt=CROSS_SYSTEM_ANALYST_PROMPT,
    analyst_prompt_template=(
        "Execution results:\n{execution_results}\n\n"
        "Investigation questions:\n{investigation_questions}"
    ),
    analyst_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__search",
        "mcp__mulder__get_raw_output",
        "mcp__mulder__submit_finding",
        "mcp__mulder__update_finding",
        "mcp__mulder__delete_finding",
        "mcp__mulder__get_findings",
        "mcp__mulder__get_timeline",
        "mcp__mulder__bookmark_window",
        "mcp__mulder__lookup_attack_technique",
        "mcp__mulder__get_ioc_summary",
        "mcp__mulder__track_progress",
    ],
    analyst_max_turns=25,
    analyst_max_budget_usd=7.0,
)

ALTERNATIVE_NARRATIVE: PhaseConfig = PhaseConfig(
    name="alternative_narrative",
    mode="split",
    # Planner: identify claims to challenge, plan counter-analysis
    planner_system_prompt=NARRATIVE_PLANNER_PROMPT,
    planner_prompt_template=("Review current findings and plan counter-analysis."),
    planner_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__get_findings",
        "mcp__mulder__get_investigation_summary",
        "mcp__mulder__list_sources",
        "mcp__mulder__get_timeline",
    ],
    planner_max_turns=8,
    planner_max_budget_usd=2.0,
    # Executor: search for counter-evidence per the plan
    executor_system_prompt=NARRATIVE_EXECUTOR_PROMPT,
    executor_prompt_template="{plan}",
    executor_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__search",
        "mcp__mulder__get_raw_output",
        "mcp__mulder__correlate_across_sources",
        "mcp__mulder__run_parallel",
    ],
    executor_max_turns=25,
    executor_max_budget_usd=3.0,
    # Analyst: evaluate counter-evidence, submit negative findings
    analyst_system_prompt=NARRATIVE_ANALYST_PROMPT,
    analyst_prompt_template=(
        "Execution results:\n{execution_results}\n\n"
        "Investigation questions:\n{investigation_questions}"
    ),
    analyst_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__search",
        "mcp__mulder__get_raw_output",
        "mcp__mulder__submit_finding",
        "mcp__mulder__update_finding",
        "mcp__mulder__get_findings",
        "mcp__mulder__track_progress",
    ],
    analyst_max_turns=25,
    analyst_max_budget_usd=5.0,
)

_AUDIT_BLOCKED_TOOLS = [
    "Bash",
    "Shell",
    "mcp__mulder__extract_archive",
    "mcp__mulder__run_volatility",
    "mcp__mulder__run_volatility_batch",
    "mcp__mulder__run_fls",
    "mcp__mulder__run_bulk_extractor",
    "mcp__mulder__run_evtx_parser",
    "mcp__mulder__run_registry_parser",
    "mcp__mulder__run_plaso",
    "mcp__mulder__run_hayabusa",
    "mcp__mulder__run_prefetch_parser",
    "mcp__mulder__run_amcache_parser",
    "mcp__mulder__run_shimcache_parser",
    "mcp__mulder__run_mft_parser",
    "mcp__mulder__start_extraction_batch",
    "mcp__mulder__scan_evidence",
]

AUDIT: PhaseConfig = PhaseConfig(
    name="audit",
    mode="split",
    disallowed_tools=_AUDIT_BLOCKED_TOOLS,
    # Planner: run audit tools, identify gaps, plan remediation
    planner_system_prompt=AUDIT_PLANNER_PROMPT,
    planner_prompt_template=("Run audit checks and plan gap remediation.\n\n{consistency_report}"),
    planner_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__audit_evidence_coverage",
        "mcp__mulder__audit_tool_coverage",
        "mcp__mulder__get_investigation_summary",
        "mcp__mulder__check_finalize_readiness",
        "mcp__mulder__list_sources",
        "mcp__mulder__get_findings",
    ],
    planner_max_turns=10,
    planner_max_budget_usd=2.0,
    # Executor: fill gaps (search uncited sources, update findings)
    executor_system_prompt=AUDIT_EXECUTOR_PROMPT,
    executor_prompt_template="{plan}",
    executor_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__search",
        "mcp__mulder__get_raw_output",
        "mcp__mulder__submit_finding",
        "mcp__mulder__update_finding",
        "mcp__mulder__list_sources",
        "mcp__mulder__get_source_stats",
    ],
    executor_max_turns=30,
    executor_max_budget_usd=4.0,
    # Analyst: verify gates pass, finalize readiness
    analyst_system_prompt=AUDIT_ANALYST_PROMPT,
    analyst_prompt_template=(
        "Execution results:\n{execution_results}\n\n"
        "Investigation questions:\n{investigation_questions}"
    ),
    analyst_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__check_finalize_readiness",
        "mcp__mulder__get_findings",
        "mcp__mulder__update_finding",
        "mcp__mulder__submit_finding",
        "mcp__mulder__delete_finding",
        "mcp__mulder__get_investigation_summary",
        "mcp__mulder__track_progress",
    ],
    analyst_max_turns=20,
    analyst_max_budget_usd=5.0,
)

REPORT: PhaseConfig = PhaseConfig(
    name="report",
    mode="single",
    single_role="analyst",
    single_system_prompt=REPORT_PROMPT,
    single_prompt_template=("Write the investigation narrative and finalize the report."),
    single_allowed_tools=[
        "mcp__mulder__open_case",
        "mcp__mulder__list_cases",
        "mcp__mulder__submit_narrative",
        "mcp__mulder__finalize_report",
        "mcp__mulder__get_findings",
        "mcp__mulder__check_finalize_readiness",
        "mcp__mulder__update_finding",
        "mcp__mulder__get_investigation_summary",
        "mcp__mulder__get_ioc_summary",
        "mcp__mulder__get_bookmarks",
        "mcp__mulder__list_sources",
        "mcp__mulder__get_source_stats",
        "mcp__mulder__get_timeline",
    ],
    single_max_turns=20,
    single_max_budget_usd=10.0,
)

PHASE_SEQUENCE: list[PhaseConfig] = [
    CATALOG,
    EXTRACTION,
    CROSS_SYSTEM,
    ALTERNATIVE_NARRATIVE,
    AUDIT,
    REPORT,
]
