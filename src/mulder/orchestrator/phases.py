"""Phase definitions for the planner/executor/analyst investigation pipeline.

Each phase declares whether it uses a single agent or the three-role
split pipeline. Single-mode phases (catalog, report) run one agent.
Split-mode phases (extract, cross-system, narrative) run a planner,
executor, and analyst in sequence with optional follow-up loops.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from mulder.orchestrator.prompts import (
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
from mulder.server.tool_access import Role, get_tools_for_role


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
    analyst_max_turns: int = 30
    analyst_max_budget_usd: float = 5.0

    # Shared across all roles
    max_retries: int = 2
    max_follow_ups: int = 2
    disallowed_tools: list[str] = field(default_factory=lambda: ["Bash", "Shell"])


# ---------------------------------------------------------------------------
# Phase definitions
# ---------------------------------------------------------------------------

CATALOG: PhaseConfig = PhaseConfig(
    name="catalog",
    mode="single",
    single_role="planner",
    single_system_prompt=CATALOG_PROMPT,
    single_prompt_template="Catalog all evidence in {evidence_path}.{case_id_instruction}",
    single_allowed_tools=get_tools_for_role(Role.CATALOG),
    single_max_turns=40,
    single_max_budget_usd=8.0,
)

_EXECUTOR_CASE_ID_PREFIX: str = (
    "The case_id is '{case_id}'. Call open_case(case_id='{case_id}') "
    "as your FIRST action before executing any other tools.\n\n"
)

_EXTRACTION_BLOCKED_TOOLS: list[str] = [
    "Bash",
    "Shell",
    "mcp__mulder__submit_narrative",
    "mcp__mulder__finalize_report",
    "mcp__mulder__audit_evidence_coverage",
    "mcp__mulder__audit_tool_coverage",
    "mcp__mulder__check_finalize_readiness",
    "mcp__mulder__deduplicate_findings",
    "mcp__mulder__delete_finding",
]

EXTRACTION: PhaseConfig = PhaseConfig(
    name="extraction",
    mode="split",
    disallowed_tools=_EXTRACTION_BLOCKED_TOOLS,
    planner_system_prompt=EXTRACT_PLANNER_PROMPT,
    planner_prompt_template=(
        "Case ID: {case_id}\n"
        "System: {system_name}\n"
        "Evidence path: {evidence_path}\n\n"
        "Call open_case(case_id='{case_id}') as your FIRST action.\n\n"
        "EVIDENCE CONTEXT:\n{evidence_context}"
    ),
    planner_allowed_tools=get_tools_for_role(Role.EXTRACT_PLANNER),
    planner_max_turns=15,
    planner_max_budget_usd=2.0,
    executor_system_prompt=EXTRACT_EXECUTOR_PROMPT,
    executor_prompt_template=_EXECUTOR_CASE_ID_PREFIX + "{plan}",
    executor_allowed_tools=get_tools_for_role(Role.EXTRACT_EXECUTOR),
    executor_max_turns=80,
    executor_max_budget_usd=5.0,
    analyst_system_prompt=EXTRACT_ANALYST_PROMPT,
    analyst_prompt_template=(
        "Case ID: {case_id}\n"
        "Call open_case(case_id='{case_id}') as your FIRST action.\n\n"
        "System: {system_name}\n\n"
        "Execution results:\n{execution_results}\n\n"
        "Investigation questions:\n{investigation_questions}"
    ),
    analyst_allowed_tools=get_tools_for_role(Role.EXTRACT_ANALYST),
    analyst_max_turns=60,
    analyst_max_budget_usd=5.0,
)

CROSS_SYSTEM: PhaseConfig = PhaseConfig(
    name="cross_system",
    mode="split",
    planner_system_prompt=CROSS_SYSTEM_PLANNER_PROMPT,
    planner_prompt_template=(
        "Case ID: {case_id}\n"
        "Call open_case(case_id='{case_id}') as your FIRST action.\n\n"
        "{case_briefing}Review all findings and sources. Plan cross-system correlation queries."
    ),
    planner_allowed_tools=get_tools_for_role(Role.CROSS_PLANNER),
    planner_max_turns=10,
    planner_max_budget_usd=3.0,
    executor_system_prompt=CROSS_SYSTEM_EXECUTOR_PROMPT,
    executor_prompt_template=_EXECUTOR_CASE_ID_PREFIX + "{plan}",
    executor_allowed_tools=get_tools_for_role(Role.CROSS_EXECUTOR),
    executor_max_turns=50,
    executor_max_budget_usd=7.0,
    analyst_system_prompt=CROSS_SYSTEM_ANALYST_PROMPT,
    analyst_prompt_template=(
        "Case ID: {case_id}\n"
        "Call open_case(case_id='{case_id}') as your FIRST action.\n\n"
        "Execution results:\n{execution_results}\n\n"
        "Investigation questions:\n{investigation_questions}"
    ),
    analyst_allowed_tools=get_tools_for_role(Role.CROSS_ANALYST),
    analyst_max_turns=50,
    analyst_max_budget_usd=7.0,
)

ALTERNATIVE_NARRATIVE: PhaseConfig = PhaseConfig(
    name="alternative_narrative",
    mode="split",
    planner_system_prompt=NARRATIVE_PLANNER_PROMPT,
    planner_prompt_template=(
        "Case ID: {case_id}\n"
        "Call open_case(case_id='{case_id}') as your FIRST action.\n\n"
        "{case_briefing}Review current findings and plan counter-analysis.\n\n{consistency_report}"
    ),
    planner_allowed_tools=get_tools_for_role(Role.NARRATIVE_PLANNER),
    planner_max_turns=10,
    planner_max_budget_usd=3.0,
    executor_system_prompt=NARRATIVE_EXECUTOR_PROMPT,
    executor_prompt_template=_EXECUTOR_CASE_ID_PREFIX + "{plan}",
    executor_allowed_tools=get_tools_for_role(Role.NARRATIVE_EXECUTOR),
    executor_max_turns=35,
    executor_max_budget_usd=5.0,
    analyst_system_prompt=NARRATIVE_ANALYST_PROMPT,
    analyst_prompt_template=(
        "Case ID: {case_id}\n"
        "Call open_case(case_id='{case_id}') as your FIRST action.\n\n"
        "Execution results:\n{execution_results}\n\n"
        "Investigation questions:\n{investigation_questions}"
    ),
    analyst_allowed_tools=get_tools_for_role(Role.NARRATIVE_ANALYST),
    analyst_max_turns=35,
    analyst_max_budget_usd=7.0,
)

REPORT: PhaseConfig = PhaseConfig(
    name="report",
    mode="single",
    single_role="analyst",
    single_system_prompt=REPORT_PROMPT,
    single_prompt_template=(
        "{case_briefing}Write the investigation narrative and finalize the report."
    ),
    single_allowed_tools=get_tools_for_role(Role.REPORT),
    single_max_turns=25,
    single_max_budget_usd=12.0,
)
