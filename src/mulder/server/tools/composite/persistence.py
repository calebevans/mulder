"""Persistence mechanism detection composite MCP tool."""

from __future__ import annotations

import time
from typing import Any

from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import (
    make_tool_call_id,
    project_window_evidence,
    slim_window,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.composite.core import (
    _EXE_CMD,
    _EXE_POWERSHELL,
    _SRC_EVTX_SYSTEM,
    _SRC_EZ_AMCACHE,
    _SRC_EZ_PREFETCH,
    _SRC_EZ_SHIMCACHE,
    _SRC_PLASO,
    _SRC_TSK_FILELIST,
    _check_missing_sources,
    _keyword_sub_query,
    _query_source,
    _source_exists,
    finalize_composite_result,
)

__all__ = ["find_persistence_mechanisms"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PERSISTENCE_KEYS: list[str] = [
    "\\Run\\",
    "\\RunOnce\\",
    "\\RunServices\\",
    "\\Userinit",
    "\\Shell",
    "AppInit_DLLs",
    "\\Winlogon\\",
    "\\Explorer\\Shell Folders",
    "WMI",
    "\\Services\\",
    "\\CurrentVersion\\Image File Execution",
]

_PERSISTENCE_EXECUTABLES: set[str] = {
    "schtasks.exe",
    "reg.exe",
    "sc.exe",
    "at.exe",
    "wmic.exe",
    "msiexec.exe",
    _EXE_POWERSHELL,
    _EXE_CMD,
    "bitsadmin.exe",
}

_STARTUP_PATH_PATTERNS: tuple[str, ...] = (
    "\\startup\\",
    "\\start menu\\programs\\startup\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_registry_persistence(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Scan SYSTEM and SOFTWARE registry hives for known autorun key patterns."""
    for reg_source in ("registry.system", "registry.software"):
        wins, tc_id = _query_source(reg_source, "find_persistence_mechanisms")
        sub_call_ids.append(tc_id)
        for w in wins:
            text_lower = w.raw_text.lower()
            matched_key = next(
                (key for key in _PERSISTENCE_KEYS if key.lower() in text_lower),
                None,
            )
            if matched_key is not None:
                mechanisms.append(
                    {
                        "type": "registry_autorun",
                        "key_pattern": matched_key,
                        "source": reg_source,
                        **project_window_evidence(w, reg_source, content_key="evidence_text"),
                        "source_window": slim_window(w),
                    }
                )


def _collect_service_persistence(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Collect installed services from Volatility svcscan output."""
    svcscan_wins, tc_svc = _query_source("volatility.svcscan", "find_persistence_mechanisms")
    sub_call_ids.append(tc_svc)
    for w in svcscan_wins:
        mechanisms.append(
            {
                "type": "installed_service",
                "source": "volatility.svcscan",
                **project_window_evidence(
                    w, "volatility.svcscan", content_key="evidence_text"
                ),
                "source_window": slim_window(w),
            }
        )


def _collect_evtx_service_installs(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Search system EVTX for service installation events (Event ID 7045)."""
    evtx_wins, tc_evtx = _keyword_sub_query(
        "service installation event 7045 new service installed",
        "find_persistence_mechanisms",
        source_name=_SRC_EVTX_SYSTEM,
        k=20,
    )
    sub_call_ids.append(tc_evtx)
    for w in evtx_wins:
        if "7045" in w.raw_text or "service" in w.raw_text.lower():
            mechanisms.append(
                {
                    "type": "service_install_event",
                    "source": _SRC_EVTX_SYSTEM,
                    **project_window_evidence(w, _SRC_EVTX_SYSTEM, content_key="evidence_text"),
                    "source_window": slim_window(w),
                }
            )


def _collect_startup_dir_modifications(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Search Plaso timeline for modifications to startup directories."""
    plaso_wins, tc_plaso = _keyword_sub_query(
        "startup directory autorun modification programs startup folder",
        "find_persistence_mechanisms",
        source_name=_SRC_PLASO,
        k=20,
    )
    sub_call_ids.append(tc_plaso)
    for w in plaso_wins:
        text_lower = w.raw_text.lower()
        if "startup" in text_lower or "autorun" in text_lower or "run\\" in text_lower:
            mechanisms.append(
                {
                    "type": "startup_directory_modification",
                    "source": _SRC_PLASO,
                    **project_window_evidence(w, _SRC_PLASO, content_key="evidence_text"),
                    "source_window": slim_window(w),
                }
            )


def _collect_ez_execution_persistence(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Query EZ shimcache/amcache/prefetch for persistence-related executables."""
    ez_sources = [
        (_SRC_EZ_SHIMCACHE, "shimcache_persistence"),
        (_SRC_EZ_AMCACHE, "amcache_persistence"),
        (_SRC_EZ_PREFETCH, "prefetch_persistence"),
    ]
    for src, mech_type in ez_sources:
        if not _source_exists(src):
            continue
        wins, tc_id = _query_source(src, "find_persistence_mechanisms")
        sub_call_ids.append(tc_id)
        for w in wins:
            text_lower = w.raw_text.lower()
            matched_exe = next(
                (exe for exe in _PERSISTENCE_EXECUTABLES if exe in text_lower),
                None,
            )
            if matched_exe is not None:
                mechanisms.append(
                    {
                        "type": mech_type,
                        "executable": matched_exe,
                        "source": src,
                        **project_window_evidence(w, src, content_key="evidence_text"),
                        "source_window": slim_window(w),
                    }
                )


def _collect_scheduled_task_persistence(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Search EVTX for scheduled task creation/modification events."""
    evtx_wins, tc_evtx = _keyword_sub_query(
        "scheduled task created modified event 106 140 4698 schtasks",
        "find_persistence_mechanisms",
        source_name=_SRC_EVTX_SYSTEM,
        k=20,
    )
    sub_call_ids.append(tc_evtx)
    for w in evtx_wins:
        text = w.raw_text
        if any(eid in text for eid in ("106", "140", "4698")) or "schtask" in text.lower():
            mechanisms.append(
                {
                    "type": "scheduled_task",
                    "source": _SRC_EVTX_SYSTEM,
                    **project_window_evidence(w, _SRC_EVTX_SYSTEM, content_key="evidence_text"),
                    "source_window": slim_window(w),
                }
            )


def _collect_startup_files(
    mechanisms: list[dict[str, Any]],
    sub_call_ids: list[str],
) -> None:
    """Check TSK file listing for files placed in startup directories."""
    if not _source_exists(_SRC_TSK_FILELIST):
        return
    wins, tc_id = _query_source(_SRC_TSK_FILELIST, "find_persistence_mechanisms")
    sub_call_ids.append(tc_id)
    for w in wins:
        text_lower = w.raw_text.lower()
        if any(pat in text_lower for pat in _STARTUP_PATH_PATTERNS):
            mechanisms.append(
                {
                    "type": "startup_directory_file",
                    "source": _SRC_TSK_FILELIST,
                    **project_window_evidence(
                        w, _SRC_TSK_FILELIST, content_key="evidence_text"
                    ),
                    "source_window": slim_window(w),
                }
            )


# ---------------------------------------------------------------------------
# MCP tool handler
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.CROSS_EXECUTOR)
def find_persistence_mechanisms() -> dict[str, object]:
    """Detect persistence mechanisms across registry, services, event logs, and timeline.

    Searches Windows registry hives for known autorun keys (Run, RunOnce,
    Userinit, AppInit_DLLs, etc.), cross-references with Volatility service
    scan output, checks event logs for service installation and scheduled
    task events, queries EZ Tools shimcache/amcache/prefetch for execution
    of persistence-related tools, and inspects TSK file listings and the
    Plaso timeline for modifications to startup directories.  Read-only.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    sub_call_ids: list[str] = []
    mechanisms: list[dict[str, Any]] = []

    _collect_registry_persistence(mechanisms, sub_call_ids)
    _collect_service_persistence(mechanisms, sub_call_ids)
    _collect_evtx_service_installs(mechanisms, sub_call_ids)
    _collect_startup_dir_modifications(mechanisms, sub_call_ids)
    _collect_ez_execution_persistence(mechanisms, sub_call_ids)
    _collect_scheduled_task_persistence(mechanisms, sub_call_ids)
    _collect_startup_files(mechanisms, sub_call_ids)

    missing = _check_missing_sources(
        [
            ("volatility.svcscan", "run_volatility('svcscan', '<memory_path>')"),
            ("registry.system", "run_registry_parser('<image_path>', hive='SYSTEM')"),
            ("registry.software", "run_registry_parser('<image_path>', hive='SOFTWARE')"),
            ("ez.shimcache", "run_shimcache_parser('<image_path>')"),
            ("ez.amcache", "run_amcache_parser('<image_path>')"),
            ("ez.prefetch", "run_prefetch_parser('<image_path>')"),
        ]
    )

    return finalize_composite_result(
        ctx=ctx,
        composite_id=composite_id,
        tool_name="find_persistence_mechanisms",
        results=mechanisms,
        coverage_sources=[
            "registry.system",
            "registry.software",
            "volatility.svcscan",
            _SRC_EVTX_SYSTEM,
            _SRC_PLASO,
            _SRC_EZ_SHIMCACHE,
            _SRC_EZ_AMCACHE,
            _SRC_EZ_PREFETCH,
            _SRC_TSK_FILELIST,
        ],
        missing=missing,
        sub_call_ids=sub_call_ids,
        t0=t0,
    )
