"""Volatility 3 memory analysis MCP tools."""

from __future__ import annotations

import logging
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FuturesTimeoutError
from pathlib import Path
from typing import Any

from mulder.extractors.volatility import (
    _find_vol_binary,
    _plugin_short_name,
)
from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "run_volatility",
    "run_volatility_batch",
]

logger = logging.getLogger(__name__)

_PLUGIN_TIMEOUT = 600

_VOL_PLUGIN_MAP: dict[str, str] = {
    "pslist": "windows.pslist.PsList",
    "pstree": "windows.pstree.PsTree",
    "cmdline": "windows.cmdline.CmdLine",
    "netscan": "windows.netscan.NetScan",
    "netstat": "windows.netstat.NetStat",
    "connscan": "windows.connscan.ConnScan",
    "sockscan": "windows.sockscan.SockScan",
    "malfind": "windows.malfind.Malfind",
    "dlllist": "windows.dlllist.DllList",
    "svcscan": "windows.svcscan.SvcScan",
    "handles": "windows.handles.Handles",
    "psscan": "windows.psscan.PsScan",
    "envars": "windows.envars.Envars",
    "getsids": "windows.getsids.GetSIDs",
    "hivelist": "windows.registry.hivelist.HiveList",
    "userassist": "windows.registry.userassist.UserAssist",
    "filescan": "windows.filescan.FileScan",
    "modules": "windows.modules.Modules",
    "modscan": "windows.modscan.ModScan",
    "vadinfo": "windows.vadinfo.VadInfo",
    "info": "windows.info.Info",
}

_NETSCAN_FALLBACKS: list[str] = [
    "windows.connscan.ConnScan",
    "windows.sockscan.SockScan",
]


def _resolve_plugin_name(plugin: str) -> str:
    """Resolve a short plugin name to the full Volatility 3 class path."""
    if "." in plugin:
        return plugin
    lower = plugin.lower()
    if lower in _VOL_PLUGIN_MAP:
        return _VOL_PLUGIN_MAP[lower]
    return f"windows.{lower}.{plugin}"


def _is_xp_unsupported_error(stderr: str) -> bool:
    """Heuristic: does stderr indicate the plugin is unsupported for this memory image?"""
    lower = stderr.lower()
    return any(
        kw in lower
        for kw in ("unsupported", "not a valid plugin", "not found", "unable to validate")
    )


def _run_single_vol_plugin(
    vol_cmd: list[str],
    memory_path: str,
    plugin: str,
    timeout: int = _PLUGIN_TIMEOUT,
) -> dict[str, object]:
    """Run one Volatility plugin, index the output, return summary.

    For netscan (Vista+), automatically falls back to connscan / sockscan
    when the plugin fails, which covers Windows XP memory images.

    Captures partial stdout on timeout so that any lines already produced
    by the plugin are indexed rather than discarded.
    """
    short = _plugin_short_name(plugin)
    cmd = [*vol_cmd, "-f", memory_path, plugin]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        partial_stdout = exc.stdout or ""
        if isinstance(partial_stdout, bytes):
            partial_stdout = partial_stdout.decode("utf-8", errors="replace")
        partial_stdout = partial_stdout.strip()

        if partial_stdout and partial_stdout.count("\n") > 1:
            summary = extract_and_index(
                raw_output=partial_stdout,
                source_name=f"volatility.{short}",
                source_path=memory_path,
                extractor_name="volatility3",
            )
            summary["plugin"] = plugin
            summary["status"] = "partial"
            summary["error_type"] = "timeout"
            summary["error_message"] = (
                f"{plugin} timed out after {timeout}s; partial results indexed"
            )
            return summary

        return {
            "plugin": plugin,
            "status": "error",
            "error_type": "timeout",
            "source_name": f"volatility.{short}",
            "error_message": f"{plugin} timed out after {timeout}s",
        }

    stderr_text = proc.stderr or ""
    if proc.returncode != 0 or not proc.stdout.strip():
        is_netscan = short == "netscan"
        if is_netscan and _is_xp_unsupported_error(stderr_text):
            for fallback_plugin in _NETSCAN_FALLBACKS:
                fb_short = _plugin_short_name(fallback_plugin)
                fb_cmd = [*vol_cmd, "-f", memory_path, fallback_plugin]
                try:
                    fb_proc = subprocess.run(
                        fb_cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    continue
                if fb_proc.returncode == 0 and fb_proc.stdout.strip():
                    summary = extract_and_index(
                        raw_output=fb_proc.stdout.strip(),
                        source_name=f"volatility.{fb_short}",
                        source_path=memory_path,
                        extractor_name="volatility3",
                    )
                    summary["plugin"] = fallback_plugin
                    summary["status"] = "fallback_used"
                    summary["original_plugin"] = plugin
                    summary["fallback_plugin"] = fallback_plugin
                    return summary

        error_type = "plugin_unsupported" if _is_xp_unsupported_error(stderr_text) else "no_output"
        result: dict[str, object] = {
            "plugin": plugin,
            "status": "error",
            "error_type": error_type,
            "source_name": f"volatility.{short}",
            "error_message": stderr_text[:300],
        }
        if is_netscan:
            result["suggestion"] = (
                "Try run_volatility('connscan', ...) or run_volatility('sockscan', ...) "
                "for XP/2003 network connections"
            )
        return result

    output = proc.stdout.strip()
    lines = output.split("\n")
    if len(lines) <= 1:
        return {
            "plugin": plugin,
            "status": "header_only",
            "source_name": f"volatility.{short}",
            "message": (
                f"Plugin {plugin} produced only column headers. "
                f"This usually means ISF symbols are missing for this "
                f"memory dump's Windows version, or the memory format "
                f"is not fully supported."
            ),
        }

    summary = extract_and_index(
        raw_output=output,
        source_name=f"volatility.{short}",
        source_path=memory_path,
        extractor_name="volatility3",
    )
    summary["plugin"] = plugin
    if short == "malfind":
        summary["caveat"] = (
            "RWX memory is expected in AV engines, JIT compilers, and "
            ".NET CLR. Verify hex dump content before concluding injection."
        )
    return summary


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_volatility(plugin: str, memory_path: str) -> dict[str, object]:
    """Run a single Volatility 3 plugin against a memory dump and index the output.

    Call after extracting a memory dump (e.g. via extract_archive) when you
    need output from one specific plugin. Prefer run_volatility_batch for
    multiple plugins since it builds the Volatility context only once.

    Indexes output as ``volatility.<plugin>`` source, searchable via
    search() and get_raw_output().

    Args:
        plugin: Volatility 3 plugin name (e.g. "windows.pslist.PsList"
            or short form "pslist").
        memory_path: Path to the memory dump file.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"plugin": plugin, "memory_path": memory_path}

    if not Path(memory_path).exists():
        return error_response(
            tc_id,
            "run_volatility",
            params,
            f"File not found: {memory_path}",
            error_type="file_not_found",
        )

    try:
        vol_cmd = _find_vol_binary()
    except RuntimeError as exc:
        return error_response(
            tc_id,
            "run_volatility",
            params,
            str(exc),
            (time.monotonic() - t0) * 1000,
            error_type="binary_missing",
            suggestion="Install Volatility 3: pip install volatility3",
        )

    plugin = _resolve_plugin_name(plugin)
    timeout = adaptive_timeout(memory_path, base=_PLUGIN_TIMEOUT)

    result = _run_single_vol_plugin(vol_cmd, memory_path, plugin, timeout)
    elapsed = (time.monotonic() - t0) * 1000
    source_name = result.get("source_name")
    return tool_response(
        tc_id,
        "run_volatility",
        params,
        result,
        str(source_name) if source_name is not None else None,
        elapsed,
    )


def _render_treegrid_to_text(treegrid: Any) -> str:
    """Convert a Volatility TreeGrid to tab-separated text."""
    columns = [c.name for c in treegrid.columns]
    lines = ["\t".join(columns)]

    def _visitor(node: Any, accumulator: Any) -> Any:
        """Append one row of tab-separated values to *accumulator*."""
        values = treegrid.values(node)
        row = []
        for i, _col in enumerate(treegrid.columns):
            val = values[i]
            if val is None:
                row.append("")
            else:
                row.append(str(val))
        accumulator.append("\t".join(row))
        return accumulator

    treegrid.populate(_visitor, lines)
    return "\n".join(lines)


def _build_volatility_context(memory_path: str) -> tuple[Any, Any, dict[str, Any]]:
    """Build the Volatility 3 framework context for batch plugin execution.

    Imports the Volatility 3 library, initializes a fresh context configured
    for the target memory image, runs automagic module discovery, and collects
    available plugins.

    Args:
        memory_path: Path to the memory dump file.

    Returns:
        Tuple of (context, automagics, plugin_list) where plugin_list maps
        fully-qualified plugin names to their class objects.

    Raises:
        ImportError: If the volatility3 library is not installed.
    """
    import volatility3.framework
    import volatility3.plugins
    from volatility3.framework import automagic, contexts
    from volatility3.framework.configuration import requirements as vol_reqs

    ctx = contexts.Context()
    volatility3.framework.import_files(volatility3.plugins, True)
    automagics = automagic.available(ctx)
    plugin_list = volatility3.framework.list_plugins()

    file_path = Path(memory_path).resolve()
    single_location = vol_reqs.URIRequirement.location_from_file(str(file_path))
    ctx.config["automagic.LayerStacker.single_location"] = single_location

    return ctx, automagics, plugin_list


def _run_batch_plugin(
    vol_ctx: Any,
    automagics: Any,
    plugin_class: Any,
    plugin_name: str,
    memory_path: str,
) -> dict[str, Any]:
    """Execute a single Volatility plugin within an existing batch context.

    Constructs the plugin against the shared context, runs it, renders
    the TreeGrid output to text, and indexes the result.

    Args:
        vol_ctx: Pre-built Volatility context.
        automagics: Automagic modules for the context.
        plugin_class: The resolved plugin class to execute.
        plugin_name: Fully-qualified plugin name (e.g. "windows.pslist.PsList").
        memory_path: Path to the memory dump file (for indexing metadata).

    Returns:
        Result dict with plugin output summary on success, or a status dict
        indicating empty output.

    Raises:
        Exception: Propagates any exception from plugin construction or execution.
    """
    from volatility3.framework import plugins as vol_plugins

    short = _plugin_short_name(plugin_name)
    base_path = f"plugins.batch.{short}"
    constructed = vol_plugins.construct_plugin(
        vol_ctx,
        automagics,
        plugin_class,
        base_path,
        None,
        None,
    )
    treegrid = constructed.run()
    output = _render_treegrid_to_text(treegrid)

    stripped = output.strip()
    if not stripped:
        return {
            "plugin": plugin_name,
            "status": "empty",
            "source_name": f"volatility.{short}",
            "error_message": "Plugin produced no output",
        }

    lines = stripped.split("\n")
    if len(lines) <= 1:
        return {
            "plugin": plugin_name,
            "status": "header_only",
            "source_name": f"volatility.{short}",
            "message": (
                f"Plugin {plugin_name} produced only column headers. "
                f"This usually means ISF symbols are missing for this "
                f"memory dump's Windows version, or the memory format "
                f"is not fully supported."
            ),
        }

    summary = extract_and_index(
        raw_output=stripped,
        source_name=f"volatility.{short}",
        source_path=memory_path,
        extractor_name="volatility3",
    )
    summary["plugin"] = plugin_name
    return summary


def _run_netscan_fallback_batch(
    vol_ctx: Any,
    automagics: Any,
    memory_path: str,
    plugin_list: dict[str, Any],
    original_plugin: str,
) -> dict[str, Any] | None:
    """Attempt ConnScan/SockScan as fallback when netscan is unsupported.

    Tries each fallback plugin (connscan, sockscan) against the shared
    context. Returns the first successful result, or None if all fail.

    Args:
        vol_ctx: Pre-built Volatility context.
        automagics: Automagic modules for the context.
        memory_path: Path to the memory dump file.
        plugin_list: Mapping of plugin names to classes.
        original_plugin: The original netscan plugin name that failed.

    Returns:
        Result dict with fallback output on success, or None if all
        fallback plugins also fail.
    """
    from volatility3.framework import plugins as vol_plugins

    for fb_name in ("connscan", "sockscan"):
        fb_full = _resolve_plugin_name(fb_name)
        fb_class = plugin_list.get(fb_full)
        if fb_class is None:
            continue
        try:
            fb_path = f"plugins.batch.{fb_name}"
            fb_constructed = vol_plugins.construct_plugin(
                vol_ctx,
                automagics,
                fb_class,
                fb_path,
                None,
                None,
            )
            fb_grid = fb_constructed.run()
            fb_output = _render_treegrid_to_text(fb_grid)
            if fb_output.strip():
                fb_summary = extract_and_index(
                    raw_output=fb_output,
                    source_name=f"volatility.{fb_name}",
                    source_path=memory_path,
                    extractor_name="volatility3",
                )
                fb_summary["plugin"] = fb_full
                fb_summary["status"] = "fallback_used"
                fb_summary["original_plugin"] = original_plugin
                return fb_summary
        except Exception:
            logger.debug("Fallback %s failed", fb_name, exc_info=True)
            continue

    return None


def _run_batch_plugin_timed(
    vol_ctx: Any,
    automagics: Any,
    plugin_class: Any,
    plugin_name: str,
    memory_path: str,
    timeout: int,
) -> dict[str, Any]:
    """Execute a batch plugin with a per-plugin timeout via thread pool.

    If the plugin exceeds *timeout* seconds, returns an error dict.  The
    underlying thread may continue running in the background, but the
    batch is not blocked.

    Args:
        vol_ctx: Pre-built Volatility context.
        automagics: Automagic modules for the context.
        plugin_class: The resolved plugin class to execute.
        plugin_name: Fully-qualified plugin name.
        memory_path: Path to the memory dump file.
        timeout: Maximum seconds to wait for the plugin.

    Returns:
        Plugin result dict on success, or an error dict on timeout.
    """
    short = _plugin_short_name(plugin_name)
    executor = _ThreadPoolExecutor(max_workers=1)
    future = executor.submit(
        _run_batch_plugin, vol_ctx, automagics, plugin_class, plugin_name, memory_path
    )
    try:
        result: dict[str, Any] = future.result(timeout=timeout)
        return result
    except (_FuturesTimeoutError, TimeoutError):
        logger.warning(
            "Batch plugin %s exceeded %ds timeout (Python API)",
            plugin_name,
            timeout,
        )
        return {
            "plugin": plugin_name,
            "status": "error",
            "error_type": "timeout",
            "source_name": f"volatility.{short}",
            "error_message": (f"{plugin_name} timed out after {timeout}s (Python API)"),
        }
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _aggregate_batch_results(
    results: dict[str, dict[str, object]],
    plugins: list[str],
    tc_id: str,
    params: dict[str, object],
    t0: float,
    *,
    fallback_used: bool = False,
) -> dict[str, object]:
    """Compute summary statistics from per-plugin results and build the response.

    Args:
        results: Mapping of plugin short names to their result dicts.
        plugins: Original list of requested plugin names.
        tc_id: Tool call ID for audit logging.
        params: Original tool parameters for audit logging.
        t0: Monotonic start time for elapsed calculation.
        fallback_used: If True, marks the response as using subprocess fallback.

    Returns:
        Standard batch tool response dict.
    """
    succeeded = sum(
        1 for r in results.values() if r.get("status") not in ("error", "empty", "header_only")
    )
    header_only_count = sum(1 for r in results.values() if r.get("status") == "header_only")
    failed = len(results) - succeeded - header_only_count

    total_windows = 0
    total_lines = 0
    for r in results.values():
        wi = r.get("windows_indexed", 0)
        lc = r.get("line_count", 0)
        total_windows += wi if isinstance(wi, int) else 0
        total_lines += lc if isinstance(lc, int) else 0
        r.pop("source_id", None)
        r.pop("source_name", None)

    payload: dict[str, object] = {
        "plugins_requested": len(plugins),
        "plugins_succeeded": succeeded,
        "plugins_header_only": header_only_count,
        "plugins_failed": failed,
        "total_windows_indexed": total_windows,
        "total_lines": total_lines,
        "per_plugin": results,
    }
    if fallback_used:
        payload["execution_mode"] = "subprocess_fallback"

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_volatility_batch",
        params,
        payload,
        None,
        elapsed,
    )


def _run_batch_subprocess_fallback(
    plugins: list[str],
    memory_path: str,
    tc_id: str,
    t0: float,
    params: dict[str, object],
) -> dict[str, object]:
    """Execute batch plugins via subprocess when the Python API fails.

    Provides a fallback path when the Volatility 3 Python library is
    importable but context construction fails (e.g., missing ISF symbols,
    corrupt layer stacking).  Each plugin runs in its own subprocess, so
    a failure in one does not affect the others.

    Args:
        plugins: List of plugin names (short or full form).
        memory_path: Path to the memory dump file.
        tc_id: Tool call ID for the parent batch request.
        t0: Monotonic start time for elapsed calculation.
        params: Original tool parameters for audit logging.

    Returns:
        Standard batch result dict.
    """
    try:
        vol_cmd = _find_vol_binary()
    except RuntimeError as exc:
        return error_response(
            tc_id,
            "run_volatility_batch",
            params,
            str(exc),
            error_type="binary_missing",
            suggestion="Install Volatility 3: pip install volatility3",
        )

    timeout = adaptive_timeout(memory_path, base=_PLUGIN_TIMEOUT)
    results: dict[str, dict[str, object]] = {}
    for plugin_name in plugins:
        full_name = _resolve_plugin_name(plugin_name)
        results[plugin_name] = _run_single_vol_plugin(vol_cmd, memory_path, full_name, timeout)

    return _aggregate_batch_results(results, plugins, tc_id, params, t0, fallback_used=True)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_volatility_batch(
    plugins: list[str],
    memory_path: str,
    force: bool = False,
) -> dict[str, object]:
    """Run multiple Volatility 3 plugins in one call with shared context setup.

    Call after extracting a memory dump when you need multiple memory
    analysis plugins. This is the primary memory extraction tool; context
    setup runs once (~15s) then each plugin executes against it. Falls
    back to subprocess execution when the Python API fails.

    Each plugin indexes as ``volatility.<plugin>`` (e.g.
    ``volatility.pslist``). Use via start_extraction_batch for background
    execution, or call directly for foreground runs.

    Args:
        plugins: List of plugin names. Recommended full set for thorough
            investigation: ``["pslist", "pstree", "cmdline", "netscan",
            "malfind", "psscan", "dlllist", "svcscan", "handles",
            "envars", "getsids", "filescan", "modules", "modscan",
            "hivelist", "userassist", "vadinfo"]``. Minimal triage set:
            ``["pslist", "cmdline", "netscan", "malfind"]``.
        memory_path: Path to the memory dump file.
        force: If True, skip the already-indexed check and re-run.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"plugins": plugins, "memory_path": memory_path}

    if not force:
        existing = sources_already_indexed(["volatility."], evidence_path=memory_path)
        if existing:
            return tool_response(
                tc_id,
                "run_volatility_batch",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "volatility",
                0.0,
            )

    if not Path(memory_path).exists():
        return error_response(
            tc_id,
            "run_volatility_batch",
            params,
            f"File not found: {memory_path}",
            error_type="file_not_found",
        )

    try:
        ctx, automagics, plugin_list = _build_volatility_context(memory_path)
    except ImportError:
        logger.info(
            "Volatility 3 Python library not available; falling back to subprocess execution"
        )
        return _run_batch_subprocess_fallback(plugins, memory_path, tc_id, t0, params)
    except Exception as exc:
        logger.warning(
            "Volatility Python API context build failed (%s); "
            "falling back to subprocess execution",
            exc,
        )
        return _run_batch_subprocess_fallback(plugins, memory_path, tc_id, t0, params)

    timeout = adaptive_timeout(memory_path, base=_PLUGIN_TIMEOUT)
    logger.info(
        "Volatility batch: context built for %r, running %d plugins (timeout=%ds)",
        memory_path,
        len(plugins),
        timeout,
    )

    results: dict[str, dict[str, object]] = {}
    for plugin_name in plugins:
        full_name = _resolve_plugin_name(plugin_name)
        short = _plugin_short_name(full_name)

        plugin_class = plugin_list.get(full_name)
        if plugin_class is None:
            results[plugin_name] = {
                "plugin": full_name,
                "status": "error",
                "error_type": "unknown_plugin",
                "source_name": f"volatility.{short}",
                "error_message": f"Plugin '{full_name}' not found in Volatility 3",
            }
            continue

        try:
            results[plugin_name] = _run_batch_plugin_timed(
                ctx, automagics, plugin_class, full_name, memory_path, timeout
            )
        except Exception as exc:
            err_msg = str(exc)[:300]
            is_netscan = short == "netscan"

            if is_netscan and any(
                kw in err_msg.lower() for kw in ("unsupported", "not valid", "unable to validate")
            ):
                fallback = _run_netscan_fallback_batch(
                    ctx, automagics, memory_path, plugin_list, full_name
                )
                if fallback:
                    results[plugin_name] = fallback
                else:
                    results[plugin_name] = {
                        "plugin": full_name,
                        "status": "error",
                        "error_type": "plugin_unsupported",
                        "source_name": f"volatility.{short}",
                        "error_message": err_msg,
                    }
            else:
                results[plugin_name] = {
                    "plugin": full_name,
                    "status": "error",
                    "error_type": "exception",
                    "source_name": f"volatility.{short}",
                    "error_message": err_msg,
                }

        logger.info(
            "Volatility batch: %s -> %s",
            short,
            results.get(plugin_name, {}).get("status", "?"),
        )

    return _aggregate_batch_results(results, plugins, tc_id, params, t0)
