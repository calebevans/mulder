"""Volatility 3 memory analysis MCP tools."""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from mulder.extractors.volatility import _find_vol_binary, _plugin_short_name
from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import error_response, make_tool_call_id, tool_response

__all__ = [
    "run_volatility",
    "run_volatility_batch",
]

logger = logging.getLogger(__name__)

_PLUGIN_TIMEOUT = 600
_TOOL_TIMEOUT = 600

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


def _require_binary(name: str) -> str | None:
    """Return the binary path if found, else None."""
    return shutil.which(name)


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


def _run_single_vol_plugin(vol_cmd: list[str], memory_path: str, plugin: str) -> dict[str, object]:
    """Run one Volatility plugin, index the output, return summary.

    For netscan (Vista+), automatically falls back to connscan / sockscan
    when the plugin fails, which covers Windows XP memory images.
    """
    short = _plugin_short_name(plugin)
    cmd = [*vol_cmd, "-f", memory_path, plugin]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_PLUGIN_TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired:
        return {
            "plugin": plugin,
            "status": "error",
            "error_type": "timeout",
            "source_name": f"volatility.{short}",
            "error_message": f"{plugin} timed out after {_PLUGIN_TIMEOUT}s",
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
                        timeout=_PLUGIN_TIMEOUT,
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
    summary = extract_and_index(
        raw_output=output,
        source_name=f"volatility.{short}",
        source_path=memory_path,
        extractor_name="volatility3",
    )
    summary["plugin"] = plugin
    return summary


@mcp.tool()
def run_volatility(plugin: str, memory_path: str) -> dict[str, object]:
    """Run a single Volatility 3 plugin against a memory dump.

    Runs the specified plugin (e.g. "windows.pslist.PsList" or just
    "pslist"), indexes the output into the case database, and returns
    a summary.  The output becomes searchable via query tools.

    Common plugins: pslist, pstree, cmdline, netscan, malfind, dlllist,
    svcscan, handles, psscan, envars, filescan, modules, modscan, vadinfo.

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

    result = _run_single_vol_plugin(vol_cmd, memory_path, plugin)
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
            elif hasattr(val, "lookup"):
                row.append(str(val))
            else:
                row.append(str(val))
        accumulator.append("\t".join(row))
        return accumulator

    treegrid.populate(_visitor, lines)
    return "\n".join(lines)


@mcp.tool()
def run_volatility_batch(
    plugins: list[str],
    memory_path: str,
) -> dict[str, object]:
    """Run multiple Volatility 3 plugins against a memory dump in one call.

    Builds the Volatility context ONCE (parsing the memory image, loading
    symbols, running automagic) and then executes each plugin against the
    shared context.  This is significantly faster than calling
    ``run_volatility`` separately for each plugin, since context setup
    takes 10-20 seconds and is only done once.

    Each plugin's output is indexed separately.  Failed plugins are
    reported individually without stopping the batch.

    For netscan, automatically falls back to connscan/sockscan if the
    plugin is unsupported (e.g. Windows XP memory images).

    Args:
        plugins: List of plugin names (short or full form), e.g.
            ``["pslist", "pstree", "cmdline", "netscan", "malfind",
            "psscan", "dlllist", "svcscan"]``.
        memory_path: Path to the memory dump file.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"plugins": plugins, "memory_path": memory_path}

    if not Path(memory_path).exists():
        return error_response(
            tc_id,
            "run_volatility_batch",
            params,
            f"File not found: {memory_path}",
            error_type="file_not_found",
        )

    try:
        import volatility3.framework
        import volatility3.plugins
        from volatility3.framework import automagic, contexts
        from volatility3.framework import plugins as vol_plugins
        from volatility3.framework.configuration import (
            requirements as vol_reqs,
        )
    except ImportError as exc:
        return error_response(
            tc_id,
            "run_volatility_batch",
            params,
            f"Volatility 3 Python library not available: {exc}",
            error_type="binary_missing",
        )

    ctx = contexts.Context()
    volatility3.framework.import_files(volatility3.plugins, True)
    automagics = automagic.available(ctx)
    plugin_list = volatility3.framework.list_plugins()

    file_path = Path(memory_path).resolve()
    single_location = vol_reqs.URIRequirement.location_from_file(str(file_path))
    ctx.config["automagic.LayerStacker.single_location"] = single_location

    logger.info(
        "Volatility batch: context built for %r, running %d plugins",
        memory_path,
        len(plugins),
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
            base_path = f"plugins.batch.{short}"
            constructed = vol_plugins.construct_plugin(
                ctx,
                automagics,
                plugin_class,
                base_path,
                None,
                None,
            )
            treegrid = constructed.run()
            output = _render_treegrid_to_text(treegrid)

            if output.strip():
                summary = extract_and_index(
                    raw_output=output,
                    source_name=f"volatility.{short}",
                    source_path=memory_path,
                    extractor_name="volatility3",
                )
                summary["plugin"] = full_name
                results[plugin_name] = summary
            else:
                results[plugin_name] = {
                    "plugin": full_name,
                    "status": "empty",
                    "source_name": f"volatility.{short}",
                    "error_message": "Plugin produced no output",
                }
        except Exception as exc:
            err_msg = str(exc)[:300]
            is_netscan = short == "netscan"

            if is_netscan and any(
                kw in err_msg.lower() for kw in ("unsupported", "not valid", "unable to validate")
            ):
                for fb_name in ("connscan", "sockscan"):
                    fb_full = _resolve_plugin_name(fb_name)
                    fb_class = plugin_list.get(fb_full)
                    if fb_class is None:
                        continue
                    try:
                        fb_path = f"plugins.batch.{fb_name}"
                        fb_constructed = vol_plugins.construct_plugin(
                            ctx,
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
                            fb_summary["original_plugin"] = full_name
                            results[plugin_name] = fb_summary
                            break
                    except Exception:
                        logger.debug("Fallback %s failed", fb_name, exc_info=True)
                        continue
                if plugin_name not in results:
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
            "Volatility batch: %s -> %s", short, results.get(plugin_name, {}).get("status", "?")
        )

    succeeded = sum(1 for r in results.values() if r.get("status") not in ("error", "empty"))
    failed = len(results) - succeeded

    total_windows = 0
    total_lines = 0
    for r in results.values():
        wi = r.get("windows_indexed", 0)
        lc = r.get("line_count", 0)
        total_windows += wi if isinstance(wi, int) else 0
        total_lines += lc if isinstance(lc, int) else 0
        r.pop("source_id", None)
        r.pop("source_name", None)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_volatility_batch",
        params,
        {
            "plugins_requested": len(plugins),
            "plugins_succeeded": succeeded,
            "plugins_failed": failed,
            "total_windows_indexed": total_windows,
            "total_lines": total_lines,
            "per_plugin": results,
        },
        "volatility.batch",
        elapsed,
    )
