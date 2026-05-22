"""Tier 2 on-demand extraction MCP tools.

Each tool runs a specific forensic CLI tool against a specific evidence
file, indexes the output into the case database via ``extract_and_index``,
and returns a summary.  The agent decides which to run and in what order.

Evidence integrity is enforced by the API design: all tools operate
read-only on evidence and only write to the case database.
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index, mount_disk_image
from mulder.server.helpers import error_response, make_tool_call_id, tool_response

logger = logging.getLogger(__name__)

_PLUGIN_TIMEOUT = 600
_PLASO_TIMEOUT = 3600
_BULK_TIMEOUT = 1800
_TOOL_TIMEOUT = 600


def _require_binary(name: str) -> str | None:
    """Return the binary path if found, else None."""
    return shutil.which(name)


def _find_vol_binary() -> list[str]:
    """Locate the Volatility 3 CLI binary."""
    for name in ("vol", "vol3"):
        if shutil.which(name):
            return [name]
    try:
        subprocess.run(
            ["python3", "-m", "volatility3", "--help"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        return ["python3", "-m", "volatility3"]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    raise RuntimeError("Volatility 3 not found on PATH")


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


def _plugin_short_name(full_name: str) -> str:
    """Extract the short name (e.g. 'pslist') from a dotted plugin path."""
    parts = full_name.split(".")
    return parts[-2] if len(parts) >= 2 else parts[-1].lower()


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
        "Volatility batch: context built for %s, running %d plugins",
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


def _detect_partition_offset(image_path: str) -> int:
    """Run mmls to find the main partition offset (in sectors)."""
    if not _require_binary("mmls"):
        return 0
    try:
        proc = subprocess.run(
            ["mmls", image_path], capture_output=True, text=True, timeout=30, check=False
        )
        if proc.returncode != 0:
            return 0
    except (subprocess.TimeoutExpired, OSError):
        return 0

    ntfs_indicators = ("ntfs", "0x07", "win95 fat", "0x0b", "0x0c")
    linux_indicators = ("linux", "0x83", "ext", "0x8e")
    row_re = re.compile(r"^\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$", re.MULTILINE)
    rows = [
        (int(m.group(1)), int(m.group(2)), m.group(3).strip().lower())
        for m in row_re.finditer(proc.stdout)
    ]
    if not rows:
        return 0

    for start, length, desc in rows:
        if any(ind in desc for ind in ntfs_indicators) and length > 0:
            return start
    for start, length, desc in rows:
        if any(ind in desc for ind in linux_indicators) and length > 0:
            return start
    biggest = max(rows, key=lambda t: t[1])
    return biggest[0] if biggest[1] > 0 else 0


@mcp.tool()
def run_mmls(image_path: str) -> dict[str, object]:
    """List partitions in a disk image using TSK mmls.

    Shows partition layout including type, start sector, and size.
    Indexes the output for later reference.

    Args:
        image_path: Path to the disk image (E01, dd, img).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not _require_binary("mmls"):
        return error_response(
            tc_id, "run_mmls", params, "mmls not found on PATH", error_type="binary_missing"
        )

    try:
        proc = subprocess.run(
            ["mmls", image_path], capture_output=True, text=True, timeout=60, check=False
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_mmls", params, "mmls timed out", error_type="timeout")

    if proc.returncode != 0:
        return error_response(
            tc_id,
            "run_mmls",
            params,
            f"mmls exited {proc.returncode}: {(proc.stderr or '')[:300]}",
        )

    summary = extract_and_index(proc.stdout.strip(), "tsk.partitions", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_mmls", params, summary, "tsk.partitions", elapsed)


@mcp.tool()
def run_fls(image_path: str, partition_offset: int | None = None) -> dict[str, object]:
    """Run recursive file listing on a disk image using TSK fls.

    Lists all files and directories (including deleted entries marked
    with ``*``).  Indexes the output for searching and deleted file
    detection.

    Args:
        image_path: Path to the disk image.
        partition_offset: Sector offset of the partition.  Auto-detected
            via mmls if omitted.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "partition_offset": partition_offset}

    if not _require_binary("fls"):
        return error_response(
            tc_id, "run_fls", params, "fls not found on PATH", error_type="binary_missing"
        )

    if partition_offset is None:
        partition_offset = _detect_partition_offset(image_path)

    cmd = ["fls", "-r", "-p"]
    if partition_offset > 0:
        cmd.extend(["-o", str(partition_offset)])
    cmd.append(image_path)

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=_TOOL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_fls", params, "fls timed out", error_type="timeout")

    stdout_text = proc.stdout.decode("utf-8", errors="replace")
    stderr_text = (proc.stderr or b"").decode("utf-8", errors="replace")

    if proc.returncode != 0:
        stderr_hint = stderr_text[:200].strip()
        return error_response(
            tc_id,
            "run_fls",
            params,
            f"fls exited {proc.returncode} (tried partition_offset={partition_offset}). "
            f"Run run_mmls first to find the correct NTFS partition offset, then retry "
            f"run_fls with that offset. stderr: {stderr_hint}",
            error_type="extraction_failed",
        )

    summary = extract_and_index(stdout_text.strip(), "tsk.filelist", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_fls", params, summary, "tsk.filelist", elapsed)


@mcp.tool()
def run_mactime(image_path: str, time_range: str | None = None) -> dict[str, object]:
    """Generate a MAC timeline from a disk image using TSK fls + mactime.

    Creates a filesystem timeline showing file creation, modification,
    access, and change times.  Optionally filter to a date range.

    Args:
        image_path: Path to the disk image.
        time_range: Optional date range filter for mactime (e.g.
            "2015-08-01..2015-08-05").
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "time_range": time_range}

    for binary in ("fls", "mactime"):
        if not _require_binary(binary):
            return error_response(tc_id, "run_mactime", params, f"{binary} not found on PATH")

    offset = _detect_partition_offset(image_path)
    fls_cmd = ["fls", "-r", "-m", "/"]
    if offset > 0:
        fls_cmd.extend(["-o", str(offset)])
    fls_cmd.append(image_path)

    try:
        fls_proc = subprocess.run(
            fls_cmd, capture_output=True, text=True, timeout=_TOOL_TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_mactime", params, "fls timed out")

    if not fls_proc.stdout.strip():
        return error_response(tc_id, "run_mactime", params, "fls produced no bodyfile output")

    mac_cmd = ["mactime", "-b", "-", "-d"]
    if time_range:
        mac_cmd.extend(time_range.split(".."))

    try:
        mac_proc = subprocess.run(
            mac_cmd,
            input=fls_proc.stdout,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_mactime", params, "mactime timed out")

    summary = extract_and_index(mac_proc.stdout.strip(), "tsk.timeline", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_mactime", params, summary, "tsk.timeline", elapsed)


@mcp.tool()
def run_fsstat(image_path: str) -> dict[str, object]:
    """Get filesystem statistics from a disk image using TSK fsstat.

    Shows filesystem type, block size, volume label, and other metadata.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not _require_binary("fsstat"):
        return error_response(tc_id, "run_fsstat", params, "fsstat not found on PATH")

    offset = _detect_partition_offset(image_path)
    cmd = ["fsstat"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_fsstat", params, "fsstat timed out")

    summary = extract_and_index(proc.stdout.strip(), "tsk.fsstat", image_path, "sleuthkit")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_fsstat", params, summary, "tsk.fsstat", elapsed)


def _find_plaso_cmd(tool: str) -> list[str] | None:
    """Locate a Plaso CLI tool, trying multiple install conventions.

    pip-installed plaso may use ``log2timeline.py``, ``log2timeline``,
    or only be reachable via ``python3 -m plaso.cli.<tool>``.
    """
    module_map = {
        "log2timeline": "plaso.cli.log2timeline",
        "psort": "plaso.cli.psort",
        "pinfo": "plaso.cli.pinfo",
    }
    base = tool.removesuffix(".py")
    for name in (f"{base}.py", base):
        path = shutil.which(name)
        if path:
            return [path]
    mod = module_map.get(base)
    if mod:
        py = shutil.which("python3") or shutil.which("python")
        if py:
            try:
                subprocess.run(
                    [py, "-m", mod, "--version"],
                    capture_output=True,
                    timeout=10,
                    check=True,
                )
                return [py, "-m", mod]
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                pass
    return None


@mcp.tool()
def run_plaso(
    evidence_path: str,
    parsers: str | None = None,
    time_range: str | None = None,
) -> dict[str, object]:
    """Run log2timeline (Plaso) against an evidence file to build a super-timeline.

    This is the most expensive extraction tool.  Use targeted parsers and
    time ranges when possible to reduce runtime.

    Args:
        evidence_path: Path to a disk image or directory.
        parsers: Comma-separated list of Plaso parsers to run (e.g.
            "winevtx,prefetch,pe").  Runs all parsers if omitted.
        time_range: Date filter passed to psort (e.g. "2015-08-01").
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"evidence_path": evidence_path, "parsers": parsers, "time_range": time_range}

    l2t_cmd_prefix = _find_plaso_cmd("log2timeline")
    if not l2t_cmd_prefix:
        return error_response(
            tc_id,
            "run_plaso",
            params,
            (
                "log2timeline not found (tried log2timeline.py, log2timeline, "
                "python3 -m plaso.cli.log2timeline)"
            ),
            error_type="binary_missing",
        )

    cfg = get_cfg()
    ctx = get_ctx()

    with tempfile.TemporaryDirectory(prefix="mulder_plaso_") as tmpdir:
        plaso_file = Path(tmpdir) / "timeline.plaso"

        l2t_cmd = [*l2t_cmd_prefix, "--status_view", "none"]
        if parsers:
            l2t_cmd.extend(["--parsers", parsers])
        l2t_cmd.extend([str(plaso_file), evidence_path])

        try:
            proc = subprocess.run(
                l2t_cmd, capture_output=True, text=True, timeout=_PLASO_TIMEOUT, check=False
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id, "run_plaso", params, f"log2timeline timed out after {_PLASO_TIMEOUT}s"
            )

        if proc.returncode != 0 and not plaso_file.exists():
            stderr = (proc.stderr or "")[:500]
            return error_response(tc_id, "run_plaso", params, f"log2timeline failed: {stderr}")

        persistent_plaso = cfg.db_dir / f"{ctx.case_id}.plaso"
        with contextlib.suppress(OSError):
            shutil.copy2(str(plaso_file), str(persistent_plaso))

        psort_prefix = _find_plaso_cmd("psort") or ["psort.py"]
        psort_cmd = [*psort_prefix, "-o", "l2tcsv"]
        if time_range:
            psort_cmd.extend([str(plaso_file), f"date > '{time_range}'"])
        else:
            psort_cmd.append(str(plaso_file))

        try:
            psort_proc = subprocess.run(
                psort_cmd, capture_output=True, text=True, timeout=_PLASO_TIMEOUT, check=False
            )
        except subprocess.TimeoutExpired:
            return error_response(tc_id, "run_plaso", params, "psort timed out")

        timeline_text = psort_proc.stdout.strip()

        stats_text = ""
        pinfo_prefix = _find_plaso_cmd("pinfo")
        if pinfo_prefix:
            try:
                stats_proc = subprocess.run(
                    [*pinfo_prefix, "-v", str(plaso_file)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                stats_text = stats_proc.stdout.strip()
            except (subprocess.TimeoutExpired, OSError):
                pass

    results: list[object] = []
    if timeline_text:
        results.append(extract_and_index(timeline_text, "plaso.timeline", evidence_path, "plaso"))
    if stats_text:
        results.append(
            extract_and_index(
                stats_text,
                "plaso.stats",
                str(persistent_plaso) if persistent_plaso.exists() else evidence_path,
                "plaso",
            )
        )

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_plaso", params, results, "plaso.timeline", elapsed)


_EZ_TOOLS_DIR = Path("/opt/zimmermantools")
_DOTNET = "dotnet"


def _find_ez_tool(dll_name: str) -> str | None:
    """Find an EZ tool DLL under /opt/zimmermantools."""
    candidates = list(_EZ_TOOLS_DIR.rglob(dll_name))
    return str(candidates[0]) if candidates else None


def _run_ez_tool(
    dll_name: str,
    args: list[str],
    source_name: str,
    source_path: str,
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    t0: float,
) -> dict[str, object]:
    """Run an EZ tool, parse CSV output, index it, and return response."""
    if not _require_binary(_DOTNET):
        return error_response(
            tc_id, tool_name, params, "dotnet not found on PATH", (time.monotonic() - t0) * 1000
        )

    dll = _find_ez_tool(dll_name)
    if dll is None:
        return error_response(
            tc_id,
            tool_name,
            params,
            f"{dll_name} not found under {_EZ_TOOLS_DIR}",
            (time.monotonic() - t0) * 1000,
        )

    with tempfile.TemporaryDirectory(prefix="mulder_ez_") as tmpdir:
        cmd = [_DOTNET, dll, *args, "--csv", tmpdir]

        try:
            subprocess.run(
                cmd, capture_output=True, text=True, timeout=_TOOL_TIMEOUT * 2, check=False
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id, tool_name, params, f"{dll_name} timed out", (time.monotonic() - t0) * 1000
            )

        csv_files = list(Path(tmpdir).glob("*.csv"))
        if not csv_files:
            return error_response(
                tc_id,
                tool_name,
                params,
                f"{dll_name} produced no CSV output",
                (time.monotonic() - t0) * 1000,
            )

        combined_text = ""
        for csv_file in sorted(csv_files):
            with contextlib.suppress(OSError):
                combined_text += csv_file.read_text(encoding="utf-8", errors="replace")

    summary = extract_and_index(combined_text, source_name, source_path, "eztools")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, tool_name, params, summary, source_name, elapsed)


_tsk_extract_dirs: list[str] = []


def _tsk_extract_files(
    image_path: str,
    path_patterns: list[str],
) -> list[tuple[str, Path]]:
    """Extract files from a disk image via TSK fls + icat as a fallback
    when ``mount_disk_image`` fails.

    Searches the pre-indexed ``tsk.filelist`` for entries matching any of
    the *path_patterns* (case-insensitive substring match), then extracts
    each via ``icat`` to a temp directory.

    Returns a list of ``(relative_path, extracted_path)`` tuples.
    """
    from mulder.server.app import get_ctx

    ctx = get_ctx()
    sources = ctx.db.get_sources()
    fls_source = next((s for s in sources if s.source_name == "tsk.filelist"), None)
    if fls_source is None:
        return []

    windows = ctx.db.get_windows_by_source("tsk.filelist")
    part_src = next((s for s in sources if s.source_name == "tsk.partitions"), None)
    offset = 0
    if part_src:
        part_windows = ctx.db.get_windows_by_source("tsk.partitions")
        mmls_text = "\n".join(w.raw_text for w in part_windows)
        offset = _parse_partition_offset(mmls_text)

    inode_re = re.compile(
        r"^[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.+)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )

    extract_dir = Path(tempfile.mkdtemp(prefix="mulder_tsk_extract_"))
    _tsk_extract_dirs.append(str(extract_dir))
    extracted: list[tuple[str, Path]] = []
    seen: set[str] = set()

    for w in windows:
        for m in inode_re.finditer(w.raw_text):
            inode_str = m.group(1).split("-")[0]
            rel_path = m.group(2).strip()
            rel_lower = rel_path.lower().replace("\\", "/")

            if not any(pat.lower() in rel_lower for pat in path_patterns):
                continue
            if inode_str in seen:
                continue
            seen.add(inode_str)

            safe_name = rel_path.replace("/", "_").replace("\\", "_")
            out_path = extract_dir / safe_name
            cmd = ["icat"]
            if offset > 0:
                cmd.extend(["-o", str(offset)])
            cmd.extend([image_path, inode_str])
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout:
                    out_path.write_bytes(proc.stdout)
                    extracted.append((rel_path, out_path))
            except (subprocess.TimeoutExpired, OSError):
                continue

    return extracted


@mcp.tool()
def run_prefetch_parser(image_path: str) -> dict[str, object]:
    """Parse Windows Prefetch files from a disk image using PECmd (EZ Tools).

    Mounts the disk image, locates Prefetch files, parses them for
    execution history, and indexes the results.  Falls back to TSK
    extraction when mounting fails.

    Args:
        image_path: Path to the disk image (E01, dd, img).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    try:
        with mount_disk_image(image_path) as mount_point:
            prefetch_dir = None
            for candidate in (
                Path(mount_point) / "Windows" / "Prefetch",
                Path(mount_point) / "windows" / "prefetch",
            ):
                if candidate.is_dir():
                    prefetch_dir = str(candidate)
                    break
            if prefetch_dir is None:
                return error_response(
                    tc_id, "run_prefetch_parser", params, "No Prefetch directory found"
                )
            return _run_ez_tool(
                "PECmd.dll",
                ["-d", prefetch_dir],
                "ez.prefetch",
                image_path,
                tc_id,
                "run_prefetch_parser",
                params,
                t0,
            )
    except RuntimeError:
        pass

    extracted = _tsk_extract_files(image_path, ["Prefetch/", ".pf"])
    if not extracted:
        return error_response(
            tc_id,
            "run_prefetch_parser",
            params,
            "Mount failed and no Prefetch files found via TSK extraction",
            (time.monotonic() - t0) * 1000,
        )
    pf_dir = extracted[0][1].parent
    return _run_ez_tool(
        "PECmd.dll",
        ["-d", str(pf_dir)],
        "ez.prefetch",
        image_path,
        tc_id,
        "run_prefetch_parser",
        params,
        t0,
    )


@mcp.tool()
def run_amcache_parser(image_path: str) -> dict[str, object]:
    """Parse Amcache from a disk image using AmcacheParser (EZ Tools).

    Shows program execution history with SHA1 hashes, file paths, and
    timestamps.  Falls back to TSK extraction when mounting fails.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    try:
        with mount_disk_image(image_path) as mount_point:
            amcache_path = None
            for candidate in (
                Path(mount_point) / "Windows" / "appcompat" / "Programs" / "Amcache.hve",
                Path(mount_point) / "windows" / "appcompat" / "programs" / "Amcache.hve",
            ):
                if candidate.exists():
                    amcache_path = str(candidate)
                    break
            if amcache_path is None:
                return error_response(tc_id, "run_amcache_parser", params, "Amcache.hve not found")
            return _run_ez_tool(
                "AmcacheParser.dll",
                ["-f", amcache_path],
                "ez.amcache",
                image_path,
                tc_id,
                "run_amcache_parser",
                params,
                t0,
            )
    except RuntimeError:
        pass

    extracted = _tsk_extract_files(image_path, ["Amcache.hve"])
    if not extracted:
        return error_response(
            tc_id,
            "run_amcache_parser",
            params,
            "Mount failed and Amcache.hve not found via TSK extraction",
            (time.monotonic() - t0) * 1000,
        )
    return _run_ez_tool(
        "AmcacheParser.dll",
        ["-f", str(extracted[0][1])],
        "ez.amcache",
        image_path,
        tc_id,
        "run_amcache_parser",
        params,
        t0,
    )


@mcp.tool()
def run_shimcache_parser(image_path: str) -> dict[str, object]:
    """Parse ShimCache (AppCompatCache) from a disk image using AppCompatCacheParser.

    Shows file existence evidence with timestamps.  Falls back to TSK
    extraction when mounting fails.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    try:
        with mount_disk_image(image_path) as mount_point:
            system_hive = None
            for candidate in (
                Path(mount_point) / "Windows" / "System32" / "config" / "SYSTEM",
                Path(mount_point) / "windows" / "system32" / "config" / "SYSTEM",
            ):
                if candidate.exists():
                    system_hive = str(candidate)
                    break
            if system_hive is None:
                return error_response(
                    tc_id, "run_shimcache_parser", params, "SYSTEM hive not found"
                )
            return _run_ez_tool(
                "AppCompatCacheParser.dll",
                ["-f", system_hive],
                "ez.shimcache",
                image_path,
                tc_id,
                "run_shimcache_parser",
                params,
                t0,
            )
    except RuntimeError:
        pass

    extracted = _tsk_extract_files(image_path, ["config/SYSTEM"])
    system_files = [
        (r, p)
        for r, p in extracted
        if p.name.upper() == "SYSTEM" or "config_system" in p.name.lower()
    ]
    if not system_files:
        return error_response(
            tc_id,
            "run_shimcache_parser",
            params,
            "Mount failed and SYSTEM hive not found via TSK extraction",
            (time.monotonic() - t0) * 1000,
        )
    return _run_ez_tool(
        "AppCompatCacheParser.dll",
        ["-f", str(system_files[0][1])],
        "ez.shimcache",
        image_path,
        tc_id,
        "run_shimcache_parser",
        params,
        t0,
    )


@mcp.tool()
def run_mft_parser(image_path: str) -> dict[str, object]:
    """Parse the $MFT from a disk image using MFTECmd (EZ Tools).

    The Master File Table contains timestamps, sizes, and parent
    directories for every file on an NTFS volume.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    try:
        with mount_disk_image(image_path) as mount_point:
            mft_path = None
            for candidate in (
                Path(mount_point) / "$MFT",
                Path(mount_point) / "Windows" / "$MFT",
            ):
                if candidate.exists():
                    mft_path = str(candidate)
                    break
            if mft_path is None:
                return error_response(
                    tc_id, "run_mft_parser", params, "$MFT not found on mounted image"
                )
            return _run_ez_tool(
                "MFTECmd.dll",
                ["-f", mft_path],
                "ez.mft",
                image_path,
                tc_id,
                "run_mft_parser",
                params,
                t0,
            )
    except RuntimeError as exc:
        return error_response(
            tc_id, "run_mft_parser", params, str(exc), (time.monotonic() - t0) * 1000
        )


def _extract_evtx_from_image(image_path: str, dest_dir: str) -> list[Path]:
    """Extract .evtx files from a disk image to *dest_dir* using TSK icat.

    Uses the fls listing already indexed for the case to locate EVTX
    inodes, then extracts each with icat.  Works on E01 and raw images
    without mounting.
    """
    from mulder.server.app import get_ctx

    ctx = get_ctx()
    sources = ctx.db.get_sources()
    fls_source = next((s for s in sources if s.source_name == "tsk.filelist"), None)
    if fls_source is None:
        return []

    windows = ctx.db.get_windows_by_source("tsk.filelist")
    evtx_re = re.compile(
        r"^[rd]/[rd*]\s+(\d+(?:-\d+-\d+)?):\s+(.+\.evtx)\s*$", re.IGNORECASE | re.MULTILINE
    )

    part_src = next((s for s in sources if s.source_name == "tsk.partitions"), None)
    offset = 0
    if part_src:
        part_windows = ctx.db.get_windows_by_source("tsk.partitions")
        mmls_text = "\n".join(w.raw_text for w in part_windows)
        offset = _parse_partition_offset(mmls_text)

    extracted: list[Path] = []
    seen_inodes: set[str] = set()
    for w in windows:
        for m in evtx_re.finditer(w.raw_text):
            inode_str = m.group(1).split("-")[0]
            if inode_str in seen_inodes:
                continue
            seen_inodes.add(inode_str)
            rel_path = m.group(2).strip()
            safe_name = rel_path.replace("/", "_").replace("\\", "_")
            out_path = Path(dest_dir) / safe_name
            cmd = ["icat"]
            if offset > 0:
                cmd.extend(["-o", str(offset)])
            cmd.extend([image_path, inode_str])
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
                if proc.returncode == 0 and proc.stdout:
                    out_path.write_bytes(proc.stdout)
                    extracted.append(out_path)
            except (subprocess.TimeoutExpired, OSError):
                continue
    return extracted


def _parse_partition_offset(mmls_text: str) -> int:
    """Parse the NTFS partition offset from mmls output."""
    row_re = re.compile(r"^\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$", re.MULTILINE)
    for m in row_re.finditer(mmls_text):
        start, length, desc = int(m.group(1)), int(m.group(2)), m.group(3).strip().lower()
        if any(ind in desc for ind in ("ntfs", "0x07", "win95 fat")) and length > 0:
            return start
    return 0


_evtx_extract_dirs: dict[str, str] = {}


def _cleanup_temp_dirs() -> None:
    """Remove all extraction temp directories."""
    for path in _evtx_extract_dirs.values():
        shutil.rmtree(path, ignore_errors=True)
    _evtx_extract_dirs.clear()
    for path in _tsk_extract_dirs:
        shutil.rmtree(path, ignore_errors=True)
    _tsk_extract_dirs.clear()


atexit.register(_cleanup_temp_dirs)


def _find_carved_evtx(dest_dir: str) -> list[Path]:
    """Scan bulk_extractor output for carved .evtx files as a fallback.

    When the TSK path (fls + icat) fails, bulk_extractor may have
    carved EVTX fragments.  This checks the case DB for bulk_extractor
    output paths and copies any .evtx files to *dest_dir*.
    """
    from mulder.server.app import get_cfg, get_ctx

    ctx = get_ctx()
    cfg = get_cfg()
    found: list[Path] = []
    search_dirs: list[Path] = []

    sources = ctx.db.get_sources()
    for s in sources:
        if s.source_name.startswith("bulk."):
            src_path = Path(s.source_path)
            if src_path.is_dir():
                search_dirs.append(src_path)
            elif src_path.parent.is_dir():
                search_dirs.append(src_path.parent)

    if cfg.db_dir.is_dir():
        search_dirs.append(cfg.db_dir)

    seen: set[str] = set()
    for d in search_dirs:
        for evtx in d.rglob("*.evtx"):
            if evtx.name in seen:
                continue
            seen.add(evtx.name)
            dest = Path(dest_dir) / evtx.name
            try:
                shutil.copy2(str(evtx), str(dest))
                found.append(dest)
            except OSError:
                continue
    return found


@mcp.tool()
def run_evtx_parser(evtx_path: str) -> dict[str, object]:
    """Extract and list Windows Event Log (.evtx) files from a disk image.

    When given a disk image (E01/raw), extracts ALL .evtx files to a
    persistent temp directory and returns a manifest with file names and
    sizes. Does NOT parse or index them -- use ``index_evtx_file`` to
    selectively parse the most relevant logs.

    When given a directory or single .evtx file, parses it immediately.

    Recommended workflow for disk images:
    1. Call ``run_evtx_parser("<image_path>")`` to extract and list files
    2. Review the manifest -- start with Security.evtx, System.evtx,
       PowerShell.evtx, Sysmon.evtx
    3. Call ``index_evtx_file("<filename>")`` on each relevant log
    4. Only index archived/rotated logs if you need historical data

    Args:
        evtx_path: Path to an EVTX file, directory, or disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"evtx_path": evtx_path}

    target = Path(evtx_path)
    if not target.exists():
        return error_response(tc_id, "run_evtx_parser", params, f"Path not found: {evtx_path}")

    is_image = target.suffix.lower() in (".e01", ".dd", ".img", ".raw", ".001")

    if is_image:
        extract_dir = tempfile.mkdtemp(prefix="mulder_evtx_extract_")
        _evtx_extract_dirs[evtx_path] = extract_dir
        evtx_files = _extract_evtx_from_image(evtx_path, extract_dir)
        if not evtx_files:
            evtx_files = _find_carved_evtx(extract_dir)
        if not evtx_files:
            return error_response(
                tc_id,
                "run_evtx_parser",
                params,
                "No EVTX files found in disk image. "
                "Ensure run_fls has been called first, or run run_bulk_extractor "
                "which can carve EVTX fragments even when fls fails.",
            )

        manifest: list[dict[str, object]] = []
        for ef in sorted(evtx_files, key=lambda p: p.stat().st_size, reverse=True):
            size = ef.stat().st_size
            name = ef.name
            priority = (
                "HIGH"
                if any(
                    k in name.lower()
                    for k in (
                        "security.evtx",
                        "system.evtx",
                        "powershell",
                        "sysmon",
                        "taskscheduler",
                        "winrm",
                        "rdp",
                    )
                )
                else "MEDIUM"
                if size > 1_000_000
                else "LOW"
            )
            manifest.append(
                {
                    "filename": name,
                    "size_bytes": size,
                    "size_human": f"{size / 1_048_576:.1f} MB"
                    if size > 1_048_576
                    else f"{size / 1024:.0f} KB",
                    "priority": priority,
                }
            )

        high_count = sum(1 for m in manifest if m["priority"] == "HIGH")
        total_size: int = sum(cast(int, m["size_bytes"]) for m in manifest)

        result = {
            "extract_dir": extract_dir,
            "total_files": len(manifest),
            "total_size_human": f"{total_size / 1_073_741_824:.1f} GB"
            if total_size > 1_073_741_824
            else f"{total_size / 1_048_576:.0f} MB",
            "high_priority_count": high_count,
            "manifest": manifest,
            "hint": (
                f"Extracted {len(manifest)} EVTX files ({total_size / 1_048_576:.0f} MB total). "
                f"{high_count} are HIGH priority. Use index_evtx_file(filename) to parse "
                f"specific logs. Start with Security, System, PowerShell, and Sysmon. "
                f"Only index archived logs (Archive-Security-*) if you need historical data."
            ),
        }

        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(tc_id, "run_evtx_parser", params, result, "evtx.manifest", elapsed)

    # Non-image path: parse directly (directory or single file)
    evtx_dir = evtx_path if target.is_dir() else None

    dll = _find_ez_tool("EvtxECmd.dll")
    if dll and _require_binary(_DOTNET):
        with tempfile.TemporaryDirectory(prefix="mulder_evtx_csv_") as csv_dir:
            if evtx_dir:
                cmd = [_DOTNET, dll, "-d", str(evtx_dir), "--csv", csv_dir]
            else:
                cmd = [_DOTNET, dll, "-f", str(target), "--csv", csv_dir]

            try:
                subprocess.run(
                    cmd, capture_output=True, text=True, timeout=_TOOL_TIMEOUT * 4, check=False
                )
            except subprocess.TimeoutExpired:
                return error_response(tc_id, "run_evtx_parser", params, "EvtxECmd timed out")

            combined = ""
            for csv_file in sorted(Path(csv_dir).glob("*.csv")):
                combined += csv_file.read_text(encoding="utf-8", errors="replace")

            if combined:
                summary = extract_and_index(combined, "ez.evtx", evtx_path, "eztools")
                elapsed = (time.monotonic() - t0) * 1000
                return tool_response(tc_id, "run_evtx_parser", params, summary, "ez.evtx", elapsed)

    try:
        from mulder.extractors.disk import _parse_evtx_file
    except ImportError:
        return error_response(tc_id, "run_evtx_parser", params, "No EVTX parser available")

    results: list[object] = []
    files = sorted(Path(evtx_dir).rglob("*.evtx")) if evtx_dir else [target]
    for ef in files:
        channel, text = _parse_evtx_file(ef)
        if text:
            summary = extract_and_index(text, f"evtx.{channel}", str(ef), "python-evtx")
            results.append(summary)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_evtx_parser", params, results, "evtx", elapsed)


@mcp.tool()
def index_evtx_file(
    filename: str,
    event_ids: list[int] | None = None,
    image_path: str = "",
) -> dict[str, object]:
    """Parse and index a specific EVTX file from a previous extraction.

    Call ``run_evtx_parser`` on a disk image first to extract all EVTX
    files. Then call this tool on specific files you want to analyze.
    The filename should match one from the manifest returned by
    ``run_evtx_parser``.

    Pass *event_ids* to extract only specific Event IDs.  This is
    **dramatically faster** on large logs -- a Security.evtx with 200k
    events takes minutes to parse fully but seconds when filtered to
    the 10-15 forensically relevant Event IDs.

    Recommended order:
    1. Security.evtx (logon events, account changes, privilege use)
    2. System.evtx (service installs, driver loads)
    3. Windows PowerShell.evtx (PowerShell commands)
    4. Sysmon logs (if present -- detailed process/network activity)
    5. WinRM, TaskScheduler, RDP logs (lateral movement)
    6. Archived logs only if you need to check a specific time window

    Args:
        filename: Name of the .evtx file to parse (from the manifest).
        event_ids: Optional list of Event IDs to extract.  When provided,
            only events matching these IDs are parsed and indexed.
            When omitted, all events are extracted.  Choose IDs based
            on the log type and what you're investigating.
        image_path: Disk image path passed to ``run_evtx_parser``.
            Required when multiple images have been extracted in the
            same session; omit for single-image cases.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"filename": filename, "event_ids": event_ids, "image_path": image_path}

    if image_path and image_path in _evtx_extract_dirs:
        extract_dir = _evtx_extract_dirs[image_path]
    elif _evtx_extract_dirs:
        extract_dir = next(reversed(_evtx_extract_dirs.values()))
    else:
        extract_dir = ""

    if not extract_dir or not Path(extract_dir).is_dir():
        return error_response(
            tc_id,
            "index_evtx_file",
            params,
            "No EVTX extraction directory found. Call run_evtx_parser on a disk image first.",
        )

    evtx_path = Path(extract_dir) / filename
    if not evtx_path.exists():
        candidates = sorted(Path(extract_dir).glob(f"*{filename}*"))
        if candidates:
            evtx_path = candidates[0]
        else:
            available = [f.name for f in sorted(Path(extract_dir).glob("*.evtx"))[:10]]
            return error_response(
                tc_id,
                "index_evtx_file",
                params,
                f"File not found: {filename}. Available files include: {', '.join(available)}",
            )

    dll = _find_ez_tool("EvtxECmd.dll")
    if dll and _require_binary(_DOTNET):
        with tempfile.TemporaryDirectory(prefix="mulder_evtx_csv_") as csv_dir:
            cmd = [_DOTNET, dll, "-f", str(evtx_path), "--csv", csv_dir]
            if event_ids:
                cmd.extend(["--inc", ",".join(str(eid) for eid in event_ids)])
            try:
                subprocess.run(
                    cmd, capture_output=True, text=True, timeout=_TOOL_TIMEOUT * 8, check=False
                )
            except subprocess.TimeoutExpired:
                return error_response(
                    tc_id, "index_evtx_file", params, f"EvtxECmd timed out on {filename}"
                )

            combined = ""
            for csv_file in sorted(Path(csv_dir).glob("*.csv")):
                combined += csv_file.read_text(encoding="utf-8", errors="replace")

            if combined:
                source_name = "evtx." + evtx_path.stem.lower().replace(" ", "-").replace("%", "")
                summary = extract_and_index(combined, source_name, str(evtx_path), "eztools")
                elapsed = (time.monotonic() - t0) * 1000
                return tool_response(
                    tc_id, "index_evtx_file", params, summary, source_name, elapsed
                )

    try:
        from mulder.extractors.disk import _parse_evtx_file
    except ImportError:
        return error_response(tc_id, "index_evtx_file", params, "No EVTX parser available")

    id_filter = set(event_ids) if event_ids else None
    channel, text = _parse_evtx_file(evtx_path, event_ids=id_filter)
    if text:
        summary = extract_and_index(text, f"evtx.{channel}", str(evtx_path), "python-evtx")
        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(tc_id, "index_evtx_file", params, summary, f"evtx.{channel}", elapsed)

    elapsed = (time.monotonic() - t0) * 1000
    return error_response(tc_id, "index_evtx_file", params, f"No events parsed from {filename}")


@mcp.tool()
def run_registry_parser(image_path: str, hive: str | None = None) -> dict[str, object]:
    """Parse Windows registry hives from a disk image.

    Uses RECmd (EZ Tools) when available, falls back to RegRipper.
    Parses all standard hives (SYSTEM, SOFTWARE, SAM, SECURITY,
    NTUSER.DAT) unless a specific hive is requested.

    Args:
        image_path: Path to the disk image.
        hive: Optional specific hive to parse (e.g. "SYSTEM", "SOFTWARE").
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "hive": hive}

    try:
        with mount_disk_image(image_path) as mount_point:
            config_dir = None
            for candidate in (
                Path(mount_point) / "Windows" / "System32" / "config",
                Path(mount_point) / "windows" / "system32" / "config",
            ):
                if candidate.is_dir():
                    config_dir = candidate
                    break

            if config_dir is None:
                return error_response(
                    tc_id, "run_registry_parser", params, "Registry config directory not found"
                )

            _HIVE_NAMES = {"system", "software", "sam", "security", "default"}
            hives_to_parse: list[tuple[str, Path]] = []
            for item in config_dir.iterdir():
                name_lower = item.name.lower()
                if hive and name_lower != hive.lower():
                    continue
                if name_lower in _HIVE_NAMES and item.is_file():
                    hives_to_parse.append((name_lower, item))

            if not hives_to_parse:
                return error_response(
                    tc_id, "run_registry_parser", params, "No registry hives found to parse"
                )

            results: list[object] = []
            for hive_name, hive_path in hives_to_parse:
                source_name = f"registry.{hive_name}"
                hive_status: str | None = None

                dll = _find_ez_tool("RECmd.dll")
                if dll and _require_binary(_DOTNET):
                    with tempfile.TemporaryDirectory(prefix="mulder_reg_") as tmpdir:
                        cmd = [_DOTNET, dll, "-f", str(hive_path), "--csv", tmpdir]
                        try:
                            proc = subprocess.run(
                                cmd,
                                capture_output=True,
                                text=True,
                                timeout=_TOOL_TIMEOUT,
                                check=False,
                            )
                        except subprocess.TimeoutExpired:
                            hive_status = "recmd_timeout"
                        else:
                            combined = ""
                            for csv_file in sorted(Path(tmpdir).glob("*.csv")):
                                combined += csv_file.read_text(encoding="utf-8", errors="replace")
                            if combined:
                                results.append(
                                    extract_and_index(combined, source_name, image_path, "eztools")
                                )
                                continue
                            stderr_hint = (proc.stderr or "")[:200].strip()
                            hive_status = (
                                f"recmd_empty_output ({stderr_hint})"
                                if stderr_hint
                                else "recmd_empty_output"
                            )

                rip = _require_binary("rip.pl") or _require_binary("regripper")
                if rip:
                    try:
                        proc = subprocess.run(
                            [rip, "-r", str(hive_path), "-a"],
                            capture_output=True,
                            text=True,
                            timeout=_TOOL_TIMEOUT,
                            check=False,
                        )
                        if proc.stdout.strip():
                            results.append(
                                extract_and_index(
                                    proc.stdout.strip(), source_name, image_path, "regripper"
                                )
                            )
                            continue
                        stderr_hint = (proc.stderr or "")[:200].strip()
                        hive_status = (
                            f"regripper_empty_output ({stderr_hint})"
                            if stderr_hint
                            else "regripper_empty_output"
                        )
                    except subprocess.TimeoutExpired:
                        hive_status = "regripper_timeout"
                    except OSError as exc:
                        hive_status = f"regripper_error ({exc})"
                elif hive_status is None:
                    has_recmd = bool(dll and _require_binary(_DOTNET))
                    hive_status = (
                        "no_parser_installed (neither RECmd nor RegRipper found on PATH)"
                        if not has_recmd
                        else "no_regripper_fallback (RECmd failed, RegRipper not on PATH)"
                    )

                results.append({"source_name": source_name, "status": hive_status})

            total_windows = sum(
                r.get("windows_indexed", 0) for r in results if isinstance(r, dict)
            )
            for r in results:
                if isinstance(r, dict):
                    r.pop("source_id", None)

            elapsed = (time.monotonic() - t0) * 1000
            return tool_response(
                tc_id,
                "run_registry_parser",
                params,
                {
                    "hives_parsed": len(results),
                    "total_windows_indexed": total_windows,
                    "per_hive": results,
                },
                "registry",
                elapsed,
            )
    except RuntimeError:
        pass

    _HIVE_NAMES = {"system", "software", "sam", "security", "default"}
    extracted = _tsk_extract_files(
        image_path,
        ["config/SYSTEM", "config/SOFTWARE", "config/SAM", "config/SECURITY", "config/DEFAULT"],
    )
    hives_to_parse = []
    for _rel, fpath in extracted:
        name_lower = fpath.name.lower()
        if name_lower not in _HIVE_NAMES:
            for h in _HIVE_NAMES:
                if h in fpath.name.lower():
                    name_lower = h
                    break
            else:
                continue
        if hive and name_lower != hive.lower():
            continue
        hives_to_parse.append((name_lower, fpath))

    if not hives_to_parse:
        return error_response(
            tc_id,
            "run_registry_parser",
            params,
            "Mount failed and no registry hives found via TSK extraction",
            (time.monotonic() - t0) * 1000,
        )

    results_fb: list[object] = []
    for hive_name, hive_path in hives_to_parse:
        source_name = f"registry.{hive_name}"
        fb_status: str | None = None

        dll = _find_ez_tool("RECmd.dll")
        if dll and _require_binary(_DOTNET):
            with tempfile.TemporaryDirectory(prefix="mulder_reg_") as tmpdir:
                cmd = [_DOTNET, dll, "-f", str(hive_path), "--csv", tmpdir]
                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=_TOOL_TIMEOUT, check=False
                    )
                except subprocess.TimeoutExpired:
                    fb_status = "recmd_timeout"
                else:
                    combined = ""
                    for csv_file in sorted(Path(tmpdir).glob("*.csv")):
                        combined += csv_file.read_text(encoding="utf-8", errors="replace")
                    if combined:
                        results_fb.append(
                            extract_and_index(combined, source_name, image_path, "eztools")
                        )
                        continue
                    stderr_hint = (proc.stderr or "")[:200].strip()
                    fb_status = (
                        f"recmd_empty_output ({stderr_hint})"
                        if stderr_hint
                        else "recmd_empty_output"
                    )

        rip = _require_binary("rip.pl") or _require_binary("regripper")
        if rip:
            try:
                proc = subprocess.run(
                    [rip, "-r", str(hive_path), "-a"],
                    capture_output=True,
                    text=True,
                    timeout=_TOOL_TIMEOUT,
                    check=False,
                )
                if proc.stdout.strip():
                    results_fb.append(
                        extract_and_index(
                            proc.stdout.strip(), source_name, image_path, "regripper"
                        )
                    )
                    continue
                stderr_hint = (proc.stderr or "")[:200].strip()
                fb_status = (
                    f"regripper_empty_output ({stderr_hint})"
                    if stderr_hint
                    else "regripper_empty_output"
                )
            except subprocess.TimeoutExpired:
                fb_status = "regripper_timeout"
            except OSError as exc:
                fb_status = f"regripper_error ({exc})"
        elif fb_status is None:
            has_recmd = bool(dll and _require_binary(_DOTNET))
            fb_status = (
                "no_parser_installed (neither RECmd nor RegRipper found on PATH)"
                if not has_recmd
                else "no_regripper_fallback (RECmd failed, RegRipper not on PATH)"
            )

        results_fb.append({"source_name": source_name, "status": fb_status})

    total_windows_fb = sum(r.get("windows_indexed", 0) for r in results_fb if isinstance(r, dict))
    for r in results_fb:
        if isinstance(r, dict):
            r.pop("source_id", None)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_registry_parser",
        params,
        {
            "hives_parsed": len(results_fb),
            "total_windows_indexed": total_windows_fb,
            "per_hive": results_fb,
        },
        "registry",
        elapsed,
    )


def _bulk_page_size() -> int:
    """Pick bulk_extractor page size based on available system memory.

    Allocates roughly 1/4 of available memory across threads (bulk_extractor
    needs ~2-3x page size per thread for decompression buffers).  Clamped
    between 16 MiB and 512 MiB, rounded down to a power of 2.  Adapts
    automatically to small containers and large servers.
    """
    _16M = 16 * 1024 * 1024
    avail = 0
    try:
        import psutil

        avail = psutil.virtual_memory().available
    except (ImportError, AttributeError):
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        avail = int(line.split()[1]) * 1024
                        break
        except OSError:
            pass
    if avail <= 0:
        return _16M
    ncpu = os.cpu_count() or 2
    per_thread = avail // (ncpu * 4)
    page = max(_16M, min(per_thread, 512 * 1024 * 1024))
    page = 1 << (page.bit_length() - 1)
    return page


@mcp.tool()
def run_bulk_extractor(
    image_path: str,
    features: list[str] | None = None,
    scanners: list[str] | None = None,
    max_depth: int | None = None,
) -> dict[str, object]:
    """Carve IOCs (URLs, emails, domains, IPs) from a disk image using bulk_extractor.

    Runs bulk_extractor and indexes each feature file as a separate
    source (bulk.email, bulk.url, bulk.domain, etc.).

    Pass *scanners* to run only specific bulk_extractor scanners,
    which is significantly faster than the default (all scanners).
    For IOC-focused investigations, ``scanners=["email", "net",
    "exif", "winpe", "winlnk", "httplogs"]`` skips expensive
    scanners like zip decompression and NTFS parsing.

    Available scanner names: accts, aes, base64, elf, email, evtx,
    exif, facebook, find, gps, gzip, httplogs, json, kml_carved,
    msxml, net, ntfsindx, ntfslogfile, ntfsmft, ntfsusn, pdf, rar,
    sqlite, utmp, vcard_carved, vin, windirs, winlnk, winpe,
    winprefetch, zip.

    NOTE: There is no "url" scanner. URLs are extracted by the
    "email" and "httplogs" scanners. IPs/domains come from "net".

    Args:
        image_path: Path to the disk image.
        features: Optional list of feature types to index from the
            output (e.g. ["email", "url"]).  Indexes all if omitted.
        scanners: Optional list of bulk_extractor scanner names to
            enable.  When provided, ONLY these scanners run (uses
            -E/-e flags).  When omitted, all scanners run.
        max_depth: Maximum recursion depth for decompressing nested
            archives (default: 12).  Use ``max_depth=2`` for a faster
            first-pass scan -- most forensic artifacts are at depth
            0-1.  Re-run with full depth on specific images if you
            suspect nested compressed content.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {
        "image_path": image_path,
        "features": features,
        "scanners": scanners,
        "max_depth": max_depth,
    }

    if not _require_binary("bulk_extractor"):
        return error_response(
            tc_id, "run_bulk_extractor", params, "bulk_extractor not found on PATH"
        )

    with tempfile.TemporaryDirectory(prefix="mulder_bulk_") as tmpdir:
        ncpu = os.cpu_count() or 2
        page_size = _bulk_page_size()
        cmd = ["bulk_extractor", "-j", str(ncpu), "-G", str(page_size), "-o", tmpdir]

        if max_depth is not None:
            cmd.extend(["-M", str(max_depth)])

        _SCANNER_ALIASES = {
            "url": "email",
            "domain": "net",
            "ip": "net",
            "http": "httplogs",
            "kml": "kml_carved",
            "vcard": "vcard_carved",
            "email_lg": "email",
            "accts_lg": "accts",
            "gps_lg": "gps",
            "base16_lg": "base64",
            "httpheader_lg": "httplogs",
        }
        if scanners:
            resolved = [_SCANNER_ALIASES.get(s, s) for s in scanners]
            deduped = list(dict.fromkeys(resolved))
            cmd.extend(["-E", deduped[0]])
            for s in deduped[1:]:
                cmd.extend(["-e", s])

        cmd.append(image_path)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=_BULK_TIMEOUT, check=False
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_bulk_extractor",
                params,
                f"bulk_extractor timed out after {_BULK_TIMEOUT}s",
            )

        if proc.returncode != 0:
            stderr_hint = (proc.stderr or "")[:500].strip()
            logger.error("bulk_extractor exited %d: %s", proc.returncode, stderr_hint)
            return error_response(
                tc_id,
                "run_bulk_extractor",
                params,
                f"bulk_extractor exited {proc.returncode}: {stderr_hint}",
                error_type="extraction_failed",
            )

        feature_map = {
            "email": "bulk.email",
            "url": "bulk.url",
            "domain": "bulk.domain",
            "ip": "bulk.ip",
            "telephone": "bulk.telephone",
            "find": "bulk.find",
            "pii": "bulk.pii",
            "elf": "bulk.elf",
            "exe": "bulk.exe",
            "json": "bulk.json",
            "winpe": "bulk.winpe",
            "winlnk": "bulk.winlnk",
        }

        results: list[object] = []
        for feature_file in sorted(Path(tmpdir).iterdir()):
            if not feature_file.is_file() or feature_file.suffix == ".xml":
                continue
            stem = feature_file.stem.replace("_histogram", "").replace("_find", "find")
            if "histogram" in feature_file.name:
                continue
            if features and stem not in features:
                continue

            source_name = feature_map.get(stem, f"bulk.{stem}")
            try:
                text = feature_file.read_text(encoding="utf-8", errors="replace").strip()
                if text:
                    results.append(
                        extract_and_index(text, source_name, image_path, "bulk_extractor")
                    )
            except OSError:
                pass

    total_windows = sum(r.get("windows_indexed", 0) for r in results if isinstance(r, dict))
    for r in results:
        if isinstance(r, dict):
            r.pop("source_id", None)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_bulk_extractor",
        params,
        {
            "features_indexed": len(results),
            "total_windows_indexed": total_windows,
            "per_feature": results,
        },
        "bulk",
        elapsed,
    )


@mcp.tool()
def run_strings(target_path: str, min_length: int = 8) -> dict[str, object]:
    """Extract printable strings from a file or disk image.

    Useful for quick triage of binary files, memory dumps, or disk
    images to find embedded text, URLs, commands, etc.

    Args:
        target_path: Path to the file to scan.
        min_length: Minimum string length to extract (default 8).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path, "min_length": min_length}

    if not _require_binary("strings"):
        return error_response(
            tc_id, "run_strings", params, "strings not found on PATH", error_type="binary_missing"
        )

    try:
        proc = subprocess.run(
            ["strings", f"-n{min_length}", target_path],
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id, "run_strings", params, "strings timed out", error_type="timeout"
        )

    summary = extract_and_index(proc.stdout.strip(), "strings.output", target_path, "strings")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_strings", params, summary, "strings.output", elapsed)


@mcp.tool()
def run_clamav(target_path: str) -> dict[str, object]:
    """Scan files for malware signatures using ClamAV.

    Runs clamscan recursively on the target path and indexes any
    detections found.

    Args:
        target_path: Path to the file or directory to scan.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path}

    if not _require_binary("clamscan"):
        return error_response(tc_id, "run_clamav", params, "clamscan not found on PATH")

    try:
        proc = subprocess.run(
            ["clamscan", "-r", "--no-summary", target_path],
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT * 5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_clamav", params, "clamscan timed out")

    output = proc.stdout.strip()
    infected_lines = [line for line in output.splitlines() if "FOUND" in line]
    summary_text = "\n".join(infected_lines) if infected_lines else output

    summary = extract_and_index(summary_text, "clamav.scan", target_path, "clamav")
    summary["detections"] = len(infected_lines)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_clamav", params, summary, "clamav.scan", elapsed)


@mcp.tool()
def run_hashdeep(target_path: str) -> dict[str, object]:
    """Compute recursive cryptographic hashes using hashdeep.

    Generates MD5, SHA1, and SHA256 hashes for all files under the
    target path.  Useful for integrity verification and IOC matching.

    Args:
        target_path: Path to the file or directory to hash.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path}

    if not _require_binary("hashdeep"):
        return error_response(tc_id, "run_hashdeep", params, "hashdeep not found on PATH")

    try:
        proc = subprocess.run(
            ["hashdeep", "-r", "-l", target_path],
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT * 3,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_hashdeep", params, "hashdeep timed out")

    summary = extract_and_index(proc.stdout.strip(), "hashdeep.hashes", target_path, "hashdeep")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_hashdeep", params, summary, "hashdeep.hashes", elapsed)


@mcp.tool()
def run_foremost(image_path: str) -> dict[str, object]:
    """Carve files from a disk image using foremost.

    Recovers deleted files by scanning for file headers and footers
    in the raw disk image.  Indexes an audit summary of carved files.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not _require_binary("foremost"):
        return error_response(tc_id, "run_foremost", params, "foremost not found on PATH")

    with tempfile.TemporaryDirectory(prefix="mulder_foremost_") as tmpdir:
        try:
            subprocess.run(
                ["foremost", "-i", image_path, "-o", tmpdir, "-T"],
                capture_output=True,
                text=True,
                timeout=_BULK_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(tc_id, "run_foremost", params, "foremost timed out")

        audit_text = ""
        for audit_file in Path(tmpdir).rglob("audit.txt"):
            with contextlib.suppress(OSError):
                audit_text += audit_file.read_text(encoding="utf-8", errors="replace")

    summary = extract_and_index(
        audit_text or "No files carved", "foremost.audit", image_path, "foremost"
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_foremost", params, summary, "foremost.audit", elapsed)


@mcp.tool()
def run_exiftool(target_path: str = "", file_path: str = "") -> dict[str, object]:
    """Extract file metadata (EXIF, document properties) using exiftool.

    Returns metadata for all files in the target path including
    timestamps, author information, GPS data, and more.

    Args:
        target_path: Path to the file or directory.
        file_path: Alias for target_path.
    """
    if not target_path and file_path:
        target_path = file_path
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path}

    if not _require_binary("exiftool"):
        return error_response(tc_id, "run_exiftool", params, "exiftool not found on PATH")

    try:
        proc = subprocess.run(
            ["exiftool", "-r", target_path],
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_exiftool", params, "exiftool timed out")

    summary = extract_and_index(proc.stdout.strip(), "exiftool.metadata", target_path, "exiftool")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_exiftool", params, summary, "exiftool.metadata", elapsed)


@mcp.tool()
def run_regripper(hive_path: str, profile: str | None = None) -> dict[str, object]:
    """Analyze a Windows registry hive using RegRipper.

    Runs all plugins by default, or a specific plugin profile if given.

    Args:
        hive_path: Path to the registry hive file.
        profile: Optional RegRipper plugin profile name.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"hive_path": hive_path, "profile": profile}

    rip = _require_binary("rip.pl") or _require_binary("regripper")
    if not rip:
        return error_response(tc_id, "run_regripper", params, "RegRipper not found on PATH")

    cmd = [rip, "-r", hive_path]
    if profile:
        cmd.extend(["-p", profile])
    else:
        cmd.append("-a")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(tc_id, "run_regripper", params, "RegRipper timed out")

    hive_label = Path(hive_path).stem.lower()
    source_name = f"regripper.{hive_label}"
    summary = extract_and_index(proc.stdout.strip(), source_name, hive_path, "regripper")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_regripper", params, summary, source_name, elapsed)


_PCAP_TIMEOUT = 600

_PCAP_MODES = {
    "summary",
    "conversations",
    "dns",
    "http",
    "smtp",
    "tls",
    "beaconing",
    "tunneling",
    "custom",
    "all",
}


def _run_tshark(
    args: list[str],
    pcap_path: str,
    timeout: int = _PCAP_TIMEOUT,
    ssl_keylog_path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run tshark with the given args against a PCAP file."""
    ssl_args: list[str] = []
    if ssl_keylog_path and Path(ssl_keylog_path).exists():
        ssl_args = ["-o", f"tls.keylog_file:{ssl_keylog_path}"]
    cmd = ["tshark", *ssl_args, "-r", pcap_path, *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _pcap_summary(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Capture statistics via capinfos + protocol hierarchy via tshark."""
    parts: list[str] = []

    capinfos = _require_binary("capinfos")
    if capinfos:
        try:
            proc = subprocess.run(
                [capinfos, pcap_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.stdout.strip():
                parts.append("=== Capture Info ===\n" + proc.stdout.strip())
        except subprocess.TimeoutExpired:
            parts.append("capinfos timed out")

    try:
        proc = _run_tshark(
            ["-q", "-z", "io,phs", "-c", str(max_packets)],
            pcap_path,
            timeout=120,
            ssl_keylog_path=ssl_keylog_path,
        )
        if proc.stdout.strip():
            parts.append("=== Protocol Hierarchy ===\n" + proc.stdout.strip())
    except subprocess.TimeoutExpired:
        parts.append("tshark protocol hierarchy timed out")

    return "\n\n".join(parts)


def _pcap_conversations(
    pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None
) -> str:
    """IP and TCP conversation tables."""
    parts: list[str] = []
    for conv_type in ("ip", "tcp"):
        try:
            proc = _run_tshark(
                ["-q", "-z", f"conv,{conv_type}", "-c", str(max_packets)],
                pcap_path,
                ssl_keylog_path=ssl_keylog_path,
            )
            if proc.stdout.strip():
                parts.append(f"=== {conv_type.upper()} Conversations ===\n" + proc.stdout.strip())
        except subprocess.TimeoutExpired:
            parts.append(f"tshark {conv_type} conversations timed out")
    return "\n\n".join(parts)


def _pcap_dns(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Extract DNS queries and responses."""
    try:
        proc = _run_tshark(
            [
                "-Y",
                "dns",
                "-T",
                "fields",
                "-e",
                "frame.time",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "dns.qry.name",
                "-e",
                "dns.resp.addr",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "tshark DNS extraction timed out"


def _pcap_http(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Extract HTTP requests and responses."""
    try:
        proc = _run_tshark(
            [
                "-Y",
                "http",
                "-T",
                "fields",
                "-e",
                "frame.time",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "http.request.method",
                "-e",
                "http.request.uri",
                "-e",
                "http.host",
                "-e",
                "http.response.code",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "tshark HTTP extraction timed out"


def _pcap_smtp(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Extract SMTP email transactions (sender, recipient, subject)."""
    try:
        proc = _run_tshark(
            [
                "-Y",
                "smtp",
                "-T",
                "fields",
                "-e",
                "frame.time",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "smtp.req.parameter",
                "-e",
                "smtp.response.parameter",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "tshark SMTP extraction timed out"


def _pcap_tls(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Extract TLS handshake info (server names, certificate subjects)."""
    try:
        proc = _run_tshark(
            [
                "-Y",
                "tls.handshake.type == 1 || tls.handshake.type == 11",
                "-T",
                "fields",
                "-e",
                "frame.time",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "tls.handshake.extensions_server_name",
                "-e",
                "x509ce.dNSName",
                "-e",
                "x509sat.uTF8String",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return "tshark TLS extraction timed out"


def _pcap_custom(
    pcap_path: str, display_filter: str, max_packets: int, ssl_keylog_path: str | None = None
) -> str:
    """Apply a custom tshark display filter."""
    try:
        proc = _run_tshark(
            ["-Y", display_filter, "-c", str(max_packets)],
            pcap_path,
            ssl_keylog_path=ssl_keylog_path,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"tshark custom filter '{display_filter}' timed out"


def _pcap_beaconing(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Detect C2 beaconing by analyzing inter-arrival timing per destination."""
    import math

    try:
        proc = _run_tshark(
            [
                "-T",
                "fields",
                "-e",
                "frame.time_epoch",
                "-e",
                "ip.dst",
                "-e",
                "tcp.dstport",
                "-e",
                "udp.dstport",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            ssl_keylog_path=ssl_keylog_path,
        )
    except subprocess.TimeoutExpired:
        return "tshark beaconing extraction timed out"

    lines = proc.stdout.strip().splitlines()
    if len(lines) < 2:
        return "No packets found for beaconing analysis"

    dest_times: dict[str, list[float]] = {}
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            epoch = float(parts[0])
        except (ValueError, IndexError):
            continue
        dst_ip = parts[1]
        dst_port = parts[2] or parts[3] if len(parts) > 3 else parts[2]
        if not dst_ip or not dst_port:
            continue
        key = f"{dst_ip}:{dst_port}"
        dest_times.setdefault(key, []).append(epoch)

    results: list[str] = ["BEACONING ANALYSIS", "=" * 50, ""]
    flagged = 0
    for dest, times in sorted(dest_times.items(), key=lambda x: len(x[1]), reverse=True):
        if len(times) < 5:
            continue
        times.sort()
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 0.1:
            continue
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        cov = stddev / mean_interval if mean_interval > 0 else 999

        if cov < 0.3 and len(times) >= 10:
            flagged += 1
            results.append(
                f"** POTENTIAL BEACON: {dest} **\n"
                f"  Connections: {len(times)}, Interval: {mean_interval:.1f}s, "
                f"StdDev: {stddev:.1f}s, CoV: {cov:.3f}"
            )
        elif cov < 0.5 and len(times) >= 20:
            flagged += 1
            results.append(
                f"POSSIBLE BEACON: {dest}\n"
                f"  Connections: {len(times)}, Interval: {mean_interval:.1f}s, "
                f"StdDev: {stddev:.1f}s, CoV: {cov:.3f}"
            )

    results.insert(
        2, f"Destinations analyzed: {len(dest_times)}, Potential beacons flagged: {flagged}\n"
    )
    return "\n".join(results)


def _pcap_tunneling(pcap_path: str, max_packets: int, ssl_keylog_path: str | None = None) -> str:
    """Detect DNS tunneling and ICMP covert channels."""
    import math

    output_parts: list[str] = ["DNS TUNNELING / COVERT CHANNEL ANALYSIS", "=" * 50, ""]

    try:
        proc = _run_tshark(
            [
                "-Y",
                "dns.qry.name",
                "-T",
                "fields",
                "-e",
                "dns.qry.name",
                "-e",
                "dns.qry.type",
                "-e",
                "frame.time",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            ssl_keylog_path=ssl_keylog_path,
        )
        dns_lines = proc.stdout.strip().splitlines()
    except subprocess.TimeoutExpired:
        dns_lines = []

    domain_stats: dict[str, dict[str, Any]] = {}
    if len(dns_lines) > 1:
        for line in dns_lines[1:]:
            parts = line.split("\t")
            if not parts or not parts[0]:
                continue
            qname = parts[0].strip().lower()
            labels = qname.split(".")
            if len(labels) < 2:
                continue
            base_domain = ".".join(labels[-2:])
            subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""
            if base_domain not in domain_stats:
                domain_stats[base_domain] = {
                    "query_count": 0,
                    "subdomain_lengths": [],
                    "subdomains": set(),
                }
            domain_stats[base_domain]["query_count"] += 1
            if subdomain:
                domain_stats[base_domain]["subdomain_lengths"].append(len(subdomain))
                domain_stats[base_domain]["subdomains"].add(subdomain)

    flagged_dns = 0
    for domain, stats in sorted(
        domain_stats.items(), key=lambda x: x[1]["query_count"], reverse=True
    ):
        lengths = stats["subdomain_lengths"]
        if not lengths or stats["query_count"] < 10:
            continue
        avg_len = sum(lengths) / len(lengths)
        freq: dict[str, int] = {}
        all_chars = "".join(stats["subdomains"])
        for c in all_chars:
            freq[c] = freq.get(c, 0) + 1
        total = len(all_chars) or 1
        entropy = -sum(
            (count / total) * math.log2(count / total) for count in freq.values() if count > 0
        )

        suspicious = False
        reasons: list[str] = []
        if avg_len > 20:
            suspicious = True
            reasons.append(f"long subdomains (avg {avg_len:.0f} chars)")
        if entropy > 3.5:
            suspicious = True
            reasons.append(f"high entropy ({entropy:.2f} bits)")
        if stats["query_count"] > 100 and len(stats["subdomains"]) > 50:
            suspicious = True
            reasons.append(f"high unique subdomain count ({len(stats['subdomains'])})")

        if suspicious:
            flagged_dns += 1
            output_parts.append(
                f"** POTENTIAL DNS TUNNEL: {domain} **\n"
                f"  Queries: {stats['query_count']}, "
                f"Unique subdomains: {len(stats['subdomains'])}, "
                f"Avg label len: {avg_len:.0f}, Entropy: {entropy:.2f}\n"
                f"  Reasons: {', '.join(reasons)}"
            )

    output_parts.append(
        f"\nDomains analyzed: {len(domain_stats)}, DNS tunneling suspects: {flagged_dns}"
    )

    try:
        icmp_proc = _run_tshark(
            [
                "-Y",
                "icmp && data.len > 64",
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "data.len",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-c",
                str(max_packets),
            ],
            pcap_path,
            ssl_keylog_path=ssl_keylog_path,
        )
        icmp_lines = icmp_proc.stdout.strip().splitlines()
        if len(icmp_lines) > 1:
            output_parts.append(
                f"\nICMP large-payload packets (data > 64 bytes): {len(icmp_lines) - 1}"
            )
            for line in icmp_lines[1:6]:
                output_parts.append(f"  {line}")
            if len(icmp_lines) > 6:
                output_parts.append(f"  ... and {len(icmp_lines) - 6} more")
    except subprocess.TimeoutExpired:
        output_parts.append("\nICMP analysis timed out")

    return "\n".join(output_parts)


@mcp.tool()
def run_pcap_analysis(
    pcap_path: str,
    mode: str = "summary",
    display_filter: str | None = None,
    max_packets: int = 10000,
    ssl_keylog_path: str | None = None,
) -> dict[str, object]:
    """Analyze a PCAP or PCAPng network capture file using tshark.

    Extracts network conversations, DNS queries, HTTP traffic, protocol
    statistics, or applies a custom Wireshark display filter.  Results
    are indexed into the case database.

    Args:
        pcap_path: Path to the .pcap or .pcapng file.
        mode: Analysis mode.  One of:
            - "summary": capture stats + protocol hierarchy
            - "conversations": IP and TCP conversation tables
            - "dns": DNS queries and responses
            - "http": HTTP requests and responses
            - "beaconing": detect C2 beaconing via inter-arrival timing
            - "tunneling": detect DNS tunneling and ICMP covert channels
            - "custom": apply display_filter (required for this mode)
            - "all": run all modes (summary through tunneling)
        display_filter: Wireshark display filter (required when mode="custom",
            e.g. "ip.addr == 10.0.0.5 && tcp.port == 4444").
        max_packets: Maximum packets to process (default 10000).  Caps
            tshark's -c flag to prevent unbounded output on large captures.
        ssl_keylog_path: Optional path to an NSS key log file (SSLKEYLOGFILE
            format) for decrypting TLS traffic.  When provided, tshark uses
            it to decrypt encrypted sessions, revealing HTTP, SMTP, and other
            application-layer data inside TLS.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {
        "pcap_path": pcap_path,
        "mode": mode,
        "display_filter": display_filter,
        "max_packets": max_packets,
        "ssl_keylog_path": ssl_keylog_path,
    }

    if mode not in _PCAP_MODES:
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            f"Unknown mode '{mode}'. Valid modes: {sorted(_PCAP_MODES)}",
            error_type="invalid_argument",
        )

    if not Path(pcap_path).exists():
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            f"File not found: {pcap_path}",
            error_type="file_not_found",
        )

    if not _require_binary("tshark"):
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            "tshark not found on PATH",
            error_type="binary_missing",
            suggestion="Install tshark: apt-get install tshark",
        )

    if mode == "custom" and not display_filter:
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            "display_filter is required when mode='custom'",
            error_type="invalid_argument",
        )

    if ssl_keylog_path and not Path(ssl_keylog_path).exists():
        return error_response(
            tc_id,
            "run_pcap_analysis",
            params,
            f"SSL keylog file not found: {ssl_keylog_path}",
            error_type="file_not_found",
        )

    _ssl = ssl_keylog_path
    results: list[object] = []

    mode_map: dict[str, tuple[str, Callable[[], str]]] = {
        "summary": ("pcap.summary", lambda: _pcap_summary(pcap_path, max_packets, _ssl)),
        "conversations": (
            "pcap.conversations",
            lambda: _pcap_conversations(pcap_path, max_packets, _ssl),
        ),
        "dns": ("pcap.dns", lambda: _pcap_dns(pcap_path, max_packets, _ssl)),
        "http": ("pcap.http", lambda: _pcap_http(pcap_path, max_packets, _ssl)),
        "smtp": ("pcap.smtp", lambda: _pcap_smtp(pcap_path, max_packets, _ssl)),
        "tls": ("pcap.tls", lambda: _pcap_tls(pcap_path, max_packets, _ssl)),
        "beaconing": ("pcap.beaconing", lambda: _pcap_beaconing(pcap_path, max_packets, _ssl)),
        "tunneling": ("pcap.tunneling", lambda: _pcap_tunneling(pcap_path, max_packets, _ssl)),
    }

    if mode == "all":
        modes_to_run = [
            "summary",
            "conversations",
            "dns",
            "http",
            "smtp",
            "tls",
            "beaconing",
            "tunneling",
        ]
    elif mode == "custom":
        modes_to_run = ["custom"]
    else:
        modes_to_run = [mode]

    for m in modes_to_run:
        if m == "custom":
            assert display_filter is not None
            output = _pcap_custom(pcap_path, display_filter, max_packets, _ssl)
            source_name = "pcap.filtered"
        else:
            source_name, fn = mode_map[m]
            output = fn()

        if output:
            summary = extract_and_index(output, source_name, pcap_path, "tshark")
            results.append(summary)
        else:
            results.append(
                {
                    "source_name": source_name,
                    "status": "no_output",
                    "mode": m,
                }
            )

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_pcap_analysis", params, results, "pcap", elapsed)


@mcp.tool()
def run_ssdeep(target_path: str, recursive: bool = False) -> dict[str, object]:
    """Compute fuzzy hashes of files using ssdeep.

    Fuzzy hashing identifies similar (not identical) files -- useful for
    finding malware variants or modified documents across systems.

    Args:
        target_path: Path to a file or directory to hash.
        recursive: If True and target is a directory, hash all files
            recursively.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path, "recursive": recursive}

    if not _require_binary("ssdeep"):
        return error_response(
            tc_id,
            "run_ssdeep",
            params,
            "ssdeep not found on PATH",
            error_type="binary_missing",
        )

    cmd = ["ssdeep"]
    if recursive:
        cmd.append("-r")
    cmd.append(target_path)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_ssdeep",
            params,
            "ssdeep timed out",
            error_type="timeout",
        )

    summary = extract_and_index(proc.stdout.strip(), "ssdeep.hashes", target_path, "ssdeep")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_ssdeep", params, summary, "ssdeep.hashes", elapsed)


_SCALPEL_TIMEOUT = 1800


@mcp.tool()
def run_scalpel(image_path: str) -> dict[str, object]:
    """Carve files from a disk image or partition using Scalpel.

    Scalpel recovers files based on header/footer signatures.  More
    configurable than foremost -- edit /etc/scalpel/scalpel.conf to
    enable specific file types before running.

    Args:
        image_path: Path to the disk image or raw partition.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not _require_binary("scalpel"):
        return error_response(
            tc_id,
            "run_scalpel",
            params,
            "scalpel not found on PATH",
            error_type="binary_missing",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_scalpel",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_scalpel_") as tmpdir:
        cmd = ["scalpel", "-o", tmpdir, image_path]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_SCALPEL_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_scalpel",
                params,
                f"scalpel timed out after {_SCALPEL_TIMEOUT}s",
                error_type="timeout",
            )

        audit_path = Path(tmpdir) / "audit.txt"
        audit_text = ""
        if audit_path.exists():
            audit_text = audit_path.read_text(errors="replace")

        if not audit_text.strip():
            audit_text = proc.stdout.strip() or "scalpel produced no output"

        summary = extract_and_index(audit_text, "scalpel.audit", image_path, "scalpel")

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_scalpel", params, summary, "scalpel.audit", elapsed)


@mcp.tool()
def run_binwalk(target_path: str, extract: bool = False) -> dict[str, object]:
    """Scan a file for embedded files, firmware headers, and compressed archives.

    binwalk identifies embedded content by signature.  Use extract=True
    to also extract discovered embedded files into a temp directory.

    Args:
        target_path: Path to the file to scan.
        extract: If True, extract embedded files (``binwalk -e``).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path, "extract": extract}

    if not _require_binary("binwalk"):
        return error_response(
            tc_id,
            "run_binwalk",
            params,
            "binwalk not found on PATH",
            error_type="binary_missing",
        )

    if not Path(target_path).exists():
        return error_response(
            tc_id,
            "run_binwalk",
            params,
            f"File not found: {target_path}",
            error_type="file_not_found",
        )

    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(target_path)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT * 3,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_binwalk",
            params,
            "binwalk timed out",
            error_type="timeout",
        )

    summary = extract_and_index(proc.stdout.strip(), "binwalk.scan", target_path, "binwalk")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_binwalk", params, summary, "binwalk.scan", elapsed)


_PHOTOREC_TIMEOUT = 3600


@mcp.tool()
def run_photorec(image_path: str) -> dict[str, object]:
    """Recover deleted files from a disk image using PhotoRec.

    PhotoRec recovers files by signature (480+ file types) from disk
    images, partitions, or raw devices.  Runs in non-interactive mode.

    Args:
        image_path: Path to the disk image or partition.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    if not _require_binary("photorec"):
        return error_response(
            tc_id,
            "run_photorec",
            params,
            "photorec not found on PATH",
            error_type="binary_missing",
            suggestion="Install testdisk package: apt-get install testdisk",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_photorec",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_photorec_") as tmpdir:
        cmd = [
            "photorec",
            "/cmd",
            image_path,
            "fileopt,everything,enable",
            f"search,{tmpdir}/",
        ]
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_PHOTOREC_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_photorec",
                params,
                f"photorec timed out after {_PHOTOREC_TIMEOUT}s",
                error_type="timeout",
            )

        report_path = Path(tmpdir) / "report.xml"
        report_text = ""
        if report_path.exists():
            report_text = report_path.read_text(errors="replace")

        if not report_text.strip():
            recovered = list(Path(tmpdir).rglob("*"))
            file_list = [str(f.relative_to(tmpdir)) for f in recovered if f.is_file()]
            report_text = f"PhotoRec recovered {len(file_list)} file(s):\n" + "\n".join(
                file_list[:500]
            )
            if len(file_list) > 500:
                report_text += f"\n... and {len(file_list) - 500} more"

        summary = extract_and_index(report_text, "photorec.report", image_path, "photorec")

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_photorec", params, summary, "photorec.report", elapsed)


@mcp.tool()
def run_pasco(indexdat_path: str) -> dict[str, object]:
    """Parse an Internet Explorer index.dat file for browser history.

    Extracts URLs, timestamps, and cache entries from IE's index.dat
    files.  Relevant for older Windows systems (XP/Vista/7).

    Args:
        indexdat_path: Path to the index.dat file.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"indexdat_path": indexdat_path}

    if not _require_binary("pasco"):
        return error_response(
            tc_id,
            "run_pasco",
            params,
            "pasco not found on PATH",
            error_type="binary_missing",
        )

    if not Path(indexdat_path).exists():
        return error_response(
            tc_id,
            "run_pasco",
            params,
            f"File not found: {indexdat_path}",
            error_type="file_not_found",
        )

    try:
        proc = subprocess.run(
            ["pasco", indexdat_path],
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_pasco",
            params,
            "pasco timed out",
            error_type="timeout",
        )

    summary = extract_and_index(
        proc.stdout.strip(),
        "pasco.history",
        indexdat_path,
        "pasco",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_pasco", params, summary, "pasco.history", elapsed)


@mcp.tool()
def run_vshadow_info(image_path: str, offset: int = 0) -> dict[str, object]:
    """List Volume Shadow Copy (VSS) snapshots in a disk image.

    Enumerates VSS snapshots with creation dates, sizes, and identifiers.
    Use this to discover which shadow copies exist before mounting them
    for deeper analysis.

    Args:
        image_path: Path to the disk image or raw partition.
        offset: Volume offset in bytes (default 0).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "offset": offset}

    if not _require_binary("vshadowinfo"):
        return error_response(
            tc_id,
            "run_vshadow_info",
            params,
            "vshadowinfo not found on PATH",
            error_type="binary_missing",
            suggestion="Install libvshadow-utils: apt-get install libvshadow-utils",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_vshadow_info",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    cmd = ["vshadowinfo"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_vshadow_info",
            params,
            "vshadowinfo timed out",
            error_type="timeout",
        )

    output = proc.stdout.strip()
    if not output and proc.stderr.strip():
        output = proc.stderr.strip()

    summary = extract_and_index(output, "vshadow.info", image_path, "vshadowinfo")
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_vshadow_info", params, summary, "vshadow.info", elapsed)


@mcp.tool()
def run_chkrootkit(target_path: str | None = None) -> dict[str, object]:
    """Scan for known Linux rootkits and suspicious kernel modifications.

    Checks for known rootkits, suspicious kernel modules, and signs of
    system compromise.  Complements ClamAV which focuses on file-based
    malware signatures.

    Args:
        target_path: Optional alternate root path to check (e.g. a
            mounted disk image).  If None, checks the live system.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"target_path": target_path}

    if not _require_binary("chkrootkit"):
        return error_response(
            tc_id,
            "run_chkrootkit",
            params,
            "chkrootkit not found on PATH",
            error_type="binary_missing",
        )

    cmd = ["chkrootkit"]
    if target_path:
        cmd.extend(["-r", target_path])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT * 3,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_chkrootkit",
            params,
            "chkrootkit timed out",
            error_type="timeout",
        )

    source_path = target_path or "/"
    summary = extract_and_index(
        proc.stdout.strip(),
        "chkrootkit.scan",
        source_path,
        "chkrootkit",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_chkrootkit", params, summary, "chkrootkit.scan", elapsed)


# ---------------------------------------------------------------------------
# radare2, tcpflow, tcpxtract, dislocker, bdeinfo, fvdeinfo, cyberchef
# ---------------------------------------------------------------------------


@mcp.tool()
def run_radare2(
    target_path: str,
    commands: str = "iI;iS;iz;afl",
) -> dict[str, object]:
    """Analyze a binary executable using radare2 for malware triage.

    Runs radare2 in batch mode (non-interactive) with the given
    commands.  Default commands extract: binary info (iI), sections (iS),
    strings (iz), and function list (afl).

    Args:
        target_path: Path to the binary to analyze.
        commands: Semicolon-separated r2 commands to run (batch mode).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"target_path": target_path, "commands": commands}

    if not _require_binary("r2"):
        return error_response(
            tc_id,
            "run_radare2",
            params,
            "r2 (radare2) not found on PATH",
            error_type="binary_missing",
        )

    if not Path(target_path).exists():
        return error_response(
            tc_id,
            "run_radare2",
            params,
            f"File not found: {target_path}",
            error_type="file_not_found",
        )

    try:
        proc = subprocess.run(
            ["r2", "-q", "-c", commands, target_path],
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_radare2",
            params,
            "radare2 timed out",
            error_type="timeout",
        )

    summary = extract_and_index(
        proc.stdout.strip(),
        "radare2.analysis",
        target_path,
        "radare2",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_radare2", params, summary, "radare2.analysis", elapsed)


@mcp.tool()
def run_tcpflow(pcap_path: str) -> dict[str, object]:
    """Reconstruct TCP streams from a PCAP file using tcpflow.

    Reassembles TCP connections into individual stream files, making it
    easy to examine HTTP transactions, file transfers, and other
    application-layer data extracted from network captures.

    Args:
        pcap_path: Path to the PCAP/PCAPNG file.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"pcap_path": pcap_path}

    if not _require_binary("tcpflow"):
        return error_response(
            tc_id,
            "run_tcpflow",
            params,
            "tcpflow not found on PATH",
            error_type="binary_missing",
        )

    if not Path(pcap_path).exists():
        return error_response(
            tc_id,
            "run_tcpflow",
            params,
            f"File not found: {pcap_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_tcpflow_") as tmpdir:
        try:
            subprocess.run(
                ["tcpflow", "-r", pcap_path, "-o", tmpdir],
                capture_output=True,
                text=True,
                timeout=_TOOL_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_tcpflow",
                params,
                "tcpflow timed out",
                error_type="timeout",
            )

        parts: list[str] = []
        for stream_file in sorted(Path(tmpdir).iterdir()):
            if stream_file.is_file() and stream_file.stat().st_size > 0:
                with contextlib.suppress(OSError):
                    preview = stream_file.read_text(
                        encoding="utf-8",
                        errors="replace",
                    )[:4096]
                    parts.append(
                        f"=== {stream_file.name} "
                        f"({stream_file.stat().st_size} bytes) ===\n{preview}"
                    )

        combined = "\n\n".join(parts) if parts else "No TCP streams reconstructed"

    summary = extract_and_index(combined, "tcpflow.streams", pcap_path, "tcpflow")
    summary["stream_count"] = len(parts)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_tcpflow", params, summary, "tcpflow.streams", elapsed)


@mcp.tool()
def run_tcpxtract(pcap_path: str) -> dict[str, object]:
    """Extract files from TCP streams in a PCAP using tcpxtract.

    Carves files from network traffic based on file signatures, similar
    to foremost but for network captures.  Useful for recovering
    transferred documents, images, and executables.

    Args:
        pcap_path: Path to the PCAP file.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"pcap_path": pcap_path}

    if not _require_binary("tcpxtract"):
        return error_response(
            tc_id,
            "run_tcpxtract",
            params,
            "tcpxtract not found on PATH",
            error_type="binary_missing",
        )

    if not Path(pcap_path).exists():
        return error_response(
            tc_id,
            "run_tcpxtract",
            params,
            f"File not found: {pcap_path}",
            error_type="file_not_found",
        )

    with tempfile.TemporaryDirectory(prefix="mulder_tcpxtract_") as tmpdir:
        try:
            proc = subprocess.run(
                ["tcpxtract", "-f", pcap_path, "-o", tmpdir],
                capture_output=True,
                text=True,
                timeout=_TOOL_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_tcpxtract",
                params,
                "tcpxtract timed out",
                error_type="timeout",
            )

        parts: list[str] = []
        for carved in sorted(Path(tmpdir).iterdir()):
            if carved.is_file():
                parts.append(f"{carved.name}  {carved.stat().st_size} bytes")

        inventory = "\n".join(parts) if parts else proc.stdout.strip()

    summary = extract_and_index(inventory, "tcpxtract.carved", pcap_path, "tcpxtract")
    summary["files_carved"] = len(parts)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_tcpxtract", params, summary, "tcpxtract.carved", elapsed)


@mcp.tool()
def run_dislocker(
    image_path: str,
    recovery_key: str = "",
    password: str = "",
) -> dict[str, object]:
    """Inspect or decrypt a BitLocker-encrypted volume.

    Without credentials, returns BitLocker metadata (encryption method,
    protector types, volume ID).  With a recovery key or password,
    decrypts the volume to a FUSE mountpoint for subsequent TSK analysis.

    Args:
        image_path: Path to the BitLocker-encrypted partition/image.
        recovery_key: BitLocker 48-digit recovery key (optional).
        password: BitLocker password (optional).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "image_path": image_path,
        "recovery_key": "***" if recovery_key else "",
        "password": "***" if password else "",
    }

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    if not recovery_key and not password:
        if not _require_binary("dislocker-metadata"):
            return error_response(
                tc_id,
                "run_dislocker",
                params,
                "dislocker-metadata not found on PATH",
                error_type="binary_missing",
            )
        try:
            proc = subprocess.run(
                ["dislocker-metadata", "-V", image_path],
                capture_output=True,
                text=True,
                timeout=_TOOL_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_dislocker",
                params,
                "dislocker-metadata timed out",
                error_type="timeout",
            )
        summary = extract_and_index(
            proc.stdout.strip(),
            "dislocker.metadata",
            image_path,
            "dislocker",
        )
        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(
            tc_id,
            "run_dislocker",
            params,
            summary,
            "dislocker.metadata",
            elapsed,
        )

    if not _require_binary("dislocker-fuse"):
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            "dislocker-fuse not found on PATH",
            error_type="binary_missing",
        )

    mount_point = tempfile.mkdtemp(prefix="mulder_dislocker_")
    cmd = ["dislocker-fuse"]
    if recovery_key:
        cmd.extend(["-p", recovery_key])
    elif password:
        cmd.extend(["-u", password])
    cmd.extend(["--", image_path, mount_point])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            "dislocker-fuse timed out",
            error_type="timeout",
        )

    if proc.returncode != 0:
        return error_response(
            tc_id,
            "run_dislocker",
            params,
            f"dislocker-fuse failed: {proc.stderr.strip()[:500]}",
        )

    result_text = (
        f"BitLocker volume decrypted and mounted at: {mount_point}\n"
        f"Decrypted image: {mount_point}/dislocker-file\n"
        f"Use this path with run_fls or run_mmls for filesystem analysis."
    )
    summary = extract_and_index(
        result_text,
        "dislocker.decrypted",
        image_path,
        "dislocker",
    )
    summary["mount_point"] = mount_point
    summary["decrypted_path"] = f"{mount_point}/dislocker-file"
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id,
        "run_dislocker",
        params,
        summary,
        "dislocker.decrypted",
        elapsed,
    )


@mcp.tool()
def run_bdeinfo(image_path: str) -> dict[str, object]:
    """Extract metadata from a BitLocker-encrypted volume using libbde.

    Returns encryption method, volume identifier, protector types, and
    creation timestamps without requiring the decryption key.

    Args:
        image_path: Path to the BitLocker-encrypted partition/image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path}

    if not _require_binary("bdeinfo"):
        return error_response(
            tc_id,
            "run_bdeinfo",
            params,
            "bdeinfo not found on PATH",
            error_type="binary_missing",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_bdeinfo",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    try:
        proc = subprocess.run(
            ["bdeinfo", image_path],
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_bdeinfo",
            params,
            "bdeinfo timed out",
            error_type="timeout",
        )

    summary = extract_and_index(
        proc.stdout.strip(),
        "bde.info",
        image_path,
        "bdeinfo",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_bdeinfo", params, summary, "bde.info", elapsed)


@mcp.tool()
def run_fvdeinfo(image_path: str) -> dict[str, object]:
    """Extract metadata from a FileVault-encrypted macOS volume.

    Returns encryption type, volume UUID, and protector information
    without requiring the decryption passphrase.

    Args:
        image_path: Path to the FileVault-encrypted volume image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path}

    if not _require_binary("fvdeinfo"):
        return error_response(
            tc_id,
            "run_fvdeinfo",
            params,
            "fvdeinfo not found on PATH",
            error_type="binary_missing",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_fvdeinfo",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    try:
        proc = subprocess.run(
            ["fvdeinfo", image_path],
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_fvdeinfo",
            params,
            "fvdeinfo timed out",
            error_type="timeout",
        )

    summary = extract_and_index(
        proc.stdout.strip(),
        "fvde.info",
        image_path,
        "fvdeinfo",
    )
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_fvdeinfo", params, summary, "fvde.info", elapsed)
