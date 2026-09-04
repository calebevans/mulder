"""Plaso (log2timeline) super-timeline MCP tools."""

from __future__ import annotations

import contextlib
import logging
import shutil
import tempfile
import time
from pathlib import Path

from mulder.execution import safe_subprocess as subprocess
from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    _PREVIEW_CHAR_LIMIT,
    adaptive_timeout,
    error_response,
    interpreter_candidates,
    make_tool_call_id,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "run_plaso",
]

logger = logging.getLogger(__name__)

_PLASO_TIMEOUT = 3600


def _find_plaso_cmd(tool: str) -> list[str] | None:
    """Locate a Plaso CLI tool, trying multiple install conventions.

    pip-installed plaso may use ``log2timeline.py``, ``log2timeline``,
    or only be reachable via ``-m plaso.cli.<tool>`` on a probed Python
    interpreter.
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
        for py in interpreter_candidates():
            try:
                subprocess.run(
                    [py, "-m", mod, "--version"],
                    capture_output=True,
                    timeout=10,
                    check=True,
                )
                return [py, "-m", mod]
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                continue
    return None


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
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
                "log2timeline not found (tried log2timeline.py, log2timeline, and "
                "-m plaso.cli.log2timeline on every probed Python interpreter)"
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

        plaso_timeout = adaptive_timeout(evidence_path, base=_PLASO_TIMEOUT)
        try:
            proc = subprocess.run(
                l2t_cmd, capture_output=True, text=True, timeout=plaso_timeout, check=False
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id, "run_plaso", params, f"log2timeline timed out after {plaso_timeout}s"
            )

        if proc.returncode != 0 and not plaso_file.exists():
            stderr = (proc.stderr or "")[:_PREVIEW_CHAR_LIMIT]
            return error_response(
                tc_id,
                "run_plaso",
                params,
                f"log2timeline failed: {stderr}",
                error_is_untrusted_evidence=True,
            )

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
                psort_cmd, capture_output=True, text=True, timeout=plaso_timeout, check=False
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
