"""YARA threat-hunting MCP tools.

All three tools are query-time only -- they shell out to the ``yara`` CLI
or Volatility 3's ``vadyarascan`` plugin on demand.  YARA is read-only by
design: it scans files and memory but never modifies evidence.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from mulder.server.app import get_ctx, mcp

logger = logging.getLogger(__name__)

_YARA_FILE_TIMEOUT = 120
_YARA_MEMORY_TIMEOUT = 600
_YARA_VOL_TIMEOUT = 600

_BUILTIN_RULES_DIR = Path(__file__).resolve().parent.parent / "yara_rules"
_COMMUNITY_RULE_PATHS = [Path("/opt/signature-base"), Path("/opt/yara-rules")]

_SRC_FILE_SCAN = "yara.file_scan"
_SRC_MEMORY_SCAN = "yara.memory_scan"
_SRC_VOL_SCAN = "yara.volatility_scan"

_ERR_NO_RULES = "No YARA rules available (built-in rules missing and none provided)"

_YARA_MATCH_RE = re.compile(r"^(\S+)\s+(.+)$")
_YARA_STRING_RE = re.compile(r"^(0x[0-9a-fA-F]+):(\S+):\s*(.*)$")


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_tool_call_id() -> str:
    return f"tc_{uuid4().hex[:8]}"


def _hash_output(output: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(output, sort_keys=True, default=str).encode()).hexdigest()
    )


def _collect_builtin_rules() -> list[str]:
    """Return paths to all .yar files shipped with Mulder."""
    if not _BUILTIN_RULES_DIR.is_dir():
        return []
    return sorted(str(p) for p in _BUILTIN_RULES_DIR.glob("*.yar"))


def _collect_community_rules() -> list[str]:
    """Return paths to community rule sets found on SIFT standard locations."""
    paths: list[str] = []
    for base in _COMMUNITY_RULE_PATHS:
        if base.is_dir():
            paths.extend(sorted(str(p) for p in base.rglob("*.yar")))
    return paths


def _resolve_rules(rules: str | None) -> tuple[str | None, bool]:
    """Determine the YARA rules source.

    Returns ``(path_or_none, needs_cleanup)``.  When *needs_cleanup* is
    True the caller must delete the path after the scan.
    """
    if rules is None:
        builtin = _collect_builtin_rules()
        if builtin:
            return builtin[0] if len(builtin) == 1 else None, False
        community = _collect_community_rules()
        if community:
            return community[0] if len(community) == 1 else None, False
        return None, False

    stripped = rules.strip()
    if stripped.endswith((".yar", ".yara")) and os.path.isfile(stripped):
        return stripped, False

    if os.path.isdir(stripped):
        return stripped, False

    fd, tmp_path = tempfile.mkstemp(suffix=".yar", prefix="mulder_yara_")
    with os.fdopen(fd, "w") as fh:
        fh.write(stripped)
    return tmp_path, True


def _build_rules_args(rules: str | None) -> tuple[list[str], bool]:
    """Build the CLI args list for yara rules and return cleanup flag.

    When ``rules`` is None and multiple built-in rule files exist, each
    file is passed via ``-d`` / individual positional args is not
    supported -- so we create a temp index file that ``include``s them.
    """
    if rules is None:
        builtin = _collect_builtin_rules()
        community = _collect_community_rules()
        all_rules = builtin or community
        if not all_rules:
            return [], False
        if len(all_rules) == 1:
            return [all_rules[0]], False
        fd, idx_path = tempfile.mkstemp(suffix=".yar", prefix="mulder_yara_idx_")
        with os.fdopen(fd, "w") as fh:
            for rp in all_rules:
                fh.write(f'include "{rp}"\n')
        return [idx_path], True

    resolved, cleanup = _resolve_rules(rules)
    if resolved is None:
        return [], False
    return [resolved], cleanup


def _find_memory_image() -> str:
    """Look up the memory dump path from ingested Volatility sources."""
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    for s in sources:
        if s.source_name.startswith("volatility."):
            return s.source_path
    raise RuntimeError(
        "No Volatility sources found in this case. "
        "Was a memory dump ingested with 'mulder ingest'?"
    )


def _parse_yara_output(stdout: str) -> list[dict]:
    """Parse ``yara -s`` output into structured match dicts."""
    results: list[dict] = []
    current: dict | None = None

    for line in stdout.splitlines():
        line = line.rstrip()
        if not line:
            continue

        string_m = _YARA_STRING_RE.match(line)
        if string_m and current is not None:
            current["matched_strings"].append(
                {
                    "offset": string_m.group(1),
                    "identifier": string_m.group(2),
                    "data": string_m.group(3),
                }
            )
            continue

        match_m = _YARA_MATCH_RE.match(line)
        if match_m:
            current = {
                "rule": match_m.group(1),
                "file": match_m.group(2),
                "matched_strings": [],
            }
            results.append(current)

    return results


def _cleanup(path: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)


# ------------------------------------------------------------------
# Tool: yara_scan_files
# ------------------------------------------------------------------


@mcp.tool()
def yara_scan_files(target_path: str, rules: str | None = None) -> dict:
    """Scan files on a mounted filesystem or extracted directory with YARA.

    *target_path* is scanned recursively.  *rules* can be a path to a
    ``.yar`` file, a YARA rule string, or None to use built-in detection
    rules.  Requires ``yara`` on PATH.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    if not shutil.which("yara"):
        results: dict | list = {"error": "yara not found on PATH"}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_files",
            params={"target_path": target_path, "rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_FILE_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    rules_args, cleanup = _build_rules_args(rules)
    if not rules_args:
        results = {"error": _ERR_NO_RULES}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_files",
            params={"target_path": target_path, "rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_FILE_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    cmd = ["yara", "-r", "-s", *rules_args, target_path]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_YARA_FILE_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        if cleanup:
            _cleanup(rules_args[0])
        results = {"error": f"yara timed out after {_YARA_FILE_TIMEOUT}s scanning {target_path}"}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_files",
            params={"target_path": target_path, "rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_FILE_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    if cleanup:
        _cleanup(rules_args[0])

    if proc.returncode != 0 and not proc.stdout.strip():
        results = {
            "error": f"yara exited {proc.returncode}",
            "stderr": (proc.stderr or "")[:500],
        }
        result_count = 0
    else:
        results = _parse_yara_output(proc.stdout)
        result_count = len(results)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="yara_scan_files",
        params={"target_path": target_path, "rules": rules is not None},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_FILE_SCAN,
        "result_count": result_count,
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: yara_scan_memory
# ------------------------------------------------------------------


@mcp.tool()
def yara_scan_memory(rules: str | None = None) -> dict:
    """Scan the ingested memory image with YARA.

    The memory image path is resolved from the case's Volatility sources.
    *rules* can be a path to a ``.yar`` file, a YARA rule string, or None
    to use built-in detection rules.  Requires ``yara`` on PATH.  Read-only.
    """
    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    if not shutil.which("yara"):
        results: dict | list = {"error": "yara not found on PATH"}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    try:
        image_path = _find_memory_image()
    except RuntimeError as exc:
        results = {"error": str(exc)}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    rules_args, cleanup = _build_rules_args(rules)
    if not rules_args:
        results = {"error": _ERR_NO_RULES}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    cmd = ["yara", "-s", *rules_args, image_path]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_YARA_MEMORY_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        if cleanup:
            _cleanup(rules_args[0])
        results = {"error": f"yara timed out after {_YARA_MEMORY_TIMEOUT}s scanning memory image"}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    if cleanup:
        _cleanup(rules_args[0])

    if proc.returncode != 0 and not proc.stdout.strip():
        results = {
            "error": f"yara exited {proc.returncode}",
            "stderr": (proc.stderr or "")[:500],
        }
        result_count = 0
    else:
        results = _parse_yara_output(proc.stdout)
        result_count = len(results)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="yara_scan_memory",
        params={"rules": rules is not None},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_MEMORY_SCAN,
        "result_count": result_count,
        "reduced": False,
        "reduction_ratio": None,
    }


# ------------------------------------------------------------------
# Tool: yara_scan_with_volatility
# ------------------------------------------------------------------


@mcp.tool()
def yara_scan_with_volatility(pid: int | None = None, rules: str | None = None) -> dict:
    """Scan process memory using Volatility 3's vadyarascan plugin.

    Scans all processes by default, or a single process when *pid* is
    given.  *rules* can be a path to a ``.yar`` file, a YARA rule string,
    or None to use built-in detection rules.  Requires Volatility 3 on
    PATH.  Read-only.
    """
    from mulder.extractors.volatility import _find_vol_binary

    ctx = get_ctx()
    tc_id = _make_tool_call_id()
    t0 = time.monotonic()

    try:
        vol_cmd = _find_vol_binary()
    except RuntimeError as exc:
        results: dict | list = {"error": str(exc)}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    try:
        image_path = _find_memory_image()
    except RuntimeError as exc:
        results = {"error": str(exc)}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    rules_args, cleanup = _build_rules_args(rules)
    if not rules_args:
        results = {"error": _ERR_NO_RULES}
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    rules_path = rules_args[0]
    cmd = [
        *vol_cmd,
        "-f",
        image_path,
        "windows.vadyarascan.VadYaraScan",
        "--yara-file",
        rules_path,
    ]
    if pid is not None:
        cmd.extend(["--pid", str(pid)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_YARA_VOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        if cleanup:
            _cleanup(rules_path)
        results = {
            "error": f"Volatility vadyarascan timed out after {_YARA_VOL_TIMEOUT}s",
        }
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=_hash_output(results),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "results": results,
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
            "reduced": False,
            "reduction_ratio": None,
        }

    if cleanup:
        _cleanup(rules_path)

    if proc.returncode != 0 and not proc.stdout.strip():
        results = {
            "error": f"Volatility vadyarascan exited {proc.returncode}",
            "stderr": (proc.stderr or "")[:500],
        }
        result_count = 0
    else:
        output = proc.stdout.strip()
        lines = [ln for ln in output.splitlines() if ln.strip()] if output else []
        results = {"raw_output": output, "line_count": len(lines)}
        result_count = len(lines)

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="yara_scan_with_volatility",
        params={"pid": pid, "rules": rules is not None},
        output_hash=_hash_output(results),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "results": results,
        "source": _SRC_VOL_SCAN,
        "result_count": result_count,
        "reduced": False,
        "reduction_ratio": None,
    }
