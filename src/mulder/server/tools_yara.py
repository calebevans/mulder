"""YARA threat-hunting MCP tools.

All three tools are query-time only -- they shell out to the ``yara`` CLI
or Volatility 3's ``vadyarascan`` plugin on demand.  YARA is read-only by
design: it scans files and memory but never modifies evidence.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import hash_output, make_tool_call_id

logger = logging.getLogger(__name__)

_YARA_FILE_TIMEOUT = 120
_YARA_MEMORY_TIMEOUT = 600
_YARA_VOL_TIMEOUT = 600

_YARA_RULES_DIR = Path("/opt/yara-rules")
_SIGNATURE_BASE_DIR = Path("/opt/signature-base")

_rules_updated = False
_rules_lock = threading.Lock()

_SRC_FILE_SCAN = "yara.file_scan"
_SRC_MEMORY_SCAN = "yara.memory_scan"
_SRC_VOL_SCAN = "yara.volatility_scan"

_ERR_NO_RULES = "No YARA rules available (built-in rules missing and none provided)"

_YARA_MATCH_RE = re.compile(r"^(\S+)\s+(.+)$")
_YARA_STRING_RE = re.compile(r"^(0x[0-9a-fA-F]+):(\S+):\s*(.*)$")


def _update_community_rules() -> None:
    """Pull latest YARA rules from upstream repos (best-effort, once per session)."""
    global _rules_updated  # noqa: PLW0603
    with _rules_lock:
        if _rules_updated:
            return
        _rules_updated = True
    for repo_dir in (_YARA_RULES_DIR, _SIGNATURE_BASE_DIR):
        if not (repo_dir / ".git").is_dir():
            continue
        try:
            subprocess.run(
                ["git", "-C", str(repo_dir), "pull", "--ff-only", "-q"],
                capture_output=True,
                timeout=30,
                check=False,
            )
            logger.info("Updated YARA rules: %s", repo_dir.name)
        except (subprocess.TimeoutExpired, OSError):
            logger.debug("Could not update %s (no network?), using cached rules", repo_dir.name)


def _collect_yara_rules_community() -> list[str]:
    """Return .yar paths from the Yara-Rules/rules repo."""
    if not _YARA_RULES_DIR.is_dir():
        return []
    return sorted(str(p) for p in _YARA_RULES_DIR.rglob("*.yar"))


def _collect_signature_base() -> list[str]:
    """Return .yar paths from Neo23x0/signature-base."""
    if not _SIGNATURE_BASE_DIR.is_dir():
        return []
    yara_dir = _SIGNATURE_BASE_DIR / "yara"
    if yara_dir.is_dir():
        return sorted(str(p) for p in yara_dir.rglob("*.yar"))
    return sorted(str(p) for p in _SIGNATURE_BASE_DIR.rglob("*.yar"))


_VALID_RULESETS = ("builtin", "standard", "full")


def _collect_rules_for_ruleset(ruleset: str) -> list[str]:
    """Collect rule file paths for the given ruleset level.

    - ``"builtin"``  -- Yara-Rules/rules (~1,500 rules)
    - ``"standard"`` -- same as builtin
    - ``"full"``     -- Neo23x0/signature-base only (~4,000 rules)

    The two repos are NOT combined because they share duplicate rule
    identifiers that cause YARA compilation errors.  Signature-base is
    the more comprehensive library and a superset of most yara-rules
    detections.
    """
    if ruleset == "full":
        return _collect_signature_base()
    return _collect_yara_rules_community()


_valid_rules_cache: dict[int, list[str]] = {}
_valid_rules_lock = threading.Lock()


def _validate_rule_files(rule_paths: list[str]) -> list[str]:
    """Return only rule files that compile without errors.

    Caches results so repeated scans don't re-validate.  Uses the
    YARA binary to test-compile each file individually.
    """
    cache_key = hash(tuple(sorted(rule_paths)))
    with _valid_rules_lock:
        if cache_key in _valid_rules_cache:
            return _valid_rules_cache[cache_key]

    if not shutil.which("yara"):
        return rule_paths

    valid: list[str] = []
    for rp in rule_paths:
        try:
            proc = subprocess.run(
                ["yara", rp, "/dev/null"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            if proc.returncode == 0:
                valid.append(rp)
        except (subprocess.TimeoutExpired, OSError):
            continue

    logger.info("YARA rule validation: %d/%d files valid", len(valid), len(rule_paths))
    with _valid_rules_lock:
        _valid_rules_cache[cache_key] = valid
    return valid


def _build_index_file(rule_paths: list[str]) -> tuple[str, bool]:
    """Create a temp .yar file with ``include`` directives for valid paths.

    Pre-validates rule files to skip ones with compilation errors.
    """
    if not rule_paths:
        return "", False

    valid_paths = _validate_rule_files(rule_paths)
    if not valid_paths:
        return "", False
    if len(valid_paths) == 1:
        return valid_paths[0], False

    fd, idx_path = tempfile.mkstemp(suffix=".yar", prefix="mulder_yara_idx_")
    with os.fdopen(fd, "w") as fh:
        for rp in valid_paths:
            fh.write(f'include "{rp}"\n')
    return idx_path, True


def _build_rules_args(
    rules: str | None,
    ruleset: str = "builtin",
) -> tuple[list[str], bool]:
    """Build the CLI args list for yara rules and return cleanup flag."""
    _update_community_rules()

    if rules is not None:
        stripped = rules.strip()
        if stripped.endswith((".yar", ".yara")) and os.path.isfile(stripped):
            return [stripped], False
        if os.path.isdir(stripped):
            dir_rules = sorted(str(p) for p in Path(stripped).rglob("*.yar"))
            if not dir_rules:
                return [], False
            idx, cleanup = _build_index_file(dir_rules)
            return ([idx], cleanup) if idx else ([], False)
        if re.search(r"^\s*include\s+", stripped, re.MULTILINE | re.IGNORECASE):
            return [], False
        fd, tmp_path = tempfile.mkstemp(suffix=".yar", prefix="mulder_yara_")
        with os.fdopen(fd, "w") as fh:
            fh.write(stripped)
        return [tmp_path], True

    all_rules = _collect_rules_for_ruleset(ruleset)
    if not all_rules:
        return [], False
    idx, cleanup = _build_index_file(all_rules)
    return ([idx], cleanup) if idx else ([], False)


def _find_memory_image() -> str:
    """Look up the memory dump path from ingested Volatility sources."""
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    for s in sources:
        if s.source_name.startswith("volatility."):
            if not Path(s.source_path).exists():
                raise RuntimeError(
                    f"Memory dump file not found: {s.source_path}. "
                    "Has the evidence been moved or unmounted?"
                )
            return s.source_path
    raise RuntimeError(
        "No Volatility sources found in this case. "
        "Was a memory dump ingested with 'mulder ingest'?"
    )


def _parse_yara_output(stdout: str) -> list[dict[str, object]]:
    """Parse ``yara -s`` output into structured match dicts."""
    results: list[dict[str, object]] = []
    current: dict[str, object] | None = None

    for line in stdout.splitlines():
        line = line.rstrip()
        if not line:
            continue

        string_m = _YARA_STRING_RE.match(line)
        if string_m and current is not None:
            matched_strings = current["matched_strings"]
            assert isinstance(matched_strings, list)
            matched_strings.append(
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
    """Remove a temporary file, ignoring errors."""
    with contextlib.suppress(OSError):
        os.unlink(path)


@mcp.tool()
def yara_scan_files(
    target_path: str,
    rules: str | None = None,
    ruleset: str = "builtin",
) -> dict[str, object]:
    """Scan files on a mounted filesystem or extracted directory with YARA.

    *target_path* is scanned recursively.  *rules* can be a path to a
    ``.yar`` file, a YARA rule string, or None to use the *ruleset*.
    *ruleset* controls which rule libraries to load when *rules* is None:

    - ``"builtin"``  -- Yara-Rules/rules (~1,500 rules)
    - ``"standard"`` -- same as builtin
    - ``"full"``     -- Neo23x0/signature-base (~4,000 rules; not combined
      with builtin due to duplicate rule identifiers)

    Community rule repos are auto-updated on first use if network is
    available.  Requires ``yara`` on PATH.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if ruleset not in _VALID_RULESETS:
        ruleset = "builtin"

    if not shutil.which("yara"):
        error_msg = "yara not found on PATH"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_files",
            params={"target_path": target_path, "rules": rules is not None, "ruleset": ruleset},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_FILE_SCAN,
            "result_count": 0,
        }

    rules_args, cleanup = _build_rules_args(rules, ruleset=ruleset)
    if not rules_args:
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_files",
            params={"target_path": target_path, "rules": rules is not None},
            output_hash=hash_output({"error": _ERR_NO_RULES}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": _ERR_NO_RULES,
            "results": [],
            "source": _SRC_FILE_SCAN,
            "result_count": 0,
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
        error_msg = f"yara timed out after {_YARA_FILE_TIMEOUT}s scanning {target_path}"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_files",
            params={"target_path": target_path, "rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_FILE_SCAN,
            "result_count": 0,
        }
    except OSError as exc:
        if cleanup:
            _cleanup(rules_args[0])
        error_msg = f"Failed to run yara: {exc}"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_files",
            params={"target_path": target_path, "rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_FILE_SCAN,
            "result_count": 0,
        }

    if cleanup:
        _cleanup(rules_args[0])

    if proc.returncode != 0 and not proc.stdout.strip():
        error_msg = f"yara exited {proc.returncode}"
        stderr_text = (proc.stderr or "")[:500]
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_files",
            params={"target_path": target_path, "rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"{error_msg}: {stderr_text}".rstrip(": "),
            "results": [],
            "source": _SRC_FILE_SCAN,
            "result_count": 0,
        }

    results = _parse_yara_output(proc.stdout)
    result_count = len(results)

    index_summary = {}
    if proc.stdout.strip():
        index_summary = extract_and_index(proc.stdout, "yara.files", target_path, "yara")

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="yara_scan_files",
        params={"target_path": target_path, "rules": rules is not None},
        output_hash=hash_output({"result_count": result_count}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "source": _SRC_FILE_SCAN,
        "source_name": "yara.files",
        "result_count": result_count,
        "windows_indexed": index_summary.get("windows_indexed", 0),
        "hint": (
            "Use search(query, source='yara.files') or "
            "get_raw_output('yara.files') to retrieve match details."
        ),
    }


@mcp.tool()
def yara_scan_memory(
    rules: str | None = None,
    ruleset: str = "builtin",
) -> dict[str, object]:
    """Scan the ingested memory image with YARA.

    The memory image path is resolved from the case's Volatility sources.
    *rules* can be a path to a ``.yar`` file, a YARA rule string, or None
    to use the *ruleset*.  *ruleset* controls which rule libraries to load
    when *rules* is None:

    - ``"builtin"``  -- Yara-Rules/rules (~1,500 rules)
    - ``"standard"`` -- same as builtin
    - ``"full"``     -- Neo23x0/signature-base (~4,000 rules; not combined
      with builtin due to duplicate rule identifiers)

    Community rule repos are auto-updated on first use if network is
    available.  Requires ``yara`` on PATH.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if ruleset not in _VALID_RULESETS:
        ruleset = "builtin"

    if not shutil.which("yara"):
        error_msg = "yara not found on PATH"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None, "ruleset": ruleset},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
        }

    try:
        image_path = _find_memory_image()
    except RuntimeError as exc:
        error_msg = str(exc)
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
        }

    rules_args, cleanup = _build_rules_args(rules, ruleset=ruleset)
    if not rules_args:
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None, "ruleset": ruleset},
            output_hash=hash_output({"error": _ERR_NO_RULES}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": _ERR_NO_RULES,
            "results": [],
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
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
        error_msg = f"yara timed out after {_YARA_MEMORY_TIMEOUT}s scanning memory image"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
        }
    except OSError as exc:
        if cleanup:
            _cleanup(rules_args[0])
        error_msg = f"Failed to run yara: {exc}"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
        }

    if cleanup:
        _cleanup(rules_args[0])

    if proc.returncode != 0 and not proc.stdout.strip():
        error_msg = f"yara exited {proc.returncode}"
        stderr_text = (proc.stderr or "")[:500]
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_memory",
            params={"rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"{error_msg}: {stderr_text}".rstrip(": "),
            "results": [],
            "source": _SRC_MEMORY_SCAN,
            "result_count": 0,
        }

    results = _parse_yara_output(proc.stdout)
    result_count = len(results)

    index_summary = {}
    if proc.stdout.strip():
        index_summary = extract_and_index(proc.stdout, "yara.memory", image_path, "yara")

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="yara_scan_memory",
        params={"rules": rules is not None},
        output_hash=hash_output({"result_count": result_count}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "source": _SRC_MEMORY_SCAN,
        "source_name": "yara.memory",
        "result_count": result_count,
        "windows_indexed": index_summary.get("windows_indexed", 0),
        "hint": (
            "Use search(query, source='yara.memory') or "
            "get_raw_output('yara.memory') to retrieve match details."
        ),
    }


@mcp.tool()
def yara_scan_with_volatility(
    pid: int | None = None, rules: str | None = None
) -> dict[str, object]:
    """Scan process memory using Volatility 3's vadyarascan plugin.

    Scans all processes by default, or a single process when *pid* is
    given.  *rules* can be a path to a ``.yar`` file, a YARA rule string,
    or None to use built-in detection rules.  Requires Volatility 3 on
    PATH.  Read-only.
    """
    from mulder.extractors.volatility import _find_vol_binary

    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    try:
        vol_cmd = _find_vol_binary()
    except RuntimeError as exc:
        error_msg = str(exc)
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
        }

    try:
        image_path = _find_memory_image()
    except RuntimeError as exc:
        error_msg = str(exc)
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
        }

    rules_args, cleanup = _build_rules_args(rules)
    if not rules_args:
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=hash_output({"error": _ERR_NO_RULES}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": _ERR_NO_RULES,
            "results": [],
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
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
        error_msg = f"Volatility vadyarascan timed out after {_YARA_VOL_TIMEOUT}s"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
        }
    except OSError as exc:
        if cleanup:
            _cleanup(rules_path)
        error_msg = f"Failed to run Volatility: {exc}"
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": error_msg,
            "results": [],
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
        }

    if cleanup:
        _cleanup(rules_path)

    if proc.returncode != 0 and not proc.stdout.strip():
        error_msg = f"Volatility vadyarascan exited {proc.returncode}"
        stderr_text = (proc.stderr or "")[:500]
        elapsed = (time.monotonic() - t0) * 1000
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name="yara_scan_with_volatility",
            params={"pid": pid, "rules": rules is not None},
            output_hash=hash_output({"error": error_msg}),
            duration_ms=elapsed,
        )
        return {
            "tool_call_id": tc_id,
            "status": "error",
            "error_message": f"{error_msg}: {stderr_text}".rstrip(": "),
            "results": [],
            "source": _SRC_VOL_SCAN,
            "result_count": 0,
        }

    output = proc.stdout.strip()
    lines = [ln for ln in output.splitlines() if ln.strip()] if output else []
    result_count = len(lines)

    index_summary = {}
    if output:
        index_summary = extract_and_index(output, "yara.volatility", image_path, "volatility_yara")

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="yara_scan_with_volatility",
        params={"pid": pid, "rules": rules is not None},
        output_hash=hash_output({"result_count": result_count}),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "source": _SRC_VOL_SCAN,
        "source_name": "yara.volatility",
        "result_count": result_count,
        "windows_indexed": index_summary.get("windows_indexed", 0),
        "hint": (
            "Use search(query, source='yara.volatility') or "
            "get_raw_output('yara.volatility') to retrieve match details."
        ),
    }
