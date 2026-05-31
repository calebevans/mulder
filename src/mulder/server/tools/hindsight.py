"""Hindsight MCP tools for Chrome/Chromium browser forensics.

Runs Hindsight against a browser profile directory and indexes the
parsed artifacts (history, downloads, cookies, autofill, bookmarks,
local storage, preferences, etc.) into the case database.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import error_response, hash_output, make_tool_call_id

logger = logging.getLogger(__name__)

_HINDSIGHT_TIMEOUT = 300
_VALID_BROWSERS = ("chrome", "brave", "edge", "opera")


def _find_hindsight_cmd() -> list[str] | None:
    """Locate the Hindsight CLI, trying multiple install conventions."""
    for name in ("hindsight.py", "hindsight"):
        if shutil.which(name):
            return [name]
    py = shutil.which("python3") or shutil.which("python")
    if py:
        try:
            subprocess.run(
                [py, "-m", "pyhindsight.hindsight", "--help"],
                capture_output=True,
                timeout=10,
                check=True,
            )
            return [py, "-m", "pyhindsight.hindsight"]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            pass
    return None


@mcp.tool()
def run_hindsight(
    profile_path: str,
    browser: str = "chrome",
) -> dict[str, object]:
    """Analyze Chrome/Chromium browser artifacts using Hindsight.

    Parses browser history, downloads, cookies, autofill, bookmarks,
    preferences, cache, local storage, sessions, and extensions from
    a Chrome/Chromium profile directory.

    Run this after extracting browser profile directories from a disk
    image (typically under ``AppData/Local/Google/Chrome/User Data/Default``
    on Windows or ``~/.config/google-chrome/Default`` on Linux).

    Args:
        profile_path: Path to the browser profile directory
            (e.g. Default/ under Chrome user data).
        browser: Browser type, one of "chrome" (default), "brave", "edge", "opera".
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"profile_path": profile_path, "browser": browser}
    tool_name = "run_hindsight"

    hs_cmd = _find_hindsight_cmd()
    if not hs_cmd:
        return error_response(
            tc_id,
            tool_name,
            params,
            "Hindsight not found. Install with: pip install pyhindsight",
            error_type="binary_missing",
        )

    if not Path(profile_path).is_dir():
        return error_response(
            tc_id,
            tool_name,
            params,
            f"Profile directory not found: {profile_path}",
            error_type="file_not_found",
        )

    browser_type = browser.lower() if browser.lower() in _VALID_BROWSERS else "chrome"

    with tempfile.TemporaryDirectory(prefix="mulder_hindsight_") as tmpdir:
        output_base = str(Path(tmpdir) / "results")

        cmd = [
            *hs_cmd,
            "-i",
            profile_path,
            "-o",
            output_base,
            "-b",
            browser_type,
            "-f",
            "jsonl",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_HINDSIGHT_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                tool_name,
                params,
                f"Hindsight timed out after {_HINDSIGHT_TIMEOUT}s",
                elapsed_ms=(time.monotonic() - t0) * 1000,
            )

        raw_output = ""
        artifact_counts: dict[str, int] = {}

        for out_file in sorted(Path(tmpdir).rglob("*")):
            if not out_file.is_file() or out_file.stat().st_size == 0:
                continue
            try:
                text = out_file.read_text(encoding="utf-8", errors="replace")
                raw_output += f"=== {out_file.name} ===\n{text}\n\n"

                if out_file.suffix == ".jsonl":
                    count = sum(1 for line in text.splitlines() if line.strip())
                    artifact_counts[out_file.stem] = count
            except OSError:
                continue

        if not raw_output.strip():
            raw_output = proc.stdout.strip() or proc.stderr.strip()

    index_result = extract_and_index(
        raw_output,
        "hindsight.browser",
        profile_path,
        "hindsight",
    )

    elapsed = (time.monotonic() - t0) * 1000
    result: dict[str, object] = {
        "browser": browser_type,
        "profile_path": profile_path,
        "artifact_counts": artifact_counts,
        "total_artifacts": sum(artifact_counts.values()),
        "index": index_result,
    }

    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=tool_name,
        params=params,
        output_hash=hash_output(result),
        duration_ms=elapsed,
    )
    return {
        "tool_call_id": tc_id,
        "status": "success",
        "results": result,
        "source": "hindsight.browser",
    }
