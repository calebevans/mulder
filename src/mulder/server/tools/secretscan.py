"""Secret detection MCP tool: find leaked credentials in CI logs, artifacts and source trees."""

from __future__ import annotations

import json
import linecache
import logging
import tempfile
import time
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import _ISO_RE, extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    require_binary,
    run_subprocess,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = ["run_secret_scan"]

logger = logging.getLogger(__name__)

_TIMEOUT = 1800
_SOURCE = "secrets.findings"
_MAX_RESPONSE_FILES = 50

# How much of each secret gitleaks blanks out. The leading fifth that survives
# ("AKIA...", "ghp_R2sT...") is enough to match a finding to a key in the
# provider's console and too little to use. Findings are indexed, shown to
# the model and quoted in reports, so the full value must never get that far.
_REDACT_PERCENT = 80

# The built-in ruleset, named explicitly: without --config gitleaks loads a
# .gitleaks.toml from the directory it scans, which is evidence.
_CONFIG = "[extend]\nuseDefault = true\n"


def _line_time(file: str, line: int) -> str:
    """The ISO timestamp on the line a secret sits on, or "-".

    CI run logs stamp every line, so this is when the secret was printed.
    """
    match = _ISO_RE.search(linecache.getline(file, line)) if line > 0 else None
    return match.group(0) if match else "-"


def _finding_line(finding: dict[str, Any]) -> str:
    """One tab-separated, single-line record per finding, time first."""
    file = str(finding.get("File", ""))
    line = finding.get("StartLine", 0)
    fields = (
        _line_time(file, line if isinstance(line, int) else 0),
        finding.get("RuleID", ""),
        f"{file}:{line}",
        finding.get("Secret", ""),
        finding.get("Description", ""),
    )
    return "\t".join(str(f).replace("\t", " ").replace("\n", " ") for f in fields)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_secret_scan(target_path: str, force: bool = False) -> dict[str, object]:
    """Find leaked credentials in files using gitleaks.

    Call on CI run logs, build artifacts, repository checkouts or any directory
    where a token, key or password may have been printed or committed. Scans
    files as they are on disk (no git history) and looks inside archives.

    Returns the finding count per rule and per file. Each finding is indexed in
    secrets.findings with the secret mostly redacted, its rule, file and line,
    and the log timestamp of that line when it has one.

    Args:
        target_path: File or directory to scan.
        force: Re-run even if this path was already scanned.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "run_secret_scan"
    params: dict[str, object] = {"target_path": target_path, "force": force}

    if not force:
        existing = sources_already_indexed(["secrets."], evidence_path=target_path)
        if existing:
            skipped: dict[str, object] = {
                "status": "skipped",
                "reason": "Sources already indexed from prior extraction",
                "existing_sources": existing,
            }
            return tool_response(tc_id, name, params, skipped, None, 0.0)

    gitleaks = require_binary("gitleaks")
    if not gitleaks:
        return error_response(
            tc_id,
            name,
            params,
            "gitleaks not found on PATH",
            error_type="binary_missing",
            suggestion="Run 'mulder setup' (installs gitleaks).",
        )
    target = Path(target_path)
    if not target.exists():
        return error_response(
            tc_id, name, params, f"Path not found: {target_path}", error_type="file_not_found"
        )

    with tempfile.TemporaryDirectory(prefix="mulder_secrets_") as tmpdir:
        tmp = Path(tmpdir).resolve()
        report = tmp / "report.json"
        config = tmp / "gitleaks.toml"
        config.write_text(_CONFIG, encoding="utf-8")
        # Evidence must not be able to switch the scan off. Inline
        # "gitleaks:allow" comments are ignored and the config is named
        # explicitly. gitleaks always loads <scanned dir>/.gitleaksignore and
        # has no flag to stop it, but an entry only matches the exact path the
        # scan reports, so a directory is scanned through a symlink in this
        # private temp directory: no entry written in advance can name it.
        scan_path = str(target.resolve())
        if target.is_dir():
            link = tmp / "evidence"
            link.symlink_to(scan_path, target_is_directory=True)
            scan_path = f"{link}/"
        result = run_subprocess(
            [
                gitleaks,
                "dir",
                scan_path,
                "--report-format=json",
                f"--report-path={report}",
                f"--config={config}",
                f"--gitleaks-ignore-path={tmp}",
                "--ignore-gitleaks-allow",
                f"--redact={_REDACT_PERCENT}",
                "--max-archive-depth=2",
                "--exit-code=0",
                "--no-banner",
                "--no-color",
                "--log-level=error",
            ],
            timeout=_TIMEOUT,
        )
        elapsed = (time.monotonic() - t0) * 1000
        if isinstance(result, str):
            return error_response(tc_id, name, params, result, elapsed, error_type="timeout")
        try:
            findings = json.loads(report.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            findings = None
        if result.returncode != 0 or not isinstance(findings, list):
            detail = (result.stderr or result.stdout or "").strip()[-500:]
            return error_response(
                tc_id,
                name,
                params,
                f"gitleaks exited {result.returncode} without a usable report: {detail}",
                elapsed,
                error_type="tool_failed",
            )

        findings = [f for f in findings if isinstance(f, dict)]
        if target.is_dir():
            # Report files where they really are, not under the temporary link.
            for finding in findings:
                file = str(finding.get("File", ""))
                if file.startswith(scan_path):
                    finding["File"] = str(target / file[len(scan_path) :])

    by_rule: dict[str, int] = {}
    by_file: dict[str, int] = {}
    for finding in findings:
        rule, file = str(finding.get("RuleID", "")), str(finding.get("File", ""))
        by_rule[rule] = by_rule.get(rule, 0) + 1
        by_file[file] = by_file.get(file, 0) + 1

    lines = sorted(_finding_line(f) for f in findings)
    linecache.clearcache()
    header = f"gitleaks secret scan of {target_path}: {len(findings)} findings"
    extract_and_index("\n".join([header, *lines]), _SOURCE, target_path, "gitleaks")

    worst = sorted(by_file.items(), key=lambda kv: (-kv[1], kv[0]))
    summary: dict[str, object] = {
        "target_path": target_path,
        "total_findings": len(findings),
        "by_rule": dict(sorted(by_rule.items())),
        "files_with_findings": len(by_file),
        "by_file": dict(worst[:_MAX_RESPONSE_FILES]),
        "source": _SOURCE,
    }
    # Returned in full: it is bounded, and the counts are what the caller acts on.
    return tool_response(tc_id, name, params, summary, None, (time.monotonic() - t0) * 1000)
