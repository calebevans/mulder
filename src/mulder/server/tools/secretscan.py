"""Secret detection MCP tool: find leaked credentials in CI logs, artifacts and source trees."""

from __future__ import annotations

import json
import logging
import re
import tempfile
import time
from collections.abc import Iterable
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
_SKIPPED_SOURCE = "secrets.not_scanned"
_MAX_RESPONSE_FILES = 50

# How much of each secret gitleaks blanks out, and how much of the remainder
# mulder keeps. The few leading characters that survive ("AKIA...",
# "ghp_R2sT...") are enough to match a finding to a key in the provider's
# console and too little to use. A fifth of a 1,700-character private key is
# still 300 characters of key, hence the second bound. Findings are indexed,
# shown to the model and quoted in reports, so the value must never get that far.
_REDACT_PERCENT = 80
_SECRET_PREVIEW_CHARS = 12

# gitleaks says at debug level why it left a file alone, e.g.
#   DBG skipping file: global allowlist path=/x/leak.png
#   DBG skipping binary file mime_type=application/pdf path=/x/build.log
#   WRN skipping file: permission denied path=/x/key.pem
#   ERR could read compressed file path=/x/run.log.gz
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SKIP_RE = re.compile(
    r"\b(?:DBG|WRN|ERR) (?P<reason>(?:skipping|could(?: not)? read)[^=]*?)"
    r"(?: mime_type=(?P<mime>\S+))? path=(?P<path>.*)$"
)

# The built-in ruleset, named explicitly: without --config gitleaks loads a
# .gitleaks.toml from the directory it scans, which is evidence.
_CONFIG = "[extend]\nuseDefault = true\n"


def _flat(value: object) -> str:
    """One line, single-spaced: a tab, newline or carriage return in a file
    name must not be able to split a record or forge a column."""
    return " ".join(str(value).split())


def _line_times(file: str, lines: Iterable[int]) -> dict[int, str]:
    """The ISO timestamp on each of *lines* in *file*, where the line has one.

    CI run logs stamp every line, so this is when a secret was printed. Lines
    are counted the way gitleaks counts them, on newlines only (a progress bar
    redrawn with carriage returns is one line), and the file is streamed, so a
    multi-gigabyte log is never held in memory.
    """
    wanted = {n for n in lines if n > 0}
    found: dict[int, str] = {}
    if not wanted:
        return found
    last = max(wanted)
    try:
        with open(file, "rb") as handle:
            for number, raw in enumerate(handle, start=1):
                if number in wanted:
                    match = _ISO_RE.search(raw[:4096].decode("utf-8", errors="replace"))
                    if match:
                        found[number] = match.group(0)
                if number >= last:
                    break
    except OSError:  # inside an archive, or gone: no time, not a failure
        pass
    return found


def _finding_line(finding: dict[str, Any], when: str) -> str:
    """One tab-separated, single-line record per finding, time first."""
    secret = str(finding.get("Secret", ""))
    if len(secret) > _SECRET_PREVIEW_CHARS:
        secret = secret[:_SECRET_PREVIEW_CHARS].rstrip(".") + "..."
    fields = (
        when,
        finding.get("RuleID", ""),
        f"{finding.get('File', '')}:{finding.get('StartLine', 0)}",
        secret,
        finding.get("Description", ""),
    )
    return "\t".join(_flat(f) for f in fields)


def _not_scanned(stderr: str) -> list[tuple[str, str]]:
    """(reason, path) for everything gitleaks reported leaving unscanned."""
    skipped: list[tuple[str, str]] = []
    for line in stderr.splitlines():
        match = _SKIP_RE.search(_ANSI_RE.sub("", line))
        if match:
            reason = match["reason"].strip().removeprefix("skipping ").replace("could read", "")
            reason = reason.strip(" :") or "unreadable"
            if reason == "compressed file":
                reason = "archive could not be read"
            if match["mime"]:
                reason = f"{reason} ({match['mime']})"
            skipped.append((reason, match["path"].strip()))
    return skipped


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_secret_scan(evidence_path: str, force: bool = False) -> dict[str, object]:
    """Find leaked credentials in files using gitleaks.

    Call on CI run logs, build artifacts, repository checkouts or any directory
    where a token, key or password may have been printed or committed. Scans
    files as they are on disk (no git history) and looks inside archives.

    Returns the finding count per rule and per file, and what was not scanned
    and why. Each finding is indexed in secrets.findings with the secret mostly
    redacted, its rule, file and line, and the log timestamp of that line when
    it has one. Files gitleaks left alone (binary content, lock files and
    vendored directories, unreadable files, archives it could not open) are
    listed in secrets.not_scanned: a secret in one of those is NOT ruled out.

    Args:
        evidence_path: File or directory to scan.
        force: Re-run even if this path was already scanned.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "run_secret_scan"
    params: dict[str, object] = {"evidence_path": evidence_path, "force": force}

    if not force:
        existing = sources_already_indexed(["secrets."], evidence_path=evidence_path)
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
    target = Path(evidence_path)
    if not target.exists():
        return error_response(
            tc_id, name, params, f"Path not found: {evidence_path}", error_type="file_not_found"
        )

    with tempfile.TemporaryDirectory(prefix="mulder_secrets_") as tmpdir:
        tmp = Path(tmpdir).resolve()
        report = tmp / "report.json"
        config = tmp / "gitleaks.toml"
        config.write_text(_CONFIG, encoding="utf-8")
        # Suppression planted in the evidence is not honoured. Inline
        # "gitleaks:allow" comments are ignored and the config is named
        # explicitly. gitleaks always loads <scanned dir>/.gitleaksignore and
        # has no flag to stop it, but an entry only matches the exact path the
        # scan reports, so a directory is scanned through a symlink in this
        # private temp directory: no entry written in advance can name it.
        # What gitleaks skips by its own rules (binary content, lock files,
        # vendored directories) cannot be turned off, so it is reported instead.
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
                # Debug is where gitleaks says which files it skipped and why;
                # it never logs a secret's value.
                "--log-level=debug",
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
            errors = [ln for ln in (result.stderr or "").splitlines() if " DBG " not in ln]
            detail = _ANSI_RE.sub("", "\n".join(errors) or result.stdout or "").strip()[-500:]
            return error_response(
                tc_id,
                name,
                params,
                f"gitleaks exited {result.returncode} without a usable report: {detail}",
                elapsed,
                error_type="tool_failed",
            )

        findings = [f for f in findings if isinstance(f, dict)]
        unscanned = _not_scanned(result.stderr or "")
        if target.is_dir():
            # Report files where they really are, not under the temporary link.
            def real(path: str) -> str:
                return str(target / path[len(scan_path) :]) if path.startswith(scan_path) else path

            for finding in findings:
                finding["File"] = real(str(finding.get("File", "")))
            unscanned = [(reason, real(path)) for reason, path in unscanned]

    by_rule: dict[str, int] = {}
    by_file: dict[str, int] = {}
    wanted: dict[str, set[int]] = {}
    for finding in findings:
        rule, file = str(finding.get("RuleID", "")), str(finding.get("File", ""))
        by_rule[rule] = by_rule.get(rule, 0) + 1
        by_file[_flat(file)] = by_file.get(_flat(file), 0) + 1
        if isinstance(finding.get("StartLine"), int):
            wanted.setdefault(file, set()).add(finding["StartLine"])
    times = {file: _line_times(file, numbers) for file, numbers in wanted.items()}

    dated: list[str] = []
    undated: list[str] = []
    for finding in findings:
        when = times.get(str(finding.get("File", "")), {}).get(finding.get("StartLine", 0))
        (dated if when else undated).append(_finding_line(finding, when or "-"))
    # Dated findings first, in time order: the index keeps one time per window
    # of lines, taken from the first timestamp in it, so a window's time is
    # that of its earliest finding and undated findings never borrow one.
    header = f"gitleaks secret scan of {evidence_path}: {len(findings)} findings"
    extract_and_index(
        "\n".join([header, *sorted(dated), *sorted(undated)]), _SOURCE, evidence_path, "gitleaks"
    )

    by_reason: dict[str, int] = {}
    for reason, _path in unscanned:
        by_reason[reason] = by_reason.get(reason, 0) + 1
    if unscanned:
        header = (
            f"Not scanned for secrets under {evidence_path}: {len(unscanned)} files or directories"
        )
        lines = sorted(f"{_flat(reason)}\t{_flat(path)}" for reason, path in unscanned)
        extract_and_index("\n".join([header, *lines]), _SKIPPED_SOURCE, evidence_path, "gitleaks")

    worst = sorted(by_file.items(), key=lambda kv: (-kv[1], kv[0]))
    summary: dict[str, object] = {
        "evidence_path": evidence_path,
        "total_findings": len(findings),
        "by_rule": dict(sorted(by_rule.items())),
        "files_with_findings": len(by_file),
        "by_file": dict(worst[:_MAX_RESPONSE_FILES]),
        "source": _SOURCE,
        # A secret in any of these is not ruled out.
        "not_scanned": dict(sorted(by_reason.items())),
        "not_scanned_source": _SKIPPED_SOURCE if unscanned else None,
    }
    # Returned in full: it is bounded, and the counts are what the caller acts on.
    return tool_response(tc_id, name, params, summary, None, (time.monotonic() - t0) * 1000)
