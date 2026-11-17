"""GitHub Actions workflow audit MCP tool: zizmor findings plus a secrets map."""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    require_binary,
    run_subprocess,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = ["run_workflow_audit"]

logger = logging.getLogger(__name__)

_TIMEOUT = 600
_FINDINGS_SOURCE = "workflow.findings"
_SECRETS_SOURCE = "workflow.secrets"
_SNIPPET_CHARS = 300
_MAX_WORKFLOW_BYTES = 1024 * 1024
_MAX_RESPONSE_WORKFLOWS = 50

_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
_YAML_EXTS = {".yml", ".yaml"}
_SECRET_REF_RE = re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)")
_SECRETS_INHERIT_RE = re.compile(r"^\s*secrets:\s*inherit\s*(#.*)?$", re.MULTILINE)


def _workflow_files(root: Path) -> tuple[list[Path], bool]:
    """Return (workflow files, whether *root* is laid out as a repository).

    A repository keeps them in ``.github/workflows``; several checkouts under
    one directory are all found. A directory with no such folder is taken to
    be the workflows folder itself, exported on its own.
    """
    if root.is_file():
        return [root], False
    yaml_files = sorted(p for p in root.rglob("*") if p.suffix.lower() in _YAML_EXTS)
    in_repo = [
        p for p in yaml_files if p.parent.name == "workflows" and p.parent.parent.name == ".github"
    ]
    return (in_repo, True) if in_repo else ([p for p in yaml_files if p.is_file()], False)


def _secrets_used(workflow: Path) -> list[str]:
    """Names of the secrets a workflow file refers to.

    ponytail: a regex over the text, so it counts a reference in a comment and
    cannot say which job uses which secret; parse the YAML per job if that
    distinction starts to matter.
    """
    try:
        if workflow.stat().st_size > _MAX_WORKFLOW_BYTES:
            return []
        text = workflow.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    names = set(_SECRET_REF_RE.findall(text))
    if _SECRETS_INHERIT_RE.search(text):
        names.add("(all, via secrets: inherit)")
    return sorted(names)


def _flat(value: object, limit: int = _SNIPPET_CHARS) -> str:
    """Render *value* on one line, bounded."""
    return " ".join(str(value).split())[:limit]


def _finding_line(finding: dict[str, Any]) -> tuple[int, str]:
    """Return (severity rank, one tab-separated line) for a zizmor finding."""
    determinations = finding.get("determinations") or {}
    severity = str(determinations.get("severity", ""))
    locations = [loc for loc in finding.get("locations") or [] if isinstance(loc, dict)]
    primary = next(
        (loc for loc in locations if (loc.get("symbolic") or {}).get("kind") == "Primary"),
        locations[0] if locations else {},
    )
    symbolic = primary.get("symbolic") or {}
    concrete = primary.get("concrete") or {}
    file = ((symbolic.get("key") or {}).get("Local") or {}).get("verbatim_path", "")
    row = ((concrete.get("location") or {}).get("start_point") or {}).get("row")
    where = f"{file}:{row + 1}" if isinstance(row, int) else str(file)
    fields = (
        severity.lower(),
        f"confidence={str(determinations.get('confidence', '')).lower()}",
        finding.get("ident", ""),
        where,
        symbolic.get("annotation", ""),
        finding.get("desc", ""),
        # An ignore comment in the workflow asked for this finding to be hidden.
        "suppressed-in-source" if finding.get("ignored") else "",
        concrete.get("feature", ""),
    )
    return _SEVERITY_ORDER.get(severity, 9), "\t".join(_flat(f) for f in fields)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_workflow_audit(repo_path: str, force: bool = False) -> dict[str, object]:
    """Audit GitHub Actions workflows for exploitable weaknesses using zizmor.

    Call when the evidence holds a repository checkout or exported workflow
    files and CI may be how the attacker got in or reached credentials. Finds
    template injection of attacker-controlled input, dangerous triggers
    (pull_request_target, workflow_run), unpinned actions, excessive
    permissions and credential persistence, and lists the secrets each
    workflow refers to.

    Returns finding counts by severity and audit, and the secrets map. Findings
    are indexed in workflow.findings and the secrets map in workflow.secrets.

    Args:
        repo_path: A repository checkout (or a directory of several), a
            directory of workflow YAML files, or one workflow file.
        force: Re-run even if this path was already audited.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "run_workflow_audit"
    params: dict[str, object] = {"repo_path": repo_path, "force": force}

    if not force:
        existing = sources_already_indexed(["workflow."], evidence_path=repo_path)
        if existing:
            skipped: dict[str, object] = {
                "status": "skipped",
                "reason": "Sources already indexed from prior extraction",
                "existing_sources": existing,
            }
            return tool_response(tc_id, name, params, skipped, None, 0.0)

    zizmor = require_binary("zizmor")
    if not zizmor:
        return error_response(
            tc_id,
            name,
            params,
            "zizmor not found on PATH",
            error_type="binary_missing",
            suggestion="Run 'mulder setup' (installs zizmor).",
        )
    root = Path(repo_path)
    if not root.exists():
        return error_response(
            tc_id, name, params, f"Path not found: {repo_path}", error_type="file_not_found"
        )
    workflows, is_repo = _workflow_files(root)
    if not workflows:
        return error_response(
            tc_id, name, params, f"No workflow YAML found under {repo_path}", error_type="no_data"
        )

    # Offline, and deaf to the evidence: a zizmor.yml, inline ignore comments
    # or a .gitignore in the audited tree would otherwise hide findings.
    result = run_subprocess(
        [
            zizmor,
            "--offline",
            "--no-config",
            "--no-ignores",
            "--collect=all",
            "--format=json",
            "--no-exit-codes",
            "--no-progress",
            "--color=never",
            *([str(root)] if is_repo else [str(w) for w in workflows]),
        ],
        timeout=_TIMEOUT,
    )
    elapsed = (time.monotonic() - t0) * 1000
    if isinstance(result, str):
        return error_response(tc_id, name, params, result, elapsed, error_type="timeout")
    try:
        findings = json.loads(result.stdout)
    except ValueError:
        findings = None
    if result.returncode != 0 or not isinstance(findings, list):
        detail = (result.stderr or "").strip()[-500:]
        return error_response(
            tc_id,
            name,
            params,
            f"zizmor exited {result.returncode} without usable output: {detail}",
            elapsed,
            error_type="tool_failed",
        )

    findings = [f for f in findings if isinstance(f, dict)]
    by_severity: dict[str, int] = {}
    by_audit: dict[str, int] = {}
    for finding in findings:
        severity = str((finding.get("determinations") or {}).get("severity", "")).lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1
        ident = str(finding.get("ident", ""))
        by_audit[ident] = by_audit.get(ident, 0) + 1
    suppressed = sum(1 for f in findings if f.get("ignored"))

    lines = [line for _rank, line in sorted(_finding_line(f) for f in findings)]
    header = f"zizmor workflow audit of {repo_path}: {len(findings)} findings"
    extract_and_index("\n".join([header, *lines]), _FINDINGS_SOURCE, repo_path, "zizmor")

    secrets = {str(w): _secrets_used(w) for w in workflows}
    secret_lines = [f"{w}\t{', '.join(names) or '(none)'}" for w, names in secrets.items()]
    header = f"Secrets referenced by each workflow under {repo_path}"
    extract_and_index("\n".join([header, *secret_lines]), _SECRETS_SOURCE, repo_path, "zizmor")

    with_secrets = {w: names for w, names in secrets.items() if names}
    summary: dict[str, object] = {
        "repo_path": repo_path,
        "workflows_audited": len(workflows),
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_audit": dict(sorted(by_audit.items())),
        "suppressed_in_source": suppressed,
        "secrets_by_workflow": dict(list(with_secrets.items())[:_MAX_RESPONSE_WORKFLOWS]),
        "sources": [_FINDINGS_SOURCE, _SECRETS_SOURCE],
    }
    # Returned in full: it is bounded, and the counts are what the caller acts on.
    return tool_response(tc_id, name, params, summary, None, (time.monotonic() - t0) * 1000)
