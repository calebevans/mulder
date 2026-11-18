"""GitHub Actions workflow audit MCP tool: zizmor findings plus a secrets map."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    require_binary,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = ["run_workflow_audit"]

logger = logging.getLogger(__name__)

# One workflow is audited per zizmor run, so one that cannot be parsed, or
# that is built to be slow (zizmor is quadratic in comment lines), costs only
# itself. The budget bounds the whole call.
_FILE_TIMEOUT = 60
_TOTAL_BUDGET = 900
_FINDINGS_SOURCE = "workflow.findings"
_SECRETS_SOURCE = "workflow.secrets"
_NOT_AUDITED_SOURCE = "workflow.not_audited"
_SNIPPET_CHARS = 300
_MAX_WORKFLOW_BYTES = 1024 * 1024
_MAX_RESPONSE_WORKFLOWS = 50

_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
_YAML_EXTS = {".yml", ".yaml"}
_ACTION_NAMES = {"action.yml", "action.yaml"}
# The secrets context, not a property that happens to be called "secrets"
# (steps.vault.outputs.secrets). Context names are case-insensitive.
_SECRETS = r"(?<![\w.])secrets"
_SECRET_REF_RE = re.compile(
    _SECRETS + r"""(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*['"]([^'"]+)['"]\s*\])""", re.IGNORECASE
)
_SECRETS_INHERIT_RE = re.compile(r"^\s*secrets:\s*inherit\s*(#.*)?$", re.MULTILINE)
# toJSON(secrets) hands a step every secret; secrets[<expression>] can name any.
_ALL_SECRETS_RE = re.compile(
    r"tojson\(\s*secrets\s*\)|" + _SECRETS + r"""\[\s*[^'"\s]""", re.IGNORECASE
)


def _workflow_files(root: Path) -> tuple[list[Path], dict[str, str]]:
    """Return (files to audit, files left out and why).

    mulder chooses the inputs itself rather than letting zizmor discover
    them: zizmor stops at the first ``.git`` it meets and honours
    ``.gitignore``, either of which lets a tree hide its own workflows.

    In a checkout, or a directory of checkouts at any depth, the inputs are
    every workflow in a ``.github/workflows`` folder and every composite
    action (``action.yml``) under ``.github`` or beside it. A directory with
    no such folder is taken to be a folder of exported workflow files, and
    its own YAML files are audited (not its subdirectories': a tree of
    unrelated YAML is not a set of workflows).

    Only regular files are audited. A symlink could point outside the
    evidence, and a FIFO would block the read.
    """
    if not root.is_dir():
        return ([root], {}) if root.is_file() and not root.is_symlink() else ([], {})
    candidates: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in _YAML_EXTS:
            continue
        parent = path.parent
        in_workflows = parent.name == "workflows" and parent.parent.name == ".github"
        is_action = path.name.lower() in _ACTION_NAMES and (
            ".github" in parent.parts or (parent / ".github").is_dir()
        )
        if in_workflows or is_action:
            candidates.append(path)
    if not any(c.parent.name == "workflows" for c in candidates):
        candidates = sorted(p for p in root.iterdir() if p.suffix.lower() in _YAML_EXTS)

    files: list[Path] = []
    left_out: dict[str, str] = {}
    for path in candidates:
        if path.is_symlink():
            left_out[str(path)] = "symlink, not followed"
        elif path.is_file():
            files.append(path)
        else:
            left_out[str(path)] = "not a regular file"
    return files, left_out


def _secrets_used(workflow: Path) -> list[str]:
    """Names of the secrets a workflow file refers to.

    ponytail: a regex over the text, so it counts a reference in a comment and
    cannot say which job uses which secret; parse the YAML per job if that
    distinction starts to matter.
    """
    try:
        if workflow.stat().st_size > _MAX_WORKFLOW_BYTES:
            return ["(not read: file larger than 1 MiB)"]
        text = workflow.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        return [f"(not read: {exc.strerror or exc})"]
    names = {dotted or quoted for dotted, quoted in _SECRET_REF_RE.findall(text)}
    if _SECRETS_INHERIT_RE.search(text):
        names.add("(all, via secrets: inherit)")
    if _ALL_SECRETS_RE.search(text):
        names.add("(all, via toJSON(secrets) or a computed name)")
    return sorted(names)


def _run_zizmor(zizmor: str, workflow: Path, timeout: float) -> tuple[list[dict[str, Any]], str]:
    """Audit one file. Returns (findings, "" or why it could not be audited)."""
    # Offline, and deaf to the evidence and to the server's own environment:
    # a zizmor.yml, an inline ignore comment or ZIZMOR_* variable would
    # otherwise hide findings or change what is audited.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("ZIZMOR_")}
    try:
        proc = subprocess.run(
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
                "--",
                str(workflow.resolve()),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return [], f"zizmor did not finish within {int(timeout)}s"
    except OSError as exc:
        return [], f"zizmor could not be run: {exc}"
    try:
        findings = json.loads(proc.stdout)
    except ValueError:
        findings = None
    if proc.returncode != 0 or not isinstance(findings, list):
        # zizmor's last WARN/error line says why: not valid YAML, not a
        # workflow, not UTF-8, more than one document (a byte-order mark).
        reasons = [ln for ln in (proc.stderr or "").splitlines() if "WARN" in ln or "rror" in ln]
        detail = _flat(reasons[0] if reasons else (proc.stderr or "no output").strip(), 200)
        return [], f"zizmor exited {proc.returncode}: {detail}"
    return [f for f in findings if isinstance(f, dict)], ""


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
def run_workflow_audit(evidence_path: str, force: bool = False) -> dict[str, object]:
    """Audit GitHub Actions workflows for exploitable weaknesses using zizmor.

    Call when the evidence holds a repository checkout or exported workflow
    files and CI may be how the attacker got in or reached credentials. Finds
    template injection of attacker-controlled input, dangerous triggers
    (pull_request_target, workflow_run), unpinned actions, excessive
    permissions and credential persistence, and lists the secrets each
    workflow refers to.

    Returns finding counts by severity and audit, the secrets map, and the
    files that could not be audited and why. Findings are indexed in
    workflow.findings, the secrets map in workflow.secrets and unaudited files
    in workflow.not_audited: a weakness in one of those is NOT ruled out.

    Args:
        evidence_path: A repository checkout (or a directory of several), a
            directory of workflow YAML files, or one workflow file.
        force: Re-run even if this path was already audited.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    name = "run_workflow_audit"
    params: dict[str, object] = {"evidence_path": evidence_path, "force": force}

    if not force:
        existing = sources_already_indexed(["workflow."], evidence_path=evidence_path)
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
    root = Path(evidence_path)
    if not root.exists():
        return error_response(
            tc_id, name, params, f"Path not found: {evidence_path}", error_type="file_not_found"
        )
    workflows, not_audited = _workflow_files(root)
    if not workflows:
        return error_response(
            tc_id,
            name,
            params,
            f"No workflow YAML found under {evidence_path}",
            error_type="no_data",
        )

    # ponytail: one process per file; batch them if a tree of thousands of
    # workflows makes the start-up cost matter.
    findings: list[dict[str, Any]] = []
    audited = 0
    for workflow in workflows:
        remaining = _TOTAL_BUDGET - (time.monotonic() - t0)
        if remaining <= 0:
            not_audited[str(workflow)] = f"time budget of {_TOTAL_BUDGET}s spent on earlier files"
            continue
        found, problem = _run_zizmor(zizmor, workflow, min(_FILE_TIMEOUT, remaining))
        if problem:
            not_audited[str(workflow)] = problem
        else:
            audited += 1
            findings.extend(found)

    elapsed = (time.monotonic() - t0) * 1000
    if not audited:
        why = "; ".join(sorted(set(not_audited.values())))[:500]
        return error_response(
            tc_id,
            name,
            params,
            f"zizmor could not audit any of {len(workflows)} files: {why}",
            elapsed,
            error_type="tool_failed",
        )

    by_severity: dict[str, int] = {}
    by_audit: dict[str, int] = {}
    for finding in findings:
        severity = str((finding.get("determinations") or {}).get("severity", "")).lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1
        ident = str(finding.get("ident", ""))
        by_audit[ident] = by_audit.get(ident, 0) + 1
    suppressed = sum(1 for f in findings if f.get("ignored"))

    lines = [line for _rank, line in sorted(_finding_line(f) for f in findings)]
    header = f"zizmor workflow audit of {evidence_path}: {len(findings)} findings"
    extract_and_index("\n".join([header, *lines]), _FINDINGS_SOURCE, evidence_path, "zizmor")

    secrets = {_flat(w, 1000): _secrets_used(w) for w in workflows}
    secret_lines = [f"{w}\t{', '.join(names) or '(none)'}" for w, names in secrets.items()]
    header = f"Secrets referenced by each workflow under {evidence_path}"
    extract_and_index("\n".join([header, *secret_lines]), _SECRETS_SOURCE, evidence_path, "zizmor")

    if not_audited:
        header = f"Not audited under {evidence_path}: {len(not_audited)} files"
        gaps = [f"{_flat(why)}\t{_flat(path, 1000)}" for path, why in sorted(not_audited.items())]
        extract_and_index("\n".join([header, *gaps]), _NOT_AUDITED_SOURCE, evidence_path, "zizmor")

    with_secrets = {w: names for w, names in secrets.items() if names}
    shown = dict(list(not_audited.items())[:_MAX_RESPONSE_WORKFLOWS])
    summary: dict[str, object] = {
        "evidence_path": evidence_path,
        "workflows_audited": audited,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_audit": dict(sorted(by_audit.items())),
        "suppressed_in_source": suppressed,
        "secrets_by_workflow": dict(list(with_secrets.items())[:_MAX_RESPONSE_WORKFLOWS]),
        # A weakness in any of these is not ruled out.
        "not_audited_count": len(not_audited),
        "not_audited": {_flat(path, 1000): why for path, why in shown.items()},
        "sources": [_FINDINGS_SOURCE, _SECRETS_SOURCE]
        + ([_NOT_AUDITED_SOURCE] if not_audited else []),
    }
    # Returned in full: the lists are capped, and the counts are what the caller acts on.
    return tool_response(tc_id, name, params, summary, None, (time.monotonic() - t0) * 1000)
