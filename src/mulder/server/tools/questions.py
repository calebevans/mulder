"""MCP tool for resolving the investigation questions the planners asked.

The orchestrator records each plan's questions in the case database. An
analyst closes one by naming the findings its answer rests on, so "nothing
was found" is a conclusion with evidence behind it instead of a missing
finding. Everything is validated here; the rules for what still counts as
resolved later are in :mod:`mulder.questions`.
"""

from __future__ import annotations

from typing import Literal, cast

from mulder.audit import AuditLog
from mulder.questions import (
    MAX_REASON_CHARS,
    NEGATIVE_PREFIX,
    NO_EVIDENCE_TOOLS,
    backs,
    clean,
    open_questions,
)
from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.helpers import audited_tool
from mulder.server.tool_access import ANALYSTS, Role, tool_access
from mulder.server.tools.findings import _is_citable, _uncitable_refs

_Resolution = Literal["answered", "ruled_out", "undetermined"]
_RESOLUTIONS = ("answered", "ruled_out", "undetermined")
# What a response echoes of the caller's own arguments: the first few ids,
# and the start of each.
_MAX_IDS_SHOWN = 10
_MAX_ID_CHARS = 40


def _refused(message: str, error_type: str = "invalid_params") -> dict[str, object]:
    """An error result; ``audited_tool`` logs it as a failed call."""
    return {"status": "error", "error_type": error_type, "error_message": message}


def _listed(unusable: dict[str, str]) -> str:
    """The first few finding ids that back nothing, each with the reason."""
    shown = [f"{fid}: {why}" for fid, why in list(unusable.items())[:_MAX_IDS_SHOWN]]
    more = len(unusable) - len(shown)
    return "; ".join(shown) + (f"; and {more} more" if more else "")


@mcp.tool()
@tool_access(ANALYSTS | Role.REPORT)
@audited_tool("resolve_question")
def resolve_question(
    question_id: str,
    resolution: str,
    finding_ids: list[str] | None = None,
    reason: str = "",
) -> dict[str, object]:
    """Record how an investigation question was resolved and what the answer rests on.

    Call for each question the planner asked, once you can say what the
    evidence shows about it. Question ids look like q_1a2b3c4d: they prefix
    the questions in your instructions, and get_investigation_summary lists
    the ones still open. Calling again replaces the earlier resolution.

    Returns the question's resolution, the findings it was recorded against,
    any finding_ids that were ignored and why, and how many questions remain
    open.

    resolution is one of:
    - "answered": the evidence shows what happened. finding_ids must name at
      least one finding of activity (not [NEGATIVE], not [COLLECT]).
    - "ruled_out": the sources examined were searched for it and do not
      show it. finding_ids must name at least one [NEGATIVE] finding that
      cites those tool calls. If none exists, submit one first; if you
      cannot submit findings, use "undetermined". This records that the
      evidence examined did not show it, not that it did not happen.
    - "undetermined": the evidence needed to answer is not in the case or
      could not be read. Give the reason. This is not for work you skipped.

    For "answered" and "ruled_out", a finding that cites only calls that
    examine no evidence (open_case, list_sources, get_investigation_summary,
    get_ioc_summary, get_bookmarks, the audits and the like) does not count:
    it must cite at least one call that extracted, searched or read evidence.

    A resolution holds only while the findings it names exist: if one is
    deleted or stops being the right kind, the question is open again.

    Args:
        question_id: The question to resolve.
        resolution: "answered", "ruled_out" or "undetermined".
        finding_ids: Findings the answer rests on. Required for "answered"
            and "ruled_out"; ignored for "undetermined".
        reason: Required for "undetermined": what evidence is missing.
            Optional otherwise.
    """
    ctx = get_ctx()
    if resolution not in _RESOLUTIONS:
        return _refused(
            f"resolution must be one of {list(_RESOLUTIONS)}, "
            f"not {str(resolution)[:_MAX_ID_CHARS]!r}."
        )

    # The prompts show an id in square brackets, and it arrives that way.
    question_id = str(question_id).strip().strip("[]")
    findings = ctx.db.get_findings()
    questions = ctx.db.get_questions()
    if question_id not in {q.question_id for q in questions}:
        still_open = [q.question_id for q in open_questions(questions, findings)]
        return _refused(
            f"No investigation question has the id {question_id[:_MAX_ID_CHARS]!r}. "
            f"Open question ids: {still_open[:_MAX_IDS_SHOWN]} ({len(still_open)} open; "
            "get_investigation_summary lists them with their text).",
            error_type="not_found",
        )

    reason = clean(reason, MAX_REASON_CHARS)
    backing: list[str] = []
    unusable: dict[str, str] = {}
    if resolution == "undetermined":
        if not reason:
            return _refused(
                "An undetermined question needs a reason: say what evidence would answer it "
                "and that it is not in the case or could not be read."
            )
    else:
        ids = list(dict.fromkeys(fid for fid in finding_ids or [] if isinstance(fid, str)))
        by_id = {f.finding_id: f for f in findings}
        audit = ctx.audit
        refs = [ref for fid in ids if fid in by_id for ref in by_id[fid].evidence_refs]
        if not all(audit.has_tool_call(ref) for ref in refs):
            # A server reads the audit log once, when it opens the case. A
            # call that another session's server has logged since is in the
            # file and not in this index, so read the file again.
            audit = AuditLog(get_cfg().db_dir / f"{ctx.case_id}.audit.jsonl")
        for fid in ids:
            finding = by_id.get(fid)
            if finding is None:
                why = "no such finding"
            elif not backs(resolution, finding):
                why = "not that kind of finding"
            elif uncitable := _uncitable_refs(audit, finding.evidence_refs):
                shown = [ref[:_MAX_ID_CHARS] for ref in uncitable[:_MAX_IDS_SHOWN]]
                why = f"cites {shown}, not successful calls to an evidence tool"
            # A finding may cite any successful call, bookkeeping included.
            # Resting a question on it takes more: something has to have
            # looked.
            elif not any(
                _is_citable(audit, ref, refused=NO_EVIDENCE_TOOLS) for ref in finding.evidence_refs
            ):
                why = "cites no call that extracted, searched or read evidence"
            else:
                backing.append(fid)
                continue
            unusable[fid[:_MAX_ID_CHARS]] = why
        if not backing:
            # The report role resolves questions too and cannot submit
            # findings, so the message must not send every caller to
            # submit_finding.
            needed = (
                f"a {NEGATIVE_PREFIX} finding that cites the tool calls that looked for it (if "
                "none exists, submit one first, or use 'undetermined' if you cannot submit "
                "findings)"
                if resolution == "ruled_out"
                else f"a finding of activity (not {NEGATIVE_PREFIX} or [COLLECT]) that cites a "
                "tool call that extracted, searched or read evidence"
            )
            return _refused(
                f"'{resolution}' must name at least one finding_id: {needed}."
                + (f" None of those named is one ({_listed(unusable)})." if unusable else "")
            )

    ctx.db.resolve_question(question_id, cast(_Resolution, resolution), backing, reason)
    result: dict[str, object] = {
        "status": "resolved",
        "question_id": question_id,
        "resolution": resolution,
        "finding_ids": backing,
        "open_questions": len(open_questions(ctx.db.get_questions(), findings)),
    }
    if unusable:
        result["ignored_finding_ids"] = _listed(unusable)
    return result
