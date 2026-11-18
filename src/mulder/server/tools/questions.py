"""MCP tool for resolving the investigation questions the planners asked.

The orchestrator records each plan's questions in the case database. An
analyst closes one by naming the findings its answer rests on, so "nothing
was found" is a conclusion with evidence behind it instead of a missing
finding. Everything is validated here; the rules for what still counts as
resolved later are in :mod:`mulder.questions`.
"""

from __future__ import annotations

from typing import Literal, cast

from mulder.questions import MAX_REASON_CHARS, NEGATIVE_PREFIX, backs, clean, open_questions
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import audited_tool
from mulder.server.tool_access import ANALYSTS, Role, tool_access
from mulder.server.tools.findings import _uncitable_refs

_Resolution = Literal["answered", "ruled_out", "undetermined"]
_RESOLUTIONS = ("answered", "ruled_out", "undetermined")
_MAX_IDS_SHOWN = 10


def _refused(message: str, error_type: str = "invalid_params") -> dict[str, object]:
    """An error result; ``audited_tool`` logs it as a failed call."""
    return {"status": "error", "error_type": error_type, "error_message": message}


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

    Returns the question's resolution and how many questions remain open.

    resolution is one of:
    - "answered": the evidence shows what happened. finding_ids must name at
      least one finding of activity (not [NEGATIVE], not [COLLECT]).
    - "ruled_out": you looked for it and the sources examined do not show
      it. finding_ids must name at least one [NEGATIVE] finding that cites
      the tool calls you ran; submit that finding first. This records that
      the evidence examined did not show it, not that it did not happen.
    - "undetermined": the evidence needed to answer is not in the case or
      could not be read. Give the reason. This is not for work you skipped.

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
        return _refused(f"resolution must be one of {list(_RESOLUTIONS)}, not {resolution!r}.")

    findings = ctx.db.get_findings()
    questions = ctx.db.get_questions()
    if question_id not in {q.question_id for q in questions}:
        still_open = [q.question_id for q in open_questions(questions, findings)]
        return _refused(
            f"No investigation question has the id {question_id!r}. "
            f"Open question ids: {still_open[:_MAX_IDS_SHOWN]} ({len(still_open)} open; "
            "get_investigation_summary lists them with their text).",
            error_type="not_found",
        )

    reason = clean(reason, MAX_REASON_CHARS)
    ids: list[str] = []
    if resolution == "undetermined":
        if not reason:
            return _refused(
                "An undetermined question needs a reason: say what evidence would answer it "
                "and that it is not in the case or could not be read."
            )
    else:
        ids = list(dict.fromkeys(finding_ids or []))
        needed = (
            f"a {NEGATIVE_PREFIX} finding that cites the tool calls you ran (submit one "
            "with submit_finding if none exists)"
            if resolution == "ruled_out"
            else f"a finding of activity (not {NEGATIVE_PREFIX} or [COLLECT])"
        )
        if not ids:
            return _refused(f"'{resolution}' must name at least one finding_id: {needed}.")
        by_id = {f.finding_id: f for f in findings}
        missing = [fid for fid in ids if fid not in by_id]
        if missing:
            return _refused(f"No such finding(s): {missing}. '{resolution}' must name {needed}.")
        wrong_kind = [fid for fid in ids if not backs(resolution, by_id[fid])]
        if wrong_kind:
            return _refused(
                f"'{resolution}' must name {needed}; {wrong_kind} is not that kind of finding."
            )
        for fid in ids:
            uncitable = _uncitable_refs(ctx.audit, by_id[fid].evidence_refs)
            if uncitable:
                return _refused(
                    f"Finding {fid} cites evidence_ref(s) {uncitable} that are not successful "
                    "calls to an evidence tool, so it cannot support a resolution. Correct it "
                    "with update_finding first."
                )

    ctx.db.resolve_question(question_id, cast(_Resolution, resolution), ids, reason)
    return {
        "status": "resolved",
        "question_id": question_id,
        "resolution": resolution,
        "finding_ids": ids,
        "open_questions": len(open_questions(ctx.db.get_questions(), findings)),
    }
