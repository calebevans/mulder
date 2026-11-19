"""Investigation questions: when one is resolved, and the no-incident outcome.

Planners ask questions; analysts resolve each one against findings. That
gives an investigation a second, explicit way to finish: every question
resolved, instead of a minimum number of findings. The finalize gates, the
investigation summary and the report renderer all decide through the pure
functions here, so they cannot disagree.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence

from mulder.models import Finding, Question

# The same title prefixes as server/tools/findings.py.
NEGATIVE_PREFIX = "[NEGATIVE]"
NON_EVENT_PREFIXES = (NEGATIVE_PREFIX, "[COLLECT]")

MIN_NON_NEGATIVE_FINDINGS = 3
AUDIT_TOOLS = ("audit_evidence_coverage", "audit_tool_coverage")
# A finding at one of these severities describes activity that needs an
# explanation; a case holding one is not reported as "no incident".
SIGNIFICANT_SEVERITIES = ("critical", "high", "medium")

# Tools whose calls examine no evidence: case, job and progress bookkeeping,
# the audits, reference lookups, the findings tools, and the tools that read
# back what the investigation itself wrote. A finding that cites only these
# looked at nothing, so it cannot answer a question or rule one out, and the
# report does not count these calls as examination. A tool missing from this
# set counts as an evidence tool, which is how every tool was treated before
# the set existed.
NO_EVIDENCE_TOOLS = frozenset(
    {
        "open_case",
        "list_cases",
        "list_sources",
        "get_source_stats",
        "get_investigation_summary",
        "check_finalize_readiness",
        "audit_evidence_coverage",
        "audit_tool_coverage",
        "track_progress",
        "bookmark_window",
        "remove_bookmark",
        "start_extraction_batch",
        "check_extraction_status",
        "wait",
        "wait_all",
        "get_tool_guide",
        "lookup_attack_technique",
        "enrich_iocs",  # asks outside services about an indicator
        "verify_evidence_integrity",  # re-hashes the index; reports no content
        # Bookmarks are windows another call already returned, and there may
        # be none. The IOC summary is drawn from the findings' own text.
        "get_bookmarks",
        "get_ioc_summary",
        # server/tools/findings.py _FINDING_TOOLS
        "submit_finding",
        "update_finding",
        "delete_finding",
        "get_findings",
        "submit_narrative",
        "finalize_report",
        "deduplicate_findings",
        "resolve_question",
    }
)

# The id labels a recorded question is handed to its analyst with, as they
# come back at the start of a question a later planner copied.
ID_LABELS = re.compile(r"^\s*(?:\[q_[0-9a-f]{8}\]\s*)+")

MAX_QUESTION_CHARS = 500
MAX_SYSTEM_CHARS = 200
MAX_REASON_CHARS = 1000
MAX_QUESTIONS_PER_PLAN = 20


def clean(text: object, max_len: int) -> str:
    """Flatten model-written text to one printable line of at most *max_len*.

    Questions and reasons are written by a model that has read evidence, and
    are shown to later models and in the report. Anything that is not a
    string becomes "".
    """
    if not isinstance(text, str):
        return ""
    printable = "".join(c if c.isprintable() else " " for c in text)
    return " ".join(printable.split())[:max_len]


def is_positive(finding: Finding) -> bool:
    """True for a finding of activity: neither [NEGATIVE] nor [COLLECT]."""
    return not finding.title.startswith(NON_EVENT_PREFIXES)


def backs(resolution: str, finding: Finding) -> bool:
    """True if *finding* is the kind of finding *resolution* has to rest on."""
    if resolution == "ruled_out":
        return finding.title.startswith(NEGATIVE_PREFIX)
    return is_positive(finding)


def statuses(questions: Sequence[Question], findings: Sequence[Finding]) -> list[str]:
    """Each question's status now: open, answered, ruled_out or undetermined.

    An answered or ruled-out resolution holds only while one of the findings
    it names still exists and is still the right kind. Deleting that finding,
    or retitling a [NEGATIVE] one because the hypothesis turned out true,
    reopens the question rather than leaving a conclusion with nothing
    behind it.
    """
    by_id = {f.finding_id: f for f in findings}
    result: list[str] = []
    for q in questions:
        resolution = q.resolution
        if resolution in ("answered", "ruled_out") and not any(
            fid in by_id and backs(resolution, by_id[fid]) for fid in q.finding_ids
        ):
            resolution = None
        result.append(resolution or "open")
    return result


def open_questions(questions: Sequence[Question], findings: Sequence[Finding]) -> list[Question]:
    """The questions that are open now, in the order they were recorded."""
    current = statuses(questions, findings)
    return [q for q, status in zip(questions, current, strict=True) if status == "open"]


def resolved_path(
    questions: Sequence[Question],
    findings: Sequence[Finding],
    tool_call_counts: Mapping[str, int],
) -> bool:
    """The second way to pass the minimum_findings gate.

    At least one question is recorded, none is open, and both coverage
    audits have been run.
    """
    return (
        bool(questions)
        and not open_questions(questions, findings)
        and all(tool in tool_call_counts for tool in AUDIT_TOOLS)
    )


def no_incident(
    questions: Sequence[Question],
    findings: Sequence[Finding],
    tool_call_counts: Mapping[str, int],
    unanalysed: Collection[str] = (),
) -> bool:
    """True when the report may say no evidence of an incident was found.

    The case passes only by the second path (too few findings for the
    first), holds no finding of activity at medium severity or above, and
    has at least one question that was answered or ruled out. The second
    path alone is not enough. It also passes with one or two findings of any
    severity, and a case with a high-severity finding has found something.
    It passes when every question is undetermined too, and a case where
    nothing could be examined has not found that nothing happened.

    Never while a system is *unanalysed* (``CaseDB.get_unanalysed``): a
    plan for it was rejected for having no questions and none reached an
    analyst, so it has no question on record to be left open, and what was
    not analysed has not been found clean.
    """
    positive = [f for f in findings if is_positive(f)]
    return (
        not unanalysed
        and len(positive) < MIN_NON_NEGATIVE_FINDINGS
        and not any(f.severity in SIGNIFICANT_SEVERITIES for f in positive)
        and resolved_path(questions, findings, tool_call_counts)
        and any(status != "undetermined" for status in statuses(questions, findings))
    )
