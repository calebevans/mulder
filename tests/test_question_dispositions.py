"""An investigation can conclude that nothing happened.

The planners' questions are recorded, analysts resolve each one against
findings, and a case whose questions are all resolved passes the gates
without the minimum number of findings. Cases with no recorded questions
are gated exactly as before.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import mulder.server.app as server_app
from mulder import questions as rules
from mulder.audit import AuditLog
from mulder.cli import cli
from mulder.db import CaseDB
from mulder.models import AuditSummary, CaseMetadataRow, Finding, Question, SourceRow
from mulder.orchestrator import prompts
from mulder.orchestrator.evidence import ServerBridge
from mulder.orchestrator.gates import GateResult, validate_cross_system
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.phases import EXTRACTION
from mulder.orchestrator.roles import RoleRunner
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import ExecutionResults, PhaseResult, Plan
from mulder.questions import MAX_QUESTION_CHARS, clean, no_incident, resolved_path, statuses
from mulder.server.app import _tool_dispatch_sync
from mulder.server.extract_helpers import extract_and_index
from mulder.server.tool_access import ALL_ROLES, ANALYSTS, Role, get_tools_for_role
from mulder.server.tools.findings import (
    _FINDING_TOOLS,
    _MIN_NON_NEGATIVE_FINDINGS,
    _NEGATIVE_PREFIX,
    _NON_EVENT_PREFIXES,
    _evaluate_finalize_gates,
    _is_citable,
)

AUDITS = {"audit_evidence_coverage": 1, "audit_tool_coverage": 1}
STATEMENT = "No evidence of an incident was found in the evidence examined."


def _finding(finding_id: str, title: str, severity: str = "info") -> Finding:
    return Finding(
        finding_id=finding_id,
        case_id="clean",
        title=title,
        description="what the tool calls showed",
        severity=severity,  # type: ignore[arg-type]
        confidence="inference",
        evidence_refs=["tc_search01"],
        sources=["evtx.security"],
        event_time_start="2026-03-01T09:00:00Z",
        submitted_at="2026-03-02T00:00:00Z",
    )


def _question(question_id: str, resolution: str | None = None, *finding_ids: str) -> Question:
    return Question(
        question_id=question_id,
        phase="extraction",
        system="WS01",
        question=f"question {question_id}",
        resolution=resolution,  # type: ignore[arg-type]
        finding_ids=list(finding_ids),
        reason="no network capture in the case" if resolution == "undetermined" else "",
    )


def _gate(
    findings: list[Finding],
    questions: list[Question] | None = None,
    tool_calls: dict[str, int] | None = None,
) -> dict[str, object]:
    """The minimum_findings gate for these findings and questions."""
    metadata = CaseMetadataRow(
        case_id="clean",
        ingested_at="2026-03-01T00:00:00Z",
        evidence_root="/evidence",
        extractor_versions={},
        narrative="Report.",
    )
    counts = AUDITS if tool_calls is None else tool_calls
    audit = AuditSummary(
        total_tool_calls=sum(counts.values()),
        total_findings=0,
        tool_call_counts=counts,
        total_duration_ms=0.0,
        first_timestamp="",
        last_timestamp="",
    )
    sources: list[SourceRow] = []
    if questions is None:
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit)
    else:
        gates = _evaluate_finalize_gates(findings, metadata, sources, audit, questions)
    return next(g for g in gates if g["name"] == "minimum_findings")


NEGATIVE = _finding("f_neg", "[NEGATIVE] No persistence mechanism on WS01")
COLLECT = _finding("f_col", "[COLLECT] Firewall log for the WS01 subnet")
LOW = _finding("f_low", "Guest account enabled", "low")
HIGH = _finding("f_high", "Unauthorised remote logon", "high")


# ---------------------------------------------------------------------------
# What counts as resolved
# ---------------------------------------------------------------------------


def test_a_resolution_holds_only_while_a_finding_of_the_right_kind_is_behind_it() -> None:
    questions = [
        _question("q_open"),
        _question("q_ruled", "ruled_out", "f_neg"),
        _question("q_ans", "answered", "f_low"),
        _question("q_und", "undetermined"),
        _question("q_gone", "ruled_out", "f_deleted"),
        # the hypothesis turned out true and the finding was retitled
        _question("q_flip", "ruled_out", "f_low"),
        _question("q_wrong", "answered", "f_neg", "f_col"),
    ]

    assert statuses(questions, [NEGATIVE, COLLECT, LOW]) == [
        "open",
        "ruled_out",
        "answered",
        "undetermined",
        "open",
        "open",
        "open",
    ]


def test_the_kinds_of_finding_are_the_ones_the_findings_tools_use() -> None:
    """mulder.questions cannot import the tool module, so it repeats two prefixes."""
    assert rules.NEGATIVE_PREFIX == _NEGATIVE_PREFIX
    assert rules.NON_EVENT_PREFIXES == _NON_EVENT_PREFIXES
    assert rules.MIN_NON_NEGATIVE_FINDINGS == _MIN_NON_NEGATIVE_FINDINGS == 3


def test_question_text_is_flattened_and_bounded() -> None:
    assert clean("Was  there\n\tpersistence?\x00\x1b[31m", 100) == "Was there persistence? [31m"
    assert len(clean("x" * 5000, MAX_QUESTION_CHARS)) == MAX_QUESTION_CHARS
    assert clean({"q": "not a string"}, 100) == clean(None, 100) == ""


# ---------------------------------------------------------------------------
# minimum_findings: the count, or every question resolved
# ---------------------------------------------------------------------------


def test_a_case_with_no_questions_is_gated_exactly_as_before() -> None:
    """The literal details from before questions existed, for both outcomes."""
    for findings, expected in (
        (
            [NEGATIVE],
            {
                "name": "minimum_findings",
                "passed": False,
                "detail": "Only 0 non-negative findings submitted, need at least 3. "
                "Submit more findings with submit_finding before finalizing.",
            },
        ),
        (
            [LOW, HIGH, _finding("f_3", "Third")],
            {
                "name": "minimum_findings",
                "passed": True,
                "detail": "3 non-negative findings submitted (minimum 3)",
            },
        ),
    ):
        assert _gate(findings) == _gate(findings, []) == expected


def test_three_findings_pass_on_the_count_whatever_the_questions_say() -> None:
    findings = [LOW, HIGH, _finding("f_3", "Third")]

    gate = _gate(findings, [_question("q_open")])

    assert gate == {
        "name": "minimum_findings",
        "passed": True,
        "detail": "3 non-negative findings submitted (minimum 3)",
    }


def test_resolved_questions_pass_without_the_count_and_the_detail_says_so() -> None:
    questions = [_question("q_1", "ruled_out", "f_neg"), _question("q_2", "undetermined")]

    gate = _gate([NEGATIVE], questions)

    assert gate["passed"] is True
    assert str(gate["detail"]).startswith("Passed on resolved questions, not on the finding count")
    assert "all 2 recorded investigation question(s)" in str(gate["detail"])


@pytest.mark.parametrize(
    ("questions", "tool_calls"),
    [
        ([_question("q_1", "ruled_out", "f_neg"), _question("q_2")], AUDITS),  # one open
        ([_question("q_1", "ruled_out", "f_gone")], AUDITS),  # its finding was deleted
        ([_question("q_1", "ruled_out", "f_neg")], {"audit_tool_coverage": 1}),  # one audit
        ([_question("q_1", "ruled_out", "f_neg")], {}),  # no audits
    ],
)
def test_the_second_path_needs_every_question_resolved_and_both_audits(
    questions: list[Question], tool_calls: dict[str, int]
) -> None:
    gate = _gate([NEGATIVE], questions, tool_calls)

    assert gate["passed"] is False
    assert not resolved_path(questions, [NEGATIVE], tool_calls)
    # A failing gate names both ways out, so a remediation session is not
    # told only to submit more findings.
    assert "resolve_question" in str(gate["detail"])
    assert "audit_evidence_coverage and audit_tool_coverage" in str(gate["detail"])
    # The report role reads this detail too, and cannot submit findings.
    assert "If you cannot, resolve a question that no finding addresses as undetermined" in str(
        gate["detail"]
    )


def test_a_failing_gate_lists_the_open_question_ids() -> None:
    questions = [_question("q_1", "ruled_out", "f_neg"), _question("q_2"), _question("q_3")]

    detail = str(_gate([NEGATIVE], questions)["detail"])

    assert "(2 of 3 open: q_2, q_3)" in detail


def test_no_incident_is_the_second_path_with_nothing_of_medium_severity_or_above() -> None:
    resolved = [_question("q_1", "ruled_out", "f_neg")]

    assert no_incident(resolved, [NEGATIVE, COLLECT, LOW], AUDITS)
    # The second path passes with a high finding; the report must not then
    # say no incident was found.
    assert resolved_path(resolved, [NEGATIVE, HIGH], AUDITS)
    assert not no_incident(resolved, [NEGATIVE, HIGH], AUDITS)
    # Passed on the count: the first path, reported as it always was.
    assert not no_incident(resolved, [NEGATIVE, LOW, LOW, LOW], AUDITS)
    assert not no_incident(resolved, [NEGATIVE], {})
    assert not no_incident([], [NEGATIVE], AUDITS)
    # Nothing could be examined: the gate passes, and the report claims nothing.
    unanswerable = [_question("q_1", "undetermined"), _question("q_2", "undetermined")]
    assert resolved_path(unanswerable, [], AUDITS)
    assert not no_incident(unanswerable, [], AUDITS)


# ---------------------------------------------------------------------------
# Cross-system gate
# ---------------------------------------------------------------------------


def _summary(**overrides: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "findings_submitted": 2,
        "findings_with_mitre_ids": 0,
        "questions": {"recorded": 4, "open": 0},
        "significant_findings": 0,
    }
    summary.update(overrides)
    return summary


def test_cross_system_gate_without_questions_is_unchanged() -> None:
    passing = validate_cross_system({"findings_submitted": 5, "findings_with_mitre_ids": 3})
    failing = validate_cross_system({"findings_submitted": 0, "findings_with_mitre_ids": 0})

    assert passing.passed
    assert [c.detail for c in passing.checks] == [
        "5 total finding(s) after cross-system analysis",
        "3 finding(s) mapped to MITRE ATT&CK",
    ]
    assert not failing.passed
    assert failing.gaps == [
        "No findings exist after cross-system analysis.",
        "No findings have MITRE ATT&CK technique mappings.",
    ]


def test_cross_system_gate_passes_a_clean_case_with_nothing_to_map() -> None:
    result = validate_cross_system(_summary())

    assert result.passed
    findings, mitre = result.checks
    assert findings.detail == "2 total finding(s) after cross-system analysis"
    assert "passed on resolved questions: all 4 recorded question(s) resolved" in mitre.detail


def test_cross_system_gate_passes_with_no_findings_when_every_question_is_resolved() -> None:
    result = validate_cross_system(_summary(findings_submitted=0))

    assert result.passed
    assert all("passed on resolved questions" in c.detail for c in result.checks)


def test_cross_system_gate_still_wants_a_mapping_when_something_was_found() -> None:
    result = validate_cross_system(_summary(significant_findings=1))

    assert not result.passed
    assert result.gaps == ["No findings have MITRE ATT&CK technique mappings."]


def test_cross_system_gate_points_a_quiet_case_at_its_open_questions() -> None:
    result = validate_cross_system(_summary(questions={"recorded": 4, "open": 3}))

    assert not result.passed
    assert "resolve the 3 open investigation question(s) with resolve_question" in result.gaps[0]


# ---------------------------------------------------------------------------
# The case database
# ---------------------------------------------------------------------------


def test_questions_are_stored_once_per_phase_and_system(tmp_case_db: CaseDB) -> None:
    first = tmp_case_db.record_questions("extraction", "WS01", ["Persistence?", "Exfil?"])
    again = tmp_case_db.record_questions("extraction", "WS01", ["Exfil?", "Exfil?", "New?"])
    other = tmp_case_db.record_questions("extraction", "WS02", ["Persistence?"])

    assert [q.question for q in again] == ["Exfil?", "New?"]
    assert again[0].question_id == first[1].question_id
    assert other[0].question_id != first[0].question_id
    assert re.fullmatch(r"q_[0-9a-f]{8}", first[0].question_id)
    stored = tmp_case_db.get_questions()
    assert [(q.system, q.question, q.resolution) for q in stored] == [
        ("WS01", "Persistence?", None),
        ("WS01", "Exfil?", None),
        ("WS01", "New?", None),
        ("WS02", "Persistence?", None),
    ]


def test_a_case_from_before_questions_were_recorded_has_none(tmp_path: Path) -> None:
    """``mulder report`` opens the database without running migrations."""
    CaseDB.create("old", "/evidence", tmp_path).close()
    with sqlite3.connect(tmp_path / "old.db") as conn:
        conn.execute("DROP TABLE investigation_questions")

    with CaseDB(tmp_path / "old.db") as unmigrated:
        assert unmigrated.get_questions() == []
    with CaseDB.open("old", tmp_path) as migrated:
        assert migrated.record_questions("extraction", "", ["Anything?"])


# ---------------------------------------------------------------------------
# A live case: the orchestrator's bridge and the real tools
# ---------------------------------------------------------------------------


def _tool(name: str, **kwargs: Any) -> dict[str, Any]:
    result: dict[str, Any] = _tool_dispatch_sync[name](**kwargs)
    return result


class _Case:
    """A real case database, opened the way the orchestrator opens it."""

    def __init__(self, root: Path) -> None:
        self.db_dir = root / "cases"
        self.evidence = root / "evidence"
        self.evidence.mkdir()
        CaseDB.create("clean", str(self.evidence), self.db_dir).close()
        self.bridge = ServerBridge("clean", self.db_dir)
        self.bridge.ensure_context()
        for name in ("evtx.security", "registry.software", "tsk.fls"):
            extract_and_index(
                f"{name} line 1\n{name} line 2\n", name, str(self.evidence / "ws01.E01"), "test"
            )

    def ask(self, *questions: str) -> list[str]:
        """Record questions for WS01 and return their ids."""
        labelled = self.bridge.record_questions("extraction", "WS01", list(questions))
        return [re.match(r"\[(q_[0-9a-f]{8})\] ", q).group(1) for q in labelled]  # type: ignore[union-attr]

    def searched(self, query: str) -> str:
        """Run a real search and return its tool_call_id."""
        return str(_tool("search", query=query)["tool_call_id"])

    def finding(self, title: str, ref: str, source: str, severity: str = "info") -> str:
        result = _tool(
            "submit_finding",
            title=title,
            description=f"{title}: searched {source}.",
            severity=severity,
            confidence="inference",
            evidence_refs=[ref],
            sources=[source],
            event_time_start=None if title.startswith("[") else "2026-03-01T09:15:42Z",
        )
        return str(result["finding_id"])

    def audit(self) -> None:
        assert _tool("audit_evidence_coverage")["status"] == "success"
        assert _tool("audit_tool_coverage")["status"] == "success"

    def minimum_findings(self) -> dict[str, Any]:
        gates = _tool("check_finalize_readiness")["gates"]
        gate: dict[str, Any] = next(g for g in gates if g["name"] == "minimum_findings")
        return gate

    def clean_case(self) -> None:
        """Three questions resolved with nothing found, audits run, narrative written."""
        q_persist, q_lateral, q_exfil = self.ask(
            "Was any persistence mechanism installed?",
            "Is there evidence of lateral movement?",
            "Was data sent to an external address?",
        )
        persistence = self.finding(
            "[NEGATIVE] No persistence mechanism on WS01",
            self.searched("CurrentVersion Run"),
            "registry.software",
        )
        lateral = self.finding(
            "[NEGATIVE] No remote logon or service install on WS01",
            self.searched("4624 7045"),
            "evtx.security",
        )
        self.finding("[COLLECT] Firewall log for the WS01 subnet", self.searched("fw"), "tsk.fls")
        for question_id, finding_id in ((q_persist, persistence), (q_lateral, lateral)):
            resolved = _tool(
                "resolve_question",
                question_id=question_id,
                resolution="ruled_out",
                finding_ids=[finding_id],
            )
            assert resolved["status"] == "resolved"
        _tool(
            "resolve_question",
            question_id=q_exfil,
            resolution="undetermined",
            reason="No network capture or firewall log is in the case.",
        )
        self.audit()
        _tool("submit_narrative", narrative="## Background\n\nRoutine review of WS01.")


@pytest.fixture()
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Case]:
    monkeypatch.setattr(server_app, "_cfg", None)
    monkeypatch.setattr(server_app, "_ctx", None)
    monkeypatch.setattr(server_app, "_job_store", None)
    live = _Case(tmp_path)
    yield live
    live.bridge.cleanup()


def test_the_bridge_records_questions_and_labels_them_for_the_analyst(case: _Case) -> None:
    planned = ["Was  persistence\ninstalled?", {"q": "not a string"}, "", "Any exfiltration?"]

    labelled = case.bridge.record_questions("extraction", "WS01", planned)

    assert re.fullmatch(r"\[q_[0-9a-f]{8}\] Was persistence installed\?", labelled[0])
    assert labelled[1:3] == [{"q": "not a string"}, ""]  # passed through as planned
    assert labelled[3].endswith("] Any exfiltration?")
    stored = server_app.get_ctx().db.get_questions()
    assert [(q.phase, q.system, q.question) for q in stored] == [
        ("extraction", "WS01", "Was persistence installed?"),
        ("extraction", "WS01", "Any exfiltration?"),
    ]


def test_questions_pass_through_unchanged_when_they_cannot_be_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(server_app, "_cfg", None)
    monkeypatch.setattr(server_app, "_ctx", None)
    bridge = ServerBridge("no-such-case", tmp_path)

    assert bridge.record_questions("extraction", "WS01", ["Anything?"]) == ["Anything?"]
    malformed: Any = "a planner that wrote a string, not a list"
    assert bridge.record_questions("extraction", "WS01", malformed) is malformed


@pytest.mark.parametrize(
    ("kwargs", "error_type", "message"),
    [
        ({"resolution": "closed"}, "invalid_params", "resolution must be one of"),
        ({"question_id": "q_00000000"}, "not_found", "No investigation question has the id"),
        ({"resolution": "answered"}, "invalid_params", "must name at least one finding_id"),
        # The report role calls this too and has no submit_finding.
        ({"resolution": "ruled_out", "finding_ids": []}, "invalid_params", "if you cannot submit"),
        ({"resolution": "answered", "finding_ids": ["f_nope"]}, "invalid_params", "no such"),
        ({"resolution": "answered", "finding_ids": ["NEG"]}, "invalid_params", "not that kind"),
        ({"resolution": "answered", "finding_ids": ["COL"]}, "invalid_params", "not that kind"),
        ({"resolution": "ruled_out", "finding_ids": ["POS"]}, "invalid_params", "not that kind"),
        ({"resolution": "ruled_out", "finding_ids": ["COL"]}, "invalid_params", "not that kind"),
        ({"resolution": "undetermined", "reason": " \n "}, "invalid_params", "needs a reason"),
    ],
)
def test_resolve_question_refuses_what_it_cannot_stand_behind(
    case: _Case, kwargs: dict[str, Any], error_type: str, message: str
) -> None:
    (question_id,) = case.ask("Was any persistence mechanism installed?")
    ref = case.searched("Run")
    named = {
        "NEG": case.finding("[NEGATIVE] No persistence", ref, "registry.software"),
        "COL": case.finding("[COLLECT] Firewall log", ref, "tsk.fls"),
        "POS": case.finding("Guest account enabled", ref, "registry.software", "low"),
    }
    call = {"question_id": question_id, "resolution": "ruled_out", **kwargs}
    if "finding_ids" in call:
        call["finding_ids"] = [named.get(fid, fid) for fid in call["finding_ids"]]

    result = _tool("resolve_question", **call)

    assert result["status"] == "error"
    assert result["error_type"] == error_type
    assert message in result["error_message"]
    assert server_app.get_ctx().db.get_questions()[0].resolution is None


def test_a_finding_that_cites_no_real_evidence_call_cannot_close_a_question(case: _Case) -> None:
    """The existing citation check, applied again when a question rests on the finding."""
    (question_id,) = case.ask("Was any persistence mechanism installed?")
    forged = NEGATIVE.model_copy(update={"evidence_refs": ["tc_never_ran"]})
    server_app.get_ctx().db.insert_finding(forged)

    result = _tool(
        "resolve_question",
        question_id=question_id,
        resolution="ruled_out",
        finding_ids=[forged.finding_id],
    )

    assert result["status"] == "error"
    assert "tc_never_ran" in result["error_message"]


def test_resolving_is_bookkeeping_and_cannot_be_cited_as_evidence(case: _Case) -> None:
    (question_id,) = case.ask("Was data sent to an external address?")
    resolved = _tool(
        "resolve_question",
        question_id=question_id,
        resolution="undetermined",
        reason="No network capture in the case.",
    )

    assert resolved["open_questions"] == 0
    assert not _is_citable(server_app.get_ctx().audit, resolved["tool_call_id"])


def test_a_question_reopens_when_its_finding_goes_and_can_be_resolved_again(case: _Case) -> None:
    (question_id,) = case.ask("Was any persistence mechanism installed?")
    ref = case.searched("Run")
    negative = case.finding("[NEGATIVE] No persistence", ref, "registry.software")
    _tool(
        "resolve_question", question_id=question_id, resolution="ruled_out", finding_ids=[negative]
    )
    assert _tool("get_investigation_summary")["questions"]["ruled_out"] == 1

    # The hypothesis turned out true: the finding is no longer a negative.
    _tool("update_finding", finding_id=negative, title="Run key persistence", severity="low")

    summary = _tool("get_investigation_summary")
    assert summary["questions"]["open"] == 1
    assert "Was ruled_out" in summary["open_questions"][0]["note"]

    answered = _tool(
        "resolve_question", question_id=question_id, resolution="answered", finding_ids=[negative]
    )
    assert answered["open_questions"] == 0


def test_a_merge_carries_the_question_to_the_surviving_finding(case: _Case) -> None:
    (question_id,) = case.ask("Was any persistence mechanism installed?")
    ref = case.searched("Run")
    kept = case.finding("[NEGATIVE] No persistence mechanism on WS01", ref, "registry.software")
    absorbed = case.finding("[NEGATIVE] No persistence mechanism WS01", ref, "registry.software")
    # Enough unrelated findings that merging one stays under the 25% guard.
    for title, source in (
        ("Guest account enabled", "registry.software"),
        ("Audit policy logs failures only", "evtx.security"),
        ("Browser extension sideloaded", "tsk.fls"),
    ):
        case.finding(title, case.searched(title), source, "low")
    _tool(
        "resolve_question", question_id=question_id, resolution="ruled_out", finding_ids=[absorbed]
    )

    merged = _tool("deduplicate_findings", case_id="clean")

    survivor = merged["groups"][0]["representative_id"]
    assert {survivor, *merged["groups"][0]["merged_ids"]} == {kept, absorbed}
    (question,) = server_app.get_ctx().db.get_questions()
    assert question.finding_ids == [survivor]
    assert _tool("get_investigation_summary")["questions"]["ruled_out"] == 1


def test_the_summary_lists_open_questions_and_says_when_it_is_not_all_of_them(
    case: _Case,
) -> None:
    case.ask("Why " + "x" * 600 + "?", *(f"Question number {i}?" for i in range(19)))
    case.bridge.record_questions("cross_system", "", [f"Cross question {i}?" for i in range(10)])

    summary = _tool("get_investigation_summary")

    assert summary["questions"] == {
        "recorded": 30,
        "open": 30,
        "answered": 0,
        "ruled_out": 0,
        "undetermined": 0,
    }
    assert len(summary["open_questions"]) == 15
    first = summary["open_questions"][0]
    assert first.keys() == {"question_id", "phase", "system", "question"}
    assert len(first["question"]) == 200 + len("... [truncated]")
    assert summary["open_questions_note"].startswith("Showing 15 of 30 open questions")
    assert "no_incident" not in summary


def test_a_case_with_no_questions_gets_the_summary_and_the_refusal_it_always_got(
    case: _Case,
) -> None:
    case.finding("[NEGATIVE] No persistence", case.searched("Run"), "registry.software")
    case.audit()
    _tool("submit_narrative", narrative="Nothing found.")

    summary = _tool("get_investigation_summary")
    refused = _tool("finalize_report")

    assert not {"questions", "open_questions", "significant_findings", "no_incident"} & set(
        summary
    )
    assert refused["status"] == "blocked"
    assert refused["error_message"] == (
        "Gate 'minimum_findings' failed: Only 0 non-negative findings submitted, need at "
        "least 3. Submit more findings with submit_finding before finalizing."
    )
    assert not (case.db_dir / "clean.report.md").exists()


def test_a_clean_case_passes_the_gates_and_renders(case: _Case) -> None:
    """Nothing happened on WS01, and the investigation is allowed to say so."""
    q_persist, q_lateral, q_exfil = case.ask(
        "Was any persistence mechanism installed?",
        "Is there evidence of lateral movement?",
        "Was data sent to an external address?",
    )
    persistence = case.finding(
        "[NEGATIVE] No persistence mechanism on WS01",
        case.searched("CurrentVersion Run"),
        "registry.software",
    )
    lateral = case.finding(
        "[NEGATIVE] No remote logon or service install on WS01",
        case.searched("4624 7045"),
        "evtx.security",
    )
    case.finding("[COLLECT] Firewall log for the WS01 subnet", case.searched("fw"), "tsk.fls")
    _tool(
        "resolve_question",
        question_id=q_persist,
        resolution="ruled_out",
        finding_ids=[persistence],
    )
    _tool("resolve_question", question_id=q_lateral, resolution="ruled_out", finding_ids=[lateral])

    # One question open and no audits yet: not ready, and it says how to be.
    blocked = case.minimum_findings()
    assert blocked["passed"] is False
    assert f"(1 of 3 open: {q_exfil})" in blocked["detail"]

    _tool(
        "resolve_question",
        question_id=q_exfil,
        resolution="undetermined",
        reason="No network capture or firewall log is in the case.",
    )
    assert case.minimum_findings()["passed"] is False  # the audits are still owed
    case.audit()
    _tool("submit_narrative", narrative="## Background\n\nRoutine review of WS01.")

    readiness = _tool("check_finalize_readiness")
    assert readiness["ready_to_finalize"] is True, readiness["gates"]
    assert case.minimum_findings()["detail"].startswith("Passed on resolved questions")
    summary = _tool("get_investigation_summary")
    assert summary["no_incident"] is True
    assert summary["questions"]["open"] == 0 and summary["open_questions"] == []
    # What the cross-system gate reads from the same summary.
    assert validate_cross_system(summary).passed

    result = _tool("finalize_report")

    assert "report_path" in result, result
    markdown = Path(result["report_path"]).read_text()
    html = Path(result["html_report_path"]).read_text()
    for report in (markdown, html):
        assert STATEMENT in report
        assert "it does not establish that nothing happened" in report
        # how much of the indexed evidence the conclusion rests on
        assert "3 evidence sources (1 disk, 2 other), 3 of them cited by a finding" in report
        assert "3 investigation questions: 2 ruled out, 0 answered, 1 undetermined" in report
        # what was not available: the undetermined question and the lead
        assert "No network capture or firewall log is in the case." in report
        assert "Firewall log for the WS01 subnet" in report
        assert "Was any persistence mechanism installed?" in report
        assert "[NEGATIVE] No persistence mechanism on WS01" in report
        assert persistence in report
        assert "Key Threats" not in report
    summary_md = markdown.split("## Executive Summary", 1)[1].split("\n---", 1)[0]
    assert summary_md.index(STATEMENT) < summary_md.index("**Examined:**")
    assert summary_md.index("**Examined:**") < summary_md.index("**Not available:**")
    assert "Attack Lifecycle" not in summary_md and "**Results:**" not in summary_md
    section = markdown.split("## Investigation Questions", 1)[1].split("\n---", 1)[0]
    assert (
        "- **Ruled out** (extraction, WS01): Was any persistence mechanism installed?" in section
    )
    assert f"  - [NEGATIVE] No persistence mechanism on WS01 (`{persistence}`)" in section
    assert (
        "- **Undetermined** (extraction, WS01): Was data sent to an external address?" in section
    )
    assert "  - Reason: No network capture or firewall log is in the case." in section
    assert "Investigation Questions</div>" in html


def test_a_finding_of_substance_is_never_reported_as_no_incident(case: _Case) -> None:
    """One high finding and every question resolved passes the second path,
    and the report says what was found, not that nothing was."""
    case.clean_case()
    case.finding("Unauthorised remote logon", case.searched("4624"), "evtx.security", "high")

    assert case.minimum_findings()["detail"].startswith("Passed on resolved questions")
    summary = _tool("get_investigation_summary")
    assert "no_incident" not in summary and summary["significant_findings"] == 1
    assert not validate_cross_system(summary).passed  # a high finding still needs a mapping

    markdown = Path(_tool("finalize_report")["report_path"]).read_text()

    assert STATEMENT not in markdown
    assert "**Results:** 1 findings (1 high)" in markdown
    assert "## Investigation Questions" in markdown


def test_question_text_is_escaped_in_the_html_report(case: _Case) -> None:
    case.clean_case()
    (question_id,) = case.ask("Did <script>alert(1)</script> run?")
    _tool(
        "resolve_question",
        question_id=question_id,
        resolution="undetermined",
        reason="<img src=x onerror=alert(2)> was not parsed",
    )

    html = Path(_tool("finalize_report")["html_report_path"]).read_text()

    assert "<script>alert(1)</script>" not in html and "<img src=x" not in html
    assert "Did &lt;script&gt;alert(1)&lt;/script&gt; run?" in html


def test_mulder_report_renders_the_same_outcome_from_the_database(case: _Case) -> None:
    case.clean_case()
    case.bridge.cleanup()

    result = CliRunner().invoke(cli, ["report", "clean", "--db-dir", str(case.db_dir)])

    assert result.exit_code == 0, result.output
    assert STATEMENT in (case.db_dir / "clean.report.md").read_text()
    assert STATEMENT in (case.db_dir / "clean.report.html").read_text()


# ---------------------------------------------------------------------------
# The orchestrator hands the analyst its questions with their ids
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_the_analyst_is_given_recorded_questions_with_their_ids(case: _Case) -> None:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator(str(case.evidence), case_id="clean", db_dir=case.db_dir)
    prompts_seen: list[str] = []

    async def planner(*_a: Any, **_kw: Any) -> Plan:
        task = {"tool": "run_fls", "args": {}, "purpose": "list files"}
        return Plan("p", [task], ["Was any persistence mechanism installed?"], [], "plan", 1)

    async def executor(_phase: Any, plan: Plan, *_a: Any, **_kw: Any) -> ExecutionResults:
        return ExecutionResults(plan.plan_id, [], 1, False, tool_calls=1)

    async def session(**kwargs: Any) -> PhaseResult:
        prompts_seen.append(kwargs["prompt"])
        return PhaseResult(phase_name="query", messages=["done"], turns_used=1)

    async def gate(phase: Any, _result: PhaseResult) -> GateResult:
        return GateResult(True, phase.name)

    with (
        patch.object(orch._roles, "run_planner", side_effect=planner),
        patch.object(orch._roles, "run_executor", side_effect=executor),
        patch.object(orch._session, "execute", side_effect=session),
        patch.object(orch, "_validate_phase", side_effect=gate),
    ):
        result = await orch._run_split_phase(
            EXTRACTION, prompt_vars={"case_id": "clean", "system_name": "WS01"}
        )

    assert result.success
    (question,) = server_app.get_ctx().db.get_questions()
    assert (question.phase, question.system) == ("extraction", "WS01")
    (analyst_prompt,) = prompts_seen
    assert f"[{question.question_id}] Was any persistence mechanism installed?" in analyst_prompt


@pytest.mark.asyncio()
async def test_a_continued_analyst_is_given_its_questions_again() -> None:
    """Its prompt says only the questions in the user message are its own."""
    continuations: list[str] = []

    async def execute(**kwargs: Any) -> PhaseResult:
        first = not kwargs["prompt"].startswith("CONTINUATION")
        if not first:
            continuations.append(kwargs["prompt"])
        return PhaseResult(phase_name="query", turns_used=1, context_exhausted=first)

    session = MagicMock()
    session.execute = execute
    roles = RoleRunner(session, MagicMock(), ModelConfig(), "clean", {}, "/tmp", 1)
    labelled = "[q_1a2b3c4d] Was any persistence mechanism installed?"

    for questions in ([labelled], []):
        plan = Plan("p", [], questions, [], "plan", 1)
        await roles.run_analyst(EXTRACTION, plan, ExecutionResults("p", [], 1, False))

    with_questions, without = continuations
    assert labelled in with_questions and "resolve_question" in with_questions
    # A plan with no questions is continued with the prompt it always was.
    assert with_questions.startswith(without)
    assert without.endswith("Do NOT re-submit existing findings.")


# ---------------------------------------------------------------------------
# Roles and guidance
# ---------------------------------------------------------------------------


def test_only_the_analysts_and_the_report_role_can_resolve_a_question() -> None:
    for role in Role:
        can = "mcp__mulder__resolve_question" in get_tools_for_role(role)
        assert can == bool(role & (ANALYSTS | Role.REPORT)), role
    assert Role.REPORT & ALL_ROLES


@pytest.mark.parametrize(
    "name", ["EXTRACT_ANALYST", "CROSS_SYSTEM_ANALYST", "NARRATIVE_ANALYST", "REPORT"]
)
def test_every_role_that_can_resolve_questions_is_told_how(name: str) -> None:
    text = getattr(prompts, f"{name}_PROMPT")

    # The report prompt already calls its own Q1 to Q8 "investigation questions".
    assert ("RECORDED QUESTIONS" if name == "REPORT" else "INVESTIGATION QUESTIONS") in text
    for word in ("resolve_question", '"answered"', '"ruled_out"', '"undetermined"', "[NEGATIVE]"):
        assert word in text, word
    # what a ruled-out answer does and does not establish
    assert "did not happen" in text or "never" in text


def test_the_report_role_is_told_how_to_write_a_case_with_no_incident() -> None:
    text = prompts.REPORT_PROMPT

    assert "no_incident: true" in text
    assert "What Was Ruled Out" in text and "What Could Not Be Determined" in text
    assert "Absence in what was examined is not absence" in text
    # It cannot submit findings, and is not told to.
    assert "mcp__mulder__submit_finding" not in get_tools_for_role(Role.REPORT)
    assert "You cannot submit" in text


# ---------------------------------------------------------------------------
# What a resolution may rest on, and what a refusal may say
# ---------------------------------------------------------------------------


def _resolve(question_id: str, resolution: str, *finding_ids: str) -> dict[str, Any]:
    return _tool(
        "resolve_question",
        question_id=question_id,
        resolution=resolution,
        finding_ids=list(finding_ids),
    )


@pytest.mark.parametrize(
    ("tool", "kwargs"),
    [
        ("open_case", {"case_id": "clean"}),
        ("list_sources", {}),
        ("get_investigation_summary", {}),
        ("check_finalize_readiness", {}),
        ("audit_tool_coverage", {}),
        # They return notes and findings the investigation wrote, and nothing
        # at all when it wrote none.
        ("get_bookmarks", {}),
        ("get_ioc_summary", {}),
        ("verify_evidence_integrity", {}),
    ],
)
def test_a_finding_that_examined_no_evidence_cannot_answer_or_rule_out_a_question(
    case: _Case, tool: str, kwargs: dict[str, Any]
) -> None:
    """A bookkeeping call is a real, successful call, and it looked at nothing."""
    (question_id,) = case.ask("Was there a remote logon?")
    bookkeeping = str(_tool(tool, **kwargs)["tool_call_id"])
    hollow = case.finding("[NEGATIVE] Nothing found", bookkeeping, "evtx.security")
    # The same call wrapped in a batch: an aggregate is only what its children are.
    server_app.get_ctx().audit.log_tool_call(
        "tc_batch", "run_parallel", {}, "hash", sub_calls=[bookkeeping]
    )
    batched = case.finding("[NEGATIVE] Nothing found in a batch", "tc_batch", "evtx.security")
    # A positive answer is held to the same standard as a negative one.
    ordinary = case.finding("Workstation looks ordinary", bookkeeping, "evtx.security")

    for resolution, finding_id in (
        ("ruled_out", hollow),
        ("ruled_out", batched),
        ("answered", ordinary),
    ):
        refused = _resolve(question_id, resolution, finding_id)

        assert refused["status"] == "error"
        assert (
            "cites no call that extracted, searched or read evidence" in refused["error_message"]
        )
    assert server_app.get_ctx().db.get_questions()[0].resolution is None


def test_one_call_that_examined_evidence_is_what_a_ruled_out_answer_needs(case: _Case) -> None:
    (question_id,) = case.ask("Was there a remote logon?")
    refs = [str(_tool("list_sources")["tool_call_id"]), case.searched("4624")]
    finding_id = _tool(
        "submit_finding",
        title="[NEGATIVE] No remote logon on WS01",
        description="Searched evtx.security for 4624.",
        severity="info",
        confidence="inference",
        evidence_refs=refs,
        sources=["evtx.security"],
    )["finding_id"]

    assert _resolve(question_id, "ruled_out", finding_id)["status"] == "resolved"


def test_the_tools_that_examine_no_evidence_are_real_and_include_the_findings_tools() -> None:
    assert set(_tool_dispatch_sync) >= rules.NO_EVIDENCE_TOOLS
    assert _FINDING_TOOLS <= rules.NO_EVIDENCE_TOOLS
    # A lookup against outside services; it reads nothing in the case.
    assert "enrich_iocs" in rules.NO_EVIDENCE_TOOLS
    assert not {"search", "get_raw_output", "run_fls", "run_parallel"} & rules.NO_EVIDENCE_TOOLS


def test_a_finding_another_session_submitted_can_back_a_resolution(case: _Case) -> None:
    """A server loads the audit log once; calls other sessions' servers log come later."""
    (question_id,) = case.ask("Was any persistence mechanism installed?")
    ctx = server_app.get_ctx()
    other_server = AuditLog(case.db_dir / "clean.audit.jsonl")
    other_server.log_tool_call("tc_other_search", "search", {"query": "Run"}, "hash")
    ctx.db.insert_finding(NEGATIVE.model_copy(update={"evidence_refs": ["tc_other_search"]}))
    assert not ctx.audit.has_tool_call("tc_other_search")

    assert _resolve(question_id, "ruled_out", NEGATIVE.finding_id)["status"] == "resolved"


def test_one_finding_of_the_right_kind_is_enough_and_the_rest_are_reported(case: _Case) -> None:
    (question_id,) = case.ask("Was any persistence mechanism installed?")
    ref = case.searched("Run")
    negative = case.finding("[NEGATIVE] No persistence", ref, "registry.software")
    positive = case.finding("Guest account enabled", ref, "registry.software", "low")

    # The id as the prompts display it, brackets included.
    resolved = _resolve(f" [{question_id}] ", "ruled_out", negative, positive, "f_nope")

    assert resolved["status"] == "resolved"
    assert resolved["question_id"] == question_id
    assert resolved["finding_ids"] == [negative]
    assert resolved["ignored_finding_ids"] == (
        f"{positive}: not that kind of finding; f_nope: no such finding"
    )
    assert server_app.get_ctx().db.get_questions()[0].finding_ids == [negative]


def test_a_refusal_does_not_echo_unbounded_input(case: _Case) -> None:
    (question_id,) = case.ask("Was any persistence mechanism installed?")
    huge = "x" * 200_000
    for kwargs in (
        {"question_id": huge, "resolution": "undetermined", "reason": "missing"},
        {"question_id": question_id, "resolution": huge},
        {"question_id": question_id, "resolution": "answered", "finding_ids": [huge]},
        {
            "question_id": question_id,
            "resolution": "answered",
            "finding_ids": [f"f_{i:08d}" for i in range(5000)],
        },
    ):
        refused = _tool("resolve_question", **kwargs)

        assert refused["status"] == "error"
        assert len(refused["error_message"]) < 2000, len(refused["error_message"])
    assert "and 4990 more" in refused["error_message"]


def test_a_question_echoed_back_with_its_label_is_the_same_question(case: _Case) -> None:
    """A follow-up planner is fed the analyst's request, which quotes labelled questions."""
    (labelled,) = case.bridge.record_questions(
        "extraction", "WS01", ["Was persistence installed?"]
    )

    echoed = case.bridge.record_questions(
        "extraction", "WS01", [labelled, f" [q_0badc0de] {labelled}"]
    )

    assert echoed == [labelled, labelled]
    assert [q.question for q in server_app.get_ctx().db.get_questions()] == [
        "Was persistence installed?"
    ]


def test_an_analyst_is_told_which_open_questions_are_its_own(case: _Case) -> None:
    """The summary lists every phase's and system's open questions, oldest first."""
    case.ask(*(f"Question number {i}?" for i in range(20)))

    note = _tool("get_investigation_summary")["open_questions_note"]

    assert note.startswith("Showing 15 of 20 open questions, oldest first")
    assert "resolve these" not in note
    for name in ("EXTRACT_ANALYST", "CROSS_SYSTEM_ANALYST"):
        assert "Only the questions in the user message are yours" in getattr(
            prompts, f"{name}_PROMPT"
        )


def test_the_report_role_closes_questions_before_it_writes_the_narrative() -> None:
    """no_incident decides the narrative's sections and is only true once they are closed."""
    text = prompts.REPORT_PROMPT

    assert "Before step 4" in text and "Before step 5" not in text
    assert "call get_investigation_summary again" in text


def test_the_examined_line_counts_what_the_citation_gate_counts(case: _Case) -> None:
    case.clean_case()
    second_device = str(case.evidence / "ws02.E01")
    extract_and_index("line\n", "evtx.security", second_device, "test")  # a name twice
    extract_and_index("line\n", "plaso.stats", second_device, "test")  # run bookkeeping
    extract_and_index("line\n", "evtx.system", second_device, "test")  # never cited
    # A blank entry is a prefix of every source name.
    case.finding("[NEGATIVE] No log clearing", case.searched("1102"), "")
    server_app.get_ctx().audit.log_tool_call("tc_failed", "run_hayabusa", {}, "h", status="error")

    gates = _tool("check_finalize_readiness")["gates"]
    citation = next(g for g in gates if g["name"] == "evidence_citation_coverage")
    markdown = Path(_tool("finalize_report")["report_path"]).read_text()

    assert "(3/4 distinct names)" in citation["detail"]
    examined = re.search(r"\*\*Examined:\*\* (.*)", markdown)
    assert examined
    assert examined.group(1).startswith(
        "4 evidence sources (1 disk, 3 other), 3 of them cited by a finding; "
    )
    # clean_case searched three times and this test once, and one extraction
    # failed: the count is of calls made, and says so. The audits, the
    # findings and the resolutions examined nothing.
    calls = re.search(
        r"(\d+) tool calls, (\d+) of them to tools that extract, search or read evidence "
        r"\(failed calls included\)",
        markdown,
    )
    assert calls and int(calls.group(2)) == 5 < int(calls.group(1))
