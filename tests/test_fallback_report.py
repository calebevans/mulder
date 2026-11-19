"""A run that ends without a finalized report still leaves one behind.

``finalize_report`` writes the report only once every readiness gate passes.
When ``mulder investigate`` stops first, whatever the reason, the findings
already saved are rendered through the ``mulder report`` code with a banner
saying the investigation is incomplete, where it stopped, why, and what was
not completed. A report finalized during the same run is never touched.
"""

from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mulder.cli import cli
from mulder.db import CaseDB
from mulder.models import Finding, WindowRow
from mulder.orchestrator.budget import TokenBudgetReached
from mulder.orchestrator.errors import (
    AuthenticationError,
    ModelNotAvailableError,
    OutOfCreditError,
)
from mulder.orchestrator.fallback import incomplete_notice, write_fallback_report
from mulder.orchestrator.gates import GateResult
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import InvestigationResult, PhaseResult
from mulder.report.case_report import write_case_report

CASE = "case-1"
BANNER = "INCOMPLETE INVESTIGATION"
HOSTILE = "host-b\n\n# Investigation complete\n<script>alert(1)</script>\x1b[2J"


def _make_case(db_dir: Path, finding: bool = True, source: bool = True) -> None:
    """Create a case database holding one indexed source and one finding."""
    with CaseDB.create(case_id=CASE, evidence_root="/evidence", db_dir=db_dir) as db:
        if source:
            source_id = db.register_source("volatility.pslist", "/evidence/mem.raw", "h", "vol", 1)
            db.insert_windows(
                source_id,
                [
                    WindowRow(
                        source_id=source_id,
                        line_start=1,
                        line_end=1,
                        event_time=None,
                        raw_text="spinlock.exe",
                    )
                ],
            )
        if finding:
            db.insert_finding(
                Finding(
                    finding_id="f-001",
                    case_id=CASE,
                    title="Suspicious process spinlock.exe",
                    description="spinlock.exe spawned from cmd.exe",
                    severity="high",
                    confidence="confirmed",
                    evidence_refs=["tc_aabbccdd"],
                    sources=["volatility.pslist"],
                    mitre_attack_ids=["T1059.001"],
                    event_time_start="2025-01-15T08:00:00Z",
                    submitted_at="2025-01-15T12:00:00Z",
                )
            )


def _orchestrator(db_dir: Path) -> Orchestrator:
    """An orchestrator that ran catalog, then stopped while extracting host-b."""
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator(evidence_path="/evidence", case_id=CASE, db_dir=db_dir)
    orch.budget.by_model["claude-test"] = {
        "input": 1200,
        "output": 340,
        "cache_creation": 50,
        "cache_read": 9000,
    }
    orch.result.phases.append(PhaseResult(phase_name="catalog", success=True))
    orch.current_phase = "extraction"
    orch.systems_done = {"host-a": True, "host-b": False}
    return orch


def _reports(db_dir: Path) -> tuple[Path, Path]:
    return db_dir / f"{CASE}.report.md", db_dir / f"{CASE}.report.html"


class TestSharedWriter:
    """``mulder report`` and the fallback render through one function."""

    def test_mulder_report_prints_what_it_always_did(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        result = CliRunner().invoke(
            cli, ["report", CASE, "--db-dir", str(tmp_path)], catch_exceptions=False
        )
        md, html = _reports(tmp_path)

        assert result.exit_code == 0
        assert result.output.splitlines() == [
            f"Loading case '{CASE}' from {tmp_path / f'{CASE}.db'} ...",
            "  1 findings, 1 sources",
            f"  Markdown: {md}",
            f"  HTML:     {html}",
            "Done.",
        ]
        assert "Suspicious process spinlock.exe" in md.read_text()
        # Byte-for-byte the old opening: the banner block leaves nothing behind.
        assert md.read_text().startswith(f"# Mulder Investigation Report\n\n**Case:** {CASE}\n")
        assert BANNER not in md.read_text()
        assert BANNER not in html.read_text()
        assert "incomplete-banner" not in html.read_text().split("</style>")[1]

    def test_banner_opens_both_formats(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        lines = ["Stopped in phase: extraction", "Reason: out of credit", "Not completed: report"]
        written = write_case_report(CASE, tmp_path, lines)
        md, html = written.markdown.read_text(), (written.html or Path()).read_text()

        assert (written.findings, written.sources, written.html_error) == (1, 1, "")
        # Under the title and above everything else.
        assert md.index("# Mulder Investigation Report") < md.index(BANNER) < md.index("**Case:**")
        quote = md[md.index("> **" + BANNER) : md.index("**Case:**")].strip().splitlines()
        assert all(line.startswith(">") for line in quote)  # one unbroken blockquote
        for line in lines:
            assert f"> - {line}" in quote
            assert f"<li>{line}</li>" in html
        assert html.index('class="main"') < html.index(BANNER) < html.index('id="page-dashboard"')
        # What a partial report does not establish.
        for text in (md, html):
            assert "passed the finalize gates" in text
            assert "is not a clean result" in text

    def test_html_banner_escapes_what_it_is_given(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        written = write_case_report(CASE, tmp_path, ["Reason: <script>alert(1)</script>"])
        html = (written.html or Path()).read_text()

        assert "<li>Reason: &lt;script&gt;alert(1)&lt;/script&gt;</li>" in html
        assert "<script>alert(1)</script>" not in html

    def test_markdown_survives_an_html_failure(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        with patch(
            "mulder.report.case_report.ReportRenderer.render_html", side_effect=ValueError("boom")
        ):
            written = write_case_report(CASE, tmp_path, ["Reason: x"])

        assert written.html is None
        assert written.html_error == "boom"
        assert BANNER in written.markdown.read_text()


class TestNotice:
    def test_fatal_error_names_phase_reason_and_unfinished_systems(self, tmp_path: Path) -> None:
        notice = incomplete_notice(
            _orchestrator(tmp_path), OutOfCreditError("Credit balance is too low")
        )
        assert notice == [
            "Stopped in phase: extraction",
            "Reason: the API account is out of credit or over its quota: "
            "Credit balance is too low",
            "Not completed: extraction (1 of 2 systems: host-b); cross_system; "
            "alternative_narrative; report",
        ]

    def test_many_unfinished_systems_do_not_push_the_phases_out(self, tmp_path: Path) -> None:
        orch = _orchestrator(tmp_path)
        orch.systems_done = {f"workstation-{i:03d}.corp.example": i < 19 for i in range(60)}
        not_completed = incomplete_notice(orch, OutOfCreditError("x"))[2]

        assert not_completed.startswith(
            "Not completed: extraction (41 of 60 systems: workstation-019.corp.example, "
        )
        assert not_completed.endswith(
            "workstation-028.corp.example, +31 more); cross_system; alternative_narrative; report"
        )

    def test_gate_failure_also_quotes_the_last_session_error(self, tmp_path: Path) -> None:
        """An ordinary 429 is not fatal; the gate it trips names only the symptom."""
        orch = _orchestrator(tmp_path)
        gate = GateResult(passed=False, phase_name="extraction", gaps=["no findings " * 60])
        orch.result.phases.append(
            PhaseResult(phase_name="extraction", success=False, gate_result=gate)
        )
        orch._session.last_query_error = "API Error: 429 rate_limit_error\n" + "x" * 500

        reason = incomplete_notice(orch, None)[1]
        assert reason.startswith("Reason: its gate failed after every retry: no findings no ")
        assert "...; last session error: API Error: 429 rate_limit_error x" in reason
        assert reason.isprintable()
        assert len(reason) < 550
        # The error that ended the run is the reason; an older session error is not added.
        fatal = incomplete_notice(orch, OutOfCreditError("Credit balance is too low"))[1]
        assert "last session error" not in fatal

    def test_gate_failure_quotes_the_gaps_of_the_last_phase(self, tmp_path: Path) -> None:
        orch = _orchestrator(tmp_path)
        orch.systems_done = {"host-a": True, "host-b": True}
        gate = GateResult(passed=False, phase_name="report", gaps=["minimum_findings: 1 of 3"])
        orch.result.phases += [
            PhaseResult(phase_name="extraction", success=True),
            PhaseResult(phase_name="cross_system", success=True),
            PhaseResult(phase_name="alternative_narrative", success=False),
            PhaseResult(phase_name="report", success=False, gate_result=gate),
        ]
        orch.current_phase = "report"

        assert incomplete_notice(orch, None) == [
            "Stopped in phase: report",
            "Reason: its gate failed after every retry: minimum_findings: 1 of 3",
            "Not completed: alternative_narrative (failed); report (failed)",
        ]

    def test_nothing_started_reports_every_phase(self, tmp_path: Path) -> None:
        with patch("mulder.orchestrator.runner.InvestigationDashboard"):
            orch = Orchestrator(evidence_path="/evidence", case_id=CASE, db_dir=tmp_path)
        notice = incomplete_notice(orch, AuthenticationError("Not logged in"))
        assert notice[0] == "Stopped in phase: catalog"
        assert notice[1] == "Reason: authentication failed: Not logged in"
        assert notice[2] == (
            "Not completed: catalog; extraction; cross_system; alternative_narrative; report"
        )

    @pytest.mark.parametrize(
        ("error", "reason"),
        [
            (KeyboardInterrupt(), "Reason: interrupted (Ctrl-C or SIGTERM)"),
            (
                ModelNotAvailableError("model not found"),
                "Reason: the configured model is not available: model not found",
            ),
            (RuntimeError("boom"), "Reason: unexpected RuntimeError: boom"),
            (
                TokenBudgetReached("9,100 of 9,000 tokens used"),
                "Reason: token budget reached: 9,100 of 9,000 tokens used",
            ),
        ],
    )
    def test_reason_per_kind_of_ending(
        self, tmp_path: Path, error: BaseException, reason: str
    ) -> None:
        assert incomplete_notice(_orchestrator(tmp_path), error)[1] == reason

    def test_hostile_names_and_errors_stay_on_one_bounded_line(self, tmp_path: Path) -> None:
        """System names come from evidence file names; error bodies from a provider."""
        orch = _orchestrator(tmp_path)
        orch.systems_done = {HOSTILE: False}
        notice = incomplete_notice(orch, RuntimeError(HOSTILE + "x" * 5000))

        assert len(notice) == 3
        for line in notice:
            assert line.isprintable()  # no newline, no escape sequence
            assert len(line) < 700
        assert notice[1].endswith("...")


class TestWriteFallback:
    def test_writes_a_partial_report_with_the_notice(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        started = time.time()
        written = write_fallback_report(
            _orchestrator(tmp_path), CASE, tmp_path, started, OutOfCreditError("Credit too low")
        )
        md, html = _reports(tmp_path)

        assert written is not None
        assert (written.markdown, written.html) == (md, html)
        for text in (md.read_text(), html.read_text()):
            assert BANNER in text
            assert "Stopped in phase: extraction" in text
            assert "out of credit or over its quota: Credit too low" in text
            assert "extraction (1 of 2 systems: host-b)" in text
            assert "Suspicious process spinlock.exe" in text  # the saved finding

    def test_token_usage_so_far_reaches_the_report(self, tmp_path: Path) -> None:
        """A completed run writes the usage sidecar before its report phase."""
        _make_case(tmp_path)
        write_fallback_report(_orchestrator(tmp_path), CASE, tmp_path, time.time(), None)

        usage = json.loads((tmp_path / f"{CASE}.model_usage.json").read_text())
        # Cached input is recorded beside the two existing fields, not in them.
        assert usage == [
            {
                "model": "claude-test",
                "input_tokens": 1200,
                "output_tokens": 340,
                "cache_creation_input_tokens": 50,
                "cache_read_input_tokens": 9000,
            }
        ]
        assert "claude-test" in _reports(tmp_path)[1].read_text()

    def test_never_overwrites_a_report_finalized_during_this_run(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        started = time.time()
        md, html = _reports(tmp_path)
        md.write_text("FINALIZED MARKDOWN")
        html.write_text("FINALIZED HTML")

        written = write_fallback_report(
            _orchestrator(tmp_path), CASE, tmp_path, started, RuntimeError("late crash")
        )

        assert written is None
        assert md.read_text() == "FINALIZED MARKDOWN"
        assert html.read_text() == "FINALIZED HTML"

    def test_keeps_a_report_left_by_an_earlier_run(self, tmp_path: Path) -> None:
        """A re-run that fails must not cost the earlier run its deliverable."""
        _make_case(tmp_path)
        md, html = _reports(tmp_path)
        # A finding title can say anything; only the fixed opening counts.
        md.write_text("# Mulder Investigation Report\n\n**Case:** x\n> **INCOMPLETE INVESTIGATION")
        html.write_text("FINALIZED HTML FROM LAST WEEK")
        finalized = md.read_text()
        for path in (md, html):
            os.utime(path, (time.time() - 3600, time.time() - 3600))

        written = write_fallback_report(
            _orchestrator(tmp_path), CASE, tmp_path, time.time(), AuthenticationError("Bad key")
        )

        partial = tmp_path / f"{CASE}.partial.report.md", tmp_path / f"{CASE}.partial.report.html"
        assert written is not None
        assert (written.markdown, written.html) == partial
        assert md.read_text() == finalized
        assert html.read_text() == "FINALIZED HTML FROM LAST WEEK"
        for text in (partial[0].read_text(), partial[1].read_text()):
            assert BANNER in text
            assert "authentication failed: Bad key" in text
            assert f"Earlier report: {CASE}.report.md is from an earlier run" in text

    def test_replaces_a_partial_report_left_by_an_earlier_run(self, tmp_path: Path) -> None:
        """Out of credit twice: the second partial report replaces the first."""
        _make_case(tmp_path)
        orch = _orchestrator(tmp_path)
        md, _ = _reports(tmp_path)
        write_fallback_report(orch, CASE, tmp_path, time.time(), OutOfCreditError("first"))
        os.utime(md, (time.time() - 3600, time.time() - 3600))

        written = write_fallback_report(orch, CASE, tmp_path, time.time(), RuntimeError("second"))

        assert written is not None
        assert written.markdown == md
        assert "unexpected RuntimeError: second" in md.read_text()
        assert "Earlier report" not in md.read_text()
        assert not list(tmp_path.glob("*.partial.*"))

    def test_no_case_database_writes_nothing(self, tmp_path: Path) -> None:
        orch = _orchestrator(tmp_path)
        assert write_fallback_report(orch, CASE, tmp_path, time.time(), None) is None
        assert list(tmp_path.iterdir()) == []  # not even an empty database

    def test_a_case_with_no_source_and_no_finding_writes_nothing(self, tmp_path: Path) -> None:
        _make_case(tmp_path, finding=False, source=False)
        orch = _orchestrator(tmp_path)
        assert write_fallback_report(orch, CASE, tmp_path, time.time(), None) is None
        assert not _reports(tmp_path)[0].exists()

    @pytest.mark.parametrize(("finding", "source"), [(True, False), (False, True)])
    def test_one_source_or_one_finding_is_enough(
        self, tmp_path: Path, finding: bool, source: bool
    ) -> None:
        _make_case(tmp_path, finding=finding, source=source)
        written = write_fallback_report(_orchestrator(tmp_path), CASE, tmp_path, time.time(), None)

        assert written is not None
        assert (written.findings, written.sources) == (int(finding), int(source))
        assert BANNER in written.markdown.read_text()

    def test_hostile_system_name_cannot_forge_report_content(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        orch = _orchestrator(tmp_path)
        orch.systems_done = {HOSTILE: False}
        write_fallback_report(orch, CASE, tmp_path, time.time(), None)
        md, html = (p.read_text() for p in _reports(tmp_path))

        assert "\n# Investigation complete" not in md  # no heading of its own
        assert "\x1b" not in md
        assert "<script>alert(1)</script>" not in html


def _invoke(db_dir: Path, outcome: object) -> Any:
    """Run ``mulder investigate`` with the pipeline replaced by *outcome*.

    *outcome* is the ``InvestigationResult`` the pipeline returns, the
    exception it raises, or a function to run in its place.
    """
    orch = SimpleNamespace(
        result=InvestigationResult(phases=[PhaseResult(phase_name="catalog", success=True)]),
        current_phase="extraction",
        systems_done={"host-a": True, "host-b": False},
        dashboard=MagicMock(),
        run=MagicMock(),
        _write_model_usage=MagicMock(),
        _session=SimpleNamespace(last_query_error=""),
    )
    pipeline = MagicMock(return_value=outcome)
    if isinstance(outcome, BaseException) or callable(outcome):
        pipeline.side_effect = outcome
    with (
        patch("mulder.orchestrator.runner.Orchestrator", return_value=orch),
        patch("asyncio.run", pipeline),
    ):
        return CliRunner().invoke(cli, ["investigate", "/evidence", CASE, "--db-dir", str(db_dir)])


_FAILED = InvestigationResult(phases=[PhaseResult(phase_name="report", success=False)])
# The pipeline returns this, rather than raising, when the token budget ends a run.
_OVER_BUDGET = InvestigationResult(budget_stop=TokenBudgetReached("9,100 of 9,000 tokens used"))


class TestInvestigateCli:
    @pytest.mark.parametrize(
        ("outcome", "exit_code", "reason"),
        [
            (OutOfCreditError("Credit balance is too low"), 2, "out of credit or over its quota"),
            (AuthenticationError("Not logged in"), 2, "authentication failed"),
            (ModelNotAvailableError("model not found"), 2, "model is not available"),
            (KeyboardInterrupt(), 1, "interrupted (Ctrl-C or SIGTERM)"),
            (RuntimeError("boom"), 1, "unexpected RuntimeError: boom"),
            (_FAILED, 1, "ended without finalizing a report"),
            (_OVER_BUDGET, 1, "token budget reached: 9,100 of 9,000 tokens used"),
        ],
        ids=["out-of-credit", "auth", "model", "ctrl-c", "crash", "gate-failure", "token-budget"],
    )
    def test_every_way_out_leaves_a_report_and_a_nonzero_exit(
        self, tmp_path: Path, outcome: object, exit_code: int, reason: str
    ) -> None:
        _make_case(tmp_path)
        result = _invoke(tmp_path, outcome)
        md, html = _reports(tmp_path)

        assert result.exit_code == exit_code
        assert "Investigation INCOMPLETE" in result.output
        assert f"Markdown: {md}" in result.output
        assert f"HTML:     {html}" in result.output
        assert BANNER in md.read_text()
        assert reason in md.read_text()
        assert reason in html.read_text()

    def test_sigterm_ends_the_run_like_ctrl_c(self, tmp_path: Path) -> None:
        """``docker stop`` sends SIGTERM, which by default kills with no report."""
        _make_case(tmp_path)

        def terminated(_coro: object) -> None:
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(1)  # cut short by KeyboardInterrupt once the signal is handled

        # Ignored for the test, so a missing handler fails it instead of
        # killing the test run.
        before = signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            result = _invoke(tmp_path, terminated)
        finally:
            signal.signal(signal.SIGTERM, before)

        assert result.exit_code == 1
        assert "interrupted (Ctrl-C or SIGTERM)" in _reports(tmp_path)[0].read_text()

    def test_an_earlier_report_is_kept_and_the_terminal_says_so(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        md, _ = _reports(tmp_path)
        md.write_text("FINALIZED LAST WEEK")
        os.utime(md, (time.time() - 3600, time.time() - 3600))

        result = _invoke(tmp_path, AuthenticationError("Not logged in"))

        assert result.exit_code == 2
        assert md.read_text() == "FINALIZED LAST WEEK"
        assert f"Markdown: {tmp_path / f'{CASE}.partial.report.md'}" in result.output
        assert f"The report an earlier run left was kept: {md}" in result.output

    def test_a_successful_run_is_left_alone(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        result = _invoke(tmp_path, InvestigationResult(success=True))

        assert result.exit_code == 0
        assert "INCOMPLETE" not in result.output
        assert not _reports(tmp_path)[0].exists()

    def test_nothing_to_report_says_nothing(self, tmp_path: Path) -> None:
        result = _invoke(tmp_path, OutOfCreditError("Credit balance is too low"))

        assert result.exit_code == 2
        assert "INCOMPLETE" not in result.output
        assert not _reports(tmp_path)[0].exists()

    def test_a_rendering_failure_does_not_hide_why_the_run_ended(self, tmp_path: Path) -> None:
        _make_case(tmp_path)
        with patch(
            "mulder.orchestrator.fallback.write_case_report", side_effect=OSError("disk full")
        ):
            result = _invoke(tmp_path, OutOfCreditError("Credit balance is too low"))

        assert result.exit_code == 2
        assert "Could not render a partial report: disk full" in result.output
        assert "out of credit or over its quota" in result.output
