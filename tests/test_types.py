"""Tests for mulder.orchestrator.types -- data structures and JSON parsing."""

from __future__ import annotations

import json

from mulder.orchestrator.types import (
    AnalystResult,
    ExecutionResults,
    Plan,
    extract_follow_up_request,
    extract_json_plan,
)


class TestPlanFromValidJson:
    """Plans parse correctly from valid JSON messages."""

    def test_basic_plan_extraction(self) -> None:
        plan_json = json.dumps(
            {
                "tasks": [
                    {
                        "tool": "read_file",
                        "args": {"path": "/evidence/log.txt"},
                        "purpose": "read log",
                    }
                ],
                "investigation_questions": ["Was there lateral movement?"],
                "expected_sources": ["log.txt"],
            }
        )
        result = extract_json_plan([f"Here is the plan:\n{plan_json}"])
        assert result is not None
        assert len(result["tasks"]) == 1
        assert result["tasks"][0]["tool"] == "read_file"

    def test_multiple_messages_finds_last(self) -> None:
        early = json.dumps({"tasks": [{"tool": "a", "args": {}, "purpose": "first"}]})
        late = json.dumps({"tasks": [{"tool": "b", "args": {}, "purpose": "second"}]})
        result = extract_json_plan([early, late])
        assert result is not None
        assert result["tasks"][0]["tool"] == "b"


class TestPlanFromFencedJson:
    """Plans wrapped in code fences are handled."""

    def test_json_fence(self) -> None:
        msg = (
            "Here is the execution plan:\n"
            "```json\n"
            '{"tasks": [{"tool": "grep", "args": {"pattern": "ssh"}, "purpose": "find ssh"}],'
            ' "investigation_questions": [], "expected_sources": []}\n'
            "```\n"
            "Let me know if you need changes."
        )
        result = extract_json_plan([msg])
        assert result is not None
        assert result["tasks"][0]["tool"] == "grep"

    def test_bare_fence(self) -> None:
        msg = '```\n{"tasks": [{"tool": "ls", "args": {}, "purpose": "list"}]}\n```'
        result = extract_json_plan([msg])
        assert result is not None


class TestPlanEmptyTasksInvalid:
    """Plans with empty tasks list are treated as invalid."""

    def test_empty_tasks_returns_none(self) -> None:
        plan_json = json.dumps({"tasks": [], "investigation_questions": []})
        result = extract_json_plan([plan_json])
        assert result is None

    def test_no_json_returns_none(self) -> None:
        result = extract_json_plan(["Just some text with no JSON"])
        assert result is None

    def test_missing_tasks_key_returns_none(self) -> None:
        msg = json.dumps({"investigation_questions": ["what?"]})
        result = extract_json_plan([msg])
        assert result is None


class TestExecutionResultsParse:
    """ExecutionResults correctly parses ok/error status."""

    def test_has_failures_detection(self) -> None:
        results = ExecutionResults(
            plan_id="test-plan-001",
            results=[
                {"tool": "read_file", "status": "ok", "source": "log.txt", "error": None},
                {"tool": "grep", "status": "error", "source": None, "error": "timeout"},
            ],
            turns_used=5,
            has_failures=True,
        )
        assert results.has_failures is True
        assert len(results.results) == 2

    def test_no_failures(self) -> None:
        results = ExecutionResults(
            plan_id="test-plan-002",
            results=[{"tool": "read_file", "status": "ok", "source": "a.txt", "error": None}],
            turns_used=2,
            has_failures=False,
        )
        assert results.has_failures is False


class TestFollowUpDetection:
    """Follow-up requests are found in analyst messages."""

    def test_finds_follow_up(self) -> None:
        follow_up = json.dumps(
            {
                "request": "additional_plan",
                "reason": "Need more network data",
                "focus_areas": ["lateral_movement"],
            }
        )
        result = extract_follow_up_request(["Analysis complete.", follow_up])
        assert result is not None
        assert result["request"] == "additional_plan"
        assert result["reason"] == "Need more network data"

    def test_fenced_follow_up(self) -> None:
        msg = (
            "I need more data:\n"
            "```json\n"
            '{"request": "additional_plan", "reason": "incomplete"}\n'
            "```"
        )
        result = extract_follow_up_request([msg])
        assert result is not None


class TestNoFollowUp:
    """Returns None when analyst does not request follow-up."""

    def test_no_json_no_follow_up(self) -> None:
        result = extract_follow_up_request(["Analysis is complete. No further action needed."])
        assert result is None

    def test_wrong_request_value(self) -> None:
        msg = json.dumps({"request": "something_else", "reason": "nope"})
        result = extract_follow_up_request([msg])
        assert result is None

    def test_empty_messages(self) -> None:
        result = extract_follow_up_request([])
        assert result is None


class TestPlanDataclass:
    """Plan dataclass holds structured plan data."""

    def test_plan_fields(self) -> None:
        plan = Plan(
            plan_id="catalog-plan-case001-abc123",
            tasks=[{"tool": "read", "args": {}, "purpose": "test"}],
            investigation_questions=["What happened?"],
            expected_sources=["syslog"],
            raw_text="raw output here",
            turns_used=3,
        )
        assert plan.plan_id == "catalog-plan-case001-abc123"
        assert plan.turns_used == 3
        assert len(plan.tasks) == 1


class TestAnalystResult:
    """AnalystResult dataclass holds analyst output."""

    def test_analyst_result_fields(self) -> None:
        result = AnalystResult(
            findings_submitted=2,
            follow_up_request=None,
            messages=["Found suspicious activity"],
            turns_used=7,
        )
        assert result.findings_submitted == 2
        assert result.follow_up_request is None
        assert result.turns_used == 7
