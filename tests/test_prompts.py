"""Tests for mulder.orchestrator.prompts -- prompt loading and constraints."""

from __future__ import annotations

import mulder.orchestrator.prompts as prompts


class TestPromptLoading:
    """All prompts load successfully and have content."""

    def test_all_prompts_importable(self) -> None:
        """Every exported prompt constant is a non-empty string."""
        exported = [
            name for name in dir(prompts) if name.endswith("_PROMPT") and not name.startswith("_")
        ]
        assert len(exported) >= 14
        for name in exported:
            val = getattr(prompts, name)
            assert isinstance(val, str), f"{name} is not a string"

    def test_no_empty_prompts(self) -> None:
        """Every prompt constant has meaningful content (>50 chars)."""
        exported = [
            name for name in dir(prompts) if name.endswith("_PROMPT") and not name.startswith("_")
        ]
        for name in exported:
            val = getattr(prompts, name)
            assert len(val) > 50, f"{name} is suspiciously short ({len(val)} chars)"


class TestPromptConstraints:
    """Role-specific prompts enforce correct boundaries."""

    def test_planner_prompts_require_json(self) -> None:
        """All planner prompts mention JSON output requirement."""
        planner_prompts = [
            ("EXTRACT_PLANNER_PROMPT", prompts.EXTRACT_PLANNER_PROMPT),
            ("CROSS_SYSTEM_PLANNER_PROMPT", prompts.CROSS_SYSTEM_PLANNER_PROMPT),
            ("NARRATIVE_PLANNER_PROMPT", prompts.NARRATIVE_PLANNER_PROMPT),
            ("AUDIT_PLANNER_PROMPT", prompts.AUDIT_PLANNER_PROMPT),
        ]
        for name, text in planner_prompts:
            assert "JSON" in text or "json" in text, (
                f"{name} does not mention JSON output requirement"
            )

    def test_executor_prompts_forbid_findings(self) -> None:
        """Non-audit executor prompts instruct agents not to submit findings.

        The audit executor is excluded because gap remediation explicitly
        requires submitting findings for newly discovered evidence.
        """
        executor_prompts = [
            ("EXTRACT_EXECUTOR_PROMPT", prompts.EXTRACT_EXECUTOR_PROMPT),
            ("CROSS_SYSTEM_EXECUTOR_PROMPT", prompts.CROSS_SYSTEM_EXECUTOR_PROMPT),
            ("NARRATIVE_EXECUTOR_PROMPT", prompts.NARRATIVE_EXECUTOR_PROMPT),
        ]
        for name, text in executor_prompts:
            lower = text.lower()
            assert "submit_finding" in lower or "submit findings" in lower, (
                f"{name} does not forbid submit_finding"
            )

    def test_analyst_prompts_forbid_extraction(self) -> None:
        """Analyst prompts instruct agents not to call extraction tools."""
        analyst_prompts = [
            ("EXTRACT_ANALYST_PROMPT", prompts.EXTRACT_ANALYST_PROMPT),
            ("CROSS_SYSTEM_ANALYST_PROMPT", prompts.CROSS_SYSTEM_ANALYST_PROMPT),
            ("NARRATIVE_ANALYST_PROMPT", prompts.NARRATIVE_ANALYST_PROMPT),
            ("AUDIT_ANALYST_PROMPT", prompts.AUDIT_ANALYST_PROMPT),
        ]
        for name, text in analyst_prompts:
            lower = text.lower()
            assert "extraction tool" in lower or "run_volatility" in lower, (
                f"{name} does not forbid extraction tools"
            )

    def test_extraction_executor_mentions_wait(self) -> None:
        """Extraction executor prompt instructs using wait() for batches.

        Only the extraction executor dispatches slow forensic tool batches
        that require polling with wait(). Other executors use fast queries.
        """
        assert "wait" in prompts.EXTRACT_EXECUTOR_PROMPT.lower()
