"""Token budget planner for per-source raw vs. reduced output decisions."""

from __future__ import annotations

import logging

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class SourceBudgetInput(BaseModel):
    """A single source whose token cost needs to be planned."""

    source_name: str
    text: str
    estimated_tokens: int | None = None


class SourceBudgetPlan(BaseModel):
    """Budget decision for a single source."""

    source_name: str
    needs_reduction: bool
    anomaly_percentile: float | None = None
    estimated_tokens: int


class TokenBudgetPlanner:
    """Decides per-source whether to return raw or Cordon-reduced output.

    Implements a greedy fair-share algorithm: sources are sorted by
    ascending token count, and each is allocated a fair share of the
    remaining budget.  Sources that fit within their share are kept raw;
    those that exceed it are marked for Cordon reduction with an
    ``anomaly_percentile`` proportional to how much they need to shrink.
    """

    def __init__(
        self,
        total_budget_tokens: int = 100_000,
        model: str = "claude-sonnet-4-20250514",
    ) -> None:
        self._budget = total_budget_tokens
        self._model = model

    def plan(self, sources: list[SourceBudgetInput]) -> list[SourceBudgetPlan]:
        """Produce a budget plan for each source."""
        if not sources:
            return []

        estimated = [
            (src, src.estimated_tokens or self._estimate_tokens(src.text)) for src in sources
        ]

        estimated.sort(key=lambda pair: pair[1])

        total_tokens = sum(t for _, t in estimated)
        if total_tokens <= self._budget:
            return [
                SourceBudgetPlan(
                    source_name=src.source_name,
                    needs_reduction=False,
                    estimated_tokens=tokens,
                )
                for src, tokens in estimated
            ]

        remaining_budget = self._budget
        remaining_count = len(estimated)
        plans: list[SourceBudgetPlan] = []

        for src, tokens in estimated:
            fair_share = remaining_budget // remaining_count if remaining_count > 0 else 0

            if tokens <= fair_share:
                plans.append(
                    SourceBudgetPlan(
                        source_name=src.source_name,
                        needs_reduction=False,
                        estimated_tokens=tokens,
                    )
                )
                remaining_budget -= tokens
            else:
                percentile = max(fair_share / tokens, 0.01) if tokens > 0 else 0.01
                plans.append(
                    SourceBudgetPlan(
                        source_name=src.source_name,
                        needs_reduction=True,
                        anomaly_percentile=percentile,
                        estimated_tokens=tokens,
                    )
                )
                remaining_budget -= fair_share

            remaining_count -= 1

        return plans

    def _estimate_tokens(self, text: str) -> int:
        """Estimate the token count for *text*."""
        try:
            from litellm import token_counter

            return token_counter(model=self._model, text=text)
        except Exception:
            logger.debug("litellm token counting unavailable; falling back to len//4")
            return len(text) // 4
