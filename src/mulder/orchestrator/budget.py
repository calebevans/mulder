"""Run-level token tally and the optional budget every session start is checked against.

One ``TokenBudget`` lives for the length of ``mulder investigate``. Every
session's final ``ResultMessage`` is added to it, and ``SessionExecutor``
asks it before starting a session. The budget is counted in tokens because
every provider path reports them; Claude Code's dollar figure is priced from
its own table and is wrong for models behind the LiteLLM proxy.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

#: Tally key -> its name in ``ResultMessage.model_usage`` (camelCase, one entry
#: per model the CLI called) and in ``ResultMessage.usage`` (snake_case, the
#: Anthropic API's own names). The four kinds are disjoint: ``input`` is
#: uncached input only, so a cached prompt is counted once, under
#: ``cache_read``.
_KINDS: dict[str, tuple[str, str]] = {
    "input": ("inputTokens", "input_tokens"),
    "output": ("outputTokens", "output_tokens"),
    "cache_creation": ("cacheCreationInputTokens", "cache_creation_input_tokens"),
    "cache_read": ("cacheReadInputTokens", "cache_read_input_tokens"),
}

#: The share of ``--max-tokens`` held back for the report phase, and the least
#: it may be. Analysis stops starting sessions once what remains is down to
#: this, so that the run ends with a written report rather than mid-extraction.
#: The floor is one report session with room to spare: in the published GLM-5
#: NDLC run (one host, no prompt caching, so the whole replayed context is
#: counted) the report session used 646K tokens out of 8.8M. Too small a
#: reserve costs only the model-written narrative, since a partial report is
#: rendered from the database either way; too large a one stops analysis
#: early with budget unspent.
REPORT_RESERVE_FRACTION = 0.15
REPORT_RESERVE_FLOOR = 750_000


def report_reserve(limit: int) -> int:
    """Return how much of a *limit*-token budget is held back for the report.

    Args:
        limit: The run's token budget.

    Returns:
        ``REPORT_RESERVE_FRACTION`` of it, at least ``REPORT_RESERVE_FLOOR``,
        and never more than half, so a small budget still leaves room for
        analysis.
    """
    return min(limit // 2, max(int(limit * REPORT_RESERVE_FRACTION), REPORT_RESERVE_FLOOR))


class TokenBudgetReached(Exception):
    """A session was not started because the run's token budget is used up.

    Not a fatal error: the pipeline skips what is left of the analysis and
    goes to the report phase.
    """


class TokenBudget:
    """Tokens used so far in this run, per model, and the limit on them.

    Attributes:
        limit: Most tokens the run may use, or None for no limit.
        reserve: Tokens ``check`` keeps back. The orchestrator sets it to 0
            when the report phase starts, which is what it was kept for.
        by_model: Tokens of each kind (``input``, ``output``,
            ``cache_creation``, ``cache_read``) per model name.
    """

    def __init__(self, limit: int | None = None) -> None:
        """Start an empty tally.

        Args:
            limit: Most tokens the run may use, or None for no limit.
        """
        self.limit = limit
        self.reserve = report_reserve(limit) if limit else 0
        self.by_model: dict[str, dict[str, int]] = {}

    @property
    def used(self) -> int:
        """Tokens of every kind, summed over every model."""
        return sum(sum(counts.values()) for counts in self.by_model.values())

    def total(self, kind: str) -> int:
        """Tokens of one *kind* (a ``by_model`` key), summed over every model."""
        return sum(counts[kind] for counts in self.by_model.values())

    def record(
        self, result: object, model: str, model_usage: dict[str, Any] | None = None
    ) -> None:
        """Add the usage a finished session reported.

        Args:
            result: The session's ``ResultMessage``. Its ``model_usage`` is
                used when present; otherwise its ``usage``, which covers the
                session's own model only.
            model: The session's model, for a result without ``model_usage``.
            model_usage: Per-model usage to count in place of the result's
                own. A resumed session reports its running total there, so
                the session layer passes only what the query added.
        """
        per_model = getattr(result, "model_usage", None) if model_usage is None else model_usage
        key = 0
        if not (isinstance(per_model, dict) and per_model):
            per_model, key = {model: getattr(result, "usage", None)}, 1
        before = self.used
        for name, usage in per_model.items():
            if not isinstance(usage, dict):
                continue
            # A count only: anything else a gateway sends is ignored.
            added = {
                kind: value
                for kind, names in _KINDS.items()
                if isinstance(value := usage.get(names[key]), int) and value > 0
            }
            if not added:
                # No entry for a model that reported nothing (a session that
                # failed before its first reply): an all-zero entry would
                # replace the report's estimate with zeros.
                continue
            counts = self.by_model.setdefault(str(name), dict.fromkeys(_KINDS, 0))
            for kind, value in added.items():
                counts[kind] += value
        logger.info(
            "Token tally: +%d -> %d used%s",
            self.used - before,
            self.used,
            f" of {self.limit}" if self.limit else "",
        )

    def check(self) -> None:
        """Refuse to start a session once what remains is down to the reserve.

        Raises:
            TokenBudgetReached: A limit is set and ``limit - used`` is at or
                below ``reserve``.
        """
        if self.limit is None or self.limit - self.used > self.reserve:
            return
        held = f"; {self.reserve:,} are held back for the report" if self.reserve else ""
        raise TokenBudgetReached(f"{self.used:,} of {self.limit:,} tokens used{held}")
