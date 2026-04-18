"""Cross-source correlation engine for time-range evidence joins."""

from __future__ import annotations

from pydantic import BaseModel

from mulder.db import CaseDB
from mulder.models import WindowRow


class CorrelationResult(BaseModel):
    time_start: str
    time_end: str
    sources_queried: list[str]
    windows_by_source: dict[str, list[WindowRow]]
    total_windows: int


class Correlator:
    """Joins windows from multiple sources within a time range.

    The agent uses this to cross-check: "At timestamp T, what did each
    artifact type see?"
    """

    def __init__(self, db: CaseDB) -> None:
        """Attach the case database used to query evidence windows."""
        self._db = db

    def correlate_across_sources(
        self,
        time_start: str,
        time_end: str,
        sources: list[str] | None = None,
    ) -> CorrelationResult:
        """Return time-window rows grouped by source, optionally limited to *sources*."""
        if sources is None:
            sources = [s.source_name for s in self._db.get_sources()]

        windows_by_source: dict[str, list[WindowRow]] = {}
        total = 0
        for src in sources:
            wins = self._db.get_windows_by_source(src, time_start, time_end)
            if wins:
                windows_by_source[src] = wins
                total += len(wins)

        return CorrelationResult(
            time_start=time_start,
            time_end=time_end,
            sources_queried=sources,
            windows_by_source=windows_by_source,
            total_windows=total,
        )
