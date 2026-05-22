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
        windows_by_source = self._db.get_windows_by_time_range(time_start, time_end)

        if sources is not None:
            windows_by_source = {k: v for k, v in windows_by_source.items() if k in sources}

        total = sum(len(v) for v in windows_by_source.values())

        return CorrelationResult(
            time_start=time_start,
            time_end=time_end,
            sources_queried=sources or list(windows_by_source.keys()),
            windows_by_source=windows_by_source,
            total_windows=total,
        )
