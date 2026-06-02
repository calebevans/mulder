"""Extractor protocol, result container, and registry for evidence extraction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class Extractor(Protocol):
    """Contract for all evidence extractors.

    Each extractor knows how to handle one class of forensic artifact (memory
    dumps, disk images, log files, etc.) and produces plain-text output ready
    for windowing and indexing.
    """

    name: str

    def can_handle(self, path: Path) -> bool:
        """Return True if this extractor handles the given file."""
        ...

    def extract(self, path: Path, case_id: str) -> list[ExtractionResult]:
        """Run extraction, return one ExtractionResult per logical source."""
        ...

    def version(self) -> str:
        """Return the version string of the underlying tool."""
        ...


@dataclass
class ExtractionResult:
    """One logical source produced by an extractor.

    For example, running Volatility's pslist plugin produces a single
    ExtractionResult with ``source_name="volatility.pslist"``.
    """

    source_name: str
    source_path: str
    extractor: str
    text_output: str
    line_count: int


class ExtractorRegistry:
    """Ordered registry of extractors; first match wins."""

    def __init__(self) -> None:
        """Create an empty registry."""
        self._extractors: list[Extractor] = []

    def register(self, extractor: Extractor) -> None:
        """Append *extractor*; earlier entries win in :meth:`get_extractor_for`."""
        self._extractors.append(extractor)

    def get_extractor_for(self, path: Path) -> Extractor | None:
        """Return the first registered extractor for which ``can_handle(path)`` is true."""
        for ext in self._extractors:
            if ext.can_handle(path):
                return ext
        return None

    def get_all_extractors_for(self, path: Path) -> list[Extractor]:
        """Return every registered extractor that can handle *path*."""
        return [ext for ext in self._extractors if ext.can_handle(path)]

    def all_extractors(self) -> list[Extractor]:
        """Return all registered extractors in registration order."""
        return list(self._extractors)
