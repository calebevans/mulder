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
    for windowing and embedding.
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
        self._extractors: list[Extractor] = []

    def register(self, extractor: Extractor) -> None:
        self._extractors.append(extractor)

    def get_extractor_for(self, path: Path) -> Extractor | None:
        for ext in self._extractors:
            if ext.can_handle(path):
                return ext
        return None

    def all_extractors(self) -> list[Extractor]:
        return list(self._extractors)


def default_registry() -> ExtractorRegistry:
    """Return a registry with all known extractors.

    Concrete extractors (Volatility, Plaso, disk, logs) are registered here
    once Pieces 3/4 are implemented.  Until then this returns an empty
    registry so the ingestion pipeline runs without error.
    """
    return ExtractorRegistry()
