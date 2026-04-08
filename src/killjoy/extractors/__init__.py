"""Evidence extraction pipeline framework."""

from killjoy.extractors.base import (
    ExtractionResult,
    Extractor,
    ExtractorRegistry,
    default_registry,
)
from killjoy.extractors.classifier import ClassifiedEvidence, EvidenceClassifier
from killjoy.extractors.disk import DiskImageExtractor
from killjoy.extractors.logs import LogFileExtractor
from killjoy.extractors.plaso import PlasoExtractor
from killjoy.extractors.volatility import VolatilityExtractor

__all__ = [
    "ClassifiedEvidence",
    "DiskImageExtractor",
    "EvidenceClassifier",
    "ExtractionResult",
    "Extractor",
    "ExtractorRegistry",
    "LogFileExtractor",
    "PlasoExtractor",
    "VolatilityExtractor",
    "default_registry",
]
