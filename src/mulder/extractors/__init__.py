"""Evidence extraction pipeline framework."""

from mulder.extractors.base import (
    ExtractionResult,
    Extractor,
    ExtractorRegistry,
    default_registry,
)
from mulder.extractors.classifier import ClassifiedEvidence, EvidenceClassifier
from mulder.extractors.disk import DiskImageExtractor
from mulder.extractors.logs import LogFileExtractor
from mulder.extractors.plaso import PlasoExtractor
from mulder.extractors.volatility import VolatilityExtractor

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
