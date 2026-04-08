"""Evidence extraction pipeline framework."""

from killjoy.extractors.base import (
    ExtractionResult,
    Extractor,
    ExtractorRegistry,
    default_registry,
)
from killjoy.extractors.classifier import ClassifiedEvidence, EvidenceClassifier
from killjoy.extractors.volatility import VolatilityExtractor

__all__ = [
    "ClassifiedEvidence",
    "EvidenceClassifier",
    "ExtractionResult",
    "Extractor",
    "ExtractorRegistry",
    "VolatilityExtractor",
    "default_registry",
]
