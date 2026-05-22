"""Public re-exports for extractors, registry helpers, and evidence classification."""

# Defined before submodule imports so that modules in this package can
# ``from mulder.extractors import DISK_IMAGE_EXTS`` without circular-import issues.
DISK_IMAGE_EXTS: frozenset[str] = frozenset({".e01", ".dd", ".img"})

from mulder.extractors.base import (  # noqa: E402
    ExtractionResult,
    Extractor,
    ExtractorRegistry,
    default_registry,
)
from mulder.extractors.classifier import ClassifiedEvidence, EvidenceClassifier  # noqa: E402
from mulder.extractors.disk import DiskImageExtractor  # noqa: E402
from mulder.extractors.eztools import EZToolsExtractor  # noqa: E402
from mulder.extractors.logs import LogFileExtractor  # noqa: E402
from mulder.extractors.plaso import PlasoExtractor  # noqa: E402
from mulder.extractors.volatility import VolatilityExtractor  # noqa: E402

__all__ = [
    "DISK_IMAGE_EXTS",
    "ClassifiedEvidence",
    "DiskImageExtractor",
    "EZToolsExtractor",
    "EvidenceClassifier",
    "ExtractionResult",
    "Extractor",
    "ExtractorRegistry",
    "LogFileExtractor",
    "PlasoExtractor",
    "VolatilityExtractor",
    "default_registry",
]
