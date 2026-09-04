"""Public re-exports for evidence classification."""

from mulder.extractors.classifier import ClassifiedEvidence, ClassifierConfig, EvidenceClassifier

__all__ = [
    "ClassifierConfig",
    "ClassifiedEvidence",
    "EvidenceClassifier",
]
