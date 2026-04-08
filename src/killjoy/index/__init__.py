"""Semantic index: embedding, querying, correlation, and reduction."""

from killjoy.index.correlator import CorrelationResult, Correlator
from killjoy.index.embedder import Embedder
from killjoy.index.query import BaselineStats, QueryEngine, ScoredWindow

__all__ = [
    "BaselineStats",
    "CorrelationResult",
    "Correlator",
    "Embedder",
    "QueryEngine",
    "ScoredWindow",
]
