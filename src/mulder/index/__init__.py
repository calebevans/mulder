"""Semantic index: embedding, querying, correlation, and reduction."""

from mulder.index.budget import SourceBudgetInput, SourceBudgetPlan, TokenBudgetPlanner
from mulder.index.correlator import CorrelationResult, Correlator
from mulder.index.embedder import Embedder
from mulder.index.query import BaselineStats, QueryEngine, ScoredWindow
from mulder.index.reducer import OutputReducer, ReducedBlock, ReducedOutput, ReducerConfig

__all__ = [
    "BaselineStats",
    "CorrelationResult",
    "Correlator",
    "Embedder",
    "OutputReducer",
    "QueryEngine",
    "ReducedBlock",
    "ReducedOutput",
    "ReducerConfig",
    "ScoredWindow",
    "SourceBudgetInput",
    "SourceBudgetPlan",
    "TokenBudgetPlanner",
]
