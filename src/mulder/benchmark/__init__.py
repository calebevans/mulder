"""Offline, deterministic evaluation contracts for Mulder investigations.

The package exposes one scoring operation plus strict versioned input/output
models. It deliberately has no orchestrator, provider, MCP, or network imports.
"""

from mulder.benchmark.ablations import execute_ablations, validate_ablation_result
from mulder.benchmark.models import (
    BenchmarkManifest,
    BenchmarkRunResult,
    BenchmarkScoreDocument,
)
from mulder.benchmark.scorer import score_benchmark

__all__ = [
    "BenchmarkManifest",
    "BenchmarkRunResult",
    "BenchmarkScoreDocument",
    "execute_ablations",
    "score_benchmark",
    "validate_ablation_result",
]
