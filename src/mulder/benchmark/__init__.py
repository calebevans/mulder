"""Offline, deterministic evaluation contracts for Mulder investigations.

The package exposes one scoring operation plus strict versioned input/output
models. It deliberately has no orchestrator, provider, MCP, or network imports.
"""

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
    "score_benchmark",
]
