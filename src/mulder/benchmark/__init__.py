"""Offline, deterministic evaluation contracts for Mulder investigations.

The package exposes deterministic scoring and bounded real-component workflow
execution plus strict versioned input/output models. It has no provider, MCP,
or network integration.
"""

from mulder.benchmark.ablations import (
    execute_ablations,
    execute_workflow_base,
    validate_ablation_result,
)
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
    "execute_workflow_base",
    "score_benchmark",
    "validate_ablation_result",
]
