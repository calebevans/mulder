"""Semantic search, k-NN density anomaly scoring, and baseline statistics."""

from __future__ import annotations

import math
from functools import cached_property

import numpy as np
from pydantic import BaseModel

from mulder.db import CaseDB
from mulder.index.embedder import Embedder
from mulder.models import WindowRow

_ANOMALY_K = 10
_EMBEDDING_DIM = 384


class ScoredWindow(BaseModel):
    window: WindowRow
    score: float
    source_name: str


class BaselineStats(BaseModel):
    source_name: str
    total_windows: int
    score_min: float
    score_mean: float
    score_median: float
    score_p90: float
    score_max: float


class QueryEngine:
    """Executes semantic and structured queries against a per-case index."""

    def __init__(self, db: CaseDB, embedder: Embedder) -> None:
        self._db = db
        self._embedder = embedder

    @cached_property
    def _source_name_map(self) -> dict[int, str]:
        return {s.source_id: s.source_name for s in self._db.get_sources()}

    def _resolve_source_name(self, source_id: int) -> str:
        name = self._source_name_map.get(source_id)
        if name is not None:
            return name
        # Cache miss after new sources were registered; rebuild.
        type(self)._source_name_map.fget.cache_clear()  # type: ignore[union-attr]
        self.__dict__.pop("_source_name_map", None)
        return self._source_name_map.get(source_id, f"unknown:{source_id}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def semantic_search(
        self,
        query: str,
        k: int = 20,
        source_name: str | None = None,
        time_start: str | None = None,
        time_end: str | None = None,
    ) -> list[ScoredWindow]:
        """Embed *query* and return the closest *k* windows."""
        query_emb = self._embedder.embed_query(query)
        results = self._db.knn_query_scored(query_emb, k, source_name, time_start, time_end)
        return [
            ScoredWindow(
                window=win,
                score=dist,
                source_name=self._resolve_source_name(win.source_id),
            )
            for win, dist in results
        ]

    def get_anomalies(
        self,
        source_name: str,
        time_start: str | None = None,
        time_end: str | None = None,
        top_percent: float = 0.1,
    ) -> list[ScoredWindow]:
        """Return the most anomalous windows in a source by k-NN density."""
        windows = self._db.get_windows_by_source(source_name, time_start, time_end)
        if not windows:
            return []

        scores = self._compute_anomaly_scores(source_name, time_start, time_end)
        if not scores:
            return []

        id_to_score = dict(scores)
        scored = [
            ScoredWindow(
                window=w,
                score=id_to_score.get(w.window_id, 0.0),
                source_name=source_name,
            )
            for w in windows
            if w.window_id in id_to_score
        ]
        scored.sort(key=lambda s: s.score, reverse=True)
        n = max(1, math.ceil(len(scored) * top_percent))
        return scored[:n]

    def get_baseline_stats(self, source_name: str) -> BaselineStats:
        """Compute anomaly-score distribution statistics for a source."""
        scores = self._compute_anomaly_scores(source_name)
        if not scores:
            return BaselineStats(
                source_name=source_name,
                total_windows=0,
                score_min=0.0,
                score_mean=0.0,
                score_median=0.0,
                score_p90=0.0,
                score_max=0.0,
            )

        vals = np.array([s for _, s in scores], dtype=np.float64)
        return BaselineStats(
            source_name=source_name,
            total_windows=len(vals),
            score_min=float(np.min(vals)),
            score_mean=float(np.mean(vals)),
            score_median=float(np.median(vals)),
            score_p90=float(np.percentile(vals, 90)),
            score_max=float(np.max(vals)),
        )

    def get_windows_in_range(
        self,
        source_name: str,
        time_start: str,
        time_end: str,
    ) -> list[WindowRow]:
        """Direct time-range query with no scoring."""
        return self._db.get_windows_by_source(source_name, time_start, time_end)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_anomaly_scores(
        self,
        source_name: str,
        time_start: str | None = None,
        time_end: str | None = None,
    ) -> list[tuple[int, float]]:
        """Batch k-NN density scoring for every window in a source.

        Returns ``(window_id, anomaly_score)`` pairs.  Higher score
        means the window is further from its neighbors (more anomalous).
        """
        raw = self._db.get_embeddings_by_source(source_name, time_start, time_end)
        if not raw:
            return []

        ids = [wid for wid, _ in raw]
        emb_matrix = np.stack(
            [np.frombuffer(blob, dtype=np.float32) for _, blob in raw]
        )  # (N, 384)

        # Cosine similarity via dot product (embeddings are L2-normalized).
        sim = emb_matrix @ emb_matrix.T  # (N, N)
        np.clip(sim, -1.0, 1.0, out=sim)
        dist = 1.0 - sim  # cosine distance

        n = len(ids)
        k = min(_ANOMALY_K, n - 1)
        if k < 1:
            return [(wid, 0.0) for wid in ids]

        # For each row, exclude the self-distance (diagonal) and take
        # the mean of the k smallest remaining distances.
        np.fill_diagonal(dist, np.inf)
        partitioned = np.partition(dist, k, axis=1)[:, :k]
        mean_distances = partitioned.mean(axis=1)

        return list(zip(ids, mean_distances.tolist(), strict=True))
