"""Text windowing and embedding for sqlite-vec storage.

Delegates windowing to ``cordon.segmentation.windower`` and embedding to
``cordon.embedding.create_vectorizer`` so that backend dispatch (sentence-
transformers, remote/litellm, llama.cpp), GPU auto-detection, L2
normalisation, and truncation warnings are handled by Cordon.

Mulder adds forensic-specific timestamp parsing on top.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime

import numpy as np
from cordon import AnalysisConfig
from cordon.core.types import TextWindow
from cordon.embedding import create_vectorizer
from cordon.segmentation.windower import SlidingWindowSegmenter

from mulder.models import EmbeddingConfig

logger = logging.getLogger(__name__)

_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")

_SYSLOG_RE = re.compile(
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})"
)

_SYSLOG_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_PLASO_DATE_RE = re.compile(r"(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})")


def _parse_timestamp(text: str) -> str | None:
    """Best-effort timestamp extraction from a text window.

    Tries ISO 8601, syslog, and Plaso L2T CSV formats in order.
    Returns an ISO 8601 string or None.
    """
    m = _ISO_RE.search(text)
    if m:
        raw = m.group(0)
        try:
            dt = datetime.fromisoformat(raw)
            return dt.isoformat()
        except ValueError:
            pass

    m = _SYSLOG_RE.search(text)
    if m:
        month_str, day, hour, minute, second = m.groups()
        try:
            dt = datetime(
                year=datetime.now().year,
                month=_SYSLOG_MONTHS[month_str],
                day=int(day),
                hour=int(hour),
                minute=int(minute),
                second=int(second),
            )
            return dt.isoformat()
        except ValueError:
            pass

    m = _PLASO_DATE_RE.search(text)
    if m:
        month, day, year, hour, minute, second = m.groups()
        try:
            dt = datetime(
                year=int(year),
                month=int(month),
                day=int(day),
                hour=int(hour),
                minute=int(minute),
                second=int(second),
            )
            return dt.isoformat()
        except ValueError:
            pass

    return None


class Embedder:
    """Windows text and produces embeddings for sqlite-vec storage.

    Windowing is handled by Cordon's ``SlidingWindowSegmenter`` and
    embedding by the vectorizer returned from ``cordon.embedding.create_vectorizer``,
    which dispatches to sentence-transformers, remote/litellm, or llama.cpp
    based on the backend field in *config*.
    """

    def __init__(
        self,
        config: EmbeddingConfig | None = None,
        api_key: str | None = None,
    ) -> None:
        self._config = config or EmbeddingConfig()
        self._dim: int | None = None
        self._segmenter = SlidingWindowSegmenter()

        cordon_config = AnalysisConfig(
            backend=self._config.backend,
            model_name=self._config.model_name,
            api_key=api_key,
        )
        logger.info(
            "Creating cordon vectorizer: backend=%s, model=%s",
            self._config.backend,
            self._config.model_name,
        )
        self._vectorizer = create_vectorizer(cordon_config)

    @property
    def embedding_dim(self) -> int:
        """Return the embedding vector dimensionality.

        For local models this is known immediately via the underlying
        SentenceTransformer; for remote models a single probe embedding
        is issued on first access.
        """
        if self._dim is not None:
            return self._dim

        if hasattr(self._vectorizer, "model"):
            dim = self._vectorizer.model.get_sentence_embedding_dimension()
            if dim is not None:
                self._dim = dim
                return self._dim

        probe = TextWindow(content="dimension probe", start_line=1, end_line=1, window_id=0)
        for _, emb in self._vectorizer.embed_windows([probe]):
            self._dim = int(emb.shape[0])
            return self._dim

        raise RuntimeError("Vectorizer produced no embedding for dimension probe")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def window_and_embed(
        self,
        text: str,
        window_size: int = 4,
    ) -> list[tuple[str, int, int, bytes, str | None]]:
        """Split text into windows, embed, and extract timestamps.

        Returns a list of ``(raw_text, line_start, line_end,
        embedding_bytes, event_time)`` tuples.  Line numbers are
        1-based.
        """
        lines = text.splitlines()
        if not lines:
            return []

        line_pairs = ((i + 1, line) for i, line in enumerate(lines))
        segment_config = AnalysisConfig(window_size=window_size)
        windows = [
            w for w in self._segmenter.segment(line_pairs, segment_config) if w.content.strip()
        ]

        if not windows:
            return []

        embedded = list(self._vectorizer.embed_windows(windows))

        results: list[tuple[str, int, int, bytes, str | None]] = []
        for text_window, emb in embedded:
            emb_bytes = np.asarray(emb, dtype=np.float32).tobytes()
            event_time = _parse_timestamp(text_window.content)
            results.append(
                (
                    text_window.content,
                    text_window.start_line,
                    text_window.end_line,
                    emb_bytes,
                    event_time,
                )
            )

        return results

    def embed_query(self, query_text: str) -> bytes:
        """Embed a single query string for k-NN search."""
        window = TextWindow(content=query_text, start_line=1, end_line=1, window_id=0)
        for _, emb in self._vectorizer.embed_windows([window]):
            return np.asarray(emb, dtype=np.float32).tobytes()
        raise RuntimeError("Vectorizer produced no embedding for query")
