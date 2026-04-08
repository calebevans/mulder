"""Text windowing and sentence-transformers embedding for sqlite-vec storage."""

from __future__ import annotations

import re
from datetime import datetime

import numpy as np
from sentence_transformers import SentenceTransformer

_ISO_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
)

_SYSLOG_RE = re.compile(
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})"
)

_SYSLOG_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_PLASO_DATE_RE = re.compile(
    r"(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})"
)


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

    Loads a sentence-transformers model once and reuses it for all
    embedding operations.  Device is auto-detected (CUDA > MPS > CPU).
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self._model = SentenceTransformer(model_name)

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

        windows: list[tuple[str, int, int]] = []
        for i in range(0, len(lines), window_size):
            chunk = lines[i : i + window_size]
            raw = "\n".join(chunk)
            line_start = i + 1
            line_end = i + len(chunk)
            windows.append((raw, line_start, line_end))

        if not windows:
            return []

        texts = [w[0] for w in windows]
        embeddings = self._model.encode(
            texts,
            normalize_embeddings=True,
            show_progress_bar=False,
        )

        results: list[tuple[str, int, int, bytes, str | None]] = []
        for (raw, line_start, line_end), emb in zip(windows, embeddings):
            emb_bytes = np.asarray(emb, dtype=np.float32).tobytes()
            event_time = _parse_timestamp(raw)
            results.append((raw, line_start, line_end, emb_bytes, event_time))

        return results

    def embed_query(self, query_text: str) -> bytes:
        """Embed a single query string for k-NN search."""
        emb = self._model.encode(
            [query_text],
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return np.asarray(emb[0], dtype=np.float32).tobytes()
