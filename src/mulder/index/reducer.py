"""Cordon-backed output reduction for verbose forensic tool outputs."""

from __future__ import annotations

import logging
import re
import tempfile
from html import unescape
from pathlib import Path

from cordon import AnalysisConfig, SemanticLogAnalyzer
from pydantic import BaseModel

logger = logging.getLogger(__name__)

_ALWAYS_REDUCE: frozenset[str] = frozenset(
    {
        "plaso.timeline",
        "volatility.handles",
        "evtx.security",
        "evtx.system",
    }
)

_NEVER_REDUCE: frozenset[str] = frozenset(
    {
        "prefetch.all",
        "volatility.cmdline",
    }
)

_NEVER_REDUCE_PREFIX = "registry."

_BLOCK_TAG_RE = re.compile(
    r'<block\s+lines="(\d+)-(\d+)"\s+score="([^"]+)">\s*\n(.*?)\n\s*</block>',
    re.DOTALL,
)


class ReducerConfig(BaseModel):
    """Configuration for Cordon-backed output reduction."""

    backend: str = "sentence-transformers"
    model_name: str = "all-MiniLM-L6-v2"
    api_key: str | None = None
    k_neighbors: int = 10
    min_lines_for_reduction: int = 50


class ReducedBlock(BaseModel):
    """A single anomalous block extracted by Cordon."""

    line_start: int
    line_end: int
    score: float
    text: str


class ReducedOutput(BaseModel):
    """Result of reducing a verbose text output via Cordon anomaly detection."""

    text: str
    original_lines: int
    retained_lines: int
    reduction_ratio: float
    blocks: list[ReducedBlock]


class OutputReducer:
    """Reduces verbose tool output using Cordon's anomaly detection.

    Verbose forensic artifacts (Plaso timelines, large EVTX channels, etc.)
    are scored for anomalousness and only the significant blocks are retained,
    keeping context-window usage manageable for the investigation agent.
    """

    def __init__(self, config: ReducerConfig | None = None) -> None:
        self._config = config or ReducerConfig()

    def reduce(self, text: str, target_percentile: float = 0.1) -> ReducedOutput:
        """Score *text* with Cordon and return only the anomalous blocks.

        The full text is written to a temporary file, analysed by
        ``SemanticLogAnalyzer``, and the XML-tagged output is parsed to
        extract per-block line ranges, scores, and content.
        """
        lines = text.splitlines()
        original_lines = len(lines)

        if original_lines < self._config.min_lines_for_reduction:
            return ReducedOutput(
                text=text,
                original_lines=original_lines,
                retained_lines=original_lines,
                reduction_ratio=1.0,
                blocks=[
                    ReducedBlock(
                        line_start=1,
                        line_end=original_lines,
                        score=0.0,
                        text=text,
                    )
                ],
            )

        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".log", delete=False, encoding="utf-8"
            ) as tmp:
                tmp_path = Path(tmp.name)
                tmp.write(text)

            cordon_kwargs: dict = {
                "anomaly_percentile": target_percentile,
                "model_name": self._config.model_name,
                "k_neighbors": self._config.k_neighbors,
            }
            if self._config.backend == "remote":
                cordon_kwargs["backend"] = "remote"
                if self._config.api_key:
                    cordon_kwargs["api_key"] = self._config.api_key
            cordon_config = AnalysisConfig(**cordon_kwargs)
            analyzer = SemanticLogAnalyzer(cordon_config)
            result = analyzer.analyze_file_detailed(tmp_path)

            blocks = _parse_blocks(result.output)
            if blocks:
                reduced_text = "\n\n".join(b.text for b in blocks)
                retained = sum(b.line_end - b.line_start + 1 for b in blocks)
            else:
                reduced_text = result.output
                retained = original_lines

            ratio = retained / original_lines if original_lines > 0 else 1.0

            return ReducedOutput(
                text=reduced_text,
                original_lines=original_lines,
                retained_lines=retained,
                reduction_ratio=ratio,
                blocks=blocks,
            )
        except Exception:
            logger.exception("Cordon reduction failed; returning original text")
            return ReducedOutput(
                text=text,
                original_lines=original_lines,
                retained_lines=original_lines,
                reduction_ratio=1.0,
                blocks=[],
            )
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

    def should_reduce(self, source_name: str, text_length: int) -> bool:
        """Decide whether *source_name* with *text_length* bytes warrants reduction."""
        if source_name in _ALWAYS_REDUCE:
            return True
        if source_name in _NEVER_REDUCE or source_name.startswith(_NEVER_REDUCE_PREFIX):
            return False
        return text_length > self._config.min_lines_for_reduction * 80


def _parse_blocks(xml_output: str) -> list[ReducedBlock]:
    """Extract ``ReducedBlock`` entries from Cordon's XML-tagged output."""
    blocks: list[ReducedBlock] = []
    for m in _BLOCK_TAG_RE.finditer(xml_output):
        start, end, score_str, raw_content = m.group(1), m.group(2), m.group(3), m.group(4)
        content = "\n".join(
            line[4:] if line.startswith("    ") else line for line in raw_content.splitlines()
        )
        content = unescape(content)
        blocks.append(
            ReducedBlock(
                line_start=int(start),
                line_end=int(end),
                score=float(score_str),
                text=content,
            )
        )
    return blocks
