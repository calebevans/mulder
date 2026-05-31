"""Append-only JSONL audit log for a case investigation."""

from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, cast

from mulder.models import (
    AuditSummary,
    ProvenanceChain,
    SourceProvenance,
    ToolCallEntry,
)

if TYPE_CHECKING:
    from mulder.db import CaseDB

logger = logging.getLogger(__name__)

_COST_PER_MTOK_INPUT = 3.0
_COST_PER_MTOK_OUTPUT = 15.0
_MIN_OUTPUT_TOKEN_ESTIMATE = 100


class AuditLog:
    """Append-only JSONL audit log for a case investigation.

    Each ``log_tool_call`` invocation appends a single JSON line and records
    the ``tool_call_id`` in an in-memory index for fast validation by
    ``submit_finding`` and provenance chain resolution.
    """

    def __init__(self, log_path: Path) -> None:
        """Open or create an audit log at ``log_path`` and load existing entries."""
        self._log_path = Path(log_path)
        self._lock = threading.Lock()
        self._tool_call_ids: set[str] = set()
        self._tool_calls: dict[str, dict[str, object]] = {}
        self._finding_entries: dict[str, dict[str, object]] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        """Populate in-memory indexes from an existing JSONL file."""
        if not self._log_path.exists():
            return
        parse_errors = 0
        with open(self._log_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    parse_errors += 1
                    continue
                if isinstance(entry, dict):
                    self._index_entry(cast(dict[str, object], entry))
        if parse_errors > 0:
            logger.warning(
                "Audit log %s: %d lines failed to parse (possible corruption)",
                self._log_path,
                parse_errors,
            )

    def _index_entry(self, entry: dict[str, object]) -> None:
        """Index a parsed audit entry by type (tool_call or finding)."""
        entry_type = entry.get("type")
        if entry_type == "tool_call" and "tool_call_id" in entry:
            tcid = entry["tool_call_id"]
            if not isinstance(tcid, str):
                return
            self._tool_call_ids.add(tcid)
            self._tool_calls[tcid] = entry
        elif entry_type == "finding" and "finding_id" in entry:
            fid = entry["finding_id"]
            if not isinstance(fid, str):
                return
            self._finding_entries[fid] = entry

    def _append(self, entry: dict[str, object]) -> None:
        """Append ``entry`` to the JSONL log file and update in-memory indexes."""
        with self._lock:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
            self._index_entry(entry)

    def log_tool_call(
        self,
        tool_call_id: str,
        tool_name: str,
        params: Mapping[str, object],
        output_hash: str,
        duration_ms: float = 0,
        sub_calls: list[str] | None = None,
        batch_id: str | None = None,
    ) -> None:
        """Record a tool invocation as one JSONL line and index ``tool_call_id``."""
        entry: dict[str, object] = {
            "type": "tool_call",
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "params": dict(params),
            "output_hash": output_hash,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if sub_calls is not None:
            entry["sub_calls"] = sub_calls
        if batch_id is not None:
            entry["batch_id"] = batch_id
        self._append(entry)

    def has_tool_call(self, tool_call_id: str) -> bool:
        """Return True if ``tool_call_id`` appears in this audit log."""
        return tool_call_id in self._tool_call_ids

    @property
    def tool_call_ids(self) -> set[str]:
        """All tool call IDs indexed from the log (copy of the internal set)."""
        return set(self._tool_call_ids)

    def log_ingestion_step(
        self,
        source_name: str,
        source_path: str,
        source_hash: str,
        extractor: str,
        window_count: int,
        duration_ms: float,
    ) -> None:
        """Record a source ingestion step (extractor run and window count)."""
        entry: dict[str, object] = {
            "type": "ingestion",
            "source_name": source_name,
            "source_path": source_path,
            "source_hash": source_hash,
            "extractor": extractor,
            "window_count": window_count,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._append(entry)

    def log_finding_submission(
        self,
        finding_id: str,
        evidence_refs: list[str],
    ) -> None:
        """Record a finding submission and its evidence tool-call references."""
        entry: dict[str, object] = {
            "type": "finding",
            "finding_id": finding_id,
            "evidence_refs": evidence_refs,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._append(entry)

    def get_provenance_chain(self, finding_id: str, db: CaseDB) -> ProvenanceChain:
        """Trace a finding back through tool calls to original evidence files."""
        finding_entry = self._finding_entries.get(finding_id)
        if finding_entry is None:
            raise KeyError(f"No finding with id '{finding_id}' in the audit log")

        raw_refs = finding_entry.get("evidence_refs", [])
        if isinstance(raw_refs, list):
            evidence_refs = [x for x in raw_refs if isinstance(x, str)]
        else:
            evidence_refs = []
        tool_calls, queried_source_names = self._resolve_tool_calls(evidence_refs)
        sources = self._resolve_sources(queried_source_names, db)

        return ProvenanceChain(
            finding_id=finding_id,
            tool_calls=tool_calls,
            sources=sources,
        )

    def _resolve_tool_calls(
        self, evidence_refs: list[str]
    ) -> tuple[list[ToolCallEntry], set[str]]:
        """Map ``evidence_refs`` to ``ToolCallEntry`` rows and collect source names."""
        tool_calls: list[ToolCallEntry] = []
        source_names: set[str] = set()

        for ref in evidence_refs:
            tc = self._tool_calls.get(ref)
            if tc is None:
                continue
            tcid_o = tc.get("tool_call_id", "")
            tname_o = tc.get("tool_name", "")
            params_o = tc.get("params", {})
            outh_o = tc.get("output_hash", "")
            ts_o = tc.get("timestamp", "")
            dur_o = tc.get("duration_ms", 0)
            params: dict[str, object] = (
                cast(dict[str, object], params_o) if isinstance(params_o, dict) else {}
            )
            dur_f = float(dur_o) if isinstance(dur_o, int | float) else 0.0
            bid_o = tc.get("batch_id")
            tool_calls.append(
                ToolCallEntry(
                    tool_call_id=tcid_o if isinstance(tcid_o, str) else "",
                    tool_name=tname_o if isinstance(tname_o, str) else "",
                    params=params,
                    output_hash=outh_o if isinstance(outh_o, str) else "",
                    timestamp=ts_o if isinstance(ts_o, str) else "",
                    duration_ms=dur_f,
                    batch_id=bid_o if isinstance(bid_o, str) else None,
                )
            )
            source_names.update(self._extract_source_names(params))

        return tool_calls, source_names

    @staticmethod
    def _extract_source_names(params: dict[str, object]) -> set[str]:
        """Collect source identifiers from tool ``params`` (keys, channel, lists)."""
        names: set[str] = set()
        for key in ("source", "source_name"):
            val = params.get(key)
            if isinstance(val, str):
                names.add(val)
        channel = params.get("channel")
        if channel is not None:
            names.add(f"evtx.{channel}")
        sources_list = params.get("sources")
        if isinstance(sources_list, list):
            names.update(x for x in sources_list if isinstance(x, str))
        return names

    @staticmethod
    def _resolve_sources(queried_names: set[str], db: CaseDB) -> list[SourceProvenance]:
        """Look up ``SourceProvenance`` rows in the case DB for ``queried_names``."""
        db_sources = {s.source_name: s for s in db.get_sources()}
        return [
            SourceProvenance(
                source_name=src.source_name,
                source_path=src.source_path,
                source_hash=src.source_hash,
                extractor=src.extractor,
            )
            for name in sorted(queried_names)
            if (src := db_sources.get(name)) is not None
        ]

    def summary(self) -> AuditSummary:
        """Compute aggregate statistics over the full audit log."""
        total_tool_calls = 0
        total_findings = 0
        tool_call_counts: dict[str, int] = defaultdict(int)
        tool_durations: dict[str, float] = defaultdict(float)
        total_duration_ms = 0.0
        timestamps: list[str] = []
        estimated_input_tokens = 0
        estimated_output_tokens = 0

        if not self._log_path.exists():
            return AuditSummary(
                total_tool_calls=0,
                total_findings=0,
                tool_call_counts={},
                total_duration_ms=0.0,
                first_timestamp="",
                last_timestamp="",
            )

        with open(self._log_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ts = entry.get("timestamp")
                if ts:
                    timestamps.append(ts)

                entry_type = entry.get("type")
                if entry_type == "tool_call":
                    tool_name = entry.get("tool_name", "unknown")
                    if tool_name == "run_parallel":
                        continue
                    total_tool_calls += 1
                    dur = entry.get("duration_ms", 0)
                    tool_call_counts[tool_name] += 1
                    tool_durations[tool_name] += dur
                    total_duration_ms += dur
                    params_str = json.dumps(entry.get("params", {}))
                    estimated_input_tokens += len(params_str) // 4
                    estimated_output_tokens += max(
                        len(params_str) // 2, _MIN_OUTPUT_TOKEN_ESTIMATE
                    )
                elif entry_type == "finding":
                    total_findings += 1

        cost_per_mtok_in = _COST_PER_MTOK_INPUT
        cost_per_mtok_out = _COST_PER_MTOK_OUTPUT
        estimated_cost = (
            estimated_input_tokens / 1_000_000 * cost_per_mtok_in
            + estimated_output_tokens / 1_000_000 * cost_per_mtok_out
        )

        wall_clock_ms = total_duration_ms
        if len(timestamps) >= 2:
            try:
                t0 = datetime.fromisoformat(timestamps[0])
                t1 = datetime.fromisoformat(timestamps[-1])
                wall_clock_ms = (t1 - t0).total_seconds() * 1000
            except (ValueError, TypeError):
                pass

        return AuditSummary(
            total_tool_calls=total_tool_calls,
            total_findings=total_findings,
            tool_call_counts=dict(tool_call_counts),
            tool_durations=dict(tool_durations),
            total_duration_ms=total_duration_ms,
            wall_clock_ms=wall_clock_ms,
            first_timestamp=timestamps[0] if timestamps else "",
            last_timestamp=timestamps[-1] if timestamps else "",
            estimated_input_tokens=estimated_input_tokens,
            estimated_output_tokens=estimated_output_tokens,
            estimated_cost_usd=round(estimated_cost, 4),
        )
