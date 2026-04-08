"""Append-only JSONL audit log for a case investigation."""

from __future__ import annotations

import json
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from killjoy.models import (
    AuditSummary,
    ProvenanceChain,
    SourceProvenance,
    ToolCallEntry,
)

if TYPE_CHECKING:
    from killjoy.db import CaseDB


class AuditLog:
    """Append-only JSONL audit log for a case investigation.

    Each ``log_tool_call`` invocation appends a single JSON line and records
    the ``tool_call_id`` in an in-memory index for fast validation by
    ``submit_finding`` and provenance chain resolution.
    """

    def __init__(self, log_path: Path) -> None:
        self._log_path = Path(log_path)
        self._lock = threading.Lock()
        self._tool_call_ids: set[str] = set()
        self._tool_calls: dict[str, dict] = {}
        self._finding_entries: dict[str, dict] = {}
        self._load_existing()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _load_existing(self) -> None:
        """Populate in-memory indexes from an existing JSONL file."""
        if not self._log_path.exists():
            return
        with open(self._log_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._index_entry(entry)

    def _index_entry(self, entry: dict) -> None:
        entry_type = entry.get("type")
        if entry_type == "tool_call" and "tool_call_id" in entry:
            tcid = entry["tool_call_id"]
            self._tool_call_ids.add(tcid)
            self._tool_calls[tcid] = entry
        elif entry_type == "finding" and "finding_id" in entry:
            self._finding_entries[entry["finding_id"]] = entry

    def _append(self, entry: dict) -> None:
        with self._lock:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
            self._index_entry(entry)

    # ------------------------------------------------------------------
    # Tool call logging (Piece 1 original)
    # ------------------------------------------------------------------

    def log_tool_call(
        self,
        tool_call_id: str,
        tool_name: str,
        params: dict,
        output_hash: str,
        cordon_ratio: float | None = None,
        duration_ms: float = 0,
        sub_calls: list[str] | None = None,
    ) -> None:
        entry = {
            "type": "tool_call",
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "params": params,
            "output_hash": output_hash,
            "cordon_ratio": cordon_ratio,
            "duration_ms": duration_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if sub_calls is not None:
            entry["sub_calls"] = sub_calls
        self._append(entry)

    def has_tool_call(self, tool_call_id: str) -> bool:
        return tool_call_id in self._tool_call_ids

    @property
    def tool_call_ids(self) -> set[str]:
        return set(self._tool_call_ids)

    # ------------------------------------------------------------------
    # Ingestion logging (Piece 11)
    # ------------------------------------------------------------------

    def log_ingestion_step(
        self,
        source_name: str,
        source_path: str,
        source_hash: str,
        extractor: str,
        window_count: int,
        duration_ms: float,
    ) -> None:
        entry = {
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

    # ------------------------------------------------------------------
    # Finding logging (Piece 11)
    # ------------------------------------------------------------------

    def log_finding_submission(
        self,
        finding_id: str,
        evidence_refs: list[str],
    ) -> None:
        entry = {
            "type": "finding",
            "finding_id": finding_id,
            "evidence_refs": evidence_refs,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._append(entry)

    # ------------------------------------------------------------------
    # Provenance chain (Piece 11)
    # ------------------------------------------------------------------

    def get_provenance_chain(self, finding_id: str, db: CaseDB) -> ProvenanceChain:
        """Trace a finding back through tool calls to original evidence files."""
        finding_entry = self._finding_entries.get(finding_id)
        if finding_entry is None:
            raise KeyError(f"No finding with id '{finding_id}' in the audit log")

        evidence_refs: list[str] = finding_entry.get("evidence_refs", [])
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
        tool_calls: list[ToolCallEntry] = []
        source_names: set[str] = set()

        for ref in evidence_refs:
            tc = self._tool_calls.get(ref)
            if tc is None:
                continue
            tool_calls.append(
                ToolCallEntry(
                    tool_call_id=tc["tool_call_id"],
                    tool_name=tc["tool_name"],
                    params=tc.get("params", {}),
                    output_hash=tc.get("output_hash", ""),
                    timestamp=tc.get("timestamp", ""),
                    duration_ms=tc.get("duration_ms", 0),
                )
            )
            source_names.update(self._extract_source_names(tc.get("params", {})))

        return tool_calls, source_names

    @staticmethod
    def _extract_source_names(params: dict) -> set[str]:
        names: set[str] = set()
        for key in ("source", "source_name"):
            val = params.get(key)
            if val is not None:
                names.add(val)
        channel = params.get("channel")
        if channel is not None:
            names.add(f"evtx.{channel}")
        sources_list = params.get("sources")
        if isinstance(sources_list, list):
            names.update(sources_list)
        return names

    @staticmethod
    def _resolve_sources(queried_names: set[str], db: CaseDB) -> list[SourceProvenance]:
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

    # ------------------------------------------------------------------
    # Summary (Piece 11)
    # ------------------------------------------------------------------

    def summary(self) -> AuditSummary:
        """Compute aggregate statistics over the full audit log."""
        total_tool_calls = 0
        total_findings = 0
        tool_call_counts: dict[str, int] = defaultdict(int)
        total_duration_ms = 0.0
        timestamps: list[str] = []

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
                    total_tool_calls += 1
                    tool_call_counts[entry.get("tool_name", "unknown")] += 1
                    total_duration_ms += entry.get("duration_ms", 0)
                elif entry_type == "finding":
                    total_findings += 1

        return AuditSummary(
            total_tool_calls=total_tool_calls,
            total_findings=total_findings,
            tool_call_counts=dict(tool_call_counts),
            total_duration_ms=total_duration_ms,
            first_timestamp=timestamps[0] if timestamps else "",
            last_timestamp=timestamps[-1] if timestamps else "",
        )
