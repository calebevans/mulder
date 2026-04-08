"""Append-only JSONL audit log for a case investigation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    """Append-only JSONL audit log for a case investigation.

    Each ``log_tool_call`` invocation appends a single JSON line and records
    the ``tool_call_id`` in an in-memory set for fast validation by
    ``submit_finding``.
    """

    def __init__(self, log_path: Path) -> None:
        self._log_path = Path(log_path)
        self._tool_call_ids: set[str] = set()
        self._load_existing()

    def _load_existing(self) -> None:
        """Populate the in-memory set from an existing JSONL file."""
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
                if entry.get("type") == "tool_call" and "tool_call_id" in entry:
                    self._tool_call_ids.add(entry["tool_call_id"])

    def _append(self, entry: dict) -> None:
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._log_path, "a") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

    def log_tool_call(
        self,
        tool_call_id: str,
        tool_name: str,
        params: dict,
        output_hash: str,
        cordon_ratio: float | None = None,
        duration_ms: float = 0,
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
        self._append(entry)
        self._tool_call_ids.add(tool_call_id)

    def has_tool_call(self, tool_call_id: str) -> bool:
        return tool_call_id in self._tool_call_ids

    @property
    def tool_call_ids(self) -> set[str]:
        return set(self._tool_call_ids)
