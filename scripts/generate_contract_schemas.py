#!/usr/bin/env python3
"""Regenerate committed Mulder contract schemas from authoritative models."""

from __future__ import annotations

import json
from pathlib import Path

from mulder.contracts import core_contract_schema


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    destination = repo_root / "schemas" / "core-contract-v1.schema.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(core_contract_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
