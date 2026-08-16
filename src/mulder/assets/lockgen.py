"""Regenerate ``assets.lock``.

A maintainer chore, run by a human via ``make assets-lock`` after bumping a
pinned version in the Dockerfile *and* in ``manifest.py``.  It is the only code
in this package that downloads by design, it is never imported at runtime, and
it must never run in CI -- ``mulder setup`` reads the checked-in result instead.

    python -m mulder.assets.lockgen [--key chainsaw ...]
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from mulder.assets.fetch import HttpFetcher
from mulder.assets.manifest import ANY_ARCH, ASSETS

LOCK_PATH = Path(__file__).with_name("assets.lock")


def generate(keys: set[str] | None = None) -> dict[str, dict[str, object]]:
    """Download every pinnable asset for every architecture and hash it."""
    fetcher = HttpFetcher(timeout=300.0)
    entries: dict[str, dict[str, object]] = {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for asset in ASSETS:
        if not asset.pinnable or (keys and asset.key not in keys):
            continue
        for arch, url in sorted(asset.urls.items()):
            if arch == ANY_ARCH and asset.arch_only:  # pragma: no cover - defensive
                continue
            print(f"  {asset.key}:{arch} <- {url}", file=sys.stderr)
            with tempfile.TemporaryDirectory(prefix="mulder-lockgen-") as tmp:
                result = fetcher(url, Path(tmp) / "download")
                entries[f"{asset.key}:{arch}"] = {
                    "url": url,
                    "sha256": result.sha256,
                    "bytes": result.bytes_written,
                    "generated_at": now,
                }
    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key",
        action="append",
        default=[],
        help="Regenerate only these asset keys (merged into the existing lock).",
    )
    args = parser.parse_args(argv)

    entries = generate(set(args.key) or None)
    if args.key and LOCK_PATH.exists():
        # A targeted regeneration merges into what is already locked, so a
        # single version bump does not re-download every other asset.
        merged = json.loads(LOCK_PATH.read_text(encoding="utf-8")).get("entries", {})
        merged.update(entries)
        entries = merged

    payload = {"schema": 1, "entries": dict(sorted(entries.items()))}
    LOCK_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {LOCK_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
