#!/usr/bin/env python3
"""Extract a compact technique-to-tactic mapping from MITRE ATT&CK STIX bundles.

Reads the Enterprise and ICS ATT&CK STIX bundles (provisioned by
``mulder setup`` under the mulder asset root, and baked into the container
image) and writes a single JSON lookup file suitable for shipping as Python
package data.

Usage::

    # Inside the container (bundles already present):
    python scripts/extract_attack_tactics.py

    # Outside the container (downloads automatically):
    python scripts/extract_attack_tactics.py --download

    # From custom paths:
    python scripts/extract_attack_tactics.py \
        --stix-path /tmp/enterprise-attack.json \
        --ics-stix-path /tmp/ics-attack.json
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

try:
    from mulder.assets.paths import asset_display_path
except ImportError:  # run standalone, outside mulder's environment

    def asset_display_path(*parts: str) -> Path:
        """Fall back to the container layout when mulder is not importable."""
        return Path("/opt").joinpath(*parts)


_DEFAULT_STIX_PATH = asset_display_path("attack", "enterprise-attack.json")
_DEFAULT_ICS_STIX_PATH = asset_display_path("attack", "ics-attack.json")
_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)
_ICS_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/ics-attack/ics-attack.json"
)
_OUTPUT_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "mulder"
    / "report"
    / "data"
    / "attack_tactics.json"
)

_TACTIC_KILL_CHAIN_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

_KILL_CHAIN_NAMES = {"mitre-attack", "mitre-ics-attack"}


def _parse_tactics(
    objects: list[dict[str, Any]],
    known_order: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Extract ordered tactic list from ``x-mitre-tactic`` STIX objects."""
    raw_tactics: dict[str, dict[str, Any]] = {}

    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        attack_ref = next(
            (r for r in ext_refs if r.get("source_name") in ("mitre-attack", "mitre-ics-attack")),
            None,
        )
        if attack_ref is None:
            continue

        shortname = obj.get("x_mitre_shortname", "")
        raw_tactics[shortname] = {
            "id": attack_ref["external_id"],
            "name": obj.get("name", ""),
            "shortname": shortname,
        }

    order = known_order or []
    ordered: list[dict[str, Any]] = []
    for idx, shortname in enumerate(order):
        if shortname in raw_tactics:
            t = raw_tactics[shortname]
            t["order"] = idx
            ordered.append(t)

    for shortname, t in raw_tactics.items():
        if shortname not in order:
            t["order"] = len(ordered)
            ordered.append(t)

    return ordered


def _parse_techniques(
    objects: list[dict[str, Any]],
    tactic_shortname_to_id: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """Extract technique-id -> {name, tactics} mapping from attack-pattern objects."""
    techniques: dict[str, dict[str, Any]] = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        attack_ref = next(
            (r for r in ext_refs if r.get("source_name") in ("mitre-attack", "mitre-ics-attack")),
            None,
        )
        if attack_ref is None:
            continue

        tid = attack_ref["external_id"]

        tactic_ids = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") not in _KILL_CHAIN_NAMES:
                continue
            phase_name = phase["phase_name"]
            tactic_id = tactic_shortname_to_id.get(phase_name)
            if tactic_id:
                tactic_ids.append(tactic_id)

        if tid in techniques:
            existing = techniques[tid]["tactics"]
            for t in tactic_ids:
                if t not in existing:
                    existing.append(t)
        else:
            techniques[tid] = {
                "name": obj.get("name", ""),
                "tactics": tactic_ids,
            }

    return techniques


def _download_if_needed(path: Path, url: str, label: str, force: bool = False) -> bool:
    """Download a STIX bundle if missing. Returns True if the file is available."""
    if path.exists() and not force:
        return True
    if not force:
        print(f"  {label} not found at {path}")
    print(f"  Downloading {label} from {url} ...")
    tmp = path.parent / (path.name + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    try:
        urllib.request.urlretrieve(url, tmp)
        tmp.rename(path)
        print(f"  Saved to {path}")
        return True
    except Exception as exc:
        print(f"  Download failed: {exc}", file=sys.stderr)
        if tmp.exists():
            tmp.unlink()
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract ATT&CK tactic mapping from STIX bundles")
    parser.add_argument(
        "--stix-path",
        type=Path,
        default=_DEFAULT_STIX_PATH,
        help="Path to enterprise-attack.json",
    )
    parser.add_argument(
        "--ics-stix-path",
        type=Path,
        default=_DEFAULT_ICS_STIX_PATH,
        help="Path to ics-attack.json",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download STIX bundles if not found locally",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_OUTPUT_PATH,
        help="Output path for the extracted JSON",
    )
    args = parser.parse_args()

    stix_path: Path = args.stix_path
    ics_stix_path: Path = args.ics_stix_path

    if not stix_path.exists():
        if args.download or not _DEFAULT_STIX_PATH.exists():
            if not _download_if_needed(stix_path, _STIX_URL, "Enterprise ATT&CK", force=True):
                print("Enterprise ATT&CK bundle required but unavailable.", file=sys.stderr)
                sys.exit(1)
        else:
            print(f"Enterprise STIX bundle not found at {stix_path}", file=sys.stderr)
            sys.exit(1)

    print(f"Parsing Enterprise ATT&CK: {stix_path} ...")
    raw = json.loads(stix_path.read_text(encoding="utf-8"))
    objects = raw.get("objects", [])

    tactics = _parse_tactics(objects, _TACTIC_KILL_CHAIN_ORDER)
    shortname_to_id = {t["shortname"]: t["id"] for t in tactics}
    techniques = _parse_techniques(objects, shortname_to_id)

    version = raw.get("spec_version", "")
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", version)
            break

    ics_count = 0
    if not ics_stix_path.exists() and (args.download or not _DEFAULT_ICS_STIX_PATH.exists()):
        _download_if_needed(ics_stix_path, _ICS_STIX_URL, "ICS ATT&CK", force=True)

    if ics_stix_path.exists():
        print(f"Parsing ICS ATT&CK: {ics_stix_path} ...")
        ics_raw = json.loads(ics_stix_path.read_text(encoding="utf-8"))
        ics_objects = ics_raw.get("objects", [])

        enterprise_shortnames = {t["shortname"] for t in tactics}
        ics_tactics = _parse_tactics(ics_objects)
        next_order: int = max((t["order"] for t in tactics), default=-1) + 1
        for t in ics_tactics:
            if t["shortname"] not in enterprise_shortnames:
                t["order"] = next_order
                next_order += 1
                tactics.append(t)
                shortname_to_id[t["shortname"]] = t["id"]

        shortname_to_id_full = {t["shortname"]: t["id"] for t in tactics}
        ics_techniques = _parse_techniques(ics_objects, shortname_to_id_full)

        for tid, info in ics_techniques.items():
            if tid in techniques:
                existing = techniques[tid]["tactics"]
                for t in info["tactics"]:
                    if t not in existing:
                        existing.append(t)
            else:
                techniques[tid] = info
                ics_count += 1
    else:
        print("  ICS ATT&CK bundle not available, skipping.")

    result = {
        "version": version,
        "tactics": [
            {"id": t["id"], "name": t["name"], "shortname": t["shortname"], "order": t["order"]}
            for t in tactics
        ],
        "techniques": techniques,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result, separators=(",", ":"), sort_keys=False)
    args.output.write_text(payload, encoding="utf-8")
    print(f"Wrote {args.output} ({args.output.stat().st_size:,} bytes)")
    print(f"  {len(tactics)} tactics, {len(techniques)} techniques ({ics_count} ICS-only)")


if __name__ == "__main__":
    main()
