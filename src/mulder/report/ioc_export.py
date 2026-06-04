"""STIX 2.1 JSON bundle and CSV export for extracted IOCs.

Reads IOCs from case findings using the shared ``_extract_iocs``
function from ``renderer.py``, then produces machine-readable
exports for SIEM/EDR/firewall import.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path
from typing import Any

from mulder.models import Finding
from mulder.report.renderer import _extract_iocs

logger = logging.getLogger(__name__)


def _stix2_available() -> bool:
    """Check whether the stix2 library is installed.

    Returns:
        True if stix2 can be imported.
    """
    try:
        import stix2  # noqa: F401

        return True
    except ImportError:
        return False


def extract_classified_iocs(
    findings: list[Finding],
) -> dict[str, list[dict[str, str]]]:
    """Extract and classify IOCs from findings.

    Args:
        findings: Investigation findings to scan for IOCs.

    Returns:
        Dict with ``network``, ``file``, and ``email`` keys, each
        containing a list of IOC dicts with ``value``, ``type``,
        and ``context`` fields.
    """
    network, file_iocs, email = _extract_iocs(findings)
    return {"network": network, "file": file_iocs, "email": email}


def _ioc_to_stix_pattern(ioc: dict[str, str]) -> str | None:
    """Convert a classified IOC dict to a STIX indicator pattern string.

    Args:
        ioc: Dict with ``type`` and ``value`` keys.

    Returns:
        STIX pattern string, or None if the IOC type is not mappable.
    """
    ioc_type = ioc.get("type", "").lower().replace(" ", "")
    value = ioc["value"]

    patterns: dict[str, str] = {
        "externalip": f"[ipv4-addr:value = '{value}']",
        "internalip": f"[ipv4-addr:value = '{value}']",
        "ipv4": f"[ipv4-addr:value = '{value}']",
        "ipv6": f"[ipv6-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "md5": f"[file:hashes.MD5 = '{value}']",
        "sha1": f"[file:hashes.'SHA-1' = '{value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "email": f"[email-addr:value = '{value}']",
    }
    return patterns.get(ioc_type)


def build_stix_bundle(
    case_id: str,
    findings: list[Finding],
    iocs: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    """Build a STIX 2.1 bundle from case findings and extracted IOCs.

    Uses the ``stix2`` library when available to create proper STIX
    objects. Falls back to raw dict construction if stix2 is missing.

    Args:
        case_id: Case identifier used in the identity object.
        findings: Full list of investigation findings.
        iocs: Classified IOCs from ``extract_classified_iocs``.

    Returns:
        A STIX 2.1 bundle dict ready for JSON serialization.
    """
    try:
        return _build_stix_bundle_with_library(case_id, findings, iocs)
    except ImportError:
        return _build_stix_bundle_manual(case_id, findings, iocs)


def _build_stix_bundle_with_library(
    case_id: str,
    findings: list[Finding],
    iocs: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    """Build STIX bundle using the stix2 library.

    Args:
        case_id: Case identifier.
        findings: Investigation findings.
        iocs: Classified IOCs.

    Returns:
        Serialized STIX bundle as dict.
    """
    from stix2 import (
        AttackPattern,
        Bundle,
        Identity,
        Indicator,
        Relationship,
    )

    identity = Identity(
        name=f"Mulder Investigation {case_id}",
        identity_class="system",
    )
    objects: list[Any] = [identity]
    seen_patterns: set[str] = set()

    for category_iocs in iocs.values():
        for ioc in category_iocs:
            pattern = _ioc_to_stix_pattern(ioc)
            if pattern and pattern not in seen_patterns:
                seen_patterns.add(pattern)
                indicator = Indicator(
                    name=ioc["value"],
                    pattern=pattern,
                    pattern_type="stix",
                    created_by_ref=identity.id,
                    labels=["malicious-activity"],
                )
                objects.append(indicator)

    seen_techniques: set[str] = set()
    for finding in findings:
        for tid in finding.mitre_attack_ids:
            if tid in seen_techniques:
                continue
            seen_techniques.add(tid)
            ap = AttackPattern(
                name=finding.title,
                external_references=[
                    {
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": (f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
                    }
                ],
            )
            objects.append(ap)
            rel = Relationship(
                relationship_type="indicates",
                source_ref=identity.id,
                target_ref=ap.id,
            )
            objects.append(rel)

    bundle = Bundle(*objects)
    return json.loads(bundle.serialize())  # type: ignore[no-any-return]


def _build_stix_bundle_manual(
    case_id: str,
    findings: list[Finding],
    iocs: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    """Build a minimal STIX 2.1 bundle without the stix2 library.

    Args:
        case_id: Case identifier.
        findings: Investigation findings.
        iocs: Classified IOCs.

    Returns:
        STIX bundle as dict.
    """
    import uuid
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = f"identity--{uuid.uuid4()}"

    identity: dict[str, Any] = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": f"Mulder Investigation {case_id}",
        "identity_class": "system",
    }
    objects: list[dict[str, Any]] = [identity]
    seen_patterns: set[str] = set()

    for category_iocs in iocs.values():
        for ioc in category_iocs:
            pattern = _ioc_to_stix_pattern(ioc)
            if pattern and pattern not in seen_patterns:
                seen_patterns.add(pattern)
                objects.append(
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{uuid.uuid4()}",
                        "created": now,
                        "modified": now,
                        "name": ioc["value"],
                        "pattern": pattern,
                        "pattern_type": "stix",
                        "valid_from": now,
                        "created_by_ref": identity_id,
                        "labels": ["malicious-activity"],
                    }
                )

    seen_techniques: set[str] = set()
    for finding in findings:
        for tid in finding.mitre_attack_ids:
            if tid in seen_techniques:
                continue
            seen_techniques.add(tid)
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            objects.append(
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now,
                    "modified": now,
                    "name": finding.title,
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tid,
                            "url": (
                                f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                            ),
                        }
                    ],
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": identity_id,
                    "target_ref": ap_id,
                }
            )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def build_csv(
    iocs: dict[str, list[dict[str, str]]],
) -> str:
    """Build a CSV string of all IOCs grouped by type.

    Args:
        iocs: Classified IOCs from ``extract_classified_iocs``.

    Returns:
        CSV text with columns: type, value, context, severity.
    """
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["type", "value", "context", "severity"],
    )
    writer.writeheader()
    for category, items in iocs.items():
        for item in items:
            writer.writerow(
                {
                    "type": item.get("type", category),
                    "value": item["value"],
                    "context": item.get("context", ""),
                    "severity": item.get("severity", ""),
                }
            )
    return output.getvalue()


def export_iocs(
    case_id: str,
    findings: list[Finding],
    output_dir: Path,
    fmt: str = "all",
) -> dict[str, str | None]:
    """Export IOCs from findings as STIX 2.1 and/or CSV files.

    Args:
        case_id: Case identifier for filenames.
        findings: Investigation findings to extract IOCs from.
        output_dir: Directory to write output files.
        fmt: Output format: ``"stix"``, ``"csv"``, or ``"all"``.

    Returns:
        Dict with ``stix_path`` and ``csv_path`` keys (None if skipped).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    iocs = extract_classified_iocs(findings)
    result: dict[str, str | None] = {"stix_path": None, "csv_path": None}

    if fmt in ("csv", "all"):
        csv_text = build_csv(iocs)
        csv_path = output_dir / f"{case_id}.iocs.csv"
        csv_path.write_text(csv_text, encoding="utf-8")
        result["csv_path"] = str(csv_path)
        logger.info("IOC CSV written to %s", csv_path)

    if fmt in ("stix", "all"):
        if _stix2_available():
            bundle = build_stix_bundle(case_id, findings, iocs)
            stix_path = output_dir / f"{case_id}.iocs.stix.json"
            stix_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
            result["stix_path"] = str(stix_path)
            logger.info("STIX bundle written to %s", stix_path)
        else:
            bundle = _build_stix_bundle_manual(case_id, findings, iocs)
            stix_path = output_dir / f"{case_id}.iocs.stix.json"
            stix_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
            result["stix_path"] = str(stix_path)
            logger.info(
                "STIX bundle written to %s (without stix2 library validation)",
                stix_path,
            )

    return result
