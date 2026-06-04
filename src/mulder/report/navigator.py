"""MITRE ATT&CK Navigator layer export.

Generates a ``.json`` layer file compatible with the MITRE ATT&CK
Navigator, showing which techniques were observed during the
investigation. Techniques are color-coded by the highest severity
finding that references them.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mulder.models import Finding
from mulder.patterns import SEVERITY_ORDER

logger = logging.getLogger(__name__)

_SEVERITY_SCORE: dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
}

_SEVERITY_COLOR: dict[str, str] = {
    "critical": "#ff0000",
    "high": "#ff6600",
    "medium": "#ffff00",
    "low": "#66ccff",
    "info": "#ffffff",
}

_SEVERITY_ORDER = SEVERITY_ORDER


def build_navigator_layer(
    case_id: str,
    findings: list[Finding],
    domain: str = "enterprise-attack",
) -> dict[str, Any]:
    """Build an ATT&CK Navigator layer from investigation findings.

    Groups findings by technique ID, assigns each technique the score
    and color of its highest-severity finding, and includes finding
    titles in the comment field.

    Args:
        case_id: Case identifier for the layer name.
        findings: Investigation findings with ``mitre_attack_ids``.
        domain: ATT&CK domain (``enterprise-attack`` or ``ics-attack``).

    Returns:
        Navigator layer dict ready for JSON serialization.
    """
    technique_map: dict[str, dict[str, Any]] = {}

    for finding in findings:
        for tid in finding.mitre_attack_ids:
            tid = tid.strip().upper()
            if tid not in technique_map:
                technique_map[tid] = {
                    "severity": finding.severity,
                    "comments": [],
                }
            existing = technique_map[tid]
            if _SEVERITY_ORDER.get(finding.severity, 99) < _SEVERITY_ORDER.get(
                existing["severity"], 99
            ):
                existing["severity"] = finding.severity
            existing["comments"].append(finding.title)

    techniques: list[dict[str, Any]] = []
    for tid, data in sorted(technique_map.items()):
        sev: str = data["severity"]
        entry: dict[str, Any] = {
            "techniqueID": tid,
            "score": _SEVERITY_SCORE.get(sev, 10),
            "color": _SEVERITY_COLOR.get(sev, "#ffffff"),
            "comment": "; ".join(data["comments"]),
            "enabled": True,
        }
        if "." in tid:
            entry["showSubtechniques"] = True
        techniques.append(entry)

    return {
        "name": f"Mulder Investigation: {case_id}",
        "versions": {"attack": "16", "navigator": "4.5", "layer": "4.5"},
        "domain": domain,
        "description": f"Techniques observed during investigation {case_id}",
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66ccff", "#ffff00", "#ff6600", "#ff0000"],
            "minValue": 0,
            "maxValue": 100,
        },
    }


def export_navigator_layer(
    case_id: str,
    findings: list[Finding],
    output_dir: Path,
    domain: str = "enterprise-attack",
) -> str | None:
    """Export an ATT&CK Navigator layer to a JSON file.

    Args:
        case_id: Case identifier for the filename.
        findings: Investigation findings with MITRE technique IDs.
        output_dir: Directory to write the output file.
        domain: ATT&CK domain for the layer.

    Returns:
        Path to the written file, or None if no techniques were found.
    """
    layer = build_navigator_layer(case_id, findings, domain=domain)
    if not layer["techniques"]:
        logger.info("No MITRE technique IDs found; skipping Navigator export")
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    layer_path = output_dir / f"{case_id}.navigator.json"
    layer_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    logger.info("ATT&CK Navigator layer written to %s", layer_path)
    return str(layer_path)
