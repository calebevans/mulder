"""MCP tool for looking up MITRE ATT&CK techniques from STIX data.

The ATT&CK Enterprise STIX bundle is provisioned by ``mulder setup`` (and
baked into the container image) under the mulder asset root as
``attack/enterprise-attack.json``.  It is loaded lazily on first use and
parsed into an in-memory lookup structure.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

from mulder.assets.paths import (
    asset_display_path,
    asset_path,
    asset_search_summary,
    register_cache_clear,
)
from mulder.server.app import mcp
from mulder.server.helpers import error_response, make_tool_call_id, tool_response
from mulder.server.tool_access import Role, tool_access

logger = logging.getLogger(__name__)

_ATTACK_DIRNAME = "attack"


def _stix_path() -> Path:
    """The Enterprise ATT&CK bundle, or where ``mulder setup`` would put it."""
    return asset_display_path(_ATTACK_DIRNAME, "enterprise-attack.json")


def _ics_stix_path() -> Path:
    """The ICS ATT&CK bundle, or where ``mulder setup`` would put it."""
    return asset_display_path(_ATTACK_DIRNAME, "ics-attack.json")


_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_attack_techniques: dict[str, dict[str, Any]] | None = None
_attack_lock = threading.Lock()


def _reset_attack_cache() -> None:
    """Drop the parsed STIX cache after the asset root moves.

    Taken without the lock: ``_attack_techniques`` is only ever assigned once
    per successful parse, so the worst case of a racing read is a re-parse,
    not a corruption.
    """
    global _attack_techniques  # noqa: PLW0603
    _attack_techniques = None


register_cache_clear(_reset_attack_cache)

_MAX_FIELD_LEN = 500


def _truncate(text: str) -> str:
    """Truncate *text* to ``_MAX_FIELD_LEN`` characters with an ellipsis."""
    if len(text) > _MAX_FIELD_LEN:
        return text[: _MAX_FIELD_LEN - 3] + "..."
    return text


def _parse_stix_technique(obj: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Extract a single technique entry from a STIX attack-pattern object."""
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None

    ext_refs: list[dict[str, str]] = obj.get("external_references", [])
    attack_ref = next(
        (r for r in ext_refs if r.get("source_name") in ("mitre-attack", "mitre-ics-attack")),
        None,
    )
    if attack_ref is None:
        return None

    tid = attack_ref["external_id"]
    url = attack_ref.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/")

    tactics = [
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") in ("mitre-attack", "mitre-ics-attack")
    ]

    detection = obj.get("x_mitre_detection", "")

    return tid, {
        "id": tid,
        "name": obj.get("name", ""),
        "description": _truncate(obj.get("description", "")),
        "tactics": tactics,
        "detection": _truncate(detection),
        "url": url,
    }


def _load_attack_data() -> dict[str, dict[str, Any]]:
    """Parse the bundled STIX JSON into a technique-ID-keyed lookup dict."""
    global _attack_techniques  # noqa: PLW0603
    if _attack_techniques is not None:
        return _attack_techniques

    with _attack_lock:
        if _attack_techniques is not None:
            return _attack_techniques

        raw = json.loads(_stix_path().read_text(encoding="utf-8"))
        techniques: dict[str, dict[str, Any]] = {}

        for obj in raw.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            parsed = _parse_stix_technique(obj)
            if parsed is not None:
                techniques[parsed[0]] = parsed[1]

        ics_path = asset_path(_ATTACK_DIRNAME, "ics-attack.json")
        if ics_path is not None:
            ics_raw = json.loads(ics_path.read_text(encoding="utf-8"))
            ics_count = 0
            for obj in ics_raw.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                parsed = _parse_stix_technique(obj)
                if parsed is not None and parsed[0] not in techniques:
                    techniques[parsed[0]] = parsed[1]
                    ics_count += 1
            logger.info("Loaded %d ICS ATT&CK techniques from %s", ics_count, ics_path)

        _attack_techniques = techniques
        logger.info("Loaded %d total ATT&CK techniques", len(techniques))
        return techniques


def _search_techniques(
    techniques: dict[str, dict[str, Any]],
    query: str,
    max_results: int,
) -> list[dict[str, Any]]:
    """Return techniques matching *query* by exact ID or substring search."""
    normalized = query.strip().upper()
    if _TECHNIQUE_ID_RE.match(normalized):
        entry = techniques.get(normalized)
        return [entry] if entry is not None else []

    q_lower = query.lower()
    matches: list[dict[str, Any]] = []
    for tech in techniques.values():
        if q_lower in tech["name"].lower() or q_lower in tech["description"].lower():
            matches.append(tech)
            if len(matches) >= max_results:
                break
    return matches


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_ANALYST)
def lookup_attack_technique(
    query: str,
    max_results: int = 5,
) -> dict[str, object]:
    """Search the MITRE ATT&CK knowledge base for techniques.

    *query* can be an exact technique ID (e.g. ``T1059.001``) or a
    keyword/phrase to search across technique names and descriptions.
    Returns up to *max_results* matching techniques with their ID, name,
    description, associated tactics, detection guidance, and a URL.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"query": query, "max_results": max_results}

    if asset_path(_ATTACK_DIRNAME, "enterprise-attack.json") is None:
        return error_response(
            tc_id=tc_id,
            tool_name="lookup_attack_technique",
            params=params,
            error=(
                "ATT&CK STIX data not found under any of: "
                f"{asset_search_summary(_ATTACK_DIRNAME, 'enterprise-attack.json')}"
            ),
            elapsed_ms=(time.monotonic() - t0) * 1000,
            error_type="file_not_found",
            suggestion=f"Run 'mulder setup --minimal' to install it to {_stix_path()}.",
        )

    try:
        techniques = _load_attack_data()
    except Exception as exc:
        return error_response(
            tc_id=tc_id,
            tool_name="lookup_attack_technique",
            params=params,
            error=f"Failed to load ATT&CK data: {exc}",
            elapsed_ms=(time.monotonic() - t0) * 1000,
            error_type="parse_error",
        )

    matches = _search_techniques(techniques, query, max_results)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id=tc_id,
        tool_name="lookup_attack_technique",
        params=params,
        results={"match_count": len(matches), "techniques": matches},
        elapsed_ms=elapsed,
    )
