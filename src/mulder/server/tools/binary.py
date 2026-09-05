"""Binary analysis MCP tools: triage, CAPA, FLOSS, and Detect-It-Easy."""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    require_binary,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "run_capa",
    "run_detect_it_easy",
    "run_floss",
    "triage_binary",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RABIN2_TIMEOUT = 60
_CAPA_TIMEOUT = 300
_FLOSS_TIMEOUT = 600
_DIEC_TIMEOUT = 120

_CAPA_BINARY = "/usr/local/bin/capa"
_FLOSS_BINARY = "/usr/local/bin/floss"
_DIEC_BINARY = "/usr/local/bin/diec"

_EPOCH_START = datetime(1990, 1, 1, tzinfo=timezone.utc)
_FUTURE_THRESHOLD = datetime(2030, 1, 1, tzinfo=timezone.utc)

SUSPICIOUS_API_CATEGORIES: dict[str, list[str]] = {
    "process_injection": [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "NtMapViewOfSection",
        "RtlCreateUserThread",
    ],
    "crypto": [
        "CryptEncrypt",
        "CryptDecrypt",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "CryptHashData",
    ],
    "network": [
        "InternetOpenUrl",
        "HttpSendRequest",
        "WSAStartup",
        "connect",
        "send",
        "recv",
        "InternetOpen",
        "URLDownloadToFile",
    ],
    "anti_debug": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
        "GetTickCount",
    ],
    "persistence": [
        "RegSetValueEx",
        "RegCreateKeyEx",
        "CreateService",
        "SchRpcRegisterTask",
        "WritePrivateProfileString",
    ],
    "privilege_escalation": [
        "AdjustTokenPrivileges",
        "OpenProcessToken",
        "ImpersonateLoggedOnUser",
        "LookupPrivilegeValue",
        "SetTokenInformation",
    ],
}

_URL_RE = re.compile(r"https?://[^\s\"']+")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REGISTRY_RE = re.compile(r"HKLM\\|HKCU\\|HKCR\\|SOFTWARE\\", re.IGNORECASE)
_FILEPATH_RE = re.compile(r"[A-Z]:\\[^\s\"]+|/(?:usr|etc|tmp|var)/[^\s\"]+")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_RAHASH_RE = re.compile(r"(\w+):\s+([0-9a-fA-F]+)")

_PACKER_SECTION_NAMES = {".UPX", ".ASPack", ".themida", ".vmp", ".nsp"}
_RESOLVER_APIS = {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"}


# ---------------------------------------------------------------------------
# rabin2 helpers
# ---------------------------------------------------------------------------


def _run_rabin2(flags: str, file_path: Path) -> dict[str, Any]:
    """Execute rabin2 with JSON output and return parsed result.

    Args:
        flags: rabin2 flag characters (e.g. "I", "i", "S").
        file_path: Path to the target binary.

    Returns:
        Parsed JSON output, or empty dict on failure.

    Raises:
        subprocess.TimeoutExpired: If rabin2 exceeds the timeout.
    """
    cmd = ["rabin2", f"-{flags}j", str(file_path)]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_RABIN2_TIMEOUT,
        check=False,
    )
    if not proc.stdout.strip():
        return {}
    try:
        loaded = json.loads(proc.stdout)
    except json.JSONDecodeError:
        logger.warning("Failed to parse rabin2 -%s JSON output", flags)
        return {}
    if isinstance(loaded, dict):
        result: dict[str, Any] = loaded
        return result
    return {}


def _parse_file_info(raw: dict[str, Any]) -> dict[str, object]:
    """Extract file metadata from rabin2 -I JSON output.

    Args:
        raw: Parsed JSON from rabin2 -Ij.

    Returns:
        Dict with arch, bits, os, compiler, and security flags.
    """
    info: dict[str, Any] = raw.get("info", raw.get("bin", raw))
    return {
        "arch": info.get("arch", "unknown"),
        "bits": info.get("bits", 0),
        "os": info.get("os", "unknown"),
        "compiler": info.get("compiler") or None,
        "language": info.get("lang") or None,
        "stripped": bool(info.get("stripped", False)),
        "canary": bool(info.get("canary", False)),
        "nx": bool(info.get("nx", False)),
        "pie": bool(info.get("pic", False)),
        "file_type": info.get("bintype", info.get("type", "unknown")),
    }


def _parse_sections(raw: dict[str, Any]) -> list[dict[str, object]]:
    """Extract section metadata from rabin2 -S JSON output.

    Args:
        raw: Parsed JSON from rabin2 -Sj.

    Returns:
        List of section dicts with name, size, entropy, and permissions.
    """
    sections: list[dict[str, object]] = []
    for s in raw.get("sections", []):
        flags_val = s.get("flags", [])
        sections.append(
            {
                "name": s.get("name", ""),
                "size": s.get("size", 0),
                "virtual_size": s.get("vsize", 0),
                "entropy": float(s.get("entropy", 0.0)),
                "permissions": s.get("perm", ""),
                "flags": flags_val if isinstance(flags_val, list) else [],
            }
        )
    return sections


def _parse_imports(raw: dict[str, Any]) -> list[str]:
    """Extract import names from rabin2 -i JSON output.

    Args:
        raw: Parsed JSON from rabin2 -ij.

    Returns:
        List of imported API/function names.
    """
    return [str(imp.get("name", "")) for imp in raw.get("imports", []) if imp.get("name")]


def _parse_strings(raw: dict[str, Any]) -> list[dict[str, object]]:
    """Extract strings with section context from rabin2 -z JSON output.

    Only returns strings that match a forensic relevance pattern (URLs,
    IPs, registry paths, file paths).

    Args:
        raw: Parsed JSON from rabin2 -zj.

    Returns:
        List of annotated string dicts with value, section, and category.
    """
    results: list[dict[str, object]] = []
    for s in raw.get("strings", []):
        value = str(s.get("string", ""))
        if not value:
            continue
        category = _categorize_string(value)
        if category is not None:
            results.append(
                {
                    "value": value,
                    "section": s.get("section") or None,
                    "category": category,
                }
            )
    return results


# ---------------------------------------------------------------------------
# Classification and detection helpers
# ---------------------------------------------------------------------------


def _categorize_string(value: str) -> str | None:
    """Classify an extracted string by forensic relevance.

    Args:
        value: Raw string extracted from a binary.

    Returns:
        Category string or None if not relevant.
    """
    if _URL_RE.search(value):
        return "url"
    if _IPV4_RE.search(value):
        return "ip"
    if _REGISTRY_RE.search(value):
        return "registry"
    if _FILEPATH_RE.search(value):
        return "filepath"
    return None


def _categorize_decoded_string(value: str) -> str | None:
    """Classify a decoded string by forensic relevance.

    Extended version that also detects potential crypto keys and
    encoded configuration data from obfuscation recovery.

    Args:
        value: Decoded string from FLOSS.

    Returns:
        Category string or None if generic.
    """
    basic = _categorize_string(value)
    if basic is not None:
        return basic
    if _HEX_KEY_RE.match(value) and len(value) in (32, 48, 64):
        return "crypto_key"
    if _BASE64_RE.match(value):
        return "config"
    return None


def _classify_imports(imports: list[str]) -> dict[str, list[str]]:
    """Group imports by suspicious behavior category.

    Args:
        imports: List of imported API names.

    Returns:
        Dict mapping category names to lists of matching API names.
    """
    result: dict[str, list[str]] = {}
    for category, apis in SUSPICIOUS_API_CATEGORIES.items():
        api_set = set(apis)
        matches = [imp for imp in imports if imp in api_set]
        if matches:
            result[category] = matches
    return result


def _detect_packing(
    sections: list[dict[str, object]],
    imports: list[str],
) -> list[str]:
    """Identify indicators of packing or obfuscation.

    Checks section entropy, naming conventions, and import table
    characteristics for signs of binary packing.

    Args:
        sections: Parsed section info with entropy values.
        imports: Full list of imported API names.

    Returns:
        List of human-readable packing indicator strings.
    """
    indicators: list[str] = []

    for section in sections:
        name = str(section.get("name", ""))
        entropy_val = section.get("entropy", 0.0)
        entropy = float(entropy_val) if isinstance(entropy_val, int | float | str) else 0.0
        perms = str(section.get("permissions", ""))

        if entropy > 7.0:
            indicators.append(f"High entropy in {name}: {entropy:.2f} (threshold: 7.0)")
        if "w" in perms and "x" in perms:
            indicators.append(f"RWX permissions on {name} (self-modifying code)")
        if name in _PACKER_SECTION_NAMES:
            indicators.append(f"Known packer section name: {name}")

    if len(imports) < 10 and _RESOLVER_APIS.intersection(imports):
        indicators.append(
            f"Minimal import table ({len(imports)} imports) with "
            f"dynamic resolution APIs (likely packed)"
        )

    return indicators


def _assess_timestamp(raw_ts: str | None) -> dict[str, object]:
    """Validate a PE compilation timestamp.

    Checks whether the timestamp falls within a plausible range.
    Dates before 1990 or after 2030 are flagged as impossible
    (common in malware that zeroes or corrupts the field).

    Args:
        raw_ts: Raw timestamp string from rabin2 output.

    Returns:
        Dict with raw_timestamp, parsed_utc, validity, and reason.
    """
    if not raw_ts:
        return {
            "raw_timestamp": None,
            "parsed_utc": None,
            "validity": "suspicious",
            "reason": "No compilation timestamp present",
        }

    try:
        parsed = datetime.fromtimestamp(int(raw_ts), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return {
            "raw_timestamp": raw_ts,
            "parsed_utc": None,
            "validity": "impossible",
            "reason": f"Cannot parse timestamp value: {raw_ts}",
        }

    if parsed < _EPOCH_START:
        return {
            "raw_timestamp": raw_ts,
            "parsed_utc": parsed.isoformat(),
            "validity": "impossible",
            "reason": f"Date {parsed.isoformat()} predates reasonable compilation",
        }

    if parsed > _FUTURE_THRESHOLD:
        return {
            "raw_timestamp": raw_ts,
            "parsed_utc": parsed.isoformat(),
            "validity": "impossible",
            "reason": f"Date {parsed.isoformat()} is in the future",
        }

    return {
        "raw_timestamp": raw_ts,
        "parsed_utc": parsed.isoformat(),
        "validity": "valid",
        "reason": None,
    }


def _compute_verdict(
    packing_indicators: list[str],
    suspicious_imports: dict[str, list[str]],
    timestamp: dict[str, object],
    sections: list[dict[str, object]],
) -> dict[str, object]:
    """Compute an overall triage verdict from analysis results.

    Weighs packing indicators, suspicious import categories, timestamp
    anomalies, and section characteristics to produce a classification
    with supporting reasons.

    Args:
        packing_indicators: Detected packing signals.
        suspicious_imports: Imports grouped by threat category.
        timestamp: Timestamp validity assessment dict.
        sections: Section metadata with entropy and permissions.

    Returns:
        Dict with classification, confidence, and reasons.
    """
    reasons: list[str] = []
    score = 0

    if packing_indicators:
        score += len(packing_indicators) * 2
        reasons.append(f"{len(packing_indicators)} packing indicator(s) detected")

    high_risk_categories = {"process_injection", "privilege_escalation"}
    for category, apis in suspicious_imports.items():
        if category in high_risk_categories:
            score += len(apis) * 3
        else:
            score += len(apis)
        reasons.append(f"{category}: {len(apis)} suspicious API(s)")

    validity = str(timestamp.get("validity", ""))
    if validity == "impossible":
        score += 5
        reasons.append(f"Impossible timestamp: {timestamp.get('reason', '')}")
    elif validity == "suspicious":
        score += 2
        reasons.append("Missing or suspicious timestamp")

    rwx_sections = [
        s
        for s in sections
        if "w" in str(s.get("permissions", "")) and "x" in str(s.get("permissions", ""))
    ]
    if rwx_sections:
        score += 4
        reasons.append(f"{len(rwx_sections)} section(s) with RWX permissions")

    if score >= 10:
        classification = "malicious_indicators"
        confidence = "high" if score >= 15 else "medium"
    elif score >= 4:
        classification = "suspicious_indicators"
        confidence = "medium" if score >= 7 else "low"
    else:
        classification = "benign_indicators"
        confidence = "medium"

    return {
        "classification": classification,
        "confidence": confidence,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# CAPA helpers
# ---------------------------------------------------------------------------


def _parse_capa_output(raw: dict[str, Any], file_path: str) -> dict[str, object]:
    """Parse CAPA JSON output into structured result.

    Args:
        raw: Parsed JSON from CAPA's stdout.
        file_path: Original file path for reference.

    Returns:
        Dict with capabilities, MITRE mappings, and stats.
    """
    capabilities: list[dict[str, object]] = []
    mitre_summary: dict[str, list[str]] = {}

    for rule_name, rule_data in raw.get("rules", {}).items():
        meta: dict[str, Any] = rule_data.get("meta", {})
        namespace = meta.get("namespace", "unknown")
        attack_refs: list[dict[str, Any]] = meta.get("attack", [])

        mappings: list[dict[str, object]] = []
        for ref in attack_refs:
            tactic = str(ref.get("tactic", ""))
            technique_id = str(ref.get("id", ""))
            technique_name = str(ref.get("technique", ""))

            mappings.append(
                {
                    "tactic": tactic,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    # capa's AttackSpec field is `subtechnique` and holds a
                    # name, not an id; `id` already carries the full
                    # "T1055.012". `subtechnique_id` was always None.
                    "subtechnique": str(ref.get("subtechnique", "")),
                }
            )

            if tactic:
                if tactic not in mitre_summary:
                    mitre_summary[tactic] = []
                subtechnique = str(ref.get("subtechnique", ""))
                desc = f"{technique_id}: {technique_name}" + (
                    f"::{subtechnique}" if subtechnique else ""
                )
                if desc not in mitre_summary[tactic]:
                    mitre_summary[tactic].append(desc)

        addresses: dict[str, Any] = rule_data.get("matches", {})
        capabilities.append(
            {
                "name": rule_name,
                "namespace": namespace,
                "attack": mappings,
                "matched_addresses": len(addresses),
            }
        )

    return {
        "file_path": file_path,
        "capabilities": capabilities,
        "mitre_summary": mitre_summary,
        "total_rules_matched": len(capabilities),
        "analysis_time_seconds": raw.get("meta", {}).get("analysis", {}).get("time", 0.0),
        "capa_version": raw.get("meta", {}).get("version", "unknown"),
    }


# ---------------------------------------------------------------------------
# FLOSS helpers
# ---------------------------------------------------------------------------


def _extract_floss_strings(
    entries: list[dict[str, Any]],
    encoding: str,
) -> list[dict[str, object]]:
    """Extract and categorize strings from a FLOSS output section.

    Args:
        entries: List of string entries from FLOSS JSON.
        encoding: The encoding type label for this section.

    Returns:
        List of categorized string dicts.
    """
    results: list[dict[str, object]] = []
    for entry in entries:
        value = str(entry.get("string", entry.get("value", "")))
        if not value:
            continue
        results.append(
            {
                "value": value,
                "encoding": str(entry.get("encoding", encoding)),
                "string_type": encoding,
                # A decoded or stack string never existed in the file, so it
                # has no offset; it has an address in memory instead.
                "offset": entry.get("offset"),
                "address": entry.get("address"),
                "decoding_routine_address": entry.get("decoding_routine"),
                "category": _categorize_decoded_string(value),
            }
        )
    return results


def _floss_runtime_seconds(raw: dict[str, Any]) -> float:
    """FLOSS records its runtime under ``metadata.runtime``, not ``elapsed_time``."""
    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        return 0.0
    runtime = metadata.get("runtime", {})
    if isinstance(runtime, dict):
        total = runtime.get("total")
        if isinstance(total, int | float):
            return float(total)
    return 0.0


def _parse_floss_output(raw: dict[str, Any], file_path: str) -> dict[str, object]:
    """Parse FLOSS JSON output into structured result.

    Categorizes each recovered string by forensic relevance.

    Args:
        raw: Parsed JSON from FLOSS stdout.
        file_path: Original file path for reference.

    Returns:
        Dict with categorized decoded strings and stats.
    """
    # FLOSS's ResultDocument is {metadata, analysis, strings}; all four string
    # lists live under `strings`, and the decoded one is `decoded_strings`.
    # Reading them from the top level returned four empty lists for every
    # sample, which the tool reported as "no obfuscated strings recovered".
    strings: dict[str, Any] = raw.get("strings", {})
    if not isinstance(strings, dict):
        strings = {}

    decoded = _extract_floss_strings(strings.get("decoded_strings", []), "xor")
    stack = _extract_floss_strings(strings.get("stack_strings", []), "stack")
    tight = _extract_floss_strings(strings.get("tight_strings", []), "tight")
    static = _extract_floss_strings(strings.get("static_strings", []), "static")

    return {
        "file_path": file_path,
        "decoded_strings": decoded,
        "stack_strings": stack,
        "tight_strings": tight,
        "static_strings": static,
        "total_decoded": len(decoded) + len(stack) + len(tight),
        "analysis_time_seconds": _floss_runtime_seconds(raw),
    }


# ---------------------------------------------------------------------------
# Detect-It-Easy helpers
# ---------------------------------------------------------------------------


def _die_records(raw: dict[str, Any]) -> list[tuple[dict[str, Any], str]]:
    """Yield ``(record, filetype)`` for every DIE detection.

    Detect It Easy nests the real detection records one level down::

        {"detects": [{"filetype": "ELF64", "parentfilepart": "Header",
                      "values": [{"type": "Compiler", "name": "GCC", ...}]}]}

    The ``detects[]`` entry itself carries no ``type`` or ``name``, so reading
    those from it produced ``{"type": "unknown", "name": ""}`` for every
    detection -- packers included. The flat shape is still accepted, so an
    older diec (or ``--json`` from a different build) keeps working.

    Verified against Detect It Easy 3.09.
    """
    records: list[tuple[dict[str, Any], str]] = []
    for entry in raw.get("detects", []):
        if not isinstance(entry, dict):
            continue
        filetype = str(entry.get("filetype", ""))
        values = entry.get("values")
        if isinstance(values, list):
            records.extend((value, filetype) for value in values if isinstance(value, dict))
        else:
            records.append((entry, filetype or str(raw.get("filetype", ""))))
    return records


def _parse_die_output(raw: dict[str, Any], file_path: str) -> dict[str, object]:
    """Parse diec JSON output into structured result.

    Categorizes detections by type and determines packing status.

    Args:
        raw: Parsed JSON from diec stdout.
        file_path: Original file path for reference.

    Returns:
        Dict with categorized detections and packing assessment.
    """
    detections: list[dict[str, object]] = []
    compilers: list[dict[str, object]] = []
    packers: list[dict[str, object]] = []
    protectors: list[dict[str, object]] = []
    linkers: list[dict[str, object]] = []

    file_type = "unknown"
    for entry in _die_records(raw):
        record, parent_filetype = entry
        if file_type == "unknown" and parent_filetype:
            file_type = parent_filetype

        detection: dict[str, object] = {
            "type": record.get("type", "unknown"),
            "name": record.get("name", ""),
            "version": record.get("version"),
            "options": record.get("options", record.get("info")),
        }
        detections.append(detection)

        # DIE capitalises the type on output: a rule declaring
        # init("packer", "UPX") is emitted as "type": "Packer".
        det_type = str(record.get("type", "")).lower()
        if det_type == "compiler":
            compilers.append(detection)
        elif det_type == "packer":
            packers.append(detection)
        elif det_type == "protector":
            protectors.append(detection)
        elif det_type == "linker":
            linkers.append(detection)

    is_packed = len(packers) > 0 or len(protectors) > 0
    packer_name: str | None = None
    if packers:
        packer_name = str(packers[0].get("name", ""))
    elif protectors:
        packer_name = str(protectors[0].get("name", ""))

    return {
        "file_path": file_path,
        "file_type": file_type,
        "detections": detections,
        "compilers": compilers,
        "packers": packers,
        "protectors": protectors,
        "linkers": linkers,
        "is_packed": is_packed,
        "packer_name": packer_name,
        "entropy": raw.get("entropy"),
        "overlay_present": raw.get("overlay", {}).get("present", False),
        "overlay_size": raw.get("overlay", {}).get("size"),
    }


# ---------------------------------------------------------------------------
# MCP Tool: triage_binary
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def triage_binary(
    case_id: str,
    file_path: str,
    depth: str = "standard",
) -> dict[str, object]:
    """Triage a binary using rabin2 for forensic analysis.

    Runs static analysis on a PE/ELF/Mach-O binary to extract metadata,
    imports, sections, strings, and indicators of malicious behavior.
    Returns structured results with a triage verdict.

    Args:
        case_id: Active case identifier.
        file_path: Absolute path to the binary to analyze (extracted
            via icat or from a mounted filesystem).
        depth: Analysis depth. "quick" returns headers only, "standard"
            adds imports, exports, strings, and sections, "deep" adds
            library dependencies and multi-algorithm hashes.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    if depth not in ("quick", "standard", "deep"):
        depth = "standard"
    params: dict[str, object] = {
        "case_id": case_id,
        "file_path": file_path,
        "depth": depth,
    }

    if not require_binary("rabin2"):
        return error_response(
            tc_id,
            "triage_binary",
            params,
            "rabin2 not found on PATH",
            error_type="binary_missing",
            suggestion="Install radare2: apt-get install radare2",
        )

    target = Path(file_path)
    if not target.exists():
        return error_response(
            tc_id,
            "triage_binary",
            params,
            f"File not found: {file_path}",
            error_type="file_not_found",
        )

    raw_parts: list[str] = []

    try:
        info_raw = _run_rabin2("I", target)
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "triage_binary",
            params,
            f"rabin2 timed out after {_RABIN2_TIMEOUT}s",
            (time.monotonic() - t0) * 1000,
            error_type="timeout",
        )
    except OSError as exc:
        return error_response(
            tc_id,
            "triage_binary",
            params,
            f"Failed to execute rabin2: {exc}",
            (time.monotonic() - t0) * 1000,
        )

    file_info = _parse_file_info(info_raw)
    raw_parts.append(json.dumps(info_raw, indent=2, default=str))

    imports: list[str] = []
    sections: list[dict[str, object]] = []
    strings_of_interest: list[dict[str, object]] = []
    hashes: dict[str, str] = {}

    if depth in ("standard", "deep"):
        try:
            imports_raw = _run_rabin2("i", target)
            imports = _parse_imports(imports_raw)
            raw_parts.append(json.dumps(imports_raw, indent=2, default=str))

            sections_raw = _run_rabin2("S", target)
            sections = _parse_sections(sections_raw)
            raw_parts.append(json.dumps(sections_raw, indent=2, default=str))

            strings_raw = _run_rabin2("z", target)
            strings_of_interest = _parse_strings(strings_raw)
            raw_parts.append(json.dumps(strings_raw, indent=2, default=str))
        except subprocess.TimeoutExpired:
            logger.warning("rabin2 timed out during standard analysis of %s", file_path)
        except OSError:
            logger.warning("Failed to run rabin2 standard analysis on %s", file_path)

    if depth == "deep":
        try:
            libs_raw = _run_rabin2("l", target)
            raw_parts.append(json.dumps(libs_raw, indent=2, default=str))
        except (subprocess.TimeoutExpired, OSError):
            logger.warning("rabin2 library enumeration failed for %s", file_path)

        if require_binary("rahash2"):
            try:
                proc = subprocess.run(
                    ["rahash2", "-a", "md5,sha1,sha256", str(target)],
                    capture_output=True,
                    text=True,
                    timeout=_RABIN2_TIMEOUT,
                    check=False,
                )
                for line in proc.stdout.splitlines():
                    m = _RAHASH_RE.search(line)
                    if m:
                        hashes[m.group(1)] = m.group(2)
                raw_parts.append(proc.stdout)
            except (subprocess.TimeoutExpired, OSError):
                logger.warning("rahash2 failed for %s", file_path)

    suspicious_imports = _classify_imports(imports)
    packing_indicators = _detect_packing(sections, imports)

    info_dict: dict[str, Any] = info_raw.get("info", info_raw.get("bin", {}))
    raw_ts_val = info_dict.get("compiled")
    raw_ts = str(raw_ts_val) if raw_ts_val is not None else None
    if raw_ts in ("None", "0", ""):
        raw_ts = None
    timestamp = _assess_timestamp(raw_ts)

    verdict = _compute_verdict(packing_indicators, suspicious_imports, timestamp, sections)

    combined_output = "\n\n".join(raw_parts)
    summary = extract_and_index(combined_output, "binary.triage", file_path, "rabin2")

    summary["file_info"] = file_info
    summary["timestamps"] = timestamp
    summary["packing_indicators"] = packing_indicators
    summary["suspicious_imports"] = suspicious_imports
    summary["sections"] = sections
    summary["strings_of_interest"] = strings_of_interest[:100]
    summary["hashes"] = hashes
    summary["triage_verdict"] = verdict
    summary["depth"] = depth

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "triage_binary", params, summary, "binary.triage", elapsed)


# ---------------------------------------------------------------------------
# MCP Tool: run_capa
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def run_capa(
    case_id: str,
    file_path: str,
    output_format: str = "default",
    rules_path: str | None = None,
) -> dict[str, object]:
    """Identify capabilities in a binary using Mandiant CAPA.

    Runs CAPA's rule engine against an executable to detect behavioral
    capabilities and map them to MITRE ATT&CK techniques. Supports
    PE, ELF, and shellcode analysis.

    Args:
        case_id: Active case identifier.
        file_path: Absolute path to the binary to analyze.
        output_format: Result grouping. "default" groups by capability
            namespace. "mitre" groups results by ATT&CK tactic and
            technique ID.
        rules_path: Optional path to a custom rules directory. If not
            provided, CAPA uses its bundled default rule set.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "case_id": case_id,
        "file_path": file_path,
        "output_format": output_format,
        "rules_path": rules_path,
    }

    capa_bin = require_binary("capa")
    if not capa_bin and not Path(_CAPA_BINARY).exists():
        return error_response(
            tc_id,
            "run_capa",
            params,
            "capa not found on PATH",
            error_type="binary_missing",
            suggestion="Install CAPA from https://github.com/mandiant/capa/releases",
        )
    capa_bin = capa_bin or _CAPA_BINARY

    target = Path(file_path)
    if not target.exists():
        return error_response(
            tc_id,
            "run_capa",
            params,
            f"File not found: {file_path}",
            error_type="file_not_found",
        )

    cmd = [capa_bin, "--json", "--quiet"]
    if rules_path:
        if not Path(rules_path).exists():
            return error_response(
                tc_id,
                "run_capa",
                params,
                f"Rules path not found: {rules_path}",
                error_type="file_not_found",
            )
        cmd.extend(["--rules", rules_path])
    cmd.append(str(target))

    capa_timeout = adaptive_timeout(file_path, base=_CAPA_TIMEOUT)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=capa_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_capa",
            params,
            f"CAPA timed out after {capa_timeout}s (complex binary?)",
            (time.monotonic() - t0) * 1000,
            error_type="timeout",
        )
    except OSError as exc:
        return error_response(
            tc_id,
            "run_capa",
            params,
            f"Failed to execute CAPA: {exc}",
            (time.monotonic() - t0) * 1000,
        )

    if proc.returncode != 0 and not proc.stdout.strip():
        stderr = (proc.stderr or "").strip()[:500]
        return error_response(
            tc_id,
            "run_capa",
            params,
            f"CAPA exited with code {proc.returncode}: {stderr}",
            (time.monotonic() - t0) * 1000,
        )

    try:
        loaded = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return error_response(
            tc_id,
            "run_capa",
            params,
            "Failed to parse CAPA JSON output",
            (time.monotonic() - t0) * 1000,
        )

    if not isinstance(loaded, dict):
        return error_response(
            tc_id,
            "run_capa",
            params,
            "Unexpected CAPA output format (expected JSON object)",
            (time.monotonic() - t0) * 1000,
        )

    raw_json: dict[str, Any] = loaded
    parsed = _parse_capa_output(raw_json, file_path)

    summary = extract_and_index(proc.stdout, "capa.analysis", file_path, "capa")
    summary.update(parsed)
    summary["grouped_by"] = "mitre_tactic" if output_format == "mitre" else "namespace"

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_capa", params, summary, "capa.analysis", elapsed)


# ---------------------------------------------------------------------------
# MCP Tool: run_floss
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_floss(
    case_id: str,
    file_path: str,
    minimum_length: int = 6,
    include_static: bool = True,
) -> dict[str, object]:
    """Extract obfuscated strings from a binary using FLOSS.

    Runs FLARE Obfuscated String Solver to decode hidden strings that
    standard extraction cannot recover. Detects XOR encoding, stack
    strings, Base64, and other obfuscation techniques via emulation.

    Args:
        case_id: Active case identifier.
        file_path: Absolute path to the binary to analyze.
        minimum_length: Minimum string length to report (filters noise).
        include_static: Whether to include standard static strings
            alongside decoded strings. Set False to see only the
            obfuscated strings that FLOSS uniquely recovers.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "case_id": case_id,
        "file_path": file_path,
        "minimum_length": minimum_length,
        "include_static": include_static,
    }

    floss_bin = require_binary("floss")
    if not floss_bin and not Path(_FLOSS_BINARY).exists():
        return error_response(
            tc_id,
            "run_floss",
            params,
            "floss not found on PATH",
            error_type="binary_missing",
            suggestion="Install FLOSS from https://github.com/mandiant/flare-floss/releases",
        )
    floss_bin = floss_bin or _FLOSS_BINARY

    target = Path(file_path)
    if not target.exists():
        return error_response(
            tc_id,
            "run_floss",
            params,
            f"File not found: {file_path}",
            error_type="file_not_found",
        )

    cmd = [
        floss_bin,
        "--json",
        "--minimum-length",
        str(minimum_length),
        # The sample must precede --no/--only: both are nargs="+" with
        # `choices`, so argparse consumes the following path as a string
        # type and exits 2.
        str(target),
    ]
    if not include_static:
        cmd.extend(["--no", "static"])

    floss_timeout = adaptive_timeout(file_path, base=_FLOSS_TIMEOUT)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=floss_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_floss",
            params,
            f"FLOSS timed out after {floss_timeout}s (emulation is expensive)",
            (time.monotonic() - t0) * 1000,
            error_type="timeout",
        )
    except OSError as exc:
        return error_response(
            tc_id,
            "run_floss",
            params,
            f"Failed to execute FLOSS: {exc}",
            (time.monotonic() - t0) * 1000,
        )

    if proc.returncode != 0 and not proc.stdout.strip():
        stderr = (proc.stderr or "").strip()[:500]
        return error_response(
            tc_id,
            "run_floss",
            params,
            f"FLOSS exited with code {proc.returncode}: {stderr}",
            (time.monotonic() - t0) * 1000,
        )

    try:
        loaded = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return error_response(
            tc_id,
            "run_floss",
            params,
            "Failed to parse FLOSS JSON output",
            (time.monotonic() - t0) * 1000,
        )

    if not isinstance(loaded, dict):
        return error_response(
            tc_id,
            "run_floss",
            params,
            "Unexpected FLOSS output format (expected JSON object)",
            (time.monotonic() - t0) * 1000,
        )

    raw_json: dict[str, Any] = loaded
    parsed = _parse_floss_output(raw_json, file_path)

    summary = extract_and_index(proc.stdout, "floss.analysis", file_path, "floss")
    summary.update(parsed)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_floss", params, summary, "floss.analysis", elapsed)


# ---------------------------------------------------------------------------
# MCP Tool: run_detect_it_easy
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_detect_it_easy(
    case_id: str,
    file_path: str,
    deep_scan: bool = True,
) -> dict[str, object]:
    """Identify packers, compilers, and protectors using Detect-It-Easy.

    Scans a binary against DIE's signature database to identify the
    specific tools used to build or transform it. Returns compiler,
    packer, linker, protector, and file format information.

    Args:
        case_id: Active case identifier.
        file_path: Absolute path to the binary to analyze.
        deep_scan: Enable deep scan mode for more thorough detection
            at the cost of slightly longer analysis time.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "case_id": case_id,
        "file_path": file_path,
        "deep_scan": deep_scan,
    }

    diec_bin = require_binary("diec")
    if not diec_bin and not Path(_DIEC_BINARY).exists():
        return error_response(
            tc_id,
            "run_detect_it_easy",
            params,
            "diec not found on PATH",
            error_type="binary_missing",
            suggestion=(
                "Detect-It-Easy is not bundled (its .deb needs ten libqt5* packages). "
                "Install it with: sudo apt install ./die_<version>_Ubuntu_<rel>_amd64.deb "
                "from https://github.com/horsicq/DIE-engine/releases -- `apt install` "
                "rather than `dpkg -i`, which cannot resolve those dependencies. "
                "Without it, triage_binary still flags packing by entropy and section shape."
            ),
        )
    diec_bin = diec_bin or _DIEC_BINARY

    target = Path(file_path)
    if not target.exists():
        return error_response(
            tc_id,
            "run_detect_it_easy",
            params,
            f"File not found: {file_path}",
            error_type="file_not_found",
        )

    cmd = [diec_bin, "--json"]
    if deep_scan:
        cmd.append("--deepscan")
    cmd.append(str(target))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_DIEC_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_detect_it_easy",
            params,
            f"diec timed out after {_DIEC_TIMEOUT}s",
            (time.monotonic() - t0) * 1000,
            error_type="timeout",
        )
    except OSError as exc:
        return error_response(
            tc_id,
            "run_detect_it_easy",
            params,
            f"Failed to execute diec: {exc}",
            (time.monotonic() - t0) * 1000,
        )

    if proc.returncode != 0 and not proc.stdout.strip():
        stderr = (proc.stderr or "").strip()[:500]
        return error_response(
            tc_id,
            "run_detect_it_easy",
            params,
            f"diec exited with code {proc.returncode}: {stderr}",
            (time.monotonic() - t0) * 1000,
        )

    try:
        loaded = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return error_response(
            tc_id,
            "run_detect_it_easy",
            params,
            "Failed to parse diec JSON output",
            (time.monotonic() - t0) * 1000,
        )

    if not isinstance(loaded, dict):
        return error_response(
            tc_id,
            "run_detect_it_easy",
            params,
            "Unexpected diec output format (expected JSON object)",
            (time.monotonic() - t0) * 1000,
        )

    raw_json: dict[str, Any] = loaded
    parsed = _parse_die_output(raw_json, file_path)

    summary = extract_and_index(proc.stdout, "die.analysis", file_path, "diec")
    summary.update(parsed)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_detect_it_easy", params, summary, "die.analysis", elapsed)
