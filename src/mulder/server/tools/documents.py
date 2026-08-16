"""Document analysis MCP tools: Microsoft Office and PDF forensics."""

from __future__ import annotations

import importlib.util
import json
import logging
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    require_binary,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "analyze_office_document",
    "analyze_pdf",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OLEVBA_TIMEOUT = 120
_PDFID_TIMEOUT = 60
_PDF_PARSER_TIMEOUT = 120

_PDFID_SCRIPT = "/opt/didier-stevens/pdfid.py"
_PDF_PARSER_SCRIPT = "/opt/didier-stevens/pdf-parser.py"

_OFFICE_EXTENSIONS = {
    ".doc",
    ".docx",
    ".docm",
    ".dot",
    ".dotx",
    ".dotm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".xlt",
    ".xltx",
    ".xltm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".pot",
    ".potx",
    ".potm",
    ".rtf",
}

_SUSPICIOUS_KEYWORDS: dict[str, str] = {
    "Shell": "Command execution",
    "WScript.Shell": "Script host execution",
    "PowerShell": "PowerShell invocation",
    "CreateObject": "COM object creation",
    "URLDownloadToFile": "File download",
    "XMLHTTP": "HTTP request",
    "ADODB.Stream": "Binary stream manipulation",
    "Environ": "Environment variable access",
    "CallByName": "Dynamic method invocation",
    "GetObject": "COM object binding",
    "Chr(": "Character obfuscation",
    "ChrW(": "Unicode character obfuscation",
    "Execute": "Dynamic code execution",
    "Eval": "Dynamic expression evaluation",
}

_AUTO_EXEC_TRIGGERS: set[str] = {
    "AutoOpen",
    "AutoClose",
    "AutoExec",
    "AutoExit",
    "AutoNew",
    "Document_Open",
    "Document_Close",
    "Workbook_Open",
    "Workbook_Close",
    "Auto_Open",
    "Auto_Close",
}

_PDF_INDICATOR_RISK_MAP: dict[str, tuple[str, str]] = {
    "/JS": ("high", "JavaScript reference in PDF"),
    "/JavaScript": ("high", "JavaScript action defined"),
    "/OpenAction": ("high", "Automatic action on document open"),
    "/AA": ("high", "Additional automatic actions"),
    "/Launch": ("high", "Launch action (can execute programs)"),
    "/EmbeddedFile": ("medium", "Embedded file stream"),
    "/RichMedia": ("medium", "Rich media content (Flash/video)"),
    "/XFA": ("medium", "XML Forms Architecture (can contain scripts)"),
    "/AcroForm": ("low", "Interactive form fields"),
    "/JBIG2Decode": ("medium", "JBIG2 decoder (CVE-2009-0658 target)"),
    "/ObjStm": ("low", "Object stream (can hide content)"),
    "/URI": ("low", "External URI reference"),
}

_SUSPICIOUS_JS_FUNCTIONS: list[str] = [
    "eval",
    "unescape",
    "fromCharCode",
    "replace",
    "substr",
    "setTimeout",
    "setInterval",
    "document.write",
    "ActiveXObject",
    "XMLHttpRequest",
    "app.launchURL",
    "util.printf",
    "spell.customDictionaryOpen",
    "Collab.collectEmailInfo",
    "getAnnots",
    "getPageNthWord",
    "media.newPlayer",
]


# ---------------------------------------------------------------------------
# Office document helpers
# ---------------------------------------------------------------------------

#: Literal header msodde prints immediately before the DDE links it found.
#: Everything above it is banner/log noise.
_MSODDE_LINK_MARKER = "DDE Links:"


def _parse_msodde_output(stdout: str) -> list[dict[str, object]]:
    """Extract DDE links from msodde's output.

    msodde unconditionally writes a four-line banner, an ``Opening file: <path>``
    line and a ``DDE Links:`` header to **stdout**, so treating every non-blank
    stdout line as a DDE link fabricates five ``risk: high`` findings for a
    perfectly clean document — one of which discloses the absolute evidence path
    as a "DDE command".

    With ``--json`` msodde emits a JSON array whose entries carry a ``type`` key:
    ``"dde-link"`` for a real link, ``"msg"`` for banner and log lines. That tag
    is the authoritative signal, so it is preferred. If the JSON cannot be parsed
    (a crashed msodde, or a future format change) fall back to the plain-text
    layout, where a real link can only appear *after* the ``DDE Links:`` marker.

    Args:
        stdout: Captured stdout from ``python -m oletools.msodde``.

    Returns:
        List of DDE link records, empty when the document has no DDE links.
    """
    raw_links: list[str] = []
    text = stdout.strip()

    parsed: Any = None
    if text:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None

    if isinstance(parsed, list):
        for entry in parsed:
            if isinstance(entry, dict) and entry.get("type") == "dde-link":
                msg = str(entry.get("msg", "")).strip()
                if msg:
                    raw_links.append(msg)
    else:
        # Plain-text fallback. Anything before the marker is banner noise, and
        # if the marker never appears (e.g. a traceback) there are no links.
        after_marker = False
        for line in stdout.splitlines():
            stripped = line.strip()
            if not after_marker:
                after_marker = stripped == _MSODDE_LINK_MARKER
                continue
            if stripped and not stripped.startswith("#"):
                raw_links.append(stripped)

    return [
        {
            "field_type": "DDEAUTO" if "DDEAUTO" in link.upper() else "DDE",
            "command": link,
            "risk": "high",
        }
        for link in raw_links
    ]


def _analyze_macros_olevba(
    file_path: Path,
) -> tuple[list[dict[str, object]], list[dict[str, object]], bool]:
    """Run olevba to extract and analyze VBA macros.

    Args:
        file_path: Path to the Office document.

    Returns:
        Tuple of (macros list, analysis indicators, has_vba flag).

    Raises:
        subprocess.TimeoutExpired: If olevba exceeds the timeout.
        OSError: If olevba cannot be executed or exits non-zero with no output.
    """
    # oletools is a mulder dependency, so its console scripts live in mulder's
    # own venv bin/ — which pipx does not link onto PATH.  Invoke the module.
    cmd = [sys.executable, "-m", "oletools.olevba", "--json", str(file_path)]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_OLEVBA_TIMEOUT,
        check=False,
    )

    output = proc.stdout.strip()
    # Module invocation always execs successfully, so a broken oletools would
    # otherwise be indistinguishable from "this document has no macros" — the
    # worst possible false negative for a potentially malicious document.
    if proc.returncode != 0 and not output:
        raise OSError(
            f"olevba failed (exit {proc.returncode}): {proc.stderr.strip()[:500] or 'no output'}"
        )
    if not output:
        return [], [], False

    try:
        raw: Any = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("Failed to parse olevba JSON output for %s", file_path)
        return [], [], False

    macros: list[dict[str, object]] = []
    indicators: list[dict[str, object]] = []
    has_vba = False

    results: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        results = raw.get("results", [])
    elif isinstance(raw, list):
        results = [r for r in raw if isinstance(r, dict)]

    for result in results:
        for macro in result.get("macros", []):
            code = str(macro.get("code", macro.get("vba_code", "")))
            module_name = str(macro.get("vba_filename", macro.get("module", "")))

            suspicious = [kw for kw in _SUSPICIOUS_KEYWORDS if kw.lower() in code.lower()]
            is_auto = any(trigger.lower() in code.lower() for trigger in _AUTO_EXEC_TRIGGERS)

            if code.strip():
                has_vba = True
                macros.append(
                    {
                        "module_name": module_name,
                        "source_code": code,
                        "is_auto_exec": is_auto,
                        "suspicious_keywords": suspicious,
                    }
                )

        for indicator in result.get("analysis", []):
            indicators.append(
                {
                    "type": indicator.get("type", ""),
                    "keyword": indicator.get("keyword", ""),
                    "description": indicator.get("description", ""),
                }
            )
            if indicator.get("type") in ("VBA", "AutoExec", "Suspicious"):
                has_vba = True

    return macros, indicators, has_vba


def _assess_office_risk(
    macros: list[dict[str, object]],
    has_vba: bool,
) -> dict[str, object]:
    """Assess risk level for an Office document.

    Args:
        macros: Extracted macro information.
        has_vba: Whether VBA macros were detected.

    Returns:
        Dict with risk_level, auto_exec, suspicious flags, and reasons.
    """
    reasons: list[str] = []
    auto_exec = any(m.get("is_auto_exec") for m in macros)

    has_suspicious = any(m.get("suspicious_keywords") for m in macros)

    exec_keywords = {"Shell", "WScript.Shell", "Execute", "PowerShell"}
    download_keywords = {"URLDownloadToFile", "XMLHTTP"}
    obfuscation_keywords = {"Chr(", "ChrW(", "CallByName"}

    all_keywords: list[str] = []
    for m in macros:
        kws = m.get("suspicious_keywords")
        if isinstance(kws, list):
            all_keywords.extend(str(k) for k in kws)

    keyword_set = set(all_keywords)
    has_execute = bool(keyword_set & exec_keywords)
    has_download = bool(keyword_set & download_keywords)
    has_obfuscation = bool(keyword_set & obfuscation_keywords)

    if auto_exec:
        reasons.append("Auto-execution trigger present")
    if has_suspicious:
        reasons.append("Suspicious API calls detected")
    if has_execute:
        reasons.append("Executes external commands")
    if has_download:
        reasons.append("Downloads content from external sources")
    if has_obfuscation:
        reasons.append("Character obfuscation detected")

    if not has_vba:
        risk_level = "clean"
    elif auto_exec and (has_execute or has_download):
        risk_level = "malicious"
    elif auto_exec:
        risk_level = "high"
    elif has_suspicious:
        risk_level = "medium"
    elif has_vba:
        risk_level = "low"
    else:
        risk_level = "clean"

    return {
        "risk_level": risk_level,
        "auto_exec": auto_exec,
        "suspicious_api_calls": has_suspicious,
        "write_to_filesystem": has_execute,
        "external_connections": has_download,
        "obfuscation_detected": has_obfuscation,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# PDF helpers
# ---------------------------------------------------------------------------


def _run_pdfid(file_path: Path) -> list[dict[str, object]]:
    """Execute pdfid and parse indicator results.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of PDF structural indicators with risk levels.

    Raises:
        subprocess.TimeoutExpired: If pdfid exceeds the timeout.
        OSError: If pdfid cannot be executed.
    """
    if Path(_PDFID_SCRIPT).exists():
        cmd = [sys.executable, _PDFID_SCRIPT, "--force", str(file_path)]
    else:
        pdfid_bin = require_binary("pdfid") or "pdfid"
        cmd = [pdfid_bin, "--force", str(file_path)]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_PDFID_TIMEOUT,
        check=False,
    )

    indicators: list[dict[str, object]] = []
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        for keyword, (risk, description) in _PDF_INDICATOR_RISK_MAP.items():
            clean_keyword = keyword.lstrip("/")
            if clean_keyword in stripped:
                count = _extract_pdfid_count(stripped)
                if count > 0:
                    indicators.append(
                        {
                            "keyword": keyword,
                            "count": count,
                            "risk_level": risk,
                            "description": description,
                        }
                    )
    return indicators


def _extract_pdfid_count(line: str) -> int:
    """Extract the numeric count from a pdfid output line.

    Args:
        line: A single line from pdfid output.

    Returns:
        Integer count value, or 0 if not parseable.
    """
    parts = line.rsplit(None, 1)
    if len(parts) == 2:
        try:
            return int(parts[1])
        except ValueError:
            return 0
    return 0


def _extract_pdf_javascript(file_path: Path) -> list[dict[str, object]]:
    """Extract JavaScript code from PDF objects.

    Uses pdf-parser to identify and extract JavaScript streams
    from the PDF document structure.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of JavaScript extractions with analysis.
    """
    if Path(_PDF_PARSER_SCRIPT).exists():
        cmd = [
            sys.executable,
            _PDF_PARSER_SCRIPT,
            "--type",
            "/JS",
            "--filter",
            str(file_path),
        ]
    else:
        parser_bin = require_binary("pdf-parser") or "pdf-parser"
        cmd = [parser_bin, "--type", "/JS", "--filter", str(file_path)]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_PDF_PARSER_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    scripts: list[dict[str, object]] = []
    obj_re = re.compile(r"obj (\d+)")
    current_obj_id: int | None = None
    current_code: list[str] = []

    for line in proc.stdout.splitlines():
        obj_match = obj_re.match(line)
        if obj_match:
            if current_obj_id is not None and current_code:
                code = "\n".join(current_code)
                scripts.append(_make_js_entry(current_obj_id, code))
            current_obj_id = int(obj_match.group(1))
            current_code = []
        else:
            current_code.append(line)

    if current_obj_id is not None and current_code:
        code = "\n".join(current_code)
        scripts.append(_make_js_entry(current_obj_id, code))

    return scripts


def _make_js_entry(object_id: int, code: str) -> dict[str, object]:
    """Build a JavaScript analysis entry for a PDF object.

    Args:
        object_id: PDF object ID containing the script.
        code: Extracted JavaScript source.

    Returns:
        Dict with object_id, code, obfuscation flag, and suspicious functions.
    """
    return {
        "object_id": object_id,
        "code": code,
        "is_obfuscated": _detect_js_obfuscation(code),
        "suspicious_functions": [f for f in _SUSPICIOUS_JS_FUNCTIONS if f.lower() in code.lower()],
    }


def _detect_js_obfuscation(code: str) -> bool:
    """Detect common JavaScript obfuscation patterns.

    Args:
        code: JavaScript source code.

    Returns:
        True if obfuscation indicators are present.
    """
    indicators = [
        len(re.findall(r"\\x[0-9a-fA-F]{2}", code)) > 10,
        len(re.findall(r"\\u[0-9a-fA-F]{4}", code)) > 10,
        "eval(" in code and ("unescape" in code or "fromCharCode" in code),
        code.count("+") > 50 and "String" in code,
        len(re.findall(r"var \w{1,2}=", code)) > 20,
    ]
    return sum(indicators) >= 2


def _compute_pdf_risk(
    indicators: list[dict[str, object]],
    javascript: list[dict[str, object]],
) -> dict[str, object]:
    """Compute overall PDF risk from indicators and extracted content.

    Args:
        indicators: Structural indicators from pdfid.
        javascript: Extracted JavaScript objects.

    Returns:
        Dict with risk_level, flags, and reasons.
    """
    reasons: list[str] = []
    has_js = any(i.get("keyword") in ("/JS", "/JavaScript") for i in indicators)
    has_auto = any(i.get("keyword") in ("/OpenAction", "/AA") for i in indicators)
    has_embedded = any(i.get("keyword") == "/EmbeddedFile" for i in indicators)
    has_launch = any(i.get("keyword") == "/Launch" for i in indicators)

    exploit_indicators: list[str] = []
    if any(i.get("keyword") == "/JBIG2Decode" for i in indicators):
        exploit_indicators.append("JBIG2 decoder present (CVE-2009-0658)")

    if has_js:
        reasons.append("Contains JavaScript")
    if has_auto:
        reasons.append("Auto-execution trigger present")
    if has_launch:
        reasons.append("Launch action can execute external programs")
    if has_embedded:
        reasons.append("Contains embedded files")

    obfuscated_js = [js for js in javascript if js.get("is_obfuscated")]
    if obfuscated_js:
        reasons.append(f"{len(obfuscated_js)} obfuscated JavaScript object(s)")

    high_count = sum(1 for i in indicators if i.get("risk_level") == "high")
    if has_launch or (has_js and has_auto and obfuscated_js):
        risk_level = "malicious"
    elif high_count >= 2 or exploit_indicators:
        risk_level = "high"
    elif has_js or has_auto:
        risk_level = "medium"
    elif has_embedded:
        risk_level = "low"
    else:
        risk_level = "clean"

    return {
        "risk_level": risk_level,
        "reasons": reasons,
        "has_javascript": has_js,
        "has_auto_action": has_auto,
        "has_embedded_files": has_embedded,
        "has_launch_action": has_launch,
        "exploit_indicators": exploit_indicators,
    }


# ---------------------------------------------------------------------------
# MCP Tool: analyze_office_document
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def analyze_office_document(
    case_id: str,
    file_path: str,
    extract_macros: bool = True,
    analyze_dde: bool = True,
) -> dict[str, object]:
    """Analyze a Microsoft Office document for malicious content.

    Examines OLE2/OOXML files using oletools to extract VBA macros,
    detect auto-execution triggers, identify suspicious embedded
    objects, and assess overall threat level.

    Args:
        case_id: Active case identifier.
        file_path: Absolute path to the Office document.
        extract_macros: Whether to extract and return full VBA source.
        analyze_dde: Whether to check for DDE/DDEAUTO fields.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "case_id": case_id,
        "file_path": file_path,
        "extract_macros": extract_macros,
        "analyze_dde": analyze_dde,
    }

    if importlib.util.find_spec("oletools") is None:
        return error_response(
            tc_id,
            "analyze_office_document",
            params,
            "oletools is not importable from mulder's interpreter",
            error_type="binary_missing",
            suggestion=(
                "oletools is a mulder dependency; reinstall mulder "
                "(pipx install --force mulder-dfir) or pip install oletools"
            ),
        )

    target = Path(file_path)
    if not target.exists():
        return error_response(
            tc_id,
            "analyze_office_document",
            params,
            f"File not found: {file_path}",
            error_type="file_not_found",
        )

    if target.suffix.lower() not in _OFFICE_EXTENSIONS:
        return error_response(
            tc_id,
            "analyze_office_document",
            params,
            f"Unsupported file format: {target.suffix}. Expected Office document.",
            error_type="invalid_input",
        )

    try:
        macros, indicators, has_vba = _analyze_macros_olevba(target)
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "analyze_office_document",
            params,
            f"olevba timed out after {_OLEVBA_TIMEOUT}s",
            (time.monotonic() - t0) * 1000,
            error_type="timeout",
        )
    except OSError as exc:
        return error_response(
            tc_id,
            "analyze_office_document",
            params,
            f"Failed to execute olevba: {exc}",
            (time.monotonic() - t0) * 1000,
        )

    risk = _assess_office_risk(macros, has_vba)

    # DDE analysis via msodde if requested and available
    dde_links: list[dict[str, object]] = []
    if analyze_dde:
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "oletools.msodde", "--json", str(target)],
                capture_output=True,
                text=True,
                timeout=_OLEVBA_TIMEOUT,
                check=False,
            )
            # DDE analysis is best-effort, but a broken msodde must not pass
            # silently as "no DDE links found". msodde always prints its banner
            # to stdout, so a stdout-emptiness test here would never fire.
            if proc.returncode != 0:
                logger.warning(
                    "msodde failed for %s (exit %s): %s",
                    file_path,
                    proc.returncode,
                    proc.stderr.strip()[:500] or proc.stdout.strip()[:500] or "no output",
                )
            else:
                dde_links = _parse_msodde_output(proc.stdout)
        except (subprocess.TimeoutExpired, OSError):
            logger.debug("msodde analysis failed for %s", file_path)

    index_parts: list[str] = [
        f"File: {file_path}",
        f"Has VBA: {has_vba}",
        f"Risk: {risk.get('risk_level', 'unknown')}",
    ]
    for m in macros:
        index_parts.append(f"Module: {m.get('module_name', 'unknown')}")
        if extract_macros:
            index_parts.append(str(m.get("source_code", "")))
    index_text = "\n".join(index_parts)

    summary = extract_and_index(index_text, "office.analysis", file_path, "oletools")

    if not extract_macros:
        for m in macros:
            m.pop("source_code", None)

    summary["file_type"] = target.suffix.lower()
    summary["macros"] = macros
    summary["indicators"] = indicators
    summary["dde_links"] = dde_links
    summary["risk_assessment"] = risk
    summary["macro_count"] = len(macros)
    summary["has_vba"] = has_vba

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id, "analyze_office_document", params, summary, "office.analysis", elapsed
    )


# ---------------------------------------------------------------------------
# MCP Tool: analyze_pdf
# ---------------------------------------------------------------------------


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def analyze_pdf(
    case_id: str,
    file_path: str,
    extract_javascript: bool = True,
    extract_urls: bool = True,
    extract_embedded: bool = True,
) -> dict[str, object]:
    """Analyze a PDF file for malicious indicators.

    Examines PDF structure using pdfid and pdf-parser to identify
    JavaScript, auto-execution triggers, embedded files, suspicious
    actions, and exploit indicators. Provides a structured risk
    assessment.

    Args:
        case_id: Active case identifier.
        file_path: Absolute path to the PDF file.
        extract_javascript: Whether to extract and return embedded
            JavaScript source code.
        extract_urls: Whether to extract URLs from the PDF.
        extract_embedded: Whether to list embedded files and streams.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "case_id": case_id,
        "file_path": file_path,
        "extract_javascript": extract_javascript,
        "extract_urls": extract_urls,
        "extract_embedded": extract_embedded,
    }

    has_pdfid = Path(_PDFID_SCRIPT).exists() or require_binary("pdfid") is not None
    if not has_pdfid:
        return error_response(
            tc_id,
            "analyze_pdf",
            params,
            "pdfid not found (expected at /opt/didier-stevens/ or on PATH)",
            error_type="binary_missing",
            suggestion="Install: pip install pdfid",
        )

    target = Path(file_path)
    if not target.exists():
        return error_response(
            tc_id,
            "analyze_pdf",
            params,
            f"File not found: {file_path}",
            error_type="file_not_found",
        )

    if target.suffix.lower() != ".pdf":
        return error_response(
            tc_id,
            "analyze_pdf",
            params,
            f"Expected .pdf file, got: {target.suffix}",
            error_type="invalid_input",
        )

    try:
        indicators = _run_pdfid(target)
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "analyze_pdf",
            params,
            f"pdfid timed out after {_PDFID_TIMEOUT}s",
            (time.monotonic() - t0) * 1000,
            error_type="timeout",
        )
    except OSError as exc:
        return error_response(
            tc_id,
            "analyze_pdf",
            params,
            f"Failed to execute pdfid: {exc}",
            (time.monotonic() - t0) * 1000,
        )

    javascript: list[dict[str, object]] = []
    if extract_javascript:
        has_js_indicator = any(i.get("keyword") in ("/JS", "/JavaScript") for i in indicators)
        if has_js_indicator:
            javascript = _extract_pdf_javascript(target)

    risk = _compute_pdf_risk(indicators, javascript)

    index_parts: list[str] = [f"PDF Analysis: {file_path}"]
    for ind in indicators:
        index_parts.append(
            f"{ind.get('keyword', '')}: {ind.get('count', 0)} [{ind.get('risk_level', '')}]"
        )
    for js in javascript:
        index_parts.append(f"JavaScript in object {js.get('object_id', '?')}")
        code_preview = str(js.get("code", ""))[:2000]
        index_parts.append(code_preview)
    index_text = "\n".join(index_parts)

    summary = extract_and_index(index_text, "pdf.analysis", file_path, "pdftools")

    summary["indicators"] = indicators
    summary["risk_assessment"] = risk
    summary["javascript"] = javascript if extract_javascript else []
    summary["urls"] = []
    summary["embedded_files"] = []

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "analyze_pdf", params, summary, "pdf.analysis", elapsed)
