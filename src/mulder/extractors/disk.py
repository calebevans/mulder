"""EVTX parsing utilities for evidence found in disk images.

Privileged image mounting deliberately lives behind
``mulder.execution.privileged.MountBroker`` and is never performed by this
in-process parser module.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger(__name__)
_EVTX_EXTS = frozenset({".evtx"})


def _parse_evtx_file(
    evtx_path: Path,
    event_ids: set[int] | None = None,
) -> tuple[str, str]:
    """Parse an EVTX file and return ``(channel_name, text_output)``.

    Each record is formatted as ``timestamp | EventID | Channel | xml``.
    When ``event_ids`` is supplied, records outside that set are omitted.
    """
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        logger.warning("python-evtx not installed, skipping %s", evtx_path)
        return "", ""

    channel = _channel_from_path(evtx_path)
    lines: list[str] = []
    try:
        with Evtx(str(evtx_path)) as evtx:
            for record in evtx.records():
                try:
                    xml_str = record.xml()
                    event_id = _extract_event_id(xml_str)
                    if event_ids is not None and int(event_id) not in event_ids:
                        continue
                    timestamp = str(record.timestamp())
                    one_line = xml_str.replace("\n", " ").replace("\r", "")
                    lines.append(f"{timestamp} | {event_id} | {channel} | {one_line}")
                except Exception:
                    logger.debug("Skipping malformed record in %s", evtx_path, exc_info=True)
    except Exception:
        logger.warning("Failed to parse EVTX file %s", evtx_path, exc_info=True)
        return channel, ""
    return channel, "\n".join(lines)


def _channel_from_path(evtx_path: Path) -> str:
    """Derive a normalized channel name from an EVTX filename."""
    stem = evtx_path.stem.lower()
    stem = stem.replace("microsoft-windows-", "").replace("%4", "-")
    stem = re.sub(r"[^a-z0-9\-]", "-", stem)
    stem = re.sub(r"-+", "-", stem).strip("-")
    return stem or "unknown"


def _extract_event_id(xml_str: str) -> str:
    """Pull the EventID from an EVTX record's XML."""
    try:
        root = ET.fromstring(xml_str)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        eid_elem = root.find(".//e:EventID", ns)
        if eid_elem is not None and eid_elem.text:
            return eid_elem.text
    except ET.ParseError:
        pass
    return "?"
