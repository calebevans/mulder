"""Chainsaw's detections must reach the case DB, not just their count.

``run_chainsaw`` indexed only a summary::

    Chainsaw hunt analysis of /evidence
    Total findings: 3
      high: 2

The detections themselves -- rule names, computers, event IDs, MITRE
techniques -- were passed to ``tool_response`` but never to
``extract_and_index``.  With ``source`` set, ``tool_response`` returns a compact
preview, so a later ``search()`` over the case could not find a single Chainsaw
detection by rule name.

There was a second half to the same defect: the parsers truncated their record
lists (``detections[:500]``, ``srum_entries[:500]``, ``timeline_entries[:1000]``)
*before* the caller ever saw them, so on a busy host the records past the cap
could not be indexed even in principle.  The cap belongs on the response, not on
the index.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.chainsaw import run_chainsaw


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"ElfFile\x00")
    return tmp_path


def _run(evidence: Path, mode: str, payload: list[dict[str, Any]]) -> tuple[str, Any]:
    """Run *mode* with Chainsaw writing *payload*; return (indexed text, response)."""
    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {}

    def _write(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        out = Path(cmd[cmd.index("--output") + 1])
        out.write_text(json.dumps(payload))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.subprocess.run", side_effect=_write),
        patch("mulder.server.tools.chainsaw.extract_and_index", side_effect=_record),
    ):
        response = run_chainsaw.__wrapped__(  # type: ignore[attr-defined]
            str(evidence), mode=mode
        )

    assert indexed, "nothing was indexed at all"
    return indexed[0], response


_DETECTION = {
    "timestamp": "2024-03-01T10:00:00Z",
    "name": "Suspicious PowerShell Encoded Command",
    "level": "high",
    "computer": "WORKSTATION-07",
    "channel": "Security",
    "event_id": 4688,
    "rule_id": "abc-123-sigma",
    "tags": ["attack.execution", "attack.t1059"],
}


def test_the_detection_itself_is_indexed_not_only_its_count(evidence: Path) -> None:
    """The searchable text must carry what an analyst would search for."""
    text, _response = _run(evidence, "hunt", [_DETECTION])

    assert "Suspicious PowerShell Encoded Command" in text, (
        f"the rule name never reached the case DB; indexed text was:\n{text}"
    )
    assert "WORKSTATION-07" in text
    assert "4688" in text
    assert "abc-123-sigma" in text
    assert "attack.t1059" in text


def test_the_summary_counts_are_still_indexed(evidence: Path) -> None:
    """Narrowness: the existing summary lines are kept, not replaced."""
    text, _response = _run(evidence, "hunt", [_DETECTION])

    assert "Total findings: 1" in text
    assert "Chainsaw hunt analysis of" in text


def test_every_detection_is_indexed_past_the_response_cap(evidence: Path) -> None:
    """The second half of the defect: records were cut before indexing.

    The parsers truncated at 500 before the caller saw them, so detection 501
    could never be indexed.  The cap belongs on the response.
    """
    payload = [
        {**_DETECTION, "name": f"Rule number {i}", "computer": f"HOST-{i}"} for i in range(600)
    ]

    text, response = _run(evidence, "hunt", payload)

    assert "Rule number 599" in text, "detections past the 500 cap were never indexed"
    assert "HOST-599" in text
    # the response stays bounded
    detections = response["results"]["detections"] if "results" in response else None
    if detections is None:  # compact preview envelope
        assert response["status"] == "success"
    else:
        assert len(detections) == 500


def test_the_response_is_still_capped(evidence: Path) -> None:
    """Indexing everything must not mean returning everything to the agent."""
    payload = [
        {**_DETECTION, "name": f"Rule number {i}", "computer": f"HOST-{i}"} for i in range(600)
    ]

    indexed: list[str] = []

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(raw)
        return {}

    def _write(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        out = Path(cmd[cmd.index("--output") + 1])
        out.write_text(json.dumps(payload))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    captured: dict[str, Any] = {}

    def _tool_response(
        tc_id: str,
        tool_name: str,
        params: Any,
        results: Any,
        source: Any = None,
        elapsed_ms: float = 0,
    ) -> dict[str, object]:
        captured["results"] = results
        return {"status": "success"}

    with (
        patch("mulder.server.tools.chainsaw._chainsaw_binary", return_value="/usr/bin/chainsaw"),
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.chainsaw.subprocess.run", side_effect=_write),
        patch("mulder.server.tools.chainsaw.extract_and_index", side_effect=_record),
        patch("mulder.server.tools.chainsaw.tool_response", side_effect=_tool_response),
    ):
        run_chainsaw.__wrapped__(str(evidence), mode="hunt")  # type: ignore[attr-defined]

    results = captured["results"]
    assert len(results["detections"]) == 500, "the response must stay bounded"
    assert results["detections_truncated"] is True
    assert results["total_findings"] == 600, "the true count must survive the cap"
    assert "Rule number 599" in indexed[0], "but everything must still be indexed"


def test_timeline_entries_are_indexed(evidence: Path) -> None:
    """The same defect applied to timeline mode, which indexed only a count."""
    payload = [
        {"timestamp": "2024-03-01T10:00:00Z", "event": "svchost.exe spawned cmd.exe"},
        {"timestamp": "2024-03-01T10:00:01Z", "event": "cmd.exe spawned whoami.exe"},
    ]

    text, _response = _run(evidence, "timeline", payload)

    assert "svchost.exe spawned cmd.exe" in text
    assert "whoami.exe" in text
    assert "Timeline entries: 2" in text


def test_a_quiet_host_still_indexes_its_summary(evidence: Path) -> None:
    """Narrowness: zero detections is a real result and stays indexed."""
    text, response = _run(evidence, "hunt", [])

    assert "Total findings: 0" in text
    assert response["status"] == "success"
