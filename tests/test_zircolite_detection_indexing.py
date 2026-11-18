"""Zircolite must index the detections, not just how many there were.

``run_zircolite`` registers its output under the source name
``zircolite.detections``, but handed ``extract_and_index`` only a header --
"Total detections: 412", the per-level counts and a MITRE tactic roll-up. Not
one rule title, rule id, timestamp or matched field ever reached the case
database, so ``search(query, source="zircolite.detections")`` could not answer
the questions the tool was run to answer.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.helpers import tool_response as real_tool_response
from mulder.server.tools.zircolite import run_zircolite

# One rule object in the shape Zircolite 2.20.0 writes: the rule's metadata and
# every event it matched.
_MATCH = {
    "row_id": 1,
    "timestamp": "2024-03-11T09:15:22",
    "process.executable": "/bin/sh",
    "process.command_line": "sh -c echo cGF5bG9hZA== | base64 -d | sh",
    "user.name": "svc_backup",
}
_DETECTION = {
    "title": "Suspicious Base64 Encoded Shell Command",
    "id": "b7c4f9a1-2e3d-4c5b-8a90-1122334455ff",
    "description": "Detects a base64-encoded payload passed to /bin/sh",
    "sigmafile": "",
    "sigma": ["SELECT * FROM logs"],
    "rule_level": "critical",
    "tags": ["attack.execution", "attack.t1059.004"],
    "count": 1,
    "matches": [_MATCH],
}


@pytest.fixture
def evidence(tmp_path: Path) -> dict[str, Path]:
    script = tmp_path / "zircolite.py"
    script.write_text("")
    events = tmp_path / "audit.log"
    events.write_text("type=EXECVE msg=audit(1710148522.000:1): argc=1\n")
    ruleset = tmp_path / "rules"
    ruleset.mkdir()
    return {"script": script, "events": events, "ruleset": ruleset}


def _run(evidence: dict[str, Path], raw: list[dict[str, Any]]) -> tuple[Any, str]:
    """Run the tool over *raw* Zircolite output; return (response, indexed text).

    ``tool_response`` collapses the results to a preview when a source is set,
    so tests that need the structured results read ``_results`` on the returned
    response, captured before that collapse.
    """
    indexed: list[str] = []
    captured: list[dict[str, object]] = []

    def _record(text: str, *args: object, **kwargs: object) -> dict[str, object]:
        indexed.append(text)
        return {}

    def _write(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        Path(cmd[cmd.index("--outfile") + 1]).write_text(json.dumps(raw))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    def _capture(*args: Any, **kwargs: Any) -> dict[str, object]:
        captured.append(args[3])
        return real_tool_response(*args, **kwargs)

    with (
        patch("mulder.server.tools.zircolite.sources_already_indexed", return_value=[]),
        patch(
            "mulder.server.tools.zircolite.importlib.util.find_spec",
            return_value=MagicMock(),
        ),
        patch(
            "mulder.server.tools.zircolite._zircolite_script",
            return_value=evidence["script"],
        ),
        patch("mulder.server.tools.zircolite.subprocess.run", side_effect=_write),
        patch("mulder.server.tools.zircolite.extract_and_index", side_effect=_record),
        patch("mulder.server.tools.zircolite.tool_response", side_effect=_capture),
    ):
        result = run_zircolite.__wrapped__(  # type: ignore[attr-defined]
            str(evidence["events"]),
            ruleset_path=str(evidence["ruleset"]),
            sigma_level_filter=None,
        )
    assert indexed, "extract_and_index was never called"
    assert captured, "tool_response was never called"
    result["_results"] = captured[0]
    return result, indexed[0]


def test_the_detection_content_reaches_the_index(evidence: dict[str, Path]) -> None:
    """Every field an analyst would search for must be in the indexed text."""
    _result, text = _run(evidence, [_DETECTION])

    assert "Suspicious Base64 Encoded Shell Command" in text
    assert "b7c4f9a1-2e3d-4c5b-8a90-1122334455ff" in text
    assert "2024-03-11T09:15:22" in text
    assert "T1059.004" in text
    # The matched event is what proves the detection; it must be searchable.
    assert "svc_backup" in text
    assert "base64 -d" in text


def test_the_header_summary_is_still_indexed(evidence: dict[str, Path]) -> None:
    """Pins the fix's narrowness: the counts are kept, not replaced."""
    _result, text = _run(evidence, [_DETECTION])

    assert "Total detections: 1" in text
    assert "critical: 1" in text


def test_one_line_per_detection_so_none_is_split_across_windows(
    evidence: dict[str, Path],
) -> None:
    """The window builder splits on line boundaries.

    A detection spread over several lines could be cut in half between two
    index windows, and the per-window timestamp would come from whichever
    fragment happened to carry one.
    """
    raw = [dict(_DETECTION, id=f"rule-{i}") for i in range(5)]

    _result, text = _run(evidence, raw)

    detection_lines = [line for line in text.splitlines() if "\t" in line]
    assert len(detection_lines) == 5
    for i, line in enumerate(detection_lines):
        assert f"rule-{i}" in line
        assert line.startswith("2024-03-11T09:15:22"), "timestamp must lead each line"


def test_a_newline_inside_a_matched_field_cannot_break_the_line(
    evidence: dict[str, Path],
) -> None:
    """A multi-line command line must not become several index records.

    A nested value is JSON-encoded, which already escapes the newline; a
    top-level string field is stripped of newlines directly. Both paths must
    yield exactly one line.
    """
    raw = [
        dict(
            _DETECTION,
            matches=[dict(_MATCH, cmd={"argv": "line one\nline two"})],
            description="desc one\ndesc two",
        )
    ]

    _result, text = _run(evidence, raw)

    detection_lines = [line for line in text.splitlines() if "\t" in line]
    assert len(detection_lines) == 1
    assert "desc one desc two" in detection_lines[0]
    assert "line one" in detection_lines[0]
    assert "line two" in detection_lines[0]


def test_every_detection_is_indexed_even_past_the_response_cap(
    evidence: dict[str, Path],
) -> None:
    """The response is bounded at 500; the index must not be.

    Truncating before indexing would silently drop detection 501 onward from
    the case database, with nothing to say they existed.
    """
    raw = [dict(_DETECTION, id=f"rule-{i}") for i in range(600)]

    result, text = _run(evidence, raw)

    assert "rule-599" in text, "detections past the response cap were not indexed"
    assert result["status"] == "success"


def test_the_response_stays_bounded(evidence: dict[str, Path]) -> None:
    """Pins the other half: indexing everything must not unbound the response."""
    raw = [dict(_DETECTION, id=f"rule-{i}") for i in range(600)]

    result, _text = _run(evidence, raw)

    results = result["_results"]
    assert results["total_detections"] == 600
    assert len(results["detections"]) == 500


def test_a_quiet_log_indexes_a_header_and_no_detection_lines(
    evidence: dict[str, Path],
) -> None:
    """No detections is still a real answer, and must index as one."""
    result, text = _run(evidence, [])

    assert "Total detections: 0" in text
    assert [line for line in text.splitlines() if "\t" in line] == []
    assert result["status"] == "success"


def test_each_matched_event_is_its_own_detection(evidence: dict[str, Path]) -> None:
    """A rule that matched three events is three detections, each with its own time."""
    times = ["2024-03-11T09:15:22", "2024-03-11T09:16:00", "2024-03-11T09:17:30"]
    raw = [dict(_DETECTION, count=3, matches=[dict(_MATCH, timestamp=t) for t in times])]

    result, text = _run(evidence, raw)

    assert result["_results"]["total_detections"] == 3
    lines = [line for line in text.splitlines() if "\t" in line]
    assert [line.split("\t")[0] for line in lines] == times


def test_the_empty_object_zircolite_pads_its_output_with_is_not_a_detection(
    evidence: dict[str, Path],
) -> None:
    result, _text = _run(evidence, [_DETECTION, {}])

    results = result["_results"]
    assert results["total_detections"] == 1
    assert results["level_counts"] == {"critical": 1}
    assert results["mitre_coverage"] == {"tactics": ["execution"], "techniques": ["T1059.004"]}


def test_coverage_describes_reported_detections_and_only_real_tactics(
    evidence: dict[str, Path],
) -> None:
    """Sigma tags also name groups and software; a filtered-out rule adds nothing."""
    tagged = dict(
        _DETECTION, tags=["attack.execution", "attack.t1059.004", "attack.g0032", "attack.s0002"]
    )
    hidden = dict(_DETECTION, rule_level="low", tags=["attack.collection", "attack.t1123"])
    from mulder.server.tools.zircolite import _parse_zircolite_output

    results = evidence["events"].with_name("results.json")
    results.write_text(json.dumps([tagged, hidden, {}]))
    parsed = _parse_zircolite_output(results, "x", "auditd", "medium")

    assert parsed["mitre_coverage"] == {"tactics": ["execution"], "techniques": ["T1059.004"]}
    # The filter's effect stays visible in the counts.
    assert parsed["level_counts"] == {"critical": 1, "low": 1}
    assert parsed["total_detections"] == 1


@pytest.mark.parametrize(
    ("match", "expected"),
    [
        ({"timestamp": "2024-03-11 09:15:22"}, "2024-03-11 09:15:22"),
        ({"UtcTime": "2023-11-14 22:13:20.123"}, "2023-11-14 22:13:20.123"),  # Sysmon
        ({"timestamp": 1731800000000}, "2024-11-16T23:33:20Z"),  # GitHub: epoch ms
        ({"timestamp": 1731800000}, "2024-11-16T23:33:20Z"),
        ({}, ""),
    ],
)
def test_the_event_time_is_found_and_epochs_become_iso(
    evidence: dict[str, Path], match: dict[str, Any], expected: str
) -> None:
    _result, text = _run(evidence, [dict(_DETECTION, matches=[match])])

    (line,) = [line for line in text.splitlines() if "\t" in line]
    assert line.split("\t")[0] == expected
