"""Detections have to reach the case database, not just their count.

``extract_and_index`` stores exactly the text it is handed. Chainsaw,
Zircolite and both LEAPP wrappers handed it a summary::

    Chainsaw hunt analysis of /evidence/evtx
    Total findings: 412
      critical: 3

Nothing else. Not one rule name, host, sigma id or command line, so the FTS
index -- the thing every downstream correlation, the report and the analyst's
own searches read from -- could not answer a single question about what the
tool had found. The counts came back in the tool response and were then
dropped on the floor when the session ended.

Each test below asserts on the text actually passed to ``extract_and_index``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

from mulder.server.extract_helpers import format_records

# A hunt result in the shape chainsaw 2.16.0 writes with --json.
CHAINSAW_HUNT = [
    {
        "timestamp": "2024-03-11T09:14:02Z",
        "name": "Suspicious PowerShell Encoded Command",
        "level": "critical",
        "source": "Security",
        "event_id": 4688,
        "computer": "WKSTN-042.corp.local",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "sigma_id": "ac7102e2-71b4-4d84-8bbf-e0e35a7d8d76",
        "tags": ["attack.execution", "attack.t1059.001"],
        "event_data": {
            "CommandLine": "powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAA==",
            "ParentImage": "C:\\\\Windows\\\\System32\\\\winword.exe",
        },
    },
    {
        "timestamp": "2024-03-11T09:16:44Z",
        "name": "Rare Service Installation",
        "level": "high",
        "source": "System",
        "event_id": 7045,
        "computer": "DC01.corp.local",
        "channel": "System",
        "sigma_id": "5a604aa7-7f4d-4e5e-b0d3-1f4a02b8f9a1",
        "tags": ["attack.persistence", "attack.t1543.003"],
        "event_data": {"ServiceName": "UpdaterSvc", "ImagePath": "C:\\\\Users\\\\Public\\\\u.exe"},
    },
    {
        "timestamp": "2024-03-11T11:02:10Z",
        "name": "Logon From Unusual Source",
        "level": "medium",
        "source": "Security",
        "event_id": 4624,
        "computer": "WKSTN-042.corp.local",
        "channel": "Security",
        "sigma_id": "8f1c2b31-1a2e-4b9d-a0c4-2c9f1d5a6e77",
        "tags": ["attack.lateral-movement"],
        "event_data": {"IpAddress": "10.4.19.203", "TargetUserName": "svc_backup"},
    },
]

ZIRCOLITE_HITS = [
    {
        "timestamp": "2024-03-11T09:14:02",
        "rule_title": "Encoded PowerShell Command Line",
        "rule_id": "ac7102e2-71b4-4d84-8bbf-e0e35a7d8d76",
        "rule_level": "critical",
        "rule_description": "Detects base64 encoded PowerShell command lines.",
        "rule_mitre": [{"tactic": "execution", "technique": "T1059.001"}],
        "matched_fields": {"CommandLine": "powershell.exe -enc SQBFAFgA"},
        "count": 4,
    },
    {
        "timestamp": "2024-03-11T09:16:44",
        "rule_title": "Service Installed From User Writable Path",
        "rule_id": "5a604aa7-7f4d-4e5e-b0d3-1f4a02b8f9a1",
        "rule_level": "high",
        "rule_description": "Detects services whose image sits under C:\\\\Users.",
        "rule_mitre": [{"tactic": "persistence", "technique": "T1543.003"}],
        "matched_fields": {"ImagePath": "C:\\\\Users\\\\Public\\\\u.exe"},
        "count": 1,
    },
]


def _completed(returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr="")


class _Capture:
    """Stands in for ``extract_and_index`` and keeps the text it was given."""

    def __init__(self) -> None:
        self.raw_output = ""

    def __call__(self, raw_output: str, *args: object, **kwargs: object) -> dict[str, object]:
        self.raw_output = raw_output if isinstance(raw_output, str) else str(raw_output)
        return {"line_count": len(self.raw_output.splitlines())}


class _CaptureSummary:
    """Wraps ``tool_response`` and keeps the results dict it was given.

    ``tool_response`` returns only a preview once the output has been indexed,
    so the record lists are not visible in the response itself.
    """

    def __init__(self, real: Any) -> None:
        self._real = real
        self.results: dict[str, Any] = {}

    def __call__(self, tc_id: str, tool_name: str, params: Any, results: Any, *a: object) -> Any:
        if isinstance(results, dict):
            self.results = dict(results)
        return self._real(tc_id, tool_name, params, results, *a)


class TestFormatRecords:
    def test_one_line_per_record(self) -> None:
        lines = format_records([{"a": 1}, {"a": 2}, {"a": 3}])
        assert lines == ["1", "2", "3"]

    def test_fields_fix_the_column_order(self) -> None:
        lines = format_records([{"b": "x", "a": "y"}], ["a", "b"])
        assert lines == ["y\tx"]

    def test_a_missing_field_is_an_empty_column(self) -> None:
        assert format_records([{"a": "y"}], ["a", "b", "c"]) == ["y\t\t"]

    def test_nested_values_stay_searchable(self) -> None:
        line = format_records([{"event_data": {"CommandLine": "whoami /all"}}])[0]
        assert "whoami /all" in line

    def test_embedded_newlines_cannot_split_a_record(self) -> None:
        line = format_records([{"a": "one\ntwo\r\nthree", "b": "z"}])[0]
        assert "\n" not in line
        assert "\r" not in line
        assert line.count("\t") == 1

    def test_embedded_tabs_do_not_shift_columns(self) -> None:
        line = format_records([{"a": "x\ty", "b": "z"}], ["a", "b"])[0]
        assert line.count("\t") == 1

    def test_one_huge_field_cannot_fill_a_window(self) -> None:
        line = format_records([{"a": "x" * 100_000}])[0]
        assert len(line) < 4096

    def test_a_realistic_event_document_keeps_its_late_fields(self) -> None:
        """Chainsaw falls back to the whole event document for `event_data`.

        That is 2-4 KB of JSON, and the fields an analyst searches for are not
        the alphabetically first ones. A tight per-field cap would keep
        `CommandLine` (which sorts early) and silently drop the rest.
        """
        document = {
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "CommandLine": "powershell.exe -enc SQBFAFgA",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentCommandLine": "C:\\Program Files\\Microsoft Office\\winword.exe /n",
            "TargetUserName": "svc_backup",
            "UtcTime": "2024-03-11 09:14:02.113",
            "_padding": "y" * 800,
        }
        line = format_records([{"event_data": document}])[0]
        assert "ParentCommandLine" in line
        assert "svc_backup" in line
        assert "winword.exe" in line

    def test_none_is_empty(self) -> None:
        assert format_records([{"a": None, "b": "z"}], ["a", "b"]) == ["\tz"]

    def test_no_records(self) -> None:
        assert format_records([]) == []


class TestChainsawIndexesDetections:
    @staticmethod
    def _run(
        tmp_path: Path, hits: list[dict[str, Any]], mode: str = "hunt"
    ) -> tuple[dict[str, object], str]:
        from mulder.server.tools import chainsaw as cs

        binary = tmp_path / "chainsaw"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        mapping = tmp_path / "sigma-event-logs-all.yml"
        mapping.write_text("")
        evidence = tmp_path / "evtx"
        evidence.mkdir()
        capture = _Capture()
        summary = _CaptureSummary(cs.tool_response)

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            Path(cmd[cmd.index("--output") + 1]).write_text(json.dumps(hits))
            return _completed()

        with (
            patch.object(cs, "sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=str(binary)),
            patch.object(cs, "_default_chainsaw_mapping", return_value=mapping),
            patch.object(cs, "extract_and_index", capture),
            patch.object(cs, "tool_response", summary),
            patch.object(cs.subprocess, "run", side_effect=fake_run),
        ):
            cs.run_chainsaw.__wrapped__(str(evidence), mode=mode)  # type: ignore[attr-defined]
        return summary.results, capture.raw_output

    def test_every_rule_name_is_indexed(self, tmp_path: Path) -> None:
        _, indexed = self._run(tmp_path, CHAINSAW_HUNT)
        for hit in CHAINSAW_HUNT:
            assert hit["name"] in indexed

    def test_the_command_line_is_indexed(self, tmp_path: Path) -> None:
        """The single most searched-for field in an intrusion investigation."""
        _, indexed = self._run(tmp_path, CHAINSAW_HUNT)
        assert "powershell.exe -enc SQBFAFgA" in indexed

    def test_hosts_and_sigma_ids_are_indexed(self, tmp_path: Path) -> None:
        _, indexed = self._run(tmp_path, CHAINSAW_HUNT)
        assert "DC01.corp.local" in indexed
        assert "ac7102e2-71b4-4d84-8bbf-e0e35a7d8d76" in indexed

    def test_each_detection_is_one_whole_line(self, tmp_path: Path) -> None:
        _, indexed = self._run(tmp_path, CHAINSAW_HUNT)
        detection_lines = [ln for ln in indexed.splitlines() if ln.startswith("2024-03-11T")]
        assert len(detection_lines) == len(CHAINSAW_HUNT)
        for line in detection_lines:
            assert line.count("\t") == 9

    def test_the_summary_counts_are_still_there(self, tmp_path: Path) -> None:
        _, indexed = self._run(tmp_path, CHAINSAW_HUNT)
        assert "Total findings: 3" in indexed
        assert "  critical: 1" in indexed

    def test_the_index_is_not_capped_at_the_response_limit(self, tmp_path: Path) -> None:
        """The response carries 500 detections; the index must carry all 700."""
        hits = [dict(CHAINSAW_HUNT[0], sigma_id=f"rule-{i:04d}") for i in range(700)]
        result, indexed = self._run(tmp_path, hits)
        assert "rule-0699" in indexed
        assert len(result["detections"]) == 500  # type: ignore[arg-type]
        assert result["total_findings"] == 700

    def test_timeline_mode_indexes_its_entries(self, tmp_path: Path) -> None:
        entries = [{"timestamp": "2024-03-11T09:14:02Z", "detail": "svchost.exe spawned cmd.exe"}]
        _, indexed = self._run(tmp_path, entries, mode="timeline")
        assert "svchost.exe spawned cmd.exe" in indexed


class TestZircoliteIndexesDetections:
    @staticmethod
    def _run(tmp_path: Path, hits: list[dict[str, Any]]) -> tuple[dict[str, object], str]:
        from mulder.server.tools import zircolite as zc

        events = tmp_path / "events"
        events.mkdir()
        script = tmp_path / "zircolite.py"
        script.write_text("")
        ruleset = tmp_path / "rules.json"
        ruleset.write_text("[]")
        capture = _Capture()
        summary = _CaptureSummary(zc.tool_response)

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            Path(cmd[cmd.index("--outfile") + 1]).write_text(json.dumps(hits))
            return _completed()

        with (
            patch.object(zc, "sources_already_indexed", return_value=[]),
            patch.object(zc, "_zircolite_script", return_value=script),
            patch.object(zc, "_missing_zircolite_modules", return_value=[]),
            patch.object(zc, "extract_and_index", capture),
            patch.object(zc, "tool_response", summary),
            patch.object(zc.subprocess, "run", side_effect=fake_run),
        ):
            zc.run_zircolite.__wrapped__(  # type: ignore[attr-defined]
                str(events), ruleset_path=str(ruleset)
            )
        return summary.results, capture.raw_output

    def test_rule_titles_and_matched_fields_are_indexed(self, tmp_path: Path) -> None:
        _, indexed = self._run(tmp_path, ZIRCOLITE_HITS)
        assert "Encoded PowerShell Command Line" in indexed
        assert "Service Installed From User Writable Path" in indexed
        assert "powershell.exe -enc SQBFAFgA" in indexed

    def test_each_detection_is_one_whole_line(self, tmp_path: Path) -> None:
        _, indexed = self._run(tmp_path, ZIRCOLITE_HITS)
        lines = [ln for ln in indexed.splitlines() if ln.startswith("2024-03-11T")]
        assert len(lines) == len(ZIRCOLITE_HITS)
        for line in lines:
            assert line.count("\t") == 7

    def test_the_index_is_not_capped_at_the_response_limit(self, tmp_path: Path) -> None:
        hits = [dict(ZIRCOLITE_HITS[0], rule_id=f"rule-{i:04d}") for i in range(700)]
        result, indexed = self._run(tmp_path, hits)
        assert "rule-0699" in indexed
        assert len(result["detections"]) == 500  # type: ignore[arg-type]
        assert result["total_detections"] == 700


class TestLeappIndexesRows:
    @staticmethod
    def _run(tmp_path: Path, tsv: dict[str, str]) -> tuple[dict[str, object], str]:
        from mulder.server.tools import phone as ph

        extraction = tmp_path / "extraction"
        extraction.mkdir()
        script = tmp_path / "aleapp.py"
        script.write_text("")
        capture = _Capture()
        summary = _CaptureSummary(ph.tool_response)

        def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            out = Path(cmd[cmd.index("-o") + 1])
            tsv_dir = out / "tsv"
            tsv_dir.mkdir(parents=True, exist_ok=True)
            for name, body in tsv.items():
                (tsv_dir / f"{name}.tsv").write_text(body)
            return _completed()

        with (
            patch.object(ph, "_aleapp_script", return_value=str(script)),
            patch.object(ph, "_find_leapp_cmd", return_value=["aleapp"]),
            patch.object(ph, "extract_and_index", capture),
            patch.object(ph, "tool_response", summary),
            patch.object(ph.subprocess, "run", side_effect=fake_run),
        ):
            ph.run_aleapp.__wrapped__(str(extraction))  # type: ignore[attr-defined]
        return summary.results, capture.raw_output

    TSV = {
        "sms_messages": (
            "Timestamp\tFrom\tTo\tBody\n"
            "2024-03-09 21:04:11\t+32470112233\t+32470445566\tmeet at the usual place\n"
            "2024-03-09 21:07:52\t+32470445566\t+32470112233\tbring the drive\n"
        )
    }

    def test_message_bodies_are_indexed(self, tmp_path: Path) -> None:
        _, indexed = self._run(tmp_path, self.TSV)
        assert "meet at the usual place" in indexed
        assert "bring the drive" in indexed

    def test_phone_numbers_are_indexed(self, tmp_path: Path) -> None:
        _, indexed = self._run(tmp_path, self.TSV)
        assert "+32470112233" in indexed

    def test_the_artifact_type_labels_its_rows(self, tmp_path: Path) -> None:
        _, indexed = self._run(tmp_path, self.TSV)
        assert "sms_messages" in indexed
        assert "Timestamp\tFrom\tTo\tBody" in indexed

    def test_the_index_is_not_capped_at_the_response_limit(self, tmp_path: Path) -> None:
        rows = "\n".join(f"2024-03-09 21:04:11\tmsg-{i:04d}" for i in range(150))
        _, indexed = self._run(tmp_path, {"sms_messages": f"Timestamp\tBody\n{rows}\n"})
        assert "msg-0149" in indexed

    def test_the_response_stays_bounded(self, tmp_path: Path) -> None:
        rows = "\n".join(f"2024-03-09 21:04:11\tmsg-{i:04d}" for i in range(150))
        result, _ = self._run(tmp_path, {"sms_messages": f"Timestamp\tBody\n{rows}\n"})
        artifacts = result["artifacts"]
        assert isinstance(artifacts, list)
        assert len(artifacts[0]["data"]) == 100
        assert artifacts[0]["record_count"] == 150
