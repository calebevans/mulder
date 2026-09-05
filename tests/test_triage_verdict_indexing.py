"""The triage analysis existed only inside the function that computed it.

``triage_binary`` derives ``file_info``, ``timestamps``, ``packing_indicators``,
``suspicious_imports`` and ``triage_verdict``, attaches them to a dict, and
hands that to ``tool_response(..., source="binary.triage", ...)``. Because a
source is given, `tool_response` returns a compact envelope and replaces the
dict with ``json.dumps(results)[:500]`` -- and JSON preserves insertion order,
so the preview is consumed by ``extract_and_index``'s own keys plus
``file_info`` and part of ``timestamps``. The packing indicators, the
suspicious imports and the verdict are cut off.

The fallback would be the case index, but only the raw rabin2 JSON was
indexed. ``search(source="binary.triage")`` returned register dumps and string
tables containing no verdict. So the analysis reached nobody: the agent saw a
truncated preview, and an analyst searching the case for ``UPX`` found the
section name but never the tool's conclusion about it.

The derived findings are now indexed ahead of the raw output, which is both
what makes them searchable and what puts them inside the preview window.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import mulder.server.tools.binary as binary
from mulder.server.tools.binary import _triage_findings_text

INFO_JSON = (
    '{"info": {"arch": "x86", "bits": 64, "bintype": "pe", "os": "windows",'
    ' "compiled": "1741772463", "compiler": "msvc"}}'
)
IMPORTS_JSON = (
    '{"imports": [{"name": "VirtualAllocEx"}, {"name": "WriteProcessMemory"},'
    ' {"name": "CreateRemoteThread"}]}'
)
SECTIONS_JSON = (
    '{"sections": [{"name": "UPX0", "vsize": 4096, "size": 0, "perm": "-rwx"},'
    ' {"name": "UPX1", "vsize": 4096, "size": 2048, "perm": "-r-x"}]}'
)


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["rabin2"], returncode, stdout, stderr)


def _run_triage(tmp_path: Path) -> tuple[str, dict[str, object]]:
    """Drive triage_binary, returning (indexed_text, results-passed-to-response)."""
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 64)

    indexed: list[str] = []
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        flag = cmd[1] if len(cmd) > 1 else ""
        return {
            "-Ij": _completed(stdout=INFO_JSON),
            "-ij": _completed(stdout=IMPORTS_JSON),
            "-Sj": _completed(stdout=SECTIONS_JSON),
        }.get(flag, _completed(stdout="{}"))

    def fake_index(text: str, *a: object, **k: object) -> dict[str, object]:
        indexed.append(text)
        return {"source_name": "binary.triage", "windows_indexed": 1, "line_count": 10}

    def capture_response(
        tc_id: str, tool_name: str, params: object, results: object, *a: object
    ) -> dict[str, object]:
        if isinstance(results, dict):
            captured.update(results)
        return {"status": "success"}

    with (
        patch("mulder.server.tools.binary.subprocess.run", side_effect=fake_run),
        patch.object(binary, "require_binary", return_value="/usr/bin/rabin2"),
        patch.object(binary, "extract_and_index", side_effect=fake_index),
        patch.object(binary, "tool_response", capture_response),
    ):
        binary.triage_binary.__wrapped__(  # type: ignore[attr-defined]
            "case-1", str(target), depth="standard"
        )

    assert indexed, "extract_and_index was never called"
    return indexed[0], captured


class TestTheVerdictIsRecoverable:
    def test_the_verdict_is_in_the_indexed_text(self, tmp_path: Path) -> None:
        text, results = _run_triage(tmp_path)
        classification = str(results["triage_verdict"]["classification"])  # type: ignore[index]
        assert classification in text

    def test_the_packing_indicators_are_searchable(self, tmp_path: Path) -> None:
        """An analyst searching the case for UPX must reach the conclusion."""
        text, results = _run_triage(tmp_path)
        assert results["packing_indicators"], "the fixture must trip the packing check"
        for indicator in results["packing_indicators"]:  # type: ignore[union-attr]
            assert str(indicator) in text

    def test_the_suspicious_imports_are_searchable(self, tmp_path: Path) -> None:
        text, _ = _run_triage(tmp_path)
        assert "VirtualAllocEx" in text
        assert "CreateRemoteThread" in text

    def test_the_raw_output_is_still_indexed(self, tmp_path: Path) -> None:
        """The findings are added to the raw output, not substituted for it."""
        text, _ = _run_triage(tmp_path)
        assert "UPX0" in text
        assert '"bintype"' in text


class TestTheFindingsSurviveThePreview:
    def test_the_verdict_is_inside_the_first_500_characters(self, tmp_path: Path) -> None:
        """`tool_response` cuts the preview at 500 characters.

        Putting the derived findings first is what makes them visible to an
        agent reading the response, rather than only to a later search.
        """
        text, results = _run_triage(tmp_path)
        classification = str(results["triage_verdict"]["classification"])  # type: ignore[index]
        assert classification in text[:500]


class TestTheRenderedFindings:
    def test_it_names_the_classification_and_confidence(self) -> None:
        rendered = _triage_findings_text(
            {"arch": "x86", "bits": 64, "os": "windows"},
            {"parsed_utc": "2025-03-12T09:41:03+00:00", "validity": "valid"},
            [],
            {},
            {"classification": "benign_indicators", "confidence": "medium", "reasons": []},
        )
        assert "benign_indicators" in rendered
        assert "confidence medium" in rendered

    def test_it_names_every_suspicious_api(self) -> None:
        rendered = _triage_findings_text(
            {},
            {"validity": "valid"},
            ["high-entropy section UPX1"],
            {"process_injection": ["VirtualAllocEx", "CreateRemoteThread"]},
            {"classification": "malicious_indicators", "confidence": "high", "reasons": ["x"]},
        )
        assert "VirtualAllocEx" in rendered
        assert "CreateRemoteThread" in rendered
        assert "high-entropy section UPX1" in rendered
        assert "Reason: x" in rendered

    def test_a_missing_timestamp_is_rendered_not_dropped(self) -> None:
        rendered = _triage_findings_text(
            {}, {"parsed_utc": None, "validity": "suspicious"}, [], {}, {}
        )
        assert "Compilation timestamp: none [suspicious]" in rendered
