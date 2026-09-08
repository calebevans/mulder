"""The triage analysis must be indexed, not only the raw rabin2 dump.

``triage_binary`` computes a verdict, packing indicators and a categorised list
of suspicious imports, then indexed ``"\\n\\n".join(raw_parts)`` -- the raw
rabin2 JSON alone. Because ``tool_response`` replaces the results dict with a
short preview once a source is given, none of the derived analysis reached the
caller in the response either. An analyst searching the case for ``UPX`` or
``VirtualAllocEx`` could not find the tool's own conclusion about the binary:
it existed only inside the function that computed it.

These tests drive ``triage_binary`` end to end with rabin2 replaced, and assert
on the text handed to ``extract_and_index`` -- the bytes that actually become
searchable. Only names that exist on ``origin/main`` are imported, so the
reverted-code check fails behaviourally rather than at import.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.binary import triage_binary

# A packed, network-capable sample with an injection-flavoured import set.
_INFO = {
    "info": {
        "arch": "x86",
        "bits": 32,
        "os": "windows",
        "bintype": "pe",
        "compiler": "MSVC",
        "compiled": "Tue Jan 10 12:00:00 2023",
    }
}
_IMPORTS = {
    "imports": [
        {"name": "VirtualAllocEx"},
        {"name": "WriteProcessMemory"},
        {"name": "CreateRemoteThread"},
        {"name": "InternetOpenUrl"},
    ]
}
_SECTIONS = {
    "sections": [
        {"name": ".UPX0", "size": 4096, "vsize": 8192, "entropy": 7.9, "perm": "mrwx"},
        {"name": ".text", "size": 2048, "vsize": 2048, "entropy": 6.1, "perm": "m-rx"},
    ]
}
_STRINGS = {"strings": [{"string": "http://evil.example/beacon", "section": ".data"}]}


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "packed.exe"
    path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1024)
    return path


def _indexed_text(sample: Path) -> str:
    """Run triage_binary with rabin2 faked; return what got indexed."""
    captured: list[str] = []

    def _fake_rabin2(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        flags = cmd[1] if len(cmd) > 1 else ""
        if "I" in flags:
            payload: dict[str, Any] = _INFO
        elif "i" in flags:
            payload = _IMPORTS
        elif "S" in flags:
            payload = _SECTIONS
        elif "z" in flags:
            payload = _STRINGS
        else:
            payload = {}
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=json.dumps(payload), stderr=""
        )

    def _record(raw: str, *args: object, **kwargs: object) -> dict[str, object]:
        captured.append(raw)
        return {}

    with (
        patch("mulder.server.tools.binary.require_binary", return_value="/usr/bin/rabin2"),
        patch("mulder.server.tools.binary.subprocess.run", side_effect=_fake_rabin2),
        patch("mulder.server.tools.binary.extract_and_index", side_effect=_record),
    ):
        triage_binary.__wrapped__("case-1", str(sample))  # type: ignore[attr-defined]

    assert captured, "triage_binary indexed nothing at all"
    return captured[0]


def test_the_verdict_is_searchable(sample: Path) -> None:
    """The tool's own conclusion must be in the indexed text."""
    text = _indexed_text(sample)

    assert "Triage verdict:" in text
    assert "confidence" in text


def test_packing_indicators_are_searchable(sample: Path) -> None:
    """Searching the case for UPX must find this binary."""
    text = _indexed_text(sample)

    assert "Packing indicator:" in text
    assert "UPX" in text.split("Packing indicator:", 1)[1][:400]


def test_suspicious_imports_are_searchable_by_api_name(sample: Path) -> None:
    """The categorised APIs are the whole point of the triage step."""
    text = _indexed_text(sample)

    marker = "Suspicious imports"
    assert marker in text
    analysis = text.split("\n\n", 1)[0]
    assert "VirtualAllocEx" in analysis
    assert "process_injection" in analysis


def test_the_analysis_precedes_the_raw_dump(sample: Path) -> None:
    """Ordering is the difference between visible and truncated.

    ``tool_response`` returns only a leading preview, so the conclusion has to
    come before the raw JSON rather than after it.
    """
    text = _indexed_text(sample)

    assert text.startswith("Triage verdict:")
    assert text.index("Triage verdict:") < text.index('"arch"')


def test_the_raw_rabin2_output_is_still_indexed(sample: Path) -> None:
    """Narrowness guard: the fix adds to the indexed text, it does not replace it.

    The raw JSON is the primary evidence and must survive intact.
    """
    text = _indexed_text(sample)

    assert '"arch"' in text
    assert '"VirtualAllocEx"' in text
    assert '"entropy"' in text


def test_the_summary_fields_are_unchanged(sample: Path) -> None:
    """Narrowness guard: this PR changes what is indexed, not the response."""
    with (
        patch("mulder.server.tools.binary.require_binary", return_value="/usr/bin/rabin2"),
        patch(
            "mulder.server.tools.binary.subprocess.run",
            side_effect=lambda cmd, **_: subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=json.dumps(_INFO), stderr=""
            ),
        ),
        patch(
            "mulder.server.tools.binary.extract_and_index",
            return_value={"line_count": 3},
        ),
    ):
        result = triage_binary.__wrapped__("case-1", str(sample))  # type: ignore[attr-defined]

    assert result["status"] == "success"
