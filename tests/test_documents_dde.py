"""Regression tests for msodde DDE-link parsing.

msodde writes a four-line banner, an ``Opening file: <path>`` line and a
``DDE Links:`` header to **stdout** unconditionally. A parser that treats every
non-blank stdout line as a DDE link therefore reports five ``risk: high``
findings for a perfectly clean document — one of which discloses the absolute
evidence path as a "DDE command".

mulder's central claim is that fabricated findings are structurally impossible,
so these tests pin the parser against the *real* captured output of oletools
0.60.2 (the pinned dependency) in both its plain-text and ``--json`` forms.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools.documents import _parse_msodde_output

# Verbatim stdout from `python -m oletools.msodde <clean.docx>`, oletools
# 0.60.2, exit code 0. Note the absolute evidence path on the "Opening file"
# line — the value that used to be reported as a high-risk DDE command.
REAL_CLEAN_BANNER = """\
msodde 0.60.2 - http://decalage.info/python/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Opening file: /evidence/case-1/t.docx
DDE Links:
"""

# The same run with a document that really does carry a DDEAUTO field.
REAL_DDE_BANNER = (
    REAL_CLEAN_BANNER + ' DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" \n'
)

# Verbatim stdout from `python -m oletools.msodde --json <clean.docx>`.
REAL_CLEAN_JSON = """\
[
    {"msg": "msodde 0.60.2 - http://decalage.info/python/oletools THIS IS WORK IN \
PROGRESS - Check updates regularly! Please report any issue at \
https://github.com/decalage2/oletools/issues ", "level": "WARNING", "type": "msg"}
,     {"msg": "Opening file: /evidence/case-1/t.docx", "level": "WARNING", "type": "msg"}
,     {"msg": "DDE Links:", "level": "WARNING", "type": "msg"}
]
"""

REAL_DDE_JSON = """\
[
    {"msg": "msodde 0.60.2 - http://decalage.info/python/oletools THIS IS WORK IN \
PROGRESS - Check updates regularly! Please report any issue at \
https://github.com/decalage2/oletools/issues ", "level": "WARNING", "type": "msg"}
,     {"msg": "Opening file: /evidence/case-1/t.docx", "level": "WARNING", "type": "msg"}
,     {"msg": "DDE Links:", "level": "WARNING", "type": "msg"}
,     {"msg": " DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe \\"/k calc.exe\\" ", \
"level": "WARNING", "type": "dde-link"}
]
"""


class TestMsoddeParserRejectsBanner:
    """A clean document must produce exactly zero findings."""

    @pytest.mark.parametrize(
        "stdout",
        [
            pytest.param(REAL_CLEAN_JSON, id="json"),
            pytest.param(REAL_CLEAN_BANNER, id="plain-text"),
        ],
    )
    def test_clean_document_yields_no_links(self, stdout: str) -> None:
        assert _parse_msodde_output(stdout) == []

    @pytest.mark.parametrize(
        "stdout",
        [
            pytest.param(REAL_CLEAN_JSON, id="json"),
            pytest.param(REAL_CLEAN_BANNER, id="plain-text"),
        ],
    )
    def test_evidence_path_is_never_reported_as_a_command(self, stdout: str) -> None:
        commands = [link["command"] for link in _parse_msodde_output(stdout)]
        assert not any("/evidence/case-1/t.docx" in str(c) for c in commands)


class TestMsoddeParserDetectsRealLinks:
    """A document that really carries a DDE field must still be caught."""

    @pytest.mark.parametrize(
        "stdout",
        [
            pytest.param(REAL_DDE_JSON, id="json"),
            pytest.param(REAL_DDE_BANNER, id="plain-text"),
        ],
    )
    def test_real_dde_link_is_detected(self, stdout: str) -> None:
        links = _parse_msodde_output(stdout)
        assert len(links) == 1
        assert links[0]["field_type"] == "DDEAUTO"
        assert links[0]["risk"] == "high"
        assert "calc.exe" in str(links[0]["command"])


class TestAnalyzeOfficeDocumentDdeIntegration:
    """The parser is wired into the tool, not just unit-tested beside it."""

    def _run(self, proc: MagicMock) -> dict[str, object]:
        from mulder.server.tools.documents import analyze_office_document

        with (
            patch(
                "mulder.server.tools.documents.importlib.util.find_spec",
                return_value=MagicMock(),
            ),
            patch("mulder.server.tools.documents.Path.exists", return_value=True),
            patch(
                "mulder.server.tools.documents._analyze_macros_olevba",
                return_value=([], [], False),
            ),
            patch(
                "mulder.server.tools.documents.extract_and_index",
                return_value={},
            ),
            patch("mulder.server.tools.documents.subprocess.run", return_value=proc),
        ):
            return analyze_office_document.__wrapped__(  # type: ignore[attr-defined,no-any-return]
                "case-1", "/evidence/case-1/t.docx", analyze_dde=True
            )

    @staticmethod
    def _preview_content(result: dict[str, object]) -> str:
        _start, payload, _end = str(result["preview"]).splitlines()
        return str(json.loads(payload)["content"])

    def test_clean_document_reports_no_dde_links(self) -> None:
        proc = MagicMock(returncode=0, stdout=REAL_CLEAN_JSON, stderr="")
        result = self._run(proc)
        assert '"dde_links": []' in self._preview_content(result)

    def test_real_dde_link_reaches_the_response(self) -> None:
        proc = MagicMock(returncode=0, stdout=REAL_DDE_JSON, stderr="")
        result = self._run(proc)
        assert "DDEAUTO" in self._preview_content(result)


class TestPackagedMcpConfig:
    """``src/mulder/data/mcp.json`` is what a fresh workspace is seeded with."""

    def test_packaged_mcp_config_is_valid_json(self) -> None:
        from mulder.cli import DEFAULT_MCP_CONFIG

        config = json.loads(DEFAULT_MCP_CONFIG.read_text(encoding="utf-8"))
        assert config["mcpServers"]["mulder"]["command"] == "mulder"
        assert config["mcpServers"]["mulder"]["args"] == ["serve"]
