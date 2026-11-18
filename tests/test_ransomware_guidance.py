"""Ransomware guidance names tools each role has and says what a result does not establish;
the helpers the ransomware tools share read evidence with bounds."""

from __future__ import annotations

import inspect
import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.orchestrator import prompts
from mulder.server import app
from mulder.server import tools as _tools  # noqa: F401 register every tool
from mulder.server.app import _tool_dispatch_sync
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import TOOL_SOURCE_PREFIXES
from mulder.server.tool_access import Role, get_tools_for_role
from mulder.server.tools.composite import core
from mulder.server.tools.composite.core import (
    decode_evidence_text,
    iter_source_text,
    read_image_file,
)

_PROMPT_DIR = Path(prompts.__file__).parent
_PROMPTS = {p.stem: p.read_text(encoding="utf-8") for p in sorted(_PROMPT_DIR.glob("*.md"))}


def _can_call(role: Role, tool: str) -> bool:
    return f"mcp__mulder__{tool}" in get_tools_for_role(role)


def _section(prompt: str) -> str:
    """The RANSOMWARE section of a prompt, up to the next blank line."""
    return _PROMPTS[prompt].split("RANSOMWARE:", 1)[1].split("\n\n", 1)[0]


@pytest.mark.parametrize(
    ("prompt", "role", "tools"),
    [
        (
            "extract_analyst",
            Role.EXTRACT_ANALYST,
            (
                "find_encryption_activity",
                "find_remote_access_tools",
                "ransomware_family_hints",
                "find_file_staging",
            ),
        ),
        (
            "cross_system_planner",
            Role.CROSS_EXECUTOR,
            (
                "find_encryption_activity",
                "find_remote_access_tools",
                "find_data_exfiltration_indicators",
                "find_file_staging",
                "find_defense_evasion",
            ),
        ),
        (
            "extract_planner",
            Role.EXTRACT_EXECUTOR,
            ("run_usn_parser", "run_hayabusa_logon_summary", "run_vshadow_info", "run_mft_parser"),
        ),
    ],
)
def test_the_guidance_names_tools_the_role_can_call(
    prompt: str, role: Role, tools: tuple[str, ...]
) -> None:
    for tool in tools:
        assert tool in _PROMPTS[prompt], f"{prompt} does not mention {tool}"
        assert _can_call(role, tool), f"{role} cannot call {tool}"


def test_the_analyst_is_not_sent_to_tools_only_another_role_has() -> None:
    section = _section("extract_analyst")

    for tool in ("find_data_exfiltration_indicators", "run_usn_parser", "run_vshadow_info"):
        assert not _can_call(Role.EXTRACT_ANALYST, tool)
        assert tool not in section


def test_the_analyst_section_covers_each_question_with_its_caution() -> None:
    section = _section("extract_analyst")

    for question in (
        "When and where it started",
        "Which family",
        "How the intruder got in and stayed",
        "What ran",
        "What left first",
        "What was destroyed",
    ):
        assert question in section
    assert "a lead, not a verdict" in section
    assert "never an identification" in section
    assert "Presence is not abuse" in section
    assert "Running is not doing" in section
    assert "Absence in what was examined is not absence" in section
    assert "vssadmin" in section and "wbadmin" in section


def test_the_cross_system_analyst_is_given_the_sources_and_the_same_cautions() -> None:
    section = _section("cross_system_analyst")

    for source in (
        "composite.encryption_activity",
        "composite.remote_access_tools",
        "rmm.*",
        "logon.summary",
    ):
        assert source in section
    assert "not a verdict" in section and "not thereby abused" in section
    assert "not thereby\nthe one that encrypted" in section or "not thereby the one" in section
    assert "not an identification" in section


@pytest.mark.parametrize("tool", ["find_encryption_activity", "find_remote_access_tools"])
def test_windows_only_composites_say_an_empty_result_elsewhere_is_not_a_negative(
    tool: str,
) -> None:
    doc = inspect.getdoc(_tool_dispatch_sync[tool]) or ""

    assert "Windows evidence only" in doc
    assert "not a negative finding" in doc


def test_new_extraction_tools_are_scoped_by_the_parameter_the_batch_reads() -> None:
    """start_extraction_batch scopes its already-indexed skip by image_path or evtx_dir."""
    assert "image_path" in inspect.signature(_tool_dispatch_sync["run_usn_parser"]).parameters
    logon = inspect.signature(_tool_dispatch_sync["run_hayabusa_logon_summary"]).parameters
    assert {"image_path", "evtx_dir"} <= set(logon)
    assert TOOL_SOURCE_PREFIXES["run_usn_parser"] == ["ez.usnjrnl"]
    # A "hayabusa." source would make run_hayabusa and the batch skip the Sigma scan.
    (prefix,) = TOOL_SOURCE_PREFIXES["run_hayabusa_logon_summary"]
    assert not any(prefix.startswith(p) for p in TOOL_SOURCE_PREFIXES["run_hayabusa"])


# ---------------------------------------------------------------------------
# Shared readers
# ---------------------------------------------------------------------------


class _FakeIcat:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.commands: list[list[str]] = []
        self.asked: list[int] = []
        self.killed = False

    def __call__(self, cmd: list[str], **_kwargs: object) -> _FakeIcat:
        self.commands.append(list(cmd))
        asked = self.asked

        class Stream(io.BytesIO):
            def read(self, size: int | None = -1) -> bytes:
                asked.append(-1 if size is None else size)
                return super().read(size)

        self.stdout = Stream(self.data)
        return self

    def __enter__(self) -> _FakeIcat:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def kill(self) -> None:
        self.killed = True


def test_a_file_of_any_size_on_the_image_costs_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    icat = _FakeIcat(b"A" * 100_000)
    monkeypatch.setattr(core, "require_binary", lambda _name: "/usr/bin/icat")
    monkeypatch.setattr("mulder.server.tools.composite.core.subprocess.Popen", icat)

    data, more = read_image_file("-rf.E01", "117014-128-3", 2048, 4096) or (b"", False)
    small = read_image_file("/evidence/a.E01", "5", 0, 200_000)

    assert (len(data), more) == (4096, True)
    assert small == (b"A" * 100_000, False)
    # Never an unbounded read: one byte past the limit is enough to know there is more.
    assert icat.asked == [4097, 200_001]
    # An image path that looks like an option is not passed as one.
    assert icat.commands == [
        ["icat", "-o", "2048", "./-rf.E01", "117014-128-3"],
        ["icat", "/evidence/a.E01", "5"],
    ]
    assert icat.killed


@pytest.mark.parametrize("inode", ["", "12; rm -rf /", "-o", "12-128", "../3", "１２"])
def test_an_inode_that_is_not_an_inode_never_reaches_icat(
    inode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    icat = _FakeIcat(b"x")
    monkeypatch.setattr(core, "require_binary", lambda _name: "/usr/bin/icat")
    monkeypatch.setattr("mulder.server.tools.composite.core.subprocess.Popen", icat)

    assert read_image_file("/evidence/a.E01", inode, 0, 10) is None
    assert icat.commands == []


def test_evidence_text_is_decoded_and_stripped_of_control_characters() -> None:
    assert decode_evidence_text("pay\r\nnow".encode("utf-16")) == "pay\nnow"
    assert (
        decode_evidence_text(b"line one\r\n\x1b[31mred\x07\tkept\n") == "line one\n[31mred\tkept\n"
    )
    assert decode_evidence_text(b"MZ\x90\x00\x03\x00") is None
    assert decode_evidence_text(b"") == ""


def test_a_source_is_read_by_id_so_another_image_s_rows_are_not_mixed_in(
    tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    extract_and_index(
        "\n".join(f"a-row-{i}" + "x" * 500 for i in range(40)),
        "tsk.filelist",
        "/evidence/a.E01",
        "t",
    )
    extract_and_index("b-row-0\n", "tsk.filelist", "/evidence/b.E01", "t")
    first, second = tmp_case_db.get_sources()

    text = "".join(iter_source_text(first, page=2))

    assert text.count("a-row-") == 40 and "b-row" not in text
    assert "".join(iter_source_text(second)) == "b-row-0\n"
