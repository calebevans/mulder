"""A CLI tool that failed must not be reported as a clean scan.

Every wrapped tool below used to discard its ``CompletedProcess``. When the
tool exited non-zero and wrote nothing, the parser found no output file and
returned "0 detections", which the MCP layer rendered as a **successful**
tool call. That is a false negative that looks like a clean result -- the
single worst outcome for a DFIR tool.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

from mulder.server.helpers import classify_tool_exit


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestClassifyToolExit:
    def test_zero_exit_is_ok(self) -> None:
        verdict, message = classify_tool_exit(_completed(), "x", produced_output=False)
        assert verdict == "ok"
        assert message == ""

    def test_nonzero_without_output_is_failed(self) -> None:
        verdict, message = classify_tool_exit(
            _completed(2, stderr="required argument --mapping"), "chainsaw", produced_output=False
        )
        assert verdict == "failed"
        assert "chainsaw exited 2" in message
        assert "--mapping" in message

    def test_nonzero_with_output_is_partial_not_failed(self) -> None:
        """chainsaw exits non-zero on one unreadable file without --skip-errors."""
        verdict, message = classify_tool_exit(
            _completed(1, stderr="failed to load a.evtx"), "chainsaw", produced_output=True
        )
        assert verdict == "partial"
        assert "may be incomplete" in message

    def test_stdout_is_used_when_stderr_is_empty(self) -> None:
        _, message = classify_tool_exit(
            _completed(1, stdout="boom"), "photorec", produced_output=False
        )
        assert "boom" in message

    def test_message_is_bounded(self) -> None:
        _, message = classify_tool_exit(
            _completed(1, stderr="x" * 10_000), "t", produced_output=False
        )
        assert len(message) < 800


class TestRunCliTool:
    @staticmethod
    def _run(tmp_path: Path, proc: subprocess.CompletedProcess[str]) -> dict[str, object]:
        from mulder.server import helpers as h

        target = tmp_path / "evidence.bin"
        target.write_bytes(b"\x00")
        with (
            patch.object(h, "require_binary", return_value="/usr/bin/strings"),
            patch.object(h, "run_subprocess", return_value=proc),
            patch(
                "mulder.server.extract_helpers.extract_and_index",
                return_value={"line_count": 1},
            ),
        ):
            return h.run_cli_tool(
                binary="strings",
                cmd=["strings", str(target)],
                tool_name="run_strings",
                params={},
                source_name="strings.output",
                source_path=str(target),
                extractor_label="strings",
            )

    def test_failed_tool_is_an_error_not_an_empty_success(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, _completed(1, stderr="No such file"))
        assert result["status"] == "error"
        assert result["error_type"] == "tool_failed"

    def test_partial_run_keeps_results_and_warns(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, _completed(1, stdout="hello", stderr="one file unreadable"))
        assert result["status"] == "success"
        assert "may be incomplete" in str(result["warning"])

    def test_clean_run_has_no_warning(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, _completed(0, stdout="hello"))
        assert result["status"] == "success"
        assert "warning" not in result


class TestChainsawExitStatus:
    @staticmethod
    def _run(tmp_path: Path, returncode: int, write_output: bool) -> dict[str, object]:
        from mulder.server.tools import chainsaw as cs

        binary = tmp_path / "chainsaw"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        mapping = tmp_path / "sigma-event-logs-all.yml"
        mapping.write_text("")
        evidence = tmp_path / "evtx"
        evidence.mkdir()

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if write_output:
                out = Path(cmd[cmd.index("--output") + 1])
                out.write_text("[]")
            return _completed(returncode, stderr="required arguments were not provided")

        with (
            patch.object(cs, "sources_already_indexed", return_value=[]),
            patch("mulder.server.helpers.shutil.which", return_value=str(binary)),
            patch.object(cs, "_default_chainsaw_mapping", return_value=mapping),
            patch.object(cs, "extract_and_index", return_value={}),
            patch.object(cs.subprocess, "run", side_effect=fake_run),
        ):
            return cs.run_chainsaw.__wrapped__(str(evidence))  # type: ignore[attr-defined]

    def test_exit_two_with_no_results_file_is_an_error(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, returncode=2, write_output=False)
        assert result["status"] == "error"
        assert result["error_type"] == "tool_failed"

    def test_clean_run_still_succeeds(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, returncode=0, write_output=True)
        assert result["status"] == "success"

    def test_partial_run_keeps_the_detections(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, returncode=1, write_output=True)
        assert result["status"] == "success"
        assert "may be incomplete" in str(result["warning"])


class TestZircoliteExitStatus:
    def test_failed_run_is_an_error(self, tmp_path: Path) -> None:
        from mulder.server.tools import zircolite as zc

        events = tmp_path / "events"
        events.mkdir()
        script = tmp_path / "zircolite.py"
        script.write_text("")
        ruleset = tmp_path / "rules.json"
        ruleset.write_text("[]")

        with (
            patch.object(zc, "sources_already_indexed", return_value=[]),
            patch.object(zc, "_zircolite_script", return_value=script),
            patch.object(zc, "_missing_zircolite_modules", return_value=[]),
            patch.object(zc, "extract_and_index", return_value={}),
            patch.object(
                zc.subprocess,
                "run",
                return_value=_completed(2, stderr="unrecognized arguments: --json"),
            ),
        ):
            result = zc.run_zircolite.__wrapped__(  # type: ignore[attr-defined]
                str(events), ruleset_path=str(ruleset)
            )

        assert result["status"] == "error"
        assert result["error_type"] == "tool_failed"


class TestReadpstExitStatus:
    """A failed readpst reported an empty mailbox, not a failure."""

    @staticmethod
    def _run(tmp_path: Path, returncode: int, write_eml: bool) -> dict[str, object]:
        from mulder.server.tools import email as em

        pst = tmp_path / "archive.pst"
        pst.write_bytes(b"!BDN")

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            out = Path(cmd[cmd.index("-o") + 1])
            if write_eml:
                folder = out / "Inbox"
                folder.mkdir(parents=True, exist_ok=True)
                (folder / "1.eml").write_text(
                    "Subject: hello\r\nFrom: a@x\r\nTo: b@x\r\n"
                    "Date: Mon, 11 Mar 2024 09:14:02 +0100\r\n"
                    "Content-Type: text/plain\r\n\r\nbody\r\n"
                )
            return _completed(returncode, stderr="Error: cannot read PST header")

        with (
            patch.object(em, "require_binary", return_value="/usr/bin/readpst"),
            patch.object(em, "extract_and_index", return_value={}),
            patch.object(em.subprocess, "run", side_effect=fake_run),
        ):
            return em.parse_pst.__wrapped__("case-1", str(pst))  # type: ignore[attr-defined]

    def test_a_failed_extraction_is_an_error_not_an_empty_mailbox(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, returncode=1, write_eml=False)
        assert result["status"] == "error"
        assert result["error_type"] == "tool_failed"

    def test_a_clean_run_succeeds(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, returncode=0, write_eml=True)
        assert result["status"] == "success"

    def test_a_partial_extraction_keeps_the_messages(self, tmp_path: Path) -> None:
        """readpst exits non-zero on one unreadable folder; the rest is real."""
        result = self._run(tmp_path, returncode=1, write_eml=True)
        assert result["status"] == "success"
        assert "may be incomplete" in str(result["warning"])
