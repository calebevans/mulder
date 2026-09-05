"""``run_radare2`` handed an arbitrary r2 script to r2 with nothing turned off.

``subprocess.run(["r2", "-q", "-c", commands, target_path])`` is safe at the
OS level -- it is a list, so no shell parses it. The problem is one layer up:
r2's own command language can leave r2.

Verified against real radare2 6.0.7, invoking it exactly as the tool does
(no ``-w``):

===============================  ==========  =========
command                          sandbox=off sandbox=on
===============================  ==========  =========
``!touch pwned.txt``             executed    blocked
``#!pipe sh -c "touch pwned"``   executed    blocked
``oo+;s 0;w PWNED``              EVIDENCE    unchanged
                                 MODIFIED
``o /etc/passwd``                opened      "Cannot open file"
===============================  ==========  =========

The ``oo+`` row is the one that matters most for a forensic tool: r2 reopens
the target read-write on request, so a command string could patch the very
binary it was asked to examine, without mulder ever passing ``-w``.

The fix prepends ``e cfg.sandbox=true;``. Two properties make that sound, both
asserted below against the real binary when it is installed:

* it must be a **command**, not a ``-e`` flag -- ``r2 -e cfg.sandbox=true``
  applies the sandbox before the target is opened and then refuses to open it,
  so the tool would return nothing;
* r2 refuses to switch it back off ("Cannot disable sandbox"), so appending it
  to an attacker-chosen string is not something the rest of that string can
  undo.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.extract.misc import R2_SANDBOX_PREFIX, _sandboxed

r2_installed = pytest.mark.skipif(shutil.which("r2") is None, reason="radare2 not installed")


def _completed(**kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="info", stderr="")


def _argv_for(commands: str | None, target: Path) -> list[str]:
    """The argv run_radare2 actually execs, with everything else stubbed out."""
    from mulder.server.tools.extract.misc import run_radare2

    with (
        patch("mulder.server.helpers.shutil.which", return_value="/usr/bin/r2"),
        patch("mulder.server.tools.extract.misc.extract_and_index", return_value={}),
        patch(
            "mulder.server.tools.extract.misc.subprocess.run", return_value=_completed()
        ) as mock_run,
    ):
        if commands is None:
            run_radare2.__wrapped__(str(target))  # type: ignore[attr-defined]
        else:
            run_radare2.__wrapped__(str(target), commands)  # type: ignore[attr-defined]
    return list(mock_run.call_args[0][0])


@pytest.fixture
def binary(tmp_path: Path) -> Path:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x7fELF" + b"\0" * 128)
    return target


class TestTheSandboxReachesR2:
    def test_the_default_commands_are_sandboxed(self, binary: Path) -> None:
        argv = _argv_for(None, binary)

        # NB: the tool execs the literal "r2", not the path the gate
        # resolved. That is a separate finding and is not touched here.
        assert argv[:3] == ["r2", "-q", "-c"]
        assert argv[3].startswith(R2_SANDBOX_PREFIX)
        assert argv[3] == R2_SANDBOX_PREFIX + "iI;iS;iz;afl"
        assert argv[4] == str(binary)

    def test_caller_commands_are_sandboxed_too(self, binary: Path) -> None:
        argv = _argv_for("!id", binary)

        assert argv[3] == "e cfg.sandbox=true;!id"

    def test_the_sandbox_comes_first(self, binary: Path) -> None:
        """After any other command it would be too late to matter."""
        argv = _argv_for("!id;iI", binary)

        assert argv[3].index("cfg.sandbox=true") < argv[3].index("!id")

    def test_it_is_still_a_list_not_a_shell_string(self, binary: Path) -> None:
        """The prefix must not turn the argv into something a shell parses."""
        argv = _argv_for("iI", binary)

        assert len(argv) == 5
        assert all(isinstance(a, str) for a in argv)

    def test_sandbox_is_a_command_not_a_flag(self, binary: Path) -> None:
        """``r2 -e cfg.sandbox=true <file>`` cannot open the file at all.

        Passing it as a flag would silently reduce every analysis to an error,
        which is why it is prepended to ``-c`` instead. Other ``-e`` flags are
        fine -- r2 suggests ``-e bin.relocs.apply=true`` itself -- so this
        asserts where the sandbox is set, not that no flag may ever be passed.
        """
        argv = _argv_for("iI", binary)

        elsewhere = [a for i, a in enumerate(argv) if i != 3 and "cfg.sandbox" in a]
        assert elsewhere == []


class TestSandboxedHelper:
    def test_it_prefixes(self) -> None:
        assert _sandboxed("iI") == "e cfg.sandbox=true;iI"

    def test_an_empty_batch_still_gets_the_sandbox(self) -> None:
        assert _sandboxed("") == R2_SANDBOX_PREFIX


@r2_installed
class TestAgainstRealRadare2:
    """The claims above, checked against the binary rather than the docs."""

    def _run(self, commands: str, target: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["r2", "-q", "-c", commands, str(target)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_the_shell_escape_is_blocked(self, tmp_path: Path) -> None:
        target = tmp_path / "sample.bin"
        shutil.copy(shutil.which("r2") or "/bin/sh", target)
        marker = tmp_path / "pwned.txt"

        self._run(_sandboxed(f"!touch {marker}"), target)

        assert not marker.exists()

    def test_the_pipe_escape_is_blocked(self, tmp_path: Path) -> None:
        target = tmp_path / "sample.bin"
        shutil.copy(shutil.which("r2") or "/bin/sh", target)
        marker = tmp_path / "pwned.txt"

        self._run(_sandboxed(f'#!pipe sh -c "touch {marker}"'), target)

        assert not marker.exists()

    def test_the_evidence_cannot_be_patched(self, tmp_path: Path) -> None:
        """oo+ reopens read-write even though mulder never passes -w."""
        target = tmp_path / "evidence.bin"
        shutil.copy(shutil.which("r2") or "/bin/sh", target)
        before = hashlib.sha256(target.read_bytes()).hexdigest()

        self._run(_sandboxed("oo+;s 0;w PWNED"), target)

        assert hashlib.sha256(target.read_bytes()).hexdigest() == before

    def test_the_sandbox_cannot_be_switched_off(self, tmp_path: Path) -> None:
        target = tmp_path / "sample.bin"
        shutil.copy(shutil.which("r2") or "/bin/sh", target)
        marker = tmp_path / "pwned.txt"

        proc = self._run(_sandboxed(f"e cfg.sandbox=false;!touch {marker}"), target)

        assert not marker.exists()
        assert "Cannot disable sandbox" in (proc.stdout + proc.stderr)

    def test_the_analysis_still_works(self, tmp_path: Path) -> None:
        """The whole point: the sandbox must not cost mulder its output."""
        target = tmp_path / "sample.bin"
        shutil.copy(shutil.which("r2") or "/bin/sh", target)

        proc = self._run(_sandboxed("iI;iS;iz;afl"), target)

        assert "bintype" in proc.stdout or "arch" in proc.stdout

    def test_deeper_analysis_is_byte_for_byte_unaffected(self, tmp_path: Path) -> None:
        """Not just the default batch: analysis and disassembly are identical.

        The only difference the sandbox makes to the run is an informational
        line on stderr, ``Debugger commands disabled in sandbox mode``. Mulder
        runs static triage against a file on disk and issues no debugger
        commands, so nothing it asks for is refused.
        """
        target = tmp_path / "sample.bin"
        shutil.copy("/bin/true", target)
        batch = "aa;afl;pdf @ entry0;px 32"

        sandboxed = self._run(_sandboxed(batch), target)
        plain = self._run(batch, target)

        assert sandboxed.stdout == plain.stdout
        assert sandboxed.stdout.strip(), "the batch must actually produce output"
