"""``run_radare2`` must run its command batch under radare2's sandbox.

``commands`` is an r2 *script*, not an argument list. The argv mulder builds is
shell-safe, but r2's own command language can leave r2: ``!cmd`` shells out,
``#!pipe sh -c cmd`` does the same by another route, ``oo+`` reopens the target
read-write so a batch can patch the evidence it was asked to examine, and ``o``
opens any other file the server can read.

Verified against radare2 6.0.7: ``r2 -q -c 'iI;!touch MARKER' /bin/true`` --
exactly the shape ``main`` builds -- creates MARKER. With the sandbox enabled as
the first command it does not.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.server.tools.extract.misc import run_radare2

# Spelled out rather than imported, so this module still imports against an
# unpatched tree -- the tests below must fail on their assertions, which is the
# evidence the bug was real, not on a missing symbol.
R2_SANDBOX_PREFIX = "e cfg.sandbox=true;"


def _sandboxed(commands: str) -> str:
    """Mirror of the production helper, for driving r2 directly."""
    return R2_SANDBOX_PREFIX + commands


def _argv_of(commands: str, target: Path) -> list[str]:
    """Capture the argv ``run_radare2`` hands to subprocess.run."""
    seen: list[list[str]] = []

    def _capture(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    with (
        patch("mulder.server.tools.extract.misc.require_binary", return_value=True),
        patch("mulder.server.tools.extract.misc.subprocess.run", side_effect=_capture),
        patch("mulder.server.tools.extract.misc.extract_and_index", return_value={}),
    ):
        run_radare2.__wrapped__(str(target), commands=commands)  # type: ignore[attr-defined]

    assert seen, "run_radare2 never invoked r2"
    return seen[0]


@pytest.fixture
def target(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF")
    return path


def test_the_batch_runs_under_the_sandbox(target: Path) -> None:
    """The default triage batch is prefixed with the sandbox setting."""
    argv = _argv_of("iI;iS;iz;afl", target)

    batch = argv[argv.index("-c") + 1]
    assert batch.startswith(R2_SANDBOX_PREFIX), batch
    assert batch == "e cfg.sandbox=true;iI;iS;iz;afl"


def test_the_sandbox_is_the_first_command_not_a_flag(target: Path) -> None:
    """Ordering is load-bearing, not cosmetic.

    ``r2 -e cfg.sandbox=true <file>`` applies the setting *before* the target is
    opened, and r2 then refuses to open it at all ("Cannot open ..."), so the
    tool would return nothing. The setting must arrive as the first command of
    the batch instead, once the file is already open.
    """
    argv = _argv_of("iI", target)

    assert "-e" not in argv, "the sandbox must not be passed as a pre-open -e flag"
    batch = argv[argv.index("-c") + 1]
    assert batch.split(";", 1)[0] == "e cfg.sandbox=true"


def test_a_caller_cannot_smuggle_the_sandbox_setting_out(target: Path) -> None:
    """Only the prefix may carry cfg.sandbox; the caller's text is appended after.

    Deliberately narrow: this must NOT forbid ``-e`` options generally -- r2
    itself recommends ``-e bin.relocs.apply=true`` -- only assert that the
    caller's own string cannot take the sandbox setting's place.
    """
    argv = _argv_of("e cfg.sandbox=false;!id", target)

    batch = argv[argv.index("-c") + 1]
    # The sandbox is still set first; the caller's attempt trails behind it,
    # where r2 rejects it with "Cannot disable sandbox".
    assert batch.startswith(R2_SANDBOX_PREFIX)
    assert batch.index("cfg.sandbox=true") < batch.index("cfg.sandbox=false")

    # No *other* argv element carries the setting -- the batch is the only place
    # it appears, so nothing outside -c can be used to override it.
    others = [a for i, a in enumerate(argv) if i != argv.index("-c") + 1]
    assert not any("cfg.sandbox" in a for a in others), others


def test_legitimate_r2_options_are_not_forbidden() -> None:
    """A guard that banned every ``-e`` would break r2's own advice.

    r2 emits "Relocs has not been applied. Please use `-e bin.relocs.apply=true`"
    on ordinary binaries, so the fix must leave that option usable.
    """
    from mulder.server.tools.extract.misc import _sandboxed as production_sandboxed

    batch = production_sandboxed("e bin.relocs.apply=true;iI")

    assert batch == "e cfg.sandbox=true;e bin.relocs.apply=true;iI"


# ---------------------------------------------------------------------------
# Live radare2 -- skipped when r2 is not installed.
# ---------------------------------------------------------------------------

_R2 = shutil.which("r2")
_needs_r2 = pytest.mark.skipif(_R2 is None, reason="radare2 not installed")


def _r2(batch: str, target: str = "/bin/true") -> subprocess.CompletedProcess[str]:
    assert _R2 is not None
    return subprocess.run(
        [_R2, "-q", "-c", batch, target],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@_needs_r2
def test_live_the_sandbox_blocks_a_shell_escape(tmp_path: Path) -> None:
    """The escape is real: unsandboxed r2 runs ``!touch``; sandboxed r2 does not."""
    marker = tmp_path / "escaped"

    # Exactly the shape main builds today.
    _r2(f"iI;!touch {marker}")
    escaped_without_sandbox = marker.exists()

    marker.unlink(missing_ok=True)
    _r2(_sandboxed(f"iI;!touch {marker}"))
    escaped_with_sandbox = marker.exists()

    assert escaped_without_sandbox, (
        "r2 did not shell out; this build cannot demonstrate the bug "
        "(the sandbox assertion below would then prove nothing)"
    )
    assert not escaped_with_sandbox, "the sandbox failed to block a shell escape"


@_needs_r2
def test_live_the_sandbox_cannot_be_turned_off_from_the_batch(tmp_path: Path) -> None:
    marker = tmp_path / "escaped"

    proc = _r2(_sandboxed(f"e cfg.sandbox=false;!touch {marker}"))

    assert not marker.exists()
    assert "Cannot disable sandbox" in (proc.stderr + proc.stdout)


@_needs_r2
def test_live_static_triage_output_is_unchanged(tmp_path: Path) -> None:
    """The sandbox costs the debugger, nothing mulder uses.

    mulder does static triage only, so the default batch must produce
    byte-identical stdout with and without the sandbox. ``/bin/true`` is
    deliberately tiny -- ``afl`` over a large binary is slow enough to time out.
    """
    commands = "iI;iS;iz;afl"

    plain = _r2(commands)
    sandboxed = _r2(_sandboxed(commands))

    assert plain.stdout == sandboxed.stdout
    assert plain.stdout.strip(), "the probe produced no output to compare"


@_needs_r2
def test_live_the_sandbox_blocks_reopening_the_evidence_read_write(tmp_path: Path) -> None:
    """``oo+`` would let a batch patch the evidence it was asked to examine."""
    sample = tmp_path / "evidence.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 64)
    before = sample.read_bytes()

    proc = _r2(_sandboxed("oo+;w PWNED"), str(sample))

    assert sample.read_bytes() == before, "the sandbox let r2 modify the evidence"
    assert "Cannot reopen" in (proc.stderr + proc.stdout)


@_needs_r2
def test_live_r2_is_the_binary_under_test() -> None:
    """Guards against a stubbed r2 silently making the live tests vacuous."""
    proc = subprocess.run(
        [os.fspath(_R2 or ""), "-v"], capture_output=True, text=True, check=False
    )
    assert "radare2" in proc.stdout.lower()
