"""Adversarial tests for the centralized command execution seam."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from mulder.execution import (
    CommandPolicy,
    CommandRequest,
    CommandRunner,
    ExecutionAuditEvent,
    ExecutionStatus,
    NetworkClass,
    PathArgument,
)
from mulder.server import helpers


def _python_policy(**kwargs: object) -> CommandPolicy:
    values: dict[str, object] = {
        "allowed_executables": frozenset({Path(sys.executable).resolve()}),
        "max_timeout_seconds": 600,
        "max_output_bytes": 16 * 1024 * 1024,
    }
    values.update(kwargs)
    return CommandPolicy(**values)  # type: ignore[arg-type]


def test_runs_pinned_executable_without_shell() -> None:
    result = CommandRunner(_python_policy()).run(
        CommandRequest(
            executable=sys.executable,
            arguments=("-c", "print('forensic output')"),
            timeout_seconds=2,
        )
    )
    assert result.status is ExecutionStatus.COMPLETED
    assert result.returncode == 0
    assert result.stdout == b"forensic output\n"
    assert result.argv[0] == str(Path(sys.executable).resolve())


def test_executable_substitution_is_denied() -> None:
    policy = CommandPolicy(
        allowed_executables=frozenset({Path("/bin/echo").resolve()}),
    )
    result = CommandRunner(policy).run(CommandRequest(executable=sys.executable))
    assert result.status is ExecutionStatus.DENIED
    assert result.decision.reason_code == "executable_denied"


def test_dangerous_environment_override_is_denied() -> None:
    result = CommandRunner(_python_policy()).run(
        CommandRequest(
            executable=sys.executable,
            environment={"LD_PRELOAD": "/tmp/attacker.so"},
        )
    )
    assert result.status is ExecutionStatus.DENIED
    assert result.decision.reason_code == "dangerous_environment_denied"


def test_dangerous_inherited_environment_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_PRELOAD", "/tmp/attacker.so")
    result = CommandRunner(_python_policy()).run(
        CommandRequest(
            executable=sys.executable,
            arguments=("-c", "import os; print('LD_PRELOAD' in os.environ)"),
            timeout_seconds=2,
        )
    )
    assert result.status is ExecutionStatus.COMPLETED
    assert result.stdout == b"False\n"


def test_symlink_path_escape_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret").write_text("x")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    policy = _python_policy(allowed_roots=(root,))
    result = CommandRunner(policy).run(
        CommandRequest(
            executable=sys.executable,
            arguments=(PathArgument(root / "escape" / "secret"),),
        )
    )
    assert result.status is ExecutionStatus.DENIED
    assert result.decision.reason_code == "path_denied"


def test_authorized_path_argument_is_replaced_with_resolved_path(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    artifact = root / "artifact.txt"
    artifact.write_text("evidence")
    result = CommandRunner(_python_policy(allowed_roots=(root,))).run(
        CommandRequest(
            executable=sys.executable,
            arguments=(
                "-c",
                "import sys; print(sys.argv[1])",
                PathArgument(root / "." / "artifact.txt"),
            ),
            timeout_seconds=2,
        )
    )
    assert result.status is ExecutionStatus.COMPLETED
    assert result.stdout.decode().strip() == str(artifact.resolve())
    assert result.decision.resolved_input_paths == (artifact.resolve(),)


def test_network_capability_is_fail_closed() -> None:
    result = CommandRunner(_python_policy()).run(
        CommandRequest(
            executable=sys.executable,
            network_class=NetworkClass.OUTBOUND,
        )
    )
    assert result.status is ExecutionStatus.DENIED
    assert result.decision.reason_code == "network_class_denied"


def test_output_cap_terminates_child() -> None:
    result = CommandRunner(_python_policy(max_output_bytes=1024)).run(
        CommandRequest(
            executable=sys.executable,
            arguments=("-c", "print('x' * 100000)"),
            timeout_seconds=2,
            max_output_bytes=256,
        )
    )
    assert result.status is ExecutionStatus.OUTPUT_LIMIT
    assert len(result.stdout) + len(result.stderr) <= 256


def test_timeout_terminates_process_group() -> None:
    result = CommandRunner(_python_policy()).run(
        CommandRequest(
            executable=sys.executable,
            arguments=("-c", "import time; time.sleep(2)"),
            timeout_seconds=0.05,
        )
    )
    assert result.status is ExecutionStatus.TIMED_OUT
    assert result.returncode is not None


def test_denial_emits_content_minimal_audit_event() -> None:
    events: list[ExecutionAuditEvent] = []
    result = CommandRunner(_python_policy(), audit_sink=events.append).run(
        CommandRequest(
            executable=sys.executable,
            network_class=NetworkClass.OUTBOUND,
            arguments=("super-secret",),
        )
    )
    assert result.status is ExecutionStatus.DENIED
    assert len(events) == 1
    event = events[0]
    assert event.policy_decision == "deny"
    assert event.reason_code == "network_class_denied"
    assert event.argument_count == 1
    assert "super-secret" not in str(event.as_mapping())
    assert event.request_digest.startswith("sha256:")


def test_argument_nul_is_rejected_before_policy() -> None:
    with pytest.raises(ValueError, match="NUL"):
        CommandRequest(executable=sys.executable, arguments=("bad\x00argument",))


def test_compatibility_runner_binds_declared_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helpers, "has_ctx", lambda: False)
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("evidence")
    result = helpers.run_subprocess(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", str(artifact)],
        timeout=2,
        input_paths=(artifact,),
        allowed_roots=(tmp_path,),
    )
    assert not isinstance(result, str)
    assert result.stdout.strip() == str(artifact.resolve())


def test_compatibility_runner_rejects_unbound_declared_path(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.txt"
    result = helpers.run_subprocess(
        [sys.executable, "-c", "print('no path argument')"],
        input_paths=(artifact,),
        allowed_roots=(tmp_path,),
    )
    assert result == "Failed to run command: a declared path is not bound to argv"


# Direct subprocess sites that predate the centralized seam.  Each is a
# deliberate migration backlog category (installer, long-lived model proxy,
# legacy extractor, or tool wrapper).  A new source module cannot introduce a
# direct run/Popen call without changing this security assertion explicitly.
_DOCUMENTED_SUBPROCESS_EXCEPTIONS = {
    "src/mulder/assets/install.py",
    "src/mulder/execution/runner.py",
    "src/mulder/execution/mount_helper.py",
    "src/mulder/orchestrator/proxy.py",
    "src/mulder/server/tools/artifacts.py",
    "src/mulder/server/tools/binary.py",
    "src/mulder/server/tools/case.py",
    "src/mulder/server/tools/chainsaw.py",
    "src/mulder/server/tools/documents.py",
    "src/mulder/server/tools/email.py",
    "src/mulder/server/tools/extract/app_files.py",
    "src/mulder/server/tools/extract/carving.py",
    "src/mulder/server/tools/extract/disk_pcap.py",
    "src/mulder/server/tools/extract/evtx.py",
    "src/mulder/server/tools/extract/misc.py",
    "src/mulder/server/tools/extract/pcap.py",
    "src/mulder/server/tools/extract/plaso.py",
    "src/mulder/server/tools/extract/registry.py",
    "src/mulder/server/tools/extract/tsk.py",
    "src/mulder/server/tools/extract/volatility.py",
    "src/mulder/server/tools/hayabusa.py",
    "src/mulder/server/tools/hindsight.py",
    "src/mulder/server/tools/mvt.py",
    "src/mulder/server/tools/phone.py",
    "src/mulder/server/tools/plaso.py",
    "src/mulder/server/tools/tsk.py",
    "src/mulder/server/tools/yara.py",
    "src/mulder/server/tools/zircolite.py",
}


def test_no_new_direct_subprocess_modules() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    found: set[str] = set()
    for source in (repo_root / "src").rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}
            ):
                found.add(source.relative_to(repo_root).as_posix())
    assert found <= _DOCUMENTED_SUBPROCESS_EXCEPTIONS
    assert "src/mulder/server/helpers.py" not in found
