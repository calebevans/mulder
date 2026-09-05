"""Adversarial tests for the centralized command execution seam."""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

from mulder.execution import (
    BubblewrapNetworkIsolationBackend,
    CommandPolicy,
    CommandRequest,
    CommandRunner,
    ExecutionAuditEvent,
    ExecutionStatus,
    NetworkClass,
    NetworkIsolationPlan,
    PathAccess,
    PathArgument,
    UnshareNetworkIsolationBackend,
    safe_subprocess,
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


class _VerifiedTestIsolation:
    def prepare(
        self, argv: tuple[str, ...], _descriptor_bindings: object = ()
    ) -> NetworkIsolationPlan:
        return NetworkIsolationPlan(
            enforced=True,
            backend="test-netns",
            argv=argv,
            reason_code="network_isolation_enforced",
            message="deterministic test isolation",
            executable_path="/usr/bin/test-bwrap",
            executable_sha256="f" * 64,
            executable_size=12345,
            executable_mtime_ns=67890,
        )


class _UnavailableTestIsolation:
    def prepare(
        self, argv: tuple[str, ...], _descriptor_bindings: object = ()
    ) -> NetworkIsolationPlan:
        return NetworkIsolationPlan(
            enforced=False,
            backend="unavailable-test-backend",
            argv=argv,
            reason_code="network_isolation_unavailable",
            message="test backend unavailable",
        )


class _CallbackTestIsolation:
    def __init__(self, callback: object) -> None:
        self._callback = callback

    def prepare(
        self, argv: tuple[str, ...], _descriptor_bindings: object = ()
    ) -> NetworkIsolationPlan:
        self._callback()  # type: ignore[operator]
        return NetworkIsolationPlan(
            enforced=True,
            backend="callback-test-netns",
            argv=argv,
            reason_code="network_isolation_enforced",
            message="deterministic callback isolation",
        )


def _runner(
    policy: CommandPolicy,
    audit_sink: object | None = None,
) -> CommandRunner:
    return CommandRunner(
        policy,
        audit_sink=audit_sink,  # type: ignore[arg-type]
        network_isolation=_VerifiedTestIsolation(),
    )


def test_runs_pinned_executable_without_shell() -> None:
    events: list[ExecutionAuditEvent] = []
    result = _runner(_python_policy(), audit_sink=events.append).run(
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
    assert result.network_enforcement == "network_isolation_enforced"
    assert result.network_backend == "test-netns"
    assert events[0].network_backend_executable == "/usr/bin/test-bwrap"
    assert events[0].network_backend_sha256 == "f" * 64
    assert events[0].network_backend_size == 12345
    assert events[0].network_backend_mtime_ns == 67890


def test_executable_substitution_is_denied() -> None:
    policy = CommandPolicy(
        allowed_executables=frozenset({Path("/bin/echo").resolve()}),
    )
    result = _runner(policy).run(CommandRequest(executable=sys.executable))
    assert result.status is ExecutionStatus.DENIED
    assert result.decision.reason_code == "executable_denied"


def test_dangerous_environment_override_is_denied() -> None:
    result = _runner(_python_policy()).run(
        CommandRequest(
            executable=sys.executable,
            environment={"LD_PRELOAD": "/tmp/attacker.so"},
        )
    )
    assert result.status is ExecutionStatus.DENIED
    assert result.decision.reason_code == "dangerous_environment_denied"


def test_dangerous_inherited_environment_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_PRELOAD", "/tmp/attacker.so")
    result = _runner(_python_policy()).run(
        CommandRequest(
            executable=sys.executable,
            arguments=("-c", "import os; print('LD_PRELOAD' in os.environ)"),
            timeout_seconds=2,
        )
    )
    assert result.status is ExecutionStatus.COMPLETED
    assert result.stdout == b"False\n"


def test_direct_forensic_launches_scrub_delegation_credentials_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mulder.server.tools import artifacts
    from mulder.server.tools.extract import tsk

    monkeypatch.setenv("MULDER_TOOL_DELEGATION_SECRET", "server-secret")
    monkeypatch.setenv("MULDER_TOOL_DELEGATION_GRANT", "signed-grant")
    seen: list[dict[str, str]] = []

    def fake_run(*_args: object, **kwargs: object) -> object:
        seen.append(dict(kwargs["env"]))  # type: ignore[arg-type]
        return object()

    monkeypatch.setattr(safe_subprocess._subprocess, "run", fake_run)
    artifacts.subprocess.run(["artifact-parser"], check=False)
    tsk.subprocess.run(["mmls", "image.raw"], check=False)

    assert len(seen) == 2
    for environment in seen:
        assert "MULDER_TOOL_DELEGATION_SECRET" not in environment
        assert "MULDER_TOOL_DELEGATION_GRANT" not in environment


def test_every_direct_tool_subprocess_import_uses_the_safe_seam() -> None:
    project_root = Path(__file__).resolve().parents[1]
    unsafe_imports: list[str] = []
    for path in (project_root / "src" / "mulder").rglob("*.py"):
        relative = path.relative_to(project_root).as_posix()
        if relative in {
            "src/mulder/execution/runner.py",
            "src/mulder/execution/safe_subprocess.py",
            "src/mulder/orchestrator/proxy.py",
        }:
            continue
        if "import subprocess" in path.read_text(encoding="utf-8"):
            unsafe_imports.append(relative)
    assert unsafe_imports == []


def test_symlink_path_escape_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret").write_text("x")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    policy = _python_policy(allowed_roots=(root,))
    result = _runner(policy).run(
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
    result = _runner(_python_policy(allowed_roots=(root,))).run(
        CommandRequest(
            executable=sys.executable,
            arguments=(
                "-c",
                "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
                PathArgument(root / "." / "artifact.txt"),
            ),
            timeout_seconds=2,
        )
    )
    assert result.status is ExecutionStatus.COMPLETED
    assert result.stdout == b"evidence\n"
    assert result.decision.resolved_input_paths == (artifact.resolve(),)


def test_executable_replacement_after_authorization_executes_held_descriptor(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "tool"
    executable.write_text("#!/bin/sh\necho ORIGINAL\n")
    executable.chmod(0o700)
    policy = CommandPolicy(allowed_executables=frozenset({executable}))

    def replace_executable() -> None:
        executable.rename(tmp_path / "authorized-tool")
        executable.write_text("#!/bin/sh\necho SWAPPED\n")
        executable.chmod(0o700)

    result = CommandRunner(
        policy,
        network_isolation=_CallbackTestIsolation(replace_executable),
    ).run(CommandRequest(executable=str(executable), timeout_seconds=2))

    assert result.status is ExecutionStatus.COMPLETED
    assert result.stdout == b"ORIGINAL\n"


@pytest.mark.parametrize("target", ["input", "output", "cwd"])
def test_authorized_root_swap_before_launch_is_denied(tmp_path: Path, target: str) -> None:
    root = tmp_path / "authorized"
    root.mkdir()
    original = root / "input.txt"
    original.write_text("ORIGINAL")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "input.txt").write_text("SWAPPED")
    output = root / "output.txt"
    policy = _python_policy(allowed_roots=(root,))

    def swap_root() -> None:
        root.rename(tmp_path / "held-root")
        root.symlink_to(outside, target_is_directory=True)

    if target == "input":
        arguments = (
            "-c",
            "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
            PathArgument(original),
        )
        cwd = None
    elif target == "output":
        arguments = (
            "-c",
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ESCAPED')",
            PathArgument(output, PathAccess.WRITE),
        )
        cwd = None
    else:
        arguments = ("-c", "import os; print(os.getcwd())")
        cwd = root

    result = CommandRunner(
        policy,
        network_isolation=_CallbackTestIsolation(swap_root),
    ).run(
        CommandRequest(
            executable=sys.executable,
            arguments=arguments,
            cwd=cwd,
            timeout_seconds=2,
        )
    )

    assert result.status is ExecutionStatus.DENIED
    assert result.decision.reason_code == "network_isolation_invalid"
    assert not (outside / "output.txt").exists()


def test_new_output_is_staged_and_committed_through_held_parent(tmp_path: Path) -> None:
    output = tmp_path / "result.txt"
    result = _runner(_python_policy(allowed_roots=(tmp_path,))).run(
        CommandRequest(
            executable=sys.executable,
            arguments=(
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('SAFE')",
                PathArgument(output, PathAccess.WRITE),
            ),
            timeout_seconds=2,
        )
    )

    assert result.status is ExecutionStatus.COMPLETED
    assert output.read_text() == "SAFE"


def test_request_environment_is_frozen_snapshotted_and_receipted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_environment = {"PATH": "/authorized/bin"}
    request = CommandRequest(
        executable=sys.executable,
        arguments=("-c", "import os; print(os.environ['PATH'])"),
        environment=original_environment,
        timeout_seconds=2,
    )
    original_environment["PATH"] = "/mutated-before-run"
    with pytest.raises(TypeError):
        request.environment["PATH"] = "/mutated-request"  # type: ignore[index]

    events: list[ExecutionAuditEvent] = []

    def mutate_ambient_environment() -> None:
        monkeypatch.setenv("PATH", str(tmp_path / "injected-bin"))

    policy = _python_policy(allowed_environment_overrides=frozenset({"PATH"}))
    result = CommandRunner(
        policy,
        audit_sink=events.append,
        network_isolation=_CallbackTestIsolation(mutate_ambient_environment),
    ).run(request)

    assert result.status is ExecutionStatus.COMPLETED
    assert result.stdout == b"/authorized/bin\n"
    assert result.decision.environment_sha256 is not None
    assert events[0].environment_sha256 == result.decision.environment_sha256


def test_network_capability_is_fail_closed() -> None:
    result = _runner(_python_policy()).run(
        CommandRequest(
            executable=sys.executable,
            network_class=NetworkClass.OUTBOUND,
        )
    )
    assert result.status is ExecutionStatus.DENIED
    assert result.decision.reason_code == "network_class_denied"


def test_output_cap_terminates_child() -> None:
    result = _runner(_python_policy(max_output_bytes=1024)).run(
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
    result = _runner(_python_policy()).run(
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
    result = _runner(_python_policy(), audit_sink=events.append).run(
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


def test_none_network_fails_closed_and_receipts_backend_denial(tmp_path: Path) -> None:
    events: list[ExecutionAuditEvent] = []
    marker = tmp_path / "must-not-exist"
    result = CommandRunner(
        _python_policy(),
        audit_sink=events.append,
        network_isolation=_UnavailableTestIsolation(),
    ).run(
        CommandRequest(
            executable=sys.executable,
            arguments=("-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"),
        )
    )

    assert result.status is ExecutionStatus.DENIED
    assert not marker.exists()
    assert result.decision.reason_code == "network_isolation_unavailable"
    assert result.network_backend == "unavailable-test-backend"
    assert events[0].network_enforcement == "network_isolation_unavailable"
    assert events[0].policy_decision == "deny"


def test_unshare_backend_preserves_mount_namespace_and_descriptor_argv() -> None:
    argv = ("/proc/self/fd/10", "-m", "helper", "/proc/self/fd/11")
    wrapped = UnshareNetworkIsolationBackend._wrapped_argv(
        "/usr/bin/unshare",
        argv,
    )

    assert wrapped == ("/usr/bin/unshare", "--net", "--", *argv)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="bubblewrap is Linux-only")
def test_production_none_network_namespace_denies_outbound_socket_attempt() -> None:
    script = (
        "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
        "\ntry: s.connect(('192.0.2.1', 9)); print('network-open')"
        "\nexcept OSError: print('network-denied')"
    )
    result = CommandRunner(
        _python_policy(),
        network_isolation=BubblewrapNetworkIsolationBackend(),
    ).run(
        CommandRequest(
            executable=sys.executable,
            arguments=("-I", "-c", script),
            timeout_seconds=2,
        )
    )

    if result.status is ExecutionStatus.DENIED:
        assert result.decision.reason_code == "network_isolation_unavailable"
    else:
        assert result.status is ExecutionStatus.COMPLETED
        assert result.stdout == b"network-denied\n"
        assert result.network_enforcement == "network_isolation_enforced"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="bubblewrap is Linux-only")
def test_network_backend_ignores_path_spoof_and_parent_verifies_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "bwrap"
    fake.write_text(
        f"""#!{sys.executable}
import os
import sys

args = sys.argv[1:]
command = args[args.index("--") + 1:]
if any("readlink('/proc/self/ns/net')" in value for value in command):
    print("net:[attacker-controlled]")
    raise SystemExit(0)
os.execv(command[0], command)
"""
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    parent_namespace = os.stat("/proc/self/ns/net").st_ino

    result = CommandRunner(
        _python_policy(),
        network_isolation=BubblewrapNetworkIsolationBackend(),
    ).run(
        CommandRequest(
            executable=sys.executable,
            arguments=(
                "-I",
                "-c",
                "import os; print(os.stat('/proc/self/ns/net').st_ino)",
            ),
            timeout_seconds=2,
        )
    )

    if result.status is ExecutionStatus.DENIED:
        assert result.decision.reason_code == "network_isolation_unavailable"
    else:
        assert result.status is ExecutionStatus.COMPLETED
        assert int(result.stdout) != parent_namespace
        assert result.network_enforcement == "network_isolation_enforced"


def test_argument_nul_is_rejected_before_policy() -> None:
    with pytest.raises(ValueError, match="NUL"):
        CommandRequest(executable=sys.executable, arguments=("bad\x00argument",))


def test_compatibility_runner_binds_declared_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helpers, "has_ctx", lambda: False)
    monkeypatch.setattr(
        "mulder.execution.runner._DEFAULT_NETWORK_ISOLATION_BACKEND",
        _VerifiedTestIsolation(),
    )
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("evidence")
    result = helpers.run_subprocess(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
            str(artifact),
        ],
        timeout=2,
        input_paths=(artifact,),
        allowed_roots=(tmp_path,),
    )
    assert not isinstance(result, str)
    assert result.stdout.strip() == "evidence"


def test_compatibility_runner_rejects_unbound_declared_path(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.txt"
    result = helpers.run_subprocess(
        [sys.executable, "-c", "print('no path argument')"],
        input_paths=(artifact,),
        allowed_roots=(tmp_path,),
    )
    assert result == "Failed to run command: a declared path is not bound to argv"


def test_child_environment_is_a_minimal_allowlist_not_a_secret_denylist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inherited = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "HOME": "/home/examiner",
        "OPENAI_API_KEY": "provider-secret",
        "AWS_SECRET_ACCESS_KEY": "cloud-secret",
        "UNKNOWN_FUTURE_CREDENTIAL": "future-secret",
        "RUBYOPT": "-rshell",
        "JAVA_TOOL_OPTIONS": "-javaagent:/tmp/evil.jar",
        "LUA_INIT": "@/tmp/evil.lua",
    }
    for name, value in inherited.items():
        monkeypatch.setenv(name, value)

    child = safe_subprocess.sanitized_environment()

    assert child["PATH"] == inherited["PATH"]
    assert child["LANG"] == inherited["LANG"]
    assert child["HOME"] == inherited["HOME"]
    assert {
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "UNKNOWN_FUTURE_CREDENTIAL",
        "RUBYOPT",
        "JAVA_TOOL_OPTIONS",
        "LUA_INIT",
    }.isdisjoint(child)


# Direct subprocess sites that predate the centralized seam.  Each is a
# deliberate migration backlog category (installer, long-lived model proxy,
# legacy extractor, or tool wrapper).  A new source module cannot introduce a
# direct run/Popen call without changing this security assertion explicitly.
_DOCUMENTED_SUBPROCESS_EXCEPTIONS = {
    "src/mulder/assets/install.py",
    "src/mulder/execution/runner.py",
    "src/mulder/execution/mount_helper.py",
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
