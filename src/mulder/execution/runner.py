"""Single subprocess runner for policy-checked forensic commands."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Protocol

from mulder.execution.policy import (
    CommandPolicy,
    CommandRequest,
    NetworkClass,
    PolicyDecision,
)


class ExecutionStatus(str, Enum):
    """Machine-readable terminal state for a command attempt."""

    COMPLETED = "completed"
    DENIED = "denied"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT = "output_limit"
    FAILED = "failed"


@dataclass(frozen=True)
class NetworkIsolationPlan:
    """Verified launch plan returned by a no-network enforcement backend."""

    enforced: bool
    backend: str
    argv: tuple[str, ...]
    reason_code: str
    message: str
    executable_path: str | None = None
    executable_sha256: str | None = None
    executable_size: int | None = None
    executable_mtime_ns: int | None = None


class NetworkIsolationBackend(Protocol):
    """Adapter that must prove isolation before wrapping a command."""

    def prepare(self, argv: tuple[str, ...]) -> NetworkIsolationPlan:
        """Return a verified isolated launch plan or a fail-closed denial."""
        ...


class BubblewrapNetworkIsolationBackend:
    """Linux network-namespace enforcement using a verified bubblewrap binary.

    The binary is pinned to a root-controlled system path and attested before
    use. The parent then inspects the launched process tree through ``/proc``
    to prove a distinct child namespace; wrapper-controlled stdout is never
    accepted as proof.
    """

    backend_name = "bubblewrap-netns-v1"

    def __init__(self, executable: str | None = None, probe_timeout: float = 5.0) -> None:
        self._configured_executable = executable
        self._probe_timeout = probe_timeout
        self._probe_result: tuple[bool, str, str | None] | None = None
        self._attested_identity: tuple[int, int, int, int, str] | None = None
        self._probe_lock = threading.Lock()

    def prepare(self, argv: tuple[str, ...]) -> NetworkIsolationPlan:
        """Wrap *argv* only after a child network namespace is observed."""
        verified, message, executable = self._verified_backend()
        if not verified or executable is None:
            return NetworkIsolationPlan(
                enforced=False,
                backend=self.backend_name,
                argv=argv,
                reason_code="network_isolation_unavailable",
                message=message,
            )
        return NetworkIsolationPlan(
            enforced=True,
            backend=self.backend_name,
            argv=self._wrapped_argv(executable, argv),
            reason_code="network_isolation_enforced",
            message="Command is confined to a verified private network namespace",
            executable_path=executable,
            executable_sha256=(self._attested_identity[4] if self._attested_identity else None),
            executable_size=(self._attested_identity[2] if self._attested_identity else None),
            executable_mtime_ns=(self._attested_identity[3] if self._attested_identity else None),
        )

    @staticmethod
    def _wrapped_argv(executable: str, argv: tuple[str, ...]) -> tuple[str, ...]:
        # The filesystem view intentionally remains compatible with existing
        # forensic tools. This adapter asserts network isolation only.
        return (
            executable,
            "--unshare-net",
            "--die-with-parent",
            "--bind",
            "/",
            "/",
            "--dev-bind",
            "/dev",
            "/dev",
            "--proc",
            "/proc",
            "--",
            *argv,
        )

    def _verified_backend(self) -> tuple[bool, str, str | None]:
        with self._probe_lock:
            if self._probe_result is not None:
                executable = self._probe_result[2]
                if executable is not None:
                    attested, _message = self._attest_executable(Path(executable))
                    if attested != self._attested_identity:
                        return (
                            False,
                            "The attested bubblewrap executable changed after verification",
                            None,
                        )
                return self._probe_result
            self._probe_result = self._probe()
            return self._probe_result

    def _probe(self) -> tuple[bool, str, str | None]:
        if not sys.platform.startswith("linux"):
            return False, "No supported no-network isolation backend exists on this platform", None
        configured = self._configured_executable
        located = Path(configured) if configured is not None else Path("/usr/bin/bwrap")
        if configured is not None and not located.is_absolute():
            return False, "Configured bubblewrap path must be absolute", None
        try:
            executable = str(Path(located).resolve(strict=True))
        except (OSError, RuntimeError) as exc:
            return False, f"Could not resolve the network isolation backend: {exc}", None
        identity, attestation_error = self._attest_executable(Path(executable))
        if identity is None:
            return False, attestation_error, None
        self._attested_identity = identity
        try:
            parent_namespace = self._namespace_identity(os.getpid())
        except OSError as exc:
            return False, f"Could not inspect the parent network namespace: {exc}", None

        probe_program = "import time; time.sleep(30)"
        probe_argv = self._wrapped_argv(
            executable,
            (
                sys.executable,
                "-I",
                "-c",
                probe_program,
            ),
        )
        probe: subprocess.Popen[bytes] | None = None
        try:
            probe = subprocess.Popen(
                probe_argv,
                env=_safe_environment({}),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
            )
            deadline = time.monotonic() + self._probe_timeout
            while time.monotonic() < deadline:
                for pid in self._process_tree(probe.pid):
                    try:
                        if self._is_probe_payload(pid, probe_program) and (
                            self._namespace_identity(pid) != parent_namespace
                        ):
                            self._terminate_probe(probe)
                            return True, "Verified private network namespace", executable
                    except OSError:
                        continue
                if probe.poll() is not None:
                    detail = (probe.stderr.read() if probe.stderr is not None else b"").decode(
                        "utf-8", errors="replace"
                    ).strip()
                    return (
                        False,
                        f"bubblewrap network namespace probe was denied: {detail}",
                        None,
                    )
                time.sleep(0.01)
            self._terminate_probe(probe)
            return False, "bubblewrap network namespace probe timed out", None
        except (OSError, subprocess.SubprocessError) as exc:
            if probe is not None:
                self._terminate_probe(probe)
            return False, f"bubblewrap network namespace probe failed: {exc}", None

    @staticmethod
    def _namespace_identity(pid: int) -> tuple[int, int]:
        namespace = os.stat(f"/proc/{pid}/ns/net")
        return namespace.st_dev, namespace.st_ino

    @staticmethod
    def _process_tree(root_pid: int) -> tuple[int, ...]:
        discovered: list[int] = []
        pending = [root_pid]
        while pending:
            pid = pending.pop()
            if pid in discovered:
                continue
            discovered.append(pid)
            try:
                children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
            except OSError:
                continue
            pending.extend(int(child) for child in children)
        return tuple(discovered)

    @staticmethod
    def _is_probe_payload(pid: int, probe_program: str) -> bool:
        try:
            executable = Path(os.readlink(f"/proc/{pid}/exe")).resolve()
            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except OSError:
            return False
        return executable == Path(sys.executable).resolve() and (
            probe_program.encode("utf-8") in command
        )

    @staticmethod
    def _terminate_probe(probe: subprocess.Popen[bytes]) -> None:
        if probe.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(probe.pid, signal.SIGKILL)
        probe.wait()

    @staticmethod
    def _attest_executable(
        executable: Path,
    ) -> tuple[tuple[int, int, int, int, str] | None, str]:
        try:
            executable_stat = executable.stat()
            if not stat.S_ISREG(executable_stat.st_mode):
                return None, "bubblewrap executable is not a regular file"
            if executable_stat.st_uid != 0 or executable_stat.st_mode & 0o022:
                return None, "bubblewrap executable is not root-owned and immutable to other users"
            if not os.access(executable, os.X_OK):
                return None, "bubblewrap executable is not executable"
            for parent in executable.parents:
                parent_stat = parent.stat()
                if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
                    return None, "bubblewrap path is not rooted in trusted directories"
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        except OSError as exc:
            return None, f"Could not attest the bubblewrap executable: {exc}"
        return (
            executable_stat.st_dev,
            executable_stat.st_ino,
            executable_stat.st_size,
            executable_stat.st_mtime_ns,
            digest,
        ), ""


_DEFAULT_NETWORK_ISOLATION_BACKEND = BubblewrapNetworkIsolationBackend()


@dataclass(frozen=True)
class CommandResult:
    """Bounded result from one command attempt."""

    status: ExecutionStatus
    decision: PolicyDecision
    argv: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    started_at: str
    finished_at: str
    duration_ms: float
    output_sha256: str
    network_enforcement: str
    network_backend: str
    network_backend_executable: str | None
    network_backend_sha256: str | None
    network_backend_size: int | None
    network_backend_mtime_ns: int | None
    error: str | None = None

    @property
    def permitted(self) -> bool:
        return self.decision.permitted


@dataclass(frozen=True)
class ExecutionAuditEvent:
    """Content-minimal permit/deny/result event for the case audit chain."""

    request_digest: str
    executable: str
    argument_count: int
    environment_keys: tuple[str, ...]
    input_paths: tuple[str, ...]
    output_paths: tuple[str, ...]
    network_class: str
    network_enforcement: str
    network_backend: str
    network_backend_executable: str | None
    network_backend_sha256: str | None
    network_backend_size: int | None
    network_backend_mtime_ns: int | None
    policy_decision: str
    reason_code: str
    status: str
    returncode: int | None
    output_sha256: str
    duration_ms: float
    timestamp: str

    def as_mapping(self) -> dict[str, object]:
        return {
            "request_digest": self.request_digest,
            "executable": self.executable,
            "argument_count": self.argument_count,
            "environment_keys": list(self.environment_keys),
            "input_paths": list(self.input_paths),
            "output_paths": list(self.output_paths),
            "network_class": self.network_class,
            "network_enforcement": self.network_enforcement,
            "network_backend": self.network_backend,
            "network_backend_executable": self.network_backend_executable,
            "network_backend_sha256": self.network_backend_sha256,
            "network_backend_size": self.network_backend_size,
            "network_backend_mtime_ns": self.network_backend_mtime_ns,
            "policy_decision": self.policy_decision,
            "reason_code": self.reason_code,
            "status": self.status,
            "returncode": self.returncode,
            "output_sha256": self.output_sha256,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
        }


AuditSink = Callable[[ExecutionAuditEvent], None]


def _canonical_digest(value: Mapping[str, object]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _request_digest(request: CommandRequest, decision: PolicyDecision) -> str:
    return _canonical_digest(
        {
            "executable": str(decision.resolved_executable or request.executable),
            "arguments": [
                argument
                if isinstance(argument, str)
                else {"path": str(argument.path), "access": argument.access.value}
                for argument in request.arguments
            ],
            "cwd": str(decision.resolved_cwd) if decision.resolved_cwd else None,
            "environment_keys": sorted(request.environment),
            "input_paths": [str(path) for path in decision.resolved_input_paths],
            "output_paths": [str(path) for path in decision.resolved_output_paths],
            "timeout_seconds": request.timeout_seconds,
            "max_output_bytes": request.max_output_bytes,
            "max_memory_bytes": request.max_memory_bytes,
            "max_cpu_seconds": request.max_cpu_seconds,
            "network_class": request.network_class.value,
        }
    )


def _output_digest(stdout: bytes, stderr: bytes) -> str:
    return (
        "sha256:"
        + hashlib.sha256(b"mulder.command-output:v1\0" + stdout + b"\0" + stderr).hexdigest()
    )


def _safe_environment(overrides: Mapping[str, str]) -> dict[str, str]:
    """Compatibility wrapper around the child-process environment seam."""
    from mulder.execution.safe_subprocess import sanitized_environment

    return sanitized_environment(overrides)


def _resource_limiter(request: CommandRequest) -> Callable[[], None] | None:
    """Return POSIX child limits without importing resource on other platforms."""
    if os.name != "posix":
        return None
    if request.max_memory_bytes is None and request.max_cpu_seconds is None:
        return None

    def apply_limits() -> None:
        import resource

        if request.max_memory_bytes is not None:
            resource.setrlimit(
                resource.RLIMIT_AS,
                (request.max_memory_bytes, request.max_memory_bytes),
            )
        if request.max_cpu_seconds is not None:
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (request.max_cpu_seconds, request.max_cpu_seconds),
            )

    return apply_limits


def _read_bounded(handle: BinaryIO, remaining: int) -> tuple[bytes, bool]:
    handle.seek(0)
    value = handle.read(remaining + 1)
    return value[:remaining], len(value) > remaining


class CommandRunner:
    """Resolve, authorize, execute, bound, and receipt one child process."""

    def __init__(
        self,
        policy: CommandPolicy,
        audit_sink: AuditSink | None = None,
        network_isolation: NetworkIsolationBackend | None = None,
    ) -> None:
        self._policy = policy
        self._audit_sink = audit_sink
        self._network_isolation = network_isolation or _DEFAULT_NETWORK_ISOLATION_BACKEND

    def run(self, request: CommandRequest) -> CommandResult:
        """Execute an authorized request without invoking a shell."""
        started = datetime.now(timezone.utc).isoformat()
        started_clock = time.monotonic()
        decision = self._policy.evaluate(request)
        request_digest = _request_digest(request, decision)
        argv = (
            str(decision.resolved_executable or request.executable),
            *(decision.resolved_arguments or tuple(str(arg) for arg in request.arguments)),
        )
        isolation = NetworkIsolationPlan(
            enforced=False,
            backend="none",
            argv=argv,
            reason_code="network_isolation_not_evaluated",
            message="Policy denied the request before network isolation",
        )
        if not decision.permitted:
            result = self._result(
                status=ExecutionStatus.DENIED,
                decision=decision,
                argv=argv,
                returncode=None,
                stdout=b"",
                stderr=b"",
                started_at=started,
                started_clock=started_clock,
                error=decision.message,
                isolation=isolation,
            )
            self._audit(request, result, request_digest)
            return result

        if request.network_class is NetworkClass.NONE:
            isolation = self._network_isolation.prepare(argv)
            if not isolation.enforced:
                decision = replace(
                    decision,
                    permitted=False,
                    reason_code=isolation.reason_code,
                    message=isolation.message,
                )
                result = self._result(
                    status=ExecutionStatus.DENIED,
                    decision=decision,
                    argv=argv,
                    returncode=None,
                    stdout=b"",
                    stderr=b"",
                    started_at=started,
                    started_clock=started_clock,
                    error=decision.message,
                    isolation=isolation,
                )
                self._audit(request, result, request_digest)
                return result
        else:
            isolation = NetworkIsolationPlan(
                enforced=False,
                backend="none",
                argv=argv,
                reason_code="network_isolation_not_required",
                message=(
                    f"Network class {request.network_class.value!r} does not request isolation"
                ),
            )

        status = ExecutionStatus.COMPLETED
        returncode: int | None = None
        error: str | None = None
        stdout = b""
        stderr = b""
        with (
            tempfile.TemporaryFile("w+b") as stdout_file,
            tempfile.TemporaryFile("w+b") as stderr_file,
        ):
            try:
                process = subprocess.Popen(
                    isolation.argv,
                    cwd=decision.resolved_cwd,
                    env=_safe_environment(request.environment),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    start_new_session=True,
                    preexec_fn=_resource_limiter(request),
                )
                deadline = time.monotonic() + request.timeout_seconds
                while True:
                    output_size = (
                        os.fstat(stdout_file.fileno()).st_size
                        + os.fstat(stderr_file.fileno()).st_size
                    )
                    if output_size > request.max_output_bytes:
                        status = ExecutionStatus.OUTPUT_LIMIT
                        error = f"Command output exceeded {request.max_output_bytes} bytes"
                        self._terminate(process)
                        returncode = process.wait()
                        break
                    returncode = process.poll()
                    if returncode is not None:
                        break
                    if time.monotonic() >= deadline:
                        status = ExecutionStatus.TIMED_OUT
                        error = f"Command timed out after {request.timeout_seconds:g}s"
                        self._terminate(process)
                        returncode = process.wait()
                        break
                    time.sleep(0.01)
            except OSError as exc:
                status = ExecutionStatus.FAILED
                error = f"Failed to start command: {exc}"

            stdout, stdout_overflow = _read_bounded(stdout_file, request.max_output_bytes)
            remaining = max(0, request.max_output_bytes - len(stdout))
            stderr, stderr_overflow = _read_bounded(stderr_file, remaining)
            if status is ExecutionStatus.COMPLETED and (stdout_overflow or stderr_overflow):
                status = ExecutionStatus.OUTPUT_LIMIT
                error = f"Command output exceeded {request.max_output_bytes} bytes"

        result = self._result(
            status=status,
            decision=decision,
            argv=argv,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            started_at=started,
            started_clock=started_clock,
            error=error,
            isolation=isolation,
        )
        self._audit(request, result, request_digest)
        return result

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        """Terminate the complete child process group."""
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()

    @staticmethod
    def _result(
        *,
        status: ExecutionStatus,
        decision: PolicyDecision,
        argv: tuple[str, ...],
        returncode: int | None,
        stdout: bytes,
        stderr: bytes,
        started_at: str,
        started_clock: float,
        error: str | None,
        isolation: NetworkIsolationPlan,
    ) -> CommandResult:
        finished = datetime.now(timezone.utc).isoformat()
        duration_ms = (time.monotonic() - started_clock) * 1000
        return CommandResult(
            status=status,
            decision=decision,
            argv=argv,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
            finished_at=finished,
            duration_ms=duration_ms,
            output_sha256=_output_digest(stdout, stderr),
            network_enforcement=isolation.reason_code,
            network_backend=isolation.backend,
            network_backend_executable=isolation.executable_path,
            network_backend_sha256=isolation.executable_sha256,
            network_backend_size=isolation.executable_size,
            network_backend_mtime_ns=isolation.executable_mtime_ns,
            error=error,
        )

    def _audit(
        self,
        request: CommandRequest,
        result: CommandResult,
        request_digest: str,
    ) -> None:
        if self._audit_sink is None:
            return
        self._audit_sink(
            ExecutionAuditEvent(
                request_digest=request_digest,
                executable=str(result.decision.resolved_executable or request.executable),
                argument_count=len(request.arguments),
                environment_keys=tuple(sorted(request.environment)),
                input_paths=tuple(str(path) for path in result.decision.resolved_input_paths),
                output_paths=tuple(str(path) for path in result.decision.resolved_output_paths),
                network_class=request.network_class.value,
                network_enforcement=result.network_enforcement,
                network_backend=result.network_backend,
                network_backend_executable=result.network_backend_executable,
                network_backend_sha256=result.network_backend_sha256,
                network_backend_size=result.network_backend_size,
                network_backend_mtime_ns=result.network_backend_mtime_ns,
                policy_decision="permit" if result.decision.permitted else "deny",
                reason_code=result.decision.reason_code,
                status=result.status.value,
                returncode=result.returncode,
                output_sha256=result.output_sha256,
                duration_ms=result.duration_ms,
                timestamp=result.finished_at,
            )
        )
