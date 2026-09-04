"""Declarative policy for forensic command execution."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from mulder.path_policy import PathPolicyError, resolve_allowed_path


class NetworkClass(str, Enum):
    """Declared network capability needed by a command."""

    NONE = "none"
    LOOPBACK = "loopback"
    OUTBOUND = "outbound"


class PathAccess(str, Enum):
    """Filesystem access requested for one argv path."""

    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


@dataclass(frozen=True)
class PathArgument:
    """A path-valued argv item that policy must resolve before execution."""

    path: Path
    access: PathAccess = PathAccess.READ


@dataclass(frozen=True)
class CommandRequest:
    """Complete, shell-free command intent submitted to the policy seam."""

    executable: str
    arguments: tuple[str | PathArgument, ...] = ()
    cwd: Path | None = None
    environment: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 600.0
    max_output_bytes: int = 16 * 1024 * 1024
    max_memory_bytes: int | None = None
    max_cpu_seconds: int | None = None
    network_class: NetworkClass = NetworkClass.NONE

    def __post_init__(self) -> None:
        if not self.executable or "\x00" in self.executable:
            raise ValueError("executable must be a non-empty path or name")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if self.max_memory_bytes is not None and self.max_memory_bytes <= 0:
            raise ValueError("max_memory_bytes must be positive")
        if self.max_cpu_seconds is not None and self.max_cpu_seconds <= 0:
            raise ValueError("max_cpu_seconds must be positive")
        if any("\x00" in arg for arg in self.arguments if isinstance(arg, str)):
            raise ValueError("command arguments may not contain NUL bytes")


@dataclass(frozen=True)
class PolicyDecision:
    """Stable allow/deny result suitable for an audit receipt."""

    permitted: bool
    reason_code: str
    message: str
    resolved_executable: Path | None = None
    resolved_arguments: tuple[str, ...] = ()
    resolved_cwd: Path | None = None
    resolved_input_paths: tuple[Path, ...] = ()
    resolved_output_paths: tuple[Path, ...] = ()


_DANGEROUS_ENVIRONMENT = frozenset(
    {
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GCONV_PATH",
        "IFS",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "MULDER_TOOL_DELEGATION_GRANT",
        "MULDER_TOOL_DELEGATION_SECRET",
        "NODE_OPTIONS",
        "PERL5OPT",
        "PERLLIB",
        "PS4",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYLIB",
        "SHELLOPTS",
    }
)
_DANGEROUS_ENVIRONMENT_PREFIXES = ("DYLD_", "LD_")


def is_dangerous_environment_name(name: str) -> bool:
    """Return whether an environment name can alter loader/runtime behavior."""
    return name in _DANGEROUS_ENVIRONMENT or name.startswith(_DANGEROUS_ENVIRONMENT_PREFIXES)


@dataclass(frozen=True)
class CommandPolicy:
    """Capability bounds for one family of commands.

    Executables are pinned to resolved paths, so checking one binary and later
    executing another PATH result is not possible.  Filesystem locators are
    likewise resolved once and returned in the decision for use by the runner.
    """

    allowed_executables: frozenset[Path]
    allowed_roots: tuple[Path, ...] = ()
    allowed_network_classes: frozenset[NetworkClass] = field(
        default_factory=lambda: frozenset({NetworkClass.NONE})
    )
    allowed_environment_overrides: frozenset[str] = field(default_factory=frozenset)
    max_timeout_seconds: float = 28_800.0
    max_output_bytes: int = 64 * 1024 * 1024
    max_memory_bytes: int | None = None
    max_cpu_seconds: int | None = None

    @classmethod
    def for_executable(
        cls,
        executable: str | Path,
        *,
        allowed_roots: tuple[Path, ...] = (),
        max_timeout_seconds: float = 28_800.0,
        max_output_bytes: int = 64 * 1024 * 1024,
    ) -> CommandPolicy:
        """Build a narrow policy pinned to the executable resolved right now."""
        located = shutil.which(str(executable))
        candidate = Path(located) if located is not None else Path(executable)
        return cls(
            allowed_executables=frozenset({candidate.resolve(strict=False)}),
            allowed_roots=allowed_roots,
            max_timeout_seconds=max_timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def evaluate(self, request: CommandRequest) -> PolicyDecision:
        """Resolve and validate a request without starting a process."""
        located = shutil.which(request.executable)
        if located is None:
            candidate = Path(request.executable)
            if not candidate.is_absolute() or not candidate.exists():
                return PolicyDecision(False, "executable_not_found", "Executable was not found")
            located = str(candidate)
        try:
            resolved_executable = Path(located).resolve(strict=True)
        except (OSError, RuntimeError):
            return PolicyDecision(
                False,
                "executable_unresolvable",
                "Executable could not be resolved safely",
            )
        pinned = {path.resolve(strict=False) for path in self.allowed_executables}
        if resolved_executable not in pinned:
            return PolicyDecision(
                False,
                "executable_denied",
                "Resolved executable is not in the policy allowlist",
                resolved_executable=resolved_executable,
            )
        if request.network_class not in self.allowed_network_classes:
            return PolicyDecision(
                False,
                "network_class_denied",
                f"Network class {request.network_class.value!r} is not permitted",
                resolved_executable=resolved_executable,
            )
        if request.timeout_seconds > self.max_timeout_seconds:
            return PolicyDecision(
                False,
                "timeout_budget_denied",
                "Requested timeout exceeds the policy budget",
                resolved_executable=resolved_executable,
            )
        if request.max_output_bytes > self.max_output_bytes:
            return PolicyDecision(
                False,
                "output_budget_denied",
                "Requested output cap exceeds the policy budget",
                resolved_executable=resolved_executable,
            )
        if (
            self.max_memory_bytes is not None
            and request.max_memory_bytes is not None
            and request.max_memory_bytes > self.max_memory_bytes
        ):
            return PolicyDecision(
                False,
                "memory_budget_denied",
                "Requested memory limit exceeds the policy budget",
                resolved_executable=resolved_executable,
            )
        if (
            self.max_cpu_seconds is not None
            and request.max_cpu_seconds is not None
            and request.max_cpu_seconds > self.max_cpu_seconds
        ):
            return PolicyDecision(
                False,
                "cpu_budget_denied",
                "Requested CPU limit exceeds the policy budget",
                resolved_executable=resolved_executable,
            )

        environment_keys = frozenset(request.environment)
        forbidden = frozenset(
            name for name in environment_keys if is_dangerous_environment_name(name)
        )
        if forbidden:
            return PolicyDecision(
                False,
                "dangerous_environment_denied",
                f"Dangerous environment overrides are forbidden: {sorted(forbidden)}",
                resolved_executable=resolved_executable,
            )
        undeclared = environment_keys.difference(self.allowed_environment_overrides)
        if undeclared:
            return PolicyDecision(
                False,
                "environment_override_denied",
                f"Environment overrides are not declared: {sorted(undeclared)}",
                resolved_executable=resolved_executable,
            )

        try:
            resolved_cwd = (
                resolve_allowed_path(request.cwd, self.allowed_roots)
                if request.cwd is not None
                else None
            )
            resolved_arguments: list[str] = []
            resolved_inputs: list[Path] = []
            resolved_outputs: list[Path] = []
            for argument in request.arguments:
                if isinstance(argument, str):
                    resolved_arguments.append(argument)
                    continue
                resolved_path = resolve_allowed_path(argument.path, self.allowed_roots)
                resolved_arguments.append(str(resolved_path))
                if argument.access in {PathAccess.READ, PathAccess.READ_WRITE}:
                    resolved_inputs.append(resolved_path)
                if argument.access in {PathAccess.WRITE, PathAccess.READ_WRITE}:
                    resolved_outputs.append(resolved_path)
        except PathPolicyError:
            return PolicyDecision(
                False,
                "path_denied",
                "A command path is outside the declared roots",
                resolved_executable=resolved_executable,
            )
        return PolicyDecision(
            True,
            "permitted",
            "Command satisfies the declared execution policy",
            resolved_executable=resolved_executable,
            resolved_arguments=tuple(resolved_arguments),
            resolved_cwd=resolved_cwd,
            resolved_input_paths=tuple(resolved_inputs),
            resolved_output_paths=tuple(resolved_outputs),
        )


def dangerous_environment_names() -> frozenset[str]:
    """Return environment names stripped from every child process."""
    return _DANGEROUS_ENVIRONMENT
