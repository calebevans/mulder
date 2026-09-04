"""Subprocess compatibility seam with a scrubbed child environment by default.

The MCP server carries a signed delegation grant in its own environment.  That
credential is for server-side authorization only and must never be inherited by
forensic parsers or installer/helper processes.  Import this module as
``subprocess`` at direct process-launch sites so omission of ``env=`` is safe.
"""

from __future__ import annotations

import os
import subprocess as _subprocess
from collections.abc import Mapping, Sequence
from typing import Any

from mulder.execution.policy import is_dangerous_environment_name

CalledProcessError = _subprocess.CalledProcessError
CompletedProcess = _subprocess.CompletedProcess
SubprocessError = _subprocess.SubprocessError
TimeoutExpired = _subprocess.TimeoutExpired


def sanitized_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return an inherited environment without credentials or loader controls.

    Overrides are filtered too.  A caller cannot accidentally re-introduce the
    delegation grant, delegation signing secret, or another dangerous runtime
    variable by supplying a custom environment mapping.
    """
    environment = {
        key: value
        for key, value in os.environ.items()
        if not is_dangerous_environment_name(key)
    }
    if overrides is not None:
        environment.update(
            (key, value)
            for key, value in overrides.items()
            if not is_dangerous_environment_name(key)
        )
    return environment


def run(
    args: Sequence[str] | str,
    *popenargs: Any,
    **kwargs: Any,
) -> _subprocess.CompletedProcess[Any]:
    """Call :func:`subprocess.run` with a centrally sanitized environment."""
    kwargs["env"] = sanitized_environment(kwargs.get("env"))
    return _subprocess.run(args, *popenargs, **kwargs)


__all__ = [
    "CalledProcessError",
    "CompletedProcess",
    "SubprocessError",
    "TimeoutExpired",
    "run",
    "sanitized_environment",
]
