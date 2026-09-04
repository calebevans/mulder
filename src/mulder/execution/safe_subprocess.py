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

CalledProcessError = _subprocess.CalledProcessError
CompletedProcess = _subprocess.CompletedProcess
SubprocessError = _subprocess.SubprocessError
TimeoutExpired = _subprocess.TimeoutExpired
DEVNULL = _subprocess.DEVNULL

_INHERITED_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "COLORTERM",
        "COMSPEC",
        "HOME",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "TZ",
        "USER",
        "WINDIR",
    }
)

# A model proxy is an explicitly authorized egress adapter and therefore needs
# a narrowly enumerated set of provider configuration values.  This list is
# deliberately separate from the forensic-child allowlist above: parser and
# helper processes must never inherit provider credentials.
_PROVIDER_PROXY_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_CONFIG_FILE",
        "AWS_DEFAULT_REGION",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_ROLE_ARN",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AZURE_AD_TOKEN",
        "AZURE_API_BASE",
        "AZURE_API_KEY",
        "AZURE_API_VERSION",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        "DO_NOT_TRACK",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_LOCATION",
        "GOOGLE_CLOUD_PROJECT",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "MULDER_ZERO_EGRESS",
        "NO_PROXY",
        "OLLAMA_API_BASE",
        "OLLAMA_HOST",
        "OPENAI_API_BASE",
        "OPENAI_API_KEY",
        "OTEL_SDK_DISABLED",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "VERTEXAI_LOCATION",
        "VERTEXAI_PROJECT",
    }
)


def sanitized_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the minimal inherited environment for forensic child processes.

    An allowlist is safer than trying to enumerate every present and future
    credential or runtime injection variable.  Overrides are constrained by
    the same allowlist, so a caller cannot reintroduce a secret accidentally.
    """
    values = dict(os.environ)
    if overrides is not None:
        values.update(overrides)
    environment = {
        key: value
        for key, value in values.items()
        if key in _INHERITED_ENVIRONMENT_ALLOWLIST
    }
    return environment


def provider_proxy_environment(
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the least-authority environment for the model proxy adapter."""
    values = dict(os.environ)
    if overrides is not None:
        values.update(overrides)
    allowed = _INHERITED_ENVIRONMENT_ALLOWLIST | _PROVIDER_PROXY_ENVIRONMENT_ALLOWLIST
    return {key: value for key, value in values.items() if key in allowed}


def popen(
    args: Sequence[str] | str,
    *popenargs: Any,
    provider_process: bool = False,
    **kwargs: Any,
) -> _subprocess.Popen[Any]:
    """Launch a child using the appropriate explicit environment policy."""
    environment = kwargs.get("env")
    kwargs["env"] = (
        provider_proxy_environment(environment)
        if provider_process
        else sanitized_environment(environment)
    )
    return _subprocess.Popen(args, *popenargs, **kwargs)


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
    "DEVNULL",
    "SubprocessError",
    "TimeoutExpired",
    "popen",
    "provider_proxy_environment",
    "run",
    "sanitized_environment",
]
