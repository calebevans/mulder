"""LiteLLM proxy management for non-Claude model routing.

Provides automatic proxy lifecycle management so the Claude Agent SDK
can communicate with any LiteLLM-supported model provider (Bedrock
non-Claude models, OpenAI, Vertex AI, Ollama). The proxy is started
as a subprocess and stopped when the orchestrator completes.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_LITELLM_PREFIXES: tuple[str, ...] = (
    "bedrock/",
    "openai/",
    "vertex_ai/",
    "azure/",
    "ollama/",
)

_DEFAULT_PORT: int = 4000
_HEALTH_CHECK_TIMEOUT: float = 30.0
_HEALTH_CHECK_INTERVAL: float = 0.5


def is_proxy_model(model_id: str) -> bool:
    """Determine whether a model ID requires routing through a LiteLLM proxy.

    Model IDs using a provider prefix (e.g., ``bedrock/meta.llama3-1-70b``)
    are not natively understood by the Claude Agent SDK and must be routed
    through a LiteLLM proxy that translates the Anthropic API format.

    Args:
        model_id: The model identifier to check.

    Returns:
        True if the model needs proxy routing.
    """
    return any(model_id.startswith(prefix) for prefix in _LITELLM_PREFIXES)


def _build_proxy_config(models: list[str], port: int) -> dict[str, Any]:
    """Build a LiteLLM proxy configuration for the given models.

    Creates a minimal config that maps each litellm model ID to itself,
    enabling the proxy to route requests based on the model name in the
    incoming Anthropic API payload.

    Args:
        models: Unique litellm model IDs to serve.
        port: Port number for the proxy server.

    Returns:
        LiteLLM config dict suitable for YAML serialization.
    """
    model_list = []
    for model_id in models:
        model_list.append(
            {
                "model_name": model_id,
                "litellm_params": {
                    "model": model_id,
                    "max_tokens": 8192,
                },
            }
        )

    return {
        "model_list": model_list,
        "litellm_settings": {
            "drop_params": True,
            "num_retries": 2,
            "set_verbose": False,
            "modify_params": True,
        },
        "general_settings": {
            "master_key": "sk-mulder-proxy",
        },
    }


def _wait_for_health(port: int, timeout: float = _HEALTH_CHECK_TIMEOUT) -> bool:
    """Wait for the LiteLLM proxy to become healthy.

    Polls the proxy health endpoint until it responds or the timeout
    expires.

    Args:
        port: Port the proxy is listening on.
        timeout: Maximum seconds to wait.

    Returns:
        True if the proxy became healthy within the timeout.
    """
    import urllib.error
    import urllib.request

    urls = [
        f"http://localhost:{port}/health/liveliness",
        f"http://localhost:{port}/health",
        f"http://localhost:{port}/",
    ]
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        for url in urls:
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=2) as resp:
                    if resp.status < 400:
                        return True
            except (urllib.error.URLError, OSError, TimeoutError):
                pass
        time.sleep(_HEALTH_CHECK_INTERVAL)

    return False


class ProxyManager:
    """Manages the lifecycle of a local LiteLLM proxy subprocess.

    Intended for use as a context manager. Starts the proxy on enter,
    stops it on exit.

    Example::

        async with ProxyManager(models=["bedrock/meta.llama3-1-70b"]) as pm:
            env_overrides = pm.env_overrides
            # ... run orchestrator with env_overrides applied
    """

    def __init__(
        self,
        models: list[str],
        port: int | None = None,
        config_path: str | None = None,
    ) -> None:
        """Initialize the proxy manager.

        Args:
            models: LiteLLM model IDs that need proxy routing.
            port: Port for the proxy server. Defaults to 4000 or the
                value of MULDER_PROXY_PORT env var.
            config_path: Optional path to a user-provided LiteLLM config
                YAML. When provided, the auto-generated config is skipped
                and this file is used instead.
        """
        import os

        self._models = models
        self._port = port or int(os.environ.get("MULDER_PROXY_PORT", _DEFAULT_PORT))
        self._config_path = config_path
        self._process: subprocess.Popen[bytes] | None = None
        self._temp_config: Path | None = None

    @property
    def port(self) -> int:
        """The port the proxy is running on."""
        return self._port

    @property
    def env_overrides(self) -> dict[str, str]:
        """Environment variables to route the SDK through the proxy.

        These must be merged into the orchestrator's env dict so that
        agent SDK sessions route API calls through the local proxy
        instead of directly to Anthropic. Bedrock/Vertex flags are
        explicitly disabled so the SDK uses standard API routing (the
        proxy handles provider translation).
        """
        return {
            "ANTHROPIC_BASE_URL": f"http://localhost:{self._port}",
            "ANTHROPIC_AUTH_TOKEN": "sk-mulder-proxy",
            "CLAUDE_CODE_USE_BEDROCK": "0",
            "CLAUDE_CODE_USE_VERTEX": "0",
            "CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY": "1",
        }

    def start(self) -> None:
        """Start the LiteLLM proxy subprocess.

        LiteLLM is installed in an isolated venv (/opt/litellm) due to
        dependency conflicts with mulder's mcp and rich versions. The
        ``litellm`` binary is symlinked to /usr/local/bin.

        Raises:
            RuntimeError: If litellm is not installed or the proxy fails
                to start within the health check timeout.
        """
        import os
        import shutil

        litellm_bin = shutil.which("litellm")
        if litellm_bin is None:
            raise RuntimeError(
                "LiteLLM is not installed. Install with: "
                "pip install 'litellm[proxy]' or rebuild the Docker image."
            )

        if self._config_path:
            config_file = self._config_path
        else:
            config = _build_proxy_config(self._models, self._port)
            fd, tmp_path = tempfile.mkstemp(suffix=".yaml", prefix="mulder_litellm_")
            self._temp_config = Path(tmp_path)
            os.close(fd)
            self._temp_config.write_text(
                yaml.dump(config, default_flow_style=False), encoding="utf-8"
            )
            config_file = str(self._temp_config)

        cmd = [
            litellm_bin,
            "--config",
            config_file,
            "--port",
            str(self._port),
            "--num_workers",
            "1",
        ]

        logger.info(
            "Starting LiteLLM proxy on port %d for models: %s",
            self._port,
            self._models,
        )

        proxy_env = os.environ.copy()

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=proxy_env,
        )

        if not _wait_for_health(self._port):
            stderr_output = ""
            if self._process and self._process.stderr:
                stderr_output = self._process.stderr.read().decode(errors="replace")[:500]
            self.stop()
            raise RuntimeError(
                f"LiteLLM proxy failed to start within {_HEALTH_CHECK_TIMEOUT}s. "
                f"Models: {self._models}\n"
                f"Stderr: {stderr_output}"
            )

        logger.info("LiteLLM proxy is healthy on port %d", self._port)

    def stop(self) -> None:
        """Stop the proxy subprocess and clean up temporary files."""
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=3)
            self._process = None
            logger.info("LiteLLM proxy stopped")

        if self._temp_config and self._temp_config.exists():
            self._temp_config.unlink()
            self._temp_config = None

    def __enter__(self) -> ProxyManager:
        """Start the proxy on context entry."""
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        """Stop the proxy on context exit."""
        self.stop()
