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
from dataclasses import dataclass, field
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
_MASTER_KEY: str = "sk-mulder-proxy"

#: Output tokens reserved per request for proxy-routed models LiteLLM
#: positively reports as non-reasoning. Doubles as the LiteLLM ``max_tokens``
#: default and as ``CLAUDE_CODE_MAX_OUTPUT_TOKENS`` for the session, because
#: the CLI's explicit value (32000 for model IDs it does not recognise) would
#: otherwise override the proxy default.
PROXY_MAX_OUTPUT_TOKENS: int = 8192

#: Same, for models that reason and for models LiteLLM's map does not know.
#: Reasoning tokens count against ``max_tokens`` and a truncated reasoning
#: chain yields no tool call, so these get Claude Code's own default cap
#: (32000, rounded). An unknown model may reason unasked (Kimi K3 does) and
#: one that does not never uses the headroom. Claude Code's auto-compact
#: reserve is ``min(cap, 20000) + 13000``, so going above 20000 costs no more
#: context. See issue #203.
PROXY_REASONING_MAX_OUTPUT_TOKENS: int = 32768

_OVERRIDE_FIELDS: tuple[str, ...] = ("context_window", "max_output_tokens", "reasoning")


@dataclass
class ModelOverride:
    """User-supplied limits for one proxy model (``--config`` or env).

    ``None`` means "not set"; :attr:`sources` names where each set field
    came from (``config`` or ``env``) for the startup log.
    """

    context_window: int | None = None
    max_output_tokens: int | None = None
    reasoning: bool | None = None
    sources: dict[str, str] = field(default_factory=dict)

    def merged_over(self, other: ModelOverride) -> ModelOverride:
        """A copy of *other* with every field set on ``self`` replacing it."""
        merged = ModelOverride(sources={**other.sources, **self.sources})
        for name in _OVERRIDE_FIELDS:
            mine = getattr(self, name)
            setattr(merged, name, getattr(other, name) if mine is None else mine)
        return merged


@dataclass
class ModelSettings:
    """Effective limits for one proxy model, with the source of each.

    The defaults describe a model nobody knows anything about: no window
    (Claude Code keeps its own), the reasoning-sized cap, no passthrough.
    """

    context_window: int | None = None
    max_output_tokens: int = PROXY_REASONING_MAX_OUTPUT_TOKENS
    reasoning: bool = False
    sources: dict[str, str] = field(default_factory=dict)
    #: Whether LiteLLM's model map knows the model; decides its route.
    known: bool = False

    def __str__(self) -> str:
        src = self.sources.get
        return (
            f"context_window={self.context_window or 'unknown'} "
            f"({src('context_window', 'default')}), "
            f"max_output_tokens={self.max_output_tokens} "
            f"({src('max_output_tokens', 'default')}), "
            f"reasoning={self.reasoning} ({src('reasoning', 'default')})"
        )


def resolve_settings(
    override: ModelOverride, litellm_reasoning: bool | None, thinking: bool = True
) -> ModelSettings:
    """Combine an override with what LiteLLM said: override > LiteLLM > default.

    Args:
        override: User overrides for the model (possibly all unset).
        litellm_reasoning: ``litellm.supports_reasoning`` for the model, or
            ``None`` when LiteLLM's map does not know it.
        thinking: False (``--no-thinking``) forces reasoning off.

    Returns:
        Settings without a LiteLLM context window; :meth:`ProxyManager.start`
        fills that in from the running proxy.
    """
    s = ModelSettings(sources=dict(override.sources), known=litellm_reasoning is not None)
    if not thinking:
        s.reasoning, s.sources["reasoning"] = False, "--no-thinking"
    elif override.reasoning is not None:
        s.reasoning = override.reasoning
    elif litellm_reasoning is not None:
        s.reasoning, s.sources["reasoning"] = litellm_reasoning, "litellm"
    if override.max_output_tokens is not None:
        s.max_output_tokens = override.max_output_tokens
    elif litellm_reasoning is False and not s.reasoning:
        s.max_output_tokens = PROXY_MAX_OUTPUT_TOKENS
    if override.context_window is not None:
        s.context_window = override.context_window
    return s


#: LiteLLM's ``/v1/messages`` adapter turns Claude Code's ``thinking`` +
#: ``output_config.effort`` into ``reasoning_effort``; Bedrock's Converse
#: mapping then rewrites that back into Anthropic's ``thinking`` block, which
#: DeepSeek (and other non-Claude reasoning models) silently ignore. Listing
#: the param here makes LiteLLM forward the raw string instead, which is the
#: shape those models honour. See issue #193.
_REASONING_PARAMS: list[str] = ["reasoning_effort"]

#: LiteLLM's Bedrock Converse config lists ``tools`` as a supported param
#: only for model families it hard-codes or for models whose map entry says
#: ``supports_function_calling``. For an unmapped model neither holds, so
#: ``drop_params: true`` silently strips ``tools`` from every request (the
#: Converse body goes out without ``toolConfig``) and the model can only
#: answer in text. Allowing the param explicitly skips that check; the
#: Converse transformation and stream decoder handle ``toolUse`` for any
#: model. ``model_info.supports_function_calling`` does not work here: the
#: router registers it under ``bedrock/...`` while the check looks up
#: ``bedrock_converse/...``. See issue #207.
_UNMAPPED_BEDROCK_PARAMS: list[str] = ["tools"]


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


def _litellm_model(model_id: str, known: bool = True) -> str:
    """The provider route LiteLLM should use for a public model name.

    Ollama models go through the native chat API so streamed tool calls
    retain their structure. Bedrock models LiteLLM's map does not know go
    through the explicit Converse route: for an unmapped ``bedrock/`` id
    LiteLLM 1.101.0 infers the provider from the id (``moonshot`` for Kimi)
    and streams back an empty ``end_turn`` with no error. Everything else
    is served as named.

    Args:
        model_id: Public model name.
        known: Whether LiteLLM's model map knows the model.
    """
    if model_id.startswith("ollama/"):
        return "ollama_chat/" + model_id.removeprefix("ollama/")
    if model_id.startswith("bedrock/") and not known:
        return "bedrock/converse/" + model_id.removeprefix("bedrock/")
    return model_id


def _build_proxy_config(
    models: list[str], port: int, settings: dict[str, ModelSettings] | None = None
) -> dict[str, Any]:
    """Build a LiteLLM proxy configuration for the given models.

    Preserves each public model name while routing Ollama models through
    the native chat API so streamed tool calls retain their structure.
    Each model's ``max_tokens`` and raw ``reasoning_effort`` passthrough
    (see :data:`_REASONING_PARAMS`) come from its :class:`ModelSettings`;
    a model without settings is served as unknown. An unmapped ``bedrock/``
    model also gets ``tools`` allowed explicitly (see
    :data:`_UNMAPPED_BEDROCK_PARAMS`).

    Args:
        models: Unique litellm model IDs to serve.
        port: Port number for the proxy server.
        settings: Effective limits per public model name.

    Returns:
        LiteLLM config dict suitable for YAML serialization.
    """
    model_list = []
    for model_id in models:
        s = (settings or {}).get(model_id) or ModelSettings()
        route = _litellm_model(model_id, s.known)
        allowed: list[str] = []
        if s.reasoning:
            allowed += _REASONING_PARAMS
        if route.startswith("bedrock/converse/"):
            allowed += _UNMAPPED_BEDROCK_PARAMS
        model_list.append(
            {
                "model_name": model_id,
                "litellm_params": {
                    "model": route,
                    "max_tokens": s.max_output_tokens,
                    **({"allowed_openai_params": allowed} if allowed else {}),
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
            "master_key": _MASTER_KEY,
        },
    }


_SUPPORTS_REASONING_SCRIPT = """\
import json, sys, litellm
def check(m):
    try:
        litellm.get_model_info(m)
    except Exception:
        return None
    try:
        return bool(litellm.supports_reasoning(model=m))
    except Exception:
        return False
print(json.dumps({m: check(m) for m in sys.argv[1:]}))
"""


def litellm_reasoning(
    litellm_bin: str, models: list[str], timeout: float = 60.0
) -> dict[str, bool | None]:
    """What LiteLLM's model map says about reasoning support for *models*.

    Runs :func:`litellm.supports_reasoning` inside LiteLLM's own venv (the
    interpreter next to the ``litellm`` binary) so litellm stays out of
    mulder's venv. Any failure yields an empty mapping with a warning, which
    means "serve as unknown" rather than "refuse to start".

    Args:
        litellm_bin: Resolved path of the ``litellm`` executable.
        models: Public model names as passed on the command line.
        timeout: Seconds to wait for the check.

    Returns:
        Public name to ``True``/``False`` for models in LiteLLM's map and
        ``None`` for models it does not know.
    """
    import json

    python = Path(litellm_bin).resolve().parent / "python"
    if not python.exists():
        logger.warning("No interpreter next to %s; serving without reasoning", litellm_bin)
        return {}
    try:
        proc = subprocess.run(
            [str(python), "-c", _SUPPORTS_REASONING_SCRIPT, *(_litellm_model(m) for m in models)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        supported = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        logger.warning("Could not query LiteLLM for reasoning support: %s", exc)
        return {}
    return {m: supported.get(_litellm_model(m)) for m in models}


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


def fetch_model_windows(port: int, timeout: float = 5.0) -> dict[str, int]:
    """Read each served model's context window from the running proxy.

    LiteLLM's ``/model_group/info`` reports ``max_input_tokens`` per public
    model name from its ``model_prices_and_context_window`` map. Claude Code
    assumes a 200K window for model IDs it does not recognise, so the real
    window is handed to each session as ``CLAUDE_CODE_MAX_CONTEXT_TOKENS``
    (see :mod:`mulder.orchestrator.session`). Reading it over HTTP keeps
    litellm out of mulder's venv.

    Args:
        port: Port the proxy is listening on.
        timeout: Seconds to wait for the endpoint.

    Returns:
        Mapping of model name to context window in tokens. Models the map
        does not know are omitted; any failure yields an empty mapping.
    """
    import json
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"http://localhost:{port}/model_group/info",
        headers={"Authorization": f"Bearer {_MASTER_KEY}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        logger.warning("Could not read model windows from proxy: %s", exc)
        return {}

    windows: dict[str, int] = {}
    entries = payload.get("data") if isinstance(payload, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        name, window = entry.get("model_group"), entry.get("max_input_tokens")
        if isinstance(name, str) and isinstance(window, (int, float)) and window > 0:
            windows[name] = int(window)
    return windows


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
        thinking: bool = True,
        overrides: dict[str, ModelOverride] | None = None,
    ) -> None:
        """Initialize the proxy manager.

        Args:
            models: LiteLLM model IDs that need proxy routing.
            port: Port for the proxy server. Defaults to 4000 or the
                value of MULDER_PROXY_PORT env var.
            config_path: Optional path to a user-provided LiteLLM config
                YAML. When provided, the auto-generated config is skipped
                and this file is used instead.
            thinking: Enable reasoning for models that support it. False
                (``--no-thinking``) serves every model without it.
            overrides: User limits per public model name; they beat
                whatever LiteLLM reports.
        """
        import os

        self._models = models
        self._port = port or int(os.environ.get("MULDER_PROXY_PORT", _DEFAULT_PORT))
        self._config_path = config_path
        self._thinking = thinking
        self._overrides = overrides or {}
        self._process: subprocess.Popen[bytes] | None = None
        self._temp_config: Path | None = None
        #: Effective limits per public model name; filled by :meth:`start`.
        self.settings: dict[str, ModelSettings] = {}

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
            "ANTHROPIC_AUTH_TOKEN": _MASTER_KEY,
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

        # The route of a bedrock/ model depends on whether LiteLLM knows it,
        # so the map is consulted whenever the config is ours to generate.
        queried = not self._config_path
        known = litellm_reasoning(litellm_bin, self._models) if queried else {}
        for model in self._models:
            override = self._overrides.get(model) or ModelOverride()
            s = resolve_settings(override, known.get(model), self._thinking)
            self.settings[model] = s
            if queried and self._thinking and override.reasoning is None and not s.reasoning:
                logger.warning(
                    "Thinking is on but LiteLLM reports no reasoning support for %s; "
                    "it will run without reasoning (pass --no-thinking to silence)",
                    model,
                )

        if self._config_path:
            config_file = self._config_path
        else:
            config = _build_proxy_config(self._models, self._port, self.settings)
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
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=proxy_env,
        )

        if not _wait_for_health(self._port):
            self.stop()
            raise RuntimeError(
                f"LiteLLM proxy failed to start within {_HEALTH_CHECK_TIMEOUT}s. "
                f"Models: {self._models}"
            )

        logger.info("LiteLLM proxy is healthy on port %d", self._port)

        windows = fetch_model_windows(self._port)
        for model, s in self.settings.items():
            if s.context_window is None and model in windows:
                s.context_window, s.sources["context_window"] = windows[model], "litellm"
            logger.info("%s: %s", model, s)

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
