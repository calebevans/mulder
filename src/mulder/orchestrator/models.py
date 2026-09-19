"""Model configuration and resolution for the investigation orchestrator.

Resolves model identifiers for each agent role (planner, executor, analyst)
from CLI flags, YAML config files, and built-in defaults. Resolution follows
a strict precedence chain: phase override > role default > --model fallback >
built-in default.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import click
import yaml

from mulder.orchestrator.proxy import ModelOverride, is_proxy_model

logger = logging.getLogger(__name__)

#: Env vars that override the same-named ``models:`` keys for every proxy
#: model in the run. A coarse knob for container runs with one model.
_OVERRIDE_ENV: dict[str, str] = {
    "context_window": "MULDER_MODEL_CONTEXT_WINDOW",
    "max_output_tokens": "MULDER_MODEL_MAX_OUTPUT_TOKENS",
    "reasoning": "MULDER_MODEL_REASONING",
}
_TRUE, _FALSE = {"1", "true", "yes", "on"}, {"0", "false", "no", "off"}


def _parse_override(raw: dict[str, Any], source: str, where: str) -> ModelOverride:
    """Validate one override mapping; values may be YAML-typed or env strings.

    Raises:
        click.ClickException: On an unknown key, a non-positive or non-integer
            token count, or a non-boolean ``reasoning``.
    """
    override = ModelOverride(sources=dict.fromkeys(raw, source))
    for key, value in raw.items():
        if key not in _OVERRIDE_ENV:
            raise click.ClickException(
                f"Unknown key {key!r} in {where}; expected {', '.join(_OVERRIDE_ENV)}"
            )
        label = _OVERRIDE_ENV[key] if source == "env" else f"{key} in {where}"
        if key == "reasoning":
            text = str(value).strip().lower()
            if text not in _TRUE | _FALSE:
                raise click.ClickException(f"{label} must be true or false, got {value!r}")
            override.reasoning = text in _TRUE
            continue
        if isinstance(value, bool) or not str(value).strip().isdigit() or int(value) <= 0:
            raise click.ClickException(f"{label} must be a positive integer, got {value!r}")
        setattr(override, key, int(value))
    return override


_BUILT_IN_DEFAULTS: dict[str, str] = {
    "planner": "claude-opus-4-6",
    "executor": "claude-haiku-4-5",
    "analyst": "claude-opus-4-6",
}

_KNOWN_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "models",
        "phases",
        "effort",
        "workers",
    }
)


@dataclass
class ModelConfig:
    """Model identifiers for each agent role with per-phase overrides.

    Attributes:
        planner: Model identifier for planner agents (catalog, planning).
        executor: Model identifier for executor agents (extraction, tools).
        analyst: Model identifier for analyst agents (analysis, reporting).
        phase_overrides: Per-phase model overrides keyed by phase name,
            with inner dicts mapping role names to model identifiers.
        model_overrides: Context/output/reasoning overrides keyed by model
            identifier, from the config file's ``models:`` mapping.
        env_override: The same overrides from ``MULDER_MODEL_*`` env vars,
            applied to every proxy model ahead of the file.
    """

    planner: str = _BUILT_IN_DEFAULTS["planner"]
    executor: str = _BUILT_IN_DEFAULTS["executor"]
    analyst: str = _BUILT_IN_DEFAULTS["analyst"]
    phase_overrides: dict[str, dict[str, str]] = field(default_factory=dict)
    model_overrides: dict[str, ModelOverride] = field(default_factory=dict)
    env_override: ModelOverride = field(default_factory=ModelOverride)

    def override_for(self, model: str) -> ModelOverride:
        """Effective user override for *model*: env over config file."""
        return self.env_override.merged_over(self.model_overrides.get(model, ModelOverride()))

    def resolve(self, phase: str, role: str) -> str:
        """Return the model identifier for a given phase and role.

        Resolution order:
            1. phase_overrides[phase][role]
            2. self.{role} (role default)

        Args:
            phase: Investigation phase name (e.g. "extraction", "catalog").
            role: Agent role name (e.g. "planner", "executor", "analyst").

        Returns:
            Resolved model identifier string.
        """
        phase_override = self.phase_overrides.get(phase, {})
        if role in phase_override:
            return phase_override[role]
        return getattr(self, role, _BUILT_IN_DEFAULTS.get(role, self.planner))

    @property
    def requires_proxy(self) -> bool:
        """Whether any configured model needs a LiteLLM proxy.

        Checks all role defaults and all phase override values for
        provider prefixes (e.g. ``bedrock/``, ``openai/``).

        Returns:
            True if at least one model uses a litellm provider prefix.
        """
        role_models = [self.planner, self.executor, self.analyst]
        for overrides in self.phase_overrides.values():
            role_models.extend(overrides.values())
        return any(is_proxy_model(m) for m in role_models)

    @classmethod
    def from_args(
        cls,
        model: str | None = None,
        planner_model: str | None = None,
        executor_model: str | None = None,
        analyst_model: str | None = None,
        config_path: str | None = None,
    ) -> ModelConfig:
        """Construct a ModelConfig from CLI arguments and optional YAML config.

        Precedence (highest to lowest):
            1. Explicit per-role CLI flags (``planner_model``, etc.)
            2. Config file role values (``models.planner``, etc.)
            3. ``--model`` fallback (sets all roles)
            4. Built-in defaults

        Args:
            model: Fallback model that sets all roles when per-role
                flags are not provided.
            planner_model: Explicit planner model from CLI.
            executor_model: Explicit executor model from CLI.
            analyst_model: Explicit analyst model from CLI.
            config_path: Path to a YAML configuration file.

        Returns:
            Fully resolved ModelConfig instance.

        Raises:
            click.ClickException: If the config file is missing or malformed.
        """
        file_config = _load_config_file(config_path) if config_path else {}

        # ``models:`` holds both role assignments (string values) and
        # per-model overrides (mapping values keyed by the model id).
        file_models: dict[str, str] = {}
        model_overrides: dict[str, ModelOverride] = {}
        raw_models = file_config.get("models")
        if isinstance(raw_models, dict):
            for key, value in raw_models.items():
                if isinstance(value, dict):
                    model_overrides[str(key)] = _parse_override(
                        value, "config", f"models.{key} in {config_path}"
                    )
                else:
                    file_models[str(key)] = str(value)

        env_raw = {k: os.environ[v] for k, v in _OVERRIDE_ENV.items() if v in os.environ}
        env_override = _parse_override(env_raw, "env", "MULDER_MODEL_* environment")

        phase_overrides: dict[str, dict[str, str]] = {}
        raw_phases = file_config.get("phases")
        if isinstance(raw_phases, dict):
            for phase_name, roles in raw_phases.items():
                if isinstance(roles, dict):
                    phase_overrides[str(phase_name)] = {str(k): str(v) for k, v in roles.items()}

        fallback = model or ""

        planner = (
            planner_model
            or file_models.get("planner")
            or fallback
            or _BUILT_IN_DEFAULTS["planner"]
        )
        executor = (
            executor_model
            or file_models.get("executor")
            or fallback
            or _BUILT_IN_DEFAULTS["executor"]
        )
        analyst = (
            analyst_model
            or file_models.get("analyst")
            or fallback
            or _BUILT_IN_DEFAULTS["analyst"]
        )

        return cls(
            planner=planner,
            executor=executor,
            analyst=analyst,
            phase_overrides=phase_overrides,
            model_overrides=model_overrides,
            env_override=env_override,
        )


def _load_config_file(config_path: str) -> dict[str, Any]:
    """Load and validate a YAML configuration file.

    Args:
        config_path: Filesystem path to the YAML config.

    Returns:
        Parsed configuration dictionary.

    Raises:
        click.ClickException: If the file is not found, is malformed YAML,
            or is not a mapping at the top level.
    """
    path = Path(config_path)
    if not path.exists():
        raise click.ClickException(f"Config file not found: {config_path}")

    raw_text = path.read_text(encoding="utf-8")
    if not raw_text.strip():
        return {}

    try:
        parsed: object = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise click.ClickException(f"Malformed YAML in config file {config_path}: {exc}") from exc

    if parsed is None:
        return {}

    if not isinstance(parsed, dict):
        raise click.ClickException(
            f"Config file {config_path} must be a YAML mapping, got {type(parsed).__name__}"
        )

    unknown_keys = set(parsed.keys()) - _KNOWN_CONFIG_KEYS
    if unknown_keys:
        logger.warning(
            "Unknown keys in config file %s: %s",
            config_path,
            ", ".join(sorted(unknown_keys)),
        )

    return parsed
