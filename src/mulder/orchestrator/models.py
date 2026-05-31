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

from mulder.orchestrator.proxy import is_proxy_model

logger = logging.getLogger(__name__)

_BEDROCK_MODEL_MAP: dict[str, str] = {
    "claude-sonnet-4-6": "us.anthropic.claude-sonnet-4-6",
    "claude-sonnet-4-5": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "claude-opus-4-7": "us.anthropic.claude-opus-4-7",
    "claude-opus-4-8": "us.anthropic.claude-opus-4-8",
    "claude-haiku-4-5": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
}

_VERTEX_MODEL_MAP: dict[str, str] = {
    "claude-sonnet-4-6": "claude-sonnet-4-6@20250514",
    "claude-sonnet-4-5": "claude-sonnet-4-5@20250514",
    "claude-opus-4-7": "claude-opus-4-7@20250415",
    "claude-opus-4-8": "claude-opus-4-8@20250514",
    "claude-haiku-4-5": "claude-haiku-4-5@20250414",
}

_BUILT_IN_DEFAULTS: dict[str, str] = {
    "planner": "claude-sonnet-4-6",
    "executor": "claude-haiku-4-5",
    "analyst": "claude-sonnet-4-6",
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
    """

    planner: str = _BUILT_IN_DEFAULTS["planner"]
    executor: str = _BUILT_IN_DEFAULTS["executor"]
    analyst: str = _BUILT_IN_DEFAULTS["analyst"]
    phase_overrides: dict[str, dict[str, str]] = field(default_factory=dict)

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

        file_models: dict[str, str] = {}
        raw_models = file_config.get("models")
        if isinstance(raw_models, dict):
            file_models = {k: str(v) for k, v in raw_models.items()}

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

        planner, executor, analyst = _apply_provider_mapping(planner, executor, analyst)
        phase_overrides = _apply_provider_mapping_to_overrides(phase_overrides)

        return cls(
            planner=planner,
            executor=executor,
            analyst=analyst,
            phase_overrides=phase_overrides,
        )


def _is_explicit_provider_id(model: str) -> bool:
    """Return True if the model ID already targets a specific provider.

    Identifiers containing dots (e.g. ``us.anthropic.claude-sonnet-4-6``) or
    colons (e.g. versioned Bedrock ARNs) are assumed to be explicit and should
    not be re-mapped.

    Args:
        model: Model identifier to inspect.

    Returns:
        True when the identifier looks provider-specific.
    """
    return "." in model or ":" in model


def _apply_provider_mapping(
    planner: str,
    executor: str,
    analyst: str,
) -> tuple[str, str, str]:
    """Re-map Anthropic API model IDs to provider-specific inference profile IDs.

    Checks ``CLAUDE_CODE_USE_BEDROCK`` and ``CLAUDE_CODE_USE_VERTEX``
    environment variables (in that order). When one is set to ``"1"``, any
    model that appears in the corresponding mapping dict and does not already
    look like a provider ID is replaced.

    Args:
        planner: Resolved planner model identifier.
        executor: Resolved executor model identifier.
        analyst: Resolved analyst model identifier.

    Returns:
        Tuple of (planner, executor, analyst) after mapping.
    """
    mapping: dict[str, str] | None = None
    provider: str = ""

    if os.environ.get("CLAUDE_CODE_USE_BEDROCK") == "1":
        mapping = _BEDROCK_MODEL_MAP
        provider = "Bedrock"
    elif os.environ.get("CLAUDE_CODE_USE_VERTEX") == "1":
        mapping = _VERTEX_MODEL_MAP
        provider = "Vertex"

    if mapping is None:
        return planner, executor, analyst

    def _map(model: str) -> str:
        if _is_explicit_provider_id(model):
            return model
        mapped = mapping.get(model)
        if mapped is not None:
            logger.info("%s detected: mapping %s -> %s", provider, model, mapped)
            return mapped
        return model

    return _map(planner), _map(executor), _map(analyst)


def _apply_provider_mapping_to_overrides(
    phase_overrides: dict[str, dict[str, str]],
) -> dict[str, dict[str, str]]:
    """Re-map model IDs inside per-phase override dicts.

    Applies the same Bedrock/Vertex mapping logic used for role defaults to
    every value in ``phase_overrides``.

    Args:
        phase_overrides: Phase override dict to process.

    Returns:
        New dict with mapped model identifiers.
    """
    mapping: dict[str, str] | None = None
    provider: str = ""

    if os.environ.get("CLAUDE_CODE_USE_BEDROCK") == "1":
        mapping = _BEDROCK_MODEL_MAP
        provider = "Bedrock"
    elif os.environ.get("CLAUDE_CODE_USE_VERTEX") == "1":
        mapping = _VERTEX_MODEL_MAP
        provider = "Vertex"

    if mapping is None:
        return phase_overrides

    result: dict[str, dict[str, str]] = {}
    for phase, roles in phase_overrides.items():
        mapped_roles: dict[str, str] = {}
        for role, model in roles.items():
            if _is_explicit_provider_id(model):
                mapped_roles[role] = model
            elif model in mapping:
                logger.info("%s detected: mapping %s -> %s", provider, model, mapping[model])
                mapped_roles[role] = mapping[model]
            else:
                mapped_roles[role] = model
        result[phase] = mapped_roles
    return result


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
