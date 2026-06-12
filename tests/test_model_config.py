"""Tests for mulder.orchestrator.models -- ModelConfig resolution."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from mulder.orchestrator.models import (
    _BUILT_IN_DEFAULTS,
    ModelConfig,
)


class TestResolveRoleDefault:
    """resolve() returns role defaults when no phase override exists."""

    def test_planner_default(self) -> None:
        config = ModelConfig()
        assert config.resolve("extraction", "planner") == _BUILT_IN_DEFAULTS["planner"]

    def test_executor_default(self) -> None:
        config = ModelConfig()
        assert config.resolve("extraction", "executor") == _BUILT_IN_DEFAULTS["executor"]

    def test_analyst_default(self) -> None:
        config = ModelConfig()
        assert config.resolve("extraction", "analyst") == _BUILT_IN_DEFAULTS["analyst"]


class TestResolvePhaseOverride:
    """Phase-specific overrides take priority over role defaults."""

    def test_override_wins(self) -> None:
        config = ModelConfig(phase_overrides={"cross-system": {"planner": "claude-opus-4-7"}})
        assert config.resolve("cross-system", "planner") == "claude-opus-4-7"


class TestModelFallback:
    """--model sets all roles when per-role flags are not provided."""

    def test_fallback_sets_all_roles(self) -> None:
        config = ModelConfig.from_args(model="custom-model")
        assert config.planner == "custom-model"
        assert config.executor == "custom-model"
        assert config.analyst == "custom-model"

    def test_per_role_overrides_fallback(self) -> None:
        config = ModelConfig.from_args(model="custom-model", planner_model="planner-v2")
        assert config.planner == "planner-v2"
        assert config.executor == "custom-model"


class TestCliOverConfig:
    """CLI flags take precedence over config file values."""

    def test_cli_wins(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump({"models": {"planner": "from-file", "executor": "from-file"}})
        )
        config = ModelConfig.from_args(
            planner_model="from-cli",
            config_path=str(config_file),
        )
        assert config.planner == "from-cli"
        assert config.executor == "from-file"


class TestConfigFileLoading:
    """Valid YAML config files parse correctly."""

    def test_full_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "models": {
                        "planner": "file-planner",
                        "executor": "file-executor",
                        "analyst": "file-analyst",
                    },
                    "phases": {
                        "cross-system": {"planner": "opus-for-cross"},
                    },
                    "effort": "max",
                    "workers": 3,
                }
            )
        )
        config = ModelConfig.from_args(config_path=str(config_file))
        assert config.planner == "file-planner"
        assert config.executor == "file-executor"
        assert config.analyst == "file-analyst"
        assert config.phase_overrides == {"cross-system": {"planner": "opus-for-cross"}}

    def test_empty_config_uses_defaults(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")
        config = ModelConfig.from_args(config_path=str(config_file))
        assert config.planner == _BUILT_IN_DEFAULTS["planner"]


class TestConfigFileInvalid:
    """Malformed YAML or missing file produces a clear error."""

    def test_missing_file_raises(self) -> None:
        import click

        with pytest.raises(click.ClickException, match="not found"):
            ModelConfig.from_args(config_path="/nonexistent/config.yaml")

    def test_malformed_yaml_raises(self, tmp_path: Path) -> None:
        import click

        config_file = tmp_path / "bad.yaml"
        config_file.write_text("models:\n  planner: [\n  broken")
        with pytest.raises(click.ClickException, match="Malformed YAML"):
            ModelConfig.from_args(config_path=str(config_file))

    def test_non_mapping_raises(self, tmp_path: Path) -> None:
        import click

        config_file = tmp_path / "list.yaml"
        config_file.write_text("- item1\n- item2\n")
        with pytest.raises(click.ClickException, match="mapping"):
            ModelConfig.from_args(config_path=str(config_file))


class TestUnknownKeysWarning:
    """Unknown keys in config produce a warning log, not an error."""

    def test_unknown_keys_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({"models": {}, "banana": True}))

        with caplog.at_level(logging.WARNING, logger="mulder.orchestrator.models"):
            config = ModelConfig.from_args(config_path=str(config_file))
        assert "banana" in caplog.text
        assert config.planner == _BUILT_IN_DEFAULTS["planner"]


class TestCatalogUsesPlanner:
    """Catalog phase maps to planner role by design."""

    def test_catalog_resolves_to_planner_model(self) -> None:
        config = ModelConfig(planner="my-planner", executor="my-executor")
        assert config.resolve("catalog", "planner") == "my-planner"


class TestReportUsesAnalyst:
    """Report phase maps to analyst role by design."""

    def test_report_resolves_to_analyst_model(self) -> None:
        config = ModelConfig(analyst="my-analyst")
        assert config.resolve("report", "analyst") == "my-analyst"


class TestRequiresProxy:
    """Models with litellm prefix are flagged as needing proxy."""

    def test_proxy_model_detected(self) -> None:
        config = ModelConfig.from_args(planner_model="bedrock/meta.llama3-1-70b")
        assert config.requires_proxy is True

    def test_native_model_no_proxy(self) -> None:
        config = ModelConfig.from_args()
        assert config.requires_proxy is False

    def test_proxy_in_phase_override(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "models": {"planner": "claude-sonnet-4-6"},
                    "phases": {"extraction": {"executor": "openai/gpt-4o"}},
                }
            )
        )
        config = ModelConfig.from_args(config_path=str(config_file))
        assert config.requires_proxy is True
