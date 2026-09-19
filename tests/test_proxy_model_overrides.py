"""Proxy models LiteLLM does not know default to the reasoning output cap, and
``--config`` ``models:`` entries or ``MULDER_MODEL_*`` env vars override what
LiteLLM reports (issue #203)."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import click
import pytest
import yaml

from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.proxy import (
    PROXY_MAX_OUTPUT_TOKENS,
    PROXY_REASONING_MAX_OUTPUT_TOKENS,
    ModelOverride,
    ModelSettings,
    ProxyManager,
    _build_proxy_config,
    resolve_settings,
)
from mulder.orchestrator.runner import Orchestrator

KIMI = "bedrock/us.moonshotai.kimi-k3"
LLAMA = "bedrock/meta.llama3-3-70b-instruct-v1:0"
KIMI_YAML = {"context_window": 262144, "max_output_tokens": 32768, "reasoning": True}
ENV = {
    "MULDER_MODEL_CONTEXT_WINDOW": "131072",
    "MULDER_MODEL_MAX_OUTPUT_TOKENS": "16384",
    "MULDER_MODEL_REASONING": "false",
}


def _config(tmp_path: Path, models: dict[str, object]) -> ModelConfig:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"models": models}))
    return ModelConfig.from_args(config_path=str(path))


class TestResolveSettings:
    def test_unknown_model_gets_reasoning_cap(self) -> None:
        s = resolve_settings(ModelOverride(), None)
        assert (s.max_output_tokens, s.reasoning, s.context_window) == (
            PROXY_REASONING_MAX_OUTPUT_TOKENS,
            False,
            None,
        )
        assert "default" in str(s)

    def test_litellm_non_reasoning_keeps_small_cap(self) -> None:
        s = resolve_settings(ModelOverride(), False)
        assert s.max_output_tokens == PROXY_MAX_OUTPUT_TOKENS
        assert s.sources == {"reasoning": "litellm"}

    def test_litellm_reasoning(self) -> None:
        s = resolve_settings(ModelOverride(), True)
        assert (s.max_output_tokens, s.reasoning) == (PROXY_REASONING_MAX_OUTPUT_TOKENS, True)

    def test_config_wins_over_litellm(self) -> None:
        override = ModelOverride(
            context_window=262144,
            reasoning=True,
            sources={"context_window": "config", "reasoning": "config"},
        )
        s = resolve_settings(override, False)
        assert (s.context_window, s.reasoning) == (262144, True)
        assert s.max_output_tokens == PROXY_REASONING_MAX_OUTPUT_TOKENS
        assert str(s) == (
            "context_window=262144 (config), max_output_tokens=32768 (default), "
            "reasoning=True (config)"
        )

    def test_no_thinking_beats_everything(self) -> None:
        s = resolve_settings(ModelOverride(reasoning=True), True, thinking=False)
        assert s.reasoning is False
        assert s.sources["reasoning"] == "--no-thinking"


class TestConfigFile:
    def test_models_mapping_holds_roles_and_overrides(self, tmp_path: Path) -> None:
        config = _config(tmp_path, {"planner": KIMI, KIMI: KIMI_YAML})
        assert config.planner == KIMI
        override = config.override_for(KIMI)
        assert (override.context_window, override.max_output_tokens, override.reasoning) == (
            262144,
            32768,
            True,
        )
        assert override.sources == dict.fromkeys(KIMI_YAML, "config")
        assert config.override_for(LLAMA) == ModelOverride()

    def test_env_wins_over_config(self, tmp_path: Path) -> None:
        with patch.dict("os.environ", ENV):
            config = _config(tmp_path, {KIMI: KIMI_YAML})
        override = config.override_for(KIMI)
        assert (override.context_window, override.max_output_tokens, override.reasoning) == (
            131072,
            16384,
            False,
        )
        assert set(override.sources.values()) == {"env"}
        assert config.override_for(LLAMA).context_window == 131072

    def test_partial_env_keeps_the_rest_of_config(self, tmp_path: Path) -> None:
        with patch.dict("os.environ", {"MULDER_MODEL_REASONING": "yes"}):
            config = _config(tmp_path, {KIMI: {"context_window": 262144, "reasoning": False}})
        override = config.override_for(KIMI)
        assert (override.context_window, override.reasoning) == (262144, True)
        assert override.sources == {"context_window": "config", "reasoning": "env"}

    @pytest.mark.parametrize(
        ("entry", "message"),
        [
            ({"context_window": "big"}, "context_window in models.* must be a positive integer"),
            ({"max_output_tokens": 0}, "max_output_tokens .* must be a positive integer"),
            ({"max_output_tokens": True}, "max_output_tokens .* must be a positive integer"),
            ({"reasoning": "maybe"}, "reasoning .* must be true or false"),
            ({"window": 1}, "Unknown key 'window'"),
        ],
    )
    def test_malformed_config_value(
        self, tmp_path: Path, entry: dict[str, object], message: str
    ) -> None:
        with pytest.raises(click.ClickException, match=message):
            _config(tmp_path, {KIMI: entry})

    @pytest.mark.parametrize(
        ("var", "value", "message"),
        [
            (
                "MULDER_MODEL_CONTEXT_WINDOW",
                "-1",
                "MULDER_MODEL_CONTEXT_WINDOW must be a positive",
            ),
            ("MULDER_MODEL_MAX_OUTPUT_TOKENS", "8k", "MULDER_MODEL_MAX_OUTPUT_TOKENS must be"),
            (
                "MULDER_MODEL_REASONING",
                "sometimes",
                "MULDER_MODEL_REASONING must be true or false",
            ),
        ],
    )
    def test_malformed_env_value(self, var: str, value: str, message: str) -> None:
        with (
            patch.dict("os.environ", {var: value}),
            pytest.raises(click.ClickException, match=message),
        ):
            ModelConfig.from_args(model=KIMI)


class TestProxyManager:
    def _start(
        self, overrides: dict[str, ModelOverride], caplog: pytest.LogCaptureFixture
    ) -> tuple[ProxyManager, dict[str, object]]:
        written: dict[str, object] = {}

        def capture_config(self: Path, text: str, encoding: str = "") -> int:
            written.update(yaml.safe_load(text))
            return len(text)

        with (
            patch("shutil.which", return_value="/usr/local/bin/litellm"),
            patch("mulder.orchestrator.proxy._wait_for_health", return_value=True),
            patch("mulder.orchestrator.proxy.fetch_model_windows", return_value={LLAMA: 131072}),
            patch("subprocess.Popen"),
            patch("mulder.orchestrator.proxy.litellm_reasoning", return_value={LLAMA: False}),
            patch.object(Path, "write_text", capture_config),
            caplog.at_level(logging.INFO, logger="mulder.orchestrator.proxy"),
        ):
            pm = ProxyManager(models=[KIMI, LLAMA], port=4000, overrides=overrides)
            pm.start()
            pm.stop()
        return pm, written

    def test_overrides_reach_proxy_config_and_settings(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        kimi = ModelOverride(262144, 32768, True, dict.fromkeys(KIMI_YAML, "config"))
        llama = ModelOverride(max_output_tokens=4096, sources={"max_output_tokens": "env"})
        pm, written = self._start({KIMI: kimi, LLAMA: llama}, caplog)

        entries = written["model_list"]
        assert isinstance(entries, list)
        params = {e["model_name"]: e["litellm_params"] for e in entries}
        assert params[KIMI]["allowed_openai_params"] == ["reasoning_effort", "tools"]
        assert params[KIMI]["max_tokens"] == 32768
        assert params[KIMI]["model"] == "bedrock/converse/us.moonshotai.kimi-k3"
        assert "allowed_openai_params" not in params[LLAMA]
        assert params[LLAMA]["max_tokens"] == 4096
        assert params[LLAMA]["model"] == LLAMA

        assert (pm.settings[KIMI].context_window, pm.settings[LLAMA].context_window) == (
            262144,
            131072,
        )
        assert (
            f"{KIMI}: context_window=262144 (config), max_output_tokens=32768 (config), "
            "reasoning=True (config)" in caplog.text
        )
        assert (
            f"{LLAMA}: context_window=131072 (litellm), max_output_tokens=4096 (env), "
            "reasoning=False (litellm)" in caplog.text
        )
        assert "no reasoning support" not in caplog.text.split(KIMI)[-1].split("\n")[0]

    def test_unknown_model_without_overrides(self, caplog: pytest.LogCaptureFixture) -> None:
        pm, written = self._start({}, caplog)
        assert pm.settings[KIMI].max_output_tokens == PROXY_REASONING_MAX_OUTPUT_TOKENS
        assert pm.settings[LLAMA].max_output_tokens == PROXY_MAX_OUTPUT_TOKENS
        assert f"{KIMI}: context_window=unknown (default), max_output_tokens=32768 (default)" in (
            caplog.text
        )
        assert f"no reasoning support for {KIMI}" in caplog.text


def test_orchestrator_hands_overrides_to_proxy(tmp_path: Path) -> None:
    config = _config(tmp_path, {"planner": KIMI, "executor": LLAMA, KIMI: KIMI_YAML})
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence", model_config=config)
    with patch("mulder.orchestrator.runner.ProxyManager") as pm_cls:
        pm_cls.return_value.env_overrides = {}
        pm_cls.return_value.settings = {}
        orch._start_proxy_if_needed()
    overrides = pm_cls.call_args.kwargs["overrides"]
    assert overrides[KIMI].context_window == 262144
    assert overrides[LLAMA] == ModelOverride()


def test_build_proxy_config_without_settings_is_unknown() -> None:
    params = _build_proxy_config([KIMI], 4000)["model_list"][0]["litellm_params"]
    assert params["max_tokens"] == PROXY_REASONING_MAX_OUTPUT_TOKENS
    assert params["allowed_openai_params"] == ["tools"]


class TestUnknownBedrockRoute:
    """Unmapped bedrock/ ids go through the explicit Converse route; the
    default route infers the wrong provider and streams an empty end_turn."""

    def _entry(self, model: str, settings: ModelSettings) -> dict[str, object]:
        config = _build_proxy_config([model], 4000, {model: settings})
        entry = config["model_list"][0]
        assert entry["model_name"] == model
        params: dict[str, object] = entry["litellm_params"]
        return params

    def test_unknown_bedrock_model_is_rewritten_with_its_settings(self) -> None:
        params = self._entry(KIMI, ModelSettings(max_output_tokens=32768, reasoning=True))
        assert params["model"] == "bedrock/converse/us.moonshotai.kimi-k3"
        assert params["max_tokens"] == 32768
        assert params["allowed_openai_params"] == ["reasoning_effort", "tools"]

    def test_unknown_bedrock_model_gets_tools_allowed(self) -> None:
        # LiteLLM lists `tools` as supported only for mapped models and
        # drop_params strips it otherwise; see issue #207.
        params = self._entry(KIMI, ModelSettings())
        assert params["model"] == "bedrock/converse/us.moonshotai.kimi-k3"
        assert params["allowed_openai_params"] == ["tools"]

    def test_known_bedrock_model_untouched(self) -> None:
        params = self._entry(LLAMA, ModelSettings(known=True))
        assert params["model"] == LLAMA
        assert "allowed_openai_params" not in params

    @pytest.mark.parametrize("model", ["openai/gpt-4o", "azure/gpt-4o"])
    def test_non_bedrock_untouched(self, model: str) -> None:
        params = self._entry(model, ModelSettings())
        assert params["model"] == model
        assert "allowed_openai_params" not in params

    def test_ollama_still_uses_chat_route(self) -> None:
        assert self._entry("ollama/qwen3", ModelSettings())["model"] == "ollama_chat/qwen3"

    def test_resolve_settings_records_whether_litellm_knows_the_model(self) -> None:
        assert resolve_settings(ModelOverride(), None).known is False
        assert resolve_settings(ModelOverride(reasoning=True), None).known is False
        assert resolve_settings(ModelOverride(), False).known is True
