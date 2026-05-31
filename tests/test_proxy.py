"""Tests for the LiteLLM proxy management module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mulder.orchestrator.proxy import (
    ProxyManager,
    _build_proxy_config,
    is_proxy_model,
)


class TestIsProxyModel:
    """Tests for provider prefix detection."""

    def test_bedrock_model(self) -> None:
        assert is_proxy_model("bedrock/meta.llama3-1-70b-instruct-v1:0") is True

    def test_openai_model(self) -> None:
        assert is_proxy_model("openai/gpt-4o") is True

    def test_vertex_ai_model(self) -> None:
        assert is_proxy_model("vertex_ai/gemini-pro") is True

    def test_azure_model(self) -> None:
        assert is_proxy_model("azure/my-deployment") is True

    def test_ollama_model(self) -> None:
        assert is_proxy_model("ollama/llama3.1:70b") is True

    def test_claude_direct_api(self) -> None:
        assert is_proxy_model("claude-sonnet-4-6") is False

    def test_bedrock_inference_profile(self) -> None:
        assert is_proxy_model("us.anthropic.claude-sonnet-4-6") is False

    def test_empty_string(self) -> None:
        assert is_proxy_model("") is False

    def test_slash_in_middle_not_prefix(self) -> None:
        assert is_proxy_model("my-model/v1") is False


class TestBuildProxyConfig:
    """Tests for proxy config generation."""

    def test_single_model(self) -> None:
        config = _build_proxy_config(["bedrock/meta.llama3-1-70b"], 4000)
        assert "model_list" in config
        assert len(config["model_list"]) == 1
        entry = config["model_list"][0]
        assert entry["model_name"] == "bedrock/meta.llama3-1-70b"
        assert entry["litellm_params"]["model"] == "bedrock/meta.llama3-1-70b"

    def test_multiple_models(self) -> None:
        models = ["bedrock/meta.llama3-1-70b", "openai/gpt-4o"]
        config = _build_proxy_config(models, 5000)
        assert len(config["model_list"]) == 2
        names = {e["model_name"] for e in config["model_list"]}
        assert names == {"bedrock/meta.llama3-1-70b", "openai/gpt-4o"}

    def test_config_has_master_key(self) -> None:
        config = _build_proxy_config(["bedrock/test"], 4000)
        assert config["general_settings"]["master_key"] == "sk-mulder-proxy"

    def test_drop_params_enabled(self) -> None:
        config = _build_proxy_config(["bedrock/test"], 4000)
        assert config["litellm_settings"]["drop_params"] is True


class TestProxyManager:
    """Tests for ProxyManager lifecycle (mocked subprocess)."""

    def test_env_overrides(self) -> None:
        pm = ProxyManager(models=["bedrock/test"], port=4000)
        overrides = pm.env_overrides
        assert overrides["ANTHROPIC_BASE_URL"] == "http://localhost:4000"
        assert overrides["ANTHROPIC_AUTH_TOKEN"] == "sk-mulder-proxy"

    def test_custom_port(self) -> None:
        pm = ProxyManager(models=["bedrock/test"], port=8080)
        assert pm.port == 8080
        assert "8080" in pm.env_overrides["ANTHROPIC_BASE_URL"]

    @patch("shutil.which", return_value="/usr/local/bin/litellm")
    @patch("mulder.orchestrator.proxy._wait_for_health", return_value=True)
    @patch("subprocess.Popen")
    def test_start_success(
        self, mock_popen: MagicMock, mock_health: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc

        pm = ProxyManager(models=["bedrock/meta.llama3-1-70b"], port=4000)
        pm.start()

        mock_popen.assert_called_once()
        mock_health.assert_called_once_with(4000)
        assert pm._process is mock_proc

    @patch("shutil.which", return_value="/usr/local/bin/litellm")
    @patch("mulder.orchestrator.proxy._wait_for_health", return_value=False)
    @patch("subprocess.Popen")
    def test_start_health_check_fails(
        self, mock_popen: MagicMock, mock_health: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_proc = MagicMock()
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b"error"
        mock_popen.return_value = mock_proc

        pm = ProxyManager(models=["bedrock/meta.llama3-1-70b"], port=4000)
        with pytest.raises(RuntimeError, match="failed to start"):
            pm.start()

        mock_proc.terminate.assert_called_once()

    @patch("shutil.which", return_value="/usr/local/bin/litellm")
    @patch("mulder.orchestrator.proxy._wait_for_health", return_value=True)
    @patch("subprocess.Popen")
    def test_stop_terminates_process(
        self, mock_popen: MagicMock, mock_health: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        pm = ProxyManager(models=["bedrock/test"], port=4000)
        pm.start()
        pm.stop()

        mock_proc.terminate.assert_called_once()
        assert pm._process is None

    def test_stop_without_start_is_safe(self) -> None:
        pm = ProxyManager(models=["bedrock/test"], port=4000)
        pm.stop()  # Should not raise

    @patch("shutil.which", return_value="/usr/local/bin/litellm")
    @patch("mulder.orchestrator.proxy._wait_for_health", return_value=True)
    @patch("subprocess.Popen")
    def test_context_manager(
        self, mock_popen: MagicMock, mock_health: MagicMock, mock_which: MagicMock
    ) -> None:
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        with ProxyManager(models=["bedrock/test"], port=4000) as pm:
            assert pm._process is mock_proc

        mock_proc.terminate.assert_called_once()
