"""Proxy-routed sessions tell Claude Code the model's real context window and
output reservation, and context overflow is recognised by provider phrasing
rather than a generic substring (issue #191)."""

from __future__ import annotations

import io
import json
from collections.abc import AsyncIterator
from unittest.mock import MagicMock, patch

import pytest
from claude_agent_sdk import ClaudeAgentOptions as Options

from mulder.orchestrator.gates import GateResult
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.phases import CATALOG
from mulder.orchestrator.proxy import (
    PROXY_MAX_OUTPUT_TOKENS,
    PROXY_REASONING_MAX_OUTPUT_TOKENS,
    ModelSettings,
    fetch_model_windows,
)
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.session import SessionExecutor, _is_context_exhausted
from mulder.orchestrator.types import PhaseResult

_OUT = "CLAUDE_CODE_MAX_OUTPUT_TOKENS"
_CTX = "CLAUDE_CODE_MAX_CONTEXT_TOKENS"
DEEPSEEK = "bedrock/deepseek.v3.2"
#: LiteLLM knows the window and says "no reasoning" (the 8192 cap).
DEEPSEEK_SETTINGS = {
    DEEPSEEK: ModelSettings(context_window=163840, max_output_tokens=PROXY_MAX_OUTPUT_TOKENS)
}

BEDROCK_OVERFLOW = (
    "API Error: 400 litellm.BadRequestError: BedrockException - "
    '{"message":"The model returned the following errors: ... This model\'s '
    "maximum context length is 163840 tokens. However, you requested 32000 "
    "output tokens and your prompt contains at least 131841 input tokens, for "
    "a total of at least 163841 tokens. Please reduce the length of the input "
    'prompt or the number of requested output tokens. (parameter=input_tokens, value=131841)"}'
)
OPENAI_OVERFLOW = (
    "API Error: 400 {'error': {'message': \"This model's maximum context length is "
    "128000 tokens...\", 'code': 'context_length_exceeded'}}"
)


def _session(env: dict[str, str] | None = None) -> SessionExecutor:
    return SessionExecutor(
        dashboard=MagicMock(), model_config=ModelConfig(), cwd="/tmp", env=env or {}, effort="max"
    )


async def _captured_env(
    session: SessionExecutor, model: str, utility: bool = False
) -> dict[str, str]:
    seen: list[dict[str, str]] = []

    async def capture_query(*, prompt: str, options: Options) -> AsyncIterator[object]:
        seen.append(dict(options.env))
        return
        yield  # pragma: no cover

    with patch("mulder.orchestrator.session.query", capture_query):
        if utility:
            await session.execute_utility("wait", [], "wait_all")
        else:
            await session.execute("s", "p", model, [], [], 1)
    assert len(seen) == 1
    return seen[0]


class TestGatewayEnv:
    @pytest.mark.asyncio()
    async def test_proxy_model_gets_window_and_output_cap(self) -> None:
        session = _session()
        session._proxy_settings = DEEPSEEK_SETTINGS
        env = await _captured_env(session, DEEPSEEK)
        assert env[_OUT] == str(PROXY_MAX_OUTPUT_TOKENS)
        assert env[_CTX] == "163840"

    @pytest.mark.asyncio()
    async def test_unknown_model_gets_reasoning_cap_and_no_window(self) -> None:
        env = await _captured_env(_session(), DEEPSEEK)
        assert env[_OUT] == str(PROXY_REASONING_MAX_OUTPUT_TOKENS)
        assert _CTX not in env

    @pytest.mark.parametrize(
        "model", ["claude-opus-4-6", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"]
    )
    @pytest.mark.asyncio()
    async def test_native_models_untouched(self, model: str) -> None:
        session = _session()
        session._proxy_settings = DEEPSEEK_SETTINGS
        env = await _captured_env(session, model)
        assert _OUT not in env
        assert _CTX not in env

    @pytest.mark.asyncio()
    async def test_caller_env_wins(self) -> None:
        session = _session({_OUT: "4096", _CTX: "100000"})
        session._proxy_settings = DEEPSEEK_SETTINGS
        env = await _captured_env(session, DEEPSEEK)
        assert env[_OUT] == "4096"
        assert env[_CTX] == "100000"

    @pytest.mark.asyncio()
    async def test_utility_query_uses_its_own_model(self) -> None:
        session = _session()
        session._model_config = ModelConfig(planner=DEEPSEEK)
        session._proxy_settings = DEEPSEEK_SETTINGS
        env = await _captured_env(session, "", utility=True)
        assert env[_OUT] == str(PROXY_MAX_OUTPUT_TOKENS)
        assert env[_CTX] == "163840"


class TestContextExhaustion:
    @pytest.mark.parametrize(
        "text",
        [
            BEDROCK_OVERFLOW,
            OPENAI_OVERFLOW,
            "prompt is too long: 213462 tokens > 200000 maximum",
            "input length and `max_tokens` exceed context limit: 190000 + 32000 > 200000",
            "Input is too long for requested model.",
            "API Error: The model has reached its context window limit.",
        ],
    )
    def test_overflow_phrasings(self, text: str) -> None:
        assert _is_context_exhausted(text)

    @pytest.mark.parametrize(
        "text",
        [
            "Submit a maximum of 5 findings per batch.",
            "API Error: 429 rate limit exceeded",
            "ThrottlingException: Too many tokens per minute",
        ],
    )
    def test_unrelated_text(self, text: str) -> None:
        assert not _is_context_exhausted(text)

    @pytest.mark.parametrize(
        ("error", "exhausted"),
        [(BEDROCK_OVERFLOW, True), (OPENAI_OVERFLOW, True), ("API Error: 500 upstream", False)],
    )
    @pytest.mark.asyncio()
    async def test_query_error_marks_result(self, error: str, exhausted: bool) -> None:
        async def failing_query(*, prompt: str, options: Options) -> AsyncIterator[object]:
            raise RuntimeError(error)
            yield  # pragma: no cover

        with patch("mulder.orchestrator.session.query", failing_query):
            result = await _session().execute("s", "p", DEEPSEEK, [], [], 1)
        assert result.context_exhausted is exhausted


class TestFetchModelWindows:
    def _fake_urlopen(self, payload: object) -> MagicMock:
        resp = MagicMock()
        resp.__enter__.return_value = io.StringIO(json.dumps(payload))
        return MagicMock(return_value=resp)

    def test_parses_model_group_info(self) -> None:
        payload = {
            "data": [
                {"model_group": DEEPSEEK, "max_input_tokens": 163840, "max_output_tokens": 163840},
                {"model_group": "ollama/unknown", "max_input_tokens": None},
                "garbage",
            ]
        }
        with patch("urllib.request.urlopen", self._fake_urlopen(payload)) as urlopen:
            assert fetch_model_windows(4000) == {DEEPSEEK: 163840}
        req = urlopen.call_args.args[0]
        assert req.full_url == "http://localhost:4000/model_group/info"
        assert req.get_header("Authorization") == "Bearer sk-mulder-proxy"

    def test_endpoint_failure_is_empty(self) -> None:
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            assert fetch_model_windows(4000) == {}

    def test_orchestrator_hands_settings_to_session(self) -> None:
        with patch("mulder.orchestrator.runner.InvestigationDashboard"):
            orch = Orchestrator("/evidence", model_config=ModelConfig(planner=DEEPSEEK))
        with patch("mulder.orchestrator.runner.ProxyManager") as pm_cls:
            pm_cls.return_value.settings = DEEPSEEK_SETTINGS
            pm_cls.return_value.env_overrides = {}
            orch._start_proxy_if_needed()
        assert orch._session._proxy_settings is DEEPSEEK_SETTINGS


class TestSinglePhaseCompaction:
    @pytest.mark.asyncio()
    async def test_clean_continuation_stops_compacting(self) -> None:
        with patch("mulder.orchestrator.runner.InvestigationDashboard"):
            orch = Orchestrator("/evidence", max_compactions=3)
        orch._case_id = "test-case"
        outcomes = iter([True, False])

        async def execute(**kwargs: object) -> PhaseResult:
            return PhaseResult(
                phase_name="query", messages=["m"], turns_used=1, context_exhausted=next(outcomes)
            )

        with (
            patch.object(orch._session, "execute", side_effect=execute) as mock_execute,
            patch.object(orch, "_validate_phase", return_value=GateResult(True, "catalog")),
        ):
            result = await orch._run_single_phase(CATALOG, prompt_vars={"evidence_path": "/e"})

        assert result.success
        assert mock_execute.call_count == 2  # initial + one continuation, not max_compactions
        assert result.turns_used == 2

    @pytest.mark.asyncio()
    async def test_repeated_overflow_is_bounded(self) -> None:
        with patch("mulder.orchestrator.runner.InvestigationDashboard"):
            orch = Orchestrator("/evidence", max_compactions=2)
        orch._case_id = "test-case"

        async def execute(**kwargs: object) -> PhaseResult:
            return PhaseResult(
                phase_name="query", messages=[], turns_used=0, context_exhausted=True
            )

        gate = GateResult(False, "catalog", gaps=["nothing"])
        with (
            patch.object(orch._session, "execute", side_effect=execute) as mock_execute,
            patch.object(orch, "_validate_phase", return_value=gate),
        ):
            result = await orch._run_single_phase(CATALOG, prompt_vars={"evidence_path": "/e"})

        assert not result.success
        # Each of the (1 + max_retries) attempts runs at most max_compactions continuations.
        assert mock_execute.call_count == (1 + CATALOG.max_retries) * (1 + 2)
