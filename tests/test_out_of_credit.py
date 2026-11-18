"""An account with no credit left ends the investigation at once.

Credit or quota exhaustion is account-wide and does not clear by waiting, so
it is fatal like a bad credential. Transient rate limiting is not: requests
or tokens per minute, "too many requests" and ordinary 429s keep their old
behaviour. As with auth errors, only the SDK's error channel is classified,
never model-written text, which can quote evidence.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from claude_agent_sdk import ResultError
from claude_agent_sdk.types import AssistantMessage, ResultMessage, TextBlock
from click.testing import CliRunner

from mulder.cli import cli
from mulder.orchestrator.errors import (
    FATAL_ERRORS,
    AuthenticationError,
    ModelNotAvailableError,
    OutOfCreditError,
)
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.phases import CATALOG
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.session import (
    SessionExecutor,
    _classify_fatal_error,
    _is_payment_required,
)
from mulder.orchestrator.types import InvestigationResult, PhaseResult

_ANTHROPIC_LOW_CREDIT = (
    'API Error: 400 {"type":"error","error":{"type":"invalid_request_error","message":'
    '"Your credit balance is too low to access the Anthropic API. Please go to Plans & '
    'Billing to upgrade or purchase credits."}}'
)
_OPENAI_NO_QUOTA = (
    "API Error: 429 litellm.RateLimitError: RateLimitError: OpenAIException - You exceeded "
    "your current quota, please check your plan and billing details. "
    "'type': 'insufficient_quota', 'code': 'insufficient_quota'"
)

_CREDIT_TEXTS = [
    "Credit balance is too low",
    "Credit balance too low · Add funds: https://platform.claude.com/settings/billing",
    _ANTHROPIC_LOW_CREDIT,
    'API Error: 402 {"type":"error","error":{"type":"billing_error","message":"declined"}}',
    "You have reached your specified API usage limits. You will regain access on "
    "2026-12-01 at 00:00 UTC.",
    _OPENAI_NO_QUOTA,
    "Billing hard limit has been reached",
    "Insufficient credits. Add more using https://openrouter.ai/settings/credits",
    "Error code: 402 - Insufficient Balance",
    "Budget has been exceeded! Current cost: 10.2, Max budget: 10.0",
    "ExceededBudget: User=default over budget. Spend=11.0, Budget=10.0",
    "LiteLLM End User: default, exceeded budget for model=deepseek-chat",
    "402 Payment Required",
]

_ANTHROPIC_RATE_LIMIT = (
    'API Error: 429 {"type":"error","error":{"type":"rate_limit_error","message":'
    "\"This request would exceed your organization's rate limit of 50,000 input tokens "
    'per minute."}}'
)

# Limits that clear on their own. The OpenAI one ends with a billing URL and
# the Gemini one says "quota" and "billing"; neither means the account is dry.
_TRANSIENT_TEXTS = [
    _ANTHROPIC_RATE_LIMIT,
    "Rate limit reached for gpt-4o in organization org-x on tokens per min (TPM): Limit "
    "30000, Used 29000, Requested 2000. Please try again in 2s. You can increase your rate "
    "limit by adding a payment method to your account at "
    "https://platform.openai.com/account/billing.",
    "ThrottlingException: Too many requests, please wait before trying again.",
    "Too many tokens per day, please wait before trying again.",
    "429 RESOURCE_EXHAUSTED: Quota exceeded for "
    "aiplatform.googleapis.com/online_prediction_requests_per_base_model",
    "You exceeded your current quota, please check your plan and billing details. "
    "https://ai.google.dev/gemini-api/docs/rate-limits",
    "429 Too Many Requests",
    "API Error: 529 Overloaded",
]


def _make_session() -> SessionExecutor:
    return SessionExecutor(
        dashboard=MagicMock(), model_config=ModelConfig(), cwd="/tmp", env={}, effort="max"
    )


def _assistant(text: str, error: Any = None) -> AssistantMessage:
    return AssistantMessage(
        content=[TextBlock(text=text)],
        model="claude-test",
        error=error,
        message_id="msg-1",
        usage={"input_tokens": 0, "output_tokens": 0},
    )


def _result(status: int | None, text: str = "API Error") -> ResultMessage:
    return ResultMessage(
        subtype="success",
        duration_ms=1,
        duration_api_ms=1,
        is_error=True,
        num_turns=1,
        session_id="sess-1",
        result=text,
        api_error_status=status,
    )


def _result_error(status: int | None, text: str, reason: str | None = None) -> ResultError:
    return ResultError(
        f"Claude Code returned an error result: {text}",
        data={
            "subtype": "success",
            "result": text,
            "api_error_status": status,
            "terminal_reason": reason,
        },
        exit_code=1,
    )


class _Stream:
    """A message stream that yields *items* and records being closed."""

    def __init__(self, *items: object, close_error: Exception | None = None) -> None:
        self._items = iter(items)
        self._close_error = close_error
        self.closed = False

    def __call__(self, **_kwargs: object) -> _Stream:
        return self

    def __aiter__(self) -> _Stream:
        return self

    async def __anext__(self) -> object:
        try:
            return next(self._items)
        except StopIteration:
            raise StopAsyncIteration from None

    async def aclose(self) -> None:
        self.closed = True
        if self._close_error:
            raise self._close_error


def _query(*items: object) -> Any:
    """A fake ``query`` that yields messages and raises any exception it is given."""

    async def fake(**_kwargs: object) -> AsyncIterator[object]:
        for item in items:
            if isinstance(item, BaseException):
                raise item
            yield item

    return fake


async def _execute(session: SessionExecutor) -> PhaseResult:
    return await session.execute(
        system_prompt="test",
        prompt="test",
        model="claude-test",
        allowed_tools=[],
        disallowed_tools=[],
        max_turns=1,
    )


async def _utility(session: SessionExecutor) -> object:
    return await session.execute_utility(prompt="test", allowed_tools=[], label="test-utility")


class TestClassification:
    @pytest.mark.parametrize("text", _CREDIT_TEXTS)
    def test_credit_and_hard_quota_wording_is_credit(self, text: str) -> None:
        assert _classify_fatal_error(text) == ("credit", text)

    @pytest.mark.parametrize("text", _TRANSIENT_TEXTS)
    def test_transient_limits_are_not_classified(self, text: str) -> None:
        assert _classify_fatal_error(text) == ("", "")

    def test_auth_and_model_results_are_unchanged(self) -> None:
        assert _classify_fatal_error("invalid x-api-key")[0] == "auth"
        assert _classify_fatal_error("model not found")[0] == "model"

    def test_only_status_402_is_payment_required(self) -> None:
        assert _is_payment_required(_result(402))
        assert not _is_payment_required(_result(429))
        assert not _is_payment_required(_result(None))
        assert not _is_payment_required(Exception("402"))

    def test_fatal_errors_lists_all_three(self) -> None:
        assert set(FATAL_ERRORS) == {AuthenticationError, ModelNotAvailableError, OutOfCreditError}


class TestSessionRaises:
    """Each SDK error channel raises ``OutOfCreditError`` from both query paths."""

    @pytest.mark.asyncio()
    @pytest.mark.parametrize("run", [_execute, _utility])
    @pytest.mark.parametrize(
        "item",
        [
            _assistant("Credit balance is too low", error="billing_error"),
            # The flag alone is enough, as ``authentication_failed`` is for auth.
            _assistant("API Error: 400", error="billing_error"),
            # OpenAI reports an empty account as a 429, which the CLI flags
            # as a rate limit; the text says which it is.
            _assistant(_OPENAI_NO_QUOTA, error="rate_limit"),
            _assistant(_ANTHROPIC_LOW_CREDIT, error="invalid_request"),
            _result(402),
            Exception(_ANTHROPIC_LOW_CREDIT),
            _result_error(402, "API Error: 402"),
            _result_error(429, _OPENAI_NO_QUOTA),
            _result_error(None, _ANTHROPIC_LOW_CREDIT, reason="api_error"),
        ],
        ids=[
            "billing-flag",
            "billing-flag-unknown-text",
            "rate-limit-flag-no-quota-text",
            "invalid-request-flag-credit-text",
            "result-message-402",
            "exception-text",
            "result-error-402",
            "result-error-429-no-quota-text",
            "result-error-api-failure-without-status",
        ],
    )
    async def test_out_of_credit_raises(self, run: Any, item: object) -> None:
        with (
            patch("mulder.orchestrator.session.query", _query(item)),
            pytest.raises(OutOfCreditError),
        ):
            await run(_make_session())

    @pytest.mark.asyncio()
    async def test_the_provider_text_is_kept(self) -> None:
        with (
            patch("mulder.orchestrator.session.query", _query(Exception(_ANTHROPIC_LOW_CREDIT))),
            pytest.raises(OutOfCreditError, match="credit balance is too low"),
        ):
            await _execute(_make_session())

    @pytest.mark.asyncio()
    async def test_tokens_are_recorded_before_a_402_result_raises(self) -> None:
        """Behind the proxy the final ResultMessage is the only usage report."""
        session = _make_session()
        message = _result(402)
        message.usage = {"input_tokens": 700, "output_tokens": 30}
        with (
            patch("mulder.orchestrator.session.query", _query(message)),
            pytest.raises(OutOfCreditError),
        ):
            await _execute(session)
        session._dashboard.add_tokens.assert_called_once_with(700, 30)  # type: ignore[attr-defined]

    @pytest.mark.asyncio()
    @pytest.mark.parametrize("run", [_execute, _utility])
    @pytest.mark.parametrize("close_error", [None, RuntimeError("cancel scope")])
    async def test_the_sdk_stream_is_closed_before_the_error_leaves(
        self, run: Any, close_error: Exception | None
    ) -> None:
        """Left open, asyncio closes it at loop shutdown and logs a traceback."""
        stream = _Stream(
            _assistant("Credit balance is too low", error="billing_error"), close_error=close_error
        )
        with (
            patch("mulder.orchestrator.session.query", stream),
            pytest.raises(OutOfCreditError),  # not whatever closing raised
        ):
            await run(_make_session())
        assert stream.closed


class TestSessionDoesNotRaise:
    """Rate limits stay transient, and model prose is never classified."""

    @pytest.mark.asyncio()
    @pytest.mark.parametrize("run", [_execute, _utility])
    @pytest.mark.parametrize("text", _CREDIT_TEXTS)
    async def test_unflagged_prose_quoting_credit_errors(self, run: Any, text: str) -> None:
        prose = f"The stolen API key was drained; the proxy log on the host shows: {text}"
        with patch("mulder.orchestrator.session.query", _query(_assistant(prose))):
            await run(_make_session())

    @pytest.mark.asyncio()
    @pytest.mark.parametrize("run", [_execute, _utility])
    @pytest.mark.parametrize("text", _CREDIT_TEXTS)
    async def test_prose_that_ends_an_error_result_which_is_not_an_api_failure(
        self, run: Any, text: str
    ) -> None:
        """The SDK builds that ``ResultError`` message from the result frame's text."""
        prose = f"The stolen API key was drained; the proxy log on the host shows: {text}"
        session = _make_session()
        with patch(
            "mulder.orchestrator.session.query",
            _query(_assistant(prose), _result_error(None, prose)),
        ):
            result = await run(session)
        if isinstance(result, PhaseResult):
            assert text in session.last_query_error  # an ordinary query error

    @pytest.mark.asyncio()
    async def test_a_query_error_is_remembered_until_the_next_session(self) -> None:
        """The partial report quotes it beside the gate that failed."""
        session = _make_session()
        failing = _query(_result_error(429, _ANTHROPIC_RATE_LIMIT))
        with patch("mulder.orchestrator.session.query", failing):
            await _execute(session)
        assert "rate_limit_error" in session.last_query_error

        with patch("mulder.orchestrator.session.query", _query(_assistant("done"))):
            await _execute(session)
        assert session.last_query_error == ""

    @pytest.mark.asyncio()
    @pytest.mark.parametrize("run", [_execute, _utility])
    @pytest.mark.parametrize(
        "item",
        [
            _assistant(_ANTHROPIC_RATE_LIMIT, error="rate_limit"),
            _assistant("API Error: 429 Too Many Requests", error="rate_limit"),
            _result(429, _ANTHROPIC_RATE_LIMIT),
            _result_error(429, _ANTHROPIC_RATE_LIMIT),
            Exception("ThrottlingException: Too many requests, please wait before trying again."),
        ],
        ids=[
            "rate-limit-flag",
            "rate-limit-flag-bare-429",
            "result-message-429",
            "result-error-429",
            "throttling-exception",
        ],
    )
    async def test_rate_limits_keep_their_behaviour(self, run: Any, item: object) -> None:
        with patch("mulder.orchestrator.session.query", _query(item)):
            result = await run(_make_session())
        # Neither path raises; execute() hands back an unsuccessful result
        # for the phase loop to retry, as before.
        if isinstance(result, PhaseResult):
            assert not result.success


def _make_orchestrator() -> Orchestrator:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator(evidence_path="/evidence", case_id="test-case")
    return orch


class TestPipelineStops:
    @pytest.mark.asyncio()
    async def test_single_phase_does_not_retry(self) -> None:
        orch = _make_orchestrator()
        calls = 0

        async def execute(**_kwargs: object) -> PhaseResult:
            nonlocal calls
            calls += 1
            raise OutOfCreditError("Credit balance is too low")

        with (
            patch.object(orch._session, "execute", side_effect=execute),
            pytest.raises(OutOfCreditError),
        ):
            await orch._run_single_phase(
                CATALOG, prompt_vars={"evidence_path": "/evidence", "case_id_instruction": ""}
            )

        assert calls == 1
        assert orch.current_phase == "catalog"
        orch.dashboard.log_gate_fail.assert_called_once_with(  # type: ignore[attr-defined]
            "Credit balance is too low"
        )

    @pytest.mark.asyncio()
    async def test_a_continuation_that_runs_dry_is_the_last_session(self) -> None:
        orch = _make_orchestrator()
        calls = 0

        async def execute(**_kwargs: object) -> PhaseResult:
            nonlocal calls
            calls += 1
            if calls == 1:
                return PhaseResult(phase_name="query", context_exhausted=True)
            raise OutOfCreditError("Credit balance is too low")

        with (
            patch.object(orch._session, "execute", side_effect=execute),
            pytest.raises(OutOfCreditError),
        ):
            await orch._run_single_phase(
                CATALOG, prompt_vars={"evidence_path": "/evidence", "case_id_instruction": ""}
            )

        assert calls == 2

    @pytest.mark.asyncio()
    async def test_extraction_pool_stops_its_other_workers(self) -> None:
        """A running worker is cancelled and a queued one never starts."""
        orch = _make_orchestrator()
        orch._parallel_extractions = 2
        started: list[str] = []
        cancelled: list[str] = []
        running = asyncio.Event()

        async def split_phase(_phase: object, prompt_vars: dict[str, str], **_kw: object) -> None:
            system = prompt_vars["system_name"]
            started.append(system)
            if system == "host-a":
                await running.wait()  # until host-b is mid-session
                raise OutOfCreditError("Credit balance is too low")
            running.set()
            try:
                await asyncio.Event().wait()  # a long tool call
            except asyncio.CancelledError:
                cancelled.append(system)
                raise

        with (
            patch.object(orch, "_run_split_phase", side_effect=split_phase),
            patch.object(orch._evidence, "build_evidence_context", return_value=""),
            pytest.raises(OutOfCreditError),
        ):
            await asyncio.wait_for(
                orch._run_extraction_pool(
                    [["host-a"], ["host-b"], ["host-c"]], InvestigationResult()
                ),
                timeout=5,
            )

        assert started == ["host-a", "host-b"]
        assert cancelled == ["host-b"]
        assert orch.systems_done == {"host-a": False, "host-b": False, "host-c": False}
        # Only the cause is reported, not the workers it stopped.
        orch.dashboard.log_gate_fail.assert_called_once_with(  # type: ignore[attr-defined]
            "Credit balance is too low"
        )

    @pytest.mark.asyncio()
    async def test_extraction_pool_records_which_systems_passed(self) -> None:
        orch = _make_orchestrator()

        async def split_phase(_phase: object, prompt_vars: dict[str, str], **_kw: object) -> Any:
            if prompt_vars["system_name"] == "host-c":
                raise RuntimeError("worker crashed")
            passed = prompt_vars["system_name"] == "host-a"
            return PhaseResult(phase_name="extraction", success=passed)

        result = InvestigationResult()
        with (
            patch.object(orch, "_run_split_phase", side_effect=split_phase),
            patch.object(orch._evidence, "build_evidence_context", return_value=""),
        ):
            await orch._run_extraction_pool([["host-a"], ["host-b"], ["host-c"]], result)

        assert orch.systems_done == {"host-a": True, "host-b": False, "host-c": False}
        assert [p.success for p in result.phases] == [True, False, False]

    @pytest.mark.asyncio()
    async def test_run_stops_at_the_phase_that_ran_dry(self) -> None:
        """Catalog passes, extraction runs dry: nothing after it is started."""
        orch = _make_orchestrator()
        catalog = json.dumps(
            {
                "case_id": "test-case",
                "evidence_root": "/evidence",
                "systems": [{"name": "host-a"}, {"name": "host-b"}],
            }
        )
        prompts: list[str] = []

        async def execute(**kwargs: Any) -> PhaseResult:
            prompts.append(kwargs["prompt"])
            if len(prompts) == 1:
                return PhaseResult(phase_name="query", messages=[catalog], turns_used=3)
            raise OutOfCreditError("Credit balance is too low")

        with (
            patch.object(orch._session, "execute", side_effect=execute),
            patch.object(orch, "_start_proxy_if_needed"),
            patch.object(orch._log_tailer, "start"),
            pytest.raises(OutOfCreditError),
        ):
            await orch.run()

        assert orch.current_phase == "extraction"
        assert [p.phase_name for p in orch.result.phases] == ["catalog"]
        assert orch.systems_done == {"host-a": False, "host-b": False}
        # Catalog, then at most one planner session per extraction worker.
        assert len(prompts) <= 3


class TestCli:
    def test_out_of_credit_exits_2_and_says_so(self, tmp_path: Any) -> None:
        with (
            patch("mulder.orchestrator.runner.Orchestrator"),
            patch("asyncio.run", side_effect=OutOfCreditError(_ANTHROPIC_LOW_CREDIT)),
        ):
            result = CliRunner().invoke(
                cli, ["investigate", "/evidence", "case-1", "--db-dir", str(tmp_path)]
            )

        assert result.exit_code == 2
        assert "out of credit or over its quota" in result.output
        assert "credit balance is too low" in result.output
        assert "Traceback" not in result.output
