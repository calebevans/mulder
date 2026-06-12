"""Tests for fatal error detection in mulder.orchestrator.session."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mulder.orchestrator.errors import AuthenticationError, ModelNotAvailableError
from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.session import (
    SessionExecutor,
    _classify_fatal_error,
    _extract_alternative_model,
)


def _make_session() -> SessionExecutor:
    """Create a SessionExecutor with a mocked dashboard."""
    dashboard = MagicMock()
    model_config = ModelConfig()
    return SessionExecutor(
        dashboard=dashboard,
        model_config=model_config,
        cwd="/tmp",
        env={},
        effort="max",
    )


# ------------------------------------------------------------------
# _classify_fatal_error unit tests
# ------------------------------------------------------------------


class TestClassifyFatalError:
    """Pattern matching classifier for auth and model errors."""

    @pytest.mark.parametrize(
        "text",
        [
            "Not logged in · Please run /login",
            "invalid api key",
            "invalid x-api-key header",
            "authentication_error: key rejected",
            "could not authenticate with provider",
            "permission denied for resource",
            "AccessDeniedException: not authorized",
        ],
    )
    def test_auth_patterns_detected(self, text: str) -> None:
        """Each known auth pattern is classified as 'auth'."""
        category, matched = _classify_fatal_error(text)
        assert category == "auth"
        assert matched == text

    @pytest.mark.parametrize(
        "text",
        [
            "The model claude-sonnet-4-6@20250514 is not available on your vertex deployment.",
            "model is not available in this region",
            "The model is not available in your AWS account",
            "model not found: claude-test-99",
            "You could try using claude-haiku-4-5@20250414 instead.",
        ],
    )
    def test_model_patterns_detected(self, text: str) -> None:
        """Each known model availability pattern is classified as 'model'."""
        category, matched = _classify_fatal_error(text)
        assert category == "model"
        assert matched == text

    def test_case_insensitivity(self) -> None:
        """Pattern matching is case-insensitive."""
        category, _ = _classify_fatal_error("NOT LOGGED IN")
        assert category == "auth"

        category, _ = _classify_fatal_error("MODEL NOT FOUND")
        assert category == "model"

    def test_generic_error_not_classified(self) -> None:
        """Non-matching errors return empty category."""
        category, matched = _classify_fatal_error("network timeout")
        assert category == ""
        assert matched == ""

    def test_empty_string(self) -> None:
        """Empty input returns no match."""
        category, matched = _classify_fatal_error("")
        assert category == ""
        assert matched == ""


# ------------------------------------------------------------------
# _extract_alternative_model unit tests
# ------------------------------------------------------------------


class TestExtractAlternativeModel:
    """Extraction of suggested model names from SDK error messages."""

    def test_standard_vertex_format(self) -> None:
        """Parses 'try using <model> instead' from Vertex AI errors."""
        text = (
            "The model claude-sonnet-4-6@20250514 is not available on your "
            "vertex deployment. You could try using claude-haiku-4-5@20250414 instead."
        )
        assert _extract_alternative_model(text) == "claude-haiku-4-5@20250414"

    def test_no_alternative(self) -> None:
        """Returns empty string when no alternative is suggested."""
        assert _extract_alternative_model("model not found") == ""

    def test_try_format(self) -> None:
        """Handles 'try <model> instead' without 'using'."""
        text = "Error. Try claude-haiku-4-5 instead."
        assert _extract_alternative_model(text) == "claude-haiku-4-5"

    def test_use_format(self) -> None:
        """Handles 'use <model> instead' format."""
        text = "Please use claude-opus-4-6@20250514 instead"
        assert _extract_alternative_model(text) == "claude-opus-4-6@20250514"


# ------------------------------------------------------------------
# SessionExecutor.execute() exception handler tests
# ------------------------------------------------------------------


class TestExecuteAuthDetection:
    """Auth errors raised as exceptions during execute()."""

    @pytest.mark.asyncio()
    async def test_auth_error_via_exception(self) -> None:
        """SDK exception containing auth text raises AuthenticationError."""
        session = _make_session()

        async def mock_query(**kwargs: object):  # type: ignore[no-untyped-def]
            raise Exception("Not logged in · Please run /login")  # noqa: TRY002
            yield  # make it an async generator  # pragma: no cover

        with (
            patch("mulder.orchestrator.session.query", mock_query),
            pytest.raises(AuthenticationError) as exc_info,
        ):
            await session.execute(
                system_prompt="test",
                prompt="test",
                model="claude-test",
                allowed_tools=[],
                disallowed_tools=[],
                max_turns=1,
                max_budget=1.0,
            )

        assert "Not logged in" in str(exc_info.value)
        assert exc_info.value.suggestion  # non-empty suggestion

    @pytest.mark.asyncio()
    async def test_model_error_via_exception(self) -> None:
        """SDK exception with model unavailability raises ModelNotAvailableError."""
        session = _make_session()
        error_msg = (
            "The model claude-sonnet-4-6@20250514 is not available on your "
            "vertex deployment. You could try using claude-haiku-4-5@20250414 instead."
        )

        async def mock_query(**kwargs: object):  # type: ignore[no-untyped-def]
            raise Exception(error_msg)  # noqa: TRY002
            yield  # make it an async generator  # pragma: no cover

        with (
            patch("mulder.orchestrator.session.query", mock_query),
            pytest.raises(ModelNotAvailableError) as exc_info,
        ):
            await session.execute(
                system_prompt="test",
                prompt="test",
                model="claude-sonnet-4-6@20250514",
                allowed_tools=[],
                disallowed_tools=[],
                max_turns=1,
                max_budget=1.0,
            )

        assert exc_info.value.model == "claude-sonnet-4-6@20250514"
        assert exc_info.value.alternative == "claude-haiku-4-5@20250414"

    @pytest.mark.asyncio()
    async def test_generic_error_not_fatal(self) -> None:
        """Non-auth, non-model errors do not raise fatal exceptions."""
        session = _make_session()

        async def mock_query(**kwargs: object):  # type: ignore[no-untyped-def]
            raise Exception("network timeout")  # noqa: TRY002
            yield  # make it an async generator  # pragma: no cover

        with patch("mulder.orchestrator.session.query", mock_query):
            result = await session.execute(
                system_prompt="test",
                prompt="test",
                model="claude-test",
                allowed_tools=[],
                disallowed_tools=[],
                max_turns=1,
                max_budget=1.0,
            )

        assert not result.success


# ------------------------------------------------------------------
# TextBlock-level detection tests
# ------------------------------------------------------------------


class TestTextBlockDetection:
    """Fatal errors delivered as streamed text content."""

    @pytest.mark.asyncio()
    async def test_auth_error_via_textblock(self) -> None:
        """Auth error in a TextBlock raises AuthenticationError."""
        session = _make_session()

        mock_text_block = MagicMock()
        mock_text_block.text = "Not logged in · Please run /login"

        mock_assistant = MagicMock()
        mock_assistant.content = [mock_text_block]
        mock_assistant.message_id = "msg-1"
        mock_assistant.usage = {"input_tokens": 0, "output_tokens": 0}

        async def mock_query(**kwargs: object):  # type: ignore[no-untyped-def]
            yield mock_assistant

        with (
            patch("mulder.orchestrator.session.query", mock_query),
            patch("mulder.orchestrator.session.AssistantMessage", type(mock_assistant)),
            patch("mulder.orchestrator.session.TextBlock", type(mock_text_block)),
            pytest.raises(AuthenticationError),
        ):
            await session.execute(
                system_prompt="test",
                prompt="test",
                model="claude-test",
                allowed_tools=[],
                disallowed_tools=[],
                max_turns=1,
                max_budget=1.0,
            )

    @pytest.mark.asyncio()
    async def test_model_error_via_textblock(self) -> None:
        """Model error in a TextBlock raises ModelNotAvailableError."""
        session = _make_session()

        mock_text_block = MagicMock()
        mock_text_block.text = (
            "The model claude-sonnet-4-6@20250514 is not available on your "
            "vertex deployment. You could try using claude-haiku-4-5@20250414 instead."
        )

        mock_assistant = MagicMock()
        mock_assistant.content = [mock_text_block]
        mock_assistant.message_id = "msg-1"
        mock_assistant.usage = {"input_tokens": 0, "output_tokens": 0}

        async def mock_query(**kwargs: object):  # type: ignore[no-untyped-def]
            yield mock_assistant

        with (
            patch("mulder.orchestrator.session.query", mock_query),
            patch("mulder.orchestrator.session.AssistantMessage", type(mock_assistant)),
            patch("mulder.orchestrator.session.TextBlock", type(mock_text_block)),
            pytest.raises(ModelNotAvailableError) as exc_info,
        ):
            await session.execute(
                system_prompt="test",
                prompt="test",
                model="claude-test",
                allowed_tools=[],
                disallowed_tools=[],
                max_turns=1,
                max_budget=1.0,
            )

        assert exc_info.value.alternative == "claude-haiku-4-5@20250414"


# ------------------------------------------------------------------
# execute_utility() fatal error propagation
# ------------------------------------------------------------------


class TestExecuteUtilityFatalErrors:
    """Fatal errors in execute_utility() propagate instead of returning None."""

    @pytest.mark.asyncio()
    async def test_auth_error_propagates(self) -> None:
        """AuthenticationError from SDK propagates through execute_utility."""
        session = _make_session()

        async def mock_query(**kwargs: object):  # type: ignore[no-untyped-def]
            raise Exception("Not logged in · Please run /login")  # noqa: TRY002
            yield  # make it an async generator  # pragma: no cover

        with (
            patch("mulder.orchestrator.session.query", mock_query),
            pytest.raises(AuthenticationError),
        ):
            await session.execute_utility(
                prompt="test",
                allowed_tools=[],
                label="test-utility",
            )

    @pytest.mark.asyncio()
    async def test_generic_error_returns_none(self) -> None:
        """Non-fatal errors in execute_utility still return None."""
        session = _make_session()

        async def mock_query(**kwargs: object):  # type: ignore[no-untyped-def]
            raise Exception("some random error")  # noqa: TRY002
            yield  # make it an async generator  # pragma: no cover

        with patch("mulder.orchestrator.session.query", mock_query):
            result = await session.execute_utility(
                prompt="test",
                allowed_tools=[],
                label="test-utility",
            )

        assert result is None


# ------------------------------------------------------------------
# Auth suggestion provider detection
# ------------------------------------------------------------------


class TestAuthSuggestion:
    """Provider-specific suggestions based on environment variables."""

    def test_default_anthropic_suggestion(self) -> None:
        """Without provider env vars, suggests ANTHROPIC_API_KEY."""
        with (
            patch.dict("os.environ", {}, clear=True),
        ):
            from mulder.orchestrator.session import _auth_suggestion

            suggestion = _auth_suggestion()
            assert "ANTHROPIC_API_KEY" in suggestion

    def test_vertex_suggestion(self) -> None:
        """With CLAUDE_CODE_USE_VERTEX=1, suggests gcloud auth."""
        with patch.dict("os.environ", {"CLAUDE_CODE_USE_VERTEX": "1"}):
            from mulder.orchestrator.session import _auth_suggestion

            suggestion = _auth_suggestion()
            assert "gcloud" in suggestion

    def test_bedrock_suggestion(self) -> None:
        """With CLAUDE_CODE_USE_BEDROCK=1, suggests AWS credentials."""
        with patch.dict("os.environ", {"CLAUDE_CODE_USE_BEDROCK": "1"}):
            from mulder.orchestrator.session import _auth_suggestion

            suggestion = _auth_suggestion()
            assert "AWS" in suggestion
