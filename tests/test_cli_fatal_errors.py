"""Tests for fatal error formatting in the CLI investigate command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner, Result

from mulder.cli import _is_interactive, cli
from mulder.orchestrator.errors import AuthenticationError, ModelNotAvailableError


def _invoke_investigate_with_error(error: Exception) -> Result:
    """Invoke the investigate command with a mocked orchestrator that raises.

    Patches the Orchestrator and asyncio.run at their source modules so
    the local imports inside ``investigate()`` resolve correctly.

    Args:
        error: Exception to raise from orchestrator.run().

    Returns:
        Click CliRunner result.
    """
    import logging as _logging

    runner = CliRunner()

    mock_orch = MagicMock()
    mock_orch.dashboard = MagicMock()

    mock_handler = MagicMock(spec=_logging.FileHandler)
    mock_handler.level = _logging.NOTSET

    with (
        patch("mulder.orchestrator.models.ModelConfig.from_args", return_value=MagicMock()),
        patch("mulder.adapters.prepare_evidence_case", return_value=MagicMock()),
        patch("mulder.orchestrator.runner.Orchestrator", return_value=mock_orch),
        patch("asyncio.run", side_effect=error),
        patch.object(Path, "exists", return_value=True),
        patch("logging.FileHandler", return_value=mock_handler),
    ):
        result = runner.invoke(
            cli,
            ["investigate", "/evidence", "test-case"],
            catch_exceptions=False,
        )

    root_logger = _logging.getLogger()
    root_logger.handlers = [h for h in root_logger.handlers if not isinstance(h, MagicMock)]

    return result


class TestAuthErrorCLI:
    """CLI formatting for AuthenticationError."""

    def test_auth_error_exit_code_2(self) -> None:
        """AuthenticationError produces exit code 2."""
        exc = AuthenticationError(
            message="Not logged in",
            suggestion="Authentication failed. To fix this:\n"
            "  - Set ANTHROPIC_API_KEY in your environment",
        )
        result = _invoke_investigate_with_error(exc)
        assert result.exit_code == 2

    def test_auth_error_shows_message(self) -> None:
        """Error message and suggestion appear in output."""
        exc = AuthenticationError(
            message="Not logged in",
            suggestion="Authentication failed. To fix this:\n"
            "  - Set ANTHROPIC_API_KEY in your environment",
        )
        result = _invoke_investigate_with_error(exc)
        assert "Not logged in" in result.output
        assert "ANTHROPIC_API_KEY" in result.output

    def test_auth_error_no_suggestion(self) -> None:
        """Auth error without suggestion still shows the error message."""
        exc = AuthenticationError(message="auth failed")
        result = _invoke_investigate_with_error(exc)
        assert result.exit_code == 2
        assert "auth failed" in result.output


class TestModelErrorCLI:
    """CLI formatting for ModelNotAvailableError."""

    def test_model_error_exit_code_2(self) -> None:
        """ModelNotAvailableError produces exit code 2."""
        exc = ModelNotAvailableError(
            message="model is not available",
            model="claude-sonnet-4-6",
        )
        result = _invoke_investigate_with_error(exc)
        assert result.exit_code == 2

    def test_model_error_with_alternative(self) -> None:
        """Model error with alternative suggests the alternative model."""
        exc = ModelNotAvailableError(
            message="model is not available",
            model="claude-sonnet-4-6",
            alternative="claude-haiku-4-5",
        )
        result = _invoke_investigate_with_error(exc)
        assert result.exit_code == 2
        assert "claude-haiku-4-5" in result.output

    def test_model_error_without_alternative(self) -> None:
        """Model error without alternative suggests --model flag."""
        exc = ModelNotAvailableError(
            message="model not found",
            model="claude-test",
        )
        result = _invoke_investigate_with_error(exc)
        assert result.exit_code == 2
        assert "--model" in result.output


class TestIsInteractive:
    """Tests for the _is_interactive() helper."""

    def test_returns_bool(self) -> None:
        """_is_interactive() returns a boolean."""
        result = _is_interactive()
        assert isinstance(result, bool)

    def test_non_tty_returns_false(self) -> None:
        """Non-TTY stderr (e.g., piped) returns False."""
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.isatty.return_value = False
            assert not _is_interactive()
