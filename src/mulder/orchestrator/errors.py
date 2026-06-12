"""Fatal configuration error types for the investigation orchestrator.

These errors represent non-retryable failures that should abort the
investigation immediately with actionable user guidance. They bypass
the phase retry loop entirely.
"""

from __future__ import annotations


class AuthenticationError(Exception):
    """SDK authentication failed. Not retryable."""

    def __init__(self, message: str, suggestion: str = "") -> None:
        """Initialize with the raw error and a user-facing suggestion.

        Args:
            message: The original error text from the SDK.
            suggestion: Actionable fix for the user.
        """
        super().__init__(message)
        self.suggestion = suggestion


class ModelNotAvailableError(Exception):
    """Configured model is not available on the provider. Not retryable."""

    def __init__(
        self,
        message: str,
        model: str = "",
        alternative: str = "",
    ) -> None:
        """Initialize with the raw error and optional alternative model.

        Args:
            message: The original error text from the SDK.
            model: The model identifier that was requested.
            alternative: Suggested alternative model from the SDK, if any.
        """
        super().__init__(message)
        self.model = model
        self.alternative = alternative
