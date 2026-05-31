"""Secret redaction for report text using detect-secrets."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class Redactor:
    """Scans text for potential secrets and replaces them with [REDACTED]."""

    def __init__(self) -> None:
        """Enable redaction when detect-secrets is importable; otherwise no-op."""
        self._available = True
        try:
            from detect_secrets.core.scan import scan_line  # noqa: F401
        except ImportError:
            logger.warning("detect-secrets is not installed; secret redaction disabled")
            self._available = False

    def redact(self, text: str) -> tuple[str, bool]:
        """Return ``(text, success)`` with detected secrets replaced by ``[REDACTED]``.

        Args:
            text: The input text to scan for secrets.

        Returns:
            A tuple of the (possibly redacted) text and a boolean indicating
            whether redaction completed successfully.  When ``detect-secrets``
            is unavailable the original text is returned with ``False``.
            An empty input always returns ``("", True)``.
        """
        if not text:
            return text, True
        if not self._available:
            return text, False

        try:
            return self._redact_with_detect_secrets(text), True
        except Exception:
            logger.warning(
                "detect-secrets scan failed; returning unredacted text",
                exc_info=True,
            )
            return text, False

    def _redact_with_detect_secrets(self, text: str) -> str:
        """Replace each substring reported by detect-secrets with ``[REDACTED]``, line by line."""
        from detect_secrets.core.scan import scan_line
        from detect_secrets.settings import default_settings

        redacted_lines: list[str] = []
        with default_settings():
            for line in text.splitlines(keepends=True):
                secrets = scan_line(line)
                if secrets:
                    redacted_line = line
                    for secret in secrets:
                        raw = secret.secret_value
                        if raw:
                            redacted_line = redacted_line.replace(raw, "[REDACTED]")
                    redacted_lines.append(redacted_line)
                else:
                    redacted_lines.append(line)
        return "".join(redacted_lines)
