"""Tests for mulder.report.redactor: secret redaction."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mulder.report.redactor import Redactor


class TestRedactorAlwaysAvailable:
    """Tests that work regardless of detect-secrets availability."""

    def test_empty_string_passthrough(self) -> None:
        r = Redactor()
        text, ok = r.redact("")
        assert text == ""
        assert ok is True

    def test_unavailable_returns_original(self) -> None:
        r = Redactor()
        r._available = False
        text, ok = r.redact('secret_key = "AKIAIOSFODNN7EXAMPLE"')
        assert text == 'secret_key = "AKIAIOSFODNN7EXAMPLE"'
        assert ok is False

    def test_multiline_preserves_structure(self) -> None:
        r = Redactor()
        text, _ok = r.redact("line one\nline two\nline three\n")
        assert text.count("\n") == 3


@pytest.mark.skipif(not Redactor()._available, reason="detect-secrets not installed")
class TestRedactorWithDetectSecrets:
    """Tests requiring detect-secrets to be installed."""

    def test_plain_text_unchanged_when_no_secrets_found(self) -> None:
        r = Redactor()
        with patch("detect_secrets.core.scan.scan_line", return_value=[]):
            text, ok = r.redact("This is normal forensic output with no secrets.")
            assert text == "This is normal forensic output with no secrets."
            assert ok is True

    def test_redaction_replaces_secret(self) -> None:
        r = Redactor()
        text, _ok = r.redact('password = "AKIAIOSFODNN7EXAMPLE"')
        assert "[REDACTED]" in text

    def test_fallback_on_exception(self) -> None:
        r = Redactor()
        with patch.object(r, "_redact_with_detect_secrets", side_effect=RuntimeError("boom")):
            text, ok = r.redact("some text")
            assert text == "some text"
            assert ok is False
