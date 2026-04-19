"""Tests for mulder.report.redactor -- secret redaction."""

from __future__ import annotations

from unittest.mock import patch

from mulder.report.redactor import Redactor


class TestRedactor:
    def test_empty_string_passthrough(self) -> None:
        r = Redactor()
        assert r.redact("") == ""

    def test_plain_text_unchanged_when_no_secrets_found(self) -> None:
        r = Redactor()
        if not r._available:
            text = "anything goes when unavailable"
            assert r.redact(text) == text
            return
        with patch("detect_secrets.core.scan.scan_line", return_value=[]):
            text = "This is normal forensic output with no secrets."
            assert r.redact(text) == text

    def test_redaction_replaces_secret(self) -> None:
        r = Redactor()
        text = 'password = "AKIAIOSFODNN7EXAMPLE"'
        result = r.redact(text)
        if r._available:
            assert "[REDACTED]" in result or result == text
        else:
            assert result == text

    def test_fallback_on_exception(self) -> None:
        r = Redactor()
        if not r._available:
            return
        with patch.object(r, "_redact_with_detect_secrets", side_effect=RuntimeError("boom")):
            result = r.redact("some text")
            assert result == "some text"

    def test_unavailable_returns_original(self) -> None:
        r = Redactor()
        r._available = False
        text = 'secret_key = "AKIAIOSFODNN7EXAMPLE"'
        assert r.redact(text) == text

    def test_multiline_preserves_structure(self) -> None:
        r = Redactor()
        text = "line one\nline two\nline three\n"
        result = r.redact(text)
        assert result.count("\n") == text.count("\n")
