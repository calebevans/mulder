"""The HTML report must not execute what the evidence says.

Two separate holes closed here:

* the case narrative was compiled with a plain ``jinja2.Environment``, so
  ``{{ cycler.__init__.__globals__ }}`` and everything reachable from it ran
  as the user running the server (server-side template injection);
* the report environment used ``autoescape=False`` for *both* templates, and
  ``markdown.markdown`` passes raw HTML straight through, so any string read
  off the evidence -- a filename, a command line, a carved registry value --
  landed in the report as live markup.
"""

from __future__ import annotations

import jinja2
import pytest

from mulder.report.renderer import ReportRenderer, _markdown_to_safe_html

SSTI_PAYLOADS = [
    "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ self.__init__.__globals__ }}",
    "{{ lipsum.__globals__['os'].popen('id').read() }}",
    "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
]


class TestNarrativeTemplateInjection:
    @pytest.mark.parametrize("payload", SSTI_PAYLOADS)
    def test_payload_does_not_execute(self, payload: str) -> None:
        out = ReportRenderer._render_narrative_template(payload, {"finding_count": 3})
        # Either the sandbox refuses (falling back to the raw text) or the
        # expression yields nothing. What must never appear is a uid line or
        # a Python repr of the interpreter internals.
        assert "uid=" not in out
        assert "<class " not in out
        assert "__globals__" not in out or out == payload

    def test_legitimate_placeholders_still_render(self) -> None:
        out = ReportRenderer._render_narrative_template(
            "The investigation produced {{ finding_count }} findings.",
            {"finding_count": 7},
        )
        assert out == "The investigation produced 7 findings."

    def test_plain_prose_is_untouched(self) -> None:
        text = "No templating here at all."
        assert ReportRenderer._render_narrative_template(text, {}) == text

    def test_broken_template_falls_back_to_the_raw_text(self) -> None:
        text = "unterminated {{ oops"
        assert ReportRenderer._render_narrative_template(text, {}) == text

    def test_empty_narrative(self) -> None:
        assert ReportRenderer._render_narrative_template("", {}) == ""


class TestMarkdownDoesNotPassRawHtml:
    @pytest.mark.parametrize(
        "payload",
        [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<svg/onload=alert(1)>",
            "</td></tr><script>alert(1)</script>",
        ],
    )
    def test_markup_is_inert(self, payload: str) -> None:
        html = _markdown_to_safe_html(f"Found this on disk: {payload}")
        assert "<script" not in html.lower()
        assert "<img" not in html.lower()
        assert "<iframe" not in html.lower()
        assert "<svg" not in html.lower()
        assert "&lt;" in html

    def test_markdown_formatting_still_works(self) -> None:
        html = _markdown_to_safe_html("**bold** and `code` and [link](http://example.com)")
        assert "<strong>bold</strong>" in html
        assert "<code>code</code>" in html
        assert 'href="http://example.com"' in html

    def test_fenced_code_still_works(self) -> None:
        html = _markdown_to_safe_html("```\ncmd.exe /c whoami\n```")
        assert "<pre>" in html
        assert "cmd.exe /c whoami" in html

    def test_ampersand_is_not_double_escaped(self) -> None:
        assert "&amp;amp;" not in _markdown_to_safe_html("Rock & Roll")

    def test_empty(self) -> None:
        assert _markdown_to_safe_html("") == ""


class TestAutoescapeSelection:
    def test_html_template_autoescapes(self) -> None:
        env = ReportRenderer()._env
        assert env.autoescape("report.html.j2") is True

    def test_markdown_template_does_not_autoescape(self) -> None:
        env = ReportRenderer()._env
        assert env.autoescape("report.md.j2") is False

    def test_a_value_reaching_the_html_template_is_escaped(self) -> None:
        env = ReportRenderer()._env
        tpl = env.from_string("<p>{{ v }}</p>")
        # from_string has no name, so assert the environment's policy directly
        # on a named template instead.
        assert isinstance(tpl.render(v="<b>x</b>"), str)

        loaded = jinja2.Environment(
            loader=jinja2.DictLoader({"x.html.j2": "<p>{{ v }}</p>"}),
            autoescape=env.autoescape,
        )
        rendered = loaded.get_template("x.html.j2").render(v="<script>alert(1)</script>")
        assert "<script>" not in rendered
        assert "&lt;script&gt;" in rendered
