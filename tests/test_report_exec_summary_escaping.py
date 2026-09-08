"""The executive summary must render as markup, and must not carry injection.

Two coupled defects on one path.

``_build_executive_summary`` returns a string of pre-built HTML. The HTML
template interpolated it as ``{{ executive_summary }}`` with no ``| safe``,
and autoescaping is on for ``.html.j2``, so the first block an analyst reads
showed raw ``&lt;div class=...&gt;`` tags as literal text instead of formatted
content.

The obvious fix -- marking it ``| safe`` -- is only correct once the finding
titles interpolated into that string are escaped. Titles come straight off the
evidence, so an attacker-chosen filename or registry value would otherwise be
injected into the report as live markup. Neither half is right alone.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import jinja2
import pytest

from mulder.models import Finding
from mulder.report.renderer import ReportRenderer, _build_executive_summary

_XSS = '<script>alert("xss")</script>'


def _finding(title: str, severity: str = "critical") -> Finding:
    return Finding(
        finding_id="f1",
        case_id="case-1",
        title=title,
        description="d",
        severity=severity,  # type: ignore[arg-type]
        confidence="confirmed",
        evidence_refs=["tc_1"],
        sources=["src"],
        submitted_at="2026-01-01T00:00:00",
    )


def _summary(**over: object) -> str:
    kwargs: dict[str, object] = {
        "case_id": "case-1",
        "finding_count": 1,
        "critical_count": 1,
        "high_count": 0,
        "sources_count": 1,
        "total_tool_calls": 1,
        "total_duration_ms": 1000.0,
        "critical_findings": [_finding("Ransomware note")],
    }
    kwargs.update(over)
    return _build_executive_summary(**kwargs)  # type: ignore[arg-type]


def _autoescape_policy(env: object) -> Callable[[str | None], bool]:
    """jinja2 types ``Environment.autoescape`` as ``bool``; here it is a callable."""
    return cast("Callable[[str | None], bool]", env.autoescape)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Half 1: the titles baked into the summary string must be escaped
# ---------------------------------------------------------------------------


def test_a_malicious_finding_title_cannot_inject_markup() -> None:
    """Titles come off the evidence, so they must never become live markup."""
    summary = _summary(critical_findings=[_finding(_XSS)])

    assert "<script>" not in summary
    assert "&lt;script&gt;" in summary


@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_timeline_titles_are_escaped_too(position: str) -> None:
    """The timeline narrative bakes three more titles into the same string."""
    titles = {
        "first": [_XSS, "b", "c", "d"],
        "middle": ["a", _XSS, "c", "d"],
        "last": ["a", "b", "c", _XSS],
    }[position]
    tl = [_finding(t) for t in titles]
    for i, f in enumerate(tl):
        f.event_time_start = f"2026-01-0{i + 1}T00:00:00"

    summary = _summary(timeline_findings=tl, critical_findings=[])

    assert "<script>" not in summary
    assert "&lt;script&gt;" in summary


def test_the_summary_keeps_its_own_structural_markup() -> None:
    """Narrowness: escaping the titles must not escape the block's own tags."""
    summary = _summary()

    assert '<div class="exec-threats">' in summary
    assert "<li>Ransomware note</li>" in summary


def test_a_title_is_not_double_escaped() -> None:
    """An ampersand in a title must survive as one entity, not `&amp;amp;`."""
    summary = _summary(critical_findings=[_finding("Rock & Roll")])

    assert "Rock &amp; Roll" in summary
    assert "&amp;amp;" not in summary


# ---------------------------------------------------------------------------
# Half 2: the summary must reach the page as markup, not as escaped text
# ---------------------------------------------------------------------------


def _template_source() -> str:
    env = ReportRenderer()._env
    loader = env.loader
    assert loader is not None
    return loader.get_source(env, "report.html.j2")[0]


def test_the_html_template_is_autoescaped() -> None:
    """The premise of the regression: autoescape is on for this template."""
    policy = _autoescape_policy(ReportRenderer()._env)

    assert policy("report.html.j2") is True
    assert policy("report.md.j2") is False


def test_the_executive_summary_is_interpolated_as_markup() -> None:
    """Without `| safe` an autoescaped template shows its tags as text."""
    assert "{{ executive_summary | safe }}" in _template_source()


def test_only_the_intended_values_are_marked_safe() -> None:
    """`| safe` is a loaded gun; keep the count of them honest."""
    safe_uses = [line.strip() for line in _template_source().splitlines() if "| safe" in line]

    assert len(safe_uses) == 4, f"unexpected `| safe` uses: {safe_uses}"
    assert any("executive_summary" in u for u in safe_uses)


def test_safe_is_what_makes_the_difference_under_this_policy() -> None:
    """Pins that the fix did not disable autoescaping to solve the display bug.

    Rendered through an overlay of the real environment, so the same
    ``select_autoescape`` policy applies to a ``.html.j2`` name.
    """
    env = ReportRenderer()._env.overlay(
        loader=jinja2.DictLoader({"probe.html.j2": "{{ v }}|{{ v | safe }}"})
    )

    plain, marked = env.get_template("probe.html.j2").render(v=_XSS).split("|", 1)

    assert plain == "&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;"
    assert marked == _XSS
