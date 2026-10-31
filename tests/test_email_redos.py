"""Turning an HTML body into text must take linear time.

``_html_to_text`` used three expressions that each backtracked quadratically
on attacker-controlled HTML: ``(?is)<(script|style).*?</\\1>`` on repeated
unterminated ``<script`` openers, ``<[^>]+>`` on repeated ``<``, and
``[ \\t]*\\n[ \\t]*`` on a long run of spaces. A few hundred KB of such a
body held a ``parse_pst`` worker for minutes. Each is now a linear scan with
the same output; the old expressions are kept here as equivalence oracles.
"""

from __future__ import annotations

import random
import re
import time

from mulder.server.tools.email import (
    _collapse_line_whitespace,
    _html_to_text,
    _strip_script_style,
    _strip_tags,
)

_OLD_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style).*?</\1>")
_OLD_TAG_RE = re.compile(r"<[^>]+>")
_OLD_WS_RE = re.compile(r"[ \t]*\n[ \t]*")

# Generous: the old expressions need minutes to hours on these bodies.
_TIME_LIMIT = 10.0


def _old(html: str) -> str:
    return _OLD_SCRIPT_STYLE_RE.sub(" ", html)


_SAMPLES = [
    "",
    "plain text, no markup",
    "<html><head><style>p{color:red}</style></head><body>"
    "<p>Please action this <b>wire&nbsp;transfer</b> today.</p>"
    "<script>var x=1;</script></body></html>",
    "<SCRIPT type='text/javascript'>alert(1)</script>after",
    "<Style>\nbody{}\n</STYLE>kept",
    "<script>a</style>b</script>c",
    "<script>unterminated <style>x</style> tail",
    "<style>one</style> mid <style>two</style> end",
    "<scripts>not a tag name boundary</scripts></script>x",
    "<script>a</script >b</script>c",
    "<script><script>nested</script>outer</script>",
    "<styl>near miss</styl><scrip>x</scrip>",
]


def test_output_matches_the_old_expression_on_normal_html() -> None:
    for sample in _SAMPLES:
        assert _strip_script_style(sample) == _old(sample), sample


def test_output_matches_the_old_expression_on_random_markup() -> None:
    pieces = [
        "<script>",
        "<script",
        "</script>",
        "<SCRIPT>",
        "</Script>",
        "<style>",
        "<style",
        "</style>",
        "</STYLE>",
        "</script",
        "<",
        ">",
        "/",
        "a",
        " ",
        "\n",
    ]
    rng = random.Random(1333)
    for _ in range(5000):
        sample = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 25)))
        assert _strip_script_style(sample) == _old(sample), sample


def test_html_to_text_still_strips_blocks() -> None:
    text = _html_to_text("<style>p{}</style><p>hello <b>world</b></p><script>x()</script>")
    assert text == "hello  world"


def test_repeated_unterminated_openers_finish_quickly() -> None:
    # ~1.4 MB of unterminated openers: the old expression needs minutes here.
    body = ("<script" * 100_000) + ("<style" * 100_000)
    start = time.monotonic()
    out = _strip_script_style(body)
    elapsed = time.monotonic() - start
    assert out == body
    assert elapsed < _TIME_LIMIT, f"stripping took {elapsed:.1f}s"


def test_tag_stripping_matches_the_old_expression() -> None:
    samples = ["", "<>", "<<a>", "a<b>c", "<a", "a>", "<><a>", "x<\n>y", "<p>hi</p>"]
    pieces = ["<", ">", "a", " ", "\n", "<a>", "</", "<>"]
    rng = random.Random(1333)
    samples += [
        "".join(rng.choice(pieces) for _ in range(rng.randint(0, 25))) for _ in range(5000)
    ]
    for sample in samples:
        assert _strip_tags(sample) == _OLD_TAG_RE.sub(" ", sample), sample


def test_whitespace_collapse_matches_the_old_expression() -> None:
    samples = ["", "a", " a ", "\n", "\n\n", " \n", "\n ", "a \t\n\t b", " \n \n "]
    pieces = [" ", "\t", "\n", "a", "\r"]
    rng = random.Random(1333)
    samples += [
        "".join(rng.choice(pieces) for _ in range(rng.randint(0, 25))) for _ in range(5000)
    ]
    for sample in samples:
        assert _collapse_line_whitespace(sample) == _OLD_WS_RE.sub("\n", sample), sample


def test_html_to_text_on_hostile_bodies_finishes_quickly() -> None:
    # 1 MB each; the old expressions take minutes on a fifth of this.
    for body in ("<" * 1_000_000, " " * 1_000_000 + "x", "<script" * 150_000):
        start = time.monotonic()
        _html_to_text(body)
        elapsed = time.monotonic() - start
        assert elapsed < _TIME_LIMIT, f"{body[:10]!r}... took {elapsed:.1f}s"
