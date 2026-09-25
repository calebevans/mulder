"""validate_filter: the whitelist tokenizer guarding the only free-text nfdump parameter.

What: every filter string the tools and docs use must pass unchanged, ``""`` becomes ``any``, and
anything that is not an nfdump primitive, an address literal, a number or a bracket is rejected
before a subprocess exists (quotes, ``;``, ``$``, backticks, pipes, hostnames, unknown words,
over-long strings, leading ``-``, bad addresses, bad flag letters).  Grammar is nfdump's job
(``src ip 192.0.2.99 and`` passes the tokenizer and is mapped from exit 254 by the runner).
``combine_filter`` parenthesises a caller filter whenever it contains an ``or`` *token*
(``a or(b)``, ``(a)or(b)`` and tab-separated spellings too); non-ASCII text, including
Arabic-Indic digits that ``\\d`` would otherwise accept, is rejected up front;
``canonical_filter`` gives the spelling-independent form used for the source id.
When: pure ``core`` tests, no case DB, no subprocess.
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import re

import pytest

from mulder.server.tools.netflow import core
from mulder.server.tools.netflow.core import NetflowArgError

_RFC1918_SRC = "(src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16)"
_RFC1918_DST = "(dst net 10.0.0.0/8 or dst net 172.16.0.0/12 or dst net 192.168.0.0/16)"
_WINDOW = "first seen <= 2001-03-04T23:59:59 and last seen >= 2001-03-04T00:00:00"

ACCEPT = [
    "any",
    "src ip 10.0.3.44 and dst port 445",
    "src net 10.0.3.0/24 and dst net 10.0.8.0/24 and proto tcp",
    "src net 10.0.3.0/24 and dst net 10.0.8.0/24 and proto tcp and dst port 445",
    "host 203.0.113.77 and duration > 3600000",
    "dst ip 10.0.1.5 and dst port 3128",
    "dst port 443 or dst port 80",
    "dst port 80 or dst port 443",
    "src ip 10.0.3.44 and dst port 445 and dst net 10.0.8.0/24",
    "src ip 10.0.2.37 and dst ip 203.0.113.77 and dst port 40519",
    "((src ip 10.0.2.37 and dst ip 203.0.113.77) or "
    "(src ip 203.0.113.77 and dst ip 10.0.2.37)) and dst port 40519 and proto tcp",
    "src ip 10.0.2.90 and dst ip 198.51.100.23 and dst port 873",
    f"proto tcp and flags S and dst port in [ 445 3389 ] and {_RFC1918_SRC} and {_RFC1918_DST}"
    f" and {_WINDOW}",
    "proto tcp and flags S and not flags A and dst port in [ 445 3389 ]",
    f"{_RFC1918_SRC} and not {_RFC1918_DST}",
    "flags S and not flags A",
    "flags SA",
    "flags ASFRPUXC",
    "dst port in [ 445 3389 ]",
    "src ip in [ 10.0.3.44 10.0.3.29 ]",
    "duration > 3600000",
    "bytes > 1M",
    "packets >= 10k and bps < 1G",
    "first seen <= 2001-03-15T07:37:00 and last seen >= 2001-03-15T07:37:00",
    "src ip 192.0.2.99",
    "not dst net 172.16.0.0/12",
    "proto udp and dst port 53",
    "proto icmp or proto gre or proto esp",
    "ipv4 and src port gt 1024",
    "host 2001:db8:1000:cafe:20e:35ff:fec0:fed5",
    "src net 2001:db8::/32",
    "dst ip ::1",
    "SRC IP 10.0.3.44 AND DST PORT 445",
    "src ip 192.0.2.99 and",  # grammar error: nfdump's exit 254 handles it, not the tokenizer
    "flags",  # same: tokens are valid, grammar is nfdump's
    "(src ip 192.0.2.99 and dst ip 192.0.2.98) or (src ip 192.0.2.98 and dst ip 192.0.2.99)",
]

REJECT = [
    "src ipp 192.0.2.99",
    "ident 'edge-router'",
    "ident edge-router",
    'src ip "192.0.2.99"',
    "src ip 192.0.2.99; ls",
    "src ip 192.0.2.99 ; rm -rf /",
    "$(id)",
    "`id`",
    "src ip 192.0.2.99 | cat",
    "src ip 192.0.2.99\nand dst port 445",
    "src ip 192.0.2.99\r\nand dst port 445",
    "src ip 192.0.2.99\x00",
    "host evil.example.com",
    "host localhost",
    "-r /etc/passwd",
    "- any",
    "src ip 192.0.2.999",
    "src net 10.0.3.0/33",
    "src ip 256.0.2.1",
    "host 2001:zz::1",
    "flags Q",
    "flags SAQ",
    "S",
    "first seen <= 2001-03-04 12:40:00",
    "%tsr",
    "dst port 445 & 1",
    "dst port 445 && dst port 3389",
    "src ip 192.0.2.99 # comment",
    "@x",
    "src ip 192.0.2.99 and dst port 445 && true",
    "src ip 192.0.2.99 ~ 1",
    "src ip 192.0.2.99 \\",
    "src ip 192.0.2.99 {}",
    "exec ls",
    "src_ip 192.0.2.99",
    "dst port \u0664\u0664\u0665",  # Arabic-Indic digits: \d would match them without re.ASCII
    "src ip 192.0.2.99\u00a0and dst port 445",  # non-breaking space inside the text
    "src ip 192.0.2.\uff11",  # full-width digit
    "src ip 192.0.2.99 \u2013 1",
]


@pytest.mark.parametrize("expr", ACCEPT)
def test_accepts_every_documented_filter_unchanged(expr: str) -> None:
    assert core.validate_filter(expr) == expr


def test_leading_and_trailing_whitespace_is_stripped() -> None:
    assert core.validate_filter("  src ip 192.0.2.99\t") == "src ip 192.0.2.99"


@pytest.mark.parametrize("expr", ["", "   ", "\t", None])
def test_empty_becomes_any(expr: str | None) -> None:
    assert core.validate_filter(expr) == "any"


@pytest.mark.parametrize("expr", REJECT)
def test_rejects_unsafe_or_unknown(expr: str) -> None:
    with pytest.raises(NetflowArgError) as ei:
        core.validate_filter(expr)
    assert ei.value.suggestion is not None
    assert "examples" in ei.value.suggestion
    for example in core.EXAMPLE_FILTERS:
        assert example in ei.value.suggestion


@pytest.mark.parametrize("ch", [";", "$", "`", "|", "&", "%", "@", "#", '"', "'", "\n", "\\"])
def test_shell_metacharacters_can_never_pass(ch: str) -> None:
    with pytest.raises(NetflowArgError):
        core.validate_filter(f"src ip 192.0.2.99 {ch} dst port 445")
    with pytest.raises(NetflowArgError):
        core.validate_filter(f"src ip 192.0.2.99{ch}and dst port 445")
    if not ch.isspace():
        with pytest.raises(NetflowArgError):
            core.validate_filter(f"{ch}src ip 192.0.2.99")
        with pytest.raises(NetflowArgError):
            core.validate_filter(f"src ip 192.0.2.99{ch}")


def test_length_limit_is_exactly_1000_characters() -> None:
    body = " and ".join(["any"] * 125)  # 995 characters of valid tokens
    exactly = "(" * 5 + body
    assert len(exactly) == 1000
    assert core.validate_filter(exactly) == exactly
    with pytest.raises(NetflowArgError) as ei:
        core.validate_filter("(" * 6 + body)
    assert "1000" in str(ei.value)


def test_leading_dash_is_rejected_even_after_whitespace() -> None:
    with pytest.raises(NetflowArgError) as ei:
        core.validate_filter("   -R /evidence")
    assert "'-'" in str(ei.value)


def test_unknown_word_names_the_word() -> None:
    with pytest.raises(NetflowArgError) as ei:
        core.validate_filter("src ipp 192.0.2.99")
    assert "'ipp'" in str(ei.value)


def test_flag_letters_only_directly_after_flags() -> None:
    assert core.validate_filter("flags S") == "flags S"
    assert core.validate_filter("flags S and flags A") == "flags S and flags A"
    with pytest.raises(NetflowArgError):
        core.validate_filter("flags and S")
    with pytest.raises(NetflowArgError):
        core.validate_filter("flags s")  # lower-case letters are not flag letters
    with pytest.raises(NetflowArgError):
        core.validate_filter("flags ASFRPUXCEA")  # nine letters


def test_bad_address_names_the_literal() -> None:
    with pytest.raises(NetflowArgError) as ei:
        core.validate_filter("src ip 192.0.2.999")
    assert "192.0.2.999" in str(ei.value)


def test_non_ascii_is_rejected_before_the_tokenizer() -> None:
    with pytest.raises(NetflowArgError) as ei:
        core.validate_filter("dst port \u0664\u0664\u0665")
    assert "ASCII" in str(ei.value)
    assert core._TOKEN_RE.flags & re.ASCII
    assert not core._TOKEN_RE.match("\u0664\u0664\u0665")  # \d is [0-9] only


def test_combine_filter_parenthesises_or_clauses_only() -> None:
    assert core.combine_filter("any", "", "") == "any"
    assert core.combine_filter() == "any"
    assert core.combine_filter("any", "any") == "any"
    assert core.combine_filter("src ip 192.0.2.99", "", "") == "src ip 192.0.2.99"
    assert core.combine_filter("any", "last seen >= 2001-03-04T12:38:00") == (
        "last seen >= 2001-03-04T12:38:00"
    )
    assert core.combine_filter("dst port 443 or dst port 80", "", _WINDOW) == (
        f"(dst port 443 or dst port 80) and {_WINDOW}"
    )
    assert core.combine_filter("src ip 192.0.2.99", "dst port 445", _WINDOW) == (
        f"src ip 192.0.2.99 and dst port 445 and {_WINDOW}"
    )


@pytest.mark.parametrize(
    "expr",
    [
        "src ip 192.0.2.99 or(dst port 3128)",
        "(src ip 192.0.2.99)or(dst port 3128)",
        "src ip 192.0.2.99\tor\tdst port 3128",
        "src ip 192.0.2.99  OR  dst port 3128",
        "src ip 192.0.2.99 or dst port 3128",
        "(src ip 192.0.2.99 or dst port 3128)",
        "not(src ip 192.0.2.99)or dst port 3128",
    ],
)
def test_combine_filter_detects_or_as_a_token(expr: str) -> None:
    """nfdump binds ``and`` tighter than ``or``: an unwrapped ``a or b and <window>`` lets ``a``
    escape the window and the direction clause."""
    assert core.validate_filter(expr) == expr
    nets = list(core.DEFAULT_INTERNAL_NETS)
    combined = core.combine_filter(expr, core.net_clause("egress", nets), _WINDOW)
    assert combined == f"({expr}) and ({_RFC1918_SRC} and not {_RFC1918_DST}) and {_WINDOW}"
    assert core.validate_filter(combined) == combined


@pytest.mark.parametrize(
    "expr",
    [
        "dst port 445",
        "proto tcp",
        "src ip 192.0.2.99 and dst port 445",
        "flags SO",
        "host 192.0.2.99",
    ],
)
def test_combine_filter_leaves_primitives_without_or_bare(expr: str) -> None:
    assert not core._OR_TOKEN_RE.search(expr)  # "port"/"proto"/flag letters are not ``or``
    assert core.combine_filter(expr, _WINDOW) == f"{expr} and {_WINDOW}"


def test_canonical_filter_folds_keyword_case_and_whitespace_only() -> None:
    assert core.canonical_filter("SRC IP 10.0.3.44 AND DST PORT 445") == (
        "src ip 10.0.3.44 and dst port 445"
    )
    assert core.canonical_filter("src  ip\t10.0.3.44 and dst port 445") == (
        "src ip 10.0.3.44 and dst port 445"
    )
    assert core.canonical_filter("  any ") == "any" and core.canonical_filter("") == "any"
    assert core.canonical_filter("(dst port 443)or(dst port 80)") == (
        "( dst port 443 ) or ( dst port 80 )"
    )
    assert core.canonical_filter("dst port in [ 445 3389 ]") == "dst port in [ 445 3389 ]"
    # flag letters, addresses and numbers are kept exactly as written
    assert core.canonical_filter("FLAGS SA and not flags A") == "flags SA and not flags A"
    assert core.canonical_filter("host 2001:DB8::1 and bytes > 1M") == (
        "host 2001:DB8::1 and bytes > 1M"
    )
    with pytest.raises(NetflowArgError):
        core.canonical_filter("src ipp 1")


def test_net_clause_per_direction() -> None:
    nets = list(core.DEFAULT_INTERNAL_NETS)
    assert core.net_clause("egress", nets) == f"{_RFC1918_SRC} and not {_RFC1918_DST}"
    assert core.net_clause("ingress", nets) == f"{_RFC1918_DST} and not {_RFC1918_SRC}"
    assert core.net_clause("internal", nets) == f"{_RFC1918_SRC} and {_RFC1918_DST}"
    assert core.net_clause("any", nets) == ""
    assert core.net_clause("egress", ["10.0.0.0/8"]) == (
        "(src net 10.0.0.0/8) and not (dst net 10.0.0.0/8)"
    )


def test_every_generated_clause_passes_the_validator() -> None:
    """The tools' own clauses (direction, window, pair, sweep) are made of whitelisted tokens."""
    nets = core.validate_internal_nets(None)
    ts, te = core.parse_window("2001-03-04T00:00:00", "2001-03-04T23:59:59")
    for direction in sorted(core.DIRECTIONS):
        clause = core.combine_filter(
            "dst port 443 or dst port 80",
            core.net_clause(direction, nets),
            core.window_clause(ts, te),
        )
        assert core.validate_filter(clause) == clause


def test_internal_nets_validation() -> None:
    assert core.validate_internal_nets(None) == list(core.DEFAULT_INTERNAL_NETS)
    assert core.validate_internal_nets([]) == list(core.DEFAULT_INTERNAL_NETS)
    assert core.validate_internal_nets(["10.0.3.1/24"]) == ["10.0.3.0/24"]
    with pytest.raises(NetflowArgError):
        core.validate_internal_nets(["10.0.0.0/8"] * 9)
    with pytest.raises(NetflowArgError):
        core.validate_internal_nets(["10.0.0.0/8; rm -rf /"])
    with pytest.raises(NetflowArgError):
        core.validate_internal_nets(["evil.example.com"])
