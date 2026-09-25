"""Pure helpers for the NetFlow (nfdump ``nfcapd.*``) tools.

Everything in this module is side-effect free apart from ``stage`` (a symlink
tempdir) and needs only the standard library plus ``mulder.extractors.classifier``
for the 4-byte magic check.  ``tools.py`` owns the MCP surface, the subprocess
runner and the case DB; this module owns constants, validation, file discovery
and selection, argv fragments, output parsers and the statistics behind the
sweep and pair-timeline tools.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import statistics
import tempfile
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from mulder.extractors.classifier import has_nfdump_magic

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXTRACTOR = "nfdump"
NFDUMP_BINARY = "/opt/nfdump/bin/nfdump"
PRLIMIT_BINARY = "/usr/bin/prlimit"
LOOKBEHIND_DAYS = 1
# A record is written when it expires; LOOKAHEAD_DAYS = 8 covers exporters whose active timeout
# is up to 7 days, plus one rotation day.
LOOKAHEAD_DAYS = 8
MAX_FILES = 400
TIMEOUT_BASE_S = 120
TIMEOUT_PER_FILE_S = 30
TIMEOUT_CAP_S = 1800
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_FILTER_LEN = 1000
INSERT_BATCH = 5000
MAX_INDEX_ROWS = 500  # data rows per source (+1 header)
DEFAULT_INLINE_ROWS = 20
MAX_INLINE_ROWS = 100
NFDUMP_SLOT_COUNT = 2  # at most two nfdump processes per server process
NFDUMP_RLIMIT_AS = 4 << 30  # RLIMIT_AS for every nfdump child (via prlimit --as)
NFDUMP_RLIMIT_CORE = 0  # RLIMIT_CORE: an abort under the 4 GiB cap must never dump a core file
HEAVY_MAX_FILES = 3
HEAVY_MASK_MIN = 25  # srcip4/N, dstip4/N with N >= 25 have per-host cardinality (= srcip/dstip)
# Any stderr at rc 0 fails the run (nfdump 1.7.10 prints nothing on stderr in a healthy run and
# aborts or hollows out a -R walk *silently* on a damaged file).  The patterns
# below are the messages nfdump prints for truncated / block-corrupt files; they pick the specific
# error text, but a line that matches none of them still fails unless it is in the allowlist.
STDERR_FAIL_RE = re.compile(
    r"Short read|read\(\) error|bad magic|bad version|stat\(\) error|Error open file"
    r"|appendix offset error|Corrupt data file|Unknown block type|Can.t process block type"
    r"|DataBlock count error|Skip block|Skip record|Corrupt exporter|Corrupt extension"
    r"|Memory allocation error|malloc\(\) error|pthread_create\(\) error"
)
# stderr line prefixes that are known to be harmless at rc 0.  Deliberately empty: every healthy
# nfdump 1.7.10 run prints nothing on stderr; extend only with a known benign message.
STDERR_BENIGN_PREFIXES: tuple[str, ...] = ()
# Out-of-memory under RLIMIT_AS: rc 255 (pthread_create under a small cap), death by SIGABRT
# (rc -6 from subprocess, 134 from a shell) from the flowHash_resize assertion under the
# 4 GiB cap, or an allocation message on stderr.
MEMORY_FAIL_RE = re.compile(
    r"Assertion .* failed|flowHash_resize|[Mm]emory allocation|malloc\(\)|pthread_create\(\)"
)
PROTO_NAMES: dict[int, str] = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmp6"}
DEFAULT_INTERNAL_NETS: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
DEFAULT_SWEEP_PORTS: tuple[int, ...] = (22, 135, 139, 445, 3389, 5985, 5986)
SWEEP_TUPLE_CAP = 50_000
MAX_INTERNAL_NETS = 8
MAX_SWEEP_PORTS = 16
MAX_TARGETS_LISTED = 20
MAX_EXCLUDED_LISTED = 20
MAX_SESSIONS_LISTED = 10

NFCAPD_NAME_RE = re.compile(r"^nfcapd\.\d{12}(?:\d{2})?$")

# Output formats.  Header names verified on nfdump 1.7.10; the header is printed
# even with -q, and epoch %tsr/%ter carry milliseconds and ignore TZ.
RAW_FMT = "csv:%tsr,%ter,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt"
SEG_FMT = "csv:%tsr,%ter,%sa,%da,%pkt,%byt,%fl"
STAT_FMT = "csv"
SEG_AGG_KEYS = "srcip4/24,dstip4/24"

_AGG_TAGS: dict[str, str] = {
    "proto": "%pr",
    "srcip": "%sa",
    "dstip": "%da",
    "srcport": "%sp",
    "dstport": "%dp",
    "flags": "%flg",
}
_MASKED_KEY_RE = re.compile(r"^(srcip|dstip)4/(?:[1-9]|[12]\d|3[0-2])$")

AGG_KEYS = frozenset({"proto", "srcip", "dstip", "srcport", "dstport", "flags"})
STAT_KEYS = frozenset({"srcip", "dstip", "ip", "srcport", "dstport", "port"})
STAT_ORDER = frozenset({"flows", "packets", "bytes", "pps", "bps", "bpp"})
RAW_ORDER = (STAT_ORDER - {"flows"}) | {"tstart", "tend", "duration"}
VOLUME_ORDER = frozenset({"bytes", "packets", "bps", "bpp", "pps"})
DIRECTIONS = frozenset({"any", "egress", "ingress", "internal"})
PROTOS = frozenset({"any", "tcp", "udp", "icmp"})
_IP_STAT_KEYS = frozenset({"srcip", "dstip", "ip"})

EXAMPLE_FILTERS = (
    "src ip 192.0.2.10 and dst port 445",
    "src net 192.0.2.0/24 and dst net 198.51.100.0/24 and proto tcp",
    "host 203.0.113.5 and duration > 3600000",
)

_STAT_COL_NORMALISE: dict[str, str] = {
    "ipkt": "pkt",
    "ipktP": "pktP",
    "ibyt": "byt",
    "ibytP": "bytP",
    "ipps": "pps",
    "ibps": "bps",
    "ibpp": "bpp",
}
_FLOW_COL_MAP: dict[str, str] = {
    "firstSeen": "first",
    "lastSeen": "last",
    "proto": "proto",
    "srcAddr": "sa",
    "srcPort": "sp",
    "dstAddr": "da",
    "dstPort": "dp",
    "flags": "flg",
    "packets": "pkt",
    "bytes": "byt",
    "bps": "bps",
    "bpp": "bpp",
    "flows": "fl",
}
NO_MATCH = "No matching flows"


class NetflowArgError(ValueError):
    """A model-supplied argument failed validation (maps to ``invalid_argument``)."""

    def __init__(self, message: str, suggestion: str | None = None) -> None:
        super().__init__(message)
        self.suggestion = suggestion


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

_ISO_IN_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?"
    r"(Z|[+-]\d{2}:?\d{2})?$",
    re.ASCII,  # [0-9] only: Unicode digits are refused, as in filters
)


def parse_iso(value: str, name: str = "timestamp") -> datetime:
    """Parse ``YYYY-MM-DD[T ]HH:MM:SS[.fff][Z|+00:00]`` into a naive UTC datetime.

    Any non-zero offset is rejected: nfcapd timestamps are UTC and the case DB
    compares ``event_time`` strings lexically, so only one zone can exist.
    """
    m = _ISO_IN_RE.match(value.strip())
    if not m:
        raise NetflowArgError(
            f"{name} {value!r} is not 'YYYY-MM-DDTHH:MM:SS'",
            "timestamps are UTC in the form 'YYYY-MM-DDTHH:MM:SS' (T-separated)",
        )
    y, mo, d, hh, mm, ss, frac, tz = m.groups()
    if tz and tz != "Z" and tz.replace(":", "") not in ("+0000", "-0000"):
        raise NetflowArgError(f"{name} {value!r} carries a non-UTC offset", "timestamps are UTC")
    micro = int((frac or "0").ljust(6, "0")[:6])
    try:
        return datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss), micro)
    except ValueError as exc:
        raise NetflowArgError(f"{name} {value!r}: {exc}", "timestamps are UTC") from exc


def parse_window(
    t_start: str | None, t_end: str | None
) -> tuple[datetime | None, datetime | None]:
    """Validate an optional, independently open-ended UTC window."""
    ts = parse_iso(t_start, "t_start") if t_start else None
    te = parse_iso(t_end, "t_end") if t_end else None
    if ts and te and ts > te:
        raise NetflowArgError("t_start is after t_end", "swap the bounds or drop one")
    return ts, te


def window_clause(ts: datetime | None, te: datetime | None) -> str:
    """Active-in-window predicate from nfdump filter primitives (or ``""``)."""
    parts: list[str] = []
    if te is not None:
        parts.append(f"first seen <= {te:%Y-%m-%dT%H:%M:%S}")
    if ts is not None:
        parts.append(f"last seen >= {ts:%Y-%m-%dT%H:%M:%S}")
    return " and ".join(parts)


def iso_s(epoch: float) -> str:
    """Epoch seconds -> naive UTC ``YYYY-MM-DDTHH:MM:SS`` (the ``event_time`` form)."""
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def iso_ms(epoch: float) -> str:
    """Epoch seconds with fraction -> ``YYYY-MM-DDTHH:MM:SS.mmm`` (UTC)."""
    whole = int(epoch)
    ms = int(round((epoch - whole) * 1000))
    if ms >= 1000:
        whole += 1
        ms -= 1000
    return datetime.fromtimestamp(whole, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}"


def stat_ts_to_iso(value: str) -> str:
    """``2001-02-03 04:05:06`` (STAT ``ts``/``te`` under TZ=UTC) -> ISO ``T`` form."""
    return value.strip().replace(" ", "T")


def window_label(ts: datetime | None, te: datetime | None) -> str:
    """Header/JSON rendering of the window: ``none`` or ``a..b`` with ``*`` for open ends."""
    if ts is None and te is None:
        return "none"
    lo = f"{ts:%Y-%m-%dT%H:%M:%S}" if ts else "*"
    hi = f"{te:%Y-%m-%dT%H:%M:%S}" if te else "*"
    return f"{lo}..{hi}"


# ---------------------------------------------------------------------------
# Filter validation (the only free-text parameter)
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>[ \t]+)
  | (?P<paren>[()\[\]])
  | (?P<cmp><=|>=|==|!=|<|>|=)
  | (?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})
  | (?P<cidr>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)
  | (?P<v6>[0-9a-fA-F]*:[0-9a-fA-F:.]+(?:/\d{1,3})?)
  | (?P<num>\d+[kKmMgG]?)
  | (?P<word>[A-Za-z][A-Za-z0-9]*)
    """,
    re.X | re.ASCII,  # \d is [0-9] only: Arabic-Indic digits must not reach nfdump
)
# ``or`` as a token (not the substring " or "): ``a or(b)``, ``(a)or(b)`` and tab-separated
# spellings all pass the tokenizer and must be parenthesised too.
_OR_TOKEN_RE = re.compile(r"(?i)(?<![A-Za-z0-9])or(?![A-Za-z0-9])")
_WORDS = frozenset(
    {
        "and", "or", "not", "src", "dst", "ip", "host", "net", "port", "proto", "tcp", "udp",
        "icmp", "gre", "esp", "in", "flags", "duration", "packets", "bytes", "bps", "pps",
        "bpp", "first", "last", "seen", "ipv4", "ipv6", "any", "eq", "ne", "gt", "lt", "ge",
        "le",
    }
)  # fmt: skip
_FLAGS_RE = re.compile(r"^[ASFRPUXCE]{1,8}$")


def _filter_error(message: str) -> NetflowArgError:
    return NetflowArgError(
        message,
        "allowed: nfdump primitives (src/dst ip|net|port, host, proto, flags, duration, "
        "bytes, packets, first/last seen), IPv4/IPv6 literals, numbers, and/or/not and "
        "parentheses; examples: " + "; ".join(f"'{e}'" for e in EXAMPLE_FILTERS),
    )


def validate_filter(expr: str | None) -> str:
    """Whitelist-tokenize an nfdump filter; return the normalised expression.

    Empty -> ``"any"``.  Every character must be consumed by a token; words must
    be known nfdump keywords (or a flag string directly after ``flags``); every
    address must parse with ``ipaddress``.  Grammar errors are left to nfdump
    (exit 254), which the runner maps to ``invalid_argument``.
    """
    text = (expr or "").strip()
    if not text:
        return "any"
    if len(text) > MAX_FILTER_LEN:
        raise _filter_error(f"filter longer than {MAX_FILTER_LEN} characters")
    if not text.isascii():
        raise _filter_error("filter must be ASCII")
    if text.startswith("-"):
        raise _filter_error("filter must not start with '-'")
    pos = 0
    prev_word: str | None = None
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if m is None:
            raise _filter_error(
                f"filter has an unsupported character at offset {pos}: {text[pos]!r}"
            )
        kind = m.lastgroup
        tok = m.group(0)
        pos = m.end()
        if kind == "ws":
            continue
        if kind == "word":
            low = tok.lower()
            if low in _WORDS:
                prev_word = low
                continue
            if prev_word == "flags" and _FLAGS_RE.match(tok):
                prev_word = None
                continue
            raise _filter_error(f"filter word {tok!r} is not an allowed nfdump keyword")
        if kind in ("cidr", "v6"):
            try:
                ipaddress.ip_network(tok, strict=False)
            except ValueError as exc:
                raise _filter_error(f"filter address {tok!r} is invalid: {exc}") from exc
        prev_word = None
    return text


def canonical_filter(expr: str) -> str:
    """The spelling-independent form of a *validated* filter, used only for the source id.

    Keywords are lower-cased, whitespace is collapsed to single spaces and
    brackets are spaced out; addresses, numbers and the flag letters after
    ``flags`` (case-sensitive in nfdump) are kept exactly.  ``SRC  IP 192.0.2.4``
    and ``src ip 192.0.2.4`` therefore share one ``netflow.<kind>.<hid>``;
    the validated original is still what reaches nfdump.
    """
    text = validate_filter(expr)
    if text == "any":
        return text
    out: list[str] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        assert m is not None  # validate_filter consumed every character
        kind = m.lastgroup
        tok = m.group(0)
        pos = m.end()
        if kind == "ws":
            continue
        if kind == "word" and tok.lower() in _WORDS:
            out.append(tok.lower())
        else:
            out.append(tok)  # addresses, numbers, brackets and flag strings: kept as written
    return " ".join(out)


_UNRESTRICTIVE_TOKENS = frozenset({"any", "ipv4", "ipv6", "and", "or", "(", ")"})


def is_unrestrictive_filter(expr: str) -> bool:
    """Whether a *validated* filter selects every flow of an address family at most.

    ``any``, ``ipv4`` and ``ipv6`` joined by ``and``/``or`` do not narrow the key space
    of a heavy query: over many files ``filter='ipv4'`` can still die at the 4 GiB cap
    (SIGABRT), so the heavy-query guard treats them like ``any``.  Anything else (an
    address, port, protocol, flag or volume primitive) may narrow it and is left to
    nfdump and the memory classifier.
    """
    return all(tok in _UNRESTRICTIVE_TOKENS for tok in canonical_filter(expr).split())


def combine_filter(*clauses: str) -> str:
    """AND together non-empty clauses; a lone/empty result is ``any``.

    A caller filter other than ``any`` is parenthesised whenever it contains an
    ``or`` *token* (nfdump binds ``and`` tighter than ``or``, so an unwrapped
    ``a or b`` would let ``a`` escape the window and direction clauses);
    ``any`` itself is dropped when other clauses are present.
    """
    parts = [c for c in clauses if c and c != "any"]
    if not parts:
        return "any"
    return " and ".join(f"({c})" if _OR_TOKEN_RE.search(c) else c for c in parts)


def validate_internal_nets(nets: Sequence[str] | None) -> list[str]:
    """Validate ``internal_nets`` (<= 8 CIDRs); default to RFC1918."""
    if not nets:
        return list(DEFAULT_INTERNAL_NETS)
    if len(nets) > MAX_INTERNAL_NETS:
        raise NetflowArgError(f"internal_nets has more than {MAX_INTERNAL_NETS} entries")
    out: list[str] = []
    for n in nets:
        try:
            out.append(str(ipaddress.ip_network(str(n).strip(), strict=False)))
        except ValueError as exc:
            raise NetflowArgError(f"internal_nets entry {n!r} is not a CIDR: {exc}") from exc
    return out


def validate_ip(value: str, name: str) -> str:
    """Validate one IP address parameter."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise NetflowArgError(f"{name} {value!r} is not an IP address") from exc


def _as_int(value: object) -> object:
    """Accept an ASCII digit-only string as an int (what pydantic's lax mode already does on the
    direct MCP path; ``run_parallel``/``start_extraction_batch`` call tools without coercion).
    Anything else is returned unchanged for the caller's type check."""
    if isinstance(value, str):
        v = value.strip()
        if v.isascii() and v.isdigit():
            return int(v)
    return value


def validate_port(value: int, name: str) -> int:
    """Validate one TCP/UDP port parameter (1..65535; a digit-only string is accepted)."""
    value = _as_int(value)  # type: ignore[assignment]
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise NetflowArgError(f"{name} {value!r} is not a port in 1..65535 (pass an integer)")
    return value


def validate_choice(value: str, allowed: frozenset[str], name: str) -> str:
    """Validate a whitelisted keyword parameter (case-insensitive)."""
    v = str(value).strip().lower()
    if v not in allowed:
        raise NetflowArgError(f"{name} {value!r} must be one of {sorted(allowed)}")
    return v


def validate_agg_keys(keys: Sequence[str] | None) -> list[str] | None:
    """Validate ``aggregate``: None or 1..5 distinct keys from AGG_KEYS / srcip4|dstip4/N."""
    if keys is None:
        return None
    if not 1 <= len(keys) <= 5:
        raise NetflowArgError("aggregate needs 1..5 keys")
    out: list[str] = []
    seen_sides: set[str] = set()
    for k in keys:
        kk = str(k).strip().lower()
        if kk not in AGG_KEYS and not _MASKED_KEY_RE.match(kk):
            raise NetflowArgError(
                f"aggregate key {k!r} is not allowed",
                f"allowed: {sorted(AGG_KEYS)} plus srcip4/N and dstip4/N (N 1..32)",
            )
        if kk in out:
            raise NetflowArgError(f"aggregate key {k!r} is repeated")
        # nfdump has ONE srcAddr / dstAddr column: ``srcip`` beside ``srcip4/N`` prints the masked
        # network under a per-host row (or ignores the host key), and two masks on one side are
        # rejected by nfdump with rc 1; refuse all three up front.
        side = kk.split("4/", 1)[0] if _MASKED_KEY_RE.match(kk) else kk
        if side in ("srcip", "dstip"):
            if side in seen_sides:
                raise NetflowArgError(
                    f"aggregate key {k!r} conflicts with another {side} key: nfdump has one "
                    f"{side} address column",
                    f"use either {side} (per host) or ONE {side}4/N (per network), not both",
                )
            seen_sides.add(side)
        out.append(kk)
    return out


def clamp(value: int, lo: int, hi: int) -> int:
    """Clamp an int parameter into its documented range (bool is rejected; a digit-only string
    is accepted as its int value)."""
    value = _as_int(value)  # type: ignore[assignment]
    if isinstance(value, bool) or not isinstance(value, int):
        raise NetflowArgError(f"{value!r} is not an integer")
    return max(lo, min(hi, value))


def net_clause(direction: str, nets: Sequence[str]) -> str:
    """Filter clause for a direction relative to ``nets`` (``""`` for ``any``)."""
    src = " or ".join(f"src net {n}" for n in nets)
    dst = " or ".join(f"dst net {n}" for n in nets)
    if direction == "egress":
        return f"({src}) and not ({dst})"
    if direction == "ingress":
        return f"({dst}) and not ({src})"
    if direction == "internal":
        return f"({src}) and ({dst})"
    return ""


def agg_format(keys: Sequence[str]) -> str:
    """``-o`` value for an aggregated query (``%flg`` only when ``flags`` is a key)."""
    tags: list[str] = []
    for k in keys:
        if _MASKED_KEY_RE.match(k):
            tags.append("%sa" if k.startswith("srcip") else "%da")
        else:
            tags.append(_AGG_TAGS[k])
    return "csv:%tsr,%ter," + ",".join(tags) + ",%pkt,%byt,%bps,%bpp,%fl"


def _heavy_key(key: str) -> str:
    """``srcip4/N``/``dstip4/N`` with ``N >= HEAVY_MASK_MIN`` count as the unmasked key: a /32
    (or /25..) mask has per-host cardinality, so spelling ``srcip,dstip`` as
    ``srcip4/32,dstip4/32`` must not bypass the memory guard."""
    if _MASKED_KEY_RE.match(key) and int(key.rsplit("/", 1)[1]) >= HEAVY_MASK_MIN:
        return key.split("4/", 1)[0]
    return key


def is_heavy_query(aggregate: Sequence[str] | None, order: str) -> bool:
    """Whether a query keeps every distinct key in nfdump's memory."""
    if aggregate is None:
        return order in VOLUME_ORDER
    keys = {_heavy_key(k) for k in aggregate}
    return "srcport" in keys or {"srcip", "dstip"} <= keys


# ---------------------------------------------------------------------------
# File discovery / selection / staging
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NfFile:
    """One validated nfdump file (regular, non-empty, magic-checked)."""

    path: Path
    day: date | None
    size: int


@dataclass(frozen=True)
class Excluded:
    """A directory entry that was nominated but rejected."""

    path: str
    reason: str

    def as_dict(self) -> dict[str, object]:
        """JSON form."""
        return {"path": self.path, "reason": self.reason}


def _name_day(name: str) -> date | None:
    if not NFCAPD_NAME_RE.match(name.lower()):
        return None
    digits = name.split(".", 1)[1]
    try:
        return date(int(digits[0:4]), int(digits[4:6]), int(digits[6:8]))
    except ValueError:
        return None


def _is_candidate(path: Path) -> bool:
    name = path.name.lower()
    if NFCAPD_NAME_RE.match(name):
        return True
    suffix = path.suffix
    return not suffix or suffix[1:].isdigit()


def _inspect(path: Path) -> NfFile | Excluded | None:
    """Classify one entry; None means "not a candidate, ignore silently"."""
    if path.is_symlink():
        return Excluded(str(path), "symlink")
    if path.is_dir():
        return None
    if not path.is_file():
        return Excluded(str(path), "not a regular file")
    try:
        size = path.stat().st_size
    except OSError:
        return Excluded(str(path), "not a regular file")
    if size == 0:
        return Excluded(str(path), "empty")
    if not _is_candidate(path):
        return None
    if not has_nfdump_magic(path):
        return Excluded(str(path), "no nfdump magic")
    return NfFile(path=path, day=_name_day(path.name), size=size)


def discover(root: Path) -> tuple[list[NfFile], list[Excluded]]:
    """Walk ``root`` (file or directory) and admit files by 4-byte magic only.

    A rotation-style name merely nominates a file; a text file with such a name
    is excluded, a renamed file with magic is kept.  Symlinks are never
    followed (``resolve_allowed_path`` already fixed ``root``).
    """
    files: list[NfFile] = []
    excluded: list[Excluded] = []
    single = root.is_file() or root.is_symlink()
    entries: list[Path] = [root] if single else sorted(root.rglob("*"))
    for entry in entries:
        try:
            res = _inspect(entry)
        except OSError as exc:
            res = Excluded(str(entry), f"unreadable: {exc.strerror or exc}")
        if isinstance(res, NfFile):
            files.append(res)
        elif isinstance(res, Excluded):
            excluded.append(res)
    files.sort(key=lambda f: (f.day or date.max, f.path.name))
    return files, excluded


def _shift_day(d: date, days: int) -> date:
    """``d + days`` clamped to the calendar (``0001-01-01`` / ``9999-12-31`` never overflow)."""
    try:
        return d + timedelta(days=days)
    except OverflowError:
        return date.min if days < 0 else date.max


def select(files: Sequence[NfFile], ts: datetime | None, te: datetime | None) -> list[NfFile]:
    """Keep the files whose day can hold a record active in the window.

    Files dated ``t_start - LOOKBEHIND_DAYS`` .. ``t_end + LOOKAHEAD_DAYS``
    (1 and 8 days) are read.  A record is written when it expires (never
    earlier); LOOKAHEAD_DAYS = 8 covers exporters whose active timeout is up
    to 7 days, plus one rotation day.  ``LOOKBEHIND_DAYS`` covers clock skew.
    Undated files are always kept.
    """
    lo = _shift_day(ts.date(), -LOOKBEHIND_DAYS) if ts else None
    hi = _shift_day(te.date(), LOOKAHEAD_DAYS) if te else None
    out: list[NfFile] = []
    for f in files:
        if f.day is None or ((lo is None or f.day >= lo) and (hi is None or f.day <= hi)):
            out.append(f)
    return out


@contextmanager
def stage(selected: Sequence[NfFile]) -> Iterator[list[str]]:
    """Yield the nfdump read arguments for ``selected`` without exposing evidence dirs.

    One file -> ``["-r", path]``; several -> a private ``nfsel_*`` directory of
    zero-padded symlinks (``000000``, ``000001`` ...) read with ``-R``, removed
    afterwards.  nfdump therefore never walks an evidence directory and never
    sees an unvalidated entry.
    """
    if len(selected) == 1:
        yield ["-r", str(selected[0].path)]
        return
    tmp = tempfile.mkdtemp(prefix="nfsel_")
    try:
        for i, f in enumerate(selected):
            os.symlink(str(f.path), os.path.join(tmp, f"{i:06d}"))
        yield ["-R", tmp]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def timeout_for(selected: Sequence[NfFile]) -> int:
    """Subprocess budget in seconds for a pass over ``selected``."""
    return min(TIMEOUT_CAP_S, TIMEOUT_BASE_S + TIMEOUT_PER_FILE_S * len(selected))


def file_range(selected: Sequence[NfFile]) -> list[str]:
    """``[first name, last name]`` of the staged set (empty list when none)."""
    if not selected:
        return []
    return [selected[0].path.name, selected[-1].path.name]


# ---------------------------------------------------------------------------
# Source naming
# ---------------------------------------------------------------------------


def source_hid(tool: str, evidence_path: str, params: Mapping[str, object]) -> str:
    """16-hex deterministic id over the tool, the resolved path and the effective params."""
    payload = json.dumps(
        {"tool": tool, "evidence_path": evidence_path, **params}, sort_keys=True, default=str
    )
    return hashlib.blake2b(payload.encode(), digest_size=8).hexdigest()


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


@dataclass
class FlowRec:
    """One line of a RAW / AGG / SEG csv table (fields absent from the format are None)."""

    first: float
    last: float
    proto: int | None = None
    sa: str | None = None
    sp: int | None = None
    da: str | None = None
    dp: int | None = None
    flg: str | None = None
    pkt: int = 0
    byt: int = 0
    bps: int | None = None
    bpp: int | None = None
    fl: int | None = None

    @property
    def duration_s(self) -> float:
        """Seconds between first and last seen (never negative)."""
        return max(0.0, self.last - self.first)

    def key(self) -> tuple[object, ...]:
        """Exact-duplicate key over every field."""
        return (
            self.first, self.last, self.proto, self.sa, self.sp, self.da, self.dp, self.flg,
            self.pkt, self.byt, self.bps, self.bpp, self.fl,
        )  # fmt: skip


@dataclass
class ParsedFlows:
    """Result of parsing a flow csv table."""

    rows: list[FlowRec] = field(default_factory=list)
    dropped: int = 0
    warnings: list[str] = field(default_factory=list)
    saw_header: bool = False


def _int(v: str) -> int:
    return int(float(v.strip())) if v.strip() else 0


def _ip_or_none(v: str) -> str | None:
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError:
        return None


def parse_flow_csv(stdout: str) -> ParsedFlows:
    """Parse ``firstSeen,...`` tables (RAW/AGG/SEG); unparseable addresses drop the row."""
    out = ParsedFlows()
    cols: list[str] | None = None
    bad_addr = 0
    bad_line = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line == NO_MATCH:
            continue
        if line.startswith("firstSeen,"):
            cols = [_FLOW_COL_MAP.get(c, c) for c in line.split(",")]
            out.saw_header = True
            continue
        if cols is None:
            continue
        parts = line.split(",")
        if len(parts) != len(cols):
            bad_line += 1
            continue
        rec: dict[str, str] = dict(zip(cols, parts, strict=True))
        try:
            fr = FlowRec(first=float(rec["first"]), last=float(rec["last"]))
            if "proto" in rec:
                fr.proto = _int(rec["proto"])
            if "sp" in rec:
                fr.sp = _int(rec["sp"])
            if "dp" in rec:
                fr.dp = _int(rec["dp"])
            if "flg" in rec:
                fr.flg = rec["flg"].strip()
            fr.pkt = _int(rec.get("pkt", "0"))
            fr.byt = _int(rec.get("byt", "0"))
            if "bps" in rec:
                fr.bps = _int(rec["bps"])
            if "bpp" in rec:
                fr.bpp = _int(rec["bpp"])
            if "fl" in rec:
                fr.fl = _int(rec["fl"])
        except (KeyError, ValueError):
            bad_line += 1
            continue
        if "sa" in rec:
            fr.sa = _ip_or_none(rec["sa"])
            if fr.sa is None:
                bad_addr += 1
                continue
        if "da" in rec:
            fr.da = _ip_or_none(rec["da"])
            if fr.da is None:
                bad_addr += 1
                continue
        out.rows.append(fr)
    out.dropped = bad_addr + bad_line
    if bad_addr:
        out.warnings.append(f"{bad_addr} rows with unparseable addresses dropped")
    if bad_line:
        out.warnings.append(f"{bad_line} malformed csv lines dropped")
    return out


@dataclass
class StatRow:
    """One row of an nfdump ``-s`` statistics table (columns normalised, ``i`` prefix removed)."""

    ts: str  # ISO T form, seconds
    te: str
    td: float
    proto: str  # "any" | "tcp" | "udp" | "17" ...
    val: str
    fl: int
    flP: float
    pkt: int
    pktP: float
    byt: int
    bytP: float
    pps: int
    bps: int
    bpp: int


@dataclass
class StatTable:
    """One ``-s`` table (nfdump prints one per ``-s`` option, in order)."""

    rows: list[StatRow] = field(default_factory=list)
    dropped: int = 0


@dataclass
class ParsedStats:
    """All tables of one nfdump run plus row-level warnings."""

    tables: list[StatTable] = field(default_factory=list)
    dropped: int = 0
    warnings: list[str] = field(default_factory=list)


def proto_name(raw: str) -> str:
    """``any`` stays; a (space padded) protocol number becomes tcp/udp/icmp/... or the number."""
    v = raw.strip()
    if v == "any" or not v:
        return "any"
    try:
        n = int(v)
    except ValueError:
        return v.lower()
    return PROTO_NAMES.get(n, str(n))


def parse_stat_csv(stdout: str, ip_valued: Sequence[bool] | None = None) -> ParsedStats:
    """Parse one or more ``ts,te,...`` tables; ``ip_valued[i]`` says table i's ``val`` is an IP."""
    out = ParsedStats()
    cols: list[str] | None = None
    table: StatTable | None = None
    bad_addr = 0
    bad_line = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line == NO_MATCH:
            continue
        if line.startswith("ts,te,"):
            cols = [_STAT_COL_NORMALISE.get(c, c) for c in line.split(",")]
            table = StatTable()
            out.tables.append(table)
            continue
        if cols is None or table is None:
            continue
        parts = line.split(",")
        if len(parts) != len(cols):
            bad_line += 1
            table.dropped += 1
            continue
        rec = dict(zip(cols, parts, strict=True))
        idx = len(out.tables) - 1
        want_ip = bool(ip_valued[idx]) if ip_valued is not None and idx < len(ip_valued) else False
        val = rec.get("val", "").strip()
        if want_ip:
            ip = _ip_or_none(val)
            if ip is None:
                bad_addr += 1
                table.dropped += 1
                continue
            val = ip
        try:
            row = StatRow(
                ts=stat_ts_to_iso(rec["ts"]),
                te=stat_ts_to_iso(rec["te"]),
                td=float(rec.get("td", "0") or 0),
                proto=proto_name(rec.get("pr", "any")),
                val=val,
                fl=_int(rec.get("fl", "0")),
                flP=float(rec.get("flP", "0") or 0),
                pkt=_int(rec.get("pkt", "0")),
                pktP=float(rec.get("pktP", "0") or 0),
                byt=_int(rec.get("byt", "0")),
                bytP=float(rec.get("bytP", "0") or 0),
                pps=_int(rec.get("pps", "0")),
                bps=_int(rec.get("bps", "0")),
                bpp=_int(rec.get("bpp", "0")),
            )
        except (KeyError, ValueError):
            bad_line += 1
            table.dropped += 1
            continue
        table.rows.append(row)
    out.dropped = bad_addr + bad_line
    if bad_addr:
        out.warnings.append(f"{bad_addr} rows with unparseable addresses dropped")
    if bad_line:
        out.warnings.append(f"{bad_line} malformed csv lines dropped")
    return out


def parse_dash_i(stdout: str) -> dict[str, int | str]:
    """Parse ``nfdump -I`` (``Key: value`` lines) into a dict; numeric values become int."""
    out: dict[str, int | str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        try:
            out[k] = int(v)
        except ValueError:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Row grammar: "<event_time> netflow <kind> key=value key=value ..."
# ---------------------------------------------------------------------------


def num(v: object) -> str:
    """Render a number compactly (``12.0`` -> ``12``; other floats to 3 decimals)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        if v == int(v) and abs(v) < 1e15:
            return str(int(v))
        return f"{v:.3f}".rstrip("0").rstrip(".")
    return str(v)


def _val(v: object) -> str:
    if v is None:
        return "null"
    if isinstance(v, (list, tuple)):
        return ",".join(_val(x) for x in v)
    if isinstance(v, (bool, int, float)):
        return num(v)
    return str(v).replace(" ", "_")


@dataclass
class Row:
    """One indexed line: its ``event_time`` (None for header/manifest), kind and fields."""

    kind: str
    event_time: str | None
    fields: list[tuple[str, object]]

    def text(self) -> str:
        """The indexed ``raw_text``: values never contain spaces."""
        head = self.event_time or "-"
        body = " ".join(f"{k}={_val(v)}" for k, v in self.fields)
        return f"{head} netflow {self.kind} {body}".rstrip()

    def as_dict(self) -> dict[str, object]:
        """JSON form of the fields (for inline ``rows``)."""
        d: dict[str, object] = {"kind": self.kind, "event_time": self.event_time}
        for k, v in self.fields:
            d[k] = list(v) if isinstance(v, tuple) else v
        return d


def flow_row(r: FlowRec, kind: str = "flow") -> Row:
    """Row for one raw flow record."""
    return Row(
        kind,
        iso_s(r.first),
        [
            ("src", r.sa), ("sport", r.sp), ("dst", r.da), ("dport", r.dp),
            ("proto", proto_name(str(r.proto)) if r.proto is not None else "any"),
            ("flags", r.flg or "-"), ("packets", r.pkt), ("bytes", r.byt),
            ("duration_s", round(r.duration_s, 3)),
            ("first", iso_ms(r.first)), ("last", iso_ms(r.last)),
        ],
    )  # fmt: skip


def agg_row(r: FlowRec, keys: Sequence[str]) -> Row:
    """Row for one aggregated tuple; only the aggregation keys present are emitted."""
    fields: list[tuple[str, object]] = []
    for k in keys:
        if k == "proto":
            fields.append(("proto", proto_name(str(r.proto)) if r.proto is not None else "any"))
        elif k == "srcip":
            fields.append(("src", r.sa))
        elif k == "dstip":
            fields.append(("dst", r.da))
        elif k == "srcport":
            fields.append(("sport", r.sp))
        elif k == "dstport":
            fields.append(("dport", r.dp))
        elif k == "flags":
            fields.append(("flags", r.flg or "-"))
        elif k.startswith("srcip4/"):
            fields.append(("src_net", f"{r.sa}/{k.split('/', 1)[1]}"))
        elif k.startswith("dstip4/"):
            fields.append(("dst_net", f"{r.da}/{k.split('/', 1)[1]}"))
    fields += [
        ("flows", r.fl if r.fl is not None else 0), ("packets", r.pkt), ("bytes", r.byt),
        ("bps", r.bps if r.bps is not None else 0), ("bpp", r.bpp if r.bpp is not None else 0),
        ("first", iso_ms(r.first)), ("last", iso_ms(r.last)),
    ]  # fmt: skip
    return Row("agg", iso_s(r.first), fields)


def flow_bps(r: FlowRec) -> float:
    """Bits per second of one record (0 for zero-duration records)."""
    return r.byt * 8 / r.duration_s if r.duration_s else 0.0


def flow_pps(r: FlowRec) -> float:
    """Packets per second of one record."""
    return r.pkt / r.duration_s if r.duration_s else 0.0


def flow_bpp(r: FlowRec) -> float:
    """Bytes per packet of one record."""
    return r.byt / r.pkt if r.pkt else 0.0


def sort_flows(rows: list[FlowRec], order: str) -> list[FlowRec]:
    """Sort raw records: tstart/tend ascending, everything else descending."""
    if order == "tstart":
        return sorted(rows, key=lambda r: (r.first, r.last))
    if order == "tend":
        return sorted(rows, key=lambda r: (r.last, r.first))
    if order == "duration":
        return sorted(rows, key=lambda r: (-r.duration_s, r.first))
    if order == "bytes":
        return sorted(rows, key=lambda r: (-r.byt, r.first))
    if order == "packets":
        return sorted(rows, key=lambda r: (-r.pkt, r.first))
    if order == "bps":
        return sorted(rows, key=lambda r: (-flow_bps(r), r.first))
    if order == "bpp":
        return sorted(rows, key=lambda r: (-flow_bpp(r), r.first))
    if order == "pps":
        return sorted(rows, key=lambda r: (-flow_pps(r), r.first))
    return rows


# ---------------------------------------------------------------------------
# Sweep statistics
# ---------------------------------------------------------------------------


def is_syn_only(flg: str | None) -> bool:
    """``S`` set and ``A`` clear in an nfdump flag string (``......S.``)."""
    return flg is not None and "S" in flg and "A" not in flg


@dataclass
class SweepGroup:
    """Fan-out from one source IP to one destination port."""

    src: str
    dport: int
    targets: int
    flows: int
    syn_only_flows: int
    burst_targets: int
    burst_start: float
    burst_span_s: float
    first: float
    last: float
    targets_list: list[str]

    def row(self, burst_window_s: int) -> Row:
        """Indexed row (event_time = burst start, seconds)."""
        return Row(
            "sweep",
            iso_s(self.burst_start),
            [
                ("src", self.src), ("dport", self.dport), ("proto", "tcp"),
                ("targets", self.targets), ("burst_targets", self.burst_targets),
                ("burst_window_s", burst_window_s), ("burst_start", iso_ms(self.burst_start)),
                ("burst_span_s", round(self.burst_span_s, 1)), ("flows", self.flows),
                ("syn_only_flows", self.syn_only_flows), ("first", iso_ms(self.first)),
                ("last", iso_ms(self.last)), ("targets_list", tuple(self.targets_list)),
            ],
        )  # fmt: skip


def _ip_sort_key(ip: str) -> tuple[int, int]:
    a = ipaddress.ip_address(ip)
    return (a.version, int(a))


def _burst(firsts: Sequence[float], window_s: float) -> tuple[int, float, float]:
    """Max number of target first-contacts inside any sliding window; (count, start, span)."""
    xs = sorted(firsts)
    best = (0, xs[0] if xs else 0.0, 0.0)
    j = 0
    for i, start in enumerate(xs):
        while j < len(xs) and xs[j] - start <= window_s:
            j += 1
        count = j - i
        if count > best[0]:
            best = (count, start, xs[j - 1] - start)
    return best


def sweep_groups(
    rows: Sequence[FlowRec], min_targets: int, burst_window_s: int
) -> list[SweepGroup]:
    """Group ``(srcAddr, dstPort)`` tuples from the aggregated sweep output."""
    per: dict[tuple[str, int], list[FlowRec]] = {}
    for r in rows:
        if r.sa is None or r.da is None or r.dp is None:
            continue
        per.setdefault((r.sa, r.dp), []).append(r)
    groups: list[SweepGroup] = []
    for (src, dport), recs in per.items():
        target_first: dict[str, float] = {}
        flows = 0
        syn_only = 0
        for r in recs:
            assert r.da is not None
            fl = r.fl if r.fl is not None else 1
            flows += fl
            if is_syn_only(r.flg):
                syn_only += fl
            target_first[r.da] = min(target_first.get(r.da, r.first), r.first)
        if len(target_first) < min_targets:
            continue
        count, start, span = _burst(list(target_first.values()), float(burst_window_s))
        groups.append(
            SweepGroup(
                src=src,
                dport=dport,
                targets=len(target_first),
                flows=flows,
                syn_only_flows=syn_only,
                burst_targets=count,
                burst_start=start,
                burst_span_s=span,
                first=min(r.first for r in recs),
                last=max(r.last for r in recs),
                targets_list=sorted(target_first, key=_ip_sort_key)[:MAX_TARGETS_LISTED],
            )
        )
    groups.sort(key=lambda g: (-g.targets, -g.burst_targets, -g.flows, g.src, g.dport))
    return groups


# ---------------------------------------------------------------------------
# Pair statistics
# ---------------------------------------------------------------------------


@dataclass
class IntervalStats:
    """Inter-arrival statistics over strictly positive gaps between distinct first-seen values."""

    n: int
    median_s: float
    p10_s: float
    p90_s: float
    share_within_5pct: float

    def as_dict(self) -> dict[str, object]:
        """JSON form."""
        return {
            "n": self.n,
            "median_s": self.median_s,
            "p10_s": self.p10_s,
            "p90_s": self.p90_s,
            "share_within_5pct": self.share_within_5pct,
        }


def _percentile(sorted_vals: Sequence[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = max(0, min(len(sorted_vals) - 1, int(round(p * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def interval_stats(firsts: Sequence[float]) -> IntervalStats | None:
    """Inter-arrival statistics, or None when fewer than two distinct first-seen values."""
    xs = sorted(set(firsts))
    gaps = sorted(b - a for a, b in zip(xs, xs[1:], strict=False) if b - a > 0)
    if not gaps:
        return None
    med = float(statistics.median(gaps))
    within = sum(1 for g in gaps if abs(g - med) <= 0.05 * med)
    # Intervals are reported to 0.1 s so millisecond jitter does not split a regular cadence,
    # while sub-second intervals keep one decimal.
    return IntervalStats(
        n=len(gaps),
        median_s=round(med, 1),
        p10_s=round(_percentile(gaps, 0.10), 1),
        p90_s=round(_percentile(gaps, 0.90), 1),
        share_within_5pct=round(within / len(gaps), 3),
    )


def _session_dict(r: FlowRec) -> dict[str, object]:
    dur = r.duration_s
    return {
        "src": r.sa,
        "dst": r.da,
        "first": iso_ms(r.first),
        "last": iso_ms(r.last),
        "duration_s": round(dur, 3),
        "packets": r.pkt,
        "bytes": r.byt,
        "bps": int(r.byt * 8 / dur) if dur > 0 else 0,
        "sport": r.sp,
        "flags": r.flg,
    }


@dataclass
class PairStats:
    """Everything ``run_netflow_pair_timeline`` reports about one host pair.

    ``records``/``bytes``/``packets`` count exact-deduplicated exporter records over BOTH legs;
    the ``*_distinct`` figures additionally collapse the exporter's near-copies of
    one flow (same 5-tuple, first/last within 2 ms, possibly different counters);
    ``*_out``/``*_in`` split the exact-deduplicated figures by leg (src->dst / dst->src).
    Sessions, intervals, source ports, SYN retries and size uniformity are computed
    on the src->dst leg of the collapsed set only.
    """

    records_raw: int
    records: int
    duplicates_removed: int
    truncated: bool
    first: float | None
    last: float | None
    span_s: float
    bytes: int
    packets: int
    distinct_sports: int
    flags_hist: dict[str, int]
    syn_only_records: int
    sessions: list[dict[str, object]]
    sessions_over_1h: int
    longest_session: dict[str, object] | None
    interval: IntervalStats | None
    syn_interval: IntervalStats | None
    bytes_mode: int | None
    bytes_mode_share: float
    distinct_days: int
    hints: list[str]
    hints_partial: bool
    records_distinct: int = 0
    near_copies_collapsed: int = 0
    bytes_distinct: int = 0
    packets_distinct: int = 0
    syn_only_records_distinct: int = 0
    records_out: int = 0
    records_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    packets_out: int = 0
    packets_in: int = 0
    active_days: int = 0

    def as_dict(self) -> dict[str, object]:
        """JSON summary (the ``summary`` envelope key)."""
        return {
            "records_raw": self.records_raw,
            "records": self.records,
            "duplicates_removed": self.duplicates_removed,
            "records_distinct": self.records_distinct,
            "near_copies_collapsed": self.near_copies_collapsed,
            "truncated": self.truncated,
            "first": iso_ms(self.first) if self.first is not None else None,
            "last": iso_ms(self.last) if self.last is not None else None,
            "span_s": round(self.span_s, 3),
            "bytes": self.bytes,
            "packets": self.packets,
            "bytes_distinct": self.bytes_distinct,
            "packets_distinct": self.packets_distinct,
            "records_out": self.records_out,
            "records_in": self.records_in,
            "bytes_out": self.bytes_out,
            "bytes_in": self.bytes_in,
            "packets_out": self.packets_out,
            "packets_in": self.packets_in,
            "distinct_sports": self.distinct_sports,
            "flags_hist": self.flags_hist,
            "syn_only_records": self.syn_only_records,
            "syn_only_records_distinct": self.syn_only_records_distinct,
            "sessions_over_1h": self.sessions_over_1h,
            "sessions": self.sessions,
            "longest_session": self.longest_session,
            "interval_stats": self.interval.as_dict() if self.interval else None,
            "syn_only_interval_stats": self.syn_interval.as_dict() if self.syn_interval else None,
            "median_interval_s": self.interval.median_s if self.interval else None,
            "interval_share_5pct": self.interval.share_within_5pct if self.interval else None,
            "bytes_mode": self.bytes_mode,
            "bytes_mode_share": self.bytes_mode_share,
            "distinct_days": self.distinct_days,
            "active_days": self.active_days,
            "hints": list(self.hints),
            "hints_partial": self.hints_partial,
        }


def dedupe_flows(rows: Sequence[FlowRec]) -> tuple[list[FlowRec], int]:
    """Drop exact duplicate records (exporter copies are genuine flows); chronological order."""
    seen: set[tuple[object, ...]] = set()
    out: list[FlowRec] = []
    for r in rows:
        k = r.key()
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    out.sort(key=lambda r: (r.first, r.last, r.sp or 0))
    return out, len(rows) - len(out)


NEAR_COPY_TOLERANCE_S = 0.002


def _five_tuple(r: FlowRec) -> tuple[object, ...]:
    return (r.proto, r.sa, r.sp, r.da, r.dp)


def collapse_exporter_copies(rows: Sequence[FlowRec]) -> tuple[list[FlowRec], int]:
    """Merge re-exports of one flow: same 5-tuple with first/last within 2 ms of the cluster's
    first member (an exporter may re-emit a flow with slightly different timestamps, within
    the 2 ms tolerance, or with different packet/byte counters); the member with the largest
    counters is kept.  A tolerance cluster, not a rounding to whole seconds, so a pair
    straddling a .5 boundary is never split.  Chronological order on return."""
    ordered = sorted(rows, key=lambda r: (str(_five_tuple(r)), r.first, r.last))
    out: list[FlowRec] = []
    anchor: FlowRec | None = None
    for r in ordered:
        if (
            anchor is not None
            and _five_tuple(r) == _five_tuple(anchor)
            and abs(r.first - anchor.first) <= NEAR_COPY_TOLERANCE_S
            and abs(r.last - anchor.last) <= NEAR_COPY_TOLERANCE_S
        ):
            if (r.byt, r.pkt) > (out[-1].byt, out[-1].pkt):
                out[-1] = r
            continue
        anchor = r
        out.append(r)
    out.sort(key=lambda r: (r.first, r.last, r.sp or 0))
    return out, len(rows) - len(out)


def _periodic(st: IntervalStats | None) -> bool:
    return st is not None and st.n >= 10 and st.share_within_5pct >= 0.5


def _active_days(rows: Sequence[FlowRec]) -> int:
    """Distinct UTC calendar days on which any record was active (first .. last inclusive)."""
    days: set[date] = set()
    for r in rows:
        d = datetime.fromtimestamp(int(r.first), timezone.utc).date()
        d_last = datetime.fromtimestamp(int(r.last), timezone.utc).date()
        while d <= d_last:
            days.add(d)
            d = _shift_day(d, 1)
            if d == date.max:
                break
    return len(days)


def pair_stats(raw: Sequence[FlowRec], truncated: bool, src: str | None = None) -> PairStats:
    """Characterise one pair's records.

    ``src`` names the client (src->dst) leg: with ``both_directions`` the reply records carry
    ``sa == dst`` and must not double the session count, the source-port count or the byte
    volume attributed to the client.  ``None`` treats every record as the client leg.
    """
    rows, dups = dedupe_flows(raw)
    distinct, near = collapse_exporter_copies(rows)
    if not rows:
        return PairStats(
            records_raw=len(raw), records=0, duplicates_removed=dups, truncated=truncated,
            first=None, last=None, span_s=0.0, bytes=0, packets=0, distinct_sports=0,
            flags_hist={}, syn_only_records=0, sessions=[], sessions_over_1h=0,
            longest_session=None, interval=None, syn_interval=None, bytes_mode=None,
            bytes_mode_share=0.0, distinct_days=0, hints=[], hints_partial=truncated,
        )  # fmt: skip
    fwd = [r for r in rows if src is None or r.sa == src]
    rev = [r for r in rows if src is not None and r.sa != src]
    fwd_d = [r for r in distinct if src is None or r.sa == src]
    first = min(r.first for r in rows)
    last = max(r.last for r in rows)
    flags_hist = Counter((r.flg or "-") for r in rows)
    syn_rows = [r for r in fwd if is_syn_only(r.flg)]
    syn_rows_d = [r for r in fwd_d if is_syn_only(r.flg)]
    long_rows = sorted((r for r in fwd_d if r.duration_s >= 3600), key=lambda r: -r.duration_s)
    longest = max(fwd_d, key=lambda r: r.duration_s) if fwd_d else None
    ivs = interval_stats([r.first for r in fwd_d])
    syn_ivs = interval_stats([r.first for r in syn_rows_d])
    mode_val: int | None = None
    mode_share = 0.0
    if fwd_d:
        mode_val, cnt = Counter(r.byt for r in fwd_d).most_common(1)[0]
        mode_share = round(cnt / len(fwd_d), 3)
    hints: list[str] = []
    if any(flow_bps(r) < 10_000 for r in long_rows):
        hints.append("long_lived_low_rate")
    if not truncated:
        if _periodic(ivs):
            hints.append("periodic")
        if len(syn_rows_d) >= 5 and _periodic(syn_ivs):
            hints.append("syn_only_retries")
        if len(fwd_d) >= 10 and mode_share >= 0.8:
            hints.append("fixed_size")
        nightly = (
            ivs is not None
            and ivs.n >= 5
            and abs(ivs.median_s - 86_400) <= 0.05 * 86_400
            and ivs.share_within_5pct >= 0.5
        )
        if nightly:
            hints.append("nightly")
    return PairStats(
        records_raw=len(raw),
        records=len(rows),
        duplicates_removed=dups,
        truncated=truncated,
        first=first,
        last=last,
        span_s=last - first,
        bytes=sum(r.byt for r in rows),
        packets=sum(r.pkt for r in rows),
        distinct_sports=len({r.sp for r in fwd_d if r.sp is not None}),
        flags_hist=dict(flags_hist.most_common()),
        syn_only_records=len(syn_rows),
        sessions=[_session_dict(r) for r in long_rows[:MAX_SESSIONS_LISTED]],
        sessions_over_1h=len(long_rows),
        longest_session=_session_dict(longest) if longest is not None else None,
        interval=ivs,
        syn_interval=syn_ivs,
        bytes_mode=mode_val,
        bytes_mode_share=mode_share,
        distinct_days=len({iso_s(r.first)[:10] for r in rows}),
        hints=hints,
        hints_partial=truncated,
        records_distinct=len(distinct),
        near_copies_collapsed=near,
        bytes_distinct=sum(r.byt for r in distinct),
        packets_distinct=sum(r.pkt for r in distinct),
        syn_only_records_distinct=len(syn_rows_d),
        records_out=len(fwd),
        records_in=len(rev),
        bytes_out=sum(r.byt for r in fwd),
        bytes_in=sum(r.byt for r in rev),
        packets_out=sum(r.pkt for r in fwd),
        packets_in=sum(r.pkt for r in rev),
        active_days=_active_days(rows),
    )


def pair_summary_row(
    st: PairStats, src: str, dst: str, dport: int | None, both_directions: bool = False
) -> Row:
    """The one summary row of a pair source (event_time = first seen)."""
    longest = st.longest_session or {}
    fields: list[tuple[str, object]] = [
        ("src", src), ("dst", dst), ("dport", dport if dport is not None else "any"),
        ("records", st.records), ("records_distinct", st.records_distinct),
        ("duplicates_removed", st.duplicates_removed),
        ("near_copies_collapsed", st.near_copies_collapsed),
        ("first", iso_ms(st.first) if st.first is not None else "-"),
        ("last", iso_ms(st.last) if st.last is not None else "-"),
        ("sessions_over_1h", st.sessions_over_1h),
        ("longest_session_s", longest.get("duration_s", 0)),
        ("longest_session_bps", longest.get("bps", 0)),
        ("syn_only_records", st.syn_only_records),
        ("syn_only_records_distinct", st.syn_only_records_distinct),
        ("median_interval_s", st.interval.median_s if st.interval else "null"),
        ("interval_share_5pct", st.interval.share_within_5pct if st.interval else "null"),
        ("bytes_mode", st.bytes_mode if st.bytes_mode is not None else "null"),
        ("bytes_mode_share", st.bytes_mode_share),
        ("bytes_distinct", st.bytes_distinct), ("packets_distinct", st.packets_distinct),
        ("distinct_days", st.distinct_days), ("active_days", st.active_days),
        ("both_directions", both_directions),
    ]  # fmt: skip
    if both_directions:
        fields += [
            ("records_out", st.records_out), ("records_in", st.records_in),
            ("bytes_out", st.bytes_out), ("bytes_in", st.bytes_in),
        ]  # fmt: skip
    fields += [
        ("truncated", st.truncated), ("hints_partial", st.hints_partial),
        ("hints", tuple(st.hints) if st.hints else "none"),
    ]  # fmt: skip
    return Row("pair", iso_s(st.first) if st.first is not None else None, fields)


# ---------------------------------------------------------------------------
# STAT-derived rows (top / profile / inventory)
# ---------------------------------------------------------------------------


def stat_ip_valued(stat: str) -> bool:
    """Whether a ``-s`` key's ``val`` column is an address."""
    return stat.split(":", 1)[0] in _IP_STAT_KEYS


def top_row(r: StatRow, rank: int, stat: str, order: str) -> Row:
    """Row for ``run_netflow_top``."""
    return Row(
        "top",
        r.ts,
        [
            ("stat", stat), ("order", order), ("rank", rank), ("value", r.val),
            ("proto", r.proto), ("flows", r.fl), ("flows_pct", r.flP), ("packets", r.pkt),
            ("bytes", r.byt), ("bytes_pct", r.bytP), ("pps", r.pps), ("bps", r.bps),
            ("bpp", r.bpp), ("first", r.ts), ("last", r.te),
        ],
    )  # fmt: skip


def profile_row(r: StatRow, rank: int, host: str, kind: str, is_port: bool) -> Row:
    """Row for one ranked ``run_netflow_host_profile`` entry."""
    key: list[tuple[str, object]] = (
        [("proto", r.proto), ("port", r.val)] if is_port else [("ip", r.val)]
    )
    return Row(
        "profile",
        r.ts,
        [("host", host), ("kind", kind), ("rank", rank), *key, ("flows", r.fl),
         ("flows_pct", r.flP), ("bytes", r.byt), ("bytes_pct", r.bytP), ("first", r.ts),
         ("last", r.te)],
    )  # fmt: skip
