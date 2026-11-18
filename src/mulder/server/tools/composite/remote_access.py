"""Remote access tool composite: the LOLRMM catalog matched against indexed sources.

Finds remote monitoring and management tools (AnyDesk, TeamViewer,
ScreenConnect, ...) by executable name and by domain, says which source each
match came from, and indexes the tool's own logs when they are on the image.
These are ordinary IT tools; a match says a tool was there, not that it was
abused.
"""

from __future__ import annotations

import fnmatch
import functools
import json
import re
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from mulder.assets.paths import asset_path, asset_search_summary, register_cache_clear
from mulder.models import SourceRow
from mulder.patterns import IP_RE, fls_file_entries, is_external_ip
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import error_response, make_tool_call_id
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.composite.core import (
    _check_missing_sources,
    _invalidate_sources_cache,
    decode_evidence_text,
    finalize_composite_result,
    iter_source_text,
    read_image_file,
)
from mulder.server.tools.extract.tsk import _KV_SOURCE_OFFSET_PREFIX, _resolve_partition_offset

__all__ = ["find_remote_access_tools"]

_CATALOG = ("lolrmm", "rmm_tools.json")
_CATALOG_MAX_BYTES = 32 * 1024 * 1024
_TOOL = "find_remote_access_tools"

# Source prefix -> what a match in it establishes. Order is the order shown.
_SOURCES: dict[str, str] = {
    "ez.prefetch": "the program ran on this host (it has its own Prefetch file)",
    "ez.amcache": "the program was installed or run on this host (Amcache)",
    "ez.shimcache": "Windows saw the file; on its own not proof that it ran (ShimCache)",
    "registry": "the name is in a registry hive: a service, run key, uninstall or other key",
    "autoruns": "the program is configured to start automatically",
    "tsk.filelist": "a file of that name is on the volume (deleted entries included)",
    "pcap.dns": "a domain the catalog lists for the tool was looked up",
    "pcap.http": "a domain the catalog lists for the tool was contacted over HTTP",
    "pcap.tls": "a domain the catalog lists for the tool was contacted over TLS",
    "zeek": "a domain the catalog lists for the tool appears in the Zeek logs",
}
_NETWORK_SOURCES = ("pcap.dns", "pcap.http", "pcap.tls", "zeek")
_FILELIST = "tsk.filelist"
_PREFETCH = "ez.prefetch"

# The catalog lists every executable a tool is known to use, including ones
# that are not the tool's own. Three filters keep those out; all three are
# judgment against one pinned catalog and are worth a look when LOLRMM_VERSION
# changes. What is left is still a file name: unrelated software can share it.
#
# 1. Names with a stem under four characters (sc.exe, dd.exe, rdp.exe, 7z.exe).
_MIN_STEM = 4
# 2. Names this many catalog tools share (agent.exe, setup.exe, installer.exe).
_SHARED_NAME_MIN_TOOLS = 4
# 3. Names that belong to Windows or to unrelated common software, or that are
#    too generic to mean one product.
_NOT_TOOL_SPECIFIC = frozenset(
    {
        "agent.exe",
        "agent32.exe",
        "agent64.exe",
        "appcore.exe",
        "autoupdate.exe",
        "baseclient.exe",
        "closeapp.exe",
        "code-insiders.exe",
        "connect.exe",
        "cpuchk.exe",
        "diskmgr.exe",
        "einstaller.exe",
        "goto.exe",
        "httpget.exe",
        "httppush.exe",
        "hypersnap.exe",
        "installcore.exe",
        "installer.exe",
        "installshield setup.exe",
        "level.exe",
        "manuallauncher.exe",
        "monitoringagent.exe",
        "notepad++.exe",
        "notificationhelper.exe",
        "nssm.exe",
        "osqueryi.exe",
        "perl.exe",
        "privacyhelper.exe",
        "pservice.exe",
        "recycler.exe",
        "regapps.exe",
        "remote access.exe",
        "remote desktop.exe",
        "rhost.exe",
        "selfupdater.exe",
        "setup.exe",
        "simpleservice.exe",
        "svchost.exe",
        "sysdiag.exe",
        "teams.exe",
        "termsrv.exe",
        "uihelper.exe",
        "update-shim.exe",
        "upload.exe",
        "usernotificationhelper.exe",
        "vhost.exe",
        "winagent.exe",
        "windowslauncher.exe",
        "winpty-agent.exe",
        "winpty-agent64.exe",
        "wperl.exe",
    }
)
# Part of every Windows install, so they are on disk, in ShimCache and in the
# registry of every host. Only having run (a Prefetch file) says something.
_SHIPS_WITH_WINDOWS = frozenset({"mstsc.exe", "quickassist.exe"})
# Hosting and platform domains the catalog lists for a tool but that carry
# everyone's traffic. A catalog domain equal to or under one of these is not used.
_SHARED_DOMAINS = (
    "aliyuncs.com",
    "amazonaws.com",
    "apache.org",
    "azurewebsites.net",
    "basecamp.com",
    "cloudflare.com",
    "cloudflare.net",
    "cloudfront.net",
    "firebaseapp.com",
    "ghcr.io",
    "github.com",
    "github.io",
    "githubusercontent.com",
    "informer.com",
    "metaquest.com",
    "pages.dev",
    "parallels.com",
    "pubnubapi.com",
    "softonic.com",
    "sophos.com",
    "sophosupd.com",
    "sophosupd.net",
    "stunprotocol.org",
    "taobao.com",
    "web.app",
    "windows.net",
    "zoho.com",
    "zoho.com.au",
    "zoho.com.cn",
    "zoho.eu",
    "zoho.in",
)

# The tools' own logs: key (matched against the lower-cased path), display
# name, and path patterns as fls prints them. AnyDesk's ad.trace and
# ad_svc.trace carry the peer's IP address; connection_trace.txt carries only
# the peer's AnyDesk ID. TeamViewer's files carry IDs and host names, no IP.
_TOOL_LOGS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "anydesk",
        "AnyDesk",
        ("*/anydesk/ad.trace", "*/anydesk/ad_svc.trace", "*/anydesk/connection_trace.txt"),
    ),
    (
        "teamviewer",
        "TeamViewer",
        (
            "*/teamviewer/connections_incoming.txt",
            "*/teamviewer/connections.txt",
            "*/teamviewer/teamviewer*_logfile.log",
        ),
    ),
    ("splashtop", "Splashtop", ("*/splashtop/*/log/splog.txt",)),
    (
        "screenconnect",
        "ScreenConnect",
        ("*/screenconnect client*/system.config", "*/screenconnect client*/user.config"),
    ),
    ("rustdesk", "RustDesk", ("*/rustdesk/log/*.log", "*/rustdesk/config/rustdesk2.toml")),
)

_MAX_TOOLS = 12
_MAX_NEEDLES = 5
_SAMPLE_CHARS = 160
_MAX_LOG_FILES = 20
# Bytes of one log read and indexed. AnyDesk traces grow to tens of megabytes;
# what is beyond this (the newest lines) is not indexed and the result says so.
_LOG_READ_BYTES = 8 * 1024 * 1024
_MAX_ADDRESSES = 8

# Characters that cannot be part of a file name, or that separate fields.
_NAME_BREAK_RE = re.compile(r"[\\/:*?\"<>|\t,;=]")
_MAX_NAME_CHARS = 64
# What follows the name in a Prefetch file's own name (ANYDESK.EXE-1A2B3C4D.pf).
# A Prefetch record also lists every file the program loaded; those are skipped.
_PF_SUFFIX_RE = re.compile(r"-[0-9a-f]{8}\.pf")
_HOST_RE = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+")
_CATALOG_HOST_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}")
_WILDCARD_RE = re.compile(r"[*?<>\[\]%]")
_CLEAN_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SLUG_RE = re.compile(r"[^a-z0-9._-]+")

_CAVEATS = [
    "Presence is not abuse. These are common IT tools: a help desk, a managed service "
    "provider or the user may have installed them.",
    "What would establish abuse: installation or first run inside the incident window; "
    "installation by a compromised account; a session in the tool's own log from an "
    "address or ID the organisation does not recognise; the tool running from a temp or "
    "user-writable directory.",
    "A match is a file name or a domain from the LOLRMM catalog. Unrelated software can "
    "use the same file name: read the path in the sample line.",
    "Not found is not absent: only the sources under sources_searched were read, a "
    "renamed portable copy is not matched, and the catalog is a snapshot.",
]


@dataclass
class _Catalog:
    """Match keys derived from the LOLRMM export."""

    tools: int
    exes: dict[str, tuple[str, ...]]  # executable name -> tool names
    domains: dict[str, tuple[str, ...]]  # domain -> tool names

    def __post_init__(self) -> None:
        self.domain_labels = max((d.count(".") + 1 for d in self.domains), default=0)


@dataclass
class _Hit:
    """Everything found for one tool label."""

    needles: Counter[str] = field(default_factory=Counter)
    lines: Counter[tuple[str, str]] = field(default_factory=Counter)  # (source, evidence)
    sample: dict[tuple[str, str], str] = field(default_factory=dict)  # first line seen


def _clean(text: str, cap: int = _SAMPLE_CHARS) -> str:
    text = _CLEAN_RE.sub(" ", text).strip()
    return text if len(text) <= cap else text[: cap - 3] + "..."


def _dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _strings(value: object, key: str) -> list[str]:
    """``value[*][key]`` (or ``value[key]``) as strings, whatever shape the export has."""
    found = [_dict(item).get(key) for item in (_list(value) or [value])]
    return [f for f in found if isinstance(f, str)]


@functools.lru_cache(maxsize=1)
def _catalog() -> _Catalog | None:
    """Load the catalog asset, or None when it is missing or not the expected shape."""
    path = asset_path(*_CATALOG)
    try:
        if path is None or path.stat().st_size > _CATALOG_MAX_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, list):
        return None

    exes: dict[str, set[str]] = {}
    domains: dict[str, set[str]] = {}
    for tool in data:
        entry = _dict(tool)
        name = entry.get("Name")
        if not isinstance(name, str):
            continue
        details, artifacts = _dict(entry.get("Details")), _dict(entry.get("Artifacts"))
        paths = _strings(details.get("PEMetadata"), "Filename")
        paths += [p for p in _list(details.get("InstallationPaths")) if isinstance(p, str)]
        disk = [d for d in _list(artifacts.get("Disk")) if _dict(d).get("Type") != "Regex"]
        paths += _strings(disk, "File")
        for path_text in paths:
            exe = re.split(r"[\\/]", path_text.strip())[-1].lower()
            if exe.endswith(".exe") and len(exe) - 4 >= _MIN_STEM and not _WILDCARD_RE.search(exe):
                exes.setdefault(exe, set()).add(name)
        for network in _list(artifacts.get("Network")):
            for domain in _list(_dict(network).get("Domains")):
                host = str(domain).strip().lower().removeprefix("*.")
                shared = any(host == s or host.endswith("." + s) for s in _SHARED_DOMAINS)
                if _CATALOG_HOST_RE.fullmatch(host) and not shared:
                    domains.setdefault(host, set()).add(name)
    return _Catalog(
        tools=len(data),
        exes={
            exe: tuple(sorted(names))
            for exe, names in exes.items()
            if exe not in _NOT_TOOL_SPECIFIC and len(names) < _SHARED_NAME_MIN_TOOLS
        },
        domains={
            host: tuple(sorted(names))
            for host, names in domains.items()
            if len(names) < _SHARED_NAME_MIN_TOOLS
        },
    )


register_cache_clear(_catalog.cache_clear)


def _sample(line: str, start: int, end: int) -> str:
    """The start of *line* plus the text around a match that lies further in."""
    if end <= _SAMPLE_CHARS:
        return _clean(line)
    return _clean(line[:80]) + " ... " + _clean(line[max(0, start - 60) : end + 40])


def _exe_names(low: str) -> Iterator[tuple[str, int, int]]:
    """Each ``<name>.exe`` in a lower-cased line, with its span.

    ``x.exe.mui`` and ``x.exe.config`` are other files, so the name must end
    at ``.exe``. Found by position rather than by one regular expression: a
    line is evidence, and its cost has to stay linear in its length.
    """
    end = 0
    while (dot := low.find(".exe", end)) != -1:
        end = dot + 4
        following = low[end : end + 1]
        if following == "." or following == "_" or following.isalnum():
            continue
        start = max(0, dot - _MAX_NAME_CHARS)
        stem = _NAME_BREAK_RE.split(low[start:dot])[-1]
        if stem.strip():
            yield stem.strip() + ".exe", dot - len(stem), end


def _scan_source(
    source: SourceRow,
    prefix: str,
    catalog: _Catalog,
    hits: dict[str, _Hit],
    logs: list[tuple[SourceRow, str, str, str]],
) -> None:
    """Match one source's lines against the catalog; collect tool log files from listings."""
    network = prefix in _NETWORK_SOURCES
    listing = prefix == _FILELIST
    prefetch = prefix == _PREFETCH
    key = (source.source_name, source.source_path)

    def _record(names: tuple[str, ...], needle: str, line: str, start: int, end: int) -> None:
        hit = hits.setdefault(" / ".join(names), _Hit())
        hit.needles[needle] += 1
        hit.lines[key] += 1
        if key not in hit.sample:
            hit.sample[key] = _sample(line, start, end)

    for text in iter_source_text(source):
        for line in text.splitlines():
            low = line.lower()
            if network:
                for match in _HOST_RE.finditer(low):
                    labels = match.group().split(".")
                    # The longest catalog domain the host is, or is under.
                    for n in range(min(len(labels), catalog.domain_labels), 1, -1):
                        domain = ".".join(labels[-n:])
                        if domain in catalog.domains:
                            _record(catalog.domains[domain], domain, line, *match.span())
                            break
                continue
            if listing and len(logs) < _MAX_LOG_FILES:
                for tool_key, display, patterns in _TOOL_LOGS:
                    if tool_key not in low:
                        continue
                    for entry in fls_file_entries(line):
                        path = entry.path.lower().replace("\\", "/")
                        if not entry.deleted and any(fnmatch.fnmatch(path, p) for p in patterns):
                            logs.append((source, display, entry.base_inode, entry.path))
            if ".exe" not in low:
                continue
            for whole, start, end in _exe_names(low):
                if prefetch and not _PF_SUFFIX_RE.match(low, end):
                    continue
                # A catalog name can hold spaces; in free text only the last word is the name.
                for exe in {whole, whole.rsplit(" ", 1)[-1]}:
                    names = catalog.exes.get(exe)
                    if names and (prefetch or exe not in _SHIPS_WITH_WINDOWS):
                        _record(names, exe, line, start, end)


def _index_logs(logs: list[tuple[SourceRow, str, str, str]]) -> list[dict[str, object]]:
    """Read each tool log from its image (bounded), index it, and list external addresses."""
    ctx = get_ctx()
    indexed = {(s.source_name, s.source_path) for s in ctx.db.get_sources()}
    out: list[dict[str, object]] = []
    for listing, display, inode, path in logs:
        image = listing.source_path
        entry: dict[str, object] = {"tool": display, "path": _clean(path), "evidence": image}
        out.append(entry)
        if not Path(image).is_file():
            entry["not_read"] = "the evidence is not a disk image a file can be read from"
            continue
        stored = ctx.db.get_kv(f"{_KV_SOURCE_OFFSET_PREFIX}{listing.source_name}:{image}")
        offset = int(stored) if stored and stored.isdigit() else _resolve_partition_offset(image)
        read = read_image_file(image, inode, offset, _LOG_READ_BYTES)
        text = decode_evidence_text(read[0]) if read else None
        if not read or not text or not text.strip():
            entry["not_read"] = "the file is empty, binary or could not be extracted"
            continue
        file_slug = _SLUG_RE.sub("_", path.replace("\\", "/").rsplit("/", 1)[-1].lower())
        name = f"rmm.{display.lower()}.{file_slug}"
        if (name, image) not in indexed:
            extract_and_index(f"=== {path} ===\n{text}", name, image, "icat")
            indexed.add((name, image))
        entry["source"] = name
        entry["bytes_indexed"] = len(read[0])
        if read[1]:
            entry["truncated"] = (
                f"Only the first {_LOG_READ_BYTES} bytes (the oldest lines) were indexed."
            )
        addresses: Counter[str] = Counter()
        samples: dict[str, str] = {}
        for line in text.splitlines():
            for address in IP_RE.findall(line):
                if is_external_ip(address):
                    addresses[address] += 1
                    samples.setdefault(address, _clean(line))
        entry["external_addresses"] = [
            {"address": address, "lines": count, "sample": samples[address]}
            for address, count in addresses.most_common(_MAX_ADDRESSES)
        ]
        if len(addresses) > _MAX_ADDRESSES:
            entry["external_addresses_not_listed"] = len(addresses) - _MAX_ADDRESSES
    return out


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR | Role.NARRATIVE_EXECUTOR)
def find_remote_access_tools() -> dict[str, object]:
    """Find remote access and management tools (AnyDesk, TeamViewer, ScreenConnect, ...).

    Call after the file listing and execution artifacts are indexed, when the
    question is how an intruder got in or kept access.
    Windows evidence only: an empty result elsewhere is not a negative finding.

    Matches the LOLRMM catalog's executable names and domains against the
    indexed file listing, Prefetch, Amcache, ShimCache, registry, autoruns and
    DNS/HTTP/TLS sources, and returns each tool with the sources it was found
    in, line counts and sample lines. Logs of AnyDesk, TeamViewer, Splashtop,
    ScreenConnect and RustDesk found on the image are indexed as
    ``rmm.<tool>.<file>`` with the external addresses in them. Presence is not
    abuse: these are common IT tools. Indexed as
    ``composite.remote_access_tools``.
    """
    ctx = get_ctx()
    composite_id = make_tool_call_id()
    t0 = time.monotonic()
    _invalidate_sources_cache()

    catalog = _catalog()
    if catalog is None:
        return error_response(
            composite_id,
            _TOOL,
            {},
            "The LOLRMM catalog is not installed or not readable (looked under "
            f"{asset_search_summary(*_CATALOG)}). Run 'mulder setup'. Nothing was examined.",
            (time.monotonic() - t0) * 1000,
            error_type="asset_missing",
        )

    hits: dict[str, _Hit] = {}
    logs: list[tuple[SourceRow, str, str, str]] = []
    searched: set[str] = set()
    for source in ctx.db.get_sources():
        prefix = next(
            (
                p
                for p in _SOURCES
                if source.source_name == p or source.source_name.startswith(p + ".")
            ),
            None,
        )
        if prefix and source.line_count:
            searched.add(source.source_name)
            _scan_source(source, prefix, catalog, hits, logs)

    ranked = sorted(
        hits.items(),
        key=lambda item: (
            -len({s for s, _e in item[1].lines}),
            -sum(item[1].lines.values()),
            item[0],
        ),
    )
    tools = [
        {
            "tool": label,
            "matched": [needle for needle, _n in hit.needles.most_common(_MAX_NEEDLES)],
            "evidence": [
                {"source": key[0], "evidence": key[1], "lines": count, "sample": hit.sample[key]}
                for key, count in hit.lines.items()
            ],
        }
        for label, hit in ranked[:_MAX_TOOLS]
    ]
    found_in = {source for hit in hits.values() for source, _evidence in hit.lines}
    results: dict[str, object] = {
        "tools_found": len(hits),
        "tools": tools,
        "tool_logs": _index_logs(logs),
        "sources_searched": sorted(searched),
        "what_a_source_establishes": {
            prefix: meaning
            for prefix, meaning in _SOURCES.items()
            if any(s == prefix or s.startswith(prefix + ".") for s in found_in)
        },
        "catalog_tools": catalog.tools,
        "caveats": _CAVEATS,
    }
    if len(hits) > _MAX_TOOLS:
        results["tools_not_listed"] = [label for label, _hit in ranked[_MAX_TOOLS:]][:20]
    if not searched:
        results["not_examined"] = (
            "None of the sources this tool reads is indexed, so nothing was examined. "
            "This is not a negative finding."
        )

    missing = _check_missing_sources(
        [
            ("tsk.filelist", "run_fls('<image_path>')"),
            ("ez.prefetch", "run_prefetch_parser('<image_path>')"),
            ("ez.amcache", "run_amcache_parser('<image_path>')"),
            ("ez.shimcache", "run_shimcache_parser('<image_path>')"),
            ("registry", "run_registry_parser('<image_path>')"),
        ]
    )
    return finalize_composite_result(
        ctx=ctx,
        composite_id=composite_id,
        tool_name=_TOOL,
        results=results,
        coverage_sources=list(_SOURCES),
        missing=missing,
        sub_call_ids=[],
        t0=t0,
        audit_params={"sources_searched": sorted(searched)},
    )
