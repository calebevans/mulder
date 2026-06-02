"""MCP tool for enriching IOCs against public threat intelligence APIs.

Queries public sources for reputation, geolocation, and metadata on
extracted IOCs. Degrades gracefully when API keys are unavailable or
services are unreachable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import hash_output, make_tool_call_id
from mulder.server.tool_access import Role, tool_access

logger = logging.getLogger(__name__)

IOCType = Literal["ipv4", "domain", "md5", "sha1", "sha256", "unknown"]

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

_ENRICHMENT_SOURCES: dict[str, str] = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "otx": "OTX_API_KEY",
}

_REQUEST_TIMEOUT = 10.0
_MAX_REQUESTS_PER_SECOND = 4


def classify_ioc(value: str) -> IOCType:
    """Classify an IOC string by type.

    Args:
        value: Raw IOC string to classify.

    Returns:
        The detected IOC type.
    """
    value = value.strip()
    if _IPV4_RE.match(value):
        return "ipv4"
    if _SHA256_RE.match(value):
        return "sha256"
    if _SHA1_RE.match(value):
        return "sha1"
    if _MD5_RE.match(value):
        return "md5"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


@dataclass
class EnrichmentResult:
    """Structured result from a single threat intel source."""

    source: str
    ioc: str
    ioc_type: IOCType
    found: bool
    reputation_score: int | None = None
    malicious: bool = False
    tags: list[str] | None = None
    country: str | None = None
    asn: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    raw: dict[str, Any] | None = None
    error: str | None = None


class RateLimiter:
    """Token-bucket rate limiter for API calls."""

    def __init__(self, calls_per_second: float) -> None:
        """Initialize the rate limiter.

        Args:
            calls_per_second: Maximum allowed calls per second.
        """
        self._interval = 1.0 / calls_per_second
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request slot is available."""
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()


_global_limiter = RateLimiter(_MAX_REQUESTS_PER_SECOND)


@dataclass
class _SessionCache:
    """Per-session in-memory cache for enrichment results."""

    _cache: dict[str, list[EnrichmentResult]] = field(default_factory=dict)

    def get(self, ioc: str) -> list[EnrichmentResult] | None:
        """Retrieve cached results for an IOC."""
        return self._cache.get(ioc)

    def put(self, ioc: str, results: list[EnrichmentResult]) -> None:
        """Cache results for an IOC."""
        self._cache[ioc] = results


_session_cache = _SessionCache()


async def _query_ip_api(
    client: httpx.AsyncClient, ioc: str, ioc_type: IOCType
) -> EnrichmentResult:
    """Query ip-api.com for geolocation data (free, no key required).

    Args:
        client: Async HTTP client instance.
        ioc: The IOC value to query.
        ioc_type: Classified type of the IOC.

    Returns:
        Enrichment result with geolocation data.
    """
    if ioc_type != "ipv4":
        return EnrichmentResult(
            source="ip-api",
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error="ip-api only supports IPv4 addresses",
        )
    try:
        await _global_limiter.acquire()
        resp = await client.get(
            f"http://ip-api.com/json/{ioc}",
            params={"fields": "status,message,country,regionName,city,isp,as,query"},
            timeout=_REQUEST_TIMEOUT,
        )
        data = resp.json()
        if data.get("status") == "success":
            return EnrichmentResult(
                source="ip-api",
                ioc=ioc,
                ioc_type=ioc_type,
                found=True,
                country=data.get("country"),
                asn=data.get("as"),
                raw=data,
            )
        return EnrichmentResult(
            source="ip-api",
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error=data.get("message", "unknown error"),
        )
    except Exception as exc:
        return EnrichmentResult(
            source="ip-api",
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error=str(exc),
        )


async def _query_abuseipdb(
    client: httpx.AsyncClient, ioc: str, ioc_type: IOCType, api_key: str
) -> EnrichmentResult:
    """Query AbuseIPDB for IP reputation data.

    Args:
        client: Async HTTP client instance.
        ioc: The IOC value to query.
        ioc_type: Classified type of the IOC.
        api_key: AbuseIPDB API key.

    Returns:
        Enrichment result with reputation data.
    """
    if ioc_type != "ipv4":
        return EnrichmentResult(
            source="abuseipdb",
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error="AbuseIPDB only supports IPv4 addresses",
        )
    try:
        await _global_limiter.acquire()
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ioc, "maxAgeInDays": "90"},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return EnrichmentResult(
                source="abuseipdb",
                ioc=ioc,
                ioc_type=ioc_type,
                found=False,
                error=f"HTTP {resp.status_code}",
            )
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return EnrichmentResult(
            source="abuseipdb",
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            reputation_score=score,
            malicious=score > 50,
            country=data.get("countryCode"),
            raw=data,
        )
    except Exception as exc:
        return EnrichmentResult(
            source="abuseipdb",
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error=str(exc),
        )


async def _query_otx(
    client: httpx.AsyncClient, ioc: str, ioc_type: IOCType, api_key: str
) -> EnrichmentResult:
    """Query OTX AlienVault for threat intelligence.

    Args:
        client: Async HTTP client instance.
        ioc: The IOC value to query.
        ioc_type: Classified type of the IOC.
        api_key: OTX API key.

    Returns:
        Enrichment result with pulse/threat data.
    """
    section_map: dict[str, str] = {
        "ipv4": f"indicators/IPv4/{ioc}/general",
        "domain": f"indicators/domain/{ioc}/general",
        "md5": f"indicators/file/{ioc}/general",
        "sha1": f"indicators/file/{ioc}/general",
        "sha256": f"indicators/file/{ioc}/general",
    }
    section = section_map.get(ioc_type)
    if not section:
        return EnrichmentResult(
            source="otx",
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error=f"Unsupported IOC type for OTX: {ioc_type}",
        )
    try:
        await _global_limiter.acquire()
        resp = await client.get(
            f"https://otx.alienvault.com/api/v1/{section}",
            headers={"X-OTX-API-KEY": api_key},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return EnrichmentResult(
                source="otx",
                ioc=ioc,
                ioc_type=ioc_type,
                found=False,
                error=f"HTTP {resp.status_code}",
            )
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        tags = data.get("pulse_info", {}).get("pulses", [])
        tag_names: list[str] = []
        for pulse in tags[:10]:
            tag_names.extend(pulse.get("tags", [])[:5])
        score = min(100, pulse_count * 10) if pulse_count else 0
        return EnrichmentResult(
            source="otx",
            ioc=ioc,
            ioc_type=ioc_type,
            found=pulse_count > 0,
            reputation_score=score,
            malicious=pulse_count > 0,
            tags=tag_names[:20] if tag_names else None,
            raw={"pulse_count": pulse_count},
        )
    except Exception as exc:
        return EnrichmentResult(
            source="otx",
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error=str(exc),
        )


async def _query_virustotal(
    client: httpx.AsyncClient, ioc: str, ioc_type: IOCType, api_key: str
) -> EnrichmentResult:
    """Query VirusTotal for reputation data.

    Args:
        client: Async HTTP client instance.
        ioc: The IOC value to query.
        ioc_type: Classified type of the IOC.
        api_key: VirusTotal API key.

    Returns:
        Enrichment result with detection data.
    """
    endpoint_map: dict[str, str] = {
        "ipv4": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "md5": f"https://www.virustotal.com/api/v3/files/{ioc}",
        "sha1": f"https://www.virustotal.com/api/v3/files/{ioc}",
        "sha256": f"https://www.virustotal.com/api/v3/files/{ioc}",
    }
    url = endpoint_map.get(ioc_type)
    if not url:
        return EnrichmentResult(
            source="virustotal",
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error=f"Unsupported IOC type for VT: {ioc_type}",
        )
    try:
        await _global_limiter.acquire()
        resp = await client.get(
            url,
            headers={"x-apikey": api_key},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return EnrichmentResult(
                source="virustotal",
                ioc=ioc,
                ioc_type=ioc_type,
                found=False,
                error=f"HTTP {resp.status_code}",
            )
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 1
        score = round(malicious_count / max(total, 1) * 100)
        tags = data.get("tags", [])
        return EnrichmentResult(
            source="virustotal",
            ioc=ioc,
            ioc_type=ioc_type,
            found=True,
            reputation_score=score,
            malicious=malicious_count > 0,
            tags=tags[:20] if tags else None,
            country=data.get("country"),
            asn=str(data.get("asn", "")) if data.get("asn") else None,
            raw={"malicious": malicious_count, "total": total},
        )
    except Exception as exc:
        return EnrichmentResult(
            source="virustotal",
            ioc=ioc,
            ioc_type=ioc_type,
            found=False,
            error=str(exc),
        )


def _aggregate_score(results: list[EnrichmentResult]) -> int:
    """Compute 0-100 aggregate threat score from multi-source results.

    Args:
        results: List of enrichment results from various sources.

    Returns:
        Aggregate threat score between 0 and 100.
    """
    if not results:
        return 0
    scores = [r.reputation_score for r in results if r.reputation_score is not None]
    if not scores:
        return 0
    return min(100, max(0, round(sum(scores) / len(scores))))


def _result_to_dict(result: EnrichmentResult) -> dict[str, Any]:
    """Convert an EnrichmentResult dataclass to a serializable dict.

    Args:
        result: The enrichment result to serialize.

    Returns:
        Dict representation of the result.
    """
    d: dict[str, Any] = {
        "source": result.source,
        "ioc": result.ioc,
        "ioc_type": result.ioc_type,
        "found": result.found,
    }
    if result.reputation_score is not None:
        d["reputation_score"] = result.reputation_score
    if result.malicious:
        d["malicious"] = result.malicious
    if result.tags:
        d["tags"] = result.tags
    if result.country:
        d["country"] = result.country
    if result.asn:
        d["asn"] = result.asn
    if result.first_seen:
        d["first_seen"] = result.first_seen
    if result.last_seen:
        d["last_seen"] = result.last_seen
    if result.error:
        d["error"] = result.error
    return d


async def _enrich_single_ioc(
    client: httpx.AsyncClient,
    ioc: str,
    skip_sources: set[str],
    api_keys: dict[str, str],
) -> dict[str, Any]:
    """Enrich a single IOC against all available sources.

    Args:
        client: Async HTTP client instance.
        ioc: The IOC value to enrich.
        skip_sources: Source names to skip.
        api_keys: Map of source name to API key.

    Returns:
        Dict with per-source results and aggregate score.
    """
    cached = _session_cache.get(ioc)
    if cached is not None:
        return {
            "ioc": ioc,
            "ioc_type": cached[0].ioc_type if cached else "unknown",
            "sources": [_result_to_dict(r) for r in cached],
            "aggregate_score": _aggregate_score(cached),
            "cached": True,
        }

    ioc_type = classify_ioc(ioc)
    results: list[EnrichmentResult] = []

    if "ip-api" not in skip_sources and ioc_type == "ipv4":
        results.append(await _query_ip_api(client, ioc, ioc_type))

    if "abuseipdb" not in skip_sources and "abuseipdb" in api_keys:
        results.append(await _query_abuseipdb(client, ioc, ioc_type, api_keys["abuseipdb"]))

    if "otx" not in skip_sources and "otx" in api_keys:
        results.append(await _query_otx(client, ioc, ioc_type, api_keys["otx"]))

    if "virustotal" not in skip_sources and "virustotal" in api_keys:
        results.append(await _query_virustotal(client, ioc, ioc_type, api_keys["virustotal"]))

    _session_cache.put(ioc, results)

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "sources": [_result_to_dict(r) for r in results],
        "aggregate_score": _aggregate_score(results),
        "cached": False,
    }


def _load_api_keys() -> dict[str, str]:
    """Load available API keys from environment variables.

    Returns:
        Map of source name to API key for sources with configured keys.
    """
    keys: dict[str, str] = {}
    for source_name, env_var in _ENRICHMENT_SOURCES.items():
        val = os.environ.get(env_var, "").strip()
        if val:
            keys[source_name] = val
        else:
            logger.debug("No API key for %s (env var %s not set)", source_name, env_var)
    return keys


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
async def enrich_iocs(
    case_id: str,
    iocs: list[str],
    skip_sources: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Enrich IOCs against public threat intelligence APIs.

    Queries public sources for reputation, geolocation, and metadata
    on each IOC. Degrades gracefully when API keys are unavailable or
    services are unreachable.

    Args:
        case_id: Active case identifier.
        iocs: List of IOC strings (IPs, domains, MD5/SHA1/SHA256 hashes).
        skip_sources: Optional list of source names to skip (e.g.,
            ``["virustotal"]`` if no API key is configured).

    Returns:
        List of enrichment dicts, one per IOC, containing source
        results and an aggregate threat score.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    api_keys = _load_api_keys()
    skip = set(skip_sources or [])
    enrichment_results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)
    ) as client:
        consecutive_failures = 0
        for ioc in iocs:
            if consecutive_failures >= 3:
                enrichment_results.append(
                    {
                        "ioc": ioc,
                        "ioc_type": classify_ioc(ioc),
                        "sources": [],
                        "aggregate_score": 0,
                        "error": "circuit breaker: skipped after 3 consecutive failures",
                    }
                )
                continue
            try:
                result = await _enrich_single_ioc(client, ioc, skip, api_keys)
                consecutive_failures = 0
                enrichment_results.append(result)
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                consecutive_failures += 1
                logger.warning("Enrichment connection failed for IOC %s: %s", ioc, exc)
                enrichment_results.append(
                    {
                        "ioc": ioc,
                        "ioc_type": classify_ioc(ioc),
                        "sources": [],
                        "aggregate_score": 0,
                        "error": str(exc),
                    }
                )
            except Exception as exc:
                consecutive_failures = 0
                logger.warning("Enrichment failed for IOC %s: %s", ioc, exc)
                enrichment_results.append(
                    {
                        "ioc": ioc,
                        "ioc_type": classify_ioc(ioc),
                        "sources": [],
                        "aggregate_score": 0,
                        "error": str(exc),
                    }
                )

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name="enrich_iocs",
        params={"case_id": case_id, "ioc_count": len(iocs)},
        output_hash=hash_output(enrichment_results),
        duration_ms=elapsed,
    )

    if enrichment_results:
        try:
            raw_output = json.dumps(enrichment_results, indent=2, default=str)
            extract_and_index(
                raw_output=raw_output,
                source_name="enrichment.iocs",
                source_path="enrichment_analysis",
                extractor_name="enrichment",
            )
        except Exception:
            logger.warning("Failed to index enrichment results", exc_info=True)

    return enrichment_results
