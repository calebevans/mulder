"""Decide and record provider-bound data movement before adapter use.

This module is the single policy seam for outbound model data and other
runtime egress capabilities.  Callers describe the fields they intend to
send; :class:`ProviderPolicy` returns an immutable decision and appends a
content-free manifest entry before the caller constructs a provider request.

The manifest contains only field names, item counts, byte sizes, hashes, and
evidence-envelope handling labels.  It never stores field values.  A denial
is a handling decision, not evidence that content is malicious.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from mulder.security.evidence_envelope import (
    EvidenceEnvelope,
    EvidenceFlag,
    TrustLabel,
    envelope_evidence,
)


class CaseDataPolicy(str, Enum):
    """Explicit case-level policies for provider-bound evidence."""

    LOCAL_ONLY = "local-only"
    METADATA_ONLY = "metadata-only"
    SENSITIVE_APPROVED = "sensitive-approved"


class DataClassification(str, Enum):
    """Caller assertion about an outbound field's data class."""

    METADATA = "metadata"
    CONTENT = "content"


class EgressCapability(str, Enum):
    """Runtime capabilities considered by zero-egress preflight."""

    MODEL_PROVIDER = "model_provider"
    MODEL_FALLBACK = "model_fallback"
    EXTERNAL_THREAT_INTELLIGENCE = "external_threat_intelligence"
    TELEMETRY = "telemetry"
    EGRESS_ADAPTER = "egress_adapter"


class PolicyDecision(str, Enum):
    """Outcome written to the outbound manifest."""

    ALLOW = "allow"
    DENY = "deny"


class ProviderPolicyError(RuntimeError):
    """Raised before adapter construction when outbound policy denies a request."""

    def __init__(self, message: str, *, decision: OutboundDecision | None = None) -> None:
        super().__init__(message)
        self.decision = decision


@dataclass(frozen=True)
class ProviderRoute:
    """Resolved provider route and whether it is confined to this machine."""

    provider: str
    model: str
    local: bool
    verified_local: bool = False


@dataclass(frozen=True)
class OutboundFieldManifest:
    """Content-free accounting record for one provider-bound field."""

    name: str
    classification: DataClassification
    count: int
    byte_size: int
    content_hash: str
    evidence_flags: tuple[str, ...]
    sensitivity_labels: tuple[str, ...]

    def manifest_dict(self) -> dict[str, object]:
        """Return a JSON-compatible representation without a field value."""
        return {
            "name": self.name,
            "classification": self.classification.value,
            "count": self.count,
            "byte_size": self.byte_size,
            "content_hash": self.content_hash,
            "evidence_flags": list(self.evidence_flags),
            "sensitivity_labels": list(self.sensitivity_labels),
        }


@dataclass(frozen=True)
class OutboundField:
    """One provider-bound value plus its declared data class.

    ``value`` is retained only for the in-process decision.  It is never
    included in :meth:`manifest`.
    """

    name: str
    value: str | bytes | Sequence[str]
    classification: DataClassification = DataClassification.CONTENT
    evidence: EvidenceEnvelope | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("outbound field name must not be empty")

    @property
    def encoded(self) -> bytes:
        """Return the deterministic bytes used for size and hash accounting."""
        if isinstance(self.value, bytes):
            return self.value
        if isinstance(self.value, str):
            return self.value.encode("utf-8", errors="surrogatepass")
        return json.dumps(list(self.value), ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )

    @property
    def count(self) -> int:
        """Return the number of logical values represented by this field."""
        if isinstance(self.value, (str, bytes)):
            return 1
        return len(self.value)

    @property
    def envelope(self) -> EvidenceEnvelope:
        """Return supplied provenance or derive a local sensitivity envelope."""
        if self.evidence is not None:
            return self.evidence
        return envelope_evidence(
            self.encoded,
            source_id=f"outbound:{self.name}",
            selector=f"provider_request.{self.name}",
            trust_label=TrustLabel.MULDER_DERIVED,
        )

    def manifest(self) -> OutboundFieldManifest:
        """Return content-free accounting metadata for this field."""
        envelope = self.envelope
        return OutboundFieldManifest(
            name=self.name,
            classification=self.classification,
            count=self.count,
            byte_size=len(self.encoded),
            content_hash="sha256:" + hashlib.sha256(self.encoded).hexdigest(),
            evidence_flags=tuple(flag.value for flag in envelope.flags),
            sensitivity_labels=envelope.sensitivity_labels,
        )


@dataclass(frozen=True)
class OutboundRequest:
    """Description of data about to cross a provider adapter seam."""

    case_id: str
    route: ProviderRoute
    fields: tuple[OutboundField, ...]
    capability: EgressCapability = EgressCapability.MODEL_PROVIDER
    request_id: str = ""


@dataclass(frozen=True)
class OutboundDecision:
    """Immutable provider decision suitable for append-only recording."""

    request_id: str
    timestamp: str
    case_id: str
    provider: str
    model: str
    route_local: bool
    route_verified_local: bool
    capability: EgressCapability
    policy: CaseDataPolicy
    zero_egress: bool
    decision: PolicyDecision
    reason: str
    fields: tuple[OutboundFieldManifest, ...]

    @property
    def allowed(self) -> bool:
        """Whether the caller may proceed to request construction."""
        return self.decision is PolicyDecision.ALLOW

    def manifest_dict(self) -> dict[str, object]:
        """Return the stable, content-free manifest representation."""
        return {
            "schema_version": 1,
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "case_id": self.case_id,
            "capability": self.capability.value,
            "provider": self.provider,
            "model": self.model,
            "route_local": self.route_local,
            "route_verified_local": self.route_verified_local,
            "policy": self.policy.value,
            "zero_egress": self.zero_egress,
            "decision": self.decision.value,
            "reason": self.reason,
            "field_count": len(self.fields),
            "item_count": sum(field.count for field in self.fields),
            "byte_size": sum(field.byte_size for field in self.fields),
            "fields": [field.manifest_dict() for field in self.fields],
        }


_manifest_lock = threading.Lock()


class OutboundManifest:
    """Append-only JSONL sink for provider decisions."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def append(self, decision: OutboundDecision) -> None:
        """Append one decision without ever serializing outbound field values."""
        payload = json.dumps(
            decision.manifest_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _manifest_lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(payload + "\n")


class ProviderPolicy:
    """Resolve provider routes, authorize fields, and emit manifest decisions."""

    def __init__(
        self,
        case_policy: CaseDataPolicy = CaseDataPolicy.SENSITIVE_APPROVED,
        *,
        zero_egress: bool = False,
        manifest: OutboundManifest | None = None,
    ) -> None:
        self.case_policy = case_policy
        self.zero_egress = zero_egress
        self.manifest = manifest

    def authorize(self, request: OutboundRequest) -> OutboundDecision:
        """Decide and record a request before any adapter sees its values.

        The caller must invoke this method before constructing or serializing
        its provider-specific request.  Denials are recorded and then raised.
        """
        field_metadata = tuple(field.manifest() for field in request.fields)
        decision, reason = self._decide(request, field_metadata)
        result = OutboundDecision(
            request_id=request.request_id or uuid4().hex,
            timestamp=datetime.now(timezone.utc).isoformat(),
            case_id=request.case_id,
            provider=request.route.provider,
            model=request.route.model,
            route_local=request.route.local,
            route_verified_local=request.route.verified_local,
            capability=request.capability,
            policy=self.case_policy,
            zero_egress=self.zero_egress,
            decision=decision,
            reason=reason,
            fields=field_metadata,
        )
        if self.manifest is not None:
            self.manifest.append(result)
        if not result.allowed:
            raise ProviderPolicyError(reason, decision=result)
        return result

    def _decide(
        self,
        request: OutboundRequest,
        fields: tuple[OutboundFieldManifest, ...],
    ) -> tuple[PolicyDecision, str]:
        if self.zero_egress and not request.route.verified_local:
            return (
                PolicyDecision.DENY,
                "zero-egress mode rejects non-local or unverified provider routes",
            )
        if self.case_policy is CaseDataPolicy.LOCAL_ONLY and not request.route.local:
            return PolicyDecision.DENY, "local-only case policy rejects non-local provider routes"
        if request.route.local:
            return PolicyDecision.ALLOW, "provider route is local to this machine"
        if self.case_policy is CaseDataPolicy.METADATA_ONLY:
            content_fields = [
                field.name
                for field in fields
                if field.classification is not DataClassification.METADATA
            ]
            sensitive_fields = [
                field.name
                for field in fields
                if EvidenceFlag.SENSITIVE_DATA.value in field.evidence_flags
            ]
            rejected = sorted(set(content_fields + sensitive_fields))
            if rejected:
                return (
                    PolicyDecision.DENY,
                    "metadata-only case policy rejects provider fields: " + ", ".join(rejected),
                )
        return PolicyDecision.ALLOW, "case policy permits the declared provider fields"


_CLOUD_MODEL_PREFIXES = ("bedrock/", "openai/", "vertex_ai/", "azure/")
_LOCAL_MODEL_PREFIXES = ("ollama/",)
_TELEMETRY_ENV_VARS = (
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "SENTRY_DSN",
    "MULDER_TELEMETRY_ENDPOINT",
)


def resolve_provider_route(model: str, env: Mapping[str, str] | None = None) -> ProviderRoute:
    """Resolve provider identity and local/cloud disposition deterministically."""
    values = env or {}
    if model.startswith(_LOCAL_MODEL_PREFIXES):
        ollama_url = values.get("OLLAMA_API_BASE", "") or values.get("OLLAMA_HOST", "")
        if ollama_url and not _is_loopback_url(_with_default_scheme(ollama_url)):
            return ProviderRoute(provider="ollama_remote", model=model, local=False)
        return ProviderRoute(provider="ollama", model=model, local=True, verified_local=True)
    for prefix in _CLOUD_MODEL_PREFIXES:
        if model.startswith(prefix):
            return ProviderRoute(provider=prefix.rstrip("/"), model=model, local=False)
    if values.get("CLAUDE_CODE_USE_BEDROCK") == "1":
        return ProviderRoute(provider="bedrock", model=model, local=False)
    if values.get("CLAUDE_CODE_USE_VERTEX") == "1":
        return ProviderRoute(provider="vertex_ai", model=model, local=False)
    base_url = values.get("ANTHROPIC_BASE_URL", "")
    if base_url and _is_loopback_url(base_url):
        return ProviderRoute(provider="local_anthropic_adapter", model=model, local=True)
    return ProviderRoute(provider="anthropic", model=model, local=False)


def preflight_zero_egress(
    *,
    models: Sequence[str],
    env: Mapping[str, str] | None = None,
    proxy_config: str | None = None,
    fallback_models: Sequence[str] = (),
    external_threat_intelligence: bool = False,
    telemetry: bool = False,
    egress_adapters: Sequence[str] = (),
) -> tuple[str, ...]:
    """Return fail-closed zero-egress violations without opening any adapter."""
    values = env or {}
    violations: list[str] = []
    for model in models:
        route = resolve_provider_route(model, values)
        if not route.local:
            violations.append(f"cloud model route: {route.provider}/{model}")
        elif not route.verified_local:
            violations.append(f"unverified local model adapter: {route.provider}/{model}")
    for fallback in fallback_models:
        route = resolve_provider_route(fallback, values)
        if not route.local:
            violations.append(f"cloud model fallback: {route.provider}/{fallback}")
        elif not route.verified_local:
            violations.append(f"unverified local fallback adapter: {route.provider}/{fallback}")
    if proxy_config:
        violations.append("custom proxy configuration is an unverified egress-capable adapter")
    if external_threat_intelligence:
        violations.append("external threat intelligence is enabled")
    telemetry_configured = any(
        value.strip()
        for name, value in values.items()
        if name in _TELEMETRY_ENV_VARS or name.startswith("OTEL_EXPORTER_")
    )
    if telemetry or telemetry_configured:
        violations.append("telemetry is enabled or an endpoint is configured")
    for adapter in egress_adapters:
        if adapter:
            violations.append(f"egress-capable adapter enabled: {adapter}")
    return tuple(violations)


def require_capability_disabled(capability: EgressCapability) -> None:
    """Reject non-model egress under zero-egress or a local-only case policy."""
    if os.environ.get("MULDER_ZERO_EGRESS") == "1":
        raise ProviderPolicyError(f"zero-egress mode rejects {capability.value}")
    if os.environ.get("MULDER_DATA_POLICY") == CaseDataPolicy.LOCAL_ONLY.value:
        raise ProviderPolicyError(f"local-only case policy rejects {capability.value}")


def zero_egress_environment() -> dict[str, str]:
    """Return subprocess environment overrides that disable telemetry paths."""
    return {
        "MULDER_ZERO_EGRESS": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "OTEL_SDK_DISABLED": "true",
        "DO_NOT_TRACK": "1",
    }


def summarize_outbound_manifest(path: Path | str) -> dict[str, object]:
    """Summarize valid JSONL decisions for CLI/report display."""
    manifest_path = Path(path)
    empty_summary: dict[str, object] = {
        "status": "not_recorded",
        "request_count": 0,
        "allowed_count": 0,
        "denied_count": 0,
        "allowed_byte_size": 0,
        "providers": [],
        "models": [],
        "field_names": [],
        "denied_field_names": [],
        "policy": "not_recorded",
        "zero_egress": False,
    }
    if not manifest_path.exists():
        return empty_summary

    providers: set[str] = set()
    models: set[str] = set()
    field_names: set[str] = set()
    denied_field_names: set[str] = set()
    policies: set[str] = set()
    request_count = 0
    allowed_count = 0
    denied_count = 0
    allowed_byte_size = 0
    zero_egress = False
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {**empty_summary, "status": "unreadable"}
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict) or entry.get("schema_version") != 1:
            continue
        request_count += 1
        decision = entry.get("decision")
        if decision == PolicyDecision.ALLOW.value:
            allowed_count += 1
            byte_size = entry.get("byte_size", 0)
            if isinstance(byte_size, int):
                allowed_byte_size += byte_size
        elif decision == PolicyDecision.DENY.value:
            denied_count += 1
        providers.add(str(entry.get("provider", "unknown")))
        models.add(str(entry.get("model", "unknown")))
        policies.add(str(entry.get("policy", "unknown")))
        fields = entry.get("fields", [])
        if isinstance(fields, list):
            for field in fields:
                if isinstance(field, dict) and isinstance(field.get("name"), str):
                    if decision == PolicyDecision.ALLOW.value:
                        field_names.add(field["name"])
                    elif decision == PolicyDecision.DENY.value:
                        denied_field_names.add(field["name"])
        zero_egress = zero_egress or entry.get("zero_egress") is True
    return {
        "status": "recorded" if request_count else "empty",
        "request_count": request_count,
        "allowed_count": allowed_count,
        "denied_count": denied_count,
        "allowed_byte_size": allowed_byte_size,
        "providers": sorted(providers),
        "models": sorted(models),
        "field_names": sorted(field_names),
        "denied_field_names": sorted(denied_field_names),
        "policy": ", ".join(sorted(policies)) if policies else "not_recorded",
        "zero_egress": zero_egress,
    }


def _is_loopback_url(value: str) -> bool:
    parsed = urlsplit(value)
    return parsed.scheme in {"http", "https"} and parsed.hostname in {
        "127.0.0.1",
        "::1",
        "localhost",
    }


def _with_default_scheme(value: str) -> str:
    return value if "://" in value else f"http://{value}"


__all__ = [
    "CaseDataPolicy",
    "DataClassification",
    "EgressCapability",
    "OutboundDecision",
    "OutboundField",
    "OutboundFieldManifest",
    "OutboundManifest",
    "OutboundRequest",
    "PolicyDecision",
    "ProviderPolicy",
    "ProviderPolicyError",
    "ProviderRoute",
    "preflight_zero_egress",
    "require_capability_disabled",
    "resolve_provider_route",
    "summarize_outbound_manifest",
    "zero_egress_environment",
]
