"""Examiner-controlled Ed25519 signing for canonical case manifests.

This module deliberately has no key-generation API.  A caller must supply an
existing private key through :class:`ExaminerKeyProvider`; identity labels are
metadata asserted by that caller, not identities vouched for by Mulder.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_ALGORITHM = "Ed25519"
SIGNATURE_PROFILE = "mulder.case-manifest.ed25519-v1"


class SigningKeyError(ValueError):
    """Raised when an examiner-supplied key cannot be used safely."""


@dataclass(frozen=True)
class PublicKeyMetadata:
    """Portable metadata for the public half of an examiner key."""

    algorithm: str
    key_id: str
    fingerprint: str
    public_key: str
    examiner: str | None = None

    def as_dict(self) -> dict[str, str]:
        """Return fields suitable for a signature block or verifier result."""
        result = {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "public_key": self.public_key,
        }
        if self.examiner is not None:
            result["examiner"] = self.examiner
        return result


class ExaminerKeyProvider(Protocol):
    """Explicit interface for an examiner-owned signing key."""

    @property
    def public_metadata(self) -> PublicKeyMetadata:
        """Describe the public key and only caller-asserted identity metadata."""

    def sign(self, payload: bytes) -> bytes:
        """Sign the supplied canonical bytes without transforming them."""


class Ed25519PEMKeyProvider:
    """Ed25519 provider backed by a caller-selected PEM private-key file."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        examiner: str | None = None,
        key_id: str | None = None,
    ) -> None:
        self._private_key = private_key
        raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest()
        self._metadata = PublicKeyMetadata(
            algorithm=SIGNATURE_ALGORITHM,
            key_id=key_id or fingerprint,
            fingerprint=fingerprint,
            public_key=base64.b64encode(raw).decode("ascii"),
            examiner=examiner,
        )

    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        examiner: str | None = None,
        key_id: str | None = None,
        password: bytes | None = None,
    ) -> Ed25519PEMKeyProvider:
        """Load an existing PEM key; this method never creates or persists one."""
        try:
            loaded = serialization.load_pem_private_key(
                Path(path).expanduser().read_bytes(), password=password
            )
        except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise SigningKeyError(f"Cannot load examiner signing key {path}: {exc}") from exc
        if not isinstance(loaded, Ed25519PrivateKey):
            raise SigningKeyError("Examiner signing key must be an Ed25519 private key")
        return cls(loaded, examiner=examiner, key_id=key_id)

    @property
    def public_metadata(self) -> PublicKeyMetadata:
        return self._metadata

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(payload)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_signature_payload(manifest: Mapping[str, object]) -> bytes:
    """Return the exact domain-separated bytes covered by a v1 signature.

    Only the two intrinsically self-referential values are omitted: the outer
    manifest hash and signature bytes.  All signature metadata, claims/table
    commitments, reports, evidence, audit state, and methodology remain bound.
    """
    copy = dict(manifest)
    integrity_raw = copy.get("integrity")
    if isinstance(integrity_raw, dict):
        integrity = dict(cast(dict[str, object], integrity_raw))
        integrity.pop("manifest_hash", None)
        signature_raw = integrity.get("signature")
        if isinstance(signature_raw, dict):
            signature = dict(cast(dict[str, object], signature_raw))
            signature.pop("value", None)
            integrity["signature"] = signature
        copy["integrity"] = integrity
    return SIGNATURE_PROFILE.encode("ascii") + b"\0" + _canonical_json(copy)


def create_signature_block(
    manifest: Mapping[str, object], provider: ExaminerKeyProvider
) -> dict[str, str]:
    """Create a signed integrity block from an explicit key provider."""
    metadata = provider.public_metadata
    block = {
        "status": "signed",
        "profile": SIGNATURE_PROFILE,
        **metadata.as_dict(),
    }
    staged = dict(manifest)
    integrity = dict(cast(dict[str, object], staged.get("integrity", {})))
    integrity["signature"] = block
    staged["integrity"] = integrity
    block["value"] = base64.b64encode(
        provider.sign(canonical_signature_payload(staged))
    ).decode("ascii")
    return block


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load an examiner-selected PEM or OpenSSH Ed25519 public key."""
    data = Path(path).expanduser().read_bytes()
    loaded: object
    try:
        loaded = serialization.load_pem_public_key(data)
    except (ValueError, UnsupportedAlgorithm):
        try:
            loaded = serialization.load_ssh_public_key(data)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise SigningKeyError(f"Cannot load Ed25519 public key {path}: {exc}") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise SigningKeyError("Verification key must be an Ed25519 public key")
    return loaded


def public_key_metadata(key: Ed25519PublicKey) -> PublicKeyMetadata:
    """Derive non-identity metadata from a verification key."""
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest()
    return PublicKeyMetadata(
        algorithm=SIGNATURE_ALGORITHM,
        key_id=fingerprint,
        fingerprint=fingerprint,
        public_key=base64.b64encode(raw).decode("ascii"),
    )


def embedded_public_key(block: Mapping[str, object]) -> Ed25519PublicKey:
    """Decode the self-described verification key carried by a signature."""
    encoded = block.get("public_key")
    if not isinstance(encoded, str):
        raise SigningKeyError("Signed manifest has no embedded public key")
    try:
        raw = base64.b64decode(encoded, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError("Signed manifest has an invalid embedded public key") from exc


def verify_manifest_signature(
    manifest: Mapping[str, object], block: Mapping[str, object], key: Ed25519PublicKey
) -> bool:
    """Verify signature bytes over the canonical manifest payload."""
    encoded = block.get("value")
    if not isinstance(encoded, str):
        raise SigningKeyError("Signed manifest has no signature value")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise SigningKeyError("Signed manifest signature is not valid base64") from exc
    try:
        key.verify(signature, canonical_signature_payload(manifest))
    except InvalidSignature:
        return False
    return True
