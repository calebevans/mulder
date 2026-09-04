"""Stable benchmark identities for authoritative evidence anchors."""

from __future__ import annotations

import hashlib
import json

from mulder.models import EvidenceAnchor


def canonical_anchor_id(anchor: EvidenceAnchor) -> str:
    """Build a stable citation ID from immutable source coordinates and content."""
    identity = {
        "source_name": anchor.source_name,
        "source_hash": anchor.source_hash,
        "line_start": anchor.line_start,
        "line_end": anchor.line_end,
        "char_start": anchor.char_start,
        "char_end": anchor.char_end,
        "exact_text_sha256": hashlib.sha256(anchor.exact_text.encode("utf-8")).hexdigest(),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "anchor:" + hashlib.sha256(encoded).hexdigest()
