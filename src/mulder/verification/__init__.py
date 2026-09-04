"""Deterministic verification modules for evidence-backed claims."""

from mulder.verification.claims import VERIFIER_NAME, VERIFIER_VERSION, verify_claim
from mulder.verification.policy import assess_confirmation

__all__ = ["VERIFIER_NAME", "VERIFIER_VERSION", "assess_confirmation", "verify_claim"]
