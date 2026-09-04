"""Versioned public data contracts spanning Mulder's trust substrate."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from mulder.models import (
    AtomicClaim,
    ClaimVerification,
    CoverageRecord,
    FindingRevision,
    ToolOutcome,
)

CORE_CONTRACT_SCHEMA_VERSION: Literal[1] = 1


class CoreContractBundle(BaseModel):
    """One fixture-shaped envelope covering every foundational contract.

    Runtime APIs continue to exchange the individual models.  This bundle is a
    schema publication surface: it gives CI and external implementers one
    versioned document whose definitions cannot drift independently from the
    authoritative Pydantic types.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = CORE_CONTRACT_SCHEMA_VERSION
    tool_outcome: ToolOutcome
    coverage_record: CoverageRecord
    finding_revision: FindingRevision
    atomic_claim: AtomicClaim
    claim_verification: ClaimVerification


def core_contract_schema() -> dict[str, object]:
    """Return the authoritative JSON Schema for the current core bundle."""
    return CoreContractBundle.model_json_schema()
