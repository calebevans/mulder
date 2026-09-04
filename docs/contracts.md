# Trust-substrate contracts

Mulder publishes the machine-readable schema at
`schemas/core-contract-v1.schema.json`. Its authoritative source is
`CoreContractBundle` in `mulder.contracts`; CI compares the committed schema to
the Pydantic-generated document byte-for-structure and validates positive and
negative fixtures. Regenerate it with:

```bash
uv run python scripts/generate_contract_schemas.py
```

The bundle versions five interfaces together because they form one dependency
chain:

1. `ToolOutcome` states whether and how a forensic operation completed.
2. `CoverageRecord` binds that outcome to a case/system/domain/check cell.
3. `AtomicClaim` binds a material assertion to exact evidence anchors.
4. `ClaimVerification` records an append-only deterministic decision.
5. `FindingRevision` preserves the narrative lifecycle and evidence deltas.

Adding an enum member or changing a field is visible as schema drift. Compatible
additions retain schema version 1 only when old documents preserve their
meaning. Renaming/removing fields, changing enum semantics, or weakening an
invariant requires a new schema version and migration notes.

Receipt structure is intentionally separate: `mulder.receipt` owns canonical
manifest versioning and offline diagnostics. ADR 0003 defines the compatibility
rules shared by both surfaces.
