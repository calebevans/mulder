# Trust-substrate contracts

Mulder publishes machine-readable schemas at
`schemas/core-contract-v1.schema.json` and
`schemas/case-manifest-v1.schema.json`. The core schema's authoritative source is
`CoreContractBundle` in `mulder.contracts`; CI compares the committed schema to
the Pydantic-generated document byte-for-structure. The receipt schema follows
the object emitted by `mulder.receipt.seal_case`. CI validates positive and
negative fixtures for both contracts. Regenerate the core schema with:

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

Every newly executed `ToolOutcome` carries source identifiers, aware start/end
timestamps, and a full-output digest. Rows imported from the original outcome
shape instead carry the explicit durable marker `LEGACY_UNCLASSIFIED`; the two
states are mutually exclusive. Evidence anchors retain both the exact text span
and a validated typed selector (`csv_cell`, `json_pointer`, `evtx_field`,
`sqlite_cell`, `byte_range`, or `parsed_record`). Their artifact, acquisition,
extractor, and observation independence dimensions are server-derived.

Coverage requirements are declared independently from coverage results. A
declared mandatory cell that is missing or incomplete blocks finalization, and
negative conclusions additionally require successful coverage for their exact
named scope. Revisions are immutable snapshots with evidence deltas and exact
links to any contradiction that caused a correction or refutation.

Adding an enum member or changing a field is visible as schema drift. Compatible
additions retain schema version 1 only when old documents preserve their
meaning. Renaming/removing fields, changing enum semantics, or weakening an
invariant requires a new schema version and migration notes.

Receipt structure is intentionally separate: `mulder.receipt` owns canonical
manifest versioning and offline diagnostics. ADR 0003 defines the compatibility
rules shared by both surfaces.
