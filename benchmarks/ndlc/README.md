# Historical NDLC benchmark conversion

This directory makes the existing NDLC evaluation consumable by the v1
offline scorer. Run `python benchmarks/ndlc/import_accuracy_report.py` to
recreate `manifest-v1.json` and `result-historical.json` from the checked-in
`examples/ndlc/ACCURACY-REPORT.md`. The importer reads local files only.

The input is real published forensic evidence, not a synthetic fixture. It is
not redistributed here: `download-manifest-v1.yaml` records names, source,
licensing caveat, and the SHA-256 values already reported by the investigation.

The source has a pre-existing internal count discrepancy: its scorecard says
12 FOUND and 6 PARTIAL, while the 20 detailed rows contain 11 FOUND and 7
PARTIAL. The generated result retains both facts and does not choose a new
adjudication. Likewise, the historical prose has no atomic evidence anchors.
Its normalized citation score is therefore zero, not an assertion that the
original report contained no citations.

The report records exact analyst/orchestrator model identifiers, runtime, and
total token use, which are stamped in the normalized result. It does not record
the Mulder build, prompt-set hash, tool-set hash, orchestrator build, seed, or
cost; those identity/resource fields remain explicitly unknown rather than
being invented during conversion.

The normalization is intentionally conservative: FOUND maps to a verified
exact answer-key item; PARTIAL maps to inconclusive; FALSE POSITIVE maps to
contradicted; MISSED produces no observed claim. These v1 scores are useful as
a machine-readable historical baseline, but are not comparable to a fresh run
with atomic claims and anchors without noting this methodology limitation.
