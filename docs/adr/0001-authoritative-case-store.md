# ADR 0001: SQLite is the authoritative case store

Status: accepted

Mulder stores evidence identity, normalized source windows, findings, atomic
claims, exact anchors, verifications, revisions, and coverage in the per-case
SQLite database. Audit JSONL is the append-only event receipt. Reports,
benchmarks, browser views, proof cards, and graph rows are projections over
those stores; none is allowed to become a parallel source of forensic truth.

A projection must carry stable identifiers back to its source rows. Rebuilding
a projection from unchanged authoritative inputs must be deterministic. A
projection may omit detail for presentation, but may not strengthen epistemic
state or replace unknown/partial coverage with a clean conclusion.

This choice keeps one transaction boundary for claims and anchors and lets
offline receipt verification commit the complete logical database. A future
graph or review console therefore extends query and presentation behavior
without introducing synchronization semantics between truth stores.
