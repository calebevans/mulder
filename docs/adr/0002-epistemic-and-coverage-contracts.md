# ADR 0002: Claims and coverage are independent contracts

Status: accepted

A finding is narrative organization. Its material facts are atomic claims.
Each new claim names one subject, predicate, typed value, qualifiers, and one or
more exact server-resolved evidence anchors. The deterministic verifier returns
`verified`, `contradicted`, or `inconclusive`; absence of support is never
converted to false or verified. Legacy prose remains `legacy_unverified`.

Corroboration counts root evidence streams through server-owned independence
keys. Two views over one acquired artifact count once. A confirmed finding is
valid only when each claim is verified and satisfies the configured independent
source threshold.

Coverage describes what was examined, separately from what was found.
`SUCCESS_EMPTY` is the sole successful empty observation. Failed, unavailable,
unsupported, timed-out, partial, sampled, and not-run checks limit knowledge.
Negative conclusions use `NO_EVIL_WITHIN_COVERAGE` and enumerate their exact
scope; they cannot assert that an entire host is clean.
