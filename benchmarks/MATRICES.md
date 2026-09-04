# Benchmark matrices and scheduled runs

The committed CI subset is a scorer/contract smoke test, not a model quality
claim. Broader model and ablation matrices should run on a schedule or by an
explicit maintainer action so cost and nondeterminism do not gate every change.
The scheduled job may invoke agents, but it must commit or retain their
normalized result JSON separately; `mulder benchmark` itself always remains
offline and deterministic.

Each matrix cell fixes all of the following before execution:

- exact model identifiers by role;
- prompt-set and tool-set SHA-256 values;
- orchestrator and methodology versions;
- an ordered set of ablation labels;
- corpus manifest hash and evidence hashes;
- resource limits and the repeat count.

Use a stable `identity.matrix_cell` string for that combination and distinct
`repeat_index` values starting at zero. Record a seed when the provider or
runner accepts one; a seed is provenance, not a promise that a hosted model is
deterministic. Do not reuse a repeat index within a matrix cell. A changed
model, prompt, tool set, orchestrator, methodology, or ablation is a new cell.

Every attempted case produces a cell. Successful analyses use `completed`;
sound abstentions use `no_verdict`; infrastructure or budget failures use
`failed` plus `failure_reason`. Never discard a failed repeat or silently omit
a case. Keep unsupported, partial, timeout, and not-run coverage statuses so
downstream readers can distinguish evidence limits from system errors.

Passing two or more compatible result objects to `mulder benchmark` emits an
`aggregates` entry for every matrix cell. Metrics contain a count, mean,
population variance, population standard deviation, minimum, and maximum.
Runtime and cost omit unknown (`null`) observations instead of treating them as
zero. The scorer rejects duplicate matrix-cell/repeat-index pairs and identity
methodology versions that disagree with the manifest.

A useful scheduled matrix starts with three or more repeats of the default
configuration, then one-factor ablations such as `no-verification`,
`no-specialist-routing`, or `no-structured-coverage`. Cross-product matrices
are harder to interpret and more expensive; add them only for a stated
hypothesis. Publish the exact input result objects alongside score JSON so any
reported aggregate can be independently recomputed without a model or network.
