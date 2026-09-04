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
- an ordered set of executable ablations and its content-bound execution receipt;
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
configuration, then one-factor executable ablations. The five supported safety
components are verifier, independence gate, Alternative Narrative, blind
reviewer, and candidate filters. A label alone is not evidence: these components
must be disabled through `mulder benchmark-ablate`, which requires a complete
ordered trace and emits a replay-checked receipt. Unknown targets, duplicate
targets, incomplete traces, an already-ablated base, mixed legacy/executable
labels, and trace/result disagreement fail closed.

The repository's scheduled workflow deliberately uses the bounded synthetic
fixture in `benchmarks/ablation/`. It produces one public-schema result for each
one-factor ablation, scores them with the normal CLI, and retains input, output,
and receipt artifacts. It makes no provider request and does not claim model
quality; larger or nondeterministic studies may use the same contracts outside
required CI. Cross-product matrices are harder to interpret and more expensive;
add them only for a stated hypothesis. Publish exact input result objects beside
score JSON so any aggregate can be independently recomputed offline.
