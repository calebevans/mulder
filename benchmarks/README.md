# Mulder benchmark documents

`mulder benchmark` compares committed JSON or YAML result documents against a
versioned manifest. Scoring is deterministic and offline: the command imports
no model provider, makes no network request, and never re-runs an investigation.

```console
mulder benchmark benchmarks/fixtures/manifest-v1.yaml \
  benchmarks/fixtures/result-reference.json \
  benchmarks/fixtures/result-duplicate-partial.yaml \
  --output benchmark-scores.json
```

For the five-case synthetic smoke set used by CI:

```console
mulder benchmark benchmarks/ci/manifest-v1.yaml \
  benchmarks/ci/result-reference.json \
  --output benchmark-ci-score.json
```

The manifest is the answer-key contract. It records case applicability tags,
clean versus nonempty ground truth, expected coverage outcomes, content hashes,
redistribution status, and license metadata. Every evidence artifact must use
an explicit `origin` label:

- `synthetic`: authored or generated test evidence. Never describe it as a
  reproduced field case, even when it imitates a real artifact format.
- `real`: acquired evidence from a real system or published corpus. Record its
  actual license and redistribution status. Restricted evidence should use
  `restricted` or `manifest_only`, retain its expected SHA-256, and must not be
  copied into this repository.

Only claims whose `verification_state` is `verified` are scored as asserted
facts. Exact claim scoring compares canonical subject, predicate, object, and
qualifiers. Entity (subject) and subject/predicate scores show partial matches. Duplicate
assertions are collapsed before set scoring and reported separately. Citation
validity requires both a resolvable anchor and an answer-key relationship from
that anchor to the exactly matched claim.

Coverage expectation accuracy and completed required coverage are separate.
For example, observing an expected `UNSUPPORTED_VERSION` is an accurate outcome
but is not completed coverage; it can justify `no_verdict`, never a clean
verdict. Scores are also split into `clean` and `nonempty` subsets. Empty-set
precision and recall are defined as 1 only when the corresponding empty result
is correct, so clean controls do not produce undefined values.

Every result must include every manifest case. A system that cannot complete a
case records `cell_status: failed`, a reason, and `no_verdict`. A completed
case that correctly abstains records `cell_status: no_verdict`. Unsupported or
partial coverage is recorded separately; silently omitting hard cases is
rejected as incomparable. The table's `U/C/I` column is
the unsupported/contradicted/inconclusive distribution. Runtime is milliseconds,
tokens combine input, output, and explicitly unattributed historical totals,
and cost is USD. Unknown runtime and cost stay `null`, never synthetic zeroes.
Output hashes bind the
canonical semantic manifest and result objects, so JSON/YAML formatting changes
do not create a new benchmark identity.

Methodology `1.1` adds optional, backward-compatible calibration and revision
inputs. `ObservedClaim.confidence` is a probability in `[0, 1]`; the scorer
reports mean confidence, empirical exact-claim accuracy, Brier score, and a
deterministic ten-bin expected calibration error. Optional expected and
observed severities use the ordered scale `informational`, `low`, `medium`,
`high`, `critical`; exact agreement and mean absolute ordinal error are reported
only for exactly matched claims with both labels. Predictions that cannot be
severity-adjudicated are counted separately, never silently treated as correct.

`CaseRunResult.revisions` records immutable before/after claims, an iteration,
stage, and reason. The answer key—not a self-reported outcome—determines
`errors_fixed`, `errors_introduced`, preserved correct assertions, and persistent
errors. Results written for methodology `1.0` remain valid; missing optional
inputs produce explicit zero counts and `null` calibration rates.

`mulder benchmark-export` normalizes current Mulder case databases without
running an investigation or contacting a model or network service. Inputs must
cover the manifest exactly, using one `--case-db CASE_ID=PATH` or
`--failed-case CASE_ID=REASON` per case. It stamps the run identity required for
repeat and ablation comparisons:

```console
mulder benchmark-export benchmarks/my-suite/manifest-v1.yaml \
  --case-db case-a=.mulder/cases/case-a.db \
  --failed-case case-b='worker resource limit' \
  --run-id candidate-r2 --system-version "$MULDER_BUILD" \
  --matrix-cell opus/default --model analyst=vendor-model-version \
  --orchestrator-version "$ORCHESTRATOR_BUILD" \
  --prompt-set-sha256 "$PROMPT_SHA256" --toolset-sha256 "$TOOLSET_SHA256" \
  --repeat-index 2 --seed 1002 --output candidate-r2.json
```

The extractor opens case databases without applying migrations. Citation IDs
derive from source coordinates and evidence text rather than database UUIDs;
coverage domains use URL-escaped `system/domain/check` components. This makes
normalization stable, but the answer-key anchors must use those canonical IDs
for citations to resolve. See `MATRICES.md` for scheduled-run and aggregation
rules, and `ndlc/README.md` for the conservative historical NDLC conversion.

`benchmark-export --ablation` retains historical free-form identity labels for
old result compatibility, but the five safety-component names cannot be stamped.
Executable ablations use a complete typed workflow trace and the separate
offline command:

```console
mulder benchmark-ablate benchmarks/ablation/result-base.json \
  --ablation without-verifier \
  --run-id no-verifier-r0 --matrix-cell fixture/without-verifier \
  --output no-verifier-r0.json
```

The supported switches are `without-verifier`, `without-independence-gate`,
`without-alternative-narrative`, `without-blind-reviewer`, and
`without-candidate-filters`. The engine first proves that executing every stage
reproduces the base result, then replays it while skipping the selected stages.
Its receipt binds the base run identity, base result and trace hashes,
executed/skipped stages, and per-case operation counts. The scorer reconstructs
the base, replays every received ablated result, and fails closed on tampering.
This facility changes normalized benchmark objects
only; it has no production-runner import or production configuration switch.

The strict Pydantic models in `mulder.benchmark.models` are authoritative. Their
portable JSON Schema exports are committed in `benchmarks/schemas/`; a parity
test fails if code and exported schemas drift. Unknown fields, non-finite
numbers, invalid hashes, duplicate IDs, invalid references, and unsupported
schema versions are rejected.
