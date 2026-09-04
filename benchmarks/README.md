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

The manifest is the answer-key contract. Loading a redistributable local
manifest re-hashes every artifact, verifies its declared size, resolves each
bounded `line=...;field=...` selector, and checks the selected text digest. It records case applicability tags,
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

Methodology `1.1` adds optional calibration and revision inputs. Score output
uses `mulder.benchmark.score/v2`; the unchanged v1 schema remains committed for
existing score artifacts. `ObservedClaim.confidence` is a probability in `[0, 1]`; the scorer
reports mean confidence, empirical exact-claim accuracy, Brier score, and a
deterministic ten-bin expected calibration error. Optional expected and
observed severities use the ordered scale `informational`, `low`, `medium`,
`high`, `critical`; exact agreement and mean absolute ordinal error are reported
only for exactly matched claims with both labels. Predictions that cannot be
severity-adjudicated are counted separately, never silently treated as correct.

`CaseRunResult.revisions` records immutable before/after claims, an iteration,
stage, reason, source revision ID, and an explicit removal tombstone. The answer
key—not a self-reported outcome—determines
`errors_fixed`, `errors_introduced`, preserved correct assertions, and persistent
errors. These counts compare the complete assertion error set before and after
each revision, so replacing one missing true claim with an unverified false
claim cannot receive false correction credit. They include verification-state changes that retain the same proposition
and removals whose `after` value is null. Duplicate propositions contribute one
calibration sample; conflicting confidence or severity labels fail closed.
Results written for methodology `1.0` remain valid; missing optional inputs
produce explicit zero counts and `null` calibration rates.

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

The extractor opens case databases without applying migrations and projects
stored confidence/severity, complete finding and claim-verification histories,
withdrawal tombstones, and coverage into a v2 executable workflow trace. It
runs the bounded workflow through the current verifier, independence policy,
candidate policy, explicit Alternative Narrative refutations, and explicit
blind-review decisions. Review stages are bound by stable decision reason codes,
not inferred from an actor label.
Because the current case schema stores categorical confidence, export maps
`confirmed` to `0.95` and `inference` to `0.50`; the trace retains the original
finding snapshots so that conversion remains auditable.
Before export, every anchor is reopened against the current CaseDB window. A
changed range, source identity, or exact text produces a current inconclusive
verification rather than reusing stale history. Export also re-hashes the
manifest artifact at its source path and emits a strict binding containing the
artifact ID/hash, selector, selected-text hash, and root acquisition ID.
Methodology 1.1 requires those bindings. The scorer replays the unablated
workflow, checks every binding against the answer key, and requires independent
anchors to come from distinct artifacts and distinct root acquisitions.
Citation IDs
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
mulder benchmark-ablate benchmarks/ablation/result-real-base-v2.json \
  --ablation without-verifier \
  --run-id no-verifier-r0 --matrix-cell fixture/without-verifier \
  --output no-verifier-r0.json
```

The supported switches are `without-verifier`, `without-independence-gate`,
`without-alternative-narrative`, `without-blind-reviewer`, and
`without-candidate-filters`. New ablations require v2 domain inputs rather than
hand-authored output transformations. The committed fixture is built through a
real CaseDB from five content-addressed evidence files; only clock and ID
adapters are fixed to make its immutable history byte-reproducible. The engine first proves that the current
real Mulder components reproduce the base result, then executes them again while
skipping the selected stage. Verdicts, claims, coverage, revisions, and resource
measurements are recomputed; base runtime, token, and cost values are never
cloned into a synthetic ablation.
Its receipt binds the base run identity, base result and trace hashes,
executed/skipped stages, and per-case operation counts. The scorer reconstructs
the base, re-executes every received ablated result, and fails closed on tampering.
Legacy v1 operation traces remain readable for old result verification but are
rejected as inputs to new ablation runs.
This facility changes normalized benchmark objects
only; it has no production-runner import or production configuration switch.

The strict Pydantic models in `mulder.benchmark.models` are authoritative, and
the nested finding, revision, claim, verification, and anchor domain values also
reject unknown fields rather than silently stripping provenance. Their
portable JSON Schema exports are committed in `benchmarks/schemas/`; a parity
test fails if code and exported schemas drift. Unknown fields, non-finite
numbers, invalid hashes, duplicate IDs, invalid references, and unsupported
schema versions are rejected.
