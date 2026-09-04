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
case records the failed/unsupported coverage status and `no_verdict`; silently
omitting hard cases is rejected as incomparable. The table's `U/C/I` column is
the unsupported/contradicted/inconclusive distribution. Runtime is milliseconds,
tokens combine input and output, and cost is USD. Output hashes bind the
canonical semantic manifest and result objects, so JSON/YAML formatting changes
do not create a new benchmark identity.

The strict Pydantic models in `mulder.benchmark.models` are authoritative. Their
portable JSON Schema exports are committed in `benchmarks/schemas/`; a parity
test fails if code and exported schemas drift. Unknown fields, non-finite
numbers, invalid hashes, duplicate IDs, invalid references, and unsupported
schema versions are rejected.
