# PR 8.2 code-mode architecture spike

Status: **NO-GO for PR 8.3 as currently specified.** The constrained assertion
DSL passes its applicable escape/abuse cases, but it intentionally has no
effectful capability calls, so effect attribution is untested. The WASM and
container candidates have reviewable abuse fixtures but no reviewed runtime
Adapter; the harness reports those cases as `NOT_RUN`, which fails the hard
gates. Missing isolation evidence is not a pass.

This directory is a repository-only experiment. Nothing under it is imported
by `src/mulder`, registered as an MCP tool, exposed by the CLI, included in a
phase list, or installed as a project script. The executable prototype is an
effect-free assertion interpreter, not a code execution tool.

## Question and constraints

The spike asks whether Mulder can safely support model-authored, bounded
composition over immutable forensic evidence. Any future Module must preserve:

- the read-only case and evidence invariants;
- provider and egress policy before an effect;
- exact source selectors, content digests, and replay metadata;
- `INCONCLUSIVE` for missing data instead of silently manufacturing `false`;
- deterministic CPU, memory, time, and output budgets;
- typed, least-authority capabilities with every effect in a receipt;
- evidence text as data, including instruction-shaped, encoded-looking,
  Markdown, and HTML content.

The candidate **Interface** sketches below are architectural comparison aids,
not production interfaces:

```text
assert(program_json, evidence_snapshot_json, limits) -> AssertionReceipt
run_wasm(module_digest, capability_manifest, budgets) -> GuestReceipt
run_container(image_digest, sealed_snapshot, capability_manifest, budgets) -> GuestReceipt
```

The proposed production **Seam** would sit after case/provider/execution policy
and before any typed read-only tool Adapter. A single `run` Interface would hide
validation, budgets, provenance, and denial behavior, creating **Depth** and
**Leverage** for callers while keeping policy changes local. This spike does not
create that Seam: there is no reviewed effectful Adapter yet, so introducing it
would be hypothetical rather than useful. Keeping the experiment outside
`src/` preserves **Locality** and prevents accidental exposure.

Dependency classification:

- The assertion DSL is in-process computation. It is safe to prototype because
  its JSON operators are interpreted directly and cannot name an ambient
  capability.
- An embedded WASM engine is local-substitutable, but the host linker and
  resource limiter are security-critical parts of the implementation.
- A container runtime is local-substitutable only on hosts with compatible
  user namespaces and cgroups. Its kernel/runtime configuration is part of the
  security Interface even if hidden behind an Adapter.

## Threat model

### Assets

- raw evidence bytes and the immutable case database;
- host files, environment variables, credentials, sockets, processes, devices,
  and other cases;
- provider policy, execution policy, receipts, chain position, and provenance;
- analyst availability and bounded CPU, RAM, disk, PID, time, and output use;
- report/model-context integrity when evidence contains presentation or prompt
  injection.

### Adversary and trust assumptions

Treat the program, module, container image, all evidence fields, and model
output as hostile. The adversary may know the runtime and limits and may submit
deeply nested, oversized, encoded, nondeterministic, or version-targeted input.
The Mulder host, pinned runtime, kernel, policy configuration, and typed tool
Adapters are trusted but fallible. A runtime security claim is accepted only
when an executable negative test demonstrates it under the supported version.

This spike does not claim protection from a compromised kernel, malicious
administrator, physical attacker, or hardware side channel. It also does not
claim that a sandbox makes arbitrary malware safe.

### Threats and required controls

| Threat | Required observation |
|---|---|
| Host filesystem read/write, traversal, symlink, `/proc`, or device access | Undeclared paths fail; the evidence snapshot is read-only and selector-scoped. |
| Network exfiltration or listener creation | No network capability is linked and an external canary receives no connection. |
| Process/thread spawn and privilege escalation | Spawn is absent or denied; PID and capability limits hold. |
| Environment/credential disclosure | Host canary variables are absent; no ambient environment is inherited. |
| Infinite loop, deep expression, memory growth, or output flood | Deterministic instruction/node, memory, wall-clock, and byte limits terminate work. |
| Confused-deputy capability call | Undeclared imports/calls fail before execution; arguments and returned selectors are validated. |
| Prompt, ANSI, Unicode, encoded, Markdown, or HTML injection | Values remain typed data and never become program source or trusted presentation. |
| Replay ambiguity or runtime drift | Program, input, output, capability, runtime, and policy versions/digests appear in the receipt. |
| Runtime/image supply-chain substitution | Runtime and guest are digest-pinned and verified without a network pull at execution time. |

## Why Python and JavaScript evaluation are rejected

In-process Python and JavaScript source evaluation are not candidates, even
with reduced globals, AST filtering, a timeout, Node `vm`, or a permission flag.
Python documents that `eval`/`exec` execute arbitrary code and warns that
user-supplied input creates security vulnerabilities. Python also warns that
even `ast.literal_eval`, which does not execute arbitrary code, can exhaust
memory, the C stack, or CPU on small hostile inputs. Node states directly that
`node:vm` is not a security mechanism and must not run untrusted code.
([Python built-ins](https://docs.python.org/3/library/functions.html#eval),
[Python AST](https://docs.python.org/3/library/ast.html#ast.literal_eval),
[Node `vm`](https://nodejs.org/api/vm.html))

The prototype therefore accepts parsed JSON and manually interprets a closed
operator set. It never compiles or evaluates source. Parsing is still bounded:
Python's JSON documentation warns that hostile JSON can consume substantial
CPU and memory and recommends limiting input size, so a production parser must
enforce a byte limit before decoding, not only after it.
([Python JSON](https://docs.python.org/3/library/json.html))

## Candidate comparison

### 1. Constrained expression/assertion DSL

The prototype follows the safety shape of CEL: non-Turing-complete expressions
that can access only host-provided data. CEL itself describes this as suitable
for predictable-cost predicate evaluation.
([Common Expression Language](https://cel.dev/))

The JSON DSL supports literals, RFC 6901-style field selection, `length`,
`exists`, comparisons, containment, and three-valued `all`/`any`/`not`.
Unknown operators and unknown operator fields fail closed. There is no lookup by
Python attribute, arbitrary function call, import, regular expression, decode,
filesystem, environment, process, network, clock, randomness, or write
operator. Program/evidence size, nesting, collection size, string size, and
evaluated nodes are bounded. The receipt contains only status, truth,
reason-code, counts, schema version, and content hashes.

This is the smallest Interface and the highest-leverage choice for pure
assertions. It is not yet adequate for PR 8.3 because it cannot compose typed
read-only capability calls, and therefore the required effect-attribution gate
has not been exercised.

### 2. WASM guest

WASI is designed around explicit, unforgeable capabilities and no ambient
authority. A Wasmtime guest with a custom linker could therefore receive only
Mulder's typed read-only capability imports; no generic WASI filesystem,
network, environment, or process imports should be linked.
([WASI design principles](https://github.com/WebAssembly/WASI/blob/main/docs/DesignPrinciples.md),
[Wasmtime WASI tutorial](https://github.com/bytecodealliance/wasmtime/blob/main/docs/WASI-tutorial.md))

That capability model is necessary but not sufficient. Wasmtime tells
embedders never to trust guest values and to validate them before acting for a
guest. It provides deterministic fuel interruption, while epoch interruption
is nondeterministic; memory/tables also require explicit limiting for
deterministic behavior. Fuel does not by itself interrupt a guest blocked in a
host call, so a wall-clock/process backstop and cancellable host calls remain
necessary.
([Wasmtime security scope](https://docs.wasmtime.dev/security-what-is-considered-a-security-vulnerability.html),
[Wasmtime interruption](https://docs.wasmtime.dev/examples-interrupting-wasm.html),
[Wasmtime deterministic execution](https://docs.wasmtime.dev/examples-deterministic-wasm-execution.html),
[Wasmtime configuration](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html))

The WAT fixtures cover an undeclared import, an infinite loop, and unbounded
memory growth. They are deliberately not executed by this spike because no
reviewed embedded engine Adapter, pinned engine, or bounded host-call Interface
exists in the repository. Reporting `NOT_RUN` is the security result.

Do not substitute Node's WASI implementation: Node explicitly says its WASI
capabilities do not form a security model and that filesystem sandboxing can be
escaped. ([Node WASI security](https://nodejs.org/api/wasi.html#security))

### 3. Isolated container process

The container fixture declares the minimum launch policy to test: no pull,
`network=none`, read-only root, all Linux capabilities dropped,
`no-new-privileges`, empty inherited environment, non-root user/user namespace,
bounded PIDs/memory/CPU/time, and a small no-exec tmpfs. Podman documents those
controls, but also notes that CPU/memory limits vary with cgroup/rootless host
support and that a container otherwise defaults to the image user (commonly
root). ([Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html))

A container has the broadest language/tool compatibility but the largest
trusted computing base and operational variance. NIST identifies runtime
vulnerabilities that permit container escape and unbounded container network
access as container-specific risks. Thus `--network=none` and rootless
hardening reduce risk; they do not turn a container into a proof of isolation.
([NIST SP 800-190](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-190.pdf))

The fixture specifies host-canary, write, network, PID, environment, and output
probes. They remain `NOT_RUN` because this repository has no digest-pinned local
test image, supported-host matrix, or safe output-capping runner. The spike
must not pull an image or run arbitrary shell code merely to make the table
green.

## Decision matrix

Scores are conclusions from the threat model and executable evidence, not
feature marketing.

| Criterion | Assertion DSL | WASM guest | Isolated container |
|---|---|---|---|
| Program expressiveness | Low: pure predicates and small transforms | High: compiled languages | Highest: existing binaries/languages |
| Capability denial | By construction; no effect operators | Strong only with a custom minimal linker | Configuration-, kernel-, and runtime-dependent |
| Deterministic CPU bound | Node/depth budget passes | Fuel design is credible; fixture `NOT_RUN` | CPU/time limits vary; fixture `NOT_RUN` |
| Memory/output bound | Input/result caps pass | Engine/host caps needed; fixture `NOT_RUN` | Cgroups and external pipe cap needed; fixture `NOT_RUN` |
| Replay | Canonical JSON and hashes | Possible with pinned engine/module/import manifest | Harder: kernel, runtime, image, architecture all matter |
| Typed read-only calls | Not implemented | Natural via typed component imports | Requires a separate broker protocol |
| Attack surface | Small custom interpreter | Engine + compiler + host linker | Kernel + runtime + image userspace + broker |
| Portability/operations | Python-only repository code | New optional runtime/toolchain | Rootless/cgroup/runtime variance |
| Current hard-gate result | `NOT_READY`: effect attribution missing | `NOT_READY`: isolation cases `NOT_RUN` | `NOT_READY`: isolation cases `NOT_RUN` |
| PR 8.3 recommendation | Safe basis for a separate effect-free assertion feature | Best eventual effectful candidate, more spike evidence required | No for MVP |

## Reproduce the result

From the repository root, with the development environment already installed:

```bash
PYTHONPATH=. python spikes/code_mode/harness.py
PYTHONPATH=src:. pytest -q tests/test_code_mode_spike.py
```

The first command emits stable JSON. A `NO_GO` decision exits successfully
because it is a valid experiment result. The committed suite currently yields:

- assertion DSL: all declared cases pass, but `effect_attribution` is missing;
- WASM guest: four isolation/resource cases are `NOT_RUN`;
- isolated container: five isolation/version cases are `NOT_RUN`;
- recommendation: `NO_GO`, reason
  `NO_CANDIDATE_PASSED_ALL_HARD_GATES`.

The tests also prove deterministic output, three-valued missing-data behavior,
rejection of Python/JavaScript/effect operators, size limits, non-disclosure of
raw evidence in receipts, fixture path confinement, and absence of production
registration.

## Conditions to reconsider PR 8.3

Do not open PR 8.3 as an effectful code-mode MVP until a second non-production
spike makes one candidate pass every hard gate. The preferred next experiment
is an embedded, version-pinned Wasmtime Adapter with:

1. no WASI linker and only a versioned, typed, read-only Mulder capability
   manifest;
2. byte limits before module/input decoding, fixed memory/table/instance limits,
   deterministic fuel, cancellable host calls, a wall-clock backstop, and an
   externally enforced output cap;
3. program/input/output/capability/policy/runtime digests in an append-only
   receipt;
4. dynamic execution of every committed WAT abuse fixture on each supported
   platform, plus a deliberately weakened negative-control Adapter proving the
   tests detect an escape;
5. normal bounded composition through a fake typed capability Adapter, followed
   by the real execution-policy Seam only after the fake and production
   Adapters agree on denials.

A separately scoped, effect-free assertion feature could proceed from the DSL
prototype after moving parsing behind a pre-decode byte cap and integrating the
existing evidence-envelope selectors/digests. It should not be called arbitrary
code mode, and it does not satisfy PR 8.3's effectful capability requirement.

Sources were checked on 2026-09-04. This note is the single research artifact
for the spike; primary specifications and first-party documentation are linked
at each claim.
